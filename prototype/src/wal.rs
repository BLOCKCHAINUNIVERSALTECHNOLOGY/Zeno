// wal.rs — Write-Ahead Log.
//
// Rule: EVERY write is appended to the WAL file and fsynced BEFORE it
// touches the memtable. If the process crashes, the WAL is replayed on
// open and no acknowledged write is lost.
//
// File format (one record per line, newline-delimited JSON):
//   {"op":"put","key":"...","value":"..."}
//   {"op":"del","key":"..."}
// Keys and values are JSON strings, so any UTF-8 text is safe. Newlines
// inside a key/value are escaped by JSON, so one line is always one record.
//
// V0.2 strictness (was: corrupt lines silently skipped in V0.1):
// replay now COUNTS every corrupt line and reports it, instead of
// hiding it. Policy for a corrupt line, wherever it sits in the file:
// count it, skip ONLY that line, and keep replaying the lines after it.
// Each line is one independent, fsynced record, so a torn line means
// only that one write was lost — the valid records after it were
// acknowledged separately and must not be thrown away with it. (If a
// corrupt "put" is skipped, the key keeps whatever older value it had
// in an SSTable or an earlier WAL line; it is not deleted. If a
// corrupt "del" is skipped, the delete itself is lost, so the key's
// older value comes back alive on replay — the delete is NOT
// re-applied from anywhere else. That resurrection is the price of
// skipping only the corrupt line instead of truncating the WAL.)
// The line number of every corrupt line is recorded, so the open-time
// warning says exactly which line(s) were bad instead of just a count.

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// One WAL record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalRecord {
    pub op: String, // "put" or "del"
    pub key: String,
    pub value: Option<String>, // None for deletes
}

impl WalRecord {
    pub fn put(key: &str, value: &str) -> Self {
        Self {
            op: "put".to_string(),
            key: key.to_string(),
            value: Some(value.to_string()),
        }
    }

    pub fn del(key: &str) -> Self {
        Self {
            op: "del".to_string(),
            key: key.to_string(),
            value: None,
        }
    }
}

/// Result of replaying a WAL file: the valid records, in order, plus
/// how many lines were corrupt and skipped.
#[derive(Debug, Default)]
pub struct WalReplay {
    pub records: Vec<WalRecord>,
    /// Lines that could not be parsed as a valid record (torn write,
    /// garbage bytes, bad UTF-8, unknown op, or a "put" with no value).
    /// Empty lines are not counted.
    pub corrupt_lines: u64,
    /// 1-based line numbers of the corrupt lines, in file order —
    /// same length as `corrupt_lines`, so a warning can name the exact
    /// line(s) instead of just a count.
    pub corrupt_line_numbers: Vec<u64>,
}

/// Append-only WAL file.
pub struct Wal {
    path: PathBuf,
    file: File,
}

impl Wal {
    /// Open (creating if needed) the WAL at `path`.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Append one record and fsync, so the write is durable before the
    /// caller applies it to the memtable.
    pub fn append(&mut self, record: &WalRecord) -> std::io::Result<()> {
        let line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        writeln!(self.file, "{line}")?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Read all records back, in order, counting corrupt lines.
    /// A corrupt line is counted and skipped — ONLY that line; valid
    /// lines after it are still replayed (see the module docs).
    pub fn replay_reported(path: &Path) -> WalReplay {
        let Ok(file) = File::open(path) else {
            return WalReplay::default();
        };
        let reader = BufReader::new(file);
        let mut out = WalReplay::default();
        for (index, line) in reader.lines().enumerate() {
            // 1-based physical line number, including empty lines.
            let line_no = index as u64 + 1;
            let Ok(line) = line else {
                // Unreadable line (e.g. invalid UTF-8): corrupt, count it.
                out.corrupt_lines += 1;
                out.corrupt_line_numbers.push(line_no);
                continue;
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<WalRecord>(&line) {
                Ok(record) if is_valid(&record) => out.records.push(record),
                _ => {
                    out.corrupt_lines += 1;
                    out.corrupt_line_numbers.push(line_no);
                }
            }
        }
        out
    }

    /// Read all records back, in order (corrupt lines counted and
    /// skipped — see `replay_reported` for the count).
    pub fn replay(path: &Path) -> Vec<WalRecord> {
        Self::replay_reported(path).records
    }

    /// Delete the WAL file (called after a memtable flush, when every
    /// record in it is safely inside an SSTable).
    pub fn clear(&self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)
    }
}

/// A parsed record is only valid if its op makes sense: "put" needs a
/// value, "del" needs none. Anything else is a corrupt line.
fn is_valid(record: &WalRecord) -> bool {
    match record.op.as_str() {
        "put" => record.value.is_some(),
        "del" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("zeno-wal-test-{name}.log"));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn append_and_replay() {
        let path = tmp_path("basic");
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&WalRecord::put("k1", "v1")).unwrap();
            wal.append(&WalRecord::put("k2", "v2")).unwrap();
            wal.append(&WalRecord::del("k1")).unwrap();
        }
        let records = Wal::replay(&path);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], WalRecord::put("k1", "v1"));
        assert_eq!(records[2], WalRecord::del("k1"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn torn_last_line_is_skipped() {
        let path = tmp_path("torn");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&WalRecord::put("k1", "v1")).unwrap()
            )
            .unwrap();
            writeln!(f, "{{\"op\":\"put\",\"key\":\"k2\",\"val").unwrap(); // torn line
        }
        let replayed = Wal::replay_reported(&path);
        assert_eq!(replayed.records.len(), 1);
        assert_eq!(replayed.records[0].key, "k1");
        assert_eq!(replayed.corrupt_lines, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_line_numbers_are_recorded() {
        let path = tmp_path("lineno");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&WalRecord::put("k1", "v1")).unwrap()
            )
            .unwrap();
            writeln!(f, "garbage-not-json").unwrap(); // line 2
            writeln!(
                f,
                "{}",
                serde_json::to_string(&WalRecord::put("k2", "v2")).unwrap()
            )
            .unwrap();
            writeln!(f, "{{\"op\":\"bogus\",\"key\":\"k3\"}}").unwrap(); // line 4
            writeln!(f).unwrap(); // line 5, empty: not counted
            writeln!(f, "{{\"op\":\"del\",\"key\":\"k1\"").unwrap(); // line 6, torn
        }
        let replayed = Wal::replay_reported(&path);
        assert_eq!(replayed.records.len(), 2);
        assert_eq!(replayed.corrupt_lines, 3);
        assert_eq!(replayed.corrupt_line_numbers, vec![2, 4, 6]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_middle_line_is_counted_and_later_lines_still_replay() {
        let path = tmp_path("middle");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&WalRecord::put("k1", "v1")).unwrap()
            )
            .unwrap();
            writeln!(f, "this is not json at all").unwrap(); // corrupt middle line
            writeln!(
                f,
                "{}",
                serde_json::to_string(&WalRecord::put("k2", "v2")).unwrap()
            )
            .unwrap();
            writeln!(f, "{{\"op\":\"bogus\",\"key\":\"k3\"}}").unwrap(); // bad op
        }
        let replayed = Wal::replay_reported(&path);
        assert_eq!(replayed.records.len(), 2, "valid lines must still replay");
        assert_eq!(replayed.records[0].key, "k1");
        assert_eq!(replayed.records[1].key, "k2");
        assert_eq!(replayed.corrupt_lines, 2, "both bad lines must be counted");
        let _ = std::fs::remove_file(&path);
    }
}

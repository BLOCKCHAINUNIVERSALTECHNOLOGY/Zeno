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

    /// Read all records back, in order. A torn/corrupt trailing line
    /// (a crash mid-write) is skipped, not fatal — the write was never
    /// acknowledged, so dropping it is safe.
    pub fn replay(path: &Path) -> Vec<WalRecord> {
        let Ok(file) = File::open(path) else {
            return Vec::new();
        };
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for line in reader.lines() {
            let Ok(line) = line else { continue };
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<WalRecord>(&line) {
                records.push(record);
            }
            // else: corrupt/torn line — skip it.
        }
        records
    }

    /// Delete the WAL file (called after a memtable flush, when every
    /// record in it is safely inside an SSTable).
    pub fn clear(&self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)
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
        let records = Wal::replay(&path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, "k1");
        let _ = std::fs::remove_file(&path);
    }
}

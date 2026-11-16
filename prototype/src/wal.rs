// wal.rs — Write-Ahead Log.
//
// Rule: EVERY write is appended to the WAL file and fsynced BEFORE it
// touches the memtable. If the process crashes, the WAL is replayed on
// open and no acknowledged write is lost.
//
// File format (one record per line, newline-delimited JSON):
//   {"op":"put","key":"...","value":"..."}
//   {"op":"del","key":"..."}
//   {"op":"put","txn":5,"key":"...","value":"..."}   (V0.6: part of txn 5)
//   {"op":"del","txn":5,"key":"..."}
//   {"op":"commit","txn":5}                          (V0.6: txn 5 committed)
// Keys and values are JSON strings, so any UTF-8 text is safe. Newlines
// inside a key/value are escaped by JSON, so one line is always one record.
//
// V0.6 transactions: a record WITH a `txn` id belongs to that
// transaction and is only applied when a matching `commit` record
// for the same id appears LATER in the file; records of a
// transaction with no commit record (crash before commit, or an
// aborted transaction) are DISCARDED on replay. A record WITHOUT
// a `txn` id is a V0.5 record (or a V0.6 autocommit write that
// predates... no — V0.6 autocommit writes DO carry a txn id plus
// a commit record; only genuine V0.5 files lack the field) and is
// applied immediately, as before. `#[serde(default)]` on `txn`
// keeps old WAL lines parsing. A `commit` record with no `txn`
// id, or a `put` with no value, is corrupt.
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
// V0.6-fix (M4) exception: a write that belongs to a transaction
// (a record WITH a `txn` id) is NOT independent — the commit
// record now carries the transaction's write count, and replay
// discards the WHOLE transaction when the count does not match
// (a torn line inside it means the commit can no longer be
// trusted as whole). So a corrupt `del` inside a transaction
// resurrects nothing: the entire transaction, deletes included,
// is dropped. A corrupt V0.5 `del` (no `txn` id) still resurrects
// its key's older value, as before — there is no commit marker
// to check it against, and that edge is stated honestly here.
// The line number of every corrupt line is recorded, so the open-time
// warning says exactly which line(s) were bad instead of just a count.

use crate::sstable::sync_dir;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// One WAL record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalRecord {
    pub op: String, // "put", "del", or "commit" (V0.6)
    pub key: String,
    pub value: Option<String>, // None for deletes and commits
    /// V0.6: the transaction this write belongs to. `None` means a
    /// V0.5 record (or a hand-written one): applied immediately on
    /// replay, as committed. `Some(id)` means "apply only if a
    /// `commit` record for `id` appears later in the file".
    /// `#[serde(default)]` keeps V0.5 WAL lines (no such field)
    /// parsing instead of becoming corrupt lines.
    #[serde(default)]
    pub txn: Option<u64>,
    /// V0.6-fix (M4): on a `commit` record, the number of write
    /// records (`put`/`del`) that belong to this transaction.
    /// Replay applies a transaction ONLY when the commit record
    /// arrives AND the buffered write count matches this number —
    /// a torn/corrupt write line inside a committed transaction
    /// is therefore a whole-transaction discard (with a loud
    /// warning), never a silent partial commit. `None` means an
    /// old commit record written before this field existed:
    /// replay falls back to the old rule (apply whatever writes
    /// were buffered). `skip_serializing_if` keeps ordinary
    /// `put`/`del` lines exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

impl WalRecord {
    pub fn put(key: &str, value: &str) -> Self {
        Self {
            op: "put".to_string(),
            key: key.to_string(),
            value: Some(value.to_string()),
            txn: None,
            count: None,
        }
    }

    pub fn del(key: &str) -> Self {
        Self {
            op: "del".to_string(),
            key: key.to_string(),
            value: None,
            txn: None,
            count: None,
        }
    }

    /// A write belonging to transaction `txn` (V0.6). Applied on
    /// replay only when the matching `commit` record appears.
    pub fn put_txn(txn: u64, key: &str, value: &str) -> Self {
        Self {
            op: "put".to_string(),
            key: key.to_string(),
            value: Some(value.to_string()),
            txn: Some(txn),
            count: None,
        }
    }

    /// A delete belonging to transaction `txn` (V0.6).
    pub fn del_txn(txn: u64, key: &str) -> Self {
        Self {
            op: "del".to_string(),
            key: key.to_string(),
            value: None,
            txn: Some(txn),
            count: None,
        }
    }

    /// The commit marker for transaction `txn` (V0.6). Everything
    /// before it in the file that carries this `txn` id becomes
    /// durable; without it, those records are discarded on replay.
    /// Kept for old callers and tests: it carries no record
    /// count, so replay falls back to the old rule for it. The
    /// engine always writes `commit_count` instead.
    pub fn commit(txn: u64) -> Self {
        Self {
            op: "commit".to_string(),
            key: String::new(),
            value: None,
            txn: Some(txn),
            count: None,
        }
    }

    /// The commit marker for transaction `txn`, carrying the
    /// number of write records that belong to it (M4). Replay
    /// applies the transaction only when the buffered write
    /// count equals this number.
    pub fn commit_count(txn: u64, count: u64) -> Self {
        Self {
            op: "commit".to_string(),
            key: String::new(),
            value: None,
            txn: Some(txn),
            count: Some(count),
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
    ///
    /// V0.11 (review finding 2): when the file is NEWLY created,
    /// its parent directory is fsynced before returning, so the
    /// new pathname itself is durable — not just the file's
    /// contents. Without this, a power loss could lose the
    /// directory entry of an acknowledged write's WAL file while
    /// its SSTable copy does not exist yet. The sync is done
    /// once, at creation (every later append only fsyncs the
    /// file, as before); an error propagates instead of being
    /// discarded.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let existed = path.exists();
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        if !existed {
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
        }
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
    ///
    /// V0.11 (review finding 2): the removal is a namespace change
    /// too, so the parent directory is fsynced afterwards and the
    /// error propagates — a crash must not resurrect the old WAL
    /// file (and replay its records a second time) after the
    /// rotation. `flush()` re-creates the WAL right after this,
    /// and that creation syncs the directory again.
    pub fn clear(&self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)?;
        if let Some(parent) = self.path.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    }
}

/// A parsed record is only valid if its op makes sense: "put" needs a
/// value, "del" needs none (a `del` WITH a value is corrupt — m7:
/// it used to be accepted, which let a hand-edited WAL smuggle a
/// value into a delete), "commit" (V0.6) needs a transaction id
/// and no value. Anything else is a corrupt line.
fn is_valid(record: &WalRecord) -> bool {
    match record.op.as_str() {
        "put" => record.value.is_some(),
        "del" => record.value.is_none(),
        "commit" => record.txn.is_some() && record.value.is_none(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        crate::unique_test_path(&format!("zeno-wal-test-{name}"))
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
    fn txn_records_and_commit_marker_replay_in_order() {
        let path = tmp_path("txn");
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&WalRecord::put_txn(5, "k1", "v1")).unwrap();
            wal.append(&WalRecord::commit(5)).unwrap();
            // Txn 6 never commits: its record is still IN the file
            // (filtering it out is the engine's replay job, not the
            // WAL's — the WAL returns records in file order).
            wal.append(&WalRecord::put_txn(6, "k2", "v2")).unwrap();
        }
        let records = Wal::replay(&path);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], WalRecord::put_txn(5, "k1", "v1"));
        assert_eq!(records[1], WalRecord::commit(5));
        assert_eq!(records[2], WalRecord::put_txn(6, "k2", "v2"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn del_with_a_value_is_corrupt_and_commit_with_a_value_is_too() {
        // m7: a `del` carrying a value used to be accepted.
        let path = tmp_path("del-value");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "{{\"op\":\"del\",\"key\":\"k1\",\"value\":\"sneaky\"}}").unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&WalRecord::put("k2", "v2")).unwrap()
            )
            .unwrap();
            writeln!(
                f,
                "{{\"op\":\"commit\",\"txn\":7,\"key\":\"\",\"value\":\"sneaky\"}}"
            )
            .unwrap();
        }
        let replayed = Wal::replay_reported(&path);
        assert_eq!(replayed.records.len(), 1);
        assert_eq!(replayed.records[0].key, "k2");
        assert_eq!(replayed.corrupt_lines, 2);
        assert_eq!(replayed.corrupt_line_numbers, vec![1, 3]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn commit_count_round_trips() {
        let path = tmp_path("commit-count");
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&WalRecord::put_txn(7, "k1", "v1")).unwrap();
            wal.append(&WalRecord::put_txn(7, "k2", "v2")).unwrap();
            wal.append(&WalRecord::commit_count(7, 2)).unwrap();
        }
        let records = Wal::replay(&path);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2], WalRecord::commit_count(7, 2));
        // An old commit record (no count) still parses.
        assert_eq!(WalRecord::commit(7).count, None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn commit_without_txn_is_corrupt_and_old_lines_still_parse() {
        let path = tmp_path("commit-valid");
        {
            let mut f = File::create(&path).unwrap();
            // A V0.5 line (no "txn" field) parses: txn defaults None.
            writeln!(f, "{{\"op\":\"put\",\"key\":\"k1\",\"value\":\"v1\"}}").unwrap();
            // A commit with no txn id is corrupt.
            writeln!(f, "{{\"op\":\"commit\",\"key\":\"\"}}").unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&WalRecord::commit(7)).unwrap()
            )
            .unwrap();
        }
        let replayed = Wal::replay_reported(&path);
        assert_eq!(replayed.records.len(), 2);
        assert_eq!(replayed.records[0].txn, None);
        assert_eq!(replayed.records[1], WalRecord::commit(7));
        assert_eq!(replayed.corrupt_lines, 1);
        assert_eq!(replayed.corrupt_line_numbers, vec![2]);
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

    /// V0.11 (review finding 2): a WAL rotation — `clear()` then
    /// a fresh `open()` — must not resurrect the old generation's
    /// records on replay. `clear()` removes the file and syncs
    /// the parent directory; the fresh `open()` creates a new
    /// file and syncs the directory again, so the new pathname
    /// itself is durable, not just its contents. (That a directory
    /// fsync happened cannot be observed from inside a test — a
    /// power cut is not reproducible here — so this test proves
    /// the rotation semantics, and the crash-order integration
    /// tests prove the reopen behaviour end to end.)
    #[test]
    fn clear_then_reopen_does_not_resurrect_old_records() {
        let path = tmp_path("rotation");
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&WalRecord::put("old", "gone")).unwrap();
            wal.clear().unwrap();
            assert!(!path.exists(), "clear must remove the WAL file");
        }
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&WalRecord::put("new", "here")).unwrap();
        }
        let records = Wal::replay(&path);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, "new");
        let _ = std::fs::remove_file(&path);
    }
}

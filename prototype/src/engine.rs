// engine.rs — the storage engine: WAL + memtable + SSTables + compaction.
//
// Write path:  WAL (fsync) -> memtable -> flush to SSTable when full.
// Read path:   memtable -> SSTables newest-to-oldest (Bloom filter skips
//              SSTables that definitely lack the key).
// A tombstone in a newer layer hides the same key in older layers.
//
// What V0.1 does NOT do (honest limits, see README):
// - No MVCC snapshots / transactions yet. Reads see the latest value.
// - No PostgreSQL wire protocol yet. The CLI is the only interface.
// - No background compaction thread; compaction runs only on command.

use crate::memtable::MemTable;
use crate::sstable::{parse_sstable_id, sstable_path, sync_dir, SsTable};
use crate::wal::{Wal, WalRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Cumulative counters, persisted in `meta.json` so `stats` reports
/// lifetime totals, not just this process's counts. Saved when the
/// engine is dropped (every CLI run ends by dropping it).
#[derive(Debug, Default, Serialize, Deserialize)]
struct EngineMeta {
    puts: u64,
    gets: u64,
    flushes: u64,
    compactions: u64,
    /// Deletes are counted separately from puts. `#[serde(default)]`
    /// keeps old `meta.json` files (written before this field existed)
    /// readable instead of falling back to all-zero counters.
    #[serde(default)]
    deletes: u64,
}

pub struct Engine {
    dir: PathBuf,
    wal_path: PathBuf,
    meta_path: PathBuf,
    wal: Wal,
    memtable: MemTable,
    /// SSTables newest first (highest id first).
    sstables: Vec<SsTable>,
    next_sst_id: u64,
    /// Cumulative counters for `stats` (persisted in meta.json).
    meta: EngineMeta,
}

pub struct Stats {
    pub memtable_entries: usize,
    pub sstable_count: usize,
    pub sstable_entries: usize,
    pub puts: u64,
    pub gets: u64,
    pub flushes: u64,
    pub compactions: u64,
    pub deletes: u64,
    pub next_sst_id: u64,
}

impl Engine {
    /// Open (or create) a database in `dir`. Replays the WAL so data
    /// written before a crash comes back.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        let wal_path = dir.join("wal.log");
        let meta_path = dir.join("meta.json");

        // Load cumulative counters (missing file = first run).
        let meta = match fs::read_to_string(&meta_path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => EngineMeta::default(),
        };

        // Load existing SSTables, newest first. Leftover `*.tmp` files
        // are half-written SSTables from a crash mid-flush: the atomic
        // rename in `SsTable::write` means the final name was never
        // reached, so they are safe to delete.
        let mut ids: Vec<u64> = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with("sst-") && name.ends_with(".tmp") {
                let _ = fs::remove_file(entry.path());
                continue;
            }
            if let Some(id) = parse_sstable_id(name) {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        let next_sst_id = ids.last().map_or(1, |id| id + 1);
        let mut sstables = Vec::new();
        for id in ids.iter().rev() {
            let path = sstable_path(dir, *id);
            match SsTable::open(&path, *id) {
                Ok(table) => sstables.push(table),
                // A corrupt SSTable must not make the whole database
                // unopenable. Quarantine it (rename to `.corrupt`, so
                // it is never re-parsed as a live table and its id is
                // never reused) and keep going: the WAL and the other
                // SSTables are still recoverable. The quarantined
                // file is kept on disk for inspection, not deleted.
                Err(e) => {
                    let quarantine = dir.join(format!("sst-{id:06}.sst.corrupt"));
                    let _ = fs::remove_file(&quarantine);
                    match fs::rename(&path, &quarantine) {
                        Ok(()) => eprintln!(
                            "warning: quarantined corrupt SSTable {} ({e}); \
                             data in it is unavailable, other data recovered",
                            path.display()
                        ),
                        Err(rename_err) => eprintln!(
                            "warning: corrupt SSTable {} could not be quarantined \
                             ({e}; rename failed: {rename_err}); skipping it",
                            path.display()
                        ),
                    }
                }
            }
        }

        // Replay the WAL into a fresh memtable.
        let mut memtable = MemTable::new();
        for record in Wal::replay(&wal_path) {
            match record.op.as_str() {
                "put" => {
                    if let Some(v) = record.value {
                        memtable.put(&record.key, &v);
                    }
                }
                "del" => memtable.delete(&record.key),
                _ => {}
            }
        }

        let wal = Wal::open(&wal_path)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            wal_path,
            meta_path,
            wal,
            memtable,
            sstables,
            next_sst_id,
            meta,
        })
    }

    pub fn put(&mut self, key: &str, value: &str) -> std::io::Result<()> {
        self.wal.append(&WalRecord::put(key, value))?; // WAL first, fsynced
        self.memtable.put(key, value);
        self.meta.puts += 1;
        self.maybe_flush()
    }

    pub fn delete(&mut self, key: &str) -> std::io::Result<()> {
        self.wal.append(&WalRecord::del(key))?;
        self.memtable.delete(key);
        self.meta.deletes += 1;
        self.maybe_flush()
    }

    pub fn get(&mut self, key: &str) -> Option<String> {
        self.meta.gets += 1;
        if let Some(found) = self.memtable.get(key) {
            return found; // Some(value) or None (tombstone)
        }
        for table in &self.sstables {
            if let Some(found) = table.get(key) {
                return found;
            }
        }
        None
    }

    /// Flush the memtable to a new SSTable (also used by `maybe_flush`).
    /// After the flush the WAL is safe to discard: every record is in
    /// the SSTable now.
    pub fn flush(&mut self) -> std::io::Result<()> {
        if self.memtable.is_empty() {
            return Ok(());
        }
        let entries = self.memtable.entries();
        let id = self.next_sst_id;
        self.next_sst_id += 1;
        let path = sstable_path(&self.dir, id);
        let table = SsTable::write(&path, id, &entries)?;
        self.sstables.insert(0, table); // newest first
        self.memtable.clear();
        self.wal.clear()?; // old WAL records are now durable in the SSTable
        self.wal = Wal::open(&self.wal_path)?; // fresh empty WAL
        self.meta.flushes += 1;
        Ok(())
    }

    fn maybe_flush(&mut self) -> std::io::Result<()> {
        if self.memtable.is_full() {
            self.flush()?;
        }
        Ok(())
    }

    /// Merge all SSTables (plus the memtable, flushed first) into ONE
    /// SSTable, dropping overwritten values and tombstones. After this,
    /// a deleted key is physically gone — a read can no longer find it
    /// in any older layer.
    pub fn compact(&mut self) -> std::io::Result<usize> {
        self.flush()?; // move memtable data into an SSTable first
        if self.sstables.is_empty() {
            // Nothing to merge — and this is not a compaction performed,
            // so do not count it.
            return Ok(0);
        }
        // Newest layer wins. Walk newest -> oldest, keep the first
        // occurrence of each key; drop tombstones entirely. This runs
        // even for a single SSTable: a lone tombstone must be physically
        // removed, not reported as a successful compaction that did
        // nothing.
        let mut merged: BTreeMap<String, Option<String>> = BTreeMap::new();
        for table in &self.sstables {
            for (k, v) in &table.entries {
                merged.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        let live: Vec<(String, Option<String>)> =
            merged.into_iter().filter(|(_, v)| v.is_some()).collect();

        // Write the merged table, then delete the old files.
        let id = self.next_sst_id;
        self.next_sst_id += 1;
        let path = sstable_path(&self.dir, id);
        let new_table = SsTable::write(&path, id, &live)?;
        for old in &self.sstables {
            let _ = fs::remove_file(&old.path);
        }
        // Best effort: make the removal of the old files durable.
        let _ = sync_dir(&self.dir);
        self.sstables = vec![new_table];
        self.meta.compactions += 1;
        Ok(self.sstables.len())
    }

    /// All live (non-deleted) entries whose key starts with `prefix`,
    /// newest value per key, in sorted key order.
    pub fn scan_prefix(&mut self, prefix: &str) -> Vec<(String, String)> {
        // Newest layer first; first occurrence of a key wins, and a
        // tombstone means "deleted, stop looking".
        let mut seen: BTreeMap<String, Option<String>> = BTreeMap::new();
        for (k, v) in self.memtable.scan_prefix(prefix) {
            seen.entry(k).or_insert(v);
        }
        for table in &self.sstables {
            for (k, v) in table.scan_prefix(prefix) {
                seen.entry(k).or_insert(v);
            }
        }
        seen.into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .collect()
    }

    /// Raw scan including tombstone keys (used by tests to verify a
    /// tombstone is physically gone after compaction). Same merge
    /// rules as `scan_prefix`, but keeps `None` values.
    pub fn scan_prefix_raw(&self, prefix: &str) -> Vec<(String, Option<String>)> {
        let mut seen: BTreeMap<String, Option<String>> = BTreeMap::new();
        for (k, v) in self.memtable.scan_prefix(prefix) {
            seen.entry(k).or_insert(v);
        }
        for table in &self.sstables {
            for (k, v) in table.scan_prefix(prefix) {
                seen.entry(k).or_insert(v);
            }
        }
        seen.into_iter().collect()
    }

    pub fn stats(&self) -> Stats {
        Stats {
            memtable_entries: self.memtable.len(),
            sstable_count: self.sstables.len(),
            sstable_entries: self.sstables.iter().map(SsTable::len).sum(),
            puts: self.meta.puts,
            gets: self.meta.gets,
            flushes: self.meta.flushes,
            compactions: self.meta.compactions,
            deletes: self.meta.deletes,
            next_sst_id: self.next_sst_id,
        }
    }

    pub fn memtable_len(&self) -> usize {
        self.memtable.len()
    }

    pub fn sstable_count(&self) -> usize {
        self.sstables.len()
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Persist the cumulative counters (best effort — a failure here
        // must not lose data, it only makes `stats` less complete).
        // The WAL is deliberately NOT touched here: it must survive
        // process exit and be replayed on the next open. It is only
        // cleared inside `flush()`, once its records are safely inside
        // an SSTable.
        if let Ok(text) = serde_json::to_string_pretty(&self.meta) {
            let _ = fs::write(&self.meta_path, text);
        }
    }
}

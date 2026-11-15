// engine.rs — the storage engine: WAL + memtable + SSTables + compaction.
//
// Write path:  WAL (fsync) -> memtable -> flush to SSTable when full.
// Read path:   memtable -> SSTables newest-to-oldest (Bloom filter skips
//              SSTables that definitely lack the key).
// A tombstone in a newer layer hides the same key in older layers.
//
// What V0.1 does NOT do (honest limits, see README):
// - No MVCC snapshots / transactions yet. Reads see the latest value.
// - The PostgreSQL wire protocol lives in pgwire.rs (Simple Query
//   only); the CLI is still the other interface.
// - No background compaction thread; compaction runs only on command.

use crate::lock::DirLock;
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
    /// Cumulative corrupt WAL lines skipped across ALL opens, not just
    /// this one. A flush clears the WAL file, which used to erase the
    /// history; persisting the total here keeps `stats` honest about
    /// lifetime corruption. Each corrupt line is counted ONCE: the two
    /// fields below track what the current WAL file already
    /// contributed, so replaying the same WAL on every open does not
    /// inflate the total (every CLI run reopens the engine). See
    /// `Engine::open` and `Engine::flush` for the bookkeeping.
    /// `#[serde(default)]` for old meta.json files.
    #[serde(default)]
    wal_corrupt_lines: u64,
    /// Corrupt lines in the CURRENT WAL file, as of the last open —
    /// the baseline the cumulative total was last updated from.
    #[serde(default)]
    wal_corrupt_lines_current: u64,
    /// Size in bytes of the WAL file at the last replay. Together
    /// with `wal_corrupt_lines_current` this tells a new generation
    /// (WAL replaced by a flush) apart from the same file replayed
    /// again; `flush()` also resets both fields in memory, and the
    /// reset is persisted when the engine is dropped.
    #[serde(default)]
    wal_size_seen: u64,
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
    /// Line numbers of the corrupt WAL lines skipped during THIS
    /// open's replay (1-based, file order). The count itself is
    /// cumulative in `meta.wal_corrupt_lines`; line numbers only make
    /// sense for the current WAL file, so they are not persisted.
    wal_corrupt_line_numbers: Vec<u64>,
    /// Held for the engine's whole lifetime; declared last so it is
    /// dropped last, after the meta.json write in `Drop`.
    #[allow(dead_code)]
    lock: DirLock,
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
    /// WAL lines that were corrupt and skipped during open-time replay
    /// (V0.2: counted and reported, no longer silently hidden).
    /// CUMULATIVE across all opens, each corrupt line counted ONCE:
    /// a flush clears the WAL file but the lifetime total in
    /// `meta.json` is kept, so `stats` never forgets corruption that
    /// happened before a flush — and reopening the same WAL again
    /// does not count its corrupt lines a second time.
    pub wal_corrupt_lines: u64,
    /// 1-based line numbers of the corrupt WAL lines skipped during
    /// THIS open's replay (empty if this WAL file was clean). Only
    /// this open's lines — after a flush the WAL is a new file, so
    /// these reset while the cumulative count above does not.
    pub wal_corrupt_line_numbers: Vec<u64>,
}

impl Engine {
    /// Open (or create) a database in `dir`. Replays the WAL so data
    /// written before a crash comes back.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        // Lock FIRST, before touching any other file: a second process
        // must fail here, before it can read or rewrite shared state.
        let lock = DirLock::acquire(dir)?;
        let wal_path = dir.join("wal.log");
        let meta_path = dir.join("meta.json");

        // A leftover meta.json.tmp is a half-written meta from a crash
        // mid-save; the atomic rename never reached the final name, so
        // the old meta.json (if any) is still the good one.
        let _ = fs::remove_file(dir.join("meta.json.tmp"));

        // Load cumulative counters (missing file = first run). A corrupt
        // meta.json is quarantined to `meta.json.corrupt.1` (numbered,
        // never overwritten — see quarantine.rs) and counters restart
        // from zero — the DATA is unaffected: it lives in the WAL and
        // SSTables, not in meta.json. Only the lifetime `stats`
        // counters are lost.
        let mut meta = match fs::read_to_string(&meta_path) {
            Ok(text) => match serde_json::from_str::<EngineMeta>(&text) {
                Ok(meta) => meta,
                Err(e) => {
                    match crate::quarantine::quarantine_file(dir, &meta_path) {
                        Ok(quarantine) => eprintln!(
                            "warning: corrupt meta.json quarantined to {} ({e}); \
                             stats counters reset to zero, data is unaffected",
                            quarantine.display()
                        ),
                        Err(rename_err) => eprintln!(
                            "warning: corrupt meta.json could not be quarantined \
                             ({e}; rename failed: {rename_err}); stats counters reset \
                             to zero, data is unaffected"
                        ),
                    }
                    EngineMeta::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => EngineMeta::default(),
            Err(e) => {
                eprintln!("warning: could not read meta.json ({e}); stats counters reset");
                EngineMeta::default()
            }
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
                // unopenable. Quarantine it (rename to a numbered
                // `.corrupt.N`, so it is never re-parsed as a live
                // table, its id is never reused, and an earlier
                // quarantine is never overwritten) and keep going: the
                // WAL and the other SSTables are still recoverable.
                // The quarantined file is kept on disk for inspection,
                // not deleted.
                Err(e) => match crate::quarantine::quarantine_file(dir, &path) {
                    Ok(quarantine) => eprintln!(
                        "warning: quarantined corrupt SSTable {} to {} ({e}); \
                             data in it is unavailable, other data recovered",
                        path.display(),
                        quarantine.display()
                    ),
                    Err(rename_err) => eprintln!(
                        "warning: corrupt SSTable {} could not be quarantined \
                             ({e}; rename failed: {rename_err}); skipping it",
                        path.display()
                    ),
                },
            }
        }

        // Replay the WAL into a fresh memtable. Corrupt lines are
        // counted, not hidden: warn on open (naming the exact line
        // numbers) and keep the count in `stats` (see wal.rs for what
        // happens to lines after a corrupt one — they are still
        // replayed). The count is CUMULATIVE in meta.json: this open
        // adds only the corrupt lines it sees for the FIRST time. The
        // WAL is append-only, so for the same file the replayed count
        // only grows — the growth over the last open's baseline is the
        // new corruption. A smaller file than last time means the WAL
        // was replaced (a flush cleared it): that is a new generation,
        // so its corrupt lines are all new. `flush()` also resets the
        // baseline in memory, which covers the case where the new WAL
        // has already grown past the old file's size.
        let replayed = Wal::replay_reported(&wal_path);
        let wal_len = fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
        if wal_len < meta.wal_size_seen {
            // New WAL generation (flush replaced the file).
            meta.wal_corrupt_lines += replayed.corrupt_lines;
            meta.wal_corrupt_lines_current = replayed.corrupt_lines;
        } else if replayed.corrupt_lines > meta.wal_corrupt_lines_current {
            // Same WAL file, new corrupt line(s) appended since last open.
            meta.wal_corrupt_lines += replayed.corrupt_lines - meta.wal_corrupt_lines_current;
            meta.wal_corrupt_lines_current = replayed.corrupt_lines;
        }
        // Else: same WAL, nothing new — replaying it again must NOT
        // count the same corrupt lines a second time.
        meta.wal_size_seen = wal_len;
        if replayed.corrupt_lines > 0 {
            eprintln!(
                "warning: WAL replay: {} corrupt line(s) skipped in {}; \
                 corrupt line number(s): {:?} (lifetime total: {}); \
                 the affected write(s) are lost, later valid records were still replayed",
                replayed.corrupt_lines,
                wal_path.display(),
                replayed.corrupt_line_numbers,
                meta.wal_corrupt_lines
            );
        }
        let wal_corrupt_line_numbers = replayed.corrupt_line_numbers;
        let mut memtable = MemTable::new();
        for record in replayed.records {
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
            wal_corrupt_line_numbers,
            lock,
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
                                               // The WAL file is now a NEW generation: reset the corrupt-line
                                               // baseline so the next open counts the new file's corrupt lines
                                               // from zero instead of comparing them against the old file's
                                               // count. The cumulative lifetime total above is NOT reset —
                                               // that is the point of persisting it in meta.json (saved on
                                               // drop). `wal_corrupt_line_numbers` is this open's only, and
                                               // is left alone: it describes the WAL this engine opened with.
        self.meta.wal_corrupt_lines_current = 0;
        self.meta.wal_size_seen = 0;
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
            wal_corrupt_lines: self.meta.wal_corrupt_lines,
            wal_corrupt_line_numbers: self.wal_corrupt_line_numbers.clone(),
        }
    }

    /// Cumulative number of corrupt WAL lines skipped across all opens
    /// (persisted in meta.json; a flush does not reset it).
    pub fn wal_corrupt_lines(&self) -> u64 {
        self.meta.wal_corrupt_lines
    }

    /// 1-based line numbers of the corrupt WAL lines skipped during
    /// this open's replay (empty if this WAL file was clean).
    pub fn wal_corrupt_line_numbers(&self) -> &[u64] {
        &self.wal_corrupt_line_numbers
    }

    pub fn memtable_len(&self) -> usize {
        self.memtable.len()
    }

    pub fn sstable_count(&self) -> usize {
        self.sstables.len()
    }
}

impl Engine {
    /// Persist the cumulative counters atomically: write to
    /// `meta.json.tmp`, fsync the file, rename onto `meta.json`, fsync
    /// the directory — the same pattern as SSTable writes and
    /// `TableStore::save`. A crash mid-save therefore leaves either
    /// the old complete meta.json or the new complete one, never a
    /// half-written file at the final name.
    fn save_meta(&self) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(&self.meta)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp_path = self.meta_path.with_extension("json.tmp");
        fs::write(&tmp_path, &text)?;
        {
            let f = fs::OpenOptions::new().write(true).open(&tmp_path)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &self.meta_path)?;
        if let Some(parent) = self.meta_path.parent() {
            sync_dir(parent)?;
        }
        Ok(())
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
        let _ = self.save_meta();
    }
}

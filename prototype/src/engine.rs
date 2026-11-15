// engine.rs — the storage engine: WAL + memtable + SSTables + compaction.
//
// Write path:  WAL (fsync) -> memtable -> flush to SSTable when full.
// Read path:   memtable -> SSTables newest-to-oldest (Bloom filter skips
//              SSTables that definitely lack the key).
// A tombstone in a newer layer hides the same key in older layers.
//
// V0.6 MVCC (see txn.rs for the full design): every key's value slot
// holds a JSON envelope with a chain of versions (`xmin`/`xmax`).
// Reads resolve the chain against a snapshot; writes inside a
// transaction sit in a private buffer until COMMIT, when they are
// written to the WAL (tagged with the transaction id, plus one
// `commit` record) and applied as new versions. The plain
// `put`/`get`/`delete` API keeps its V0.5 meaning — each call is
// one autocommit transaction — so old callers are unaffected.
//
// What V0.6 does NOT do (honest limits, see README):
// - No background compaction thread; compaction runs only on command,
//   and refuses to run while a transaction is live (it prunes
//   version chains, which is only safe with no live snapshots).
//   The online alternative is `VACUUM` (SQL statement and CLI
//   command): it prunes only versions no live snapshot can see,
//   and prunes the committed-transaction set with them, so it is
//   safe while the server runs. Since V0.7 the server also runs
//   VACUUM by itself on a timer (auto-vacuum, see `pgwire.rs`);
//   the operator can still run VACUUM by hand.
// - No 2PC, DDL-in-transaction, or SERIALIZABLE. Savepoints exist
//   since V0.7 (see `txn_savepoint` below).

use crate::lock::DirLock;
use crate::memtable::MemTable;
use crate::sstable::{parse_sstable_id, sstable_path, sync_dir, SsTable};
use crate::txn::{
    decode_chain_limited, dedupe_chain, encode_chain, is_version_visible, looks_like_envelope,
    newest_version, resolve_visible, CommitError, Snapshot, Txn, TxnConflict, Version, LEGACY_XID,
};
use crate::wal::{Wal, WalRecord};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    /// Next transaction id to allocate (V0.6). Persisted so a
    /// restart never reuses an id that already appears in a
    /// version chain; the WAL/SSTable scan on open is the second
    /// line of defence (see `Engine::open`). `#[serde(default)]`
    /// with `1` keeps V0.5 meta.json files readable.
    #[serde(default = "default_next_txn_id")]
    next_txn_id: u64,
    /// Cumulative VACUUM runs (V0.6-fix). `#[serde(default)]`
    /// keeps old `meta.json` files readable.
    #[serde(default)]
    vacuums: u64,
}

fn default_next_txn_id() -> u64 {
    1
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
    /// Transactions that committed in THIS process run, by id.
    /// Anything below `committed_watermark` counts as committed
    /// without being in this set (see below).
    committed: BTreeSet<u64>,
    /// Transactions that aborted in THIS process run, by id
    /// (ROLLBACK, or a COMMIT that failed with a conflict or an
    /// I/O error). Checked BEFORE the watermark in
    /// `is_committed`, so an id that aborted here never reads as
    /// committed even after `VACUUM` advances the watermark
    /// past it. Pruned together with `committed` by `vacuum()`.
    /// Invariant (see `is_committed`): no stored version ever
    /// references an aborted id, because aborted writes never
    /// reach a version chain — so on a restart, ids below the
    /// watermark that never committed have no versions to
    /// misread, and the watermark rule is safe.
    aborted: BTreeSet<u64>,
    /// Every transaction id below this one counts as committed.
    /// Set at open to `next_txn_id`: replay only ever applies
    /// committed transactions, so every id a loaded version chain
    /// can reference is either below the watermark or in
    /// `committed`. Ids at/above the watermark that are neither
    /// committed nor active are aborted.
    committed_watermark: u64,
    /// Bound for trusting an UNPREFIXED (pre-fix) version
    /// envelope found on disk (see `txn::decode_chain_limited`):
    /// `None` trusts any old envelope; `Some(n)` trusts one only
    /// when every id it carries is `< n`. Computed once at open
    /// from the provenance of the directory — a `meta.json` that
    /// exists, or a WAL with transactional records, proves the
    /// directory is a real V0.6 database; a directory with
    /// neither (a bare V0.5-style SSTable) trusts no old envelope
    /// at all (`Some(0)`), so a forged envelope-shaped value is
    /// read back as the plain data it is. New envelopes carry
    /// the `ZENO-MVCC2:` prefix and are unaffected by this bound.
    old_envelope_limit: Option<u64>,
    /// Fail the next `flush()` with an I/O error (test hook for
    /// the commit-flush-failure fix — see `set_flush_failure`).
    /// The flag is consumed by the failing flush.
    flush_fail_once: bool,
    /// Transactions discarded during THIS open's WAL replay
    /// because their commit record's write count did not match
    /// the writes actually buffered (M4: a torn line inside a
    /// committed transaction). Reported in `stats`.
    wal_discarded_txns: u64,
    /// Live transactions, by id. Their writes live only in their
    /// own `Txn.writes` buffers until COMMIT — never in the
    /// memtable, never in the WAL.
    active_txns: HashMap<u64, Txn>,
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
    /// Next transaction id to be allocated (V0.6).
    pub next_txn_id: u64,
    /// Transactions live right now (V0.6).
    pub active_txns: usize,
    /// Transactions in the in-run committed set (V0.6-fix):
    /// `VACUUM` prunes this, so it stays bounded by the number
    /// of transactions since the last VACUUM (plus the live
    /// ones). Ids below the watermark are committed without
    /// being in this set.
    pub committed_txns: usize,
    /// Cumulative VACUUM runs (V0.6-fix).
    pub vacuums: u64,
    /// Transactions discarded during this open's WAL replay
    /// because their commit record's write count did not match
    /// the writes buffered (M4).
    pub wal_discarded_txns: u64,
}

/// The result of a `VACUUM`: how many old versions were pruned,
/// how many SSTables remain, and how many committed ids left the
/// in-memory committed set.
pub struct VacuumReport {
    pub pruned_versions: usize,
    pub sstables: usize,
    pub committed_pruned: usize,
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
        let mut meta_existed = false;
        let mut meta = match fs::read_to_string(&meta_path) {
            Ok(text) => match serde_json::from_str::<EngineMeta>(&text) {
                Ok(meta) => {
                    meta_existed = true;
                    meta
                }
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

        // V0.6 MVCC replay: the WAL holds versioned writes, not
        // plain values. A record WITHOUT a txn id is a V0.5 record:
        // applied at once as a version with xmin 0 (committed before
        // the beginning of time). A record WITH a txn id is buffered
        // per transaction and applied ONLY when that transaction's
        // `commit` record appears later in the file; a transaction
        // with no commit record (crash before commit, or abort)
        // is discarded — its writes never reach the memtable.
        // Within one transaction, only the LAST write per key is
        // kept (intermediate versions were never visible to anyone).
        // `next_txn_id` must end up above every id any loaded
        // version references: the WAL scan gives the ids in the
        // WAL, the SSTable scan gives the ids already flushed
        // (a kill -9 after a flush but before the meta save could
        // otherwise reuse an id that an SSTable envelope already
        // carries — and that id would then read as "aborted").
        if meta.next_txn_id < 1 {
            meta.next_txn_id = 1;
        }
        // Bound for trusting unprefixed (pre-fix) envelopes found
        // in the SSTables (M1 — see the `old_envelope_limit`
        // field docs). A real V0.6 database proves itself with a
        // `meta.json` (bound: its `next_txn_id`, widened by any
        // transaction id the WAL still carries) or with a WAL
        // that holds transactional records at all (then old
        // envelopes are trusted — a forged WAL + SSTable pair is
        // outside this fix's threat model). A directory with
        // neither — a bare V0.5-style SSTable, the reviewer's M1
        // repro — trusts NO old envelope: every envelope-shaped
        // value in it reads back as the plain data it is.
        let wal_max_txn: u64 = replayed
            .records
            .iter()
            .filter_map(|r| r.txn)
            .max()
            .unwrap_or(0);
        let wal_has_txn_records = replayed.records.iter().any(|r| r.txn.is_some());
        let old_envelope_limit: Option<u64> = if meta_existed {
            Some(meta.next_txn_id.max(wal_max_txn.saturating_add(1)))
        } else if wal_has_txn_records {
            None
        } else {
            Some(0)
        };
        let mut max_txn_seen: u64 = 0;
        for table in &sstables {
            for (key, stored) in &table.entries {
                let chain = decode_chain_limited(stored.as_deref(), old_envelope_limit);
                // Loud warning when an envelope-shaped value was
                // REJECTED as an envelope and is being read back as
                // plain data (M1): an operator must see that the
                // value in this SSTable is not what it looks like.
                if let Some(text) = stored.as_deref() {
                    if looks_like_envelope(text)
                        && chain.len() == 1
                        && chain[0].xmin == LEGACY_XID
                        && chain[0].value.as_deref() == Some(text)
                    {
                        eprintln!(
                            "warning: SSTable {} key '{key}': value looks like a version \
                             envelope but its transaction ids are not plausible for this \
                             database (old-envelope bound: {old_envelope_limit:?}); treating \
                             it as plain V0.5 data instead",
                            table.path.display()
                        );
                    }
                }
                for version in chain {
                    max_txn_seen = max_txn_seen.max(version.xmin);
                    if let Some(xmax) = version.xmax {
                        max_txn_seen = max_txn_seen.max(xmax);
                    }
                }
            }
        }
        let mut chains: BTreeMap<String, Vec<Version>> = BTreeMap::new();
        let mut pending: HashMap<u64, BTreeMap<String, Option<String>>> = HashMap::new();
        let mut discarded_writes: u64 = 0;
        let mut discarded_txns: BTreeSet<u64> = BTreeSet::new();
        // Transactions whose commit record's write count did not
        // match the writes actually buffered (M4): a torn line
        // inside a committed transaction.
        let mut count_discarded_txns: BTreeSet<u64> = BTreeSet::new();
        for record in replayed.records {
            if let Some(txn) = record.txn {
                max_txn_seen = max_txn_seen.max(txn);
            }
            match record.op.as_str() {
                "commit" => {
                    // `is_valid` guarantees a commit record has a txn id.
                    let txn = record.txn.unwrap_or(0);
                    // M4: the commit record carries how many writes
                    // this transaction had. If the buffered count
                    // disagrees, a write line was torn or lost on
                    // the way here — the transaction can no longer
                    // be trusted as whole, so discard ALL of it
                    // (never a silent partial commit). A commit
                    // record with no count (written before the fix)
                    // falls back to the old rule: apply whatever
                    // was buffered.
                    let writes = pending.remove(&txn);
                    let buffered = writes.as_ref().map(|w| w.len() as u64).unwrap_or(0);
                    if let Some(expected) = record.count {
                        if buffered != expected {
                            count_discarded_txns.insert(txn);
                            discarded_writes += buffered;
                            discarded_txns.insert(txn);
                            eprintln!(
                                "warning: WAL replay: DISCARDING transaction {txn}: its commit \
                                 record says {expected} write(s) but only {buffered} survived in \
                                 the WAL (a torn/corrupt line inside the transaction) — the \
                                 transaction is not applied at all, not partially"
                            );
                            continue;
                        }
                    }
                    if let Some(writes) = writes {
                        for (key, value) in writes {
                            apply_write(
                                &mut chains,
                                &sstables,
                                &key,
                                txn,
                                value,
                                old_envelope_limit,
                            );
                        }
                    }
                }
                "put" | "del" => {
                    let value = if record.op == "put" {
                        record.value.clone()
                    } else {
                        None
                    };
                    match record.txn {
                        // V0.5 record: immediate, xmin 0.
                        None => apply_write(
                            &mut chains,
                            &sstables,
                            &record.key,
                            LEGACY_XID,
                            value,
                            old_envelope_limit,
                        ),
                        Some(txn) => {
                            pending.entry(txn).or_default().insert(record.key, value);
                        }
                    }
                }
                _ => {}
            }
        }
        // Whatever is still pending never committed: discard it.
        for (txn, writes) in pending {
            discarded_writes += writes.len() as u64;
            discarded_txns.insert(txn);
        }
        if !discarded_txns.is_empty() {
            eprintln!(
                "warning: WAL replay: discarded {discarded_writes} write(s) from \
                 {} uncommitted transaction(s) {:?} in {}; those writes never \
                 committed, so they are gone — only committed data was recovered",
                discarded_txns.len(),
                discarded_txns,
                wal_path.display()
            );
        }
        meta.next_txn_id = meta.next_txn_id.max(max_txn_seen.saturating_add(1));
        let committed_watermark = meta.next_txn_id;
        let mut memtable = MemTable::new();
        for (key, chain) in &chains {
            memtable.put(key, &encode_chain(chain));
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
            committed: BTreeSet::new(),
            aborted: BTreeSet::new(),
            committed_watermark,
            old_envelope_limit,
            flush_fail_once: false,
            wal_discarded_txns: count_discarded_txns.len() as u64,
            active_txns: HashMap::new(),
            lock,
        })
    }

    pub fn put(&mut self, key: &str, value: &str) -> std::io::Result<()> {
        check_key_not_reserved(key)?;
        self.put_internal(key, value)
    }

    /// The internal write path, used by the table and document
    /// stores for their own `table:` / `doc:` keys (m2: those
    /// prefixes are reserved — a raw KV `put` of a `table:` key
    /// used to forge table rows straight past the registry).
    pub(crate) fn put_internal(&mut self, key: &str, value: &str) -> std::io::Result<()> {
        // Autocommit: one statement, one transaction. The write
        // gets a fresh txn id (so a snapshot taken before this
        // statement cannot see it — an xmin of 0 would be visible
        // to every snapshot, which would break snapshot
        // isolation), then the WAL gets the write record PLUS a
        // commit record: two fsyncs per put in V0.6, not one.
        // That is the honest price of MVCC here (see README).
        let txn = self.alloc_txn_id();
        self.wal.append(&WalRecord::put_txn(txn, key, value))?;
        self.wal.append(&WalRecord::commit_count(txn, 1))?;
        self.apply_committed_write(key, txn, Some(value.to_string()));
        self.committed.insert(txn);
        self.meta.puts += 1;
        // M3: the write is durable in the WAL already; a flush
        // failure here must not report the put as failed.
        self.swallow_flush_error("put");
        Ok(())
    }

    /// Apply several writes as ONE autocommit transaction (M6):
    /// one txn id, one WAL record per write, ONE commit record —
    /// so a crash mid-way replays either all of them or none of
    /// them (the commit marker is what makes them durable), and a
    /// multi-row UPDATE/DELETE is a single transaction in the
    /// WAL instead of one transaction per row. Used by the table
    /// store's autocommit UPDATE/DELETE; the single-row `put` /
    /// `delete` above are the one-write case of the same shape.
    pub(crate) fn autocommit_writes(
        &mut self,
        writes: &[(String, Option<String>)],
    ) -> std::io::Result<()> {
        if writes.is_empty() {
            return Ok(());
        }
        let txn = self.alloc_txn_id();
        for (key, value) in writes {
            match value {
                Some(v) => self.wal.append(&WalRecord::put_txn(txn, key, v))?,
                None => self.wal.append(&WalRecord::del_txn(txn, key))?,
            }
        }
        self.wal
            .append(&WalRecord::commit_count(txn, writes.len() as u64))?;
        for (key, value) in writes {
            self.apply_committed_write(key, txn, value.clone());
            match value {
                Some(_) => self.meta.puts += 1,
                None => self.meta.deletes += 1,
            }
        }
        self.committed.insert(txn);
        self.swallow_flush_error("autocommit multi-write");
        Ok(())
    }

    /// A flush failure after the WAL write must never report the
    /// write as failed (M3): the data is durable in the WAL, and
    /// the next write retries the flush (the memtable is still
    /// full). Log it loudly instead of returning the error.
    fn swallow_flush_error(&mut self, what: &str) {
        if let Err(e) = self.maybe_flush() {
            eprintln!(
                "warning: {what}: the write is durable in the WAL, but the memtable flush \
                 failed ({e}); data is safe, the flush will be retried on the next write"
            );
        }
    }

    pub fn delete(&mut self, key: &str) -> std::io::Result<()> {
        check_key_not_reserved(key)?;
        self.delete_internal(key)
    }

    /// Internal delete path for the table/document stores (m2 —
    /// see `put_internal`).
    pub(crate) fn delete_internal(&mut self, key: &str) -> std::io::Result<()> {
        // Autocommit delete: same two-record pattern as `put`
        // (write + commit), applied as a delete version.
        let txn = self.alloc_txn_id();
        self.wal.append(&WalRecord::del_txn(txn, key))?;
        self.wal.append(&WalRecord::commit_count(txn, 1))?;
        self.apply_committed_write(key, txn, None);
        self.committed.insert(txn);
        self.meta.deletes += 1;
        // M3: see `swallow_flush_error`.
        self.swallow_flush_error("delete");
        Ok(())
    }

    /// Test/diagnostic hook (M3): make the next `flush()` fail
    /// with an I/O error instead of writing an SSTable. The flag
    /// is consumed by that failing flush, so a test can prove a
    /// commit (or put) still succeeds when its flush fails.
    pub fn set_flush_failure(&mut self, fail: bool) {
        self.flush_fail_once = fail;
    }

    /// Length of the version chain for `key` (B1 regression
    /// hook): the number of versions the read path actually
    /// merges across all layers, after dedupe. A key written 5
    /// times and flushed after each write must report 5, however
    /// many flushes happened.
    pub fn version_chain_len(&self, key: &str) -> usize {
        self.chain_for(key).len()
    }

    /// Read the latest COMMITTED value of a key (a fresh snapshot:
    /// every statement outside a transaction sees the newest
    /// committed data). Snapshot reads use `txn_get` /
    /// `txn_scan_prefix` instead.
    pub fn get(&mut self, key: &str) -> Option<String> {
        self.meta.gets += 1;
        let snapshot = self.current_snapshot();
        let chain = self.chain_for(key);
        resolve_visible(&chain, &snapshot, None, &|xid| self.is_committed(xid))
    }

    /// Flush the memtable to a new SSTable (also used by `maybe_flush`).
    /// After the flush the WAL is safe to discard: every record is in
    /// the SSTable now.
    ///
    /// B1: the flush writes only the DELTA — only versions the
    /// SSTables do not already hold (matched by `xmin`). The old
    /// code wrote the memtable's whole envelope (the full chain)
    /// into every new SSTable while the old SSTable kept its own
    /// copy of the chain, so the chain length doubled on every
    /// flush (2, 3, 6, 12, 24 entries for 5 versions). With the
    /// delta, one version is stored once, in exactly one SSTable
    /// — and `chain_for` dedupes by `xmin` as well, so SSTables
    /// written by the old code (which already hold duplicated
    /// chains) still read correctly.
    pub fn flush(&mut self) -> std::io::Result<()> {
        if self.flush_fail_once {
            // Test hook (M3): consume the flag and fail, without
            // touching the memtable or the WAL.
            self.flush_fail_once = false;
            return Err(std::io::Error::other(
                "injected flush failure (test hook: set_flush_failure)",
            ));
        }
        if self.memtable.is_empty() {
            return Ok(());
        }
        let mut delta: Vec<(String, Option<String>)> = Vec::new();
        for (key, stored) in self.memtable.entries() {
            let Some(value) = stored else {
                // A legacy tombstone (no envelope): pass through.
                delta.push((key, None));
                continue;
            };
            let chain = self.decode_stored(Some(&value));
            // Versions this key already has in an SSTable, from
            // every layer. Only `xmin`s are compared: a version
            // superseded in the memtable (its `xmax` set there)
            // is NOT re-written — the superseding version sits in
            // a newer layer, and the read path scans newest-first,
            // so the stale `xmax: null` on the old copy can never
            // hide the newer version or resurrect the old one.
            // Re-writing it would store every version twice.
            let mut flushed: BTreeSet<u64> = BTreeSet::new();
            for table in &self.sstables {
                if let Some(found) = table.get(&key) {
                    for version in self.decode_stored(found.as_deref()) {
                        flushed.insert(version.xmin);
                    }
                }
            }
            let new_versions: Vec<Version> = chain
                .into_iter()
                .filter(|v| !flushed.contains(&v.xmin))
                .collect();
            if new_versions.is_empty() {
                continue;
            }
            delta.push((key, Some(encode_chain(&new_versions))));
        }
        if delta.is_empty() {
            // Everything in the memtable was already durable in an
            // SSTable (e.g. a flush right after open, when the
            // memtable was seeded from the SSTables): no new
            // SSTable is needed, but the memtable and the WAL can
            // still be cleared — every WAL record is already in
            // an SSTable too.
            self.memtable.clear();
            self.wal.clear()?; // old WAL records are now durable in the SSTable
            self.wal = Wal::open(&self.wal_path)?; // fresh empty WAL
            self.meta.wal_corrupt_lines_current = 0;
            self.meta.wal_size_seen = 0;
            self.meta.flushes += 1;
            return Ok(());
        }
        let id = self.next_sst_id;
        self.next_sst_id += 1;
        let path = sstable_path(&self.dir, id);
        let table = SsTable::write(&path, id, &delta)?;
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
    ///
    /// V0.6: the merge is over VERSION CHAINS, not plain values.
    /// Each key's chain is concatenated oldest-first across all
    /// layers, then pruned to its NEWEST version only — and a key
    /// whose newest version is a delete is dropped entirely.
    /// Pruning is safe ONLY because there is no live snapshot to
    /// protect: compaction refuses to run while any transaction
    /// is active (the server never calls it; the CLI runs it in a
    /// one-shot process with no transactions at all).
    pub fn compact(&mut self) -> std::io::Result<usize> {
        if !self.active_txns.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot compact while a transaction is active: compaction \
                 prunes old row versions, which a live snapshot may still need",
            ));
        }
        self.flush()?; // move memtable data into an SSTable first
        if self.sstables.is_empty() {
            // Nothing to merge — and this is not a compaction performed,
            // so do not count it.
            return Ok(0);
        }
        // Oldest layer first, so each key's versions concatenate in
        // chain order (oldest -> newest); `dedupe_chain` collapses
        // any version the old flush bug stored twice (B1).
        let mut merged: BTreeMap<String, Vec<Version>> = BTreeMap::new();
        for table in self.sstables.iter().rev() {
            for (k, v) in &table.entries {
                merged
                    .entry(k.clone())
                    .or_default()
                    .extend(self.decode_stored(v.as_deref()));
            }
        }
        let live: Vec<(String, Option<String>)> = merged
            .into_iter()
            .map(|(k, chain)| (k, dedupe_chain(vec![chain])))
            .filter_map(|(k, chain)| {
                let newest = newest_version(&chain)?;
                // Newest version is a delete: drop the key entirely.
                newest.value.as_ref()?;
                // Prune the chain to its newest version only.
                Some((k, Some(encode_chain(std::slice::from_ref(newest)))))
            })
            .collect();

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
        // No transaction is live (checked above), so every id
        // below `next_txn_id` is covered by the watermark now:
        // the committed/aborted sets can be emptied (M5).
        self.committed_watermark = self.meta.next_txn_id;
        self.committed.clear();
        self.aborted.clear();
        self.meta.compactions += 1;
        Ok(self.sstables.len())
    }

    /// Online VACUUM (M5): prune version chains and the
    /// committed set while the server is running, without
    /// disturbing any live snapshot.
    ///
    /// The watermark is the oldest live snapshot's `next_xid`
    /// (or `next_txn_id` when no transaction is live). A version
    /// is kept when it is (a) the newest version of its key
    /// (conflict checks read the newest version), (b) created
    /// at/after the watermark (`xmin >= watermark` — it may
    /// still become visible to a future snapshot), or (c) the
    /// newest version visible to some live snapshot. Everything
    /// else is invisible to every live snapshot and to every
    /// future one, so it can go. The committed set is pruned to
    /// ids `>= watermark` and the watermark itself advances to
    /// cover the pruned ids (see `is_committed` for the
    /// invariant that makes that safe). A key whose newest kept
    /// version is a delete is dropped entirely, but only when
    /// no live snapshot exists — with a live snapshot the delete
    /// version stays, so older versions stay hidden from it.
    ///
    /// Unlike `compact()`, this runs WITH live transactions:
    /// the server exposes it as the `VACUUM` SQL statement and
    /// the `vacuum` CLI command, so a long-running server can
    /// be vacuumed periodically instead of waiting for a
    /// (refused) CLI compaction.
    pub fn vacuum(&mut self) -> std::io::Result<VacuumReport> {
        let snapshots: Vec<Snapshot> = self
            .active_txns
            .values()
            .map(|t| t.snapshot.clone())
            .collect();
        let watermark = snapshots
            .iter()
            .map(|s| s.next_xid)
            .min()
            .unwrap_or(self.meta.next_txn_id);
        let committed_before = self.committed.len();
        self.committed.retain(|id| *id >= watermark);
        self.aborted.retain(|id| *id >= watermark);
        let committed_pruned = committed_before - self.committed.len();
        self.committed_watermark = self.committed_watermark.max(watermark);
        self.flush()?; // move memtable data into an SSTable first
        if self.sstables.is_empty() {
            return Ok(VacuumReport {
                pruned_versions: 0,
                sstables: 0,
                committed_pruned,
            });
        }
        let mut merged: BTreeMap<String, Vec<Version>> = BTreeMap::new();
        for table in self.sstables.iter().rev() {
            for (k, v) in &table.entries {
                merged
                    .entry(k.clone())
                    .or_default()
                    .extend(self.decode_stored(v.as_deref()));
            }
        }
        let mut pruned = 0usize;
        let mut live: Vec<(String, Option<String>)> = Vec::new();
        for (k, chain) in merged {
            let chain = dedupe_chain(vec![chain]);
            let total = chain.len();
            let keep = self.vacuum_keep_indices(&chain, watermark, &snapshots);
            pruned += total - keep.len();
            if keep.is_empty() {
                continue;
            }
            let kept: Vec<Version> = keep.iter().map(|&i| chain[i].clone()).collect();
            let newest = kept.last().expect("keep is non-empty");
            if newest.value.is_none() && snapshots.is_empty() {
                // Newest kept version is a delete and no live
                // snapshot needs it: drop the key entirely.
                pruned += kept.len();
                continue;
            }
            live.push((k, Some(encode_chain(&kept))));
        }
        if pruned == 0 {
            // M3 (V0.7 review): nothing was pruned, so rewriting
            // every SSTable into a fresh one would be a byte-for-
            // byte copy that only burns a new SSTable id (and a
            // full rewrite on every auto-vacuum tick). Skip the
            // rewrite: the live data is already durable exactly
            // as it is, in the existing SSTables. The vacuum
            // still counts as a run (the committed set above was
            // pruned), and a flush that just moved memtable data
            // into a new SSTable is untouched by this skip.
            self.meta.vacuums += 1;
            return Ok(VacuumReport {
                pruned_versions: 0,
                sstables: self.sstables.len(),
                committed_pruned,
            });
        }
        let id = self.next_sst_id;
        self.next_sst_id += 1;
        let path = sstable_path(&self.dir, id);
        let new_table = SsTable::write(&path, id, &live)?;
        for old in &self.sstables {
            let _ = fs::remove_file(&old.path);
        }
        let _ = sync_dir(&self.dir);
        self.sstables = vec![new_table];
        self.meta.vacuums += 1;
        Ok(VacuumReport {
            pruned_versions: pruned,
            sstables: self.sstables.len(),
            committed_pruned,
        })
    }

    /// Indices of the versions of `chain` a VACUUM must keep
    /// (see `vacuum` for the rule).
    fn vacuum_keep_indices(
        &self,
        chain: &[Version],
        watermark: u64,
        snapshots: &[Snapshot],
    ) -> Vec<usize> {
        let mut keep: BTreeSet<usize> = BTreeSet::new();
        // (a) the newest version overall.
        if let Some(last) = chain.len().checked_sub(1) {
            keep.insert(last);
        }
        // (b) versions created at/after the watermark.
        for (i, v) in chain.iter().enumerate() {
            if v.xmin >= watermark {
                keep.insert(i);
            }
        }
        // (c) the newest version visible to each live snapshot.
        for snapshot in snapshots {
            for (i, v) in chain.iter().enumerate().rev() {
                if is_version_visible(v, snapshot, None, &|xid| self.is_committed(xid)) {
                    keep.insert(i);
                    break;
                }
            }
        }
        keep.into_iter().collect()
    }

    /// All live (non-deleted) entries whose key starts with `prefix`,
    /// newest COMMITTED value per key, in sorted key order. A fresh
    /// snapshot: this is the autocommit read path. Snapshot reads
    /// use `txn_scan_prefix` instead.
    pub fn scan_prefix(&mut self, prefix: &str) -> Vec<(String, String)> {
        let snapshot = self.current_snapshot();
        let mut out = Vec::new();
        for key in self.keys_with_prefix(prefix) {
            let chain = self.chain_for(&key);
            if let Some(value) =
                resolve_visible(&chain, &snapshot, None, &|xid| self.is_committed(xid))
            {
                out.push((key, value));
            }
        }
        out
    }

    /// Raw scan including deleted keys (used by tests to verify a
    /// deleted key is physically gone after compaction). Returns
    /// each key's NEWEST version — `None` when the newest version
    /// is a delete — regardless of snapshots. Same merge rules as
    /// `scan_prefix`, but keeps `None` values.
    pub fn scan_prefix_raw(&self, prefix: &str) -> Vec<(String, Option<String>)> {
        let mut out = Vec::new();
        for key in self.keys_with_prefix(prefix) {
            let chain = self.chain_for(&key);
            if let Some(newest) = newest_version(&chain) {
                out.push((key, newest.value.clone()));
            }
        }
        out
    }

    /// Every key with `prefix` in any layer (memtable + SSTables),
    /// deduplicated, in sorted order. The layers hold version
    /// envelopes, not plain values, so this only collects keys —
    /// callers resolve each key's chain themselves.
    fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
        let mut keys: BTreeSet<String> = BTreeSet::new();
        for (k, _) in self.memtable.scan_prefix(prefix) {
            keys.insert(k);
        }
        for table in &self.sstables {
            for (k, _) in table.scan_prefix(prefix) {
                keys.insert(k);
            }
        }
        keys.into_iter().collect()
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
            next_txn_id: self.meta.next_txn_id,
            active_txns: self.active_txns.len(),
            committed_txns: self.committed.len(),
            vacuums: self.meta.vacuums,
            wal_discarded_txns: self.wal_discarded_txns,
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

    /// Next transaction id to be allocated (V0.6; also in `stats`).
    pub fn next_txn_id(&self) -> u64 {
        self.meta.next_txn_id
    }
}

// ---------------------------------------------------------------------
// MVCC transactions (V0.6). See txn.rs for the design.
// ---------------------------------------------------------------------

impl Engine {
    /// Allocate a fresh transaction id. Persisted in `meta.json`
    /// on drop, and recovered from the WAL/SSTables on open, so an
    /// id that reached disk is never reused.
    fn alloc_txn_id(&mut self) -> u64 {
        let id = self.meta.next_txn_id;
        self.meta.next_txn_id = self.meta.next_txn_id.saturating_add(1);
        id
    }

    /// Is `xid` committed? Id 0 (pre-MVCC data) always is; ids
    /// below the watermark count as committed (replay only ever
    /// applies committed transactions, and `VACUUM` only advances
    /// the watermark past ids no stored version can reference —
    /// see the `aborted` field docs); otherwise the in-run
    /// committed set decides. Active and aborted ids are NOT
    /// committed — the aborted set is checked BEFORE the
    /// watermark, so an id that aborted in this run never reads
    /// as committed even after the watermark passes it.
    fn is_committed(&self, xid: u64) -> bool {
        if xid == LEGACY_XID {
            return true;
        }
        if self.aborted.contains(&xid) {
            return false;
        }
        xid < self.committed_watermark || self.committed.contains(&xid)
    }

    /// Decode one stored value with this engine's envelope bound
    /// (M1): prefixed envelopes are always trusted, unprefixed
    /// old envelopes only within `old_envelope_limit`, and
    /// anything else is a plain legacy value.
    fn decode_stored(&self, stored: Option<&str>) -> Vec<Version> {
        decode_chain_limited(stored, self.old_envelope_limit)
    }

    /// A snapshot of "right now": the next id to allocate, and
    /// the transactions currently active. Autocommit reads use
    /// this; `begin` builds the same shape for its own snapshot.
    fn current_snapshot(&self) -> Snapshot {
        Snapshot {
            next_xid: self.meta.next_txn_id,
            active: self.active_txns.keys().copied().collect(),
        }
    }

    /// The full version chain for a key, oldest-first: SSTable
    /// envelopes oldest-to-newest, then the memtable envelope.
    /// Layers are deduped by `xmin` (B1): a version stored twice
    /// — by the old flush bug, or by a delta flush re-writing a
    /// version whose `xmax` changed — appears once, with the
    /// newest layer's copy winning.
    fn chain_for(&self, key: &str) -> Vec<Version> {
        let mut layers = Vec::new();
        for table in self.sstables.iter().rev() {
            if let Some(found) = table.get(key) {
                layers.push(self.decode_stored(found.as_deref()));
            }
        }
        if let Some(found) = self.memtable.get(key) {
            layers.push(self.decode_stored(found.as_deref()));
        }
        dedupe_chain(layers)
    }

    /// Append a committed version to a key's chain in the
    /// memtable: the previous newest version gets `xmax = xmin`,
    /// then the new version is pushed and the whole chain is
    /// re-encoded as the key's envelope value.
    fn apply_committed_write(&mut self, key: &str, xmin: u64, value: Option<String>) {
        let mut chain = self.chain_for(key);
        if let Some(last) = chain.last_mut() {
            if last.xmax.is_none() {
                last.xmax = Some(xmin);
            }
        }
        chain.push(Version::new(xmin, value));
        self.memtable.put(key, &encode_chain(&chain));
    }

    /// BEGIN: allocate an id and take its snapshot (the next id to
    /// be allocated, plus the transactions active right now).
    /// The transaction's writes will live only in its buffer
    /// until COMMIT.
    pub fn begin(&mut self) -> u64 {
        let id = self.alloc_txn_id();
        let snapshot = self.current_snapshot();
        self.active_txns.insert(id, Txn::new(id, snapshot));
        id
    }

    /// Is `txn` still active?
    pub fn txn_active(&self, txn: u64) -> bool {
        self.active_txns.contains_key(&txn)
    }

    fn no_such_txn(txn: u64) -> String {
        format!(
            "no active transaction {txn} (it may have committed, rolled back, \
             or never begun — run BEGIN first)"
        )
    }

    /// Buffer a write in the transaction. Nothing touches the
    /// WAL or the memtable until COMMIT.
    pub fn txn_put(&mut self, txn: u64, key: &str, value: &str) -> Result<(), String> {
        let t = self
            .active_txns
            .get_mut(&txn)
            .ok_or_else(|| Self::no_such_txn(txn))?;
        t.writes.insert(key.to_string(), Some(value.to_string()));
        Ok(())
    }

    /// Buffer a delete in the transaction.
    pub fn txn_delete(&mut self, txn: u64, key: &str) -> Result<(), String> {
        let t = self
            .active_txns
            .get_mut(&txn)
            .ok_or_else(|| Self::no_such_txn(txn))?;
        t.writes.insert(key.to_string(), None);
        Ok(())
    }

    /// Read a key as this transaction sees it: its own buffered
    /// write first, otherwise its BEGIN snapshot.
    pub fn txn_get(&mut self, txn: u64, key: &str) -> Result<Option<String>, String> {
        let snapshot = {
            let t = self
                .active_txns
                .get(&txn)
                .ok_or_else(|| Self::no_such_txn(txn))?;
            if let Some(value) = t.writes.get(key) {
                return Ok(value.clone());
            }
            t.snapshot.clone()
        };
        let chain = self.chain_for(key);
        Ok(resolve_visible(&chain, &snapshot, Some(txn), &|xid| {
            self.is_committed(xid)
        }))
    }

    /// Scan a prefix as this transaction sees it: its BEGIN
    /// snapshot, overlaid with its own buffered writes (a
    /// buffered delete hides the row; a buffered put shows the
    /// new value even for a key the snapshot never had).
    pub fn txn_scan_prefix(
        &mut self,
        txn: u64,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, String> {
        let (snapshot, buffered) = {
            let t = self
                .active_txns
                .get(&txn)
                .ok_or_else(|| Self::no_such_txn(txn))?;
            (
                t.snapshot.clone(),
                t.writes
                    .range(prefix.to_string()..)
                    .take_while(|(k, _)| k.starts_with(prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<BTreeMap<String, Option<String>>>(),
            )
        };
        let mut out = Vec::new();
        let layer_keys = self.keys_with_prefix(prefix);
        for key in &layer_keys {
            if let Some(value) = buffered.get(key) {
                if let Some(value) = value {
                    out.push((key.clone(), value.clone()));
                }
                continue;
            }
            let chain = self.chain_for(key);
            if let Some(value) =
                resolve_visible(&chain, &snapshot, Some(txn), &|xid| self.is_committed(xid))
            {
                out.push((key.clone(), value));
            }
        }
        // Buffered keys the snapshot never had (brand-new rows):
        // they are not in any layer's key set yet.
        for (key, value) in buffered {
            if !layer_keys.contains(&key) {
                if let Some(value) = value {
                    out.push((key, value));
                }
            }
        }
        // The overlay loop above pushed snapshot rows in sorted
        // key order; the buffered-new rows appended here may be
        // out of order — sort so callers always see sorted rows.
        out.sort();
        Ok(out)
    }

    /// COMMIT: first-committer-wins. For each key this
    /// transaction wrote, if the newest committed version was
    /// created by a transaction that committed AFTER this
    /// transaction's snapshot began, the commit fails with a
    /// conflict and the transaction is aborted (its buffer is
    /// dropped — nothing was ever written to disk for it).
    /// Otherwise the writes go to the WAL (one record per write,
    /// each tagged with the txn id, then ONE commit record
    /// carrying the write count (M4) — fsynced in order, so a
    /// crash before the commit record leaves the transaction
    /// uncommitted on replay) and are applied to the memtable
    /// as new versions.
    pub fn commit(&mut self, txn: u64) -> Result<(), CommitError> {
        let txn_data = self
            .active_txns
            .remove(&txn)
            .ok_or_else(|| CommitError::Unknown(Self::no_such_txn(txn)))?;
        for key in txn_data.writes.keys() {
            let chain = self.chain_for(key);
            if let Some(newest) = newest_version(&chain) {
                let xmin = newest.xmin;
                if xmin != LEGACY_XID
                    && self.is_committed(xmin)
                    && (xmin >= txn_data.snapshot.next_xid
                        || txn_data.snapshot.active.contains(&xmin))
                {
                    // The transaction is aborted: remember the id
                    // explicitly (m4), so it never reads as
                    // committed via the watermark later.
                    self.aborted.insert(txn);
                    return Err(CommitError::Conflict(TxnConflict { key: key.clone() }));
                }
            }
        }
        let write_count = txn_data.writes.len() as u64;
        for (key, value) in &txn_data.writes {
            let appended = match value {
                Some(v) => self.wal.append(&WalRecord::put_txn(txn, key, v)),
                None => self.wal.append(&WalRecord::del_txn(txn, key)),
            };
            if let Err(e) = appended {
                self.aborted.insert(txn);
                return Err(CommitError::Io(e));
            }
        }
        if let Err(e) = self.wal.append(&WalRecord::commit_count(txn, write_count)) {
            self.aborted.insert(txn);
            return Err(CommitError::Io(e));
        }
        for (key, value) in &txn_data.writes {
            self.apply_committed_write(key, txn, value.clone());
            match value {
                Some(_) => self.meta.puts += 1,
                None => self.meta.deletes += 1,
            }
        }
        self.committed.insert(txn);
        // M3: the commit is durable in the WAL already; a flush
        // failure here must not report the commit as failed (the
        // old code did exactly that, against its own comment).
        // Log it and return Ok — the flush is retried on the
        // next write. (In practice the memtable only flushes at
        // 64 entries.)
        self.swallow_flush_error("commit");
        Ok(())
    }

    /// ROLLBACK: drop the write buffer. Nothing was ever written
    /// to the WAL or the memtable for this transaction, so there
    /// is nothing to undo on disk. The id is remembered in the
    /// aborted set (m4).
    pub fn rollback(&mut self, txn: u64) -> Result<(), String> {
        match self.active_txns.remove(&txn) {
            Some(_) => {
                self.aborted.insert(txn);
                Ok(())
            }
            None => Err(Self::no_such_txn(txn)),
        }
    }

    /// SAVEPOINT (V0.7): remember the transaction's write buffer
    /// under `name`, so a later ROLLBACK TO can restore it. A
    /// savepoint with the same name does NOT delete the earlier
    /// one: the new savepoint hides the old one (PostgreSQL
    /// behaviour, M1 of the V0.7 review — the old code dropped
    /// the earlier savepoint, so `RELEASE` of the new one made
    /// `ROLLBACK TO` fail with 3B001 instead of rolling back to
    /// the first savepoint). `RELEASE` removes only the newest
    /// savepoint of that name and reveals the older one again;
    /// `ROLLBACK TO` addresses the newest one.
    pub fn txn_savepoint(&mut self, txn: u64, name: &str) -> Result<(), String> {
        let t = self
            .active_txns
            .get_mut(&txn)
            .ok_or_else(|| Self::no_such_txn(txn))?;
        t.savepoints.push(crate::txn::Savepoint {
            name: name.to_string(),
            writes: t.writes.clone(),
        });
        Ok(())
    }

    /// ROLLBACK TO SAVEPOINT (V0.7): restore the write buffer to
    /// the buffer the named savepoint captured, dropping every
    /// write made after it. The named savepoint itself STAYS, so
    /// rolling back to it again still works; savepoints made
    /// after it are gone (they described a buffer state that no
    /// longer exists). Unknown name: 3B001 at the SQL layer.
    pub fn txn_rollback_to_savepoint(&mut self, txn: u64, name: &str) -> Result<(), String> {
        let t = self
            .active_txns
            .get_mut(&txn)
            .ok_or_else(|| Self::no_such_txn(txn))?;
        let pos = t
            .savepoints
            .iter()
            .rposition(|s| s.name == name)
            .ok_or_else(|| format!("no such savepoint '{name}'"))?;
        let saved = t.savepoints[pos].writes.clone();
        t.writes = saved;
        t.savepoints.truncate(pos + 1);
        Ok(())
    }

    /// RELEASE SAVEPOINT (V0.7): forget the NEWEST savepoint of
    /// the name — and every savepoint made after it, which only
    /// made sense on top of it. When the same name was used
    /// twice, releasing the newest reveals the older one again,
    /// so a later ROLLBACK TO that name rolls back to the older
    /// savepoint (PostgreSQL behaviour). Only when no savepoint
    /// of that name is left does a later ROLLBACK TO fail with
    /// 3B001 (at the SQL layer).
    pub fn txn_release_savepoint(&mut self, txn: u64, name: &str) -> Result<(), String> {
        let t = self
            .active_txns
            .get_mut(&txn)
            .ok_or_else(|| Self::no_such_txn(txn))?;
        let pos = t
            .savepoints
            .iter()
            .rposition(|s| s.name == name)
            .ok_or_else(|| format!("no such savepoint '{name}'"))?;
        t.savepoints.truncate(pos);
        Ok(())
    }
}

/// Reject a raw KV key whose prefix belongs to the table or
/// document stores (m2). Those stores write `table:` / `doc:`
/// keys through `put_internal` / `delete_internal` /
/// `autocommit_writes`; the public `put` / `delete` (and the
/// CLI) must not be able to forge rows or documents past the
/// registry.
fn check_key_not_reserved(key: &str) -> std::io::Result<()> {
    for prefix in ["table:", "doc:"] {
        if key.starts_with(prefix) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "key prefix '{prefix}' is reserved for internal table/document storage — \
                     use the table or doc commands instead of a raw put"
                ),
            ));
        }
    }
    Ok(())
}

/// Append one committed version to a key's chain during WAL
/// replay (a free function so `Engine::open` can use it while
/// building its first memtable). The chain is seeded from the
/// SSTables when the key is first touched; the previous newest
/// version gets `xmax = xmin`, then the new version is pushed.
/// The seeded chain is deduped by `xmin` (B1), so SSTables
/// written by the old flush bug do not duplicate versions on
/// replay either.
fn apply_write(
    chains: &mut BTreeMap<String, Vec<Version>>,
    sstables: &[SsTable],
    key: &str,
    xmin: u64,
    value: Option<String>,
    old_envelope_limit: Option<u64>,
) {
    let chain = chains.entry(key.to_string()).or_insert_with(|| {
        let mut chain = Vec::new();
        for table in sstables.iter().rev() {
            if let Some(found) = table.get(key) {
                chain.extend(decode_chain_limited(found.as_deref(), old_envelope_limit));
            }
        }
        dedupe_chain(vec![chain])
    });
    // Idempotent replay: a crash between the SSTable write of a
    // flush and the WAL clear leaves the same version in both
    // places. If this (non-legacy) `xmin` is already in the
    // chain, the write is already durable — pushing it again
    // would duplicate the `xmin` (and the re-encoded chain would
    // fail the well-formedness check), so skip it. Legacy
    // (`xmin = 0`) records are exempt: several V0.5 records for
    // one key legitimately share `xmin 0`, each superseding the
    // previous — `dedupe_chain` keeps the last of them.
    if xmin != LEGACY_XID && chain.iter().any(|v| v.xmin == xmin) {
        return;
    }
    if let Some(last) = chain.last_mut() {
        if last.xmax.is_none() {
            last.xmax = Some(xmin);
        }
    }
    chain.push(Version::new(xmin, value));
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

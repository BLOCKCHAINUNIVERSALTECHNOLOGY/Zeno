# Zeno — One Engine, All Data (V0.2 prototype)

> **Zeno is a hybrid SQL + JSON database in Rust — not ZenoDB (Lantern, Go
> time-series) and not ZenDB.** The name was chosen knowing those exist.

Zeno V0.2 is a small, working, single-node database prototype. One engine
stores three kinds of data: **key-value**, **tables**, and **JSON
documents**. It is written in Rust using only `std` + `serde` +
`serde_json` — no heavy dependencies, no external database engine.

## What is new in V0.2

- **Lock file (`LOCK`).** One data directory can be opened by only one
  process at a time. A second process gets a clear error: "data
  directory already in use / locked by another process". The lock file
  holds the owner process's PID; on open, a PID that is no longer alive
  (checked via Linux `/proc/<pid>`) is recognised as stale — e.g. after
  `kill -9` — and safely taken over, so a crash never leaves the
  database permanently locked. Method: `O_EXCL` create + PID check,
  std-only (no `flock`, no `libc` crate); see `src/lock.rs` for the
  reasoning and the honest limits (single machine only, no NFS).
  Two race guards: an empty/unparseable LOCK file is never deleted at
  once — a contender polls it (20 ms at a time) until a PID appears or
  it has stayed empty for ~100 ms (its mtime is that old), so a live
  creator between `create_new` and its PID write is not mistaken for a
  torn file; and the creator re-reads the file after writing its PID
  and fails if it no longer holds its own PID (its write went to an
  unlinked inode). A concurrent test (12 processes x 5 rounds) proves
  exactly one holder ever wins.
- **Corrupt `tables.json` fails closed.** A corrupt registry used to
  silently reset to "no tables", so recreating a table restarted
  `next_row_id` at 1 and overwrote the old row 1. Now a parse error
  quarantines `tables.json` to `tables.json.corrupt` and open FAILS
  with a clear error, before any create/insert can touch the old rows.
  Opening also fails while a quarantine exists and `tables.json` is
  missing, so retrying the command cannot silently become an empty
  registry either. An operator must inspect the quarantine and restore
  it as `tables.json` (or delete it, accepting the registry loss)
  before the database opens again. This is stricter than `meta.json`
  on purpose: corrupt `meta.json` only loses stats counters, which the
  disk scan rebuilds — corrupt `tables.json` loses `next_row_id`,
  which nothing can rebuild.
- **WAL replay strictness.** A corrupt WAL line is no longer silently
  skipped: it is counted, a warning is printed on open, and `stats`
  shows `wal corrupt lines`. Policy, stated in `src/wal.rs`: a corrupt
  line is skipped and counted, ONLY that line — valid lines after it
  are still replayed, because each line is one independent, fsynced
  record. A corrupt "put" means only that one write is lost; the key
  keeps its older value, it is not deleted. A corrupt "del" means the
  delete itself is lost, so the key's older value comes back alive on
  replay. The warning now names the exact corrupt line number(s)
  (e.g. `corrupt line number(s): [2]`), and the count is CUMULATIVE
  across all opens, persisted in `meta.json`: a flush clears the WAL
  file but the lifetime total is kept, and each corrupt line is
  counted once — reopening the same WAL does not inflate the total.
- **`meta.json` atomic write.** Counters are now saved the same way
  SSTables and `tables.json` already were: temp file + fsync + rename
  + directory fsync. A crash mid-save can no longer leave a
  half-written `meta.json`. A corrupt `meta.json` is quarantined to
  `meta.json.corrupt` (kept for inspection) and counters restart from
  zero — the data itself is unaffected, it lives in the WAL and
  SSTables, not in `meta.json`.
- **Bloom filter scales with entry count.** Was fixed 1 KiB / 3 hashes;
  now 16 bits per key with a 1 KiB minimum, still 3 hashes, so the
  false-positive rate stays near 0.5% however large the table gets. A
  fixed 1 KiB filter holding 5000 keys is ~60% false positives (it
  barely filters); the scaled filter at 5000 keys is still ~0.5%.
  False negatives remain impossible. Old V0.1 SSTables still open:
  the filter size is encoded in its hex string.
- **New diagnostic command** `zeno hold <seconds>` — opens the engine
  and holds its lock for N seconds, so the lock behaviour can be
  demonstrated and tested (used by `demo.sh` and the lock tests).
- Version is now **0.2.0** (Cargo.toml, CLI, README).

## What works in V0.2

- **Key-Value** — `put` / `get` / `del`. Deletes are tombstones: the key
  disappears from reads immediately and is physically removed by
  compaction.
- **WAL (Write-Ahead Log)** — every write is appended to `wal.log` and
  fsynced *before* it touches the memtable. On open, the WAL is replayed,
  so data written before a crash comes back. Format: one JSON record per
  line, `{"op":"put","key":"...","value":"..."}` or
  `{"op":"del","key":"..."}`. A torn/corrupt line is counted and
  reported (see "What is new in V0.2"), not silently hidden: the
  warning names its line number(s), and the count is cumulative
  across opens (persisted in `meta.json`, counted once per line).
- **MemTable** — an in-memory `BTreeMap` (sorted keys). It flushes to disk
  at 64 entries (small on purpose, so flushing is easy to see).
- **SSTables** — immutable sorted files on disk (`sst-000001.sst`, ...).
  Each carries a Bloom filter (16 bits per key, minimum 1 KiB, 3 hashes)
  so reads can skip SSTables that definitely do not contain the key.
  The filter is teaching-grade, not a production-tuned one. SSTable writes are
  atomic (`.tmp` file + fsync + rename + directory fsync); a corrupt
  SSTable is quarantined to `*.sst.corrupt` on open instead of making
  the whole database unopenable, and leftover `*.tmp` files are
  deleted on open.
- **Read path** — memtable first, then SSTables newest-to-oldest. A
  tombstone in a newer layer hides the same key in older layers.
- **Tables** — `CREATE TABLE`-like registration (column names stored in
  `tables.json`), `INSERT` rows, `SELECT` with an optional
  `column=value` filter. Rows are stored as keys
  `table:<name>:<row-id>`. **There is no real SQL parser** — SELECT is a
  simple scan filter. `INSERT` persists the next row id (atomically
  written `tables.json`) before writing the row, so a crash cannot
  reuse an id and overwrite the previous row (worst case: a gap).
  A corrupt `tables.json` is quarantined to `tables.json.corrupt` and
  open FAILS instead of silently resetting to an empty registry (see
  "What is new in V0.2") — a silent reset would let a recreated table
  overwrite old rows.
- **JSON documents** — `put` a JSON object under
  `doc:<collection>:<id>`, `get` it back, `find` by one field equals a
  value. `find` is a **linear scan** over the collection in V0.2 — no
  index yet.
- **Compaction** — merges all SSTables into one, dropping overwritten
  versions and tombstoned keys.
- **Crash recovery (process crash / restart only)** — proven by the
  demo: stop the process, reopen the same data directory, and the
  data is still there. WAL, SSTable, `tables.json` and `meta.json`
  writes are all atomic/fsynced now, but this is still **not proven
  power-loss safety**: it has been tested with process kills and
  restarts, not with a sudden power cut, and the OS/disk flush path
  has not been independently verified.
- **One process at a time per data directory.** Enforced by the `LOCK`
  file in V0.2 (see above) — a second process is refused with a clear
  error instead of silently corrupting shared files.
- **`del` on a missing key prints OK even though nothing existed.**
  Delete is unconditional: it writes a tombstone whether or not the
  key was there.

## What does NOT work yet (honest limits)

- **No PostgreSQL wire protocol.** `psql`, DBeaver, Python `psycopg`
  cannot connect yet. The CLI is the only interface. (Planned for a
  later version, as the design doc promises.)
- **No MVCC snapshots / transactions.** Reads see the latest value;
  there is no `BEGIN`/`COMMIT`/`ROLLBACK`, no snapshot isolation.
- **No real SQL parser.** No `JOIN`, no `WHERE` beyond one
  `column=value`, no `UPDATE`/`DELETE` on tables.
- **No secondary index on documents.** `doc find` scans the whole
  collection linearly.
- **No multi-node / replication / clustering.** Single node only.
- **SSTables are fully loaded into memory on open.** Fine for a
  prototype, not for large data.
- **No authentication, no encryption at rest.** Anyone with the data
  directory can read it.
- **Lock file is single-machine only.** It does not protect a data
  directory shared over NFS, and a reused PID could in theory make a
  stale lock look live briefly (see `src/lock.rs`).
- **Not production-ready.** No independent audit, no benchmark against
  other databases. No speed claims are made anywhere in this repo.

## How the engine works (short version)

```
write:  WAL (fsync) -> memtable -> flush at 64 entries -> SSTable
read:   memtable -> SSTables, newest first (Bloom filter skips misses)
delete: tombstone in memtable/WAL -> compaction removes it for real
```

## How to run

```bash
cargo build --release
./target/release/zeno --help

# Key-value
./target/release/zeno --data ./my-data put greeting "hello zeno"
./target/release/zeno --data ./my-data get greeting
./target/release/zeno --data ./my-data del greeting

# Table
./target/release/zeno --data ./my-data table create users id,name,city
./target/release/zeno --data ./my-data table insert users 1,Sanjay,Delhi
./target/release/zeno --data ./my-data table select users city=Delhi

# JSON document
./target/release/zeno --data ./my-data doc put profiles u1 '{"name":"Sanjay","city":"Delhi"}'
./target/release/zeno --data ./my-data doc get profiles u1
./target/release/zeno --data ./my-data doc find profiles city=Delhi

# Maintenance
./target/release/zeno --data ./my-data flush
./target/release/zeno --data ./my-data compact
./target/release/zeno --data ./my-data stats
./target/release/zeno --data ./my-data hold 5   # diagnostic: hold the lock 5s
```

## Demo

```bash
./demo.sh
```

Runs the full end-to-end scenario: key-value, table, JSON document,
forced flushes (70 puts), compaction, then **reopens the same data
directory in fresh processes and reads everything back** — the
crash-recovery proof — then the V0.2 additions: a live lock holder
refusing a second process, `kill -9` of the holder followed by a
successful reopen (stale-lock takeover), and a torn WAL line that is
warned about and counted in `stats` while the data stays safe.

## Tests

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- 20 unit tests (Bloom filter incl. scaling, WAL incl. corrupt-middle
  counting and corrupt line numbers, lock incl. stale takeover,
  memtable, SSTable)
- 18 integration tests (the 10 from V0.1, plus: second open fails while
  first is open, stale lock reopens after `kill -9`, 12 concurrent
  holders yield exactly one winner (x 5 rounds), corrupt WAL middle
  line counted + data safe, corrupt WAL count cumulative across
  reopen + flush, corrupt `meta.json` opens + data safe, corrupt
  `tables.json` fails open + quarantines + old row survives, scaled
  Bloom filter on a large SSTable)
- 38 tests total, all passing.

## Project layout

```
src/
  main.rs      CLI (subcommands only; the engine lives in the library)
  lib.rs       library root
  engine.rs    WAL + memtable + SSTables + compaction + read path
  lock.rs      LOCK file: one process per data dir, stale-PID takeover
  wal.rs       append + fsync + replay (one JSON record per line, corrupt lines counted)
  memtable.rs  in-memory BTreeMap, tombstones, 64-entry flush threshold
  sstable.rs   immutable sorted files, Bloom filter stored alongside
  bloom.rs     Bloom filter, scaled: 16 bits/key, min 1 KiB, 3 hashes
  table.rs     table registry + insert/select over prefixed keys
  doc.rs       JSON documents + linear-scan find
tests/
  engine_tests.rs   integration tests (each in its own temp directory)
demo.sh        end-to-end demo incl. restart / crash-recovery proof + V0.2 lock/WAL demos
```

## License

Apache-2.0. See the design doc
`../Zeno-design-hindi.md` for the full plan (V1 scope, funding path,
and the honest limits).

# Zeno — One Engine, All Data (V0.1 prototype)

> **Zeno is a hybrid SQL + JSON database in Rust — not ZenoDB (Lantern, Go
> time-series) and not ZenDB.** The name was chosen knowing those exist.

Zeno V0.1 is a small, working, single-node database prototype. One engine
stores three kinds of data: **key-value**, **tables**, and **JSON
documents**. It is written in Rust using only `std` + `serde` +
`serde_json` — no heavy dependencies, no external database engine.

## What works in V0.1

- **Key-Value** — `put` / `get` / `del`. Deletes are tombstones: the key
  disappears from reads immediately and is physically removed by
  compaction.
- **WAL (Write-Ahead Log)** — every write is appended to `wal.log` and
  fsynced *before* it touches the memtable. On open, the WAL is replayed,
  so data written before a crash comes back. Format: one JSON record per
  line, `{"op":"put","key":"...","value":"..."}` or
  `{"op":"del","key":"..."}`. A torn trailing line (crash mid-write) is
  skipped, not fatal.
- **MemTable** — an in-memory `BTreeMap` (sorted keys). It flushes to disk
  at 64 entries (small on purpose, so flushing is easy to see).
- **SSTables** — immutable sorted files on disk (`sst-000001.sst`, ...).
  Each carries a small Bloom filter (1 KiB, 3 hashes) so reads can skip
  SSTables that definitely do not contain the key. The filter is small
  and teaching-grade, not a production-tuned one. SSTable writes are
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
- **JSON documents** — `put` a JSON object under
  `doc:<collection>:<id>`, `get` it back, `find` by one field equals a
  value. `find` is a **linear scan** over the collection in V0.1 — no
  index yet.
- **Compaction** — merges all SSTables into one, dropping overwritten
  versions and tombstoned keys.
- **Crash recovery (process crash / restart only)** — proven by the
  demo: stop the process, reopen the same data directory, and the
  data is still there. This is **not** power-loss safety: SSTable
  writes are atomic (temp file + fsync + rename + directory fsync)
  and the WAL is fsynced, but `meta.json` / `tables.json` directory
  fsyncs are not all guaranteed, so a sudden power cut (as opposed
  to a process kill/restart) can still lose the latest counters or
  table registry.
- **One process at a time per data directory.** There is no lock file
  yet — do not open the same data directory from two processes at
  once.
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
```

## Demo

```bash
./demo.sh
```

Runs the full end-to-end scenario: key-value, table, JSON document,
forced flushes (70 puts), compaction, then **reopens the same data
directory in fresh processes and reads everything back** — the
crash-recovery proof.

## Tests

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- 10 unit tests (Bloom filter, WAL, memtable, SSTable)
- 10 integration tests (KV put/get/delete, WAL replay after reopen,
  memtable flush to SSTable, read-after-flush, compaction removes
  duplicates + tombstones, table insert/select, doc put/find, delete
  survives flush/reopen, truncated-SSTable quarantine + WAL recovery,
  delete of a key in an older SSTable survives reopen + compaction,
  single-SSTable compaction drops a lone tombstone)

## Project layout

```
src/
  main.rs      CLI (subcommands only; the engine lives in the library)
  lib.rs       library root
  engine.rs    WAL + memtable + SSTables + compaction + read path
  wal.rs       append + fsync + replay (one JSON record per line)
  memtable.rs  in-memory BTreeMap, tombstones, 64-entry flush threshold
  sstable.rs   immutable sorted files, Bloom filter stored alongside
  bloom.rs     small Bloom filter (1 KiB, 3 hashes, teaching-grade)
  table.rs     table registry + insert/select over prefixed keys
  doc.rs       JSON documents + linear-scan find
tests/
  engine_tests.rs   integration tests (each in its own temp directory)
demo.sh        end-to-end demo incl. restart / crash-recovery proof
```

## License

Apache-2.0. See the design doc
`../Zeno-design-hindi.md` for the full plan (V1 scope, funding path,
and the honest limits).

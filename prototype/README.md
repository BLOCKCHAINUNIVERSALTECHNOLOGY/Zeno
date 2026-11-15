# Zeno — One Engine, All Data (V0.4 prototype)

> **Zeno is a hybrid SQL + JSON database in Rust — not ZenoDB (Lantern, Go
> time-series) and not ZenDB.** The name was chosen knowing those exist.

Zeno V0.4 is a small, working, single-node database prototype. One engine
stores three kinds of data: **key-value**, **tables**, and **JSON
documents**. It is written in Rust using `std` + `serde` +
`serde_json` + small RustCrypto crates (`sha2`, `hmac`, `pbkdf2`,
`base64`, `getrandom`, `subtle`) for SCRAM-SHA-256 auth — no heavy
dependencies, no external database engine. V0.4 adds the **extended
query protocol** (Parse/Bind/Describe/Execute/Sync, prepared
statements with `$1` parameters) and **SCRAM-SHA-256 password auth**
to the PostgreSQL wire protocol server (`zeno serve`), so `psql`,
DBeaver, Python `psycopg` and any libpq client can connect with
prepared statements as well as Simple Query.

> **⚠️ LOCAL PROTOTYPE ONLY. With no users configured, `zeno serve`
> accepts EVERY local client with NO password (trust auth) and
> listens only on 127.0.0.1. With users configured (`zeno user
> set-password`), SCRAM-SHA-256 password auth is required — but
> there is still no SSL and no encryption, so the SCRAM exchange
> itself travels in plaintext over loopback. Never expose this port
> to a network, never run it on a shared machine, and never use it
> in production. Anyone on the same machine can read and change all
> your data. See "Password auth (SCRAM-SHA-256)" below.**

## What is new in V0.4

- **Extended query protocol (`src/extended.rs`).** Parse/Bind/
  Describe/Execute/Close/Sync now really work, over the same four
  statements as Simple Query (CREATE TABLE / INSERT / SELECT with
  one `column=value` WHERE filter / DELETE). Written from the
  official PostgreSQL docs ("Message Flow" 54.2.3, "Message
  Formats" 54.7, protocol 3.0). Unnamed + named statements and
  portals; `$1`, `$2` parameters — text format, plus binary int4
  (4 bytes big-endian) and binary text; param types text (OID 25,
  the default when the client leaves a type unspecified) and int4
  (OID 23), any other declared OID is 0A000. Parse validates the
  SQL (one statement only — a multi-statement string is 42601),
  the statement kind, the placeholders (gaps like `$1` + `$3`
  are 42P18) and the types; a failed Parse never stores anything.
  A failed Parse drops the stored statement of that name and a
  failed Bind drops the portal of that name (PostgreSQL
  behaviour), so a later Bind/Execute fails with "does not
  exist" instead of silently running the old query — the only
  exceptions are the duplicate-name errors (42P05/42P03), where
  the stored object is the one being protected. Parameters are
  capped at 32767 (a ParameterDescription count is an Int16, so
  more would wrap negative — Parse rejects them with 54000).
  Describe(S) checks table/column existence BEFORE sending
  ParameterDescription, so a missing table gets only the
  ErrorResponse. `/* */` block comments are supported in Simple
  Query and Parse (a `$2` inside one is not a parameter, a `;`
  inside one never splits); a literal `')'` value inserts fine.
  Describe answers ParameterDescription + RowDescription (or
  NoData for non-SELECT and empty statements). Execute sends
  RowDescription + DataRow + CommandComplete, and honours max
  rows: a limited Execute ends with PortalSuspended and the next
  Execute resumes from the same cached rows; a completed portal
  re-runs fresh on the next Execute. Close answers CloseComplete
  (closing a nonexistent name is not an error); closing a
  statement also closes its portals. Named statements/portals
  must be Closed before redefinition (42P05 / 42P03); the unnamed
  ones may be re-Parsed/re-Bound freely. A Simple Query destroys
  the unnamed statement and portal. Substitution happens at the
  TOKEN level, never by editing the SQL text, so a bound value can
  never be re-parsed as SQL. Error recovery follows the protocol
  exactly: after an extended-protocol error the server sends ONE
  ErrorResponse and then reads and discards every message until
  Sync — even a Simple Query smuggled into the same pipeline is
  discarded, never run — and Sync sends exactly one
  ReadyForQuery. Verified by 12 new raw-TCP tests in
  `tests/pgwire_tests.rs` (pipelined batch, params, named
  reuse, int4 text+binary, error-skip, PortalSuspended resume,
  Close/redefine rules, Describe/NoData, binary result format,
  NULL param, Simple-Query-clears-unnamed).
  Honest deviations from PostgreSQL, stated plainly: Execute
  repeats the RowDescription (PostgreSQL sends it only on
  Describe) so clients that skip Describe still learn the column
  names; Parse checks syntax and parameter types only, while
  table/column existence is checked at Bind/Describe/Execute
  (42P01/42703 there, the same codes a Simple Query reports);
  a bound SQL NULL becomes the empty string (Zeno has no NULLs).
  (An earlier draft of this README said a failed Parse leaves a
  previously stored statement untouched — that was the V0.4
  review finding #1, fixed: a failed Parse now drops it.)
- **SCRAM-SHA-256 password auth (`src/auth.rs`, `zeno user`).**
  `zeno user set-password <name>` (password asked twice on
  stdin), `zeno user list`, `zeno user remove <name>`. The
  password is NEVER stored: `users.json` in the data directory
  keeps only the SCRAM verifier (random 16-byte salt, 4096
  PBKDF2-HMAC-SHA256 iterations — PostgreSQL's default, kept at
  4096 — StoredKey, ServerKey), written atomically and explicitly
  mode 0600 (never umask-dependent, so no 0644 verifier under
  umask 022). Passwords must be at least 8 characters (a
  1-character password is rejected). Passwords go through
  SASLprep (RFC 4013: NBSP and friends map to a space, then
  NFKC) before PBKDF2, on both the `set-password` side and the
  client side, so a libpq-style client that SASLpreps logs in
  with the same verifier. With users configured, every connection must do
  the full SCRAM exchange (AuthenticationSASL → client-first →
  server-first → client-final → server-final → AuthenticationOk,
  mutual auth: the server proves itself back to the client);
  a wrong password or unknown user ends in ErrorResponse 28P01
  and the connection is closed. Unknown users get a FAKE exchange
  (salt + keys derived deterministically from the username and a
  per-data-dir server secret in `server-secret`, mode 0600 — the
  SAME unknown username gets the SAME fake salt on every
  handshake, a different username a different one) so the
  handshake leaks nothing about whether a username exists.
  `users.json` is re-read on EVERY connection,
  so a password set while the server runs applies to new
  connections at once, no restart. A corrupt `users.json` fails
  the connection (and `serve` at startup) instead of silently
  falling back to trust auth — and an EMPTY (0-byte) `users.json`
  is corrupt, not "no users": only a MISSING file means trust
  auth, an empty file makes `serve` exit (rc=1). The crypto is pinned to the
  RFC 7677 §3 test vectors in the unit tests (the SHA-256 example
  — not the RFC 5802 SHA-1 one, which has the same
  username/password but different values), and 4 raw-TCP
  integration tests drive the whole handshake (success, wrong
  password, unknown user, password-set-after-start, plus
  deterministic fake salt, NBSP/SASLprep login, strict
  client-first parsing, and set-password on a missing data
  directory). The client-first message is parsed strictly: a
  duplicate `n=`/`r=` is rejected (never silently last-wins)
  and a client nonce shorter than 8 characters is rejected.
  Honest limits: no SSL, so the exchange travels in plaintext over
  loopback (a captured proof cannot be replayed — the nonce is
  fresh every time — and the password never crosses the wire);
  no channel binding (there is no TLS to bind to); PBKDF2 at
  4096 iterations is PostgreSQL's default, modest for a
  prototype; the `set-password` prompt echoes the password as
  you type (stdin read, no hidden-input crate) — use a private
  terminal. New dependencies, all small and widely reviewed
  RustCrypto crates: `sha2 0.10`, `hmac 0.12`, `pbkdf2 0.12`,
  `base64 0.22`, `getrandom 0.2`, `subtle 2` — plus
  `unicode-normalization 0.1` for the SASLprep NFKC step (added
  with the V0.4 review fixes).
- **Refactor for the two new modules.** `pgwire.rs` (1221 lines
  in V0.3) is now 1404 lines: statement execution returns a
  `StmtOutcome` (rows or a CommandComplete tag) instead of
  writing wire bytes directly, so Simple Query and extended
  Execute share one execution path, and the SELECT parser is a
  reusable `parse_select`. The extended protocol lives in
  `src/extended.rs` (940 lines), SCRAM in `src/auth.rs`
  (724 lines). No file is over 1500 lines.
- Version is now **0.4.0** (Cargo.toml, CLI, README).

## What was new in V0.3

- **PostgreSQL wire protocol (`zeno serve`, `src/pgwire.rs`).**
  `zeno serve --port <port> --data <dir>` listens on
  `127.0.0.1:<port>` (default 5432) and speaks PostgreSQL frontend/
  backend protocol 3.0, written from the official PostgreSQL docs
  (startup message, AuthenticationOk, Simple Query 'Q',
  RowDescription 'T', DataRow 'D', CommandComplete 'C',
  ReadyForQuery 'Z', ErrorResponse 'E') — std `TcpListener` only,
  no pgwire crate, no new dependency. Startup handshake with trust
  auth (AuthenticationOk for every client, **local prototype only —
  see the warning above**), ParameterStatus (`server_version`,
  `client_encoding`, `standard_conforming_strings`), BackendKeyData,
  ReadyForQuery 'I' after every query. SSLRequest is answered 'N'
  (no SSL); CancelRequest closes silently. Supported SQL subset,
  mapped onto the engine's table API: `CREATE TABLE name (col, ...)`,
  `INSERT INTO name VALUES (...)`, `SELECT [cols] FROM name
  [WHERE col = value]`, `DELETE FROM name [WHERE col = value]`.
  All values travel as text (type OID 25). One Query message may
  hold several `;`-separated statements; each runs in turn, then one
  ReadyForQuery. Unsupported SQL (UPDATE, DROP, BEGIN, ...) gets a
  proper ErrorResponse with a SQLSTATE code (0A000 feature not
  supported, 42601 syntax error, 42P01 undefined table, 42703
  undefined column, 42P07 table already exists) — the connection is
  NOT closed and NOT crashed, the next query still works. One
  connection serves query after query; a client disconnect never
  stops the server; clients run one thread each behind one Mutex, so
  concurrent clients share one engine safely; a second server on the
  same data directory fails with the LOCK error. `server_version`
  is reported as "18.0" — that is the PostgreSQL version whose wire
  protocol this implements, so clients that parse the version do not
  choke; Zeno is NOT PostgreSQL, and the README says so plainly.
  Verified by `tests/pgwire_tests.rs`: a hand-rolled raw-TCP client
  that parses the reply bytes (see "Tests" — `psql` is not installed
  in this sandbox, so the tests speak the protocol directly).
- **Numbered quarantine files (`src/quarantine.rs`).** V0.2
  overwrote the old quarantine on the next corruption
  (`meta.json.corrupt` was deleted and re-created), so the FIRST
  corrupt file could silently disappear. Now every quarantine is
  numbered and never overwritten: `meta.json.corrupt.1`, then
  `.corrupt.2`, and so on — for `meta.json`, `tables.json`, and
  SSTables alike. The table registry's fail-closed check now looks
  for any numbered (or legacy V0.2 unnumbered) quarantine.
- **WAL `del` strictness, now in the README too (was only a comment
  in `src/wal.rs`).** Policy: a corrupt line is skipped and counted,
  ONLY that line — valid lines after it are still replayed. That has
  one sharp edge, stated honestly here: **if the lost line was a
  `del`, the delete itself is lost, so the key's older value comes
  back alive on replay** (it still sits in an SSTable, and nothing
  re-applies the delete). A corrupt `put` only loses that one write;
  the key keeps its older value, it is not deleted. This is the
  deliberate price of never throwing later valid records away with
  the corrupt line. Proven by a new test
  (`corrupt_wal_del_line_resurrects_old_value`), not just a comment.
- **`TableStore::delete`** — delete table rows (used by SQL DELETE);
  rows are tombstoned through the engine like KV `del`.
- Version is now **0.3.0** (Cargo.toml, CLI, README).

## What was new in V0.2

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
  quarantines `tables.json` to `tables.json.corrupt.1` (V0.3: numbered,
  never overwritten) and open FAILS
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
  `meta.json.corrupt.1` (V0.3: numbered, never overwritten — see
  `src/quarantine.rs`) and counters restart from zero — the data
  itself is unaffected, it lives in the WAL and SSTables, not in
  `meta.json`.
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

## What works in V0.4

- **PostgreSQL wire protocol** — `zeno serve` (see "What is new in
  V0.4" above). `psql` / libpq clients connect over TCP on
  127.0.0.1 and run CREATE TABLE / INSERT / SELECT (one
  `column=value` WHERE filter) / DELETE, over Simple Query AND the
  extended protocol (prepared statements, `$1` params, named +
  unnamed statements/portals, PortalSuspended resume). **Auth:
  trust auth (no password) while no users are configured, SCRAM-
  SHA-256 password auth once a user exists — local prototype only
  (see the warning at the top and "Password auth" below).**
- **Password auth (SCRAM-SHA-256)** — `zeno user set-password
  <name>` / `list` / `remove` (see "How to run"). The password is
  never stored, only its SCRAM verifier in `users.json`; the
  server re-reads it on every new connection, so a password set
  while the server runs applies at once. Unknown users get a fake
  exchange and still fail with 28P01; a corrupt `users.json`
  fails connections instead of silently falling back to trust
  auth. No SSL — the exchange travels in plaintext over loopback;
  a captured proof cannot be replayed (fresh nonce every time).
- **Key-Value** — `put` / `get` / `del`. Deletes are tombstones: the key
  disappears from reads immediately and is physically removed by
  compaction.
- **WAL (Write-Ahead Log)** — every write is appended to `wal.log` and
  fsynced *before* it touches the memtable. On open, the WAL is replayed,
  so data written before a crash comes back. Format: one JSON record per
  line, `{"op":"put","key":"...","value":"..."}` or
  `{"op":"del","key":"..."}`. A torn/corrupt line is counted and
  reported (see "What was new in V0.2"), not silently hidden: the
  warning names its line number(s), and the count is cumulative
  across opens (persisted in `meta.json`, counted once per line).
  One sharp edge, stated in "What was new in V0.3": a corrupt `del`
  line loses the delete, so the key's older value comes back alive.
- **MemTable** — an in-memory `BTreeMap` (sorted keys). It flushes to disk
  at 64 entries (small on purpose, so flushing is easy to see).
- **SSTables** — immutable sorted files on disk (`sst-000001.sst`, ...).
  Each carries a Bloom filter (16 bits per key, minimum 1 KiB, 3 hashes)
  so reads can skip SSTables that definitely do not contain the key.
  The filter is teaching-grade, not a production-tuned one. SSTable writes are
  atomic (`.tmp` file + fsync + rename + directory fsync); a corrupt
  SSTable is quarantined to `*.sst.corrupt.1` (numbered, never
  overwritten) on open instead of making the whole database
  unopenable, and leftover `*.tmp` files are deleted on open.
- **Read path** — memtable first, then SSTables newest-to-oldest. A
  tombstone in a newer layer hides the same key in older layers.
- **Tables** — `CREATE TABLE`-like registration (column names stored in
  `tables.json`), `INSERT` rows, `SELECT` with an optional
  `column=value` filter. Rows are stored as keys
  `table:<name>:<row-id>`. **There is no real SQL parser** — SELECT is a
  simple scan filter. `INSERT` persists the next row id (atomically
  written `tables.json`) before writing the row, so a crash cannot
  reuse an id and overwrite the previous row (worst case: a gap).
  A corrupt `tables.json` is quarantined to `tables.json.corrupt.1`
  (numbered, never overwritten) and open FAILS instead of silently
  resetting to an empty registry (see "What was new in V0.2") — a
  silent reset would let a recreated table overwrite old rows.
- **JSON documents** — `put` a JSON object under
  `doc:<collection>:<id>`, `get` it back, `find` by one field equals a
  value. `find` is a **linear scan** over the collection in V0.4 — no
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

- **No SSL.** The server answers SSLRequest with 'N'. SCRAM
  password auth exists (see above), but without TLS the SCRAM
  exchange itself is plaintext on loopback, and there is no
  channel binding. Still local-prototype-only — see the warning
  at the top.
- **Bound NULL becomes the empty string.** Zeno has no NULLs: a
  parameter bound as SQL NULL is stored as `""`, and a missing
  column reads back as `""` (never NULL) — same as V0.3's
  DataRow behaviour.
- **Extended protocol deviations (documented in "What is new in
  V0.4"):** Execute repeats the RowDescription (PostgreSQL
  sends it only on Describe); Parse checks syntax and parameter
  types only, table/column existence is checked at
  Bind/Describe/Execute; a failed Parse leaves a previously
  stored statement untouched.
- **No MVCC snapshots / transactions.** Reads see the latest value;
  there is no `BEGIN`/`COMMIT`/`ROLLBACK`, no snapshot isolation.
- **No real SQL parser.** No `JOIN`, no `WHERE` beyond one
  `column=value`, no `UPDATE`/`DELETE` on tables via the CLI (SQL
  DELETE exists over the wire protocol), no `ORDER BY` / `LIMIT`.
  Everyday DDL/SQL that real tools emit is NOT accepted yet and
  returns a 42601 syntax error, so psql/DBeaver users should keep
  to the subset in "How to run": `VARCHAR(10)` or `SERIAL PRIMARY
  KEY` in a column definition, a column list in `INSERT INTO t (a,
  b) VALUES (...)`, `WHERE id > 1` (only `=` is supported), and
  `ORDER BY` / `LIMIT` are all unsupported.
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
- **Remaining risks, deferred to V0.5 (review findings, not
  fixed here):** no rate-limiting or account lockout on failed
  SCRAM logins (an attacker can guess passwords without delay);
  no connection limit (threads are unbounded — 200 idle
  connections already grow the server); a poisoned engine Mutex
  fails every statement with XX000 instead of recovering; and
  concurrent `zeno user set-password` processes can race and
  lose each other's users (no file lock around the
  read-modify-write of `users.json`).
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

# PostgreSQL wire protocol (V0.4) — server keeps running until killed
./target/release/zeno --data ./my-data serve --port 5433

# Password auth (SCRAM-SHA-256): set a password, then the server
# requires it on every new connection (no restart needed).
# The password is asked twice on stdin and echoes as you type —
# use a private terminal. The password itself is never stored.
./target/release/zeno --data ./my-data user set-password sanjay
./target/release/zeno --data ./my-data user list
./target/release/zeno --data ./my-data user remove sanjay
```

**Connect with `psql`** (on a machine that has it — this sandbox does
not; `which psql` finds nothing here, so the tests and the demo speak
raw TCP instead and parse the reply bytes):

```bash
psql -h 127.0.0.1 -p 5433 -U zeno -d zeno   # no password: trust auth, LOCAL ONLY
```

```sql
CREATE TABLE users (id, name, city);
INSERT INTO users VALUES (1, 'Sanjay', 'Delhi');
INSERT INTO users VALUES (2, 'Asha', 'Mumbai');
SELECT * FROM users WHERE city = 'Delhi';
SELECT id, name FROM users;
DELETE FROM users WHERE id = 2;
SELECT * FROM users;
```

Notes for real clients: with no users configured, any
username/database is accepted (trust auth); once a user exists,
that user must log in with SCRAM-SHA-256 (wrong password:
28P01, connection closed). Every column is text, so `CREATE TABLE
t (id int, name text)` works but `id` is still stored and returned
as text; several statements separated by `;` in one query all run;
an unsupported statement returns an error and the connection stays
usable. Prepared statements work now — `psycopg` (v3) sends
Parse/Bind/Describe/Execute/Sync by default once a query has run
`prepare_threshold` times (default 5); `prepare_threshold=0`
prepares every query:

```python
import psycopg

# No users configured: no password (trust auth, LOCAL ONLY).
# With a user set: password="..." is required (SCRAM-SHA-256).
conn = psycopg.connect(
    "host=127.0.0.1 port=5433 user=sanjay dbname=zeno",
    prepare_threshold=0,  # every query via the extended protocol
)
cur = conn.execute(
    "SELECT name FROM users WHERE city = %s", ("Delhi",)
)
print(cur.fetchall())  # parameters travel as $1, never as SQL text
conn.close()
```

```sql
-- The same prepared statement, as psql would run it:
PREPARE find_city(text) AS SELECT name FROM users WHERE city = $1;
-- (SQL-level PREPARE/EXECUTE are NOT supported — only the wire
-- protocol Parse/Bind/Execute. The example above is what a driver
-- sends on the wire; in psql itself, use plain Simple Query.)
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
warned about and counted in `stats` while the data stays safe — and
the V0.3 addition: `zeno serve` on 127.0.0.1:5433 with a raw-TCP
Python client (no `psql` in this sandbox) running CREATE / INSERT /
SELECT / an unsupported UPDATE (ErrorResponse, connection survives),
then a second server on the same data directory refused by the lock —
and the V0.4 addition: the same client pipelines
Parse+Describe+Bind+Describe+Execute+Sync with a `$1` parameter,
fetches rows one at a time (PortalSuspended), then sets a password
with `zeno user set-password` and logs in with a full SCRAM-SHA-256
handshake (Python `hashlib` client), plus a wrong-password
rejection (28P01, connection closed).

## Tests

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- 60 unit tests (the 50 from V0.4, plus: SASLprep mapping +
  NFKC + prohibited characters, the 8-character minimum
  password, `users.json` mode 0600, `set-password` creating a
  missing data directory, deterministic fake salt per username,
  strict client-first parsing incl. duplicate `n=`/`r=` and the
  8-character minimum nonce, and the 32767 parameter cap)
- 22 integration tests in `tests/engine_tests.rs` (the 18 from V0.2,
  plus: second tables.json corruption keeps the first quarantine,
  second meta.json corruption keeps the first quarantine, second
  SSTable corruption keeps the first quarantine, corrupt WAL `del`
  line resurrects the old value)
- 37 integration tests in `tests/pgwire_tests.rs` (the 27 from
  V0.4, plus 10 review-fix regressions: failed Parse drops the
  old statement, failed Bind drops the old portal, Describe(S)
  on a missing table sends only the ErrorResponse, block
  comments in Parse/Simple Query, INSERT of a literal `')'`
  value + `CREATE TABLE "a""b"`, the 32767 parameter cap,
  deterministic fake salt for unknown users, NBSP-password login
  via the SASLprep'd form, strict client-first parsing, and
  `set-password` on a missing data directory)
- 119 tests total, all passing.

**How the wire protocol is verified without `psql`:** `psql` is not
installed in this sandbox, so `tests/pgwire_tests.rs` builds the
StartupMessage and Query ('Q') frames byte by byte, sends them over
a real TCP socket to a real `zeno serve` process, and parses the
reply bytes into AuthenticationOk / ParameterStatus / BackendKeyData /
RowDescription / DataRow / CommandComplete / ErrorResponse /
ReadyForQuery — the same framing and message flow a real client
sees. On a machine with `psql`, use the commands in "How to run".

## Project layout

```
src/
  main.rs      CLI (subcommands incl. `serve` and `user`; the engine lives in the library)
  lib.rs       library root
  engine.rs    WAL + memtable + SSTables + compaction + read path
  pgwire.rs    PostgreSQL wire protocol 3.0, Simple Query + handshake (std TcpListener)
  extended.rs  extended query protocol: Parse/Bind/Describe/Execute/Close/Sync
  auth.rs      SCRAM-SHA-256 auth + users.json store (sha2/hmac/pbkdf2/base64)
  quarantine.rs  numbered quarantine names (.corrupt.1, .corrupt.2, never overwritten)
  lock.rs      LOCK file: one process per data dir, stale-PID takeover
  wal.rs       append + fsync + replay (one JSON record per line, corrupt lines counted)
  memtable.rs  in-memory BTreeMap, tombstones, 64-entry flush threshold
  sstable.rs   immutable sorted files, Bloom filter stored alongside
  bloom.rs     Bloom filter, scaled: 16 bits/key, min 1 KiB, 3 hashes
  table.rs     table registry + insert/select/delete over prefixed keys
  doc.rs       JSON documents + linear-scan find
tests/
  engine_tests.rs   integration tests (each in its own temp directory)
  pgwire_tests.rs   wire-protocol tests: raw-TCP client vs a real `zeno serve`
demo.sh        end-to-end demo incl. restart / crash-recovery proof + V0.2 lock/WAL demos + V0.3 serve demo + V0.4 extended-protocol + SCRAM demo
```

## License

Apache-2.0. See the design doc
`../Zeno-design-hindi.md` for the full plan (V1 scope, funding path,
and the honest limits).

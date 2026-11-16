# Zeno — One Engine, All Data (V0.9 prototype)

> **Zeno is a hybrid SQL + JSON database in Rust — not ZenoDB (Lantern, Go
> time-series) and not ZenDB.** The name was chosen knowing those exist.

Zeno V0.9 is a small, working, single-node database prototype. One engine
stores three kinds of data: **key-value**, **tables**, and **JSON
documents**. It is written in Rust using `std` + `serde` +
`serde_json` + small RustCrypto crates (`sha2`, `hmac`, `pbkdf2`,
`base64`, `getrandom`, `subtle`) for SCRAM-SHA-256 auth, plus
`rustls` (TLS 1.2/1.3, `ring` provider) + `rcgen` (self-signed
certificate generation) for `serve --tls` — and `ctrlc`
(SIGINT/SIGTERM handling) for the graceful shutdown — no heavy
dependencies, no external database engine. V0.9 adds **SQL query
power — INNER / LEFT JOIN, WHERE subqueries (`IN (SELECT ...)` and
scalar `= (SELECT ...)`), and GROUP BY + aggregates (COUNT, SUM,
AVG, MIN, MAX) + HAVING** — on top of the V0.8 savepoint portal
closing, graceful shutdown and `zeno bench` (see "What is new in
V0.9").

> **⚠️ LOCAL PROTOTYPE ONLY. With no users configured, `zeno serve`
> accepts EVERY local client with NO password (trust auth) and
> listens only on 127.0.0.1. With users configured (`zeno user
> set-password`), SCRAM-SHA-256 password auth is required — and
> with `--tls` the exchange runs inside TLS 1.2/1.3, but the
> certificate is SELF-SIGNED (see "TLS" below): it proves the
> channel is encrypted, not that the server is who it claims to
> be. Never expose this port to a network, never run it on a
> shared machine, and never use it in production. Anyone on the
> same machine can read and change all your data. See "Password
> auth (SCRAM-SHA-256)" and "TLS" below.**

## What is new in V0.9

- **JOIN — INNER JOIN and LEFT JOIN.** Two or more tables, one
  `=` ON condition per JOIN, table aliases (`users u JOIN orders
  o ON u.id = o.user_id`), qualified columns (`u.id`,
  `o.amount`), and `SELECT *` over a JOIN expands to every
  column of every table, base table first. An unqualified column
  that exists in two tables is 42702 (ambiguous — qualify it);
  an unknown column is 42703; a missing table is 42P01. A LEFT
  JOIN pads an unmatched row's columns with real SQL NULLs
  (sent as DataRow length -1, not as `""`). JOIN works with
  WHERE / ORDER BY / LIMIT / OFFSET, and with GROUP BY (below).
  The executor is a **nested-loop join**: correct and simple at
  this scale, and slow on large inputs — there is no hash join
  and no index, so a JOIN over two big tables scans both fully.
  A hash join is V1.0+ work (see `docs/V1-READINESS.md`). No
  speed claim is made anywhere for JOINs.
  ```sql
  SELECT u.name, o.amount FROM users u
    JOIN orders o ON u.id = o.user_id ORDER BY o.id;
  SELECT u.name, o.amount FROM users u
    LEFT JOIN orders o ON u.id = o.user_id ORDER BY u.id;
  ```
  (`IS NULL` is still unsupported, so there is no way to ask
  for "users with no orders" in one query yet — the unmatched
  row shows up with NULL in the orders columns instead.)
  A table or alias named twice in one SELECT (the same alias
  for two tables, or the same table twice with no alias) is
  **42712** ("table name specified more than once") — before
  the V0.9 review fix the second table silently overwrote the
  first table's columns and returned mismatched values. A
  self-join with two different aliases (`users a JOIN users b`)
  still works. `SELECT u.*` expands to every column of that
  table; `SELECT *` still expands to every column of every
  table in scope.
- **Subqueries in WHERE.** `IN (SELECT ...)` and `NOT IN
  (SELECT ...)` over a single-column subquery, and scalar
  `= (SELECT ...)` (also with `!=`, `<`, `>`, `<=`, `>=`) over
  a one-row, one-column subquery. A scalar subquery returning
  no rows is NULL (so the row does not match — it is not an
  error); returning more than one row is 21000; a subquery
  returning more than one column is 42601. NULL rules follow
  PostgreSQL: a NULL value never matches `IN`, and a NULL
  anywhere in the list makes `NOT IN` false. A subquery reads
  the same snapshot as its outer query (inside a transaction it
  sees the BEGIN snapshot plus the transaction's own writes).
  Each subquery is evaluated **once per statement, not once
  per outer row** (hoisted before the WHERE loop — a nested
  `IN` of depth 2 over 200-row tables used to run 30s+ and
  never finish; it now finishes in well under a second).
  **Correlated subqueries are not supported** — a subquery
  cannot reference the outer query's tables (there is no syntax
  for it; an outer-table reference inside a subquery does not
  resolve). Scalar subqueries in the SELECT list are not
  supported either (0A000) — only in WHERE.
  ```sql
  SELECT name FROM users WHERE id IN (SELECT user_id FROM orders);
  SELECT name FROM users WHERE id NOT IN (SELECT user_id FROM orders);
  SELECT name FROM users WHERE id = (SELECT MAX(user_id) FROM orders);
  ```
- **GROUP BY + aggregates + HAVING.** `GROUP BY` one or more
  columns; aggregates `COUNT(*)`, `COUNT(col)`, `SUM`, `AVG`,
  `MIN`, `MAX`; `HAVING` on an aggregate (with AND) — with or
  without `GROUP BY` (`SELECT COUNT(*) FROM orders HAVING
  COUNT(*) > 1` returns one row); `ORDER BY`
  on an aggregate or on an output alias. Aggregates without
  GROUP BY return one row over the whole table — over no rows,
  `COUNT` is 0 and `SUM`/`AVG`/`MIN`/`MAX` are NULL. `SUM`/`AVG`
  over a non-numeric value is 22P02 (invalid input syntax for
  type numeric); a plain column in the SELECT list that is not
  in GROUP BY is 42803 (PostgreSQL's rule), and an unknown
  column there (or in HAVING, or in ORDER BY) is 42703 — a
  HAVING output alias such as `HAVING total > 100` is 42703
  too, because the alias is no table column. GROUP BY works
  with JOINs. `SUM` over plain integers is exact (i128
  arithmetic); `AVG` over plain integers is exact too —
  integer division plus the remainder as a decimal expansion
  (e.g. `AVG` of 100 and 250 is `175`, `AVG` of 1 and 2 is
  `1.5`); when the division does not terminate (1/3) the
  expansion runs to 16 decimal places, which is an
  approximation and is not claimed exact. An integer `SUM` /
  `AVG` whose sum overflows i128 is **22003**, not a silent
  f64 approximation.
  ```sql
  SELECT city, COUNT(*) FROM users GROUP BY city ORDER BY city;
  SELECT user_id, SUM(amount) AS total FROM orders
    GROUP BY user_id HAVING SUM(amount) > 100 ORDER BY total DESC;
  SELECT COUNT(*), SUM(amount) FROM orders;
  ```
- **NULLs in query results (new in V0.9).** Stored values are
  still never NULL, and a bound SQL NULL parameter is still
  stored as `""` — but a LEFT JOIN miss, an empty scalar
  subquery and an aggregate over no rows now produce real NULLs
  in SELECT results, sent as DataRow length -1. Comparisons
  involving NULL never match (PostgreSQL rule). The
  `StmtOutcome::Rows` type is now `Vec<Vec<Option<String>>>`
  and `data_row` writes -1 for `None`.
- **Executor: `src/query.rs` (new).** The SELECT executor moved
  out of `pgwire.rs` into its own module: scope resolution
  (tables + aliases), nested-loop join, WHERE (with subquery
  execution), GROUP BY + aggregates + HAVING, projection,
  ORDER BY, LIMIT/OFFSET. Simple Query and the extended
  protocol share it — a prepared JOIN / GROUP BY query runs
  through Parse + Describe + Bind + Execute the same way a
  plain SELECT does (Describe resolves the output columns from
  the registry, including `*` over a JOIN and aggregate
  aliases). JOIN/grouped reads inside a transaction use the
  V0.6 snapshot rules — the tables must have existed at BEGIN,
  and the scan is the transaction's snapshot plus its own
  writes. A SELECT takes a **statement-level snapshot** of
  every table it reads (one scan per table, under the shared
  lock) and then executes against the snapshot with the lock
  released, so a long SELECT no longer blocks other
  connections, and concurrent writes mid-SELECT are not seen
  by it. There is a **statement timeout** (57014): a SELECT
  running longer than `ZENO_STATEMENT_TIMEOUT_MS` (default
  30000 ms; `0` disables it) is cancelled instead of running
  forever. Subquery nesting is capped at 64 levels (54001) —
  deeper nesting used to overflow the server's stack and kill
  the process.
- **LIMIT is applied last (no LIMIT pushdown).** `LIMIT` /
  `OFFSET` slice the result after the join, WHERE, grouping
  and sort — so `LIMIT 5` over a big JOIN still materialises
  the whole join first, and a big cross product can use a lot
  of memory before the LIMIT cuts it down. That is a known
  prototype limit, not a bug.
- Version is now **0.9.0** (Cargo.toml, CLI, README).

## What is new in V0.8

- **Savepoint portal closing, PostgreSQL-compatible
  (`src/pgwire.rs`, `src/extended.rs`, `src/txn.rs`).** V0.7
  kept every portal alive across a `ROLLBACK TO SAVEPOINT`
  and re-ran its cached rows fresh — a documented deviation
  from PostgreSQL, which closes the portals created after the
  savepoint. V0.8 does what PostgreSQL does: on a successful
  `ROLLBACK TO SAVEPOINT`, every portal AND prepared statement
  created AFTER that savepoint is closed, so a later Execute /
  Describe / Bind of one fails with **26000** (invalid sql
  statement name) and the connection stays alive. Portals and
  statements created BEFORE the savepoint survive — and a
  suspended portal of theirs still re-runs fresh on resume
  (its cache predates the rollback), exactly like the V0.7
  review fix (B2). How it works: every SAVEPOINT, Parse and
  Bind advances a strictly increasing per-connection clock
  (`Session::sp_clock`); a savepoint records the clock at its
  creation, a portal / statement records the clock at its
  Parse/Bind, and the rollback closes everything with a HIGHER
  clock than the savepoint's. The clock never resets — not even
  at transaction end — so a statement from before a
  transaction is never closed by a rollback inside a later one.
  (Two deliberate deviations remain, unchanged: a failed
  savepoint-control statement, 3B001, and a VACUUM inside a
  transaction, 25001, do NOT abort the transaction — see "What
  is new in V0.7".)
- **Graceful shutdown on SIGINT/SIGTERM (`src/pgwire.rs`,
  `serve`).** A signal used to kill the process at once. Now:
  the first SIGINT/SIGTERM stops the server accepting new
  connections, stops the auto-vacuum thread, waits up to **5
  seconds** for live connections to finish their queries and
  disconnect, then force-closes any sockets still open (a
  query running longer than the grace period may lose its
  reply — its committed data is already safe in the WAL),
  flushes the memtable to an SSTable, saves `meta.json` with
  fresh counters, and exits **0**. A second signal exits
  immediately (code 130, force). Signal handling is the
  `ctrlc` crate (version 3, `termination` feature — without
  that feature ctrlc only handles SIGINT, not SIGTERM; that
  cost one debugging round, see `docs/V1-READINESS.md` for the
  note). The table registry needs no shutdown save — it is
  written on every mutation already. A failed shutdown flush
  still exits 0: the data is durable in the WAL and the next
  open replays it. Known shutdown edges, prototype-only (no
  fix): the auto-vacuum thread is joined without a timeout; the
  signal handler is installed only after the engine opens and
  the socket binds, so a signal in that tiny window still kills
  at once; `ctrlc` installs once per process; and a portal
  suspended before a savepoint resumes from its pre-savepoint
  state on ROLLBACK TO (see V1-READINESS item 14).
- **Benchmark command + V1.0 checklist (`src/bench.rs`,
  `docs/V1-READINESS.md`).** `zeno bench [--rows
  100,1000,10000]` measures Zeno's OWN engine — KV put/get,
  table insert, full table select — at each row count, with a
  warmup before each measured run, **3 measured runs per row
  count, reporting the median of the 3 runs** (a single sample
  varied 2x run to run in review — KV put 26536 -> 11352 ->
  14111 ops/s — so one run's numbers are not a measurement),
  and prints median / p95 / mean latency and ops/s next to the
  machine (CPU, core count, debug/release). It runs on a fresh
  temporary data directory that is removed afterwards, so it
  never touches the user's data. The numbers are this machine's only: there
  is NO comparison with PostgreSQL or MongoDB, because neither
  is installed in this sandbox (`which psql mongod postgres`
  finds nothing) — the checklist says so plainly, and no
  estimated or guessed comparison number appears anywhere.
  `docs/V1-READINESS.md` lists everything still missing
  before V1.0 (psql verification, power-loss test, JOIN,
  2PC, production hardening, benchmarks vs PostgreSQL/MongoDB)
  with an honest done / pending status per item.
- Version is now **0.8.0** (Cargo.toml, CLI, README).

## What is new in V0.7

- **A real SQL parser — lexer + recursive-descent parser
  (`src/parser.rs`).** SQL is no longer string-matched over a flat
  token list: every statement is lexed (tokens carry their line and
  column) and parsed into a small AST, which `pgwire.rs` then
  executes. What it supports: SELECT with a column list or `*`,
  WHERE with AND-joined conditions (`=`, `!=`, `<>`, `<`, `>`,
  `<=`, `>=`), ORDER BY with several keys, each [ASC|DESC]
  (`ORDER BY a, b DESC`), LIMIT and OFFSET in either order
  (`OFFSET 0 LIMIT 1` as well as `LIMIT 1 OFFSET 0`); INSERT with an
  optional column list (values are stored in registry column
  order, so the list may name the columns in any order) and
  multi-row VALUES; UPDATE with several SET assignments and a
  multi-condition WHERE; DELETE with a multi-condition WHERE;
  CREATE TABLE with column types (`VARCHAR(10)`, `NUMERIC(10,2)`,
  `SERIAL PRIMARY KEY` — the type is parsed and then ignored,
  every column is still text) and `IF NOT EXISTS`. A genuine syntax
  error fails with **42601 and the line and column where parsing
  stopped** (`syntax error at line 2, column 14: ...`), never a
  crash. JOIN, subqueries, GROUP BY / HAVING, UNION, OR in WHERE,
  LIKE / IS NULL, INSERT ... SELECT, a table-level PRIMARY KEY,
  and aggregate/function calls (`COUNT(*)`, `upper('x')`, ...) fail with
  **0A000 ("feature not supported")** naming the construct, so a
  client can tell "not supported" apart from "syntax error" (see
  "What the parser does not support" below). Comparisons and
  ORDER BY compare numerically when both sides parse as numbers
  (`"10" > "9"`), lexicographically otherwise — WHERE and ORDER BY
  sort the same way. Integers compare as integers, exactly, at
  any size — never through `f64`, whose 53-bit mantissa used to
  call `9007199254740992` and `9007199254740993` equal; `f64` is
  used only for decimals (`"1.5"` vs `"1.25"`). A duplicate
  column name in CREATE TABLE and a column set twice in one
  UPDATE are both rejected with 42601 instead of silently eating
  or overwriting a value. All old SQL keeps working exactly as before
  (225 old tests still pass); the extended protocol goes through
  the same parser (its tokens are rebuilt into SQL after `$n`
  substitution, so a bound value can never be re-parsed as SQL).
  Honest limits of this parser: no OR, no expressions or
  arithmetic, no table-qualified columns (`t.col`), no aliases,
  no `LIMIT $1` (LIMIT/OFFSET need literal numbers), and a column
  list in INSERT must name every column exactly once (Zeno has no
  NULLs and no defaults to fill the rest).
- **Savepoints (`src/txn.rs`, `src/engine.rs`, `src/pgwire.rs`).**
  Inside a transaction: `SAVEPOINT <name>` remembers the
  transaction's write buffer, `ROLLBACK TO [SAVEPOINT] <name>`
  restores it (dropping every write made after the savepoint, and
  every savepoint made after it — the named one stays, so rolling
  back to it again still works), and `RELEASE [SAVEPOINT] <name>`
  forgets the NEWEST savepoint of that name (a later ROLLBACK TO
  that name fails with 3B001 only when no savepoint of that name
  is left). A savepoint with the same name hides the earlier one
  instead of deleting it: RELEASE of the new one reveals the old
  one again, so ROLLBACK TO rolls back to the FIRST savepoint —
  PostgreSQL behaviour. Unknown name:
  **3B001** (invalid savepoint specification). Outside a
  transaction all three fail with **25P01**. Savepoints work over
  Simple Query AND the extended protocol. A suspended portal
  whose cached rows predate a ROLLBACK TO SAVEPOINT is re-run
  fresh on its next Execute (resuming from the rows already
  sent), so it can never serve a row the rollback undid — but
  only when the portal was created BEFORE the savepoint: since
  V0.8, PostgreSQL's rule applies and portals / prepared
  statements created AFTER the savepoint are closed instead
  (26000 on a later use) — see "What is new in V0.8". One
  PostgreSQL behaviour
  is kept deliberately: `ROLLBACK TO SAVEPOINT` is the way back
  out of an aborted (25P02) transaction — it runs while aborted
  and clears the abort, so the transaction is usable again. A
  savepoint is a snapshot of the write buffer only, not a
  sub-transaction: it cannot commit part of a transaction, and it
  dies with the transaction (COMMIT / ROLLBACK / disconnect).
  Savepoint names are case-sensitive, like table names. Two
  deliberate deviations from PostgreSQL, kept and documented:
  a failed savepoint-control statement (unknown name, 3B001)
  and a VACUUM inside a transaction (25001) do NOT abort the
  transaction — PostgreSQL aborts on any error — so the
  transaction stays usable afterwards (pinned by a test).
- **Background auto-vacuum (`src/pgwire.rs`,
  `start_auto_vacuum`).** `zeno serve` now runs `VACUUM` by
  itself in a background thread, every `--vacuum-interval`
  seconds (default 60; `--no-auto-vacuum` turns it off). It is
  the same snapshot-safe `Engine::vacuum` the `VACUUM` statement
  runs — versions a live snapshot can still see are kept, and the
  committed-transaction set is pruned to the oldest live
  snapshot's watermark — so the thread can never corrupt a running
  transaction's view (verified by a test that holds a live
  snapshot open while the thread ticks: the chain shrinks only by
  the version nobody needs, and the snapshot still reads its old
  data). A failed vacuum is logged and retried at the next
  interval, never fatal — and a vacuum that panics is caught,
  logged, and retried too, instead of silently killing the
  thread. A vacuum that prunes nothing does NOT rewrite the
  SSTables: the data is already durable as it is, so a no-op
  vacuum burns no new SSTable id. The stop flag + join run when
  the server stops serving — since V0.8 that is the graceful
  shutdown on SIGINT/SIGTERM (see "What is new in V0.8"): the
  signal stops the accept loop first, then the vacuum thread is
  stopped and joined, so no vacuum is left running after the
  server has stopped serving. (Before V0.8 the accept loop only
  ended on a listener error and there was no signal handling, so
  SIGINT/SIGTERM ended the process at once and the thread died
  with it.) The interval is
  also settable small for tests (`--vacuum-interval 1`); the
  manual `VACUUM` statement and the `vacuum` CLI command are
  unchanged and still work. (The library API clamps an interval
  below 100 ms to 100 ms — an interval of 0 used to busy-spin
  the thread with no sleep at all; the CLI already rejects
  intervals below 1 s.)
- Version is now **0.7.0** (Cargo.toml, CLI, README).

## V0.7 review fixes (post-review hardening)

A review of V0.7 found 2 blockers, 5 must-fix items and 6
minors; all are fixed except the two documented deviations
below. Each has a regression test (see "Tests").

- **B1 — integers compare exactly, never through `f64`.**
  `compare_values` compares integer strings by sign, digit
  length and digits (exact at any size); `f64` is used only
  for decimals. `WHERE id = 9007199254740993` no longer also
  matches `9007199254740992`, and ORDER BY sorts the same way.
- **B2 — a suspended portal never serves rows a ROLLBACK TO
  SAVEPOINT undid.** A successful ROLLBACK TO bumps a
  per-connection cache epoch; a portal whose cached rows
  predate it re-runs its statement fresh on the next Execute
  and resumes from the rows already sent. (V0.8 narrows this
  to portals created BEFORE the savepoint: portals and
  prepared statements created AFTER it are now closed
  outright, PostgreSQL-style — see "What is new in V0.8".)
- **M1 — duplicate savepoint names stack.** A second
  `SAVEPOINT s` hides the first instead of deleting it;
  `RELEASE s` reveals the first again, so `ROLLBACK TO s`
  rolls back to it.
- **M2 — duplicate column names rejected.** `CREATE TABLE t
  (id, id)` fails with 42601; the table is not created.
- **M3 — a no-op VACUUM does not rewrite the SSTables.**
  When nothing is pruned, `vacuum()` skips the rewrite (and
  burns no SSTable id); the committed-set prune and the
  vacuum counter still happen.
- **M4 — a column set twice in one UPDATE rejected.**
  `UPDATE t SET a = 1, a = 2` fails with 42601 and changes
  nothing.
- **M5 — LIMIT/OFFSET in either order, multi-column ORDER
  BY.** `OFFSET 0 LIMIT 1` works, and `ORDER BY a, b DESC`
  sorts by `a`, then by `b` (each key with its own direction).
- **Minors (m1–m6):** m1 LIKE / IS NULL / a function call as
  a value / INSERT ... SELECT / a table-level PRIMARY KEY
  fail with 0A000, not 42601; m2 kept deliberately — a failed
  savepoint-control statement (3B001) or VACUUM inside a
  transaction (25001) does NOT abort the transaction, unlike
  PostgreSQL (see "What is new in V0.7"); m3 savepoint names
  are case-sensitive, like table names; m4 the auto-vacuum
  shutdown claim is corrected — the stop flag + join run only
  when the accept loop ends, SIGINT/SIGTERM end the process
  at once (no signal handling yet); m5 an auto-vacuum
  interval below 100 ms is clamped to 100 ms, so 0 can never
  busy-spin; m6 a panic inside the auto-vacuum thread is
  caught with `catch_unwind`, logged, and the thread retries
  at the next interval.

## V0.8 review fixes (post-review hardening)

A review of V0.8 found no blockers, 3 must-fix items and 5
minors; all must-fix items and minors m1–m3 are fixed, m4
needed no fix, m5 is documented only. Each fix has a
regression test (see "Tests").

- **M1 — `zeno --version` works and creates nothing.**
  `--version` / `-V` are handled in `main()` like `--help`,
  before any engine opens: they print `zeno 0.8.0` and exit 0.
  Unknown top-level commands are also validated before the
  engine opens, so a typo no longer creates a `zeno-data/`
  directory. (Before: `--version` fell through to `run()`,
  exited 1, and created `zeno-data/` with meta.json + wal.log.)
- **M2 — duplicate `--rows` rejected up front.** `parse_rows`
  rejects a repeated count with a clear error (`--rows has
  duplicate count 100 — each row count may appear only once`).
  (Before: `--rows 100,100` was accepted and failed mid-run
  when the second iteration tried to create `bench100` again.)
- **M3 — bench temp dir removed on every exit path.** The
  temp dir is owned by a `BenchTempDir` Drop guard, created
  before the engine opens: success, any error return, or a
  panic all remove `/tmp/zeno-bench-<pid>-<nanos>/`. (Before:
  the dir was removed only at the end of `run()`, so every
  failed bench run leaked it.)
- **Minors:** m1 `docs/V1-READINESS.md` said 247 tests, the
  real count is 255; m2 the README "Tests" section still
  quoted V0.7 counts (119 unit / 79 pgwire / 239 total) —
  now 127 / 85 / 255; m3 `zeno bench` was single-sample and
  varied 2x run to run, so each row count is now measured 3
  times and the median of the 3 runs is reported; m4 the
  "shutdown 5s grace" observation did not reproduce (0.00s on
  an already-disconnected client; 5s only with a client still
  connected idle, which is the documented design) — no fix;
  m5 small shutdown edges documented, not fixed: the
  auto-vacuum thread is joined without a timeout, the signal
  handler is installed after engine-open/bind, `ctrlc`
  installs once per process, and a portal suspended before a
  savepoint resumes from its pre-savepoint state on ROLLBACK
  TO (see "What is new in V0.8").

## What is new in V0.6

- **MVCC transactions — snapshot isolation (`src/txn.rs`,
  `src/engine.rs`, `src/pgwire.rs`, `src/extended.rs`,
  `src/table.rs`).** `BEGIN` / `COMMIT` / `ROLLBACK` (plus
  `START TRANSACTION`, `END`, `ABORT`) over Simple Query AND the
  extended protocol, one transaction per connection. Every row
  version carries `xmin` (creator txn) and `xmax` (deleter txn);
  a transaction reads the world as of its BEGIN snapshot — data
  committed by others afterwards is invisible to it, its own
  writes are visible to itself, and other transactions'
  uncommitted writes are visible to nobody. COMMIT makes all of
  the transaction's writes visible at once; ROLLBACK drops them
  (they never reached the WAL or the memtable). A connection
  that disconnects with a transaction open rolls it back, and
  ReadyForQuery reports 'T' while a transaction is open, 'E'
  while it is aborted (see below), 'I' otherwise. **Aborted
  transaction (PostgreSQL 25P02):** if a statement inside a
  transaction fails (INSERT/SELECT/UPDATE/DELETE — not DDL,
  not a nested BEGIN, not a Parse/Bind/Describe error), the
  transaction is aborted: every further statement except
  ROLLBACK fails with 25P02, including COMMIT, until ROLLBACK.
  A multi-statement Simple Query that fails mid-batch aborts
  the same way, so a later COMMIT in the same batch cannot land
  the earlier writes. **Isolation level: snapshot isolation ONLY — this
  is NOT PostgreSQL's READ COMMITTED.** In READ COMMITTED each
  statement would see the newest committed data; here each
  statement inside a transaction sees the BEGIN snapshot, even
  if another transaction commits newer data mid-transaction.
  Verified by two-connection tests (uncommitted INSERT invisible,
  later commits invisible to an open snapshot, ROLLBACK, and
  disconnect-rollback).
- **UPDATE (`UPDATE name SET col = val [WHERE col = val]`,
  one SET assignment).** An UPDATE rewrites each matching row
  as a new version (old version gets `xmax`). Autocommit UPDATE
  works too; `UPDATE 0` when nothing matches; unknown SET column
  is 42703. (UPDATE used to be 0A000 — two old tests asserted
  that and were updated, see "Tests".)
- **Write-write conflict — first-committer-wins.** If two
  concurrent transactions change the same row, the second
  COMMIT fails with **40001 (serialization failure)** and that
  transaction is aborted (its writes are gone); the winner's
  data stands. The check runs at COMMIT, not at the UPDATE —
  the losing transaction reads and writes normally until its
  COMMIT. After a 40001 the transaction is over and the
  connection is idle again — a commit conflict ends the
  transaction, it does not leave it aborted (contrast the
  25P02 aborted state above, which a failed DML statement
  leaves behind). Verified by
  a two-connection test.
- **Transactional WAL + crash recovery.** WAL records now carry
  an optional transaction id, and a transaction's writes are
  followed by ONE `commit` record:
  `{"op":"put","txn":5,"key":"...","value":"..."}` …
  `{"op":"commit","txn":5,"count":1}`. The commit record
  carries the transaction's write count (`count`); on replay,
  if the buffered write count for a transaction does not match
  its commit record's count, the whole transaction is discarded
  (a torn WAL line can no longer silently half-commit a
  transaction) and the discard is counted in stats. Replay
  applies a transaction's records ONLY when its commit record
  appears later in the file; records of a transaction with no
  commit record (crash before commit, or abort) are discarded
  with a warning naming the discarded transaction ids. Records
  WITHOUT a txn id are V0.5 records and still apply
  immediately. **Migration: V0.5 data opens fine** — old values
  decode as a single version with `xmin = 0` (committed before
  the beginning of time), old tombstones as a single delete
  version. **Envelope collision (fixed, see "V0.6 review
  fixes"):** a V0.5 value that merely *looks* like an MVCC
  envelope is no longer trusted as one — new envelopes carry
  an unambiguous `ZENO-MVCC2:` prefix, and an old-style
  envelope is trusted only if every id in it is below the
  bound the engine computes at open (from `meta.json` / the
  WAL) and the chain is well-formed; anything else reads back
  as the plain value it always was. **Format note: this
  is a prototype format change, not a stable on-disk promise —
  old data reads, but V0.6 does not promise V0.7 will read V0.6
  files.** Transaction ids are allocated monotonically and
  persisted in `meta.json`, and are also recovered from the
  WAL/SSTables on open, so a restart never reuses an id that a
  stored version already carries. Verified by a kill -9 test:
  the server is killed mid-transaction and after restart only
  committed rows are there.
- **Version storage: chains in the value slot.** Each key's
  versions live as a JSON envelope in its value
  (`ZENO-MVCC2:{"__zeno_mvcc":1,"versions":[{"xmin":..,"xmax":..,"v":..}]}`),
  so the memtable, SSTables, Bloom filter, flush and compaction
  needed no new on-disk structures — the envelope travels with
  the key. Flush writes only the versions that are new since
  the last flush (a version is stored exactly once, however
  many flushes happen), and the read path dedupes overlapping
  chains by `xmin` (newest copy wins), so chains no longer grow
  with every flush. Compaction merges chains and prunes each to
  its newest version (and drops keys whose newest version is a
  delete); it refuses to run while a transaction is active,
  because pruning is only safe with no live snapshot. The
  committed-transaction set is kept in memory and is pruned by
  VACUUM / compaction to the oldest live snapshot's watermark
  (see "V0.6 review fixes"); a restart rebuilds it from a
  watermark (every id below `next_txn_id` at open counts as
  committed, because replay only applies committed
  transactions). Aborted ids are tracked separately, so a
  below-watermark id is never mistaken for committed.
- **Honest costs and limits of this design (read before
  relying on it):** an autocommit `put`/`del` now writes TWO
  WAL records (write + commit marker) and fsyncs twice, not
  once. A transaction that INSERTs reserves its row ids at
  statement time, so a ROLLBACK leaves gaps in the row ids
  (never a reuse). A multi-row autocommit UPDATE/DELETE is one
  implicit transaction (one txn id, one commit marker — see
  "V0.6 review fixes"); inside a transaction it commits
  atomically, as before. DDL inside a transaction fails with
  0A000 (the table registry is not versioned), and a table
  created by another connection after BEGIN is invisible inside
  the transaction (42P01) — the transaction only sees the
  tables that existed at BEGIN. A flush failure after a commit
  is logged, not reported as a failed commit (the commit was
  already durable in the WAL). COMMIT/ROLLBACK with no
  transaction open fail with 25P01 and
  a nested BEGIN fails with 25001 — PostgreSQL would warn and
  carry on; Zeno reports the mistake instead. No savepoints, no
  two-phase commit, no SERIALIZABLE, no READ COMMITTED.

## V0.6 review fixes (post-review hardening)

A review of V0.6 found 2 blockers, 6 must-fix items and 7
minors; all are fixed except the documented residuals below.
Each has a regression test (see "Tests").

- **B1 — flush no longer duplicates version chains.** Flush
  writes only the versions that are new since the last flush,
  and the read path dedupes overlapping chains by `xmin`
  (newest copy wins). A key with 5 versions keeps a chain of
  5 across any number of flushes.
- **B2 — portals die with the transaction.** Every COMMIT /
  ROLLBACK (and a disconnect-rollback) closes all of that
  connection's portals, so a suspended portal can no longer
  serve rows from a rolled-back transaction; resuming one
  fails with 26000. Portals bound outside a transaction
  survive transaction ends (documented deviation).
- **M1 — envelope collision.** New envelopes carry the
  `ZENO-MVCC2:` prefix; old-style envelopes are trusted only
  below the open-time id bound and only when well-formed.
- **M2 — aborted-transaction state (25P02).** See "What is new
  in V0.6" above.
- **M3 — COMMIT no longer reports a flush failure as a failed
  commit.** Flush errors after commit (and after autocommit
  writes) are logged, not returned.
- **M4 — WAL per-transaction integrity.** The commit record
  carries the write count; a mismatch on replay discards the
  whole transaction. This covers torn puts and torn deletes
  (a corrupt delete can no longer resurrect an old value).
- **M5 — online VACUUM.** `VACUUM` is now a SQL statement
  (and a `vacuum` CLI command): it prunes, per key, every
  version invisible to all live snapshots, keeps the newest
  version overall plus the newest version each live snapshot
  can see, drops a key only when its newest kept version is a
  delete and no live snapshot exists, and prunes the
  committed/aborted transaction sets to the oldest live
  snapshot's watermark. There is no background or periodic
  vacuum thread — an operator or client runs `VACUUM`
  explicitly. A transaction that executes no statement for 5
  minutes (default; `ZENO_TXN_IDLE_TIMEOUT_SECS` overrides it)
  is rolled back automatically, so an abandoned transaction
  cannot pin its snapshot forever. The offline CLI `compact`
  still refuses to run while the server holds the lock.
- **M6 — autocommit multi-row UPDATE/DELETE is atomic.** All
  rows of one statement go in a single implicit transaction
  with one commit marker.
- **Minors (m1–m7), all fixed:** m1 DDL snapshot isolation
  (42P01 for tables created after BEGIN; Describe/Bind do not
  enforce it — only Execute does); m2 raw KV `put`/`delete`
  reject keys starting with `table:` / `doc:` (tables and
  documents use internal paths); m3 a Drop guard rolls back
  an abandoned transaction even if the connection handler
  panics; m4 aborted ids are tracked separately from the
  committed watermark; m5 idle-transaction timeout (see M5);
  m6 skipped corrupt rows in `SELECT` are warned about and
  counted (`skipped_rows` in stats); m7 a `del` WAL record
  with a value is now corrupt, as is a `commit` record without
  a txn id or with a value.
- **Known residuals (V0.7 candidates):** a V0.5 value that is
  byte-identical to an old-style envelope whose ids are all
  below the open-time bound cannot be distinguished from a
  real old envelope (the new prefixed format removes the
  problem going forward); `meta.json` is only saved on a
  graceful shutdown, so a `kill -9` after a flush with a stale
  meta file can misread an old envelope (accepted — see
  `src/engine.rs`); Describe/Bind do not enforce the DDL
  snapshot (only Execute does); portals bound outside a
  transaction survive transaction ends; there is no background
  vacuum and no automatic snapshot-pinning bound beyond the
  idle timeout.

## What is new in V0.5

- **TLS — PostgreSQL SSLRequest answered 'S' (`src/tls.rs`).**
  `zeno cert generate` creates a self-signed certificate + private
  key in the data directory (`server-cert.pem` / `server-key.pem`,
  both mode 0600, ECDSA P-256, SANs `localhost` + `127.0.0.1`,
  server-auth usage, valid 1 year from one day before creation —
  backdated so slightly-behind client clocks never see "not yet
  valid") and refuses to overwrite an
  existing one. `zeno serve --tls` loads it once at startup (a
  missing cert fails the start with a clear "run `zeno cert
  generate` first"; so does an expired / not-yet-valid cert, and
  a key readable by group/other is refused until `chmod 600`),
  answers SSLRequest with 'S', runs a real
  TLS 1.2/1.3 handshake (rustls 0.23.46, `ring` provider — pure
  Rust, no OpenSSL), and then runs the normal protocol inside the
  encrypted stream. `--tls` means TLS is REQUIRED: a plain
  StartupMessage without an SSLRequest is refused with 08P01,
  never answered in plaintext. Without `--tls` the behaviour is unchanged
  (SSLRequest -> 'N', plaintext). GSSENCRequest is answered 'N'
  like PostgreSQL, and a clean shutdown sends TLS `close_notify`. Crates, all reviewed: `rustls
  0.23`, `rcgen 0.14`, `time 0.3` (certificate dates); PEM
  parsing uses rustls's own `pki_types` — the unmaintained
  `rustls-pemfile` (RUSTSEC-2025-0134) is deliberately not used.
  Verified by a real rustls client test (trusting exactly the
  generated cert): SSLRequest -> 'S' -> TLS 1.3 handshake ->
  SCRAM login -> CREATE/INSERT over the encrypted stream, plus a
  test that `serve --tls` without a cert refuses to start.
  **BOLD, honest warning: the certificate is SELF-SIGNED.**
  It encrypts the channel, but any client that trusts it blindly
  can be talking to ANY server that minted a cert for
  `localhost` — a self-signed cert is not an identity. Clients
  must pin this exact cert (or use it as their only trust root)
  and production needs a certificate from a real CA. A second
  honest limit found while building this: rustls's
  `Connection::reader().read()` returns `Err(WouldBlock)` — NOT
  `Ok(0)` — when no decrypted bytes are buffered yet, so the
  read loop treats exactly that as "pull more TLS records"
  (the first version of the code waited on `Ok(0)` and hung —
  fixed and covered by the TLS test above).
- **SCRAM rate limiting / lockout (`src/auth.rs`,
  `LoginRateLimiter`).** 5 failed logins for one `user@IP` lock
  that key for 5 minutes; EVERY failure — the 1st wrong password
  and a locked-out login alike — waits the same constant 2 s
  delay before its 28P01, so the timing can never reveal whether
  an account is locked (a progressive delay used to leak exactly
  that: 0.1 s fresh vs 2.0 s locked). A correct password during
  lockout still fails — the lockout cannot be guessed around. A
  locked-out login runs the EXACT same handshake as an unknown
  user (same server-first, same 28P01, same closed connection),
  so the lockout leaks nothing about whether the username exists;
  and attempts during a lockout do NOT extend it (otherwise an
  attacker could keep an account locked forever by knocking once
  a minute). A successful login forgets the key's failures, and
  the next failure after an expired lockout starts a fresh
  allowance. The tracker holds at most 10,000 `user@IP` keys
  (stale unlocked entries are purged at the cap; active lockouts
  are never dropped by the purge). **In-memory only: a server
  restart resets every counter and lockout** — there is no
  persistent lockout store yet. **Known trade-off (account-DoS):
  anyone who knows a username can lock that user out for 5
  minutes by failing 5 logins from one IP — the lockout is
  per-`user@IP`, so the same user from another IP still logs in,
  and a restart clears every lockout; there is no allowlist or
  CAPTCHA in this prototype.** Verified by 8 unit tests (lock at
  5, expiry + fresh allowance, success resets, per-user/per-IP
  isolation, constant failure delay, entry cap eviction, cap
  never drops a lockout, concurrent fake credentials agree) and 3
  raw-TCP integration tests (5 wrong -> the right password still
  28P01, another user unaffected; unknown user gets the identical
  response 6 times in a row; fresh and locked logins take the
  same time).
- **Connection limit (`zeno serve --max-connections <n>`,
  default 20).** The count is incremented on accept (before the
  thread starts, so handshaking and idle connections count too)
  and decremented when the connection's thread ends; two accepts
  racing each other cannot slip past the cap. Past the limit a
  new connection is refused inline — no thread — with a proper
  PostgreSQL ErrorResponse **53300 (too_many_connections)** and
  the socket is closed; the server keeps running and serving the
  existing connections. Verified by an integration test: with
  `--max-connections 2`, two idle connections hold both slots,
  the 3rd gets 53300, the server still answers a query on the
  first connection, and closing one idle connection lets a new
  one in.
- **Mutex-poisoning recovery (`src/pgwire.rs`,
  `recover_lock`).** Every place that locks the shared engine
  used to fail with XX000 "server lock poisoned" if any thread
  had panicked while holding the lock — one panicking statement
  wedged the server until restart. Now the lock is recovered
  with `into_inner` (and the poisoning is logged loudly — a
  panic is still a bug worth fixing, recovery is not a
  substitute). Honest std detail, found by the test: the poison
  FLAG itself is sticky (only the unstable `clear_poison` would
  clear it), so `is_poisoned()` stays true — but every server
  path locks through `recover_lock`, which recovers on every
  call, so the server keeps serving. Verified by a unit test
  that injects a real panic while holding a lock, then recovers
  twice and mutates the data.
- **`user set-password` race lock (`src/auth.rs`,
  `src/lock.rs`).** Two `zeno user set-password` processes could
  both load the same `users.json`, each add their own user, and
  the second save silently dropped the first user's entry. Now
  `set-password` and `remove` take a `users.lock` file lock
  (same PID + `create_new` + stale-takeover rules as the
  data-dir `LOCK`, via a generalized `DirLock::acquire_named`)
  and WAIT for it (up to 10 s) instead of failing, holding it
  across the whole load-modify-save; the save itself was already
  atomic (tmp + fsync + rename + 0600). Verified by an
  integration test: 8 concurrent `set-password` processes for
  8 different users, all 8 survive in `user list`.
- Version is now **0.5.0** (Cargo.toml, CLI, README).

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

## What works in V0.9

- **MVCC transactions (snapshot isolation)** — `BEGIN` /
  `COMMIT` / `ROLLBACK` (+ `START TRANSACTION`, `END`,
  `ABORT`) over Simple Query and the extended protocol, one
  transaction per connection; `UPDATE` (several SET assignments
  since V0.7); **savepoints** (`SAVEPOINT` / `ROLLBACK TO
  SAVEPOINT` / `RELEASE SAVEPOINT`, V0.7 — see "What is new in
  V0.7"); write-write conflict aborts the second committer with
  40001 (first-committer-wins); WAL + crash recovery keeps only
  committed transactions (see "What is new in V0.6" for the
  isolation level, the WAL format, and the honest limits).
  ReadyForQuery is 'T' inside a transaction, 'I' otherwise, 'E'
  while the transaction is aborted.
- **PostgreSQL wire protocol** — `zeno serve` (see "What is new in
  V0.4" above). `psql` / libpq clients connect over TCP on
  127.0.0.1 and run CREATE TABLE / INSERT / UPDATE / SELECT /
  DELETE / VACUUM / BEGIN / COMMIT / ROLLBACK / SAVEPOINT, over
  Simple Query AND the extended protocol (prepared statements,
  `$1` params, named + unnamed statements/portals,
  PortalSuspended resume). The SQL is parsed by the real V0.7
  parser: multi-condition WHERE (`=`, `!=`, `<`, `>`, `<=`, `>=`),
  ORDER BY / LIMIT / OFFSET, multi-row INSERT, multi-SET UPDATE
  (see "What is new in V0.7") — extended in V0.9 with JOINs,
  subqueries and GROUP BY / aggregates (see "What is new in
  V0.9"). **Auth: trust auth (no password)
  while no users are configured, SCRAM-SHA-256 password auth
  once a user exists — local prototype only (see the warning at
  the top and "Password auth" below).**
- **Background auto-vacuum (V0.7)** — `zeno serve` runs `VACUUM`
  by itself every `--vacuum-interval` seconds (default 60;
  `--no-auto-vacuum` turns it off). It prunes only versions no
  live snapshot needs, and the committed-transaction set with
  them; a failed vacuum is logged and retried, never fatal. The
  manual `VACUUM` statement and the `vacuum` CLI command still
  work the same way.
- **Password auth (SCRAM-SHA-256)** — `zeno user set-password
  <name>` / `list` / `remove` (see "How to run"). The password is
  never stored, only its SCRAM verifier in `users.json`; the
  server re-reads it on every new connection, so a password set
  while the server runs applies at once. Unknown users get a fake
  exchange and still fail with 28P01; a corrupt `users.json`
  fails connections instead of silently falling back to trust
  auth. **Rate limiting (V0.5):** 5 failed logins lock a
  `user@IP` for 5 minutes (in-memory only — a restart resets
  it), with a constant 2 s delay before each 28P01; a locked-out
  login is indistinguishable from a wrong password, including in
  timing. **TLS
  (V0.5):** with `serve --tls` the exchange runs inside TLS
  1.2/1.3 (self-signed cert — prototype only, see "TLS" in
  "What is new in V0.5"); without it the exchange still travels
  in plaintext over loopback; a captured proof cannot be
  replayed (fresh nonce every time).
- **TLS (V0.5)** — `zeno cert generate` + `zeno serve --tls`
  (see "What is new in V0.5"): SSLRequest answered 'S', real
  TLS 1.2/1.3 handshake, the whole protocol inside the encrypted
  stream. **The certificate is SELF-SIGNED — prototype only**;
  clients must pin it (or trust exactly it) and production needs
  a real CA certificate. Without `--tls` the server still answers
  'N' and speaks plaintext.
- **Connection limit (V0.5)** — `serve --max-connections <n>`
  (default 20): past the limit a new connection gets
  ErrorResponse 53300 and is closed; the server keeps running.
  Idle and handshaking connections count toward the limit.
- **Key-Value** — `put` / `get` / `del`. Deletes are tombstones: the key
  disappears from reads immediately and is physically removed by
  compaction.
- **WAL (Write-Ahead Log)** — every write is appended to `wal.log` and
  fsynced *before* it touches the memtable. On open, the WAL is replayed,
  so data written before a crash comes back. Format: one JSON record per
  line, `{"op":"put","key":"...","value":"..."}` or
  `{"op":"del","key":"..."}` for V0.5 records; V0.6 adds an optional
  `"txn":<id>` to write records and a `{"op":"commit","txn":<id>}`
  marker — only transactions with a commit marker are replayed
  (see "What is new in V0.6"). An autocommit write is two records
  (write + commit), i.e. two fsyncs. A torn/corrupt line is counted and
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
  `tables.json`), `INSERT` rows (single-row, multi-row, or with a
  column list — V0.7), `SELECT` with a multi-condition WHERE,
  ORDER BY / LIMIT / OFFSET (V0.7), `UPDATE` (several SET
  assignments, V0.7), `DELETE`. V0.9 adds `INNER` / `LEFT JOIN`
  (with aliases and qualified columns), `WHERE ... IN (SELECT
  ...)` / scalar subqueries, and `GROUP BY` + aggregates
  (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`) + `HAVING` (see "What is
  new in V0.9"). Rows are stored as keys
  `table:<name>:<row-id>`. SELECT is still a linear scan filter
  over the rows (no index) — only the parsing is real SQL now.
  JOINs are nested-loop (slow on large inputs — see "What is new
  in V0.9").
  `INSERT` persists the next row id (atomically
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
  versions and tombstoned keys. V0.6: the merge is over version
  chains — each key's chain is pruned to its newest version — and
  compaction refuses to run while a transaction is active.
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

- **TLS certificate is self-signed, and there is no channel
  binding.** `serve --tls` encrypts the channel, but the cert
  proves nothing about the server's identity — a client must pin
  this exact cert (or trust exactly it) and production needs a
  real CA certificate. A client that demands SCRAM channel
  binding (`p=tls-server-end-point`) is still rejected, and the
  certificate is loaded once at server startup (regenerating it
  needs a server restart). Without `--tls` there is no
  encryption at all (SSLRequest answered 'N').
- **The login lockout is in-memory only.** A server restart
  resets all failure counts and lockouts; there is no persistent
  lockout store, and no per-IP (as opposed to per-user@IP)
  block. The failure delay is a constant 2 s — it slows guessing,
  it does not stop a distributed attack. And the lockout itself
  is an account-DoS trade-off (see "SCRAM rate limiting" above):
  anyone who knows a username can lock that user out for 5
  minutes from one IP; a restart clears it.
- **Bound NULL becomes the empty string.** A parameter bound as
  SQL NULL is still stored as `""`, and a missing column still
  reads back as `""` — but since V0.9 a SELECT result CAN be
  NULL (a LEFT JOIN miss, an empty scalar subquery, an
  aggregate over no rows), and that NULL is sent as a real NULL
  (DataRow length -1), not as `""` (see "What is new in V0.9").
- **Extended protocol deviations (documented in "What is new in
  V0.4"):** Execute repeats the RowDescription (PostgreSQL
  sends it only on Describe); Parse checks syntax and parameter
  types only, table/column existence is checked at
  Bind/Describe/Execute; a bound SQL NULL becomes the empty string (stored values are still never NULL — only SELECT results can be NULL since V0.9).
- **No MVCC beyond snapshot isolation.** Transactions are snapshot
  isolation only: no two-phase commit, no DDL inside a
  transaction, no SERIALIZABLE, no READ COMMITTED (see "What is
  new in V0.6"). Savepoints exist since V0.7, and old versions are
  vacuumed by the background auto-vacuum thread as well as by an
  explicit `VACUUM` statement (or the `vacuum` / `compact` CLI
  commands when the server is stopped); the committed-transaction
  set is pruned by VACUUM / compaction.
- **What the parser does not support (V0.9).** The parser is real
  but small: no `RIGHT` / `FULL` / `CROSS JOIN`, no subqueries
  in `FROM`, no `UNION`, no `OR` in WHERE, no expressions or
  arithmetic, no scalar functions (`UPPER(...)`,
  `COALESCE(...)`, ...), no `LIKE` / `IS NULL`, no `EXISTS`,
  no `IN (...)` list of literals (only `IN (SELECT ...)`), no
  `INSERT ... SELECT`, no table-level `PRIMARY KEY (...)`, no
  `LIMIT $1` (LIMIT/OFFSET need literal numbers), no scalar
  subqueries in the SELECT list (only in WHERE), no correlated
  subqueries (a subquery cannot reference the outer query's
  tables), no `ON ... AND ...` and no literal in an `ON`
  condition (only one `table.col = table.col`), no
  `COUNT(DISTINCT ...)`, no `GROUP BY 1` / `ORDER BY 1`
  (column positions — name the column). Those fail
  with 0A000 ("feature not supported"), not with a silent
  misparse. `JOIN` (INNER / LEFT), `WHERE ... IN (SELECT ...)`
  and scalar subqueries, `GROUP BY` / `HAVING`, aggregates
  (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`), table-qualified
  columns (`u.id`) and aliases (`users u`, `SUM(x) AS total`)
  all work now (V0.9). `VARCHAR(10)` and `SERIAL PRIMARY KEY`
  in a column definition, a column list in
  `INSERT INTO t (a, b) VALUES (...)`, `WHERE id > 1`, and
  `ORDER BY` / `LIMIT` all work now (V0.7) — including several
  ORDER BY keys (`ORDER BY a, b DESC`) and LIMIT/OFFSET in either
  order — but a column list in
  INSERT must name every column exactly once (Zeno has no NULLs
  or defaults to fill the rest).
- **WHERE on an unknown column, one table, silently matches
  nothing (deliberate, V0.3 behaviour — not changed).** A
  filter on a column the (single) table does not have filters
  every row out instead of erroring with 42703; with two or
  more tables in scope the same filter IS 42703. Inconsistent,
  kept as-is in V0.9 because changing it risked regressions
  elsewhere; it is documented here so nobody mistakes the
  silence for a correct empty result.
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
- **Remaining risks, fixed in V0.5 (were review findings):** the
  four items listed above — no rate-limiting, no connection
  limit, poisoned-Mutex XX000, and the `set-password` race — are
  all fixed in V0.5 (see "What is new in V0.5"). What remains:
  the lockout is in-memory only (restart resets it), the TLS
  cert is self-signed with no channel binding, and there is
  still no RIGHT/FULL JOIN, no FROM-subqueries, no UNION, no
  2PC / SERIALIZABLE, and no multi-node support (see the other
  bullets in this section). The V0.7 parser, savepoints, and
  V0.9 JOINs / subqueries / GROUP BY are done (see "What is new
  in V0.7" and "What is new in V0.9").
- **Not production-ready.** No independent audit. A Zeno-only
  benchmark exists (`zeno bench`, see "What is new in V0.8")
  but there is still no benchmark against PostgreSQL or
  MongoDB — neither is installed in this sandbox, so no
  comparison number is claimed anywhere in this repo. No speed
  claims are made beyond the measured numbers `zeno bench`
  prints on the machine it runs on.

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
./target/release/zeno --data ./my-data vacuum    # snapshot-safe prune (also as SQL: VACUUM)
./target/release/zeno --data ./my-data compact
./target/release/zeno --data ./my-data stats
./target/release/zeno --data ./my-data hold 5   # diagnostic: hold the lock 5s

# PostgreSQL wire protocol (V0.8) — server keeps running until it
# gets SIGINT/SIGTERM, then shuts down gracefully (stops accepting,
# up to 5s for live queries, flush + meta.json save, exit 0 —
# a second signal exits at once). See "What is new in V0.8".
./target/release/zeno --data ./my-data serve --port 5433
# With TLS (needs a certificate first — see below) and a smaller
# connection cap than the default 20:
./target/release/zeno --data ./my-data serve --port 5433 --tls --max-connections 10
# Auto-vacuum runs every 60s by default; change the interval, or off:
./target/release/zeno --data ./my-data serve --port 5433 --vacuum-interval 10
./target/release/zeno --data ./my-data serve --port 5433 --no-auto-vacuum

# Benchmark (V0.8) — Zeno's own engine only, on a fresh temp dir
# (removed afterwards; your data is untouched). No PostgreSQL /
# MongoDB comparison: neither is installed in this sandbox.
./target/release/zeno bench
./target/release/zeno bench --rows 100,1000
# V1.0 readiness checklist: docs/V1-READINESS.md

# TLS (V0.5): generate a SELF-SIGNED certificate (prototype only —
# production needs a real CA certificate; clients must pin this
# exact cert or trust exactly it). Refuses to overwrite an
# existing cert; the files are mode 0600.
./target/release/zeno --data ./my-data cert generate
# -> server-cert.pem + server-key.pem in ./my-data
# (SANs localhost + 127.0.0.1, valid 1 year, ECDSA P-256).

# Password auth (SCRAM-SHA-256): set a password, then the server
# requires it on every new connection (no restart needed).
# The password is asked twice on stdin and echoes as you type —
# use a private terminal. The password itself is never stored.
# 5 wrong logins lock a user@IP for 5 minutes (in-memory only).
./target/release/zeno --data ./my-data user set-password sanjay
./target/release/zeno --data ./my-data user list
./target/release/zeno --data ./my-data user remove sanjay
```

**Connect with `psql`** (on a machine that has it — this sandbox does
not; `which psql` finds nothing here, so the tests and the demo speak
raw TCP instead and parse the reply bytes):

```bash
psql -h 127.0.0.1 -p 5433 -U zeno -d zeno   # no password: trust auth, LOCAL ONLY
# With --tls, psql needs sslmode=require and the self-signed cert as
# its trust root (otherwise it will not trust the server):
psql "host=127.0.0.1 port=5433 user=sanjay dbname=zeno sslmode=require sslrootcert=./my-data/server-cert.pem"
```

```sql
CREATE TABLE users (id, name, city);
INSERT INTO users VALUES (1, 'Sanjay', 'Delhi');
INSERT INTO users VALUES (2, 'Asha', 'Mumbai'), (3, 'Ravi', 'Jaipur');
SELECT * FROM users WHERE city = 'Delhi';
SELECT id, name FROM users WHERE id >= 2 AND city != 'Delhi' ORDER BY id DESC LIMIT 2;
UPDATE users SET city = 'Pune', name = 'Asha2' WHERE id = 2;
DELETE FROM users WHERE id = 2;
SELECT * FROM users;
```

```sql
-- Transactions (V0.6 snapshot isolation + V0.7 savepoints — see
-- "What is new in V0.6" / "What is new in V0.7"): inside the
-- transaction, other connections see neither the INSERT nor the
-- UPDATE until COMMIT; a concurrent COMMIT to the same row first
-- makes this COMMIT fail with 40001.
BEGIN;
INSERT INTO users VALUES (3, 'Ravi', 'Jaipur');
SAVEPOINT sp1;
UPDATE users SET city = 'Agra' WHERE id = 1;
ROLLBACK TO SAVEPOINT sp1;   -- the UPDATE goes, the INSERT stays
SELECT * FROM users;         -- this connection sees its own writes
COMMIT;                      -- or ROLLBACK to drop both writes
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
SELECT / UPDATE, then a second server on the same data directory
refused by the lock — and the V0.4 addition: the same client pipelines
Parse+Describe+Bind+Describe+Execute+Sync with a `$1` parameter,
fetches rows one at a time (PortalSuspended), then sets a password
with `zeno user set-password` and logs in with a full SCRAM-SHA-256
handshake (Python `hashlib` client), plus a wrong-password
rejection (28P01, connection closed) — and the V0.5 addition:
`zeno cert generate` (self-signed cert, 0600) + `serve --tls`
(SSLRequest answered 'S', TLS 1.3 handshake, SCRAM login +
query inside the encrypted stream), then 5 wrong SCRAM logins
lock the 'ratelimit' user and even the right password is still
28P01, and a `--max-connections 2` server refuses its 3rd (idle)
connection with 53300, then lets a new one in once a slot frees up —
and the V0.6 addition (section 12, fresh data dir, two connections):
BEGIN + INSERT invisible to the other connection until COMMIT
(snapshot isolation), ROLLBACK undoes an UPDATE, a write-write
conflict on the same row fails the second COMMIT with 40001, and
kill -9 mid-transaction loses only the uncommitted row on restart —
and the V0.7 addition (section 13, fresh data dir, two
connections, `--vacuum-interval 2`): the background auto-vacuum
prunes dead versions every 2s while a live snapshot still reads
its old data; SAVEPOINT / ROLLBACK TO SAVEPOINT / RELEASE (with a
3B001 for a released name); and the new parser — multi-row INSERT,
column-list INSERT, ORDER BY + LIMIT, multi-condition WHERE,
multi-SET UPDATE, plus a bad SQL failing with 42601 and its line
and column — and the V0.9 addition (section 15, fresh data dir):
users + orders tables, INNER JOIN and LEFT JOIN (with a real
NULL row), GROUP BY + SUM/COUNT with HAVING, and an IN-subquery
— with the exact numbers printed.

## Tests

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- 128 unit tests (the 99 from V0.6, plus 16 parser ones (15
  from V0.7, plus 1 net new in V0.9: the old "JOIN / GROUP BY /
  aggregates / subqueries as not supported" test became two —
  JOIN / LEFT JOIN / GROUP BY / aggregates / IN + NOT IN +
  scalar subqueries now parse (with aliases, qualified columns,
  HAVING, ORDER BY on an alias), and RIGHT / FULL / CROSS JOIN,
  FROM-subqueries, UNION, OR, EXISTS stay 0A000) — lexer
  line/column tracking, comments, unterminated string
  position, SELECT with multi-condition WHERE + ORDER BY +
  LIMIT + OFFSET, all six comparison operators, INSERT column
  list + multi-row VALUES, multi-SET UPDATE, multi-condition
  DELETE, CREATE TABLE with types and constraints, syntax errors
  with line/column, LIMIT validation, `$1` surviving as a
  parameter, multi-column ORDER BY + OFFSET-before-LIMIT, LIKE /
  IS NULL / function call / INSERT ... SELECT / table-level
  PRIMARY KEY as 0A000 — plus 1 auto-vacuum one: the background thread
  prunes only the version no live snapshot needs, the live
  snapshot still reads its old data, the chain prunes to one
  version once the snapshot is gone, and the thread joins
  cleanly on stop — plus 1 vacuum-interval clamp one (0 clamps
  to 100 ms, never busy-spins) — plus 3 table ones: integer
  comparison exact above 2^53, duplicate CREATE TABLE column
  rejected, duplicate UPDATE SET column rejected — plus 1 V0.8
  table one: corrupt row values are warned and counted, not
  silently dropped — plus 7 V0.8 bench ones: latency summary
  median/p95/mean, empty summary is zero, `--rows` parsing
  incl. duplicate rejection, median-of-runs takes the middle
  value, the temp-dir guard removes on drop, and the error path
  removes the temp dir)
- 43 integration tests in `tests/engine_tests.rs` (the 23 from
  V0.5, plus 7 V0.6 ones: commit makes writes visible /
  rollback hides them, snapshot isolation hides later commits,
  write-write conflict aborts the second committer, table
  UPDATE + DELETE inside a transaction with rollback, WAL
  replay recovers only committed transactions, legacy WAL
  records without a txn id replay as committed, txn ids survive
  flush + restart — plus 10 review-fix ones: flush does not
  duplicate the version chain, envelope-shaped legacy values
  are plain data, a plausible old envelope is still trusted
  (migration), commit succeeds when the flush fails, WAL replay
  discards a transaction with a torn put / a torn delete,
  VACUUM prunes old versions but keeps live snapshots, VACUUM
  drops a deleted key with no snapshot needing it, a no-op
  VACUUM does not rewrite the SSTables, autocommit
  UPDATE/DELETE is one WAL transaction, reserved `table:` /
  `doc:` prefixes are rejected for raw puts). Two V0.5 tests changed line numbers only:
  an autocommit `put` now writes two WAL records (write +
  commit marker), so the corrupt lines the tests append land
  on lines 3 and 5 instead of 2 and 3 — plus 2 V0.8 review-fix
  ones: `zeno --version` exits 0 and creates no data dir, and an
  unknown command fails without creating a data dir.
- 96 integration tests in `tests/pgwire_tests.rs` (the 62 from
  V0.6, plus 17 V0.7 ones: savepoint rollback keeps earlier
  writes and drops later ones (and the savepoint survives a
  ROLLBACK TO), savepoint release + unknown-name 3B001 +
  savepoint statements outside a transaction 25P01, ROLLBACK TO
  SAVEPOINT recovers an aborted (25P02) transaction, savepoints
  over the extended protocol, SELECT with ORDER BY / LIMIT /
  OFFSET, multi-condition WHERE with comparisons, multi-row
  INSERT + column list, multi-SET UPDATE, syntax errors with
  line/column + RIGHT JOIN as 0A000 + COUNT(*) working + typed
  CREATE TABLE,
  `--vacuum-interval` / `--no-auto-vacuum` flags start a working
  server — plus 7 review-fix ones: integers above 2^53 compare
  exactly in WHERE and ORDER BY, a suspended portal is re-run
  fresh after ROLLBACK TO SAVEPOINT, RELEASE of a duplicate
  savepoint reveals the older one, duplicate CREATE TABLE
  columns rejected with 42601, duplicate UPDATE SET column
  rejected with 42601, OFFSET-before-LIMIT + multi-column
  ORDER BY, LIKE / IS NULL / function call / INSERT ... SELECT /
  table-level PRIMARY KEY as 0A000). One
  V0.5 test changed deliberately: UPDATE is supported now, so
  the "unsupported SQL" test asserts UPDATE succeeds (UPDATE 1)
  and uses DROP TABLE for the 0A000 case instead; one extended
  Parse test does the same — plus 6 V0.8 ones, including
  savepoint rollback closing portals/statements created after
  it and keeping the ones created before it, graceful shutdown
  on SIGTERM exiting 0 and keeping data, `zeno bench`
  reporting measured numbers, and duplicate `--rows` rejected
  with a clear error — plus 11 V0.9 ones: INNER JOIN rows with
  aliases + `*` expansion over a JOIN + JOIN with WHERE/LIMIT +
  a second JOIN in one query, LEFT JOIN NULL padding + NULL
  filtering in WHERE, ambiguous column 42702 + RIGHT/FULL JOIN
  0A000 + missing table 42P01, IN / NOT IN subqueries, scalar
  subquery (NULL / one row / many rows 21000), FROM-subquery
  0A000, GROUP BY + all five aggregates + aggregates without
  GROUP BY + aggregates over no rows + JOIN+GROUP BY, HAVING
  with AND + ORDER BY on an alias, aggregate errors (SUM over
  text 22P02, non-grouped column 42803, `SELECT *` with GROUP
  BY 42803), JOIN + GROUP BY inside a transaction seeing the
  BEGIN snapshot, and JOIN + GROUP BY over the extended
  protocol with a `$1` parameter.
- 267 tests total, all passing.

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
  main.rs      CLI (subcommands incl. `serve`, `cert` and `user`; the engine lives in the library)
  lib.rs       library root
  engine.rs    WAL + memtable + SSTables + compaction + read path
  pgwire.rs    PostgreSQL wire protocol 3.0, Simple Query + handshake (std TcpListener) + connection limit + poison recovery
  extended.rs  extended query protocol: Parse/Bind/Describe/Execute/Close/Sync
  auth.rs      SCRAM-SHA-256 auth + users.json store (sha2/hmac/pbkdf2/base64) + login rate limiter + users.lock
  tls.rs       TLS for `serve --tls`: cert generate (rcgen, self-signed) + rustls handshake + TLS reader/writer halves
  quarantine.rs  numbered quarantine names (.corrupt.1, .corrupt.2, never overwritten)
  lock.rs      LOCK file: one process per data dir, stale-PID takeover (+ `acquire_named` for users.lock)
  wal.rs       append + fsync + replay (one JSON record per line, corrupt lines counted)
  memtable.rs  in-memory BTreeMap, tombstones, 64-entry flush threshold
  sstable.rs   immutable sorted files, Bloom filter stored alongside
  bloom.rs     Bloom filter, scaled: 16 bits/key, min 1 KiB, 3 hashes
  table.rs     table registry + insert/select/delete over prefixed keys
  parser.rs    real SQL parser (V0.7): lexer + recursive-descent AST, line/column errors (V0.9: JOIN, subqueries, GROUP BY/aggregates)
  query.rs     SELECT executor (V0.9): scope resolution, nested-loop JOIN, WHERE subqueries, GROUP BY + aggregates + HAVING
  doc.rs       JSON documents + linear-scan find
tests/
  engine_tests.rs   integration tests (each in its own temp directory)
  pgwire_tests.rs   wire-protocol tests: raw-TCP client vs a real `zeno serve` (+ a real rustls TLS client)
demo.sh        end-to-end demo incl. restart / crash-recovery proof + V0.2 lock/WAL demos + V0.3 serve demo + V0.4 extended-protocol + SCRAM demo + V0.5 TLS + rate-limit + connection-limit demo + V0.6 MVCC transactions demo
```

## License

Apache-2.0. See the design doc
`../Zeno-design-hindi.md` for the full plan (V1 scope, funding path,
and the honest limits).

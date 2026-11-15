# Zeno V1.0 readiness checklist

What is still missing before Zeno can call itself V1.0 — with an
honest status per item. Statuses as of **V0.8.0** (2026-11-15).
Nothing here is a promise of a date; "pending" means not done,
not "coming soon".

## Status key

- **done** — implemented, with a regression test.
- **pending** — not done. The note says what is missing and,
  where one exists, what would prove it done.

## Checklist

| # | Item | Status | Note |
|---|------|--------|------|
| 1 | Real-client verification with `psql` / libpq | pending | `psql` is NOT installed in this sandbox (`which psql` finds nothing, checked again 2026-11-15). Every wire-protocol test speaks raw TCP from a hand-rolled client instead. Done = the same server answers a real `psql` session (Simple + extended protocol, SCRAM login, prepared statements) on a machine that has it. |
| 2 | Power-loss / crash-safety test | pending | WAL replay is tested (kill -9 mid-transaction loses only uncommitted rows), but there is no test that cuts power mid-fsync or verifies the on-disk files after an OS crash. A `kill -9` is not a power cut. Done = a test (or a documented manual procedure) that kills the process at arbitrary points and reopens with no lost committed data and no corrupt files. |
| 3 | JOIN | pending | Parser reports JOIN as 0A000 ("feature not supported"). Done = `SELECT ... FROM a JOIN b ON ...` works with tests. |
| 4 | Subqueries | pending | Parser reports subqueries as 0A000. Done = `SELECT ... WHERE x IN (SELECT ...)` and scalar subqueries work with tests. |
| 5 | GROUP BY / HAVING / aggregates | pending | Parser reports them as 0A000 (`COUNT(*)`, `SUM`, ... do not exist). Done = GROUP BY + HAVING + at least COUNT/SUM/AVG/MIN/MAX work with tests. |
| 6 | Two-phase commit (2PC) | pending | No PREPARE TRANSACTION / COMMIT PREPARED. Transactions are snapshot isolation only. Done = 2PC works across a crash (prepared txns survive restart) with tests. |
| 7 | READ COMMITTED / SERIALIZABLE | pending | Snapshot isolation only; every statement in a transaction sees the BEGIN snapshot. Done = at least one more isolation level works with tests. |
| 8 | Benchmarks vs PostgreSQL / MongoDB | pending | `zeno bench` (V0.8) measures Zeno's own engine only. No comparison ran, because neither PostgreSQL nor MongoDB is installed in this sandbox (`which psql mongod postgres` finds nothing, checked again 2026-11-15). No comparison number is claimed anywhere — any number would be invented. Done = the same workload runs against a real PostgreSQL and a real MongoDB on the same machine, and the numbers are published side by side with the machine and config. |
| 9 | Production hardening | pending | Several prototype-only behaviours remain: trust auth when no users are configured (any local client, no password); self-signed TLS certificate with no channel binding; SCRAM lockout in-memory only (a restart clears it); no encryption at rest; SSTables fully loaded into memory on open; single-machine lock file (no NFS). Done = each of these is fixed or the V1.0 scope explicitly excludes it in writing. |
| 10 | Independent security audit | pending | No outside audit of the auth, wire protocol, or storage code. The code has self-review fixes (see README "review fixes" sections) and 255 tests, but that is not an audit. |
| 11 | DDL inside transactions | pending | CREATE TABLE inside a transaction fails with 0A000. Done = DDL is transactional (or the V1.0 scope explicitly excludes it in writing). |
| 12 | Secondary indexes | pending | `doc find` is a linear scan; tables have no indexes either. Done = at least one index type works with tests. |
| 13 | Multi-node / replication | pending | Single node only; out of scope for the current design. Listed so nobody assumes otherwise. |
| 14 | Savepoint PG-compat (portals/statements) | done (V0.8) | ROLLBACK TO SAVEPOINT closes portals and prepared statements created after the savepoint (26000 on later use); pre-savepoint ones survive. Regression tests: `savepoint_rollback_closes_portals_and_statements_created_after_it`, `savepoint_rollback_keeps_portals_and_statements_created_before_it`. |
| 15 | Graceful shutdown (SIGINT/SIGTERM) | done (V0.8) | First signal: stop accepting, 5s grace for live queries, stop auto-vacuum, flush + save meta.json, exit 0. Second signal: immediate exit (130). Regression test: `graceful_shutdown_sigterm_exits_zero_and_keeps_data`. |
| 16 | Zeno-only benchmark command | done (V0.8) | `zeno bench` measures KV put/get + table insert/select (median/p95/ops/s) with warmup, on a fresh temp dir — 3 measured runs per row count, median of the 3 reported (a single sample varied 2x run to run in review), and the temp dir is removed by a Drop guard on every exit path, including errors. Regression tests: `bench_command_reports_measured_numbers`, `bench_duplicate_rows_rejected_with_clear_error`, `run_error_path_removes_temp_dir`. It is explicitly NOT a comparison (see item 8). |
| 17 | SQL parser (real, not string-matched) | done (V0.7) | Lexer + recursive-descent parser with line/column syntax errors; multi-condition WHERE, ORDER BY / LIMIT / OFFSET, multi-row INSERT, multi-SET UPDATE. |
| 18 | MVCC snapshot isolation + savepoints | done (V0.6/V0.7) | BEGIN/COMMIT/ROLLBACK, write-write conflict 40001, SAVEPOINT / ROLLBACK TO / RELEASE, idle-transaction timeout. |
| 19 | SCRAM-SHA-256 auth + TLS 1.2/1.3 | done (V0.4/V0.5) | With users configured, password auth is required; self-signed cert (prototype only — see item 9). |
| 20 | Auto-vacuum | done (V0.7) | Background thread, snapshot-safe, panic-caught, no-op does not rewrite SSTables. |

## Notes from the V0.8 build

- **ctrlc needs the `termination` feature for SIGTERM.**
  The first V0.8 build used plain `ctrlc = "3"`, and SIGTERM
  killed the server at once (exit 143) while SIGINT was also
  uncaught in the test harness — which turned out to be a
  second, separate mistake: the test's `$!` was the wrapper
  shell's PID, not the server's (this sandbox's exec wrapper
  runs the command through an extra `bash -c`, so `$!` points
  at an inner shell). Both are fixed: `ctrlc = { version =
  "3", features = ["termination"] }` in Cargo.toml, and the
  graceful-shutdown test uses `Child::id()` (the real PID) plus
  the `kill` command. Lesson kept here so the next person does
  not re-learn it: verify the signal reaches the real PID, and
  read the crate's feature flags before assuming a signal is
  handled.
- **The non-blocking accept loop.** `serve` polls the listener
  (5 ms sleep on WouldBlock) so a shutdown signal is noticed
  promptly. No measured cost: the pgwire suite runs in ~21.5s
  with it, the same as the V0.7 baseline (~21s).
- **Leaked socket clones (found and fixed in V0.8).** The first
  V0.8 build kept a clone of every accepted socket in the
  shutdown list forever. A socket sends FIN only when its last
  fd closes, so the peer never saw EOF: after a failed login
  the client waited out its whole 5 s read timeout instead of
  seeing the close at once, and the pgwire suite went from
  ~21s to ~57s (scram tests alone: 160s serially). The fix is
  `LiveSocketGuard` in `pgwire.rs`: the connection thread
  removes its clone when it ends (normal return or panic).
  After the fix the suite is back to ~21.5s (scram serial:
  48s, which is the genuine built-in 2 s failure-delay work).
  Regression test: `failed_login_closes_connection_promptly`
  (the close must arrive in under 3 s, well inside the 5 s
  client timeout).

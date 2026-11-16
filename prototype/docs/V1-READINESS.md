# Zeno V1.0 readiness checklist

What is still missing before Zeno can call itself V1.0 — with an
honest status per item. Statuses as of **V0.9.0** (2026-11-16).
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
| 3 | JOIN | done (V0.9) | INNER JOIN and LEFT JOIN work (nested-loop; aliases, qualified columns, `*` and `u.*` expansion, NULL padding on LEFT misses, 42702 ambiguous / 42703 unknown / 42P01 missing table, 42712 duplicate alias/table). RIGHT / FULL / CROSS JOIN are still 0A000 — a hash join and the remaining JOIN types are V1.0+ work. Regression tests: `v09_inner_join_returns_matching_rows`, `v09_left_join_pads_missing_rows_with_null`, `v09_ambiguous_column_is_42702_and_right_join_is_0a000`, `v09fix_duplicate_alias_is_42712_and_self_join_still_works`, `v09fix_qualified_star_expands`. |
| 4 | Subqueries | done (V0.9) | `WHERE ... IN (SELECT ...)` / `NOT IN` (single-column) and scalar `= (SELECT ...)` (0 rows = NULL, 1 row = value, many rows = 21000) work, through Simple Query and the extended protocol, inside transactions (same snapshot). FROM-subqueries are still 0A000. **Correlated subqueries are not supported** (a subquery cannot reference the outer query's tables) and **scalar subqueries in the SELECT list are not supported** (0A000) — both are documented in the README. Cost after the V0.9 review fix: each subquery is evaluated once per statement (hoisted before the WHERE loop), not once per outer row — a nested IN of depth 2 over 200-row tables finishes in well under a second (it used to run 30s+ and never finish). A SELECT takes a statement-level snapshot under the lock and then executes with the lock released, so a slow SELECT no longer blocks other connections; a statement timeout (57014, `ZENO_STATEMENT_TIMEOUT_MS`, default 30000 ms) cancels a SELECT that runs too long. Regression tests: `v09_in_subquery_and_not_in`, `v09_scalar_subquery_null_one_and_many_rows`, `v09_from_subquery_is_0a000`, `v09fix_nested_in_subquery_finishes_fast`, `v09fix_second_connection_not_blocked_by_slow_select`, `v09fix_statement_timeout_cancels_slow_query`, `v09fix_deep_subquery_nesting_is_54001_and_server_survives`. |
| 5 | GROUP BY / HAVING / aggregates | done (V0.9) | GROUP BY (one or more columns) + COUNT(*), COUNT(col), SUM, AVG, MIN, MAX + HAVING (with AND) + ORDER BY on an aggregate/alias work, with JOINs and **without GROUP BY** (one row over the whole table; COUNT 0 / SUM NULL over no rows — `SELECT COUNT(*) FROM orders HAVING COUNT(*) > 1` returns one row). Wrong aggregate input is 22P02, a non-grouped column is 42803, an unknown column in the SELECT list / HAVING / ORDER BY is 42703 (a HAVING output alias is 42703 too). SUM over plain integers is exact (i128); AVG over plain integers is exact via integer division + remainder decimal (non-terminating divisions run to 16 decimal places, documented as approximate); an integer SUM/AVG overflowing i128 is 22003. Regression tests: `v09_group_by_aggregates`, `v09_having_filters_groups_and_order_by_alias`, `v09_aggregate_errors`, `v09fix_having_without_group_by`, `v09fix_aggregate_error_codes`, `v09fix_avg_exact_and_sum_overflow`. |
| 6 | Two-phase commit (2PC) | pending | No PREPARE TRANSACTION / COMMIT PREPARED. Transactions are snapshot isolation only. Done = 2PC works across a crash (prepared txns survive restart) with tests. |
| 7 | READ COMMITTED / SERIALIZABLE | pending | Snapshot isolation only; every statement in a transaction sees the BEGIN snapshot. Done = at least one more isolation level works with tests. |
| 8 | Benchmarks vs PostgreSQL / MongoDB | pending | `zeno bench` (V0.8) measures Zeno's own engine only. No comparison ran, because neither PostgreSQL nor MongoDB is installed in this sandbox (`which psql mongod postgres` finds nothing, checked again 2026-11-15). No comparison number is claimed anywhere — any number would be invented. Done = the same workload runs against a real PostgreSQL and a real MongoDB on the same machine, and the numbers are published side by side with the machine and config. |
| 9 | Production hardening | pending | Several prototype-only behaviours remain: trust auth when no users are configured (any local client, no password); self-signed TLS certificate with no channel binding; SCRAM lockout in-memory only (a restart clears it); no encryption at rest; SSTables fully loaded into memory on open; single-machine lock file (no NFS). Done = each of these is fixed or the V1.0 scope explicitly excludes it in writing. |
| 10 | Independent security audit | pending | No outside audit of the auth, wire protocol, or storage code. The code has self-review fixes (see README "review fixes" sections) and 283 tests, but that is not an audit. |
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

## Notes from the V0.9 build

- **NULLs arrived with JOINs.** V0.8's `StmtOutcome::Rows`
  was `Vec<Vec<String>>` and `data_row` never wrote -1, because
  stored values are never NULL. A LEFT JOIN miss needs a real
  NULL, so both changed to `Option<String>` (and `CachedRows`
  in `extended.rs` with them). The test client's `rows()` already
  parsed -1 as `None`, so the wire tests needed no harness change.
- **A subquery error must fail the statement, not filter a row.**
  The first executor draft evaluated WHERE with `retain` and
  swallowed errors (`unwrap_or(false)`); a 21000 inside a
  subquery would then have silently dropped rows instead of
  erroring. The loop is now a plain fallible `for` that returns
  the first error.
- **The test caught a wrong expectation, not a bug.** The
  extended-protocol test expected Sanjay's total as 350 with
  `WHERE o.amount > $1` ($1 = 100) — but his 100 order is not
  `> 100`, so the correct total is 250. The expectation was
  fixed, not the code.
- **Old tests that asserted "not supported" had to move.**
  `parser_syntax_errors_carry_line_and_column` asserted JOIN and
  `COUNT(*)` are 0A000; it now asserts JOIN over a missing table
  is 42P01, RIGHT JOIN is 0A000, and `COUNT(*)` returns 4. The
  parser unit test `join_group_by_aggregate_and_subquery_are_not_supported`
  became two tests: the features parse, and the still-unsupported
  ones (RIGHT/FULL/CROSS JOIN, FROM-subqueries, UNION, OR,
  EXISTS) stay 0A000.
- **Nested-loop JOIN is a deliberate V0.9 limit, not an
  oversight.** Every table is scanned once and every pair is
  compared; there is no hash join and no index. It is documented
  as slow on large inputs in the README and in `src/query.rs`,
  and no speed number is claimed for it.

## Notes from the V0.9 review fixes (B1/B2/B3, M1–M5)

A reviewer re-probed V0.9 and found 3 blockers and 5
must-fixes, all verified by probe; all are fixed, with
regression tests (11 new pgwire tests `v09fix_*` + 5 new
parser unit tests; suite total 267 → 283):

- **B1 — duplicate alias/table (42712).** `Scope::push` in
  `src/query.rs` now rejects a table key named twice
  (42712, PostgreSQL's "table name specified more than
  once"); before, the second table silently overwrote the
  first table's columns in the merged row. Self-joins with
  distinct aliases still work.
- **B2 — subquery hoisting + snapshot execution + statement
  timeout.** Each subquery is evaluated once per statement
  (hoisted before the WHERE loop) instead of once per outer
  row — nested IN depth 2 over 200-row tables went from 30s+
  (never finished) to well under a second. A SELECT now takes
  a statement-level snapshot under the shared lock and
  executes against it with the lock released, so a slow SELECT
  (measured: a 500×500 cross product taking 2.9s) no longer
  blocks a second connection (measured: its `COUNT(*)` answered
  in 58ms mid-query). Backstop: a statement timeout, 57014,
  `ZENO_STATEMENT_TIMEOUT_MS` (default 30000 ms, `0`
  disables), checked inside the long loops.
- **B3 — subquery nesting cap (54001).** The parser caps
  nesting at 64 levels; 1000-deep nesting used to overflow the
  stack and kill the server process, and now returns 54001
  with the server alive. 40-deep nesting still works.
- **M1 — HAVING without GROUP BY.** The parser no longer
  requires GROUP BY before HAVING (the executor already
  handled it).
- **M2 — error codes.** ORDER BY on a non-grouped column is
  42803 (was a misleading 42703); unknown columns in the
  SELECT list / HAVING are checked for existence first
  (42703) and only then for GROUP BY membership (42803); a
  HAVING output alias is 42703. `IN (1, 2)`, `LIMIT $1`,
  SELECT-list scalar subqueries, `ON ... AND ...`, `ON col =
  1`, `COUNT(DISTINCT ...)`, `GROUP BY 1` / `ORDER BY 1` are
  all 0A000 now (the README's "Those fail with 0A000" claim is
  true for them). `SELECT u.*` is implemented (qualified-star
  expansion) instead of erroring.
- **M3 — IS NULL message.** It no longer claims "Zeno has no
  NULLs" — NULLs exist in SELECT results; only the syntax is
  unsupported.
- **M4 — AVG exact, SUM overflow errors.** AVG over integers
  no longer goes through f64 (`AVG(9007199254740993,
  9007199254740993)` is now exactly 9007199254740993);
  non-terminating divisions expand to 16 decimal places,
  documented as approximate. An integer SUM/AVG overflowing
  i128 is 22003, not a silent f64 approximation.
- **M5 — docs.** README and this checklist updated for all of
  the above; the "no speed claim / nested-loop slowness"
  wording was left untouched.
- **Minors fixed along the way:** unknown GROUP BY / ORDER BY
  columns now error even over an empty result set (up-front
  validation); HAVING-alias code (42703, via M2b).
- **Minors deliberately left, documented in the README:**
  WHERE on an unknown column with one table still silently
  matches nothing (V0.3 behaviour — changing it risked
  regressions); no LIMIT pushdown (LIMIT applies after the
  full result is built — a big cross product can use a lot of
  memory first); correlated subqueries stay unsupported
  (documented, no syntax for them).

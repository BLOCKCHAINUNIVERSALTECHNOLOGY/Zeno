# Zeno V1.0 readiness checklist

What is still missing before Zeno can call itself V1.0 — with an
honest status per item. Statuses as of **V0.11.0** (2026-11-16).
Nothing here is a promise of a date; "pending" means not done,
not "coming soon".

## Status key

- **done** — implemented, with a regression test.
- **pending** — not done. The note says what is missing and,
  where one exists, what would prove it done.

## Checklist

| # | Item | Status | Note |
|---|------|--------|------|
| 1 | Real-client verification with `psql` / libpq | pending | `psql` is NOT installed in this sandbox (`which psql` finds nothing, checked again 2026-11-16). Every wire-protocol test speaks raw TCP from a hand-rolled client instead. Done = the same server answers a real `psql` session (Simple + extended protocol, SCRAM login, prepared statements) on a machine that has it. |
| 2 | Process-crash recovery test | done (V0.10, extended V0.11) | `v10_power_loss_kill9_committed_rows_survive`: a real server writes committed rows (5 users, 6 orders, WAL-only), opens a transaction that never commits, is killed with SIGKILL (no graceful shutdown), gets a torn line appended to `wal.log`, and restarts on the same directory — every committed row comes back, the uncommitted row is gone, the torn line is warned about but does not block the open, and the database stays writable (a row written after the recovery survives a second, graceful restart too). No data loss was found, so no WAL fix was needed. Honest limit: a kill -9 is a process crash, not a power cut — there is still no test that cuts power mid-fsync or verifies the on-disk files after an OS crash. **V0.11 extends this to compaction/vacuum:** `v11_compact_crash_after_new_table_reopens_old_generation`, `v11_compact_crash_after_manifest_reopens_new_generation` and `v11_vacuum_crash_after_manifest_reopens_new_generation` crash a real CLI `compact` / `vacuum` at each commit stage (exit 137 = simulated kill -9) and reopen — committed rows present, deleted rows gone, exactly one generation live. A real power cut is still untested (see the V1 acceptance list). |
| 3 | JOIN | done (V0.9) | INNER JOIN and LEFT JOIN work (nested-loop; aliases, qualified columns, `*` and `u.*` expansion, NULL padding on LEFT misses, 42702 ambiguous / 42703 unknown / 42P01 missing table, 42712 duplicate alias/table). RIGHT / FULL / CROSS JOIN are still 0A000 — a hash join and the remaining JOIN types are V1.0+ work. Regression tests: `v09_inner_join_returns_matching_rows`, `v09_left_join_pads_missing_rows_with_null`, `v09_ambiguous_column_is_42702_and_right_join_is_0a000`, `v09fix_duplicate_alias_is_42712_and_self_join_still_works`, `v09fix_qualified_star_expands`. |
| 4 | Subqueries | done (V0.9, extended V0.10) | `WHERE ... IN (SELECT ...)` / `NOT IN` (single-column) and scalar `= (SELECT ...)` (0 rows = NULL, 1 row = value, many rows = 21000) work, through Simple Query and the extended protocol, inside transactions (same snapshot). FROM-subqueries are still 0A000. **V0.10 adds scalar subqueries in the SELECT list, correlated and uncorrelated** (`SELECT name, (SELECT MAX(amount) FROM orders WHERE orders.user_id = users.id) FROM users` — per-row values 250 / 50 / 300 / NULL; uncorrelated evaluated lazily once per statement; 0 rows = NULL, >1 row = 21000, >1 column = 42601; aggregates inside; GROUP BY: uncorrelated same value per group, correlated only on GROUP BY columns, anything else 42803; statement timeout 57014 applies). A qualified column is now a valid WHERE right-hand side (`orders.user_id = users.id`); an unqualified bare word stays a literal. **Correlated subqueries in WHERE work since the V0.10 review fix** — a WHERE subquery that references its own statement's tables, or an ancestor statement's, is evaluated once per row, against that row (uncorrelated ones are still hoisted once per statement). Cost: a correlated SELECT-list subquery runs once per outer row (once per group when grouped) with no index and no hash join, so it is slow on large inputs by design. Regression tests: `v09_in_subquery_and_not_in`, `v09_scalar_subquery_null_one_and_many_rows`, `v09_from_subquery_is_0a000`, `v09fix_nested_in_subquery_finishes_fast`, `v09fix_second_connection_not_blocked_by_slow_select`, `v09fix_statement_timeout_cancels_slow_query`, `v09fix_deep_subquery_nesting_is_54001_and_server_survives`, `v10_select_list_subquery_uncorrelated_is_evaluated_once`, `v10_select_list_subquery_correlated_per_row_value`, `v10_select_list_subquery_error_codes`, `v10_select_list_subquery_with_group_by`, `v10_select_list_subquery_timeout_cancels_slow_query`, `v10_power_loss_kill9_committed_rows_survive`, `v10_select_list_subquery_extended_protocol`, `v10fix_nested_select_list_subquery_references_grand_outer`, `v10fix_correlated_where_subquery_evaluated_per_row`. |
| 5 | GROUP BY / HAVING / aggregates | done (V0.9) | GROUP BY (one or more columns) + COUNT(*), COUNT(col), SUM, AVG, MIN, MAX + HAVING (with AND) + ORDER BY on an aggregate/alias work, with JOINs and **without GROUP BY** (one row over the whole table; COUNT 0 / SUM NULL over no rows — `SELECT COUNT(*) FROM orders HAVING COUNT(*) > 1` returns one row). Wrong aggregate input is 22P02, a non-grouped column is 42803, an unknown column in the SELECT list / HAVING / ORDER BY is 42703 (a HAVING output alias is 42703 too). SUM over plain integers is exact (i128); AVG over plain integers is exact via integer division + remainder decimal (non-terminating divisions run to 16 decimal places, documented as approximate); an integer SUM/AVG overflowing i128 is 22003. Regression tests: `v09_group_by_aggregates`, `v09_having_filters_groups_and_order_by_alias`, `v09_aggregate_errors`, `v09fix_having_without_group_by`, `v09fix_aggregate_error_codes`, `v09fix_avg_exact_and_sum_overflow`. |
| 6 | Two-phase commit (2PC) | pending | No PREPARE TRANSACTION / COMMIT PREPARED. Transactions are snapshot isolation only. Done = 2PC works across a crash (prepared txns survive restart) with tests. |
| 7 | READ COMMITTED / SERIALIZABLE | pending | Snapshot isolation only; every statement in a transaction sees the BEGIN snapshot. Done = at least one more isolation level works with tests. |
| 8 | Benchmarks vs PostgreSQL / MongoDB | pending | `zeno bench` (V0.8) measures Zeno's own engine only. No comparison ran, because neither PostgreSQL nor MongoDB is installed in this sandbox (`which psql mongod postgres` finds nothing, checked again 2026-11-16). No comparison number is claimed anywhere — any number would be invented. Done = the same workload runs against a real PostgreSQL and a real MongoDB on the same machine, and the numbers are published side by side with the machine and config. |
| 9 | Production hardening | pending | V0.11 fixed the durability half of this (SSTable manifest commit protocol, WAL parent-directory sync, absolute deadlines for slow clients — see items 21–23). Several prototype-only behaviours remain: trust auth when no users are configured (any local client, no password); self-signed TLS certificate with no channel binding; SCRAM lockout in-memory only (a restart clears it); no encryption at rest; SSTables fully loaded into memory on open; single-machine lock file (no NFS). Done = each of these is fixed or the V1.0 scope explicitly excludes it in writing. |
| 10 | Independent security audit | pending | No outside audit of the auth, wire protocol, or storage code. The code has self-review fixes (see README "review fixes" sections) and 306 tests, but that is not an audit. |
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
| 21 | Durable compaction/vacuum commit protocol | done (V0.11) | `sst-manifest.json` commit: new SSTable written + synced, manifest atomically committed to name only the new table, old files deleted only then, unlink + directory-sync errors propagated. Crash before the commit reopens the old generation, crash after it reopens the new one — a deleted key never comes back. Orphans are ignored (never loaded); a corrupt SSTable, live or orphan, is quarantined; a manifest-listed file that is missing warns loudly instead of refusing the open. Regression tests: `v11_compact_crash_after_new_table_reopens_old_generation`, `v11_compact_crash_after_manifest_reopens_new_generation`, `v11_vacuum_crash_after_manifest_reopens_new_generation` (demo.sh §17 shows it live). |
| 22 | WAL namespace durability | done (V0.11) | `Wal::open` fsyncs the parent directory on creating a new WAL file; `Wal::clear` fsyncs it after deleting the old one — an acknowledged write's WAL pathname is durable, not just its contents. Regression tests: `v11_wal_rotation_after_flush_survives_reopen`, `clear_then_reopen_does_not_resurrect_old_records`. Honest limit: a directory fsync cannot be observed from inside a test; a real power cut is still untested. |
| 23 | Slow-drip connection slots | done (V0.11) | Absolute deadlines for the handshake and for every frame (60 s each, `ZENO_HANDSHAKE_TIMEOUT_SECS` / `ZENO_FRAME_TIMEOUT_SECS` override); the budget starts at the frame's first byte, so an idle connection is not cut off between queries. Over-limit refusals run on a separate best-effort thread, off the accept loop. Regression tests: `deadline_reader_closes_a_slow_drip_client`, `v11_slow_drip_frame_frees_its_slot`. Honest limit: a single blocked `read()` can still wait out the socket timeout, and the TLS handshake itself is not deadline-wrapped. |
| 24 | Bare SQL NULL | done (V0.11) | Bare `NULL` (any case) is a real NULL: stored as JSON `null`, `WHERE c = NULL` never matches, `UPDATE ... SET c = NULL` stores NULL, `SELECT *` reads it as NULL, `COUNT(col)` skips it. Quoted `'NULL'` stays text. Regression tests: `bare_null_is_a_real_null_and_quoted_null_is_text`, `v11_bare_null_stores_real_null_and_quoted_null_is_text`. Known gap: a bound NULL parameter over the extended protocol still arrives as an empty string; `IS NULL` syntax is still 0A000. |
| 25 | Unambiguous document keys | done (V0.11) | Collection and id are percent-escaped (`:` → `%3A`, `%` → `%25`) in `put`, `get` and `find` alike — (`a:b`, `c`) and (`a`, `b:c`) are different keys, and `find` is isolated per collection. Keys with no `%` or `:` encode byte-identically to V0.10, so old documents read with no migration; only keys containing `%` or `:` change, and those were ambiguous before. Regression tests: `separator_collision_is_isolated`, `legacy_keys_without_separator_still_read`. |
| 26 | Unknown WHERE column is 42703 | done (V0.11) | A single-table query with an unknown WHERE column now fails with 42703 instead of silently returning zero rows — validated up front, so it errors even over an empty table; UPDATE / DELETE too. Regression test: `v11_unknown_where_column_is_42703`. |
| 27 | CI draft + toolchain pin + MSRV | done (V0.11, draft) | Drafts in `prototype/ci/` (`.github/workflows/ci.yml`, `rust-toolchain.toml` pinned to 1.99.1) and `rust-version = "1.85"` in `Cargo.toml`. They move to the repo root on push — CI only runs from there. Done = the workflow is live at the root and green. |
| 28 | Unique test temp dirs | done (V0.11) | Every integration-test directory is unique per call (PID + nanoseconds + counter, `unique_test_dir` in `src/lib.rs`), so concurrent runs of the same test binary cannot delete each other's data. |

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
  WHERE on an unknown column with one table silently matched
  nothing (V0.3 behaviour) — **fixed in V0.11: it is 42703 now**
  (see "Notes from the V0.11 build", item 26); no general LIMIT pushdown (LIMIT applies after
  the full result is built — a big cross product is now capped
  at 100_000 joined rows, 54000, instead of growing memory
  first; simple aggregates stream and LIMIT 0 skips the
  projection); correlated subqueries in WHERE stayed
  unsupported in V0.9 (documented, no syntax for them) — fixed
  in the V0.10 review (per-row evaluation, see below).

## Notes from the V0.10 build

- **A correlated subquery needs a column on the right-hand side
  of WHERE.** The example query
  `(SELECT MAX(amount) FROM orders WHERE orders.user_id =
  users.id)` could not even parse in V0.9: a WHERE condition
  was `column <op> literal` only, so `users.id` after `=` was
  read as the bare-word literal "users" and the trailing `.id`
  was a syntax error. V0.10 adds `CondRhs::Column` — but only
  for a QUALIFIED reference (`table.column`); an unqualified
  bare word stays a literal (`city = Delhi` still means the
  text "Delhi"), so no existing query changes meaning.
  UPDATE / DELETE reject a column-to-column comparison with
  0A000 (the table store only filters on literals).
- **Inner scope shadows outer scope, everywhere.** Column
  resolution in a subquery tries its own tables first and
  falls through to the outer row only when nothing matches —
  for qualified references, unqualified references, validation
  (`validate_column_with_outer`), JOIN ON, WHERE (both sides),
  GROUP BY, HAVING and aggregates. A reference that exists in
  both is read from the inner row, never the outer one.
- **Uncorrelated means evaluated once — but lazily.** The
  first draft cached uncorrelated SELECT-list subqueries
  before the row loop, which would have failed a statement
  over an empty outer table with the subquery's own error
  (21000) even though it returns no rows at all. The cache is
  now lazy: the correlation check runs up front (a missing
  table is still 42P01 at plan time), the value is evaluated
  on the first row that needs it and reused after that.
- **GROUP BY + correlated subquery is 42803, not a wrong
  value.** The per-group outer row carries ONLY the GROUP BY
  key values, so a correlated reference to any other outer
  column fails in `outer_value` instead of reading some other
  row of the group. The first probe of this caught a wrong
  test, not a bug: `GROUP BY user_id` over `users` is 42703
  because `users` has no `user_id` column — grouping by `id`
  is the correct query.
- **The old "not supported" tests had to move, again.** The
  parser unit test and the pgwire 0A000 test that asserted
  SELECT-list subqueries are 0A000 now assert they work
  (uncorrelated MAX 300 in every row; `MAX(id)` is 5 in every
  row), and the CLI `--version` test moved from 0.9.0 to
  0.10.0. Suite total 283 → 290 (133 unit + 43 engine +
  114 pgwire).
- **Process-crash recovery test found nothing to fix.** Every committed
  row survived kill -9 + a torn WAL line on the first run, and
  the uncommitted row was correctly gone — the WAL fsync
  discipline from V0.2/V0.6 already held. The test stays as
  the regression proof. A kill -9 is still not a power cut:
  no mid-fsync power-loss test exists.

## Notes from the V0.10 review fixes (B1, M1–M6, m1–m4)

A reviewer re-probed V0.10 and found 1 blocker, 6 must-fixes
and 4 minors, all verified by probe; all are fixed, with
regression tests (4 new pgwire tests `v10fix_*`; suite total
290 → 294: 133 unit + 43 engine + 118 pgwire, green in both
the debug and the release profile):

- **B1 — a big cross product OOM-killed the server.** `COUNT(*)`
  over a 2000×2000 join materialised 4M joined rows (~2 KB
  each) and died with SIGABRT (`memory allocation of 808 bytes
  failed`); 1000×1000 took 6.49 s and ~2 GB. Fix, in
  `src/query.rs`: (a) a simple aggregate query (aggregate
  items only, no GROUP BY / HAVING / ORDER BY, no SELECT-list
  subquery) now streams — `stream_joined` hands each joined
  row to the accumulator and drops it, so the 2000×2000 COUNT
  returns 4000000 in ~2.2 s (release) with flat memory; the
  streaming arithmetic mirrors `compute_aggregate` exactly
  (i128-exact integer SUM/AVG, 22003 on overflow, 22P02 on the
  first non-finite value in row order, exact AVG); (b) a
  materialised join is capped at 100_000 rows
  (`ZENO_MAX_JOIN_ROWS` overrides it, `0` disables it) and
  fails fast with 54000 — a plain 1000×1000 SELECT is 54000 in
  ~0.3 s; (c) LIMIT 0 returns no rows without running the
  projection (M4). No general LIMIT pushdown yet: a plain
  `LIMIT 5` over a big join still materialises first and hits
  the cap — documented in the README, not claimed otherwise.
- **M1 — nested SELECT-list subquery, grand-outer 42703.**
  Uncorrelated subqueries ran with the parent outer context
  only (`outer.parent`), skipping one level, so a subquery
  nested inside another could not read the grand-outer row.
  Both call sites (`execute_plain`, `execute_aggregate`) now
  pass `outer` itself. Safe by construction: "uncorrelated"
  means no reference matches this statement's scope, so
  passing `outer` only exposes ancestor levels, and the
  nearest scope still wins — shadowing is unchanged (regression
  test covers an inner FROM that reuses the outer table name).
- **M2 / M5 — correlated WHERE subqueries work now.** WHERE
  subqueries were always hoisted with no outer context, so any
  outer reference failed with a misleading 42703. Now each
  WHERE subquery is checked for correlation against its own
  statement's scope and every ancestor scope; a correlated one
  is evaluated once per row, against that row (with the full
  parent chain, so a WHERE subquery nested inside a SELECT-list
  subquery can read both its own statement's alias and the
  grand-outer row). Uncorrelated ones are still hoisted once.
  M5's probe query now returns correct rows instead of 42703,
  so no separate "not supported" message was needed.
- **M3 — timeout tests use a 2000×2000 workload.** The
  streaming aggregate made the old 500×500 cross product
  finish inside the 500 ms timeout in release, so
  `v10_select_list_subquery_timeout_cancels_slow_query` (and
  the V0.9 `v09fix_statement_timeout_cancels_slow_query`, which
  failed in release for the same reason) now seed 2000 rows
  per table. The test-harness `Server::start` also changed
  (m4): readiness is now the server's own stdout listening
  line, not a bare TCP probe + 150 ms settle — under parallel
  load the probe could connect to another test's server on the
  same port, which failed the TLS test once in a parallel
  release run. The drain thread keeps reading until EOF: an
  early version exited when the starter stopped listening,
  closing the pipe while the server was still printing startup
  lines, and the server panicked with EPIPE (exit 101).
- **M4 — LIMIT 0 + failing subquery is 0 rows, no error.**
  `execute_plain`, `execute_aggregate` and the streaming
  aggregate path all return early on LIMIT 0, after the
  up-front column validation — so a failing SELECT-list
  subquery (21000) does not fail a query that returns nothing.
- **M6 — README "Tests" section was stale** (128 unit / 96
  pgwire / 267 total vs the real 133 / 114 / 290). Counts are
  now 133 unit + 43 engine + 118 pgwire = 294, verified
  against `cargo test` and `cargo test --release`, and the
  section says so — when the counts change, it changes with
  them.
- **Minors:** `outer_value` on a missing key in a plain outer
  row is XX000 (internal error) instead of a silent `""`
  (unreachable in practice — Zeno has no ADD COLUMN);
  `parse_subquery` restores `subquery_depth` on a parse error;
  the integer SUM/AVG path checks the statement deadline every
  1024 values, like the f64 path.


## V1 acceptance list (authoritative, V0.11)

One list, one verdict per item — **release blocker** (V1.0
cannot ship without it), **post-V1** (explicitly after V1.0),
or **excluded** (not in Zeno at all, by design). This list is
the authority; if the design draft or an old note disagrees,
this list wins. "Done" items are listed so the list is
complete, not because they need more work.

| Item | Verdict | Note |
|------|---------|------|
| Real-client verification (`psql` / libpq) — checklist 1 | **release blocker** | No real client has ever spoken to the server yet. |
| Process-crash recovery — checklist 2 | done (V0.10, extended V0.11) | Kill -9 at every stage, WAL + compaction/vacuum. |
| Real power-loss test (power cut mid-fsync, on-disk files verified after an OS crash) | **release blocker** | Needs a test rig that cuts power; until it exists, V1.0 claims **process-crash recovery only**, never power-loss safety. |
| JOIN: INNER / LEFT — checklist 3 | done (V0.9) | Nested-loop only. |
| JOIN: RIGHT / FULL / CROSS | **post-V1** | 0A000 today; needs a hash join first. |
| Subqueries: WHERE IN / scalar, SELECT-list — checklist 4 | done (V0.9 / V0.10) | |
| Subqueries: FROM-subqueries | **post-V1** | 0A000 today. |
| GROUP BY / HAVING / aggregates — checklist 5 | done (V0.9) | |
| Two-phase commit (2PC) — checklist 6 | **release blocker** | Or the V1.0 scope explicitly excludes it in writing (checklist 6 allows that). |
| READ COMMITTED / SERIALIZABLE — checklist 7 | **release blocker** | Or explicitly excluded in writing (checklist 7 allows that). |
| Benchmarks vs PostgreSQL / MongoDB — checklist 8 | **post-V1** | Changed in V0.11 from the original design draft (§5 item 5): a comparison is only honest after the baseline benchmark and disk-backed SSTable blocks/cache exist (Phase 2/3). No comparison number is claimed anywhere. |
| Baseline benchmark (Zeno-only, published, reproducible) | **release blocker** | `zeno bench` exists (checklist 16) but no published baseline numbers yet — Phase 2. |
| Disk-backed SSTable blocks/cache (SSTables not fully loaded into memory on open) | **release blocker** | Phase 2. Today every SSTable loads fully into memory (checklist 9). |
| Group commit | **post-V1** | Performance, not correctness. |
| Production hardening — checklist 9 | **release blocker** | Each sub-item fixed, or the V1.0 scope explicitly excludes it in writing: trust auth with no users, self-signed TLS with no channel binding, in-memory-only SCRAM lockout, no encryption at rest, single-machine lock file. Durability half done in V0.11 (items 21–23). |
| Independent security audit — checklist 10 | **release blocker** | Self-review + tests are not an audit. |
| DDL inside transactions — checklist 11 | **release blocker** | Or explicitly excluded in writing. |
| Secondary indexes — checklist 12 | **release blocker** | Or explicitly excluded in writing. `doc find` is a linear scan today. |
| Multi-node / replication — checklist 13 | **excluded** | Single node by design; V1.0 is a single-node database. |
| Savepoint PG-compat — checklist 14 | done (V0.8) | |
| Graceful shutdown — checklist 15 | done (V0.8) | |
| Zeno-only benchmark command — checklist 16 | done (V0.8) | |
| SQL parser — checklist 17 | done (V0.7) | |
| MVCC snapshot isolation + savepoints — checklist 18 | done (V0.6/V0.7) | |
| SCRAM-SHA-256 auth + TLS — checklist 19 | done (V0.4/V0.5) | |
| Auto-vacuum — checklist 20 | done (V0.7) | |
| Durable compaction/vacuum commit protocol — checklist 21 | done (V0.11) | |
| WAL namespace durability — checklist 22 | done (V0.11) | |
| Slow-drip connection slots — checklist 23 | done (V0.11) | |
| Bare SQL NULL — checklist 24 | done (V0.11) | Bound NULL params still a gap (see item 24). |
| Unambiguous document keys — checklist 25 | done (V0.11) | |
| Unknown WHERE column is 42703 — checklist 26 | done (V0.11) | |
| CI draft + toolchain pin + MSRV — checklist 27 | done (V0.11, draft) | Live at the repo root on push. |
| Unique test temp dirs — checklist 28 | done (V0.11) | |
| UNION, OR, LIKE, `IS NULL` syntax, hash join, LIMIT pushdown | **post-V1** | All 0A000 today; no new SQL feature was added in V0.11 by design. |
| Cross-model transactional rollback (table + document + KV in one transaction) | **post-V1** | Design draft §2 promises it; the prototype does not have it. |

## Notes from the V0.11 build

- **A manifest changes what an id means.** SSTable ids are
  never reused — `next_sst_id` counts every `sst-*.sst` file
  on disk, orphans included — so after a quarantine the next
  flush takes a NEW id, not the freed one. The old
  `quarantine_second_sstable_corruption_keeps_first` test
  assumed the id was reused; it failed (the second torn file
  was an orphan, ignored, never quarantined) and was NOT
  changed by weakening the engine — the engine is right, the
  test's assumption was pre-manifest. The fix was in the
  engine's open path, two parts: (a) a corrupt ORPHAN is now
  quarantined too (a corrupt file in the data directory is
  never silently ignored — it is renamed to `.corrupt.N` for
  inspection); (b) a manifest-listed file that is missing
  warns loudly instead of refusing the whole open, because a
  quarantined table would otherwise wedge the next open (its
  id is still in the manifest, its file is gone).
- **The delete pass cleans orphans.** The first version of
  `compact()` deleted only the tables it knew in memory; a
  crash-order test caught an orphan from an earlier crashed
  compaction surviving on disk. `delete_old_sstables` now
  enumerates the directory and deletes every `sst-*.sst`
  except the new one — so each successful compaction also
  cleans up the previous crash's leftovers.
- **Bound NULL params are still not SQL NULL.** The literal
  `NULL` keyword is the only NULL source so far; `$1` bound
  to NULL over the extended protocol arrives as an empty
  string (pre-existing, in `extended.rs`). That is the next
  NULL fix, not this version's.
- **A deadline is checked between reads, not during one.**
  `DeadlineReader` bounds a slow drip, but a single blocked
  `read()` can still wait out the 60 s socket timeout, and the
  TLS handshake is not wrapped. The test proves the slot
  frees, not that every slow byte is cut off instantly.
- **Docs moved, not duplicated.** The root README and
  `docs/DESIGN.md` were NOT edited — their corrected versions
  are drafts in `prototype/docs-draft/` and move to the root
  on push. The prototype README and this checklist were edited
  in place. The design draft is marked proposal/future, with an
  explicit "Aaj ki haalat (V0.11)" under every section where it
  differs from the implementation.

// query.rs — the SELECT executor for Zeno V0.10: JOINs, subqueries,
// GROUP BY + aggregates, on top of the table store.
//
// A SELECT runs in three stages:
//   1. Snapshot + scope: every table the statement (and its
//      subqueries — WHERE and SELECT-list alike) can read is
//      scanned once under the shared lock, then the lock is
//      released — a long SELECT no longer blocks other
//      connections. The scope is the base table plus each JOINed
//      table (aliases are the names the query uses; a missing
//      table is 42P01, a table or alias named twice is 42712,
//      and inside a transaction a table created after BEGIN is
//      invisible — the same rule as V0.6).
//   2. Rows: the snapshot rows are nested-loop joined (the V0.6
//      snapshot when inside a transaction — JOIN/grouped reads
//      see the same snapshot as a plain SELECT, never newer
//      commits), then a nested-loop join combines them.
//      Nested-loop is the V0.9 choice for this scale: it is
//      simple and correct, and it gets slow on large inputs — a
//      hash join is V1.0+ work (see README). No index is used
//      anywhere. Each WHERE subquery is evaluated ONCE per
//      statement (hoisted before the WHERE loop — subqueries in
//      WHERE are always uncorrelated here, so this is always
//      correct) and the result reused for every outer row;
//      per-row evaluation used to make nested IN exponential.
//      A SELECT-list subquery is different: an UNCORRELATED one
//      is evaluated once per statement and reused for every
//      row, but a CORRELATED one (it references the outer
//      query's tables, e.g. `WHERE orders.user_id = users.id`)
//      is evaluated once per outer row — or once per group in a
//      GROUP BY query, where it may only use GROUP BY columns
//      (anything else is 42803). A correlated subquery over a
//      big table is therefore slow by design: it runs the inner
//      query once per row, with no index and no hash join —
//      see the README. A statement timeout
//      (57014, `ZENO_STATEMENT_TIMEOUT_MS`, default 30000 ms)
//      caps how long any of this may run, including SELECT-list
//      subqueries.
//   3. WHERE, then GROUP BY + aggregates + HAVING (or a plain
//      projection), then ORDER BY, then LIMIT/OFFSET. LIMIT is
//      applied last — there is no general LIMIT pushdown, so a
//      LIMIT 5 over a big JOIN still materialises the whole join
//      first (capped at `max_join_rows`, 54000 — see B1). Two
//      exceptions: a simple aggregate query (COUNT / SUM / MIN /
//      MAX, no GROUP BY) streams the join and never materialises
//      it at all, and LIMIT 0 returns no rows without running
//      the projection (so a failing SELECT-list subquery does
//      not fail a LIMIT 0 query).
//
// Values are `Cell = Option<String>`: stored values are never
// NULL, but a LEFT JOIN miss, an empty scalar subquery and an
// aggregate over no rows all produce NULL, and NULL is sent to
// the client as a real NULL (DataRow length -1), not as "".
// Comparisons involving NULL never match — the PostgreSQL rule
// (`NULL = x` is not true, so the row is filtered out).

use crate::engine::Engine;
use crate::parser::{
    AggFunc, AggregateExpr, CmpOp, ColumnRef, CondRhs, Condition, JoinKind, OrderByItem,
    SelectItem, Stmt, Value,
};
use crate::pgwire::{check_table_visible_in_txn, sql_err, table_err, Session, SqlError};
use crate::table::{compare_values, TableRow, TableStore};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// One cell of a result: `None` = SQL NULL.
pub type Cell = Option<String>;

/// One joined row: (table key, column) -> value. The table key
/// is the alias when one was given, else the table name.
pub type JoinedRow = BTreeMap<(String, String), Cell>;

/// One table in scope: its key (alias or name) and its columns
/// in registry order.
#[derive(Clone)]
struct ScopeTable {
    key: String,
    columns: Vec<String>,
}

/// A statement-level snapshot of every table a SELECT (and its
/// subqueries) can read: column lists and rows, taken once under
/// the shared lock. Executing against the snapshot — instead of
/// holding the lock for the whole query — is the B2 lock fix: a
/// long SELECT no longer blocks every other connection, and a
/// SELECT sees one consistent view even if another connection
/// writes mid-query (inside a transaction it is the BEGIN
/// snapshot plus the transaction's own writes, as before).
pub(crate) struct Snapshot {
    columns: BTreeMap<String, Vec<String>>,
    rows: BTreeMap<String, Vec<TableRow>>,
}

/// Every table name a statement can read: its own tables and
/// JOINs, plus every subquery's tables, recursively — WHERE
/// subqueries and SELECT-list subqueries (V0.10) alike.
fn collect_table_names(stmt: &Stmt, out: &mut BTreeSet<String>) {
    let Stmt::Select {
        items,
        table,
        joins,
        conditions,
        ..
    } = stmt
    else {
        return;
    };
    out.insert(table.clone());
    for join in joins {
        out.insert(join.table.clone());
    }
    if let Some(items) = items {
        for item in items {
            if let SelectItem::ScalarSubquery { query, .. } = item {
                collect_table_names(query, out);
            }
        }
    }
    for cond in conditions {
        match &cond.rhs {
            CondRhs::InSubquery { query, .. } | CondRhs::ScalarSubquery(query) => {
                collect_table_names(query, out);
            }
            CondRhs::Value(_) | CondRhs::Column(_) => {}
        }
    }
}

/// Take the snapshot for a statement: scan every table it can
/// read once, under the caller's lock. A missing table is 42P01.
pub(crate) fn collect_snapshot(
    engine: &mut Engine,
    tables: &mut TableStore,
    session: &Session,
    stmt: &Stmt,
) -> Result<Snapshot, SqlError> {
    let mut names = BTreeSet::new();
    collect_table_names(stmt, &mut names);
    let mut columns = BTreeMap::new();
    let mut rows = BTreeMap::new();
    for name in names {
        let cols = tables
            .columns(&name)
            .ok_or_else(|| sql_err("42P01", format!("no such table '{name}'")))?
            .to_vec();
        let scanned = fetch_table(engine, tables, session, &name)?;
        columns.insert(name.clone(), cols);
        rows.insert(name, scanned);
    }
    Ok(Snapshot { columns, rows })
}

/// Statement timeout (B2 backstop): a SELECT that runs longer
/// than this is cancelled with 57014 instead of running forever
/// and holding the server. Default 30 seconds; the
/// `ZENO_STATEMENT_TIMEOUT_MS` environment variable overrides it
/// (diagnostic/test hook); `0` disables it. Read once per
/// statement, so a long statement uses one deadline throughout,
/// including its subqueries.
fn statement_deadline() -> Option<Instant> {
    let ms: u64 = std::env::var("ZENO_STATEMENT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30_000);
    if ms == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(ms))
    }
}

/// Fail with 57014 (query_canceled) when the statement deadline
/// has passed. Called periodically inside the long loops, not on
/// every row, so the check itself costs nothing measurable.
fn check_deadline(deadline: Option<Instant>) -> Result<(), SqlError> {
    if let Some(at) = deadline {
        if Instant::now() > at {
            return Err(sql_err(
                "57014",
                "cancelled the statement due to statement timeout — the statement ran longer \
                 than the configured limit (ZENO_STATEMENT_TIMEOUT_MS, default 30000 ms)",
            ));
        }
    }
    Ok(())
}

/// The tables a SELECT may read: base table first, then each
/// JOINed table in written order.
#[derive(Clone)]
struct Scope {
    tables: Vec<ScopeTable>,
}

/// The outer query a subquery may reference (V0.10): the outer
/// row and its scope, plus the next level out (a subquery inside
/// a subquery may reference either level — PostgreSQL resolves
/// outward until a table matches). `group_only` is true when
/// the row carries only GROUP BY key values (a SELECT-list
/// subquery evaluated per group): a correlated reference to a
/// column that is NOT a GROUP BY column is then 42803, not a
/// silent NULL or a wrong value.
struct OuterCtx<'a> {
    row: &'a JoinedRow,
    scope: &'a Scope,
    parent: Option<&'a OuterCtx<'a>>,
    group_only: bool,
}

/// What resolving a column reference found.
enum Resolve {
    /// The value (`None` = NULL — a LEFT JOIN miss).
    Found(Cell),
    /// No table in scope has this column.
    NotFound,
    /// An unqualified name that exists in two or more tables.
    Ambiguous,
}

impl Scope {
    /// The scope of a SELECT: base table + JOINed tables. A
    /// missing table is 42P01; a table (or alias) named twice
    /// is 42712 (B1 — PostgreSQL's "table name specified more
    /// than once"). Without the duplicate check two tables
    /// sharing a key silently overwrote each other's columns in
    /// the merged row and returned mismatched values.
    fn of(tables: &TableStore, stmt: &Stmt) -> Result<Scope, SqlError> {
        Self::build(stmt, &|name| tables.columns(name).map(<[String]>::to_vec))
    }

    /// The scope of a SELECT against a snapshot (same rules,
    /// same errors — the snapshot already holds every table the
    /// statement can read).
    fn of_snapshot(snapshot: &Snapshot, stmt: &Stmt) -> Result<Scope, SqlError> {
        Self::build(stmt, &|name| snapshot.columns.get(name).cloned())
    }

    fn build(
        stmt: &Stmt,
        columns_of: &dyn Fn(&str) -> Option<Vec<String>>,
    ) -> Result<Scope, SqlError> {
        let Stmt::Select {
            table,
            table_alias,
            joins,
            ..
        } = stmt
        else {
            return Err(sql_err(
                "XX000",
                "internal error: Scope::of called with a non-SELECT statement",
            ));
        };
        let mut scope = Scope { tables: Vec::new() };
        scope.push(columns_of, table, table_alias.as_deref())?;
        for join in joins {
            scope.push(columns_of, &join.table, join.alias.as_deref())?;
        }
        Ok(scope)
    }

    fn push(
        &mut self,
        columns_of: &dyn Fn(&str) -> Option<Vec<String>>,
        name: &str,
        alias: Option<&str>,
    ) -> Result<(), SqlError> {
        let columns =
            columns_of(name).ok_or_else(|| sql_err("42P01", format!("no such table '{name}'")))?;
        let key = alias.unwrap_or(name).to_string();
        if self.tables.iter().any(|t| t.key == key) {
            return Err(sql_err(
                "42712",
                format!("table name '{key}' specified more than once"),
            ));
        }
        self.tables.push(ScopeTable { key, columns });
        Ok(())
    }

    /// All output columns for `SELECT *`: every column of every
    /// table in scope, base table first.
    fn star_columns(&self) -> Vec<String> {
        self.tables
            .iter()
            .flat_map(|t| t.columns.iter().cloned())
            .collect()
    }
}

/// Resolve a column reference against the scope, without a row:
/// unknown column (42703) or ambiguous unqualified name (42702).
/// A qualifier that names no table in scope is 42703 too.
/// With an outer context (V0.10, a subquery), a reference that
/// matches nothing in this scope falls through to the outer
/// scope(s) — an inner match always wins over an outer one.
fn validate_column_with_outer(
    scope: &Scope,
    col: &ColumnRef,
    outer: Option<&OuterCtx<'_>>,
) -> Result<(), SqlError> {
    match &col.qualifier {
        Some(q) => {
            if let Some(t) = scope.tables.iter().find(|t| t.key == *q) {
                if !t.columns.iter().any(|c| c == &col.name) {
                    return Err(sql_err(
                        "42703",
                        format!("column '{}.{}' does not exist", q, col.name),
                    ));
                }
                return Ok(());
            }
            let mut level = outer;
            while let Some(ctx) = level {
                if let Some(t) = ctx.scope.tables.iter().find(|t| t.key == *q) {
                    if !t.columns.iter().any(|c| c == &col.name) {
                        return Err(sql_err(
                            "42703",
                            format!("column '{}.{}' does not exist", q, col.name),
                        ));
                    }
                    return Ok(());
                }
                level = ctx.parent;
            }
            Err(sql_err(
                "42703",
                format!("missing FROM-clause entry for table '{q}'"),
            ))
        }
        None => {
            let matches: Vec<&ScopeTable> = scope
                .tables
                .iter()
                .filter(|t| t.columns.iter().any(|c| c == &col.name))
                .collect();
            match matches.len() {
                0 => {
                    let mut level = outer;
                    while let Some(ctx) = level {
                        let outer_matches: Vec<&ScopeTable> = ctx
                            .scope
                            .tables
                            .iter()
                            .filter(|t| t.columns.iter().any(|c| c == &col.name))
                            .collect();
                        match outer_matches.len() {
                            0 => {}
                            1 => return Ok(()),
                            _ => {
                                return Err(sql_err(
                                    "42702",
                                    format!(
                                        "column reference '{}' is ambiguous — qualify it with a table name",
                                        col.name
                                    ),
                                ));
                            }
                        }
                        level = ctx.parent;
                    }
                    Err(sql_err(
                        "42703",
                        format!("column '{}' does not exist", col.name),
                    ))
                }
                1 => Ok(()),
                _ => Err(sql_err(
                    "42702",
                    format!(
                        "column reference '{}' is ambiguous — qualify it with a table name",
                        col.name
                    ),
                )),
            }
        }
    }
}

/// Resolve a column reference in one joined row. A qualifier
/// that names no table, or a qualified column that does not
/// exist, is 42703; an ambiguous unqualified name is 42702; an
/// unknown unqualified name is `NotFound` (the caller decides
/// what that means — in WHERE on one table it matches no row,
/// the V0.3 behaviour; everywhere else it is 42703).
/// With an outer context (V0.10), a reference that matches
/// nothing in this row's scope falls through to the outer
/// row(s) — the correlated-subquery case. An inner match always
/// wins: a column that exists in the subquery's own tables is
/// never read from the outer row, even when the outer row has
/// a column of the same name.
/// One value out of an outer row (V0.10): the value when the
/// outer row carries that (table, column) key. A group-only outer
/// row lacks the key exactly when the column is NOT a GROUP BY
/// column, and that is 42803 — a correlated subquery in the
/// SELECT list of a grouped query can only use GROUP BY columns.
fn outer_value(ctx: &OuterCtx<'_>, table_key: &str, col_name: &str) -> Result<Resolve, SqlError> {
    match ctx.row.get(&(table_key.to_string(), col_name.to_string())) {
        Some(v) => Ok(Resolve::Found(v.clone())),
        None => {
            if ctx.group_only {
                Err(sql_err(
                    "42803",
                    format!(
                        "column '{col_name}' must appear in the GROUP BY clause or be used in an \
                         aggregate function — a correlated subquery in the SELECT list can only \
                         use GROUP BY columns of the outer query"
                    ),
                ))
            } else {
                // A plain outer row lacks the key only when its
                // scope says the column exists but the row was
                // written before the column did — Zeno has no
                // ADD COLUMN, so that cannot happen; it is
                // XX000 (an internal error), not a silent ""
                // that would hide a bug.
                Err(sql_err(
                    "XX000",
                    format!(
                        "internal error: outer row for table '{table_key}' has no value for \
                         column '{col_name}'"
                    ),
                ))
            }
        }
    }
}

fn resolve_with_outer(
    row: &JoinedRow,
    scope: &Scope,
    col: &ColumnRef,
    outer: Option<&OuterCtx<'_>>,
) -> Result<Resolve, SqlError> {
    match &col.qualifier {
        Some(q) => {
            if let Some(t) = scope.tables.iter().find(|t| t.key == *q) {
                if !t.columns.iter().any(|c| c == &col.name) {
                    return Err(sql_err(
                        "42703",
                        format!("column '{}.{}' does not exist", q, col.name),
                    ));
                }
                return Ok(match row.get(&(q.clone(), col.name.clone())) {
                    // A LEFT JOIN miss is stored as an explicit
                    // NULL; a row that simply lacks the key (a row
                    // written before the column existed) reads as
                    // "" — the pre-V0.9 behaviour for a missing
                    // column value.
                    Some(v) => Resolve::Found(v.clone()),
                    None => Resolve::Found(Some(String::new())),
                });
            }
            // The qualifier names no table in this scope: try
            // each outer level in turn (nearest first).
            let mut level = outer;
            while let Some(ctx) = level {
                if ctx.scope.tables.iter().any(|t| t.key == *q) {
                    let t = ctx
                        .scope
                        .tables
                        .iter()
                        .find(|t| t.key == *q)
                        .expect("qualifier is in this outer scope");
                    if !t.columns.iter().any(|c| c == &col.name) {
                        return Err(sql_err(
                            "42703",
                            format!("column '{}.{}' does not exist", q, col.name),
                        ));
                    }
                    return outer_value(ctx, q, &col.name);
                }
                level = ctx.parent;
            }
            Err(sql_err(
                "42703",
                format!("missing FROM-clause entry for table '{q}'"),
            ))
        }
        None => {
            let mut found: Option<&ScopeTable> = None;
            for t in &scope.tables {
                if t.columns.iter().any(|c| c == &col.name) {
                    if found.is_some() {
                        return Ok(Resolve::Ambiguous);
                    }
                    found = Some(t);
                }
            }
            match found {
                Some(t) => Ok(match row.get(&(t.key.clone(), col.name.clone())) {
                    Some(v) => Resolve::Found(v.clone()),
                    None => Resolve::Found(Some(String::new())),
                }),
                None => {
                    let mut level = outer;
                    while let Some(ctx) = level {
                        let mut outer_found: Option<&ScopeTable> = None;
                        let mut ambiguous = false;
                        for t in &ctx.scope.tables {
                            if t.columns.iter().any(|c| c == &col.name) {
                                if outer_found.is_some() {
                                    ambiguous = true;
                                    break;
                                }
                                outer_found = Some(t);
                            }
                        }
                        if ambiguous {
                            return Ok(Resolve::Ambiguous);
                        }
                        if let Some(t) = outer_found {
                            return outer_value(ctx, &t.key, &col.name);
                        }
                        level = ctx.parent;
                    }
                    Ok(Resolve::NotFound)
                }
            }
        }
    }
}

/// A parsed literal as stored text. An unbound `$n` is a syntax
/// error, not data (same rule as `pgwire::resolve_value`).
fn literal(value: &Value) -> Result<String, SqlError> {
    match value {
        Value::Text(text) => Ok(text.clone()),
        Value::Param(n) => Err(sql_err(
            "42601",
            format!("parameter ${n} has no bound value — Bind the statement before executing it"),
        )),
    }
}

/// Compare two cells with an operator. Any comparison involving
/// NULL is false (PostgreSQL: the result is NULL, and a WHERE /
/// HAVING / ON row with a NULL result is filtered out).
fn cmp_cells(a: &Cell, b: &Cell, op: CmpOp) -> bool {
    let (Some(a), Some(b)) = (a, b) else {
        return false;
    };
    let ord = compare_values(a, b);
    match op {
        CmpOp::Eq => ord == std::cmp::Ordering::Equal,
        CmpOp::Ne => ord != std::cmp::Ordering::Equal,
        CmpOp::Lt => ord == std::cmp::Ordering::Less,
        CmpOp::Gt => ord == std::cmp::Ordering::Greater,
        CmpOp::Le => ord != std::cmp::Ordering::Greater,
        CmpOp::Ge => ord != std::cmp::Ordering::Less,
    }
}

/// Compare two cells for ORDER BY. NULL sorts as larger than any
/// value (PostgreSQL: ASC puts NULLs last, DESC puts them first).
fn cmp_order(a: &Cell, b: &Cell) -> std::cmp::Ordering {
    match (a, b) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(a), Some(b)) => compare_values(a, b),
    }
}

/// Scan one table as this session sees it: the transaction's
/// BEGIN snapshot plus its own writes when inside a transaction,
/// the live data otherwise. The table must have existed at this
/// transaction's BEGIN (the V0.6 DDL-snapshot rule).
fn fetch_table(
    engine: &mut Engine,
    tables: &mut TableStore,
    session: &Session,
    name: &str,
) -> Result<Vec<TableRow>, SqlError> {
    check_table_visible_in_txn(session, name)?;
    match session.txn {
        Some(txn) => tables
            .select_txn_filtered(engine, txn, name, None)
            .map_err(table_err),
        None => tables
            .select_filtered(engine, name, None)
            .map_err(table_err),
    }
}

/// Execute a SELECT and return (output column names, rows).
/// Takes the statement's snapshot first (one scan per table,
/// under the caller's lock) and then executes against it without
/// the lock — so a long SELECT cannot block other connections.
/// Subqueries run against the same snapshot as the outer query.
///
/// Kept as the engine-level entry point (the server path uses
/// `execute_select_snapshot` so it can drop the lock between
/// the snapshot and the execution); hence the allow(dead_code).
#[allow(dead_code)]
pub(crate) fn execute_select(
    engine: &mut Engine,
    tables: &mut TableStore,
    session: &Session,
    stmt: &Stmt,
) -> Result<(Vec<String>, Vec<Vec<Cell>>), SqlError> {
    let snapshot = collect_snapshot(engine, tables, session, stmt)?;
    execute_select_snapshot(&snapshot, stmt)
}

/// Execute a SELECT against an already-taken snapshot, with one
/// shared statement deadline for the statement and all of its
/// subqueries.
pub(crate) fn execute_select_snapshot(
    snapshot: &Snapshot,
    stmt: &Stmt,
) -> Result<(Vec<String>, Vec<Vec<Cell>>), SqlError> {
    execute_select_snapshot_deadline(snapshot, stmt, statement_deadline(), None)
}

/// One subquery result, hoisted out of the WHERE loop (B2): an
/// UNCORRELATED subquery in WHERE is evaluated once per
/// statement — not once per outer row — which is always
/// correct for it, and turns a nested IN from exponential into
/// linear. (A correlated WHERE subquery is NOT hoisted — see
/// `WhereEval` / `hoist_where_subqueries` (M2) — and a
/// SELECT-list subquery is different again: a correlated one IS
/// evaluated once per outer row — see `execute_plain` /
/// `execute_aggregate`.)
enum Hoisted {
    In(Vec<Cell>),
    Scalar(Cell),
}

/// How one WHERE condition's subquery is evaluated (M2): an
/// uncorrelated subquery is hoisted (evaluated once, reused for
/// every row); a correlated one — it references this
/// statement's tables, or any ancestor statement's tables — is
/// evaluated once per row, against that row.
enum WhereEval {
    /// No subquery in this condition.
    None,
    /// Hoisted result, reused for every row.
    Hoisted(Hoisted),
    /// Per-row IN subquery: evaluate per row, then apply the
    /// condition's `negated` flag (read off the condition, as
    /// with a hoisted IN).
    PerRowIn { query: Stmt },
    /// Per-row scalar subquery.
    PerRowScalar { query: Stmt },
}

/// Stage 1b — hoist every WHERE subquery: an uncorrelated one
/// is evaluated once, here, and its result reused for every
/// outer row. Before this fix each row re-ran the subquery, so
/// a nested IN (depth 2, 200 rows) never finished. A
/// CORRELATED WHERE subquery is NOT hoisted (M2): it
/// references this statement's tables — or an ancestor
/// statement's tables, e.g. a WHERE subquery nested inside a
/// SELECT-list subquery referencing that subquery's own alias
/// — so it is evaluated once per row, against that row (see
/// `eval_where_row`). Hoisting one would fail its outer
/// references with a misleading 42703 ("missing FROM-clause
/// entry" for a table that IS in the outer FROM).
fn hoist_where_subqueries(
    snapshot: &Snapshot,
    stmt: &Stmt,
    scope: &Scope,
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<Vec<WhereEval>, SqlError> {
    let Stmt::Select { conditions, .. } = stmt else {
        return Err(sql_err(
            "XX000",
            "internal error: hoist_where_subqueries called with a non-SELECT statement",
        ));
    };
    let mut out: Vec<WhereEval> = Vec::with_capacity(conditions.len());
    for cond in conditions {
        out.push(match &cond.rhs {
            CondRhs::InSubquery { query, .. } => {
                if where_subquery_is_correlated(snapshot, query, scope, outer)? {
                    WhereEval::PerRowIn {
                        query: query.as_ref().clone(),
                    }
                } else {
                    WhereEval::Hoisted(Hoisted::In(run_subquery_values(
                        snapshot, query, deadline, None,
                    )?))
                }
            }
            CondRhs::ScalarSubquery(query) => {
                if where_subquery_is_correlated(snapshot, query, scope, outer)? {
                    WhereEval::PerRowScalar {
                        query: query.as_ref().clone(),
                    }
                } else {
                    WhereEval::Hoisted(Hoisted::Scalar(run_scalar_subquery(
                        snapshot, query, deadline, None,
                    )?))
                }
            }
            CondRhs::Value(_) | CondRhs::Column(_) => WhereEval::None,
        });
    }
    Ok(out)
}

/// Does a WHERE subquery reference this statement's tables, or
/// any ancestor statement's tables (M2)? Either way it is
/// correlated and must be evaluated once per row, against that
/// row — hoisting it with no outer context would fail its
/// outer references with a misleading 42703. A reference that
/// matches the subquery's own tables (shadowing) is NOT
/// correlation: the inner match always wins, so it stays
/// hoisted.
fn where_subquery_is_correlated(
    snapshot: &Snapshot,
    query: &Stmt,
    scope: &Scope,
    outer: Option<&OuterCtx<'_>>,
) -> Result<bool, SqlError> {
    if select_subquery_is_correlated(snapshot, query, scope)? {
        return Ok(true);
    }
    let mut level = outer;
    while let Some(ctx) = level {
        if select_subquery_is_correlated(snapshot, query, ctx.scope)? {
            return Ok(true);
        }
        level = ctx.parent;
    }
    Ok(false)
}

/// Evaluate every WHERE condition on one joined row
/// (AND-joined). Hoisted subquery results come from
/// `where_evals`; a correlated WHERE subquery is evaluated
/// here, once per row, against this row as its outer row (M2).
/// A failing condition (an ambiguous column) fails the whole
/// statement — it is not a filtered row.
#[allow(clippy::too_many_arguments)]
fn eval_where_row(
    row: &JoinedRow,
    scope: &Scope,
    conditions: &[Condition],
    where_evals: &[WhereEval],
    outer: Option<&OuterCtx<'_>>,
    snapshot: &Snapshot,
    deadline: Option<Instant>,
) -> Result<bool, SqlError> {
    for (cond, eval) in conditions.iter().zip(where_evals.iter()) {
        let keep = match eval {
            WhereEval::None => eval_condition(row, scope, cond, None, outer)?,
            WhereEval::Hoisted(cached) => eval_condition(row, scope, cond, Some(cached), outer)?,
            WhereEval::PerRowIn { query } => {
                let ctx = OuterCtx {
                    row,
                    scope,
                    parent: outer,
                    group_only: false,
                };
                let values = run_subquery_values(snapshot, query, deadline, Some(&ctx))?;
                eval_condition(row, scope, cond, Some(&Hoisted::In(values)), outer)?
            }
            WhereEval::PerRowScalar { query } => {
                let ctx = OuterCtx {
                    row,
                    scope,
                    parent: outer,
                    group_only: false,
                };
                let value = run_scalar_subquery(snapshot, query, deadline, Some(&ctx))?;
                eval_condition(row, scope, cond, Some(&Hoisted::Scalar(value)), outer)?
            }
        };
        if !keep {
            return Ok(false);
        }
    }
    Ok(true)
}

fn execute_select_snapshot_deadline(
    snapshot: &Snapshot,
    stmt: &Stmt,
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<(Vec<String>, Vec<Vec<Cell>>), SqlError> {
    let Stmt::Select {
        items,
        conditions,
        group_by,
        having,
        order_by,
        limit,
        offset,
        ..
    } = stmt
    else {
        return Err(sql_err(
            "XX000",
            "internal error: execute_select called with a non-SELECT statement",
        ));
    };
    let scope = Scope::of_snapshot(snapshot, stmt)?;

    // Is this an aggregate query? Any aggregate in the SELECT
    // list, GROUP BY, HAVING, or ORDER BY makes it one.
    let is_aggregate = items.as_ref().is_some_and(|items| {
        items
            .iter()
            .any(|i| matches!(i, SelectItem::Aggregate { .. }))
    }) || !group_by.is_empty()
        || !having.is_empty()
        || order_by
            .iter()
            .any(|k| matches!(k, OrderByItem::Aggregate(..)));

    // Streaming-aggregate fast path (B1): a simple aggregate
    // query — aggregate items only, no GROUP BY / HAVING /
    // ORDER BY, no SELECT-list subqueries — never materialises
    // the join: each joined row updates the accumulators on the
    // fly and is then dropped (see
    // `execute_aggregate_streaming`). A COUNT(*) over a
    // 2000x2000 cross product used to materialise 4M joined
    // rows and OOM-kill the server; now it counts them one by
    // one. Anything else takes the materialising path below,
    // capped at `max_join_rows` (54000).
    if is_aggregate && streaming_aggregate_eligible(stmt) {
        let where_evals = hoist_where_subqueries(snapshot, stmt, &scope, deadline, outer)?;
        let (out_columns, out_rows) =
            execute_aggregate_streaming(snapshot, stmt, &scope, &where_evals, deadline, outer)?;
        let offset = (*offset).unwrap_or(0) as usize;
        let limit = (*limit).map(|n| n as usize);
        let out_rows: Vec<Vec<Cell>> = out_rows
            .into_iter()
            .skip(offset)
            .take(limit.unwrap_or(usize::MAX))
            .collect();
        return Ok((out_columns, out_rows));
    }

    // Stage 1 — nested-loop join over the snapshot rows
    // (materialised, capped — see `fetch_joined`).
    let joined = fetch_joined(snapshot, stmt, &scope, deadline, outer)?;

    // Stage 1b — hoist every uncorrelated WHERE subquery (a
    // correlated one is evaluated per row instead — M2).
    let where_evals = hoist_where_subqueries(snapshot, stmt, &scope, deadline, outer)?;

    // Stage 2 — WHERE (AND-joined). A failing condition (an
    // ambiguous column) fails the whole statement — it is not
    // a filtered row.
    let mut filtered: Vec<JoinedRow> = Vec::with_capacity(joined.len());
    for (i, row) in joined.into_iter().enumerate() {
        if i.is_multiple_of(1024) {
            check_deadline(deadline)?;
        }
        if eval_where_row(
            &row,
            &scope,
            conditions,
            &where_evals,
            outer,
            snapshot,
            deadline,
        )? {
            filtered.push(row);
        }
    }
    let joined = filtered;

    let (out_columns, out_rows): (Vec<String>, Vec<Vec<Cell>>) = if is_aggregate {
        execute_aggregate(stmt, &scope, &joined, deadline, outer, snapshot)?
    } else {
        execute_plain(stmt, &scope, &joined, deadline, outer, snapshot)?
    };

    // LIMIT/OFFSET slice last, after sorting (ORDER BY was
    // applied inside the two executors above).
    let offset = (*offset).unwrap_or(0) as usize;
    let limit = (*limit).map(|n| n as usize);
    let out_rows: Vec<Vec<Cell>> = out_rows
        .into_iter()
        .skip(offset)
        .take(limit.unwrap_or(usize::MAX))
        .collect();
    Ok((out_columns, out_rows))
}

/// Is this statement eligible for the streaming-aggregate fast
/// path (B1)? A simple aggregate query: every SELECT-list item
/// is an aggregate, and there is no GROUP BY, no HAVING and no
/// ORDER BY. (GROUP BY / HAVING / an ORDER BY key / a
/// SELECT-list subquery next to an aggregate all take the
/// materialising path — still correct, still capped.)
fn streaming_aggregate_eligible(stmt: &Stmt) -> bool {
    let Stmt::Select {
        items,
        group_by,
        having,
        order_by,
        ..
    } = stmt
    else {
        return false;
    };
    if !group_by.is_empty() || !having.is_empty() || !order_by.is_empty() {
        return false;
    }
    match items {
        Some(items) => {
            !items.is_empty()
                && items
                    .iter()
                    .all(|i| matches!(i, SelectItem::Aggregate { .. }))
        }
        None => false,
    }
}

/// One aggregate's running state, updated per joined row — the
/// same arithmetic as `compute_aggregate`, but without ever
/// collecting the rows. `COUNT(*)` / `COUNT(col)` just count;
/// `SUM` / `AVG` keep the exact i128 sum while every value is
/// a plain integer (and the f64 sum alongside, for the
/// fallback); `MIN` / `MAX` keep the best value seen.
enum AggAcc {
    Count(usize),
    SumAvg {
        count: usize,
        /// Every value so far a plain integer?
        all_int: bool,
        /// Exact sum while `all_int` and no overflow; `None`
        /// once a non-integer value arrives or the sum
        /// overflows i128.
        sum_i128: Option<i128>,
        /// f64 sum of every value (the fallback path).
        sum_f64: f64,
        /// Did the exact sum overflow i128? (22003 at the end
        /// — unless a non-integer value also arrived, in which
        /// case the f64 path runs instead, like
        /// `compute_aggregate`.)
        overflow: bool,
        /// First value that is not a finite f64 (a non-numeric
        /// string, or a number too big for f64) — 22P02 at the
        /// end, but only when the f64 path runs (i.e. not all
        /// integers). Recorded in row order, like the f64 loop
        /// in `compute_aggregate`, which fails on the first
        /// such value.
        first_bad_f64: Option<String>,
    },
    MinMax {
        best: Option<String>,
        func: AggFunc,
    },
}

impl AggAcc {
    fn new(func: AggFunc) -> AggAcc {
        match func {
            AggFunc::Count => AggAcc::Count(0),
            AggFunc::Sum | AggFunc::Avg => AggAcc::SumAvg {
                count: 0,
                all_int: true,
                sum_i128: Some(0),
                sum_f64: 0.0,
                overflow: false,
                first_bad_f64: None,
            },
            AggFunc::Min | AggFunc::Max => AggAcc::MinMax { best: None, func },
        }
    }

    /// Fold one joined row into this aggregate. Mirrors the
    /// per-row loops of `compute_aggregate`: NULLs are skipped,
    /// a non-numeric SUM/AVG value is 22P02 (raised at once —
    /// the materialised path raises it for the first such value
    /// in row order too, and a resolve error for this fixed
    /// column is scope-level, so no later row could pre-empt
    /// it), an integer overflow is remembered for the end.
    fn update(
        &mut self,
        agg: &AggregateExpr,
        row: &JoinedRow,
        scope: &Scope,
        outer: Option<&OuterCtx<'_>>,
    ) -> Result<(), SqlError> {
        match self {
            AggAcc::Count(n) => {
                match &agg.arg {
                    None => *n += 1,
                    Some(col) => {
                        if let Resolve::Found(Some(_)) = resolve_with_outer(row, scope, col, outer)?
                        {
                            *n += 1;
                        }
                    }
                }
                Ok(())
            }
            AggAcc::SumAvg {
                count,
                all_int,
                sum_i128,
                sum_f64,
                overflow,
                first_bad_f64,
            } => {
                let Some(col) = &agg.arg else {
                    return Err(sql_err(
                        "42601",
                        format!(
                            "{}(*) is not valid — {} needs a column",
                            agg.func.name(),
                            agg.func.name()
                        ),
                    ));
                };
                if let Resolve::Found(Some(v)) = resolve_with_outer(row, scope, col, outer)? {
                    *count += 1;
                    if is_plain_int(&v) {
                        if let Some(sum) = sum_i128.as_mut() {
                            match v.parse::<i128>() {
                                Ok(n) => match sum.checked_add(n) {
                                    Some(s) => *sum = s,
                                    None => {
                                        *sum_i128 = None;
                                        *overflow = true;
                                    }
                                },
                                Err(_) => {
                                    *sum_i128 = None;
                                    *overflow = true;
                                }
                            }
                        }
                    } else {
                        *all_int = false;
                        *sum_i128 = None;
                    }
                    match v.parse::<f64>() {
                        Ok(n) if n.is_finite() => *sum_f64 += n,
                        _ => {
                            if first_bad_f64.is_none() {
                                *first_bad_f64 = Some(v.clone());
                            }
                        }
                    }
                    // The f64 path runs as soon as any
                    // non-integer value has been seen, so the
                    // first non-finite value in row order is a
                    // 22P02 now — exactly like the f64 loop in
                    // `compute_aggregate`, which fails on the
                    // first such value. (While every value is
                    // still a plain integer, a huge value that
                    // parses to an infinite f64 is only
                    // recorded: the exact path may still return
                    // 22003 instead.)
                    if !*all_int {
                        if let Some(bad) = first_bad_f64.as_ref() {
                            return Err(sql_err(
                                "22P02",
                                format!(
                                    "invalid input syntax for type numeric: \"{bad}\" — \
                                     {} needs numbers",
                                    agg.func.name()
                                ),
                            ));
                        }
                    }
                }
                Ok(())
            }
            AggAcc::MinMax { best, func } => {
                let Some(col) = &agg.arg else {
                    return Err(sql_err(
                        "42601",
                        format!(
                            "{}(*) is not valid — {} needs a column",
                            agg.func.name(),
                            agg.func.name()
                        ),
                    ));
                };
                if let Resolve::Found(Some(v)) = resolve_with_outer(row, scope, col, outer)? {
                    *best = Some(match best.take() {
                        None => v,
                        Some(b) => {
                            let ord = compare_values(&v, &b);
                            match func {
                                AggFunc::Min => {
                                    if ord == std::cmp::Ordering::Less {
                                        v
                                    } else {
                                        b
                                    }
                                }
                                AggFunc::Max => {
                                    if ord == std::cmp::Ordering::Greater {
                                        v
                                    } else {
                                        b
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                    });
                }
                Ok(())
            }
        }
    }

    /// The aggregate's value after all rows: `COUNT` over no
    /// rows is 0, the rest are NULL. Error precedence mirrors
    /// `compute_aggregate` (all-integer overflow is 22003; a
    /// non-numeric value on the f64 path is 22P02).
    fn finish(self, agg: &AggregateExpr) -> Result<Cell, SqlError> {
        match self {
            AggAcc::Count(n) => Ok(Some(n.to_string())),
            AggAcc::SumAvg {
                count,
                all_int,
                sum_i128,
                sum_f64,
                overflow,
                first_bad_f64,
            } => {
                if count == 0 {
                    return Ok(None);
                }
                if all_int {
                    if overflow {
                        return Err(sql_err(
                            "22003",
                            format!(
                                "value out of range: {} over integers overflowed i128 — \
                                 the values are too large to add exactly",
                                agg.func.name()
                            ),
                        ));
                    }
                    let sum = sum_i128.expect("all-integer sum without overflow");
                    return Ok(Some(match agg.func {
                        AggFunc::Sum => sum.to_string(),
                        AggFunc::Avg => format_avg_exact(sum, count),
                        _ => unreachable!(),
                    }));
                }
                if let Some(v) = first_bad_f64 {
                    return Err(sql_err(
                        "22P02",
                        format!(
                            "invalid input syntax for type numeric: \"{v}\" — \
                             {} needs numbers",
                            agg.func.name()
                        ),
                    ));
                }
                Ok(Some(match agg.func {
                    AggFunc::Sum => format_number(sum_f64),
                    AggFunc::Avg => format_number(sum_f64 / count as f64),
                    _ => unreachable!(),
                }))
            }
            AggAcc::MinMax { best, .. } => Ok(best),
        }
    }
}

/// A simple aggregate query, executed without materialising the
/// join (B1): the join streams row by row (`stream_joined`),
/// each row is WHERE-filtered, each aggregate folds the row in,
/// and the row is dropped. Memory stays flat no matter how big
/// the join product is — the statement timeout (checked every
/// 1024 rows, and every 1024 pairs inside the join) is what
/// bounds the runtime instead. Returns the single output row;
/// LIMIT/OFFSET are applied by the caller, as usual.
fn execute_aggregate_streaming(
    snapshot: &Snapshot,
    stmt: &Stmt,
    scope: &Scope,
    where_evals: &[WhereEval],
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<(Vec<String>, Vec<Vec<Cell>>), SqlError> {
    let Stmt::Select {
        items,
        conditions,
        limit,
        ..
    } = stmt
    else {
        return Err(sql_err(
            "XX000",
            "internal error: execute_aggregate_streaming called with a non-SELECT statement",
        ));
    };
    let items = items.as_ref().ok_or_else(|| {
        sql_err(
            "XX000",
            "internal error: streaming aggregate called with SELECT *",
        )
    })?;
    // Output columns, and the up-front argument validation
    // `execute_aggregate` does: an unknown aggregate column is
    // 42703 even over an empty table, and SUM(*)/AVG(*)/MIN(*)/
    // MAX(*) is 42601 — before any row streams.
    let out_columns: Vec<String> = items.iter().map(SelectItem::output_name).collect();
    let mut accs: Vec<AggAcc> = Vec::with_capacity(items.len());
    for item in items {
        let SelectItem::Aggregate { agg, .. } = item else {
            return Err(sql_err(
                "XX000",
                "internal error: non-aggregate item in a streaming aggregate query",
            ));
        };
        if let Some(arg) = &agg.arg {
            validate_column_with_outer(scope, arg, outer)?;
        } else if !matches!(agg.func, AggFunc::Count) {
            return Err(sql_err(
                "42601",
                format!(
                    "{}(*) is not valid — {} needs a column",
                    agg.func.name(),
                    agg.func.name()
                ),
            ));
        }
        accs.push(AggAcc::new(agg.func));
    }
    // LIMIT 0: no rows out, and nothing needs to stream (M4) —
    // the arguments are already validated above, so this still
    // errors on an unknown column like the materialising path.
    if *limit == Some(0) {
        return Ok((out_columns, Vec::new()));
    }
    let mut seen: usize = 0;
    stream_joined(snapshot, stmt, scope, deadline, outer, &mut |row| {
        seen += 1;
        if seen.is_multiple_of(1024) {
            check_deadline(deadline)?;
        }
        if !eval_where_row(
            row,
            scope,
            conditions,
            where_evals,
            outer,
            snapshot,
            deadline,
        )? {
            return Ok(());
        }
        for (item, acc) in items.iter().zip(accs.iter_mut()) {
            let SelectItem::Aggregate { agg, .. } = item else {
                unreachable!("eligibility checked every item is an aggregate");
            };
            acc.update(agg, row, scope, outer)?;
        }
        Ok(())
    })?;
    let mut out: Vec<Cell> = Vec::with_capacity(items.len());
    for (item, acc) in items.iter().zip(accs) {
        let SelectItem::Aggregate { agg, .. } = item else {
            unreachable!("eligibility checked every item is an aggregate");
        };
        out.push(acc.finish(agg)?);
    }
    Ok((out_columns, vec![out]))
}

/// Maximum joined rows one SELECT materialises (B1): a JOIN
/// whose product exceeds this fails with 54000 instead of
/// growing memory until the server dies — a 1000x1000 cross
/// product used to materialise ~2 GB of joined rows (~2 KB per
/// joined row: every merged row is a `BTreeMap` clone) and a
/// 2000x2000 one OOM-killed the server. The cap is on
/// materialised rows, not on pairs scanned: a streaming
/// aggregate (see `execute_aggregate_streaming`) counts a
/// cross product of any size without storing a row, and a plain
/// SELECT over a big join fails fast with 54000 instead of
/// dying. Default 100_000 (about 200 MB of joined rows at the
/// measured ~2 KB per row); `ZENO_MAX_JOIN_ROWS` overrides it
/// (diagnostic/test hook); `0` disables the cap.
fn max_join_rows() -> usize {
    std::env::var("ZENO_MAX_JOIN_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
}

/// Stage 1: nested-loop join each further table onto the base
/// table, in written order, over the snapshot rows. INNER keeps
/// only matching pairs; LEFT keeps every left row, padding the
/// right side with NULLs when nothing matches. This is the
/// streaming core: every matched (or padded) row is handed to
/// `sink` instead of being collected, so a caller that only
/// needs aggregates never materialises the join at all.
/// `fetch_joined` (collecting) and `stream_joined` (streaming
/// the last stage) both build on it. (There is no early-stop:
/// a plain SELECT with LIMIT still materialises the join first
/// — see the README — so the sink always runs to completion.)
#[allow(clippy::too_many_arguments)]
fn join_stage(
    left_rows: &[JoinedRow],
    right_rows: &[JoinedRow],
    join: &crate::parser::JoinClause,
    right_scope: &ScopeTable,
    scope: &Scope,
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
    sink: &mut dyn FnMut(&JoinedRow) -> Result<(), SqlError>,
) -> Result<(), SqlError> {
    let mut pairs: usize = 0;
    for left in left_rows {
        let mut matched = false;
        for right in right_rows {
            pairs += 1;
            if pairs.is_multiple_of(1024) {
                check_deadline(deadline)?;
            }
            // The ON pair is evaluated on the merged row,
            // so either side may reference either table
            // (PostgreSQL allows that too). Inside a
            // subquery, either side may also reference the
            // outer query's tables (V0.10).
            let mut merged = left.clone();
            merged.extend(right.clone());
            let l = resolve_with_outer(&merged, scope, &join.left, outer)?;
            let r = resolve_with_outer(&merged, scope, &join.right, outer)?;
            let equal = match (l, r) {
                (Resolve::Found(a), Resolve::Found(b)) => cmp_cells(&a, &b, CmpOp::Eq),
                // An unknown or ambiguous ON column is an
                // error, not a silent non-match.
                (Resolve::NotFound, _) | (_, Resolve::NotFound) => {
                    return Err(sql_err(
                        "42703",
                        "ON column does not exist in either joined table",
                    ));
                }
                (Resolve::Ambiguous, _) | (_, Resolve::Ambiguous) => {
                    return Err(sql_err(
                        "42702",
                        "ON column reference is ambiguous — qualify it with a table name",
                    ));
                }
            };
            if equal {
                matched = true;
                sink(&merged)?;
            }
        }
        if !matched && join.kind == JoinKind::Left {
            let mut padded = left.clone();
            for col in &right_scope.columns {
                padded.insert((right_scope.key.clone(), col.clone()), None);
            }
            sink(&padded)?;
        }
    }
    Ok(())
}

/// The snapshot rows of one table as joined rows, under `key`.
fn snapshot_joined_rows(
    snapshot: &Snapshot,
    name: &str,
    key: &str,
) -> Result<Vec<JoinedRow>, SqlError> {
    Ok(snapshot_rows(snapshot, name)?
        .iter()
        .map(|(_, row)| to_joined_row(key, row.clone()))
        .collect())
}

/// Stage 1 (materialising): nested-loop join over the snapshot
/// rows, collecting every joined row into a `Vec` — the path
/// for plain SELECTs (which need all rows to sort / project)
/// and grouped aggregates. The collected rows are capped
/// (`max_join_rows`, 54000): a join whose product exceeds the
/// cap fails fast instead of growing memory until the server
/// dies (B1). Streaming callers use `stream_joined` instead.
fn fetch_joined(
    snapshot: &Snapshot,
    stmt: &Stmt,
    scope: &Scope,
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<Vec<JoinedRow>, SqlError> {
    let Stmt::Select {
        table,
        table_alias,
        joins,
        ..
    } = stmt
    else {
        return Err(sql_err(
            "XX000",
            "internal error: fetch_joined called with a non-SELECT statement",
        ));
    };
    let base_key = table_alias.clone().unwrap_or_else(|| table.clone());
    let mut joined: Vec<JoinedRow> = snapshot_joined_rows(snapshot, table, &base_key)?;
    let cap = max_join_rows();
    for join in joins {
        let right_key = join.alias.clone().unwrap_or_else(|| join.table.clone());
        let right_rows: Vec<JoinedRow> = snapshot_joined_rows(snapshot, &join.table, &right_key)?;
        let right_scope = scope
            .tables
            .iter()
            .find(|t| t.key == right_key)
            .expect("join table is in scope");
        let mut next: Vec<JoinedRow> = Vec::new();
        join_stage(
            &joined,
            &right_rows,
            join,
            right_scope,
            scope,
            deadline,
            outer,
            &mut |row| {
                next.push(row.clone());
                if cap != 0 && next.len() > cap {
                    return Err(sql_err(
                        "54000",
                        format!(
                            "joined result exceeds the materialisation limit of {cap} rows \
                             (ZENO_MAX_JOIN_ROWS) — narrow the query with a WHERE clause, \
                             aggregate it instead of selecting the raw join, or raise the limit"
                        ),
                    ));
                }
                Ok(())
            },
        )?;
        joined = next;
    }
    Ok(joined)
}

/// Stage 1 (streaming): the same nested-loop join, but the
/// LAST stage hands each joined row to `sink` instead of
/// collecting it — so a caller that only aggregates never
/// materialises the join product at all. Earlier stages (a
/// 3+-table join) still materialise their intermediate rows,
/// capped like `fetch_joined` (54000); with no joins at all
/// the base rows stream straight through.
fn stream_joined(
    snapshot: &Snapshot,
    stmt: &Stmt,
    scope: &Scope,
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
    sink: &mut dyn FnMut(&JoinedRow) -> Result<(), SqlError>,
) -> Result<(), SqlError> {
    let Stmt::Select {
        table,
        table_alias,
        joins,
        ..
    } = stmt
    else {
        return Err(sql_err(
            "XX000",
            "internal error: stream_joined called with a non-SELECT statement",
        ));
    };
    let base_key = table_alias.clone().unwrap_or_else(|| table.clone());
    let mut current: Vec<JoinedRow> = snapshot_joined_rows(snapshot, table, &base_key)?;
    let cap = max_join_rows();
    let n_joins = joins.len();
    for (idx, join) in joins.iter().enumerate() {
        let right_key = join.alias.clone().unwrap_or_else(|| join.table.clone());
        let right_rows: Vec<JoinedRow> = snapshot_joined_rows(snapshot, &join.table, &right_key)?;
        let right_scope = scope
            .tables
            .iter()
            .find(|t| t.key == right_key)
            .expect("join table is in scope");
        if idx + 1 == n_joins {
            // Last stage: stream each joined row to the sink.
            return join_stage(
                &current,
                &right_rows,
                join,
                right_scope,
                scope,
                deadline,
                outer,
                sink,
            );
        }
        let mut next: Vec<JoinedRow> = Vec::new();
        join_stage(
            &current,
            &right_rows,
            join,
            right_scope,
            scope,
            deadline,
            outer,
            &mut |row| {
                next.push(row.clone());
                if cap != 0 && next.len() > cap {
                    return Err(sql_err(
                        "54000",
                        format!(
                            "joined result exceeds the materialisation limit of {cap} rows \
                             (ZENO_MAX_JOIN_ROWS) — narrow the query with a WHERE clause, \
                             aggregate it instead of selecting the raw join, or raise the limit"
                        ),
                    ));
                }
                Ok(())
            },
        )?;
        current = next;
    }
    // No joins: stream the base rows straight through.
    for row in &current {
        sink(row)?;
    }
    Ok(())
}

/// The snapshot rows of one table. The snapshot holds every
/// table the statement can read, so a miss here is a bug, not
/// a user error — it reads as an empty table rather than
/// panicking.
fn snapshot_rows<'a>(snapshot: &'a Snapshot, name: &str) -> Result<&'a Vec<TableRow>, SqlError> {
    snapshot.rows.get(name).ok_or_else(|| {
        sql_err(
            "XX000",
            format!("internal error: table '{name}' is missing from the statement snapshot"),
        )
    })
}

/// One stored row as a joined row: every value `Some`.
fn to_joined_row(key: &str, row: BTreeMap<String, String>) -> JoinedRow {
    row.into_iter()
        .map(|(col, val)| ((key.to_string(), col), Some(val)))
        .collect()
}

/// One WHERE condition on one joined row. Subqueries are NOT
/// run here any more: their results were hoisted before the
/// loop (`cached`), so this is a pure per-row comparison.
/// A column on either side may be an outer-query column
/// (V0.10, inside a subquery): it resolves against `outer`.
fn eval_condition(
    row: &JoinedRow,
    scope: &Scope,
    cond: &Condition,
    cached: Option<&Hoisted>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<bool, SqlError> {
    let value = match resolve_with_outer(row, scope, &cond.column, outer)? {
        Resolve::Found(v) => v,
        // One table, unknown column: matches no row (the V0.3
        // behaviour — a filter on a column the table does not
        // have filters everything out instead of erroring).
        // Several tables: the column must exist somewhere.
        Resolve::NotFound => {
            if scope.tables.len() == 1 {
                return Ok(false);
            }
            return Err(sql_err(
                "42703",
                format!("column '{}' does not exist", cond.column.name),
            ));
        }
        Resolve::Ambiguous => {
            return Err(sql_err(
                "42702",
                format!(
                    "column reference '{}' is ambiguous — qualify it with a table name",
                    cond.column.name
                ),
            ));
        }
    };
    match &cond.rhs {
        CondRhs::Value(v) => Ok(cmp_cells(&value, &Some(literal(v)?), cond.op)),
        CondRhs::Column(col) => {
            // A qualified column on the right-hand side
            // (V0.10): `orders.user_id = users.id`. An unknown
            // column is 42703 — a reference is not a literal,
            // so the single-table "matches nothing" rule for
            // the left-hand side does not apply to it.
            let other = match resolve_with_outer(row, scope, col, outer)? {
                Resolve::Found(v) => v,
                Resolve::NotFound => {
                    return Err(sql_err(
                        "42703",
                        format!("column '{}' does not exist", col.name),
                    ));
                }
                Resolve::Ambiguous => {
                    return Err(sql_err(
                        "42702",
                        format!(
                            "column reference '{}' is ambiguous — qualify it with a table name",
                            col.name
                        ),
                    ));
                }
            };
            Ok(cmp_cells(&value, &other, cond.op))
        }
        CondRhs::InSubquery { negated, .. } => {
            let Some(Hoisted::In(values)) = cached else {
                return Err(sql_err(
                    "XX000",
                    "internal error: IN subquery result was not hoisted before the WHERE loop",
                ));
            };
            Ok(eval_in(&value, values, *negated))
        }
        CondRhs::ScalarSubquery(_) => {
            let Some(Hoisted::Scalar(scalar)) = cached else {
                return Err(sql_err(
                    "XX000",
                    "internal error: scalar subquery result was not hoisted before the WHERE loop",
                ));
            };
            Ok(cmp_cells(&value, scalar, cond.op))
        }
    }
}

/// `x IN (values)` / `x NOT IN (values)`, PostgreSQL NULL
/// rules: a NULL `x` never matches; a NULL anywhere in the
/// list makes NOT IN false (the result would be NULL).
fn eval_in(value: &Cell, values: &[Cell], negated: bool) -> bool {
    if value.is_none() {
        return false;
    }
    let mut has_null = false;
    let mut found = false;
    for v in values {
        match v {
            None => has_null = true,
            Some(_) => {
                if cmp_cells(value, v, CmpOp::Eq) {
                    found = true;
                }
            }
        }
    }
    if negated {
        !found && !has_null
    } else {
        found
    }
}

/// Run a subquery and return its first column's values. The
/// subquery must return exactly one column (42601 otherwise).
/// It runs against the outer statement's snapshot, under the
/// outer statement's deadline, and — for a SELECT-list
/// subquery — with the outer row as its outer context (`outer`).
fn run_subquery_values(
    snapshot: &Snapshot,
    query: &Stmt,
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<Vec<Cell>, SqlError> {
    let (cols, rows) = execute_select_snapshot_deadline(snapshot, query, deadline, outer)?;
    if cols.len() != 1 {
        return Err(sql_err(
            "42601",
            format!(
                "subquery must return only one column (it returns {})",
                cols.len()
            ),
        ));
    }
    Ok(rows.into_iter().map(|mut r| r.remove(0)).collect())
}

/// Run a scalar subquery and return its single value: NULL when
/// it returns no rows, 21000 when it returns more than one.
fn run_scalar_subquery(
    snapshot: &Snapshot,
    query: &Stmt,
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<Cell, SqlError> {
    let values = run_subquery_values(snapshot, query, deadline, outer)?;
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.into_iter().next().expect("one value")),
        _ => Err(sql_err(
            "21000",
            "more than one row returned by a subquery used as an expression",
        )),
    }
}

/// Does one column reference point at the OUTER query's tables
/// (V0.10)? A reference is outer when it matches nothing in
/// any scope of the subquery's own statement chain (`inner_scopes`,
/// innermost first — an inner match always wins) but does match
/// the immediate outer scope. A reference that matches neither
/// is not outer: execution will reject it as 42703.
fn ref_is_outer(col: &ColumnRef, inner_scopes: &[Scope], outer_scope: &Scope) -> bool {
    match &col.qualifier {
        Some(q) => {
            if inner_scopes
                .iter()
                .any(|s| s.tables.iter().any(|t| t.key == *q))
            {
                false
            } else {
                outer_scope.tables.iter().any(|t| t.key == *q)
            }
        }
        None => {
            if inner_scopes.iter().any(|s| {
                s.tables
                    .iter()
                    .any(|t| t.columns.iter().any(|c| c == &col.name))
            }) {
                false
            } else {
                outer_scope
                    .tables
                    .iter()
                    .any(|t| t.columns.iter().any(|c| c == &col.name))
            }
        }
    }
}

/// Does a SELECT-list subquery reference the immediate outer
/// query's tables (V0.10)? Walks the whole subquery subtree:
/// every column reference in the subquery and in any subquery
/// nested inside it, with the scope of each level on the stack
/// as it descends, so a reference that resolves to an
/// intermediate level is not mistaken for an outer reference.
/// A scope that cannot be built (a missing table) fails here
/// with the same 42P01 / 42712 execution would have produced.
fn select_subquery_is_correlated(
    snapshot: &Snapshot,
    query: &Stmt,
    outer_scope: &Scope,
) -> Result<bool, SqlError> {
    let mut inner_scopes: Vec<Scope> = Vec::new();
    stmt_uses_outer_scope(query, snapshot, &mut inner_scopes, outer_scope)
}

fn stmt_uses_outer_scope(
    stmt: &Stmt,
    snapshot: &Snapshot,
    inner_scopes: &mut Vec<Scope>,
    outer_scope: &Scope,
) -> Result<bool, SqlError> {
    let Stmt::Select {
        items,
        joins,
        conditions,
        group_by,
        having,
        order_by,
        ..
    } = stmt
    else {
        return Ok(false);
    };
    let scope = Scope::of_snapshot(snapshot, stmt)?;
    inner_scopes.push(scope);
    let mut uses = false;
    if let Some(items) = items {
        for item in items {
            match item {
                SelectItem::Column { col, .. } => {
                    uses |= ref_is_outer(col, inner_scopes, outer_scope);
                }
                SelectItem::Aggregate { agg, .. } => {
                    if let Some(arg) = &agg.arg {
                        uses |= ref_is_outer(arg, inner_scopes, outer_scope);
                    }
                }
                SelectItem::QualifiedStar { .. } => {}
                SelectItem::ScalarSubquery { query, .. } => {
                    uses |= stmt_uses_outer_scope(query, snapshot, inner_scopes, outer_scope)?;
                }
            }
        }
    }
    for join in joins {
        uses |= ref_is_outer(&join.left, inner_scopes, outer_scope);
        uses |= ref_is_outer(&join.right, inner_scopes, outer_scope);
    }
    for cond in conditions {
        uses |= ref_is_outer(&cond.column, inner_scopes, outer_scope);
        match &cond.rhs {
            CondRhs::Column(col) => uses |= ref_is_outer(col, inner_scopes, outer_scope),
            CondRhs::InSubquery { query, .. } | CondRhs::ScalarSubquery(query) => {
                uses |= stmt_uses_outer_scope(query, snapshot, inner_scopes, outer_scope)?;
            }
            CondRhs::Value(_) => {}
        }
    }
    for col in group_by {
        uses |= ref_is_outer(col, inner_scopes, outer_scope);
    }
    for cond in having {
        if let Some(col) = &cond.column {
            uses |= ref_is_outer(col, inner_scopes, outer_scope);
        }
        if let Some(agg) = &cond.agg {
            if let Some(arg) = &agg.arg {
                uses |= ref_is_outer(arg, inner_scopes, outer_scope);
            }
        }
    }
    for key in order_by {
        match key {
            OrderByItem::Column(col, _) => {
                uses |= ref_is_outer(col, inner_scopes, outer_scope);
            }
            OrderByItem::Aggregate(agg, _) => {
                if let Some(arg) = &agg.arg {
                    uses |= ref_is_outer(arg, inner_scopes, outer_scope);
                }
            }
        }
    }
    inner_scopes.pop();
    Ok(uses)
}

/// Which SELECT-list items are UNCORRELATED scalar subqueries
/// (V0.10): one `bool` per item, `true` only for a scalar
/// subquery that does not reference this statement's row. The
/// check itself runs up front (a missing table in the subquery
/// is 42P01 at plan time, like PostgreSQL), but the VALUE is
/// evaluated lazily, on the first row that needs it — so a
/// subquery that would fail (21000, 42601, ...) does not fail
/// a statement whose outer table is empty and returns no rows
/// at all. Once evaluated, the value is cached and reused for
/// every further row. The lazy value runs with the statement's
/// own outer context (`outer` — see `execute_plain`): a
/// subquery that references an ancestor level (not this
/// statement's row) still sees that ancestor, whose row is
/// fixed for the whole execution of this statement.
fn uncorrelated_subquery_flags(
    snapshot: &Snapshot,
    items: &[SelectItem],
    scope: &Scope,
) -> Result<Vec<bool>, SqlError> {
    let mut flags = Vec::with_capacity(items.len());
    for item in items {
        match item {
            SelectItem::ScalarSubquery { query, .. } => {
                flags.push(!select_subquery_is_correlated(snapshot, query, scope)?);
            }
            _ => flags.push(false),
        }
    }
    Ok(flags)
}

/// A plain (non-aggregate) SELECT: project the rows, sort by
/// the ORDER BY keys, and return (columns, rows) in sorted
/// order (LIMIT/OFFSET are applied by the caller).
fn execute_plain(
    stmt: &Stmt,
    scope: &Scope,
    joined: &[JoinedRow],
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
    snapshot: &Snapshot,
) -> Result<(Vec<String>, Vec<Vec<Cell>>), SqlError> {
    let Stmt::Select {
        items,
        order_by,
        limit,
        ..
    } = stmt
    else {
        return Err(sql_err(
            "XX000",
            "internal error: execute_plain called with a non-SELECT statement",
        ));
    };
    // Output columns: `*` = every column of every table in
    // scope; an explicit list = the item names (alias wins); a
    // qualified star (`u.*`) expands to that table's columns.
    let out_columns: Vec<String> = match items {
        None => scope.star_columns(),
        Some(items) => expand_output_columns(scope, items, outer)?,
    };
    // ORDER BY keys are validated up front (existence only — an
    // output alias is valid even when it names no table column),
    // so an unknown key errors even over an empty result set
    // instead of silently sorting nothing.
    validate_order_by(scope, &out_columns, order_by, outer)?;
    // Which SELECT-list subqueries are uncorrelated (V0.10):
    // their values are evaluated lazily, once, and cached —
    // see `uncorrelated_subquery_flags`. An uncorrelated
    // subquery runs with this statement's own outer context
    // (`outer`, not its parent): "uncorrelated" only means it
    // does not reference THIS statement's scope, so it may
    // still reference an ancestor level — a subquery nested
    // inside it can read the grand-outer row — and `outer`'s
    // parent chain reaches that ancestor. Passing `outer`
    // cannot break shadowing: a reference that matched this
    // statement's scope would have made the subquery
    // correlated, so no reference resolves to this statement's
    // row. (Skipping one level — running with the parent
    // only — dropped exactly those grand-outer references and
    // failed them with 42703.)
    let uncorrelated: Vec<bool> = match items {
        Some(items) => uncorrelated_subquery_flags(snapshot, items, scope)?,
        None => Vec::new(),
    };
    // LIMIT 0: no rows out, and no projection runs at all (M4)
    // — so a failing SELECT-list subquery does not fail a query
    // that returns nothing. The output columns and ORDER BY are
    // already validated above, so this still errors on an
    // unknown column, like a LIMIT 0 over a bad query should.
    if *limit == Some(0) {
        return Ok((out_columns, Vec::new()));
    }
    let mut cached: Vec<Option<Cell>> = vec![None; uncorrelated.len()];
    // Project each row, and resolve its ORDER BY keys at the
    // same time (a key may be an output alias, or a column that
    // was not selected at all).
    let mut projected: Vec<(Vec<Cell>, Vec<Cell>)> = Vec::with_capacity(joined.len());
    for (i, row) in joined.iter().enumerate() {
        if i.is_multiple_of(1024) {
            check_deadline(deadline)?;
        }
        let out: Vec<Cell> = match items {
            None => scope
                .tables
                .iter()
                .flat_map(|t| {
                    t.columns.iter().map(|c| {
                        row.get(&(t.key.clone(), c.clone()))
                            .cloned()
                            .unwrap_or_else(|| Some(String::new()))
                    })
                })
                .collect(),
            Some(items) => {
                let mut out = Vec::with_capacity(items.len());
                for (idx, item) in items.iter().enumerate() {
                    match item {
                        SelectItem::Column { col, .. } => {
                            out.push(match resolve_with_outer(row, scope, col, outer)? {
                                Resolve::Found(v) => v,
                                Resolve::NotFound => {
                                    return Err(sql_err(
                                        "42703",
                                        format!("column '{}' does not exist", col.name),
                                    ));
                                }
                                Resolve::Ambiguous => {
                                    return Err(sql_err(
                                        "42702",
                                        format!(
                                            "column reference '{}' is ambiguous — qualify it with a table name",
                                            col.name
                                        ),
                                    ));
                                }
                            });
                        }
                        SelectItem::QualifiedStar { qualifier } => {
                            let table = scope
                                .tables
                                .iter()
                                .find(|t| t.key == *qualifier)
                                .expect("qualified star table is in scope");
                            for c in &table.columns {
                                out.push(
                                    row.get(&(qualifier.clone(), c.clone()))
                                        .cloned()
                                        .unwrap_or_else(|| Some(String::new())),
                                );
                            }
                        }
                        SelectItem::Aggregate { .. } => {
                            return Err(sql_err(
                                "XX000",
                                "internal error: aggregate item in a plain SELECT",
                            ));
                        }
                        SelectItem::ScalarSubquery { query, .. } => {
                            // Uncorrelated: evaluate once (on
                            // the first row that needs it) and
                            // reuse the value for every row.
                            // Correlated: evaluate once per row,
                            // against this row as the outer row.
                            if uncorrelated[idx] {
                                if let Some(v) = cached[idx].clone() {
                                    out.push(v);
                                } else {
                                    let v = run_scalar_subquery(snapshot, query, deadline, outer)?;
                                    cached[idx] = Some(v.clone());
                                    out.push(v);
                                }
                            } else {
                                let ctx = OuterCtx {
                                    row,
                                    scope,
                                    parent: outer,
                                    group_only: false,
                                };
                                out.push(run_scalar_subquery(
                                    snapshot,
                                    query,
                                    deadline,
                                    Some(&ctx),
                                )?);
                            }
                        }
                    }
                }
                out
            }
        };
        let keys = order_keys_plain(row, scope, items, &out_columns, &out, order_by, outer)?;
        projected.push((out, keys));
    }
    sort_by_keys(&mut projected, order_by);
    Ok((
        out_columns,
        projected.into_iter().map(|(out, _)| out).collect(),
    ))
}

/// Expand an explicit SELECT list to output column names:
/// plain columns (alias wins) and aggregates keep their
/// `output_name`; a qualified star expands to its table's
/// columns in registry order (an unknown qualifier is 42703);
/// a scalar subquery (V0.10) keeps its `output_name` (its alias,
/// or `?column?` — its inner columns are validated when it runs,
/// not here).
fn expand_output_columns(
    scope: &Scope,
    items: &[SelectItem],
    outer: Option<&OuterCtx<'_>>,
) -> Result<Vec<String>, SqlError> {
    let mut out = Vec::new();
    for item in items {
        match item {
            SelectItem::Column { col, .. } => {
                validate_column_with_outer(scope, col, outer)?;
                out.push(item.output_name());
            }
            SelectItem::Aggregate { agg, .. } => {
                if let Some(arg) = &agg.arg {
                    validate_column_with_outer(scope, arg, outer)?;
                }
                out.push(item.output_name());
            }
            SelectItem::QualifiedStar { qualifier } => {
                let Some(table) = scope.tables.iter().find(|t| t.key == *qualifier) else {
                    return Err(sql_err(
                        "42703",
                        format!("missing FROM-clause entry for table '{qualifier}'"),
                    ));
                };
                out.extend(table.columns.iter().cloned());
            }
            SelectItem::ScalarSubquery { .. } => {
                out.push(item.output_name());
            }
        }
    }
    Ok(out)
}

/// ORDER BY existence check (shared by plain and aggregate
/// queries): an unqualified name matching an output column is
/// an alias and needs no table column; anything else must
/// exist in scope (42703). Whether a non-grouped column may
/// sort an aggregate query is the 42803 check in
/// `order_keys_aggregate`, which still runs per group.
fn validate_order_by(
    scope: &Scope,
    out_columns: &[String],
    order_by: &[OrderByItem],
    outer: Option<&OuterCtx<'_>>,
) -> Result<(), SqlError> {
    for key in order_by {
        match key {
            OrderByItem::Column(col, _) => {
                if col.qualifier.is_none() && out_columns.iter().any(|c| c == &col.name) {
                    continue;
                }
                validate_column_with_outer(scope, col, outer)?;
            }
            OrderByItem::Aggregate(agg, _) => {
                if let Some(arg) = &agg.arg {
                    validate_column_with_outer(scope, arg, outer)?;
                }
            }
        }
    }
    Ok(())
}

/// ORDER BY keys for one plain row: an unqualified name that
/// matches an output alias (or output column) sorts by that
/// output value; otherwise the key is read off the joined row.
fn order_keys_plain(
    row: &JoinedRow,
    scope: &Scope,
    items: &Option<Vec<SelectItem>>,
    out_columns: &[String],
    out: &[Cell],
    order_by: &[OrderByItem],
    outer: Option<&OuterCtx<'_>>,
) -> Result<Vec<Cell>, SqlError> {
    let mut keys = Vec::with_capacity(order_by.len());
    for key in order_by {
        match key {
            OrderByItem::Column(col, _) => {
                if col.qualifier.is_none() {
                    if let Some(idx) = out_columns.iter().position(|c| c == &col.name) {
                        // An output alias (or an output column
                        // name) wins over the table columns —
                        // PostgreSQL resolves ORDER BY against
                        // the output list first.
                        keys.push(out[idx].clone());
                        continue;
                    }
                }
                keys.push(match resolve_with_outer(row, scope, col, outer)? {
                    Resolve::Found(v) => v,
                    Resolve::NotFound => {
                        return Err(sql_err(
                            "42703",
                            format!("column '{}' does not exist", col.name),
                        ));
                    }
                    Resolve::Ambiguous => {
                        return Err(sql_err(
                            "42702",
                            format!(
                                "column reference '{}' is ambiguous — qualify it with a table name",
                                col.name
                            ),
                        ));
                    }
                });
            }
            OrderByItem::Aggregate(..) => {
                // An aggregate in ORDER BY makes the whole query
                // aggregate — this function only runs for plain
                // queries, so reaching here is a bug.
                return Err(sql_err(
                    "XX000",
                    "internal error: aggregate ORDER BY key in a plain SELECT",
                ));
            }
        }
    }
    let _ = items;
    Ok(keys)
}

/// Sort (row, keys) pairs by the keys in order; each key's
/// direction comes from its ORDER BY item.
fn sort_by_keys(projected: &mut [(Vec<Cell>, Vec<Cell>)], order_by: &[OrderByItem]) {
    if order_by.is_empty() {
        return;
    }
    projected.sort_by(|(_, a), (_, b)| {
        for (i, key) in order_by.iter().enumerate() {
            let asc = match key {
                OrderByItem::Column(_, asc) => *asc,
                OrderByItem::Aggregate(_, asc) => *asc,
            };
            let ord = cmp_order(&a[i], &b[i]);
            if ord != std::cmp::Ordering::Equal {
                return if asc { ord } else { ord.reverse() };
            }
        }
        std::cmp::Ordering::Equal
    });
}

/// An aggregate SELECT: group the rows, compute the aggregates,
/// apply HAVING, sort by the ORDER BY keys, and return
/// (columns, rows) in sorted order (LIMIT/OFFSET are applied by
/// the caller). A SELECT-list subquery (V0.10) is evaluated once
/// per group: uncorrelated ones are evaluated lazily, once, and
/// cached; correlated ones run against the group's key values
/// as the outer row, so they may only reference GROUP BY
/// columns (any other outer column is 42803).
fn execute_aggregate(
    stmt: &Stmt,
    scope: &Scope,
    joined: &[JoinedRow],
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
    snapshot: &Snapshot,
) -> Result<(Vec<String>, Vec<Vec<Cell>>), SqlError> {
    let Stmt::Select {
        items,
        group_by,
        having,
        order_by,
        limit,
        ..
    } = stmt
    else {
        return Err(sql_err(
            "XX000",
            "internal error: execute_aggregate called with a non-SELECT statement",
        ));
    };
    let items = items.as_ref().ok_or_else(|| {
        sql_err(
            "42803",
            "SELECT * cannot be used with GROUP BY or aggregates — list the columns explicitly",
        )
    })?;
    // A qualified star cannot be grouped: it expands to columns
    // that are not GROUP BY columns. (Plain `*` is rejected
    // above; `u.*` gets the same treatment.)
    if items
        .iter()
        .any(|i| matches!(i, SelectItem::QualifiedStar { .. }))
    {
        return Err(sql_err(
            "42803",
            "SELECT <table>.* cannot be used with GROUP BY or aggregates — list the columns explicitly",
        ));
    }
    // GROUP BY columns are validated up front, so an unknown one
    // errors even when the filtered set is empty (it used to
    // pass silently — the lazy-validation gap, minor 2).
    for col in group_by {
        validate_column_with_outer(scope, col, outer)?;
    }
    // Every plain column in the SELECT list must be a GROUP BY
    // column (PostgreSQL 42803), and every aggregate argument
    // must exist. Existence is checked FIRST (42703): an unknown
    // column is "does not exist", not "must appear in GROUP BY"
    // (M2b — the old order reported 42803 for a typo).
    for item in items {
        match item {
            SelectItem::Column { col, .. } => {
                validate_column_with_outer(scope, col, outer)?;
                if !is_group_column(group_by, col) {
                    return Err(sql_err(
                        "42803",
                        format!(
                            "column '{}' must appear in the GROUP BY clause or be used in an aggregate function",
                            col.name
                        ),
                    ));
                }
            }
            SelectItem::Aggregate { agg, .. } => {
                if let Some(arg) = &agg.arg {
                    validate_column_with_outer(scope, arg, outer)?;
                }
            }
            SelectItem::ScalarSubquery { .. } => {
                // Validated when it runs (its inner columns
                // belong to its own tables, or to the outer
                // query — see `resolve_with_outer`).
            }
            SelectItem::QualifiedStar { .. } => unreachable!("rejected above"),
        }
    }
    // HAVING columns: same order — existence (42703) first,
    // then the GROUP BY check (42803). A HAVING alias such as
    // `HAVING total > 100` is 42703 in PostgreSQL, because
    // `total` is no table column.
    for cond in having {
        if let Some(col) = &cond.column {
            validate_column_with_outer(scope, col, outer)?;
            if !is_group_column(group_by, col) {
                return Err(sql_err(
                    "42803",
                    format!(
                        "column '{}' must appear in the GROUP BY clause or be used in an aggregate function",
                        col.name
                    ),
                ));
            }
        }
        if let Some(agg) = &cond.agg {
            if let Some(arg) = &agg.arg {
                validate_column_with_outer(scope, arg, outer)?;
            }
        }
    }
    let out_columns: Vec<String> = items.iter().map(SelectItem::output_name).collect();
    validate_order_by(scope, &out_columns, order_by, outer)?;
    // LIMIT 0: no rows out, and no grouping or projection runs
    // at all (M4) — so a failing SELECT-list subquery does not
    // fail a query that returns nothing. The GROUP BY / HAVING
    // / ORDER BY validation above already ran, so this still
    // errors on an unknown column, like a LIMIT 0 over a bad
    // query should.
    if *limit == Some(0) {
        return Ok((out_columns, Vec::new()));
    }

    // Group the rows: the key is the GROUP BY column values, in
    // order. NULLs group together (PostgreSQL: one NULL group).
    // With no GROUP BY there is exactly one group — even over an
    // empty table, so `SELECT COUNT(*)` still returns one row.
    let mut groups: BTreeMap<Vec<Cell>, Vec<JoinedRow>> = BTreeMap::new();
    if group_by.is_empty() {
        groups.insert(Vec::new(), joined.to_vec());
    } else {
        for (i, row) in joined.iter().enumerate() {
            if i.is_multiple_of(1024) {
                check_deadline(deadline)?;
            }
            let mut key = Vec::with_capacity(group_by.len());
            for col in group_by {
                key.push(match resolve_with_outer(row, scope, col, outer)? {
                    Resolve::Found(v) => v,
                    Resolve::NotFound => {
                        return Err(sql_err(
                            "42703",
                            format!("column '{}' does not exist", col.name),
                        ));
                    }
                    Resolve::Ambiguous => {
                        return Err(sql_err(
                            "42702",
                            format!(
                                "column reference '{}' is ambiguous — qualify it with a table name",
                                col.name
                            ),
                        ));
                    }
                });
            }
            groups.entry(key).or_default().push(row.clone());
        }
    }

    // Which SELECT-list subqueries are uncorrelated (V0.10):
    // their values are evaluated lazily, once, and cached —
    // see `uncorrelated_subquery_flags`. An uncorrelated
    // subquery runs with this statement's own outer context
    // (`outer`, not its parent) — see the note in
    // `execute_plain`: a nested subquery may still reference
    // an ancestor level, and `outer`'s parent chain reaches it.
    let uncorrelated = uncorrelated_subquery_flags(snapshot, items, scope)?;
    let mut cached: Vec<Option<Cell>> = vec![None; uncorrelated.len()];

    let mut projected: Vec<(Vec<Cell>, Vec<Cell>)> = Vec::new();
    for (key, rows) in &groups {
        // HAVING: one condition per group; an aggregate is
        // computed over the group's rows, a column is read off
        // the group key.
        let mut keep = true;
        for cond in having {
            let got: Cell = match (&cond.agg, &cond.column) {
                (Some(agg), _) => compute_aggregate(agg, rows, scope, deadline, outer)?,
                (None, Some(col)) => group_key_value(group_by, key, col),
                (None, None) => {
                    return Err(sql_err(
                        "XX000",
                        "internal error: HAVING condition with neither aggregate nor column",
                    ));
                }
            };
            if !cmp_cells(&got, &Some(literal(&cond.value)?), cond.op) {
                keep = false;
                break;
            }
        }
        if !keep {
            continue;
        }
        // The group's outer row for a correlated SELECT-list
        // subquery: only the GROUP BY key values, keyed by
        // (table, column) — so a subquery that references any
        // other outer column gets 42803 from `outer_value`,
        // never a wrong value from another row of the group.
        let mut group_row: JoinedRow = BTreeMap::new();
        for (col, val) in group_by.iter().zip(key.iter()) {
            let table_key = match &col.qualifier {
                Some(q) => q.clone(),
                None => scope
                    .tables
                    .iter()
                    .find(|t| t.columns.iter().any(|c| c == &col.name))
                    .map(|t| t.key.clone())
                    .unwrap_or_default(),
            };
            group_row.insert((table_key, col.name.clone()), val.clone());
        }
        let group_ctx = OuterCtx {
            row: &group_row,
            scope,
            parent: outer,
            group_only: true,
        };
        // Project the group's output row.
        let mut out = Vec::with_capacity(items.len());
        for (idx, item) in items.iter().enumerate() {
            match item {
                SelectItem::Column { col, .. } => {
                    out.push(group_key_value(group_by, key, col));
                }
                SelectItem::Aggregate { agg, .. } => {
                    out.push(compute_aggregate(agg, rows, scope, deadline, outer)?);
                }
                SelectItem::ScalarSubquery { query, .. } => {
                    // Uncorrelated: evaluate once (on the first
                    // group that needs it) and reuse the value
                    // for every group. Correlated: evaluate once
                    // per group, against the group key values.
                    if uncorrelated[idx] {
                        if let Some(v) = cached[idx].clone() {
                            out.push(v);
                        } else {
                            let v = run_scalar_subquery(snapshot, query, deadline, outer)?;
                            cached[idx] = Some(v.clone());
                            out.push(v);
                        }
                    } else {
                        out.push(run_scalar_subquery(
                            snapshot,
                            query,
                            deadline,
                            Some(&group_ctx),
                        )?);
                    }
                }
                SelectItem::QualifiedStar { .. } => unreachable!("rejected above"),
            }
        }
        let keys = order_keys_aggregate(
            group_by,
            key,
            rows,
            scope,
            items,
            &out_columns,
            &out,
            order_by,
            deadline,
            outer,
        )?;
        projected.push((out, keys));
    }
    sort_by_keys(&mut projected, order_by);
    Ok((
        out_columns,
        projected.into_iter().map(|(out, _)| out).collect(),
    ))
}

/// Is `col` one of the GROUP BY columns? A match is by column
/// name, and by qualifier when both sides name one.
fn is_group_column(group_by: &[ColumnRef], col: &ColumnRef) -> bool {
    group_by.iter().any(|g| {
        g.name == col.name
            && match (&g.qualifier, &col.qualifier) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    })
}

/// The value of a GROUP BY column in one group, read off the
/// group key. (The caller has already checked that the column
/// is a GROUP BY column, so a missing key entry is a bug, not
/// a user error — it reads as NULL rather than panicking.)
fn group_key_value(group_by: &[ColumnRef], key: &[Cell], col: &ColumnRef) -> Cell {
    group_by
        .iter()
        .position(|g| {
            g.name == col.name
                && match (&g.qualifier, &col.qualifier) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                }
        })
        .and_then(|i| key.get(i).cloned())
        .unwrap_or(None)
}

/// ORDER BY keys for one group: an unqualified name matching an
/// output column sorts by that output value; an aggregate is
/// computed over the group's rows (whether or not it was
/// selected); a GROUP BY column is read off the group key.
/// Anything else is 42703.
#[allow(clippy::too_many_arguments)]
fn order_keys_aggregate(
    group_by: &[ColumnRef],
    key: &[Cell],
    rows: &[JoinedRow],
    scope: &Scope,
    items: &[SelectItem],
    out_columns: &[String],
    out: &[Cell],
    order_by: &[OrderByItem],
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<Vec<Cell>, SqlError> {
    let mut keys = Vec::with_capacity(order_by.len());
    for item in order_by {
        match item {
            OrderByItem::Column(col, _) => {
                if col.qualifier.is_none() {
                    if let Some(idx) = out_columns.iter().position(|c| c == &col.name) {
                        keys.push(out[idx].clone());
                        continue;
                    }
                }
                if is_group_column(group_by, col) {
                    keys.push(group_key_value(group_by, key, col));
                    continue;
                }
                // M2a: the column exists (existence was checked
                // up front, 42703) — it is just not grouped, so
                // this is 42803, like PostgreSQL, with a message
                // that says so instead of claiming it does not
                // exist.
                return Err(sql_err(
                    "42803",
                    format!(
                        "column '{}' must appear in the GROUP BY clause or be used in an aggregate function — \
                         ORDER BY can only use output columns, GROUP BY columns, or aggregates",
                        col.name
                    ),
                ));
            }
            OrderByItem::Aggregate(agg, _) => {
                if let Some(arg) = &agg.arg {
                    validate_column_with_outer(scope, arg, outer)?;
                }
                // Prefer the selected aggregate when the same
                // call is in the SELECT list, so the ORDER BY
                // value is exactly the displayed one.
                let mut value: Option<Cell> = None;
                for (i, item) in items.iter().enumerate() {
                    if let SelectItem::Aggregate { agg: a, .. } = item {
                        if a == agg {
                            value = Some(out[i].clone());
                            break;
                        }
                    }
                }
                keys.push(match value {
                    Some(v) => v,
                    None => compute_aggregate(agg, rows, scope, deadline, outer)?,
                });
            }
        }
    }
    Ok(keys)
}

/// One aggregate over a group's rows. COUNT(*) counts rows;
/// COUNT(col) counts non-NULL values; SUM / AVG need numbers
/// (a non-numeric value is 22P02); MIN / MAX take any values.
/// Over no rows, COUNT is 0 and the rest are NULL.
fn compute_aggregate(
    agg: &AggregateExpr,
    rows: &[JoinedRow],
    scope: &Scope,
    deadline: Option<Instant>,
    outer: Option<&OuterCtx<'_>>,
) -> Result<Cell, SqlError> {
    match agg.func {
        AggFunc::Count => {
            let n = match &agg.arg {
                None => rows.len(),
                Some(col) => {
                    let mut n = 0;
                    for row in rows {
                        if let Resolve::Found(Some(_)) = resolve_with_outer(row, scope, col, outer)?
                        {
                            n += 1;
                        }
                    }
                    n
                }
            };
            Ok(Some(n.to_string()))
        }
        AggFunc::Sum | AggFunc::Avg => {
            let Some(col) = &agg.arg else {
                return Err(sql_err(
                    "42601",
                    format!(
                        "{}(*) is not valid — {} needs a column",
                        agg.func.name(),
                        agg.func.name()
                    ),
                ));
            };
            let mut values: Vec<String> = Vec::new();
            for row in rows {
                if let Resolve::Found(Some(v)) = resolve_with_outer(row, scope, col, outer)? {
                    values.push(v);
                }
            }
            if values.is_empty() {
                return Ok(None);
            }
            // Integer path: exact (i128) when every value is a
            // plain integer; otherwise f64. A value that is not
            // a number at all is 22P02 (PostgreSQL: invalid
            // input syntax for type numeric). An integer sum
            // that overflows i128 is 22003 — it used to fall
            // through silently to an f64 approximation (M4), so
            // SUM of two i128::MAX values printed a wrong
            // 39-digit number with no error.
            let all_int = values.iter().all(|v| is_plain_int(v));
            if all_int {
                let mut sum: i128 = 0;
                let mut overflow = false;
                for (i, v) in values.iter().enumerate() {
                    // The f64 path below checks the deadline
                    // every 1024 values; the integer path must
                    // too — a huge integer SUM over a big group
                    // is just as long a loop.
                    if i.is_multiple_of(1024) {
                        check_deadline(deadline)?;
                    }
                    match v.parse::<i128>() {
                        Ok(n) => match sum.checked_add(n) {
                            Some(s) => sum = s,
                            None => {
                                overflow = true;
                                break;
                            }
                        },
                        Err(_) => {
                            overflow = true;
                            break;
                        }
                    }
                }
                if overflow {
                    return Err(sql_err(
                        "22003",
                        format!(
                            "value out of range: {} over integers overflowed i128 — \
                             the values are too large to add exactly",
                            agg.func.name()
                        ),
                    ));
                }
                return Ok(Some(match agg.func {
                    AggFunc::Sum => sum.to_string(),
                    // Exact AVG (M4): integer division plus the
                    // remainder as a decimal expansion — never
                    // through f64, which lost 1 on
                    // AVG(9007199254740993, 9007199254740993).
                    AggFunc::Avg => format_avg_exact(sum, values.len()),
                    _ => unreachable!(),
                }));
            }
            let mut sum: f64 = 0.0;
            for (i, v) in values.iter().enumerate() {
                if i.is_multiple_of(1024) {
                    check_deadline(deadline)?;
                }
                match v.parse::<f64>() {
                    Ok(n) if n.is_finite() => sum += n,
                    _ => {
                        return Err(sql_err(
                            "22P02",
                            format!(
                                "invalid input syntax for type numeric: \"{v}\" — \
                                 {} needs numbers",
                                agg.func.name()
                            ),
                        ));
                    }
                }
            }
            Ok(Some(match agg.func {
                AggFunc::Sum => format_number(sum),
                AggFunc::Avg => format_number(sum / values.len() as f64),
                _ => unreachable!(),
            }))
        }
        AggFunc::Min | AggFunc::Max => {
            let Some(col) = &agg.arg else {
                return Err(sql_err(
                    "42601",
                    format!(
                        "{}(*) is not valid — {} needs a column",
                        agg.func.name(),
                        agg.func.name()
                    ),
                ));
            };
            let mut best: Option<String> = None;
            for row in rows {
                if let Resolve::Found(Some(v)) = resolve_with_outer(row, scope, col, outer)? {
                    best = Some(match best {
                        None => v,
                        Some(b) => {
                            let ord = compare_values(&v, &b);
                            match agg.func {
                                AggFunc::Min => {
                                    if ord == std::cmp::Ordering::Less {
                                        v
                                    } else {
                                        b
                                    }
                                }
                                AggFunc::Max => {
                                    if ord == std::cmp::Ordering::Greater {
                                        v
                                    } else {
                                        b
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                    });
                }
            }
            Ok(best)
        }
    }
}

/// A plain integer string (`[+-]?[0-9]+`)? Used to pick the
/// exact i128 path for SUM / AVG.
fn is_plain_int(v: &str) -> bool {
    let bytes = v.as_bytes();
    let digits = match bytes.first() {
        Some(b'+') | Some(b'-') => &bytes[1..],
        _ => bytes,
    };
    !digits.is_empty() && digits.iter().all(|c| c.is_ascii_digit())
}

/// Format an f64 aggregate result: whole numbers print without
/// a decimal point (`150`, not `150.0`); anything else prints
/// as Rust prints an f64 (shortest round-trip form).
fn format_number(v: f64) -> String {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// Exact AVG of an i128 sum over `n` values (M4): integer
/// division plus the remainder as a decimal expansion, in
/// u128 so even `i128::MIN` is safe. Exact when the division
/// terminates (e.g. AVG(9007199254740993, 9007199254740993) is
/// 9007199254740993, not the f64-rounded 9007199254740992);
/// when it repeats (1/3), the expansion runs to 16 decimal
/// places — documented in the README, not claimed exact.
fn format_avg_exact(sum: i128, n: usize) -> String {
    let n = n as u128;
    let mag = sum.unsigned_abs();
    let (quotient, mut rem) = (mag / n, mag % n);
    if rem == 0 {
        return if sum < 0 {
            format!("-{quotient}")
        } else {
            quotient.to_string()
        };
    }
    let mut digits = String::new();
    for _ in 0..16 {
        rem *= 10;
        let d = (rem / n) as u32;
        digits.push(char::from_digit(d, 10).expect("digit 0-9"));
        rem %= n;
        if rem == 0 {
            break;
        }
    }
    format!("{}{}.{}", if sum < 0 { "-" } else { "" }, quotient, digits)
}

/// Output columns of a SELECT, resolved against the registry —
/// for the extended protocol's Describe, which answers without
/// executing. `*` expands to every column of every table in
/// scope; an explicit list is the item names (alias wins), with
/// unknown / ambiguous columns rejected (42703 / 42702).
pub(crate) fn output_columns(tables: &TableStore, stmt: &Stmt) -> Result<Vec<String>, SqlError> {
    let Stmt::Select { items, .. } = stmt else {
        return Err(sql_err(
            "XX000",
            "internal error: output_columns called with a non-SELECT statement",
        ));
    };
    let scope = Scope::of(tables, stmt)?;
    match items {
        None => Ok(scope.star_columns()),
        Some(items) => Ok(expand_output_columns(&scope, items, None)?),
    }
}

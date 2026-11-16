// query.rs — the SELECT executor for Zeno V0.9: JOINs, subqueries,
// GROUP BY + aggregates, on top of the table store.
//
// A SELECT runs in three stages:
//   1. Snapshot + scope: every table the statement (and its
//      subqueries) can read is scanned once under the shared
//      lock, then the lock is released — a long SELECT no
//      longer blocks other connections. The scope is the base
//      table plus each JOINed table (aliases are the names the
//      query uses; a missing table is 42P01, a table or alias
//      named twice is 42712, and inside a transaction a table
//      created after BEGIN is invisible — the same rule as V0.6).
//   2. Rows: the snapshot rows are nested-loop joined (the V0.6
//      snapshot when inside a transaction — JOIN/grouped reads
//      see the same snapshot as a plain SELECT, never newer
//      commits), then a nested-loop join combines them.
//      Nested-loop is the V0.9 choice for this scale: it is
//      simple and correct, and it gets slow on large inputs — a
//      hash join is V1.0+ work (see README). No index is used
//      anywhere. Each subquery is evaluated ONCE per statement
//      (hoisted before the WHERE loop — subqueries are always
//      uncorrelated here, so this is always correct) and the
//      result reused for every outer row; per-row evaluation
//      used to make nested IN exponential. A statement timeout
//      (57014, `ZENO_STATEMENT_TIMEOUT_MS`, default 30000 ms)
//      caps how long any of this may run.
//   3. WHERE, then GROUP BY + aggregates + HAVING (or a plain
//      projection), then ORDER BY, then LIMIT/OFFSET. LIMIT is
//      applied last — there is no LIMIT pushdown, so a LIMIT 5
//      over a big JOIN still materialises the whole join first.
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
/// JOINs, plus every subquery's tables, recursively.
fn collect_table_names(stmt: &Stmt, out: &mut BTreeSet<String>) {
    let Stmt::Select {
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
    for cond in conditions {
        match &cond.rhs {
            CondRhs::InSubquery { query, .. } | CondRhs::ScalarSubquery(query) => {
                collect_table_names(query, out);
            }
            CondRhs::Value(_) => {}
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
struct Scope {
    tables: Vec<ScopeTable>,
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
fn validate_column(scope: &Scope, col: &ColumnRef) -> Result<(), SqlError> {
    match &col.qualifier {
        Some(q) => {
            let Some(t) = scope.tables.iter().find(|t| t.key == *q) else {
                return Err(sql_err(
                    "42703",
                    format!("missing FROM-clause entry for table '{q}'"),
                ));
            };
            if !t.columns.iter().any(|c| c == &col.name) {
                return Err(sql_err(
                    "42703",
                    format!("column '{}.{}' does not exist", q, col.name),
                ));
            }
            Ok(())
        }
        None => {
            let matches: Vec<&ScopeTable> = scope
                .tables
                .iter()
                .filter(|t| t.columns.iter().any(|c| c == &col.name))
                .collect();
            match matches.len() {
                0 => Err(sql_err(
                    "42703",
                    format!("column '{}' does not exist", col.name),
                )),
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
fn resolve(row: &JoinedRow, scope: &Scope, col: &ColumnRef) -> Result<Resolve, SqlError> {
    match &col.qualifier {
        Some(q) => {
            let Some(t) = scope.tables.iter().find(|t| t.key == *q) else {
                return Err(sql_err(
                    "42703",
                    format!("missing FROM-clause entry for table '{q}'"),
                ));
            };
            if !t.columns.iter().any(|c| c == &col.name) {
                return Err(sql_err(
                    "42703",
                    format!("column '{}.{}' does not exist", q, col.name),
                ));
            }
            Ok(match row.get(&(q.clone(), col.name.clone())) {
                // A LEFT JOIN miss is stored as an explicit
                // NULL; a row that simply lacks the key (a row
                // written before the column existed) reads as
                // "" — the pre-V0.9 behaviour for a missing
                // column value.
                Some(v) => Resolve::Found(v.clone()),
                None => Resolve::Found(Some(String::new())),
            })
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
                None => Ok(Resolve::NotFound),
                Some(t) => Ok(match row.get(&(t.key.clone(), col.name.clone())) {
                    Some(v) => Resolve::Found(v.clone()),
                    None => Resolve::Found(Some(String::new())),
                }),
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
    execute_select_snapshot_deadline(snapshot, stmt, statement_deadline())
}

/// One subquery result, hoisted out of the WHERE loop (B2): a
/// subquery in Zeno is always uncorrelated (the parser has no
/// syntax for an outer reference), so evaluating it once per
/// statement — not once per outer row — is always correct, and
/// turns a nested IN from exponential into linear.
enum Hoisted {
    In(Vec<Cell>),
    Scalar(Cell),
}

fn execute_select_snapshot_deadline(
    snapshot: &Snapshot,
    stmt: &Stmt,
    deadline: Option<Instant>,
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

    // Stage 1 — nested-loop join over the snapshot rows.
    let joined = fetch_joined(snapshot, stmt, &scope, deadline)?;

    // Stage 1b — hoist every subquery: evaluate each one once,
    // here, and reuse the result for every outer row. Before
    // this fix each row re-ran the subquery, so a nested IN
    // (depth 2, 200 rows) never finished.
    let mut hoisted: Vec<Option<Hoisted>> = Vec::with_capacity(conditions.len());
    for cond in conditions {
        hoisted.push(match &cond.rhs {
            CondRhs::InSubquery { query, .. } => {
                Some(Hoisted::In(run_subquery_values(snapshot, query, deadline)?))
            }
            CondRhs::ScalarSubquery(query) => Some(Hoisted::Scalar(run_scalar_subquery(
                snapshot, query, deadline,
            )?)),
            CondRhs::Value(_) => None,
        });
    }

    // Stage 2 — WHERE (AND-joined; subquery results come from
    // the hoisted cache). A failing condition (an ambiguous
    // column) fails the whole statement — it is not a filtered
    // row.
    let mut filtered: Vec<JoinedRow> = Vec::with_capacity(joined.len());
    for (i, row) in joined.into_iter().enumerate() {
        if i.is_multiple_of(1024) {
            check_deadline(deadline)?;
        }
        let mut keep = true;
        for (cond, cached) in conditions.iter().zip(hoisted.iter()) {
            if !eval_condition(&row, &scope, cond, cached.as_ref())? {
                keep = false;
                break;
            }
        }
        if keep {
            filtered.push(row);
        }
    }
    let joined = filtered;

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

    let (out_columns, out_rows): (Vec<String>, Vec<Vec<Cell>>) = if is_aggregate {
        execute_aggregate(stmt, &scope, &joined, deadline)?
    } else {
        execute_plain(stmt, &scope, &joined, deadline)?
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

/// Stage 1: nested-loop join each further table onto the base
/// table, in written order, over the snapshot rows. INNER keeps
/// only matching pairs; LEFT keeps every left row, padding the
/// right side with NULLs when nothing matches.
fn fetch_joined(
    snapshot: &Snapshot,
    stmt: &Stmt,
    scope: &Scope,
    deadline: Option<Instant>,
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
    let mut joined: Vec<JoinedRow> = snapshot_rows(snapshot, table)?
        .iter()
        .map(|(_, row)| to_joined_row(&base_key, row.clone()))
        .collect();
    for join in joins {
        let right_key = join.alias.clone().unwrap_or_else(|| join.table.clone());
        let right_rows: Vec<JoinedRow> = snapshot_rows(snapshot, &join.table)?
            .iter()
            .map(|(_, row)| to_joined_row(&right_key, row.clone()))
            .collect();
        let right_scope = scope
            .tables
            .iter()
            .find(|t| t.key == right_key)
            .expect("join table is in scope");
        let mut next: Vec<JoinedRow> = Vec::new();
        let mut pairs: usize = 0;
        for left in &joined {
            let mut matched = false;
            for right in &right_rows {
                pairs += 1;
                if pairs.is_multiple_of(1024) {
                    check_deadline(deadline)?;
                }
                // The ON pair is evaluated on the merged row,
                // so either side may reference either table
                // (PostgreSQL allows that too).
                let mut merged = left.clone();
                merged.extend(right.clone());
                let l = resolve(&merged, scope, &join.left)?;
                let r = resolve(&merged, scope, &join.right)?;
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
                    next.push(merged);
                }
            }
            if !matched && join.kind == JoinKind::Left {
                let mut padded = left.clone();
                for col in &right_scope.columns {
                    padded.insert((right_key.clone(), col.clone()), None);
                }
                next.push(padded);
            }
        }
        joined = next;
    }
    Ok(joined)
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
fn eval_condition(
    row: &JoinedRow,
    scope: &Scope,
    cond: &Condition,
    cached: Option<&Hoisted>,
) -> Result<bool, SqlError> {
    let value = match resolve(row, scope, &cond.column)? {
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
/// outer statement's deadline.
fn run_subquery_values(
    snapshot: &Snapshot,
    query: &Stmt,
    deadline: Option<Instant>,
) -> Result<Vec<Cell>, SqlError> {
    let (cols, rows) = execute_select_snapshot_deadline(snapshot, query, deadline)?;
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
) -> Result<Cell, SqlError> {
    let values = run_subquery_values(snapshot, query, deadline)?;
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.into_iter().next().expect("one value")),
        _ => Err(sql_err(
            "21000",
            "more than one row returned by a subquery used as an expression",
        )),
    }
}

/// A plain (non-aggregate) SELECT: project the rows, sort by
/// the ORDER BY keys, and return (columns, rows) in sorted
/// order (LIMIT/OFFSET are applied by the caller).
fn execute_plain(
    stmt: &Stmt,
    scope: &Scope,
    joined: &[JoinedRow],
    deadline: Option<Instant>,
) -> Result<(Vec<String>, Vec<Vec<Cell>>), SqlError> {
    let Stmt::Select {
        items, order_by, ..
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
        Some(items) => expand_output_columns(scope, items)?,
    };
    // ORDER BY keys are validated up front (existence only — an
    // output alias is valid even when it names no table column),
    // so an unknown key errors even over an empty result set
    // instead of silently sorting nothing.
    validate_order_by(scope, &out_columns, order_by)?;
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
                for item in items {
                    match item {
                        SelectItem::Column { col, .. } => {
                            out.push(match resolve(row, scope, col)? {
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
                    }
                }
                out
            }
        };
        let keys = order_keys_plain(row, scope, items, &out_columns, &out, order_by)?;
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
/// columns in registry order (an unknown qualifier is 42703).
fn expand_output_columns(scope: &Scope, items: &[SelectItem]) -> Result<Vec<String>, SqlError> {
    let mut out = Vec::new();
    for item in items {
        match item {
            SelectItem::Column { col, .. } => {
                validate_column(scope, col)?;
                out.push(item.output_name());
            }
            SelectItem::Aggregate { agg, .. } => {
                if let Some(arg) = &agg.arg {
                    validate_column(scope, arg)?;
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
) -> Result<(), SqlError> {
    for key in order_by {
        match key {
            OrderByItem::Column(col, _) => {
                if col.qualifier.is_none() && out_columns.iter().any(|c| c == &col.name) {
                    continue;
                }
                validate_column(scope, col)?;
            }
            OrderByItem::Aggregate(agg, _) => {
                if let Some(arg) = &agg.arg {
                    validate_column(scope, arg)?;
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
                keys.push(match resolve(row, scope, col)? {
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
/// the caller).
fn execute_aggregate(
    stmt: &Stmt,
    scope: &Scope,
    joined: &[JoinedRow],
    deadline: Option<Instant>,
) -> Result<(Vec<String>, Vec<Vec<Cell>>), SqlError> {
    let Stmt::Select {
        items,
        group_by,
        having,
        order_by,
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
        validate_column(scope, col)?;
    }
    // Every plain column in the SELECT list must be a GROUP BY
    // column (PostgreSQL 42803), and every aggregate argument
    // must exist. Existence is checked FIRST (42703): an unknown
    // column is "does not exist", not "must appear in GROUP BY"
    // (M2b — the old order reported 42803 for a typo).
    for item in items {
        match item {
            SelectItem::Column { col, .. } => {
                validate_column(scope, col)?;
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
                    validate_column(scope, arg)?;
                }
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
            validate_column(scope, col)?;
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
                validate_column(scope, arg)?;
            }
        }
    }
    let out_columns: Vec<String> = items.iter().map(SelectItem::output_name).collect();
    validate_order_by(scope, &out_columns, order_by)?;

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
                key.push(match resolve(row, scope, col)? {
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

    let mut projected: Vec<(Vec<Cell>, Vec<Cell>)> = Vec::new();
    for (key, rows) in &groups {
        // HAVING: one condition per group; an aggregate is
        // computed over the group's rows, a column is read off
        // the group key.
        let mut keep = true;
        for cond in having {
            let got: Cell = match (&cond.agg, &cond.column) {
                (Some(agg), _) => compute_aggregate(agg, rows, scope, deadline)?,
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
        // Project the group's output row.
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            match item {
                SelectItem::Column { col, .. } => {
                    out.push(group_key_value(group_by, key, col));
                }
                SelectItem::Aggregate { agg, .. } => {
                    out.push(compute_aggregate(agg, rows, scope, deadline)?);
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
                    validate_column(scope, arg)?;
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
                    None => compute_aggregate(agg, rows, scope, deadline)?,
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
) -> Result<Cell, SqlError> {
    match agg.func {
        AggFunc::Count => {
            let n = match &agg.arg {
                None => rows.len(),
                Some(col) => {
                    let mut n = 0;
                    for row in rows {
                        if let Resolve::Found(Some(_)) = resolve(row, scope, col)? {
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
                if let Resolve::Found(Some(v)) = resolve(row, scope, col)? {
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
                for v in &values {
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
                if let Resolve::Found(Some(v)) = resolve(row, scope, col)? {
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
        Some(items) => Ok(expand_output_columns(&scope, items)?),
    }
}

// table.rs — a basic table on top of the key-value engine.
//
// A table is just a namespace of keys:
//   table:<name>:<row-id>  ->  {"col1": "value1", "col2": "value2", ...}
//
// The SQL itself is parsed in `parser.rs` (V0.7: a real lexer +
// recursive-descent parser); this file is the storage layer the
// parser's AST executes against. `select` here means: scan all
// rows of the table, keeping only rows matching a `RowFilter`
// (AND-joined conditions, V0.7) — still a linear scan, not an
// indexed query.
//
// Table schemas (the list of column names) are kept in a small JSON file
// `tables.json` inside the data directory, so they survive a restart.

use crate::engine::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// One row from `select`: (row id, column name -> value).
pub type TableRow = (u64, BTreeMap<String, String>);

/// A comparison operator in a WHERE condition (V0.7: the SQL
/// parser supports all six; V0.6 only had `=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

/// A WHERE filter: AND-joined `column <op> value` conditions
/// (V0.7). An empty filter matches every row. A condition on a
/// column the row does not have matches NO row — including `!=`,
/// because a missing value is not a value at all (this keeps the
/// V0.6 behaviour, where a filter on an unknown column matched
/// nothing, instead of silently matching everything under `!=`).
/// The value is `None` for a SQL NULL literal (V0.11): a
/// comparison against NULL is never true in PostgreSQL, so a NULL
/// condition matches no row, for every operator — including `!=`.
/// (The SQL layer validates unknown columns as 42703 before a
/// filter is built; this struct is the last line of defence.)
#[derive(Debug, Clone, Default)]
pub struct RowFilter {
    pub conditions: Vec<(String, FilterOp, Option<String>)>,
}

impl RowFilter {
    /// The V0.6 single-condition filter: `column = value`.
    pub fn one(column: &str, value: &str) -> Self {
        Self {
            conditions: vec![(column.to_string(), FilterOp::Eq, Some(value.to_string()))],
        }
    }

    pub fn matches(&self, row: &BTreeMap<String, String>) -> bool {
        self.conditions.iter().all(|(col, op, want)| {
            // A NULL literal never matches (see the struct docs),
            // and neither does a column the row does not carry
            // (a stored NULL is absent from the row map).
            let Some(want) = want else {
                return false;
            };
            let Some(got) = row.get(col) else {
                return false;
            };
            let ord = compare_values(got, want);
            match op {
                FilterOp::Eq => ord == std::cmp::Ordering::Equal,
                FilterOp::Ne => ord != std::cmp::Ordering::Equal,
                FilterOp::Lt => ord == std::cmp::Ordering::Less,
                FilterOp::Gt => ord == std::cmp::Ordering::Greater,
                FilterOp::Le => ord != std::cmp::Ordering::Greater,
                FilterOp::Ge => ord != std::cmp::Ordering::Less,
            }
        })
    }
}

/// Compare two stored values: numerically when BOTH parse as
/// numbers (`"10" > "9"` — a plain string compare would say the
/// opposite), lexicographically otherwise. Used by WHERE
/// `<`/`>`/`<=`/`>=` and by ORDER BY, so both sort the same way.
///
/// B1 (V0.7 review): integers compare as integers, at arbitrary
/// precision — never through `f64`. An `f64` has only 53 bits of
/// mantissa, so `9007199254740992` and `9007199254740993` parse
/// to the SAME `f64` and a `WHERE id = 9007199254740993` matched
/// both rows. Integer strings (optional sign + digits) are
/// compared by sign, then digit length, then lexicographically,
/// which is exact for any size. `f64` is used only once both
/// sides are NOT plain integers (a decimal point or exponent
/// in at least one of them — e.g. `"1.5"` vs `"1.25"`); `NaN`
/// still falls back to a plain string compare so ORDER BY
/// keeps a total order.
pub fn compare_values(a: &str, b: &str) -> std::cmp::Ordering {
    if let Some(ord) = compare_integers(a, b) {
        return ord;
    }
    if let (Ok(x), Ok(y)) = (a.parse::<f64>(), b.parse::<f64>()) {
        // NaN cannot come from a parse of stored text that is
        // itself a number literal... `f64::parse` accepts "NaN"
        // as text, so guard it: NaN compares equal to nothing,
        // which would break ORDER BY's total order.
        if x.is_nan() || y.is_nan() {
            return a.cmp(b);
        }
        return x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal);
    }
    a.cmp(b)
}

/// Exact comparison of two integer strings (`[+-]?[0-9]+`),
/// or `None` when either side is not a plain integer. Compares
/// by sign, then by number of digits (after stripping leading
/// zeros), then lexicographically — exact for integers of any
/// size, including values far above `i64`/`u64`/`f64` range.
fn compare_integers(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    let (a_neg, a_digits) = split_int(a)?;
    let (b_neg, b_digits) = split_int(b)?;
    // Zero has no sign: "-0" == "0" == "+0". (`split_int`
    // strips leading zeros, so an all-zero value has empty
    // digits here — that is zero, not "not an integer".)
    let a_zero = a_digits.iter().all(|c| *c == b'0');
    let b_zero = b_digits.iter().all(|c| *c == b'0');
    if a_zero && b_zero {
        return Some(Ordering::Equal);
    }
    if a_neg != b_neg {
        return Some(if a_neg {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let ord = a_digits
        .len()
        .cmp(&b_digits.len())
        .then_with(|| a_digits.cmp(b_digits));
    Some(if a_neg { ord.reverse() } else { ord })
}

/// Split an integer string into (is_negative, digits without
/// sign or leading zeros). Returns `None` unless the whole
/// string is an optional sign followed by one or more digits.
fn split_int(s: &str) -> Option<(bool, &[u8])> {
    let bytes = s.as_bytes();
    let (neg, digits) = match bytes.first() {
        Some(b'+') => (false, &bytes[1..]),
        Some(b'-') => (true, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() || !digits.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let stripped = &digits[digits.iter().take_while(|c| **c == b'0').count()..];
    Some((neg, stripped))
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TableRegistry {
    /// table name -> { columns: [...], next_row_id: N }
    tables: BTreeMap<String, TableMeta>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TableMeta {
    columns: Vec<String>,
    next_row_id: u64,
}

fn key_prefix(table: &str) -> String {
    format!("table:{table}:")
}

fn row_key(table: &str, row_id: u64) -> String {
    // Zero-padded id so rows sort in numeric order in the BTreeMap.
    format!("table:{table}:{row_id:020}")
}

/// A row as JSON text. `None` is a SQL NULL: it is written as an
/// explicit JSON `null`, so the stored row says the column IS null
/// rather than merely missing. The scan path (`scan_rows`) keeps
/// only JSON strings, so a null column is absent from the in-memory
/// row map — and the SQL layer reads an absent in-scope column as
/// NULL (see `query::resolve_with_outer`).
fn row_to_json(row: BTreeMap<String, Option<String>>) -> String {
    let obj: Map<String, Value> = row
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                match v {
                    Some(s) => Value::String(s),
                    None => Value::Null,
                },
            )
        })
        .collect();
    serde_json::to_string(&Value::Object(obj)).expect("row is valid JSON")
}

#[derive(Debug)]
pub struct TableStore {
    registry_path: PathBuf,
    registry: TableRegistry,
    /// Rows skipped by the last `select` because their stored
    /// value was corrupt or not a JSON object (m6): previously
    /// they vanished silently. The count is cumulative across
    /// selects; each skipped row is also warned about on stderr
    /// with its key, so a corrupt row is visible, not hidden.
    skipped_rows: u64,
}

impl TableStore {
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        let registry_path = dir.join("tables.json");
        let registry = match fs::read_to_string(&registry_path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(registry) => registry,
                Err(e) => {
                    // FAIL CLOSED, never fail open: a corrupt registry
                    // must not silently become "no tables". If we did,
                    // `create_table` would happily re-register a table
                    // and `insert` would restart next_row_id at 1 and
                    // OVERWRITE the old rows still stored in the KV
                    // engine. Quarantine the corrupt file (numbered,
                    // never overwritten — see quarantine.rs) and refuse
                    // to open so no create/insert can touch the old
                    // rows until an operator has looked at the
                    // quarantine. (This is deliberately stricter than
                    // meta.json: corrupt meta.json only loses stats
                    // counters, which the disk scan rebuilds — corrupt
                    // tables.json loses next_row_id, which nothing can
                    // rebuild.)
                    let quarantined = crate::quarantine::quarantine_file(dir, &registry_path);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "corrupt tables.json ({e}); {} — refusing to open so \
                             existing rows cannot be overwritten; inspect the \
                             quarantine and restore it as tables.json, or delete \
                             it only if you accept losing the table registry",
                            match quarantined {
                                Ok(q) => format!("quarantined to {}", q.display()),
                                Err(rename_err) =>
                                    format!("could not quarantine it ({rename_err})"),
                            },
                        ),
                    ));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // First run — unless a quarantine from an earlier
                // corruption is still sitting here. If it is, the
                // registry was already lost once and nobody has dealt
                // with it: opening as "no tables" now would let the
                // next create/insert overwrite the old rows, exactly
                // the failure the quarantine is meant to stop. Refuse
                // until an operator removes or restores the quarantine.
                if let Some(quarantine) = crate::quarantine::any_quarantine(dir, "tables.json") {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "tables.json is missing but {} exists (an earlier \
                             corrupt tables.json was quarantined) — refusing to \
                             open as an empty registry so existing rows cannot \
                             be overwritten; inspect the quarantine and restore \
                             it as tables.json, or delete it only if you accept \
                             losing the table registry",
                            quarantine.display()
                        ),
                    ));
                }
                TableRegistry::default()
            }
            Err(e) => return Err(e),
        };
        Ok(Self {
            registry_path,
            registry,
            skipped_rows: 0,
        })
    }

    /// Rows skipped as corrupt/non-object by `select` so far (m6).
    pub fn skipped_rows(&self) -> u64 {
        self.skipped_rows
    }

    fn save(&self) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(&self.registry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // Atomic write: temp file + fsync + rename + directory fsync
        // (best effort), so a crash cannot leave a truncated tables.json.
        let tmp_path = self.registry_path.with_extension("json.tmp");
        fs::write(&tmp_path, &text)?;
        {
            let f = fs::OpenOptions::new().write(true).open(&tmp_path)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &self.registry_path)?;
        if let Some(parent) = self.registry_path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Register a table with its column names. Errors if it exists.
    pub fn create_table(&mut self, name: &str, columns: Vec<String>) -> Result<(), String> {
        if self.registry.tables.contains_key(name) {
            return Err(format!("table '{name}' already exists"));
        }
        if columns.is_empty() {
            return Err("a table needs at least one column".to_string());
        }
        // M2 (V0.7 review): a duplicate column name used to be
        // accepted, and an INSERT then silently overwrote the
        // first value with the second (the stored row kept only
        // one "id"). Reject it at CREATE TABLE (42601 at the SQL
        // layer) instead of eating data.
        {
            let mut seen = std::collections::BTreeSet::new();
            for col in &columns {
                if !seen.insert(col) {
                    return Err(format!(
                        "duplicate column name '{col}' in CREATE TABLE '{name}'"
                    ));
                }
            }
        }
        self.registry.tables.insert(
            name.to_string(),
            TableMeta {
                columns,
                next_row_id: 1,
            },
        );
        self.save().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn table_exists(&self, name: &str) -> bool {
        self.registry.tables.contains_key(name)
    }

    pub fn columns(&self, name: &str) -> Option<&[String]> {
        self.registry.tables.get(name).map(|m| m.columns.as_slice())
    }

    pub fn list_tables(&self) -> Vec<String> {
        self.registry.tables.keys().cloned().collect()
    }

    /// Insert one row. `values` must match the table's columns in order.
    /// Returns the new row id. A value of `None` is a SQL NULL
    /// (V0.11): the column is stored as JSON `null`.
    pub fn insert(
        &mut self,
        engine: &mut Engine,
        name: &str,
        values: Vec<Option<String>>,
    ) -> Result<u64, String> {
        self.insert_inner(engine, None, name, values)
    }

    /// Insert one row inside transaction `txn` (V0.6): the row is
    /// buffered in the transaction and becomes visible to others
    /// only at COMMIT. The row id is still reserved (and the
    /// registry saved) at statement time, exactly like the
    /// autocommit path — so a ROLLBACK leaves a gap in the row
    /// ids, never a reuse (see README).
    pub fn insert_txn(
        &mut self,
        engine: &mut Engine,
        txn: u64,
        name: &str,
        values: Vec<Option<String>>,
    ) -> Result<u64, String> {
        self.insert_inner(engine, Some(txn), name, values)
    }

    fn insert_inner(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        values: Vec<Option<String>>,
    ) -> Result<u64, String> {
        let columns = self
            .registry
            .tables
            .get(name)
            .ok_or_else(|| format!("no such table '{name}'"))?
            .columns
            .clone();
        if values.len() != columns.len() {
            return Err(format!(
                "table '{name}' has {} columns, got {} values",
                columns.len(),
                values.len()
            ));
        }
        let mut row: BTreeMap<String, Option<String>> = BTreeMap::new();
        for (col, val) in columns.iter().zip(values.iter()) {
            row.insert(col.clone(), val.clone());
        }
        // Reserve the row id AND persist it BEFORE the row itself is
        // written. A crash between the two used to reuse the same id
        // and silently overwrite the previous row; now the worst case
        // is a skipped (gap) id, never an overwrite.
        let row_id = {
            let meta = self.registry.tables.get_mut(name).unwrap();
            let id = meta.next_row_id;
            meta.next_row_id += 1;
            id
        };
        self.save().map_err(|e| e.to_string())?;
        let key = row_key(name, row_id);
        let value = row_to_json(row);
        match txn {
            Some(txn) => engine.txn_put(txn, &key, &value)?,
            None => engine
                .put_internal(&key, &value)
                .map_err(|e| e.to_string())?,
        }
        Ok(row_id)
    }

    /// Delete rows of a table, optionally keeping only rows where one
    /// column equals one value. Returns how many rows were deleted.
    /// Each row key is tombstoned through the engine, so the row
    /// disappears from reads immediately and is physically removed by
    /// compaction — the same delete path as the KV `del` command.
    ///
    /// V0.6-fix (M6): the autocommit path is atomic across rows —
    /// all deletes go through ONE autocommit transaction (one txn
    /// id, one commit marker in the WAL), so a crash mid-delete
    /// replays either all of them or none of them. Inside a
    /// transaction the deletes were already atomic (they sit in
    /// the transaction's buffer until COMMIT).
    pub fn delete(
        &mut self,
        engine: &mut Engine,
        name: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<usize, String> {
        let filter = filter.map(|(c, v)| RowFilter::one(c, v));
        self.delete_filtered(engine, None, name, filter.as_ref())
    }

    /// Delete rows inside transaction `txn` (V0.6): the rows
    /// disappear for this transaction at once, and for everyone
    /// else only at COMMIT; on ROLLBACK nothing is deleted.
    pub fn delete_txn(
        &mut self,
        engine: &mut Engine,
        txn: u64,
        name: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<usize, String> {
        let filter = filter.map(|(c, v)| RowFilter::one(c, v));
        self.delete_filtered(engine, Some(txn), name, filter.as_ref())
    }

    /// Delete rows matching a multi-condition filter (V0.7).
    pub fn delete_filtered(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        filter: Option<&RowFilter>,
    ) -> Result<usize, String> {
        self.delete_inner(engine, txn, name, filter)
    }

    fn delete_inner(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        filter: Option<&RowFilter>,
    ) -> Result<usize, String> {
        let rows = match txn {
            Some(txn) => self.select_txn_filtered(engine, txn, name, filter)?,
            None => self.select_filtered(engine, name, filter)?,
        };
        match txn {
            Some(txn) => {
                let mut deleted = 0;
                for (row_id, _) in rows {
                    engine.txn_delete(txn, &row_key(name, row_id))?;
                    deleted += 1;
                }
                Ok(deleted)
            }
            // M6: one autocommit transaction for all rows.
            None => {
                let writes: Vec<(String, Option<String>)> = rows
                    .iter()
                    .map(|(row_id, _)| (row_key(name, *row_id), None))
                    .collect();
                let deleted = writes.len();
                engine
                    .autocommit_writes(&writes)
                    .map_err(|e| e.to_string())?;
                Ok(deleted)
            }
        }
    }

    /// UPDATE one column of every row matching the filter (V0.6):
    /// `UPDATE name SET set_col = set_val [WHERE col = value]`.
    /// Each matching row is rewritten as a new version (the old
    /// version gets `xmax` — see txn.rs). Returns how many rows
    /// were updated. The SET column must exist (42703-style
    /// error otherwise); a WHERE on an unknown column matches no
    /// rows, like SELECT. V0.6-fix (M6): autocommit UPDATE is
    /// atomic across rows — all rewrites go through ONE
    /// autocommit transaction (one txn id, one commit marker);
    /// inside a transaction it commits atomically with the rest
    /// of the transaction, as before.
    pub fn update(
        &mut self,
        engine: &mut Engine,
        name: &str,
        set_col: &str,
        set_val: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<usize, String> {
        let filter = filter.map(|(c, v)| RowFilter::one(c, v));
        self.update_many_filtered(
            engine,
            None,
            name,
            &[(set_col, Some(set_val))],
            filter.as_ref(),
        )
    }

    /// UPDATE inside transaction `txn` (V0.6).
    pub fn update_txn(
        &mut self,
        engine: &mut Engine,
        txn: u64,
        name: &str,
        set_col: &str,
        set_val: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<usize, String> {
        let filter = filter.map(|(c, v)| RowFilter::one(c, v));
        self.update_many_filtered(
            engine,
            Some(txn),
            name,
            &[(set_col, Some(set_val))],
            filter.as_ref(),
        )
    }

    /// UPDATE with several SET assignments and a multi-condition
    /// filter (V0.7): `UPDATE name SET a = 1, b = 2 WHERE ...`.
    /// Every SET column must exist (42703 otherwise). A SET value
    /// of `None` is a SQL NULL (V0.11): the column is stored as
    /// JSON `null`.
    pub fn update_many_filtered(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        sets: &[(&str, Option<&str>)],
        filter: Option<&RowFilter>,
    ) -> Result<usize, String> {
        self.update_inner(engine, txn, name, sets, filter)
    }

    fn update_inner(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        sets: &[(&str, Option<&str>)],
        filter: Option<&RowFilter>,
    ) -> Result<usize, String> {
        let columns = self
            .registry
            .tables
            .get(name)
            .ok_or_else(|| format!("no such table '{name}'"))?
            .columns
            .clone();
        for (set_col, _) in sets {
            if !columns.iter().any(|c| c == set_col) {
                return Err(format!(
                    "column '{set_col}' does not exist in table '{name}'"
                ));
            }
        }
        // M4 (V0.7 review): the same column twice in one SET
        // list used to be silently last-wins (`SET a = 1, a = 2`
        // stored 2). PostgreSQL rejects it — so does Zeno now
        // (42601 at the SQL layer), before any row is touched.
        {
            let mut seen = std::collections::BTreeSet::new();
            for (set_col, _) in sets {
                if !seen.insert(set_col) {
                    return Err(format!(
                        "column '{set_col}' is set twice in UPDATE of table '{name}'"
                    ));
                }
            }
        }
        let rows = match txn {
            Some(txn) => self.select_txn_filtered(engine, txn, name, filter)?,
            None => self.select_filtered(engine, name, filter)?,
        };
        // Rows come back as text-only maps (a stored NULL column
        // is absent); lift them to nullable cells so a SET NULL
        // can be recorded, then write them back as JSON nulls.
        let apply_sets = |row: BTreeMap<String, String>| {
            let mut cells: BTreeMap<String, Option<String>> =
                row.into_iter().map(|(k, v)| (k, Some(v))).collect();
            for (set_col, set_val) in sets {
                cells.insert(set_col.to_string(), set_val.map(|v| v.to_string()));
            }
            row_to_json(cells)
        };
        match txn {
            Some(txn) => {
                let mut updated = 0;
                for (row_id, row) in rows {
                    let value = apply_sets(row);
                    engine.txn_put(txn, &row_key(name, row_id), &value)?;
                    updated += 1;
                }
                Ok(updated)
            }
            // M6: one autocommit transaction for all rows.
            None => {
                let writes: Vec<(String, Option<String>)> = rows
                    .into_iter()
                    .map(|(row_id, row)| (row_key(name, row_id), Some(apply_sets(row))))
                    .collect();
                let updated = writes.len();
                engine
                    .autocommit_writes(&writes)
                    .map_err(|e| e.to_string())?;
                Ok(updated)
            }
        }
    }

    /// Scan all rows of a table. If `filter` is `Some((column, value))`,
    /// keep only rows where that column equals that value.
    /// V0.1: this is a linear scan, not an indexed query.
    pub fn select(
        &mut self,
        engine: &mut Engine,
        name: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<Vec<TableRow>, String> {
        let filter = filter.map(|(c, v)| RowFilter::one(c, v));
        self.select_filtered(engine, name, filter.as_ref())
    }

    /// Scan all rows of a table as transaction `txn` sees them
    /// (V0.6): its BEGIN snapshot plus its own writes.
    pub fn select_txn(
        &mut self,
        engine: &mut Engine,
        txn: u64,
        name: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<Vec<TableRow>, String> {
        let filter = filter.map(|(c, v)| RowFilter::one(c, v));
        self.select_txn_filtered(engine, txn, name, filter.as_ref())
    }

    /// Scan all rows matching a multi-condition filter (V0.7).
    pub fn select_filtered(
        &mut self,
        engine: &mut Engine,
        name: &str,
        filter: Option<&RowFilter>,
    ) -> Result<Vec<TableRow>, String> {
        self.select_inner(engine, None, name, filter)
    }

    /// Scan as transaction `txn` sees them, with a multi-condition
    /// filter (V0.7).
    pub fn select_txn_filtered(
        &mut self,
        engine: &mut Engine,
        txn: u64,
        name: &str,
        filter: Option<&RowFilter>,
    ) -> Result<Vec<TableRow>, String> {
        self.select_inner(engine, Some(txn), name, filter)
    }

    fn select_inner(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        filter: Option<&RowFilter>,
    ) -> Result<Vec<TableRow>, String> {
        if !self.registry.tables.contains_key(name) {
            return Err(format!("no such table '{name}'"));
        }
        let scanned = match txn {
            Some(txn) => engine.txn_scan_prefix(txn, &key_prefix(name))?,
            None => engine.scan_prefix(&key_prefix(name)),
        };
        let mut rows = Vec::new();
        for (key, value) in scanned {
            let Some(id_part) = key.strip_prefix(&key_prefix(name)) else {
                continue;
            };
            let Ok(row_id) = id_part.parse::<u64>() else {
                // A key under the table prefix that is not a row
                // id (e.g. a forged key from before the `table:`
                // prefix was reserved): warn and skip, do not
                // silently drop it (m6).
                self.skipped_rows += 1;
                eprintln!("warning: table '{name}': skipping key '{key}' — not a row id");
                continue;
            };
            let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&value) else {
                // Corrupt or non-object row value: warn and skip,
                // and count it (m6) — the old code skipped it in
                // silence, so a corrupt row just vanished.
                self.skipped_rows += 1;
                eprintln!(
                    "warning: table '{name}': skipping row {row_id} (key '{key}') — \
                     stored value is not a JSON object: {value:?}"
                );
                continue;
            };
            let mut row = BTreeMap::new();
            for (k, v) in obj {
                if let Value::String(s) = v {
                    row.insert(k, s);
                }
            }
            if let Some(filter) = filter {
                if !filter.matches(&row) {
                    continue;
                }
            }
            rows.push((row_id, row));
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        crate::unique_test_dir(&format!("zeno-table-test-{name}"))
    }

    #[test]
    fn compare_values_is_exact_for_integers_above_2_pow_53() {
        // B1: 2^53 and 2^53+1 parse to the SAME f64 — an f64
        // comparison would call them equal. Integer strings
        // must compare exactly.
        use std::cmp::Ordering::*;
        assert_eq!(compare_values("9007199254740992", "9007199254740993"), Less);
        assert_eq!(
            compare_values("9007199254740993", "9007199254740992"),
            Greater
        );
        assert_eq!(
            compare_values("9007199254740993", "9007199254740993"),
            Equal
        );
        // Beyond u64/i64 entirely (arbitrary precision).
        assert_eq!(
            compare_values(
                "340282366920938463463374607431768211456",
                "340282366920938463463374607431768211455"
            ),
            Greater
        );
        assert_eq!(compare_values("-5", "3"), Less);
        assert_eq!(compare_values("-0", "0"), Equal);
        assert_eq!(compare_values("007", "7"), Equal);
        assert_eq!(compare_values("10", "9"), Greater);
        // Decimals still compare numerically, and a decimal
        // against an integer too.
        assert_eq!(compare_values("1.5", "1.25"), Greater);
        assert_eq!(compare_values("1.0", "1"), Equal);
        assert_eq!(compare_values("1e3", "999"), Greater);
        // Non-numbers stay lexicographic.
        assert_eq!(compare_values("Delhi", "Mumbai"), Less);
        assert_eq!(compare_values("10", "Delhi"), Less);
    }

    #[test]
    fn create_table_rejects_duplicate_column_names() {
        // M2: CREATE TABLE t (id, id) must fail, not accept a
        // table whose INSERT silently eats one value.
        let dir = tmp_dir("dup-col");
        let mut tables = TableStore::open(&dir).unwrap();
        let err = tables
            .create_table("t", vec!["id".into(), "id".into()])
            .unwrap_err();
        assert!(err.contains("duplicate column"), "{err}");
        assert!(!tables.table_exists("t"), "rejected table must not exist");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_rejects_duplicate_set_column() {
        // M4: UPDATE t SET a = 1, a = 2 must fail, not store
        // the last value silently.
        let dir = tmp_dir("dup-set");
        let mut engine = Engine::open(&dir).unwrap();
        let mut tables = TableStore::open(&dir).unwrap();
        tables
            .create_table("t", vec!["a".into(), "b".into()])
            .unwrap();
        tables
            .insert(&mut engine, "t", vec![Some("1".into()), Some("x".into())])
            .unwrap();
        let err = tables
            .update_many_filtered(
                &mut engine,
                None,
                "t",
                &[("a", Some("1")), ("a", Some("2"))],
                None,
            )
            .unwrap_err();
        assert!(err.contains("set twice"), "{err}");
        let rows = tables.select(&mut engine, "t", None).unwrap();
        assert_eq!(
            rows[0].1.get("a").unwrap(),
            "1",
            "failed UPDATE must change nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_row_values_are_warned_and_counted_not_silently_dropped() {
        // m6: a corrupt / non-object row value used to vanish
        // from SELECT with no trace at all.
        let dir = tmp_dir("corrupt-row");
        let mut engine = Engine::open(&dir).unwrap();
        let mut tables = TableStore::open(&dir).unwrap();
        tables
            .create_table("t", vec!["id".into(), "city".into()])
            .unwrap();
        tables
            .insert(
                &mut engine,
                "t",
                vec![Some("1".into()), Some("Delhi".into())],
            )
            .unwrap();
        // Forge two bad rows straight into the engine (the
        // internal path — the public `put` now refuses `table:`
        // keys, m2): one not JSON at all, one valid JSON but not
        // an object.
        engine
            .put_internal("table:t:00000000000000000099", "not-json-at-all")
            .unwrap();
        engine
            .put_internal("table:t:00000000000000000100", "[1, 2, 3]")
            .unwrap();
        let rows = tables.select(&mut engine, "t", None).unwrap();
        assert_eq!(rows.len(), 1, "only the good row must come back");
        assert_eq!(rows[0].1.get("city").unwrap(), "Delhi");
        assert_eq!(
            tables.skipped_rows(),
            2,
            "both corrupt rows must be counted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

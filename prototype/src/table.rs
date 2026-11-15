// table.rs — a basic table on top of the key-value engine.
//
// A table is just a namespace of keys:
//   table:<name>:<row-id>  ->  {"col1": "value1", "col2": "value2", ...}
//
// There is NO real SQL parser in V0.1. "SELECT" here means: scan all rows
// of the table, optionally keeping only rows where one column equals one
// value. That is a simple scan filter, not SQL.
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

fn row_to_json(row: BTreeMap<String, String>) -> String {
    let obj: Map<String, Value> = row
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
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
    /// Returns the new row id.
    pub fn insert(
        &mut self,
        engine: &mut Engine,
        name: &str,
        values: Vec<String>,
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
        values: Vec<String>,
    ) -> Result<u64, String> {
        self.insert_inner(engine, Some(txn), name, values)
    }

    fn insert_inner(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        values: Vec<String>,
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
        let mut row = Map::new();
        for (col, val) in columns.iter().zip(values.iter()) {
            row.insert(col.clone(), Value::String(val.clone()));
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
        let value = serde_json::to_string(&Value::Object(row)).expect("row is valid JSON");
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
        self.delete_inner(engine, None, name, filter)
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
        self.delete_inner(engine, Some(txn), name, filter)
    }

    fn delete_inner(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<usize, String> {
        let rows = match txn {
            Some(txn) => self.select_txn(engine, txn, name, filter)?,
            None => self.select(engine, name, filter)?,
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
        self.update_inner(engine, None, name, set_col, set_val, filter)
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
        self.update_inner(engine, Some(txn), name, set_col, set_val, filter)
    }

    fn update_inner(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        set_col: &str,
        set_val: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<usize, String> {
        let columns = self
            .registry
            .tables
            .get(name)
            .ok_or_else(|| format!("no such table '{name}'"))?
            .columns
            .clone();
        if !columns.iter().any(|c| c == set_col) {
            return Err(format!(
                "column '{set_col}' does not exist in table '{name}'"
            ));
        }
        let rows = match txn {
            Some(txn) => self.select_txn(engine, txn, name, filter)?,
            None => self.select(engine, name, filter)?,
        };
        match txn {
            Some(txn) => {
                let mut updated = 0;
                for (row_id, mut row) in rows {
                    row.insert(set_col.to_string(), set_val.to_string());
                    let value = row_to_json(row);
                    engine.txn_put(txn, &row_key(name, row_id), &value)?;
                    updated += 1;
                }
                Ok(updated)
            }
            // M6: one autocommit transaction for all rows.
            None => {
                let writes: Vec<(String, Option<String>)> = rows
                    .into_iter()
                    .map(|(row_id, mut row)| {
                        row.insert(set_col.to_string(), set_val.to_string());
                        (row_key(name, row_id), Some(row_to_json(row)))
                    })
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
        self.select_inner(engine, None, name, filter)
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
        self.select_inner(engine, Some(txn), name, filter)
    }

    fn select_inner(
        &mut self,
        engine: &mut Engine,
        txn: Option<u64>,
        name: &str,
        filter: Option<(&str, &str)>,
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
            if let Some((col, want)) = filter {
                if row.get(col).map(String::as_str) != Some(want) {
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
        let mut p = std::env::temp_dir();
        p.push(format!("zeno-table-test-{name}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
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
            .insert(&mut engine, "t", vec!["1".into(), "Delhi".into()])
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

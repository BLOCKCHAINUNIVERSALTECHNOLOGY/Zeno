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

#[derive(Debug)]
pub struct TableStore {
    registry_path: PathBuf,
    registry: TableRegistry,
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
        })
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
        engine.put(&key, &value).map_err(|e| e.to_string())?;
        Ok(row_id)
    }

    /// Delete rows of a table, optionally keeping only rows where one
    /// column equals one value. Returns how many rows were deleted.
    /// Each row key is tombstoned through the engine, so the row
    /// disappears from reads immediately and is physically removed by
    /// compaction — the same delete path as the KV `del` command.
    ///
    /// m8 note: this delete is NOT atomic across rows — it tombstones
    /// one row key at a time, so a crash mid-delete leaves some rows
    /// deleted and some still there. That is safe in V0.3 only
    /// because every caller holds the single server Mutex (or the
    /// one-shot CLI process) for the whole call, so no other thread
    /// can observe a half-deleted table; a future multi-threaded
    /// delete must make this one WAL transaction first.
    pub fn delete(
        &mut self,
        engine: &mut Engine,
        name: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<usize, String> {
        let rows = self.select(engine, name, filter)?;
        let mut deleted = 0;
        for (row_id, _) in rows {
            engine
                .delete(&row_key(name, row_id))
                .map_err(|e| e.to_string())?;
            deleted += 1;
        }
        Ok(deleted)
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
        if !self.registry.tables.contains_key(name) {
            return Err(format!("no such table '{name}'"));
        }
        let mut rows = Vec::new();
        for (key, value) in engine.scan_prefix(&key_prefix(name)) {
            let Some(id_part) = key.strip_prefix(&key_prefix(name)) else {
                continue;
            };
            let Ok(row_id) = id_part.parse::<u64>() else {
                continue;
            };
            let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&value) else {
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

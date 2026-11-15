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

pub struct TableStore {
    registry_path: PathBuf,
    registry: TableRegistry,
}

impl TableStore {
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        let registry_path = dir.join("tables.json");
        let registry = match fs::read_to_string(&registry_path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => TableRegistry::default(), // first run: no tables yet
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

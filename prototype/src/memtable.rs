// memtable.rs — the in-memory write buffer.
//
// A BTreeMap keeps keys sorted, so flushing to disk produces a sorted
// SSTable for free. Values are `Option<String>`: `None` is a tombstone,
// i.e. a delete marker. A tombstone hides older values of the same key
// until compaction physically removes both.

use std::collections::BTreeMap;

/// How many entries the memtable holds before it is flushed to disk.
/// Small on purpose in V0.1 so flushing is easy to demonstrate.
pub const FLUSH_THRESHOLD: usize = 64;

#[derive(Debug, Default)]
pub struct MemTable {
    map: BTreeMap<String, Option<String>>,
}

impl MemTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, key: &str, value: &str) {
        self.map.insert(key.to_string(), Some(value.to_string()));
    }

    pub fn delete(&mut self, key: &str) {
        self.map.insert(key.to_string(), None);
    }

    /// Look up a key. Returns:
    /// - `Some(Some(value))` — key present with this value
    /// - `Some(None)` — key was deleted (tombstone); do NOT look further
    /// - `None` — key not in the memtable; older SSTables may have it
    pub fn get(&self, key: &str) -> Option<Option<String>> {
        self.map.get(key).cloned()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.map.len() >= FLUSH_THRESHOLD
    }

    /// All entries in sorted key order (for flushing to an SSTable).
    pub fn entries(&self) -> Vec<(String, Option<String>)> {
        self.map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// All entries whose key starts with `prefix`, in sorted order.
    /// Used by table/document scans. (V0.1 scans the whole memtable;
    /// this is fine at prototype scale.)
    pub fn scan_prefix(&self, prefix: &str) -> Vec<(String, Option<String>)> {
        self.map
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_delete() {
        let mut m = MemTable::new();
        m.put("a", "1");
        assert_eq!(m.get("a"), Some(Some("1".to_string())));
        m.delete("a");
        assert_eq!(m.get("a"), Some(None)); // tombstone, not "missing"
        assert_eq!(m.get("zzz"), None);
    }

    #[test]
    fn entries_are_sorted() {
        let mut m = MemTable::new();
        m.put("c", "3");
        m.put("a", "1");
        m.put("b", "2");
        let keys: Vec<String> = m.entries().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }
}

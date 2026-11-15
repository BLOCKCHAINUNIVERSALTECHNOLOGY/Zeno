// doc.rs — basic JSON documents on top of the key-value engine.
//
// A document lives under:
//   doc:<collection>:<id>  ->  <raw JSON text>
//
// `find` scans every document in one collection and keeps those where a
// single field equals a given value. V0.1 does this as a LINEAR scan —
// there is no GIN / secondary index yet. That is slow on big collections
// and is stated honestly here and in the README.

use crate::engine::Engine;
use serde_json::Value;

fn key_prefix(collection: &str) -> String {
    format!("doc:{collection}:")
}

fn doc_key(collection: &str, id: &str) -> String {
    format!("doc:{collection}:{id}")
}

pub struct DocStore;

impl DocStore {
    /// Store a JSON document. The text must parse as JSON; anything else
    /// is rejected so the store never holds broken documents.
    pub fn put(engine: &mut Engine, collection: &str, id: &str, json: &str) -> Result<(), String> {
        let parsed: Value =
            serde_json::from_str(json).map_err(|e| format!("not valid JSON: {e}"))?;
        if !parsed.is_object() {
            return Err("a document must be a JSON object".to_string());
        }
        engine
            .put(&doc_key(collection, id), json)
            .map_err(|e| e.to_string())
    }

    /// Fetch one document as raw JSON text.
    pub fn get(engine: &mut Engine, collection: &str, id: &str) -> Option<String> {
        engine.get(&doc_key(collection, id))
    }

    /// Find all documents in `collection` where field `field` equals
    /// `value` (string comparison against the JSON value rendered as a
    /// string). Linear scan — no index in V0.1.
    pub fn find(
        engine: &mut Engine,
        collection: &str,
        field: &str,
        value: &str,
    ) -> Vec<(String, String)> {
        let prefix = key_prefix(collection);
        let mut out = Vec::new();
        for (key, doc_json) in engine.scan_prefix(&prefix) {
            let Some(id) = key.strip_prefix(&prefix) else {
                continue;
            };
            let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&doc_json) else {
                continue;
            };
            let matches = match obj.get(field) {
                Some(Value::String(s)) => s == value,
                Some(other) => other.to_string().trim_matches('"') == value,
                None => false,
            };
            if matches {
                out.push((id.to_string(), doc_json));
            }
        }
        out
    }
}

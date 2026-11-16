// doc.rs — basic JSON documents on top of the key-value engine.
//
// A document lives under:
//   doc:<collection>:<id>  ->  <raw JSON text>
//
// `find` scans every document in one collection and keeps those where a
// single field equals a given value. V0.1 does this as a LINEAR scan —
// there is no GIN / secondary index yet. That is slow on big collections
// and is stated honestly here and in the README.
//
// V0.11 key encoding (review finding 9): the collection and id are
// percent-escaped before they are joined with `:`, so the key is
// unambiguous — `%` becomes `%25` and `:` becomes `%3A`, and the
// escape is applied to BOTH parts in `put`, `get` and `find` alike.
// Before V0.11 the parts were joined raw, so (`a:b`, `c`) and (`a`,
// `b:c`) both produced the key `doc:a:b:c` and one collection's
// document could overwrite / show up in another's. The escape keeps
// every OLD key readable: a collection/id with no `%` or `:` in it
// encodes exactly as before (`doc:profiles:u1`), so documents
// written by V0.10 open unchanged. Only keys that contain `%` or
// `:` change — and those were ambiguous (broken) before, so no
// well-defined old document is lost; a V0.10 document whose
// collection or id contained a `:` is simply not found under the
// new encoding, which the README states plainly.

use crate::engine::Engine;
use serde_json::Value;

/// Escape one key component (`:` and `%` only — everything else,
/// including `/`, spaces and Unicode, passes through unchanged, so
/// old keys without those two characters encode byte-identically).
fn escape_component(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    for ch in part.chars() {
        match ch {
            '%' => out.push_str("%25"),
            ':' => out.push_str("%3A"),
            _ => out.push(ch),
        }
    }
    out
}

/// Undo `escape_component`. A `%` not followed by `25` or `3A` is
/// left as-is (a hand-written key, never one this module wrote).
fn unescape_component(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    let mut rest = part;
    while let Some(pos) = rest.find('%') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(code) = after.get(..2) {
            match code {
                "25" => {
                    out.push('%');
                    rest = &after[2..];
                    continue;
                }
                "3A" => {
                    out.push(':');
                    rest = &after[2..];
                    continue;
                }
                _ => {}
            }
        }
        out.push('%');
        rest = after;
    }
    out.push_str(rest);
    out
}

fn key_prefix(collection: &str) -> String {
    format!("doc:{}:", escape_component(collection))
}

fn doc_key(collection: &str, id: &str) -> String {
    format!(
        "doc:{}:{}",
        escape_component(collection),
        escape_component(id)
    )
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
            .put_internal(&doc_key(collection, id), json)
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
            let Some(escaped_id) = key.strip_prefix(&prefix) else {
                continue;
            };
            // The id stored in the key is escaped; hand back the
            // real id the caller stored.
            let id = unescape_component(escaped_id);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// V0.11 (review finding 9): (`a:b`, `c`) and (`a`, `b:c`)
    /// used to collide on the single key `doc:a:b:c`, so one
    /// document overwrote / showed up in the other collection.
    /// With escaping they are distinct keys, and `find` is
    /// isolated per collection too.
    #[test]
    fn separator_collision_is_isolated() {
        let dir = crate::unique_test_dir("zeno-doc-collision-test");
        let mut engine = Engine::open(&dir).unwrap();
        DocStore::put(&mut engine, "a:b", "c", r#"{"x":"first"}"#).unwrap();
        DocStore::put(&mut engine, "a", "b:c", r#"{"x":"second"}"#).unwrap();
        assert_eq!(
            DocStore::get(&mut engine, "a:b", "c").as_deref(),
            Some(r#"{"x":"first"}"#)
        );
        assert_eq!(
            DocStore::get(&mut engine, "a", "b:c").as_deref(),
            Some(r#"{"x":"second"}"#)
        );
        assert_eq!(DocStore::find(&mut engine, "a:b", "x", "first").len(), 1);
        assert_eq!(DocStore::find(&mut engine, "a:b", "x", "second").len(), 0);
        assert_eq!(DocStore::find(&mut engine, "a", "x", "second").len(), 1);
        assert_eq!(DocStore::find(&mut engine, "a", "x", "first").len(), 0);
        // `find` hands back the real id, not the escaped form.
        let hits = DocStore::find(&mut engine, "a", "x", "second");
        assert_eq!(hits[0].0, "b:c");
        // A `%` in a name escapes too, and does not collide with
        // an already-escaped-looking name.
        DocStore::put(&mut engine, "p%q", "1", r#"{"x":"pct"}"#).unwrap();
        DocStore::put(&mut engine, "p", "%q1", r#"{"x":"other"}"#).unwrap();
        assert_eq!(
            DocStore::get(&mut engine, "p%q", "1").as_deref(),
            Some(r#"{"x":"pct"}"#)
        );
        assert_eq!(
            DocStore::get(&mut engine, "p", "%q1").as_deref(),
            Some(r#"{"x":"other"}"#)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// V0.11 (review finding 9): a document written by V0.10
    /// under the raw key `doc:profiles:u1` (no `%` or `:` in the
    /// parts) encodes byte-identically under the new scheme, so
    /// it still reads — no migration is needed for such keys.
    #[test]
    fn legacy_keys_without_separator_still_read() {
        let dir = crate::unique_test_dir("zeno-doc-legacy-test");
        let mut engine = Engine::open(&dir).unwrap();
        engine
            .put_internal("doc:profiles:u1", r#"{"name":"Sanjay"}"#)
            .unwrap();
        assert_eq!(
            DocStore::get(&mut engine, "profiles", "u1").as_deref(),
            Some(r#"{"name":"Sanjay"}"#)
        );
        assert_eq!(
            DocStore::find(&mut engine, "profiles", "name", "Sanjay").len(),
            1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

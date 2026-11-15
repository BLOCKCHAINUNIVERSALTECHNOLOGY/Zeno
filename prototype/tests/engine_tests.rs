// Integration tests for the Zeno V0.1 engine.
//
// Each test uses its own temp directory so tests never touch each
// other's data and never touch the user's real data directory.

use std::path::PathBuf;
use zeno::doc::DocStore;
use zeno::engine::Engine;
use zeno::table::TableStore;

fn tmp_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("zeno-engine-test-{name}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn cleanup(p: &PathBuf) {
    let _ = std::fs::remove_dir_all(p);
}

#[test]
fn kv_put_get_delete() {
    let dir = tmp_dir("kv");
    let mut e = Engine::open(&dir).unwrap();
    e.put("hello", "world").unwrap();
    assert_eq!(e.get("hello"), Some("world".to_string()));
    assert_eq!(e.get("missing"), None);
    e.put("hello", "again").unwrap();
    assert_eq!(e.get("hello"), Some("again".to_string()));
    e.delete("hello").unwrap();
    assert_eq!(e.get("hello"), None);
    cleanup(&dir);
}

#[test]
fn wal_replay_after_reopen() {
    let dir = tmp_dir("wal");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("crash-key", "crash-value").unwrap();
        e.put("other", "kept").unwrap();
        // No explicit flush, no clean shutdown — drop the engine
        // exactly like a crash would.
    }
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.get("crash-key"), Some("crash-value".to_string()));
    assert_eq!(e2.get("other"), Some("kept".to_string()));
    cleanup(&dir);
}

#[test]
fn memtable_flush_to_sstable_and_read_after_flush() {
    let dir = tmp_dir("flush");
    let mut e = Engine::open(&dir).unwrap();
    // 64 entries = the flush threshold; write more to force a flush.
    for i in 0..70 {
        e.put(&format!("k{i:03}"), &format!("v{i}")).unwrap();
    }
    assert!(
        e.sstable_count() >= 1,
        "expected at least one SSTable after 70 puts"
    );
    // Everything still readable after the flush (some from SSTable,
    // some still in the memtable).
    for i in 0..70 {
        assert_eq!(e.get(&format!("k{i:03}")), Some(format!("v{i}")));
    }
    // And readable again after a full reopen.
    drop(e);
    let mut e2 = Engine::open(&dir).unwrap();
    for i in 0..70 {
        assert_eq!(e2.get(&format!("k{i:03}")), Some(format!("v{i}")));
    }
    cleanup(&dir);
}

#[test]
fn compaction_removes_duplicates_and_tombstones() {
    let dir = tmp_dir("compact");
    let mut e = Engine::open(&dir).unwrap();
    // Write the same key twice across two flushes, then delete another.
    e.put("dup", "old").unwrap();
    e.flush().unwrap();
    e.put("dup", "new").unwrap();
    e.put("gone", "x").unwrap();
    e.flush().unwrap();
    e.delete("gone").unwrap();
    e.flush().unwrap();
    assert!(e.sstable_count() >= 3);
    assert_eq!(e.get("dup"), Some("new".to_string()));
    assert_eq!(e.get("gone"), None);

    e.compact().unwrap();
    assert_eq!(e.sstable_count(), 1);
    assert_eq!(e.get("dup"), Some("new".to_string()));
    assert_eq!(e.get("gone"), None);

    // The tombstone is physically gone: the raw merged SSTable must not
    // contain "gone" at all.
    let raw = e.scan_prefix_raw("gone");
    assert!(raw.is_empty(), "tombstone survived compaction: {raw:?}");

    // Reopen: "dup" still new, "gone" still absent.
    drop(e);
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.get("dup"), Some("new".to_string()));
    assert_eq!(e2.get("gone"), None);
    cleanup(&dir);
}

#[test]
fn table_insert_and_select() {
    let dir = tmp_dir("table");
    let mut e = Engine::open(&dir).unwrap();
    let mut tables = TableStore::open(&dir).unwrap();
    tables
        .create_table("users", vec!["id".into(), "name".into(), "city".into()])
        .unwrap();
    tables
        .insert(
            &mut e,
            "users",
            vec!["1".into(), "Sanjay".into(), "Delhi".into()],
        )
        .unwrap();
    tables
        .insert(
            &mut e,
            "users",
            vec!["2".into(), "Asha".into(), "Mumbai".into()],
        )
        .unwrap();
    tables
        .insert(
            &mut e,
            "users",
            vec!["3".into(), "Ravi".into(), "Delhi".into()],
        )
        .unwrap();

    let all = tables.select(&mut e, "users", None).unwrap();
    assert_eq!(all.len(), 3);

    let delhi = tables
        .select(&mut e, "users", Some(("city", "Delhi")))
        .unwrap();
    assert_eq!(delhi.len(), 2);
    let names: Vec<&str> = delhi
        .iter()
        .map(|(_, r)| r.get("name").unwrap().as_str())
        .collect();
    assert!(names.contains(&"Sanjay"));
    assert!(names.contains(&"Ravi"));

    // Tables survive a reopen.
    drop(e);
    let mut e2 = Engine::open(&dir).unwrap();
    let mut tables2 = TableStore::open(&dir).unwrap();
    let all2 = tables2.select(&mut e2, "users", None).unwrap();
    assert_eq!(all2.len(), 3);
    cleanup(&dir);
}

#[test]
fn doc_put_get_find() {
    let dir = tmp_dir("doc");
    let mut e = Engine::open(&dir).unwrap();
    DocStore::put(
        &mut e,
        "profiles",
        "u1",
        r#"{"name":"Sanjay","city":"Delhi"}"#,
    )
    .unwrap();
    DocStore::put(
        &mut e,
        "profiles",
        "u2",
        r#"{"name":"Asha","city":"Mumbai"}"#,
    )
    .unwrap();
    DocStore::put(
        &mut e,
        "profiles",
        "u3",
        r#"{"name":"Ravi","city":"Delhi"}"#,
    )
    .unwrap();

    assert_eq!(
        DocStore::get(&mut e, "profiles", "u1"),
        Some(r#"{"name":"Sanjay","city":"Delhi"}"#.to_string())
    );
    assert_eq!(DocStore::get(&mut e, "profiles", "nope"), None);

    let delhi = DocStore::find(&mut e, "profiles", "city", "Delhi");
    assert_eq!(delhi.len(), 2);
    let ids: Vec<&str> = delhi.iter().map(|(id, _)| id.as_str()).collect();
    assert!(ids.contains(&"u1"));
    assert!(ids.contains(&"u3"));

    // Invalid JSON is rejected.
    assert!(DocStore::put(&mut e, "profiles", "bad", "{not json").is_err());
    cleanup(&dir);
}

#[test]
fn delete_survives_flush_and_reopen() {
    let dir = tmp_dir("del-flush");
    let mut e = Engine::open(&dir).unwrap();
    e.put("a", "1").unwrap();
    e.flush().unwrap();
    e.delete("a").unwrap();
    drop(e);
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.get("a"), None);
    cleanup(&dir);
}

#[test]
fn truncated_sstable_is_quarantined_and_wal_key_recovers() {
    let dir = tmp_dir("trunc-sst");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("flushed-key", "flushed-value").unwrap();
        e.flush().unwrap(); // now in an SSTable
        e.put("wal-key", "wal-value").unwrap(); // WAL only, never flushed
                                                // No clean shutdown beyond drop — exactly like a crash.
    }
    // Simulate the reviewer's crash mid-flush: truncate the SSTable
    // to garbage, and leave a stray half-written *.tmp file behind.
    let sst_path = dir.join("sst-000001.sst");
    assert!(sst_path.exists(), "expected a flushed SSTable");
    std::fs::write(&sst_path, b"ZENO-SSTABLE-1\n{\"torn").unwrap();
    std::fs::write(dir.join("sst-000002.sst.tmp"), b"half-written").unwrap();

    // Open must succeed (not fail the whole DB), the WAL key must
    // come back, and the corrupt file must be quarantined, not deleted.
    let mut e2 = Engine::open(&dir).expect("engine must open despite corrupt SSTable");
    assert_eq!(e2.get("wal-key"), Some("wal-value".to_string()));
    assert_eq!(e2.get("flushed-key"), None, "corrupt SSTable data is gone");
    assert!(
        dir.join("sst-000001.sst.corrupt").exists(),
        "corrupt SSTable should be quarantined as .corrupt"
    );
    assert!(
        !dir.join("sst-000002.sst.tmp").exists(),
        "leftover .tmp file should be removed on open"
    );
    // The recovered engine is still usable.
    e2.put("after", "works").unwrap();
    assert_eq!(e2.get("after"), Some("works".to_string()));
    cleanup(&dir);
}

#[test]
fn delete_of_key_in_older_sstable_survives_reopen_and_compaction() {
    let dir = tmp_dir("del-older");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("old-key", "old-value").unwrap();
        e.flush().unwrap(); // key lives only in an older SSTable now
        e.delete("old-key").unwrap();
        e.put("keeper", "yes").unwrap();
        // Drop without flushing the tombstone: it is in the WAL.
    }
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.get("old-key"), None, "delete must survive reopen");
    assert_eq!(e2.get("keeper"), Some("yes".to_string()));
    e2.compact().unwrap();
    assert_eq!(e2.get("old-key"), None, "delete must survive compaction");
    assert_eq!(e2.get("keeper"), Some("yes".to_string()));
    assert!(
        e2.scan_prefix_raw("old-key").is_empty(),
        "tombstone must be physically gone after compaction"
    );
    drop(e2);
    let mut e3 = Engine::open(&dir).unwrap();
    assert_eq!(
        e3.get("old-key"),
        None,
        "delete must survive reopen after compaction"
    );
    assert_eq!(e3.get("keeper"), Some("yes".to_string()));
    cleanup(&dir);
}

#[test]
fn single_sstable_compaction_drops_tombstone() {
    let dir = tmp_dir("compact-one");
    let mut e = Engine::open(&dir).unwrap();
    // A lone SSTable containing only a tombstone.
    e.put("gone", "x").unwrap();
    e.delete("gone").unwrap();
    e.flush().unwrap();
    assert_eq!(e.sstable_count(), 1);
    let before = e.stats().compactions;
    e.compact().unwrap();
    assert_eq!(
        e.stats().compactions,
        before + 1,
        "compaction must be counted"
    );
    assert_eq!(e.sstable_count(), 1);
    assert_eq!(e.get("gone"), None);
    assert!(
        e.scan_prefix_raw("gone").is_empty(),
        "tombstone in a lone SSTable must be physically removed"
    );
    drop(e);
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.get("gone"), None);
    cleanup(&dir);
}

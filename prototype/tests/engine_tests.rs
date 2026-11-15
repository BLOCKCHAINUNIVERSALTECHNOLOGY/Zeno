// Integration tests for the Zeno V0.3 engine.
//
// Each test uses its own temp directory so tests never touch each
// other's data and never touch the user's real data directory.

use std::path::PathBuf;
use zeno::bloom::BloomFilter;
use zeno::doc::DocStore;
use zeno::engine::Engine;
use zeno::sstable::{sstable_path, SsTable};
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
        dir.join("sst-000001.sst.corrupt.1").exists(),
        "corrupt SSTable should be quarantined as .corrupt.1"
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

// ======================= V0.2 tests =======================

#[test]
fn lock_second_open_fails_while_first_open() {
    let dir = tmp_dir("lock-held");
    let mut e1 = Engine::open(&dir).unwrap();
    e1.put("k", "v").unwrap();
    // A second engine on the same directory must fail cleanly while
    // the first is alive — and must say the directory is in use.
    let err = match Engine::open(&dir) {
        Ok(_) => panic!("second open must fail while first is open"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("already in use"),
        "error must say the directory is in use: {err}"
    );
    // The first engine is unaffected and the data is intact.
    assert_eq!(e1.get("k"), Some("v".to_string()));
    drop(e1);
    // After the first closes, the same directory opens again.
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.get("k"), Some("v".to_string()));
    cleanup(&dir);
}

#[test]
fn lock_stale_after_kill_nine_reopens() {
    let dir = tmp_dir("lock-kill");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("before-kill", "survives").unwrap();
    }
    // A real holder process: `zeno hold 30` opens the engine (taking
    // the lock) and sleeps. Kill it with SIGKILL, exactly like a crash.
    let zeno_bin = env!("CARGO_BIN_EXE_zeno");
    let mut child = std::process::Command::new(zeno_bin)
        .args(["--data", dir.to_str().unwrap(), "hold", "30"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn zeno hold");
    // Wait until the holder has actually taken the lock (max 5s).
    let lock_path = dir.join("LOCK");
    let mut took = false;
    for _ in 0..50 {
        if lock_path.exists() {
            took = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(took, "holder process never took the lock");
    // While the holder lives, a second open must fail.
    assert!(
        Engine::open(&dir).is_err(),
        "second open must fail while holder is alive"
    );
    child.kill().expect("kill holder (SIGKILL)");
    let _ = child.wait();
    // After the kill, the stale lock (dead PID) must not block reopen.
    let mut e2 = Engine::open(&dir).expect("engine must reopen after kill -9 of holder");
    assert_eq!(e2.get("before-kill"), Some("survives".to_string()));
    e2.put("after-kill", "works").unwrap();
    assert_eq!(e2.get("after-kill"), Some("works".to_string()));
    cleanup(&dir);
}

#[test]
fn lock_concurrent_holders_exactly_one_winner() {
    // Regression test for the V0.2 LOCK race (BLOCKER 1): the winner
    // used to create an empty LOCK file and only then write its PID,
    // and a contender that read the empty file deleted it as "torn"
    // and won too — two engines, both writing sst-000001.sst, data
    // loss. Sequential tests never saw it; only N processes racing
    // at once do. 12 holders x 5 rounds: each round exactly 1 winner.
    // `hold 2` gives every contender a 2 s window to attempt while the
    // winner is alive (spawning 12 processes takes far less than 2 s),
    // so a second winner can only mean the race is back — never a
    // slow spawn. 5 rounds x 2 s = ~10 s; slow, but this is the test
    // that proves the lock actually works.
    let zeno_bin = env!("CARGO_BIN_EXE_zeno");
    for round in 0..5 {
        let dir = tmp_dir(&format!("lock-race-{round}"));
        let mut children = Vec::new();
        for _ in 0..12 {
            let child = std::process::Command::new(zeno_bin)
                .args(["--data", dir.to_str().unwrap(), "hold", "2"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn zeno hold");
            children.push(child);
        }
        let mut winners = 0;
        for mut child in children {
            let status = child.wait().expect("wait for holder process");
            if status.success() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "round {round}: exactly 1 of 12 concurrent holders must win, got {winners}"
        );
        // The directory must be cleanly usable afterwards.
        let mut e = Engine::open(&dir).unwrap();
        e.put("after-race", "ok").unwrap();
        assert_eq!(e.get("after-race"), Some("ok".to_string()));
        drop(e);
        cleanup(&dir);
    }
}

#[test]
fn corrupt_tables_json_fails_open_and_quarantines() {
    // Regression test for BLOCKER 2: a corrupt tables.json used to be
    // silently reset to an empty registry, so recreating the table
    // restarted next_row_id at 1 and overwrote the old row 1.
    let dir = tmp_dir("tables-corrupt");
    {
        let mut e = Engine::open(&dir).unwrap();
        let mut tables = TableStore::open(&dir).unwrap();
        tables
            .create_table("users", vec!["id".into(), "name".into()])
            .unwrap();
        tables
            .insert(&mut e, "users", vec!["1".into(), "Sanjay".into()])
            .unwrap();
        e.flush().unwrap();
    }
    // Simulate a torn/corrupt registry file.
    std::fs::write(dir.join("tables.json"), "{\"tables\": {\"users\": {\"col").unwrap();

    // Reopen must FAIL at the table registry — not silently reset.
    let mut e2 = Engine::open(&dir).unwrap();
    // The old row is still in the KV engine, untouched.
    let old_row = e2
        .get("table:users:00000000000000000001")
        .expect("old row 1 must still be in the engine");
    assert!(
        old_row.contains("Sanjay"),
        "old row 1 must still be Sanjay's row: {old_row}"
    );
    let err = TableStore::open(&dir).expect_err("corrupt tables.json must fail open");
    assert!(
        err.to_string().contains("corrupt tables.json"),
        "error must say tables.json is corrupt: {err}"
    );
    assert!(
        dir.join("tables.json.corrupt.1").exists(),
        "corrupt tables.json must be quarantined as tables.json.corrupt.1"
    );
    assert!(
        !dir.join("tables.json").exists(),
        "corrupt file must be moved to quarantine, not left in place"
    );
    drop(e2);

    // A second open must ALSO fail while the quarantine is present:
    // retrying the command must not silently become an empty registry
    // and let a recreate overwrite row 1.
    let mut e3 = Engine::open(&dir).unwrap();
    let err2 =
        TableStore::open(&dir).expect_err("second open must still fail while quarantine exists");
    assert!(
        err2.to_string().contains("tables.json.corrupt"),
        "second-open error must point at the quarantine: {err2}"
    );
    let still_there = e3
        .get("table:users:00000000000000000001")
        .expect("old row 1 must survive the failed reopens");
    assert!(
        still_there.contains("Sanjay"),
        "old row 1 must still be Sanjay's row after failed reopens: {still_there}"
    );
    drop(e3);
    cleanup(&dir);
}

#[test]
fn wal_corrupt_lines_cumulative_across_flush_and_reopen() {
    // M2: the corrupt-line count used to be open-time only — a flush
    // cleared the WAL and the history with it. M3: the warning now
    // also names the exact corrupt line number(s).
    let dir = tmp_dir("wal-cumulative");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("good-1", "v1").unwrap();
    }
    // Corrupt line 2, then a valid record on line 3.
    use std::io::Write as _;
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("wal.log"))
            .unwrap();
        writeln!(f, "garbage-not-json").unwrap();
        writeln!(
            f,
            "{}",
            serde_json::to_string(&zeno::wal::WalRecord::put("good-2", "v2")).unwrap()
        )
        .unwrap();
    }
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.get("good-1"), Some("v1".to_string()));
    assert_eq!(e2.get("good-2"), Some("v2".to_string()));
    assert_eq!(e2.stats().wal_corrupt_lines, 1);
    assert_eq!(e2.stats().wal_corrupt_line_numbers, vec![2]);
    drop(e2);

    // Reopening the SAME WAL again must NOT count the same corrupt
    // line a second time — the lifetime total stays 1.
    let e2b = Engine::open(&dir).unwrap();
    assert_eq!(
        e2b.stats().wal_corrupt_lines,
        1,
        "replaying the same WAL must not double-count its corrupt lines"
    );
    assert_eq!(e2b.stats().wal_corrupt_line_numbers, vec![2]);
    drop(e2b);

    // Now flush (clears the WAL file) and reopen.
    let mut e2c = Engine::open(&dir).unwrap();
    e2c.flush().unwrap(); // clears the WAL file
    drop(e2c);

    // After flush + reopen the count must still be 1 (cumulative,
    // persisted in meta.json), while this open's line list is empty
    // because the new WAL file is clean.
    let mut e3 = Engine::open(&dir).unwrap();
    assert_eq!(
        e3.stats().wal_corrupt_lines,
        1,
        "cumulative corrupt-line count must survive flush + reopen"
    );
    assert!(
        e3.stats().wal_corrupt_line_numbers.is_empty(),
        "new WAL file is clean, no corrupt lines this open: {:?}",
        e3.stats().wal_corrupt_line_numbers
    );
    assert_eq!(e3.get("good-1"), Some("v1".to_string()));
    assert_eq!(e3.get("good-2"), Some("v2".to_string()));
    cleanup(&dir);
}

#[test]
fn wal_corrupt_middle_line_is_counted_and_data_safe() {
    let dir = tmp_dir("wal-corrupt");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("good-1", "v1").unwrap();
        e.put("good-2", "v2").unwrap();
    }
    // Append a corrupt line in the MIDDLE, then a valid record after it.
    use std::io::Write as _;
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("wal.log"))
            .unwrap();
        writeln!(f, "garbage-not-json").unwrap();
        writeln!(
            f,
            "{}",
            serde_json::to_string(&zeno::wal::WalRecord::put("good-3", "v3")).unwrap()
        )
        .unwrap();
    }
    let mut e2 = Engine::open(&dir).unwrap();
    // Data is safe: the records before AND after the corrupt line replay.
    assert_eq!(e2.get("good-1"), Some("v1".to_string()));
    assert_eq!(e2.get("good-2"), Some("v2".to_string()));
    assert_eq!(e2.get("good-3"), Some("v3".to_string()));
    // And the corruption is reported, not hidden.
    assert!(
        e2.stats().wal_corrupt_lines >= 1,
        "stats must report the corrupt WAL line"
    );
    assert_eq!(
        e2.stats().wal_corrupt_line_numbers,
        vec![3],
        "the corrupt line was line 3 of wal.log"
    );
    cleanup(&dir);
}

#[test]
fn corrupt_meta_json_opens_and_data_safe() {
    let dir = tmp_dir("meta-corrupt");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("meta-key", "meta-value").unwrap();
        e.flush().unwrap(); // data also in an SSTable, not just the WAL
    }
    // Simulate a crash mid-save: a half-written meta.json.
    std::fs::write(dir.join("meta.json"), "{\"puts\": 12, \"gets\": 3, \"fl").unwrap();
    let mut e2 = Engine::open(&dir).expect("engine must open despite corrupt meta.json");
    assert_eq!(e2.get("meta-key"), Some("meta-value".to_string()));
    assert!(
        dir.join("meta.json.corrupt.1").exists(),
        "corrupt meta.json should be quarantined as .corrupt.1"
    );
    // The recovered engine is still usable, and a later reopen works
    // (meta.json was rewritten atomically on drop).
    e2.put("after-meta", "works").unwrap();
    drop(e2);
    let mut e3 = Engine::open(&dir).unwrap();
    assert_eq!(e3.get("meta-key"), Some("meta-value".to_string()));
    assert_eq!(e3.get("after-meta"), Some("works".to_string()));
    cleanup(&dir);
}

#[test]
fn bloom_scales_on_large_sstable() {
    let dir = tmp_dir("bloom-large");
    // 600 keys through the real engine: many flushes, many SSTables.
    let mut e = Engine::open(&dir).unwrap();
    for i in 0..600 {
        e.put(&format!("big-key-{i:04}"), &format!("v{i}")).unwrap();
    }
    e.flush().unwrap();
    assert!(e.sstable_count() >= 1);
    // No false negatives through the engine: every key still reads back.
    for i in 0..600 {
        assert_eq!(
            e.get(&format!("big-key-{i:04}")),
            Some(format!("v{i}")),
            "false negative for big-key-{i:04}"
        );
    }
    drop(e);

    // Direct SSTable check at 1000 keys: the filter must be bigger
    // than the old fixed 1 KiB, must find every key, and must stay
    // accurate (under 5% false positives on 1000 absent keys — the
    // old fixed filter at 1000 keys is already ~3%, and at 5000 keys
    // it is ~60%; the scaled filter stays near 0.5%).
    let keys: Vec<String> = (0..1000).map(|i| format!("key-{i:04}")).collect();
    let filter = BloomFilter::from_keys(&keys);
    assert!(
        filter.num_bits() >= 16_000,
        "filter did not scale for 1000 keys: {} bits",
        filter.num_bits()
    );
    for key in &keys {
        assert!(filter.may_contain(key), "false negative for {key}");
    }
    let false_positives = (5000..6000)
        .filter(|i| filter.may_contain(&format!("key-{i:04}")))
        .count();
    assert!(
        false_positives < 50,
        "scaled filter too weak: {false_positives}/1000 false positives"
    );

    // Same check through a real SSTable file on disk (round-trip).
    let path = sstable_path(&dir, 999);
    let entries: Vec<(String, Option<String>)> = keys
        .iter()
        .map(|k| (k.clone(), Some(format!("v-{k}"))))
        .collect();
    let table = SsTable::write(&path, 999, &entries).unwrap();
    assert!(table.filter.num_bits() >= 16_000);
    let reopened = SsTable::open(&path, 999).unwrap();
    for key in &keys {
        assert!(
            reopened.filter.may_contain(key),
            "false negative after SSTable round-trip for {key}"
        );
    }
    cleanup(&dir);
}

// ---------------------------------------------------------------------
// V0.3: numbered quarantine (never overwrite the first corrupt file)
// and WAL `del` strictness (a corrupt `del` resurrects the old value).
// ---------------------------------------------------------------------

#[test]
fn quarantine_second_tables_corruption_keeps_first() {
    // V0.2 overwrote tables.json.corrupt on the next corruption. V0.3
    // numbers quarantines: .corrupt.1, .corrupt.2, ... — the first
    // corrupt file must still be there, byte for byte, after the second.
    let dir = tmp_dir("quar-tables");
    {
        let mut e = Engine::open(&dir).unwrap();
        let mut tables = TableStore::open(&dir).unwrap();
        tables
            .create_table("users", vec!["id".into(), "name".into()])
            .unwrap();
        tables
            .insert(&mut e, "users", vec!["1".into(), "Sanjay".into()])
            .unwrap();
        e.flush().unwrap();
    }
    std::fs::write(dir.join("tables.json"), "corrupt-one").unwrap();
    let err = TableStore::open(&dir).expect_err("first corrupt tables.json must fail open");
    assert!(err.to_string().contains("tables.json.corrupt.1"), "{err}");
    assert_eq!(
        std::fs::read_to_string(dir.join("tables.json.corrupt.1")).unwrap(),
        "corrupt-one"
    );

    // Corrupt it a second time: the first quarantine must survive.
    std::fs::write(dir.join("tables.json"), "corrupt-two").unwrap();
    let err = TableStore::open(&dir).expect_err("second corrupt tables.json must fail open");
    assert!(err.to_string().contains("tables.json.corrupt.2"), "{err}");
    assert_eq!(
        std::fs::read_to_string(dir.join("tables.json.corrupt.1")).unwrap(),
        "corrupt-one",
        "first quarantine must not be overwritten by the second"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("tables.json.corrupt.2")).unwrap(),
        "corrupt-two"
    );
    cleanup(&dir);
}

#[test]
fn quarantine_second_meta_corruption_keeps_first() {
    let dir = tmp_dir("quar-meta");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("k", "v").unwrap();
    }
    std::fs::write(dir.join("meta.json"), "corrupt-one").unwrap();
    let mut e = Engine::open(&dir).expect("engine must open despite corrupt meta.json");
    assert_eq!(
        e.get("k"),
        Some("v".to_string()),
        "data must survive corrupt meta.json"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("meta.json.corrupt.1")).unwrap(),
        "corrupt-one"
    );
    drop(e);

    std::fs::write(dir.join("meta.json"), "corrupt-two").unwrap();
    let mut e = Engine::open(&dir).expect("engine must open despite second corrupt meta.json");
    assert_eq!(e.get("k"), Some("v".to_string()));
    assert_eq!(
        std::fs::read_to_string(dir.join("meta.json.corrupt.1")).unwrap(),
        "corrupt-one",
        "first quarantine must not be overwritten by the second"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("meta.json.corrupt.2")).unwrap(),
        "corrupt-two"
    );
    drop(e);
    cleanup(&dir);
}

#[test]
fn quarantine_second_sstable_corruption_keeps_first() {
    let dir = tmp_dir("quar-sst");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("flushed-key", "flushed-value").unwrap();
        e.flush().unwrap();
    }
    std::fs::write(dir.join("sst-000001.sst"), b"torn-one").unwrap();
    let mut e = Engine::open(&dir).expect("engine must open despite corrupt SSTable");
    assert_eq!(
        std::fs::read(dir.join("sst-000001.sst.corrupt.1")).unwrap(),
        b"torn-one"
    );
    // Flush a fresh SSTable: the quarantined id is free again, so the
    // new table takes sst-000001.sst — and corrupting THAT must go to
    // .corrupt.2, not overwrite .corrupt.1.
    e.put("flushed-key", "flushed-value").unwrap();
    e.flush().unwrap();
    drop(e);

    std::fs::write(dir.join("sst-000001.sst"), b"torn-two").unwrap();
    let _e = Engine::open(&dir).expect("engine must open despite second corrupt SSTable");
    assert_eq!(
        std::fs::read(dir.join("sst-000001.sst.corrupt.1")).unwrap(),
        b"torn-one",
        "first quarantine must not be overwritten by the second"
    );
    assert_eq!(
        std::fs::read(dir.join("sst-000001.sst.corrupt.2")).unwrap(),
        b"torn-two"
    );
    cleanup(&dir);
}

#[test]
fn corrupt_wal_del_line_resurrects_old_value() {
    // Policy (wal.rs, and now the README too): a corrupt WAL line is
    // skipped, ONLY that line. If the lost line was a `del`, the
    // delete itself is lost, so the key's older value — still sitting
    // in an SSTable — comes back alive on replay. This test proves
    // that behaviour instead of leaving it as a comment: it is a
    // deliberate trade-off (later valid lines are never thrown away
    // with the corrupt one), not a bug, but callers must know it.
    let dir = tmp_dir("wal-del-corrupt");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("res-key", "old-value").unwrap();
        e.flush().unwrap(); // old value now lives only in an SSTable
        e.delete("res-key").unwrap(); // the `del` lives only in the WAL
        assert_eq!(e.get("res-key"), None, "delete must hide the key");
    }
    // Corrupt exactly the `del` line, leaving the rest of the WAL intact.
    let wal_path = dir.join("wal.log");
    let text = std::fs::read_to_string(&wal_path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let del_line = lines
        .iter()
        .position(|l| l.contains("\"op\":\"del\""))
        .expect("WAL must contain the del line");
    lines[del_line] = "garbage-not-json".to_string();
    std::fs::write(&wal_path, lines.join("\n") + "\n").unwrap();

    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(
        e2.stats().wal_corrupt_lines,
        1,
        "the corrupt del line must be counted"
    );
    assert_eq!(
        e2.stats().wal_corrupt_line_numbers,
        vec![del_line as u64 + 1],
        "the corrupt line number must be reported"
    );
    assert_eq!(
        e2.get("res-key"),
        Some("old-value".to_string()),
        "a corrupt `del` line means the delete is lost and the old value comes back alive"
    );
    // The reopened engine is still usable: a fresh delete works.
    e2.delete("res-key").unwrap();
    assert_eq!(e2.get("res-key"), None);
    cleanup(&dir);
}

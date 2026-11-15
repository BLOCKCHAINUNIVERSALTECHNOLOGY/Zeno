// Integration tests for the Zeno V0.3 engine.
//
// Each test uses its own temp directory so tests never touch each
// other's data and never touch the user's real data directory.

use std::path::{Path, PathBuf};
use zeno::bloom::BloomFilter;
use zeno::doc::DocStore;
use zeno::engine::Engine;
use zeno::sstable::{sstable_path, SsTable};
use zeno::table::TableStore;
use zeno::txn::decode_chain;
use zeno::wal::WalRecord;

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
        err.to_string().contains("locked by"),
        "error must say the directory is locked: {err}"
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
    // Corrupt line 3, then a valid record on line 4. (V0.6: one
    // autocommit `put` writes TWO WAL records — the write plus a
    // commit marker — so the first put occupies lines 1-2, not
    // just line 1.)
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
    assert_eq!(e2.stats().wal_corrupt_line_numbers, vec![3]);
    drop(e2);

    // Reopening the SAME WAL again must NOT count the same corrupt
    // line a second time — the lifetime total stays 1.
    let e2b = Engine::open(&dir).unwrap();
    assert_eq!(
        e2b.stats().wal_corrupt_lines,
        1,
        "replaying the same WAL must not double-count its corrupt lines"
    );
    assert_eq!(e2b.stats().wal_corrupt_line_numbers, vec![3]);
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
    // (V0.6: two autocommit puts occupy lines 1-4 — write + commit
    // marker each — so the garbage lands on line 5, not line 3.)
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
        vec![5],
        "the corrupt line was line 5 of wal.log"
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

// ---------------------------------------------------------------------
// V0.5 test: concurrent `user set-password` must not lose users.
// ---------------------------------------------------------------------

#[test]
fn concurrent_set_password_keeps_all_users() {
    // Eight `zeno user set-password` processes at once, different
    // users, same data directory. Without the users.lock each one
    // loads the same users.json, adds its own user, and the last
    // save silently drops the others — the test fails. With the
    // lock they serialize and all eight survive.
    use std::io::Write;
    use std::process::{Command, Stdio};
    let dir = tmp_dir("setpw-race");
    let bin = env!("CARGO_BIN_EXE_zeno");
    let names: Vec<String> = (0..8).map(|i| format!("user{i}")).collect();
    let mut children = Vec::new();
    for name in &names {
        let mut child = Command::new(bin)
            .args([
                "--data",
                dir.to_str().unwrap(),
                "user",
                "set-password",
                name,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn zeno user set-password");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"password123\npassword123\n")
            .unwrap();
        children.push(child);
    }
    for child in children {
        let output = child.wait_with_output().expect("wait zeno user");
        assert!(
            output.status.success(),
            "set-password failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let users = zeno::auth::list_users(&dir).unwrap();
    for name in &names {
        assert!(
            users.contains(name),
            "user {name} was lost in the race: {users:?}"
        );
    }
    assert_eq!(users.len(), 8, "all eight users must survive: {users:?}");
    cleanup(&dir);
}

// ---------------------------------------------------------------------
// V0.6 tests: MVCC transactions (snapshot isolation).
// ---------------------------------------------------------------------

#[test]
fn txn_commit_makes_writes_visible_and_rollback_hides_them() {
    let dir = tmp_dir("txn-basic");
    let mut e = Engine::open(&dir).unwrap();
    // Begin: own writes are visible to the transaction itself...
    let txn = e.begin();
    e.txn_put(txn, "k1", "v1").unwrap();
    assert_eq!(e.txn_get(txn, "k1").unwrap(), Some("v1".to_string()));
    // ...but invisible to everyone else (an autocommit read).
    assert_eq!(e.get("k1"), None, "uncommitted data must be invisible");
    // Commit: now everyone sees it.
    e.commit(txn).unwrap();
    assert_eq!(e.get("k1"), Some("v1".to_string()));

    // Rollback: nothing survives.
    let txn2 = e.begin();
    e.txn_put(txn2, "k2", "v2").unwrap();
    e.txn_delete(txn2, "k1").unwrap();
    assert_eq!(
        e.txn_get(txn2, "k1").unwrap(),
        None,
        "own delete visible to self"
    );
    e.rollback(txn2).unwrap();
    assert_eq!(e.get("k2"), None, "rolled-back insert must be gone");
    assert_eq!(
        e.get("k1"),
        Some("v1".to_string()),
        "rolled-back delete must not take effect"
    );
    drop(e);
    cleanup(&dir);
}

#[test]
fn txn_snapshot_isolation_hides_later_commits() {
    let dir = tmp_dir("txn-snapshot");
    let mut e = Engine::open(&dir).unwrap();
    e.put("a", "old").unwrap();
    // T1 begins, then another writer commits a new value...
    let t1 = e.begin();
    e.put("a", "new").unwrap();
    e.put("b", "brand-new").unwrap();
    // ...but T1 still sees the world as of BEGIN.
    assert_eq!(
        e.txn_get(t1, "a").unwrap(),
        Some("old".to_string()),
        "a snapshot must not see data committed after BEGIN"
    );
    assert_eq!(
        e.txn_get(t1, "b").unwrap(),
        None,
        "a snapshot must not see rows created after BEGIN"
    );
    // A fresh read sees the new data.
    assert_eq!(e.get("a"), Some("new".to_string()));
    assert_eq!(e.get("b"), Some("brand-new".to_string()));
    // Committing a read-only transaction changes nothing.
    e.commit(t1).unwrap();
    assert_eq!(e.get("a"), Some("new".to_string()));
    drop(e);
    cleanup(&dir);
}

#[test]
fn txn_write_write_conflict_aborts_second_committer() {
    use zeno::txn::CommitError;
    let dir = tmp_dir("txn-conflict");
    let mut e = Engine::open(&dir).unwrap();
    e.put("row", "v0").unwrap();
    // Two transactions begin on the same snapshot and both change
    // the same key: first-committer-wins.
    let t1 = e.begin();
    let t2 = e.begin();
    e.txn_put(t1, "row", "from-t1").unwrap();
    e.txn_put(t2, "row", "from-t2").unwrap();
    e.commit(t1).unwrap();
    assert_eq!(e.get("row"), Some("from-t1".to_string()));
    let err = e.commit(t2).unwrap_err();
    assert!(
        matches!(err, CommitError::Conflict(_)),
        "second committer must get a conflict, got: {err}"
    );
    // The loser's write is gone; the winner's stands.
    assert_eq!(e.get("row"), Some("from-t1".to_string()));
    // The aborted transaction is gone: no further operations on it.
    assert!(e.txn_put(t2, "row", "again").is_err());
    drop(e);
    cleanup(&dir);
}

#[test]
fn txn_table_update_and_delete_with_rollback() {
    let dir = tmp_dir("txn-table");
    let mut e = Engine::open(&dir).unwrap();
    let mut tables = TableStore::open(&dir).unwrap();
    tables
        .create_table("users", vec!["id".to_string(), "city".to_string()])
        .unwrap();
    tables
        .insert(&mut e, "users", vec!["1".to_string(), "Delhi".to_string()])
        .unwrap();
    // Inside a transaction: UPDATE is visible to self, DELETE
    // removes the row for self — nobody else sees either yet.
    let txn = e.begin();
    let updated = tables
        .update_txn(&mut e, txn, "users", "city", "Mumbai", None)
        .unwrap();
    assert_eq!(updated, 1);
    let rows = tables.select_txn(&mut e, txn, "users", None).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.get("city").unwrap(), "Mumbai");
    let rows_outside = tables.select(&mut e, "users", None).unwrap();
    assert_eq!(
        rows_outside[0].1.get("city").unwrap(),
        "Delhi",
        "uncommitted UPDATE must be invisible outside the txn"
    );
    let deleted = tables.delete_txn(&mut e, txn, "users", None).unwrap();
    assert_eq!(deleted, 1);
    assert!(tables
        .select_txn(&mut e, txn, "users", None)
        .unwrap()
        .is_empty());
    // Rollback: the row comes back, UPDATE and DELETE both undone.
    e.rollback(txn).unwrap();
    let rows = tables.select(&mut e, "users", None).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.get("city").unwrap(), "Delhi");
    drop(e);
    cleanup(&dir);
}

#[test]
fn wal_replay_recovers_only_committed_txns() {
    // Hand-write WAL records: txn 900 commits, txn 901 never
    // does (crash before its commit marker). On reopen only 900's
    // data may come back — and the next txn id must stay above
    // both, so neither id is ever reused.
    use std::io::Write as _;
    use zeno::wal::WalRecord;
    let dir = tmp_dir("txn-wal-replay");
    {
        let mut e = Engine::open(&dir).unwrap();
        e.put("committed-before", "yes").unwrap();
    }
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("wal.log"))
            .unwrap();
        writeln!(
            f,
            "{}",
            serde_json::to_string(&WalRecord::put_txn(900, "txn-committed", "c")).unwrap()
        )
        .unwrap();
        writeln!(
            f,
            "{}",
            serde_json::to_string(&WalRecord::commit(900)).unwrap()
        )
        .unwrap();
        writeln!(
            f,
            "{}",
            serde_json::to_string(&WalRecord::put_txn(901, "txn-crashed", "x")).unwrap()
        )
        .unwrap();
        // No commit record for 901: the crash.
    }
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.get("committed-before"), Some("yes".to_string()));
    assert_eq!(
        e2.get("txn-committed"),
        Some("c".to_string()),
        "a committed txn must survive replay"
    );
    assert_eq!(
        e2.get("txn-crashed"),
        None,
        "an uncommitted txn must be discarded on replay"
    );
    assert!(
        e2.next_txn_id() > 901,
        "next txn id must stay above every id seen in the WAL, got {}",
        e2.next_txn_id()
    );
    drop(e2);
    cleanup(&dir);
}

#[test]
fn legacy_wal_records_without_txn_replay_as_committed() {
    // A genuine V0.5 WAL file has no "txn" field at all. It must
    // still open, and its rows must be readable (as pre-MVCC data,
    // visible to every snapshot).
    use std::io::Write as _;
    let dir = tmp_dir("txn-legacy-wal");
    {
        let mut f = std::fs::File::create(dir.join("wal.log")).unwrap();
        writeln!(
            f,
            "{{\"op\":\"put\",\"key\":\"old-key\",\"value\":\"old-val\"}}"
        )
        .unwrap();
        writeln!(f, "{{\"op\":\"put\",\"key\":\"gone\",\"value\":\"x\"}}").unwrap();
        writeln!(f, "{{\"op\":\"del\",\"key\":\"gone\"}}").unwrap();
    }
    let mut e = Engine::open(&dir).unwrap();
    assert_eq!(e.get("old-key"), Some("old-val".to_string()));
    assert_eq!(e.get("gone"), None);
    // And new MVCC writes work on top of the legacy data.
    let txn = e.begin();
    e.txn_put(txn, "old-key", "new-val").unwrap();
    e.commit(txn).unwrap();
    assert_eq!(e.get("old-key"), Some("new-val".to_string()));
    drop(e);
    cleanup(&dir);
}

#[test]
fn txn_ids_survive_flush_and_restart() {
    // After a flush the WAL is cleared, so the next txn id must
    // come from meta.json / the SSTable envelopes — never reuse
    // an id that an SSTable version already carries (a reused id
    // would read as "aborted" and hide committed data).
    let dir = tmp_dir("txn-id-restart");
    let first_txn;
    {
        let mut e = Engine::open(&dir).unwrap();
        let txn = e.begin();
        first_txn = txn;
        e.txn_put(txn, "k", "v").unwrap();
        e.commit(txn).unwrap();
        e.flush().unwrap(); // WAL cleared; version lives in an SSTable now
    }
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(
        e2.get("k"),
        Some("v".to_string()),
        "flushed data must survive"
    );
    let txn2 = e2.begin();
    assert!(
        txn2 > first_txn,
        "a restarted engine must not reuse txn id {first_txn}, got {txn2}"
    );
    e2.rollback(txn2).unwrap();
    drop(e2);
    cleanup(&dir);
}

/// Count the versions of `key` in every SSTable on disk (the
/// envelopes as literally stored, not the merged read path).
fn sstable_chain_lengths(dir: &Path, key: &str) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("sst-") && n.ends_with(".sst"))
        .collect();
    names.sort();
    for name in names {
        let text = std::fs::read_to_string(dir.join(&name)).unwrap();
        for line in text.lines().skip(2) {
            if line.trim().is_empty() {
                continue;
            }
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            if entry["k"].as_str() == Some(key) {
                let value = entry["v"].as_str().map(str::to_string);
                lengths.push(decode_chain(value.as_deref()).len());
            }
        }
    }
    lengths
}

#[test]
fn flush_does_not_duplicate_version_chain() {
    // B1: the old flush wrote the memtable's WHOLE envelope
    // (the full chain) into every new SSTable while the old
    // SSTable kept its copy, so the chain doubled on every flush
    // (2, 3, 6, 12, 24 entries for 5 versions). A flush must
    // write only the delta.
    let dir = tmp_dir("flush-no-dupe");
    let mut e = Engine::open(&dir).unwrap();
    for (i, v) in ["v1", "v2", "v3", "v4", "v5"].iter().enumerate() {
        e.put("k", v).unwrap();
        e.flush().unwrap();
        assert_eq!(
            e.version_chain_len("k"),
            i + 1,
            "after {} version(s) the chain must have exactly that many versions",
            i + 1
        );
        assert_eq!(e.get("k"), Some(v.to_string()));
    }
    // Each SSTable on disk holds exactly one new version.
    let lengths = sstable_chain_lengths(&dir, "k");
    assert_eq!(
        lengths.iter().sum::<usize>(),
        5,
        "5 versions must be stored as 5 entries across all SSTables, got {lengths:?}"
    );
    assert!(
        lengths.iter().all(|&n| n == 1),
        "each flush must store only its delta: {lengths:?}"
    );
    // Ten more flushes with no new writes change nothing.
    for _ in 0..10 {
        e.flush().unwrap();
    }
    assert_eq!(e.version_chain_len("k"), 5);
    assert_eq!(e.get("k"), Some("v5".to_string()));
    // And the chain still reads right after a reopen.
    drop(e);
    let mut e2 = Engine::open(&dir).unwrap();
    assert_eq!(e2.version_chain_len("k"), 5);
    assert_eq!(e2.get("k"), Some("v5".to_string()));
    drop(e2);
    cleanup(&dir);
}

#[test]
fn envelope_shaped_legacy_values_are_plain_data() {
    // M1: a V0.5-style SSTable whose raw values happen to look
    // like MVCC envelopes must NOT be misread as version chains
    // — no injected "pwned" value, no hidden rows, and no
    // inflated next_txn_id.
    let dir = tmp_dir("envelope-collision");
    let forged_pwned =
        r#"{"__zeno_mvcc":1,"versions":[{"xmin":999999,"xmax":null,"value":"pwned"}]}"#;
    let forged_null = r#"{"__zeno_mvcc":1,"versions":[{"xmin":0,"value":null}]}"#;
    let forged_hidden = r#"{"__zeno_mvcc":1,"versions":[{"xmin":0,"xmax":1,"value":"hidden"}]}"#;
    let mut lines = vec![
        "ZENO-SSTABLE-1".to_string(),
        "ff".repeat(1024),
        serde_json::to_string(&serde_json::json!({"k": "k1", "v": forged_pwned})).unwrap(),
        serde_json::to_string(&serde_json::json!({"k": "k2", "v": forged_null})).unwrap(),
        serde_json::to_string(&serde_json::json!({"k": "k3", "v": forged_hidden})).unwrap(),
    ];
    std::fs::write(dir.join("sst-000001.sst"), lines.join("\n") + "\n").unwrap();
    lines.clear();
    // No meta.json, no WAL: a bare V0.5-style directory.
    let mut e = Engine::open(&dir).unwrap();
    assert_eq!(
        e.get("k1"),
        Some(forged_pwned.to_string()),
        "the forged envelope must read back as the plain text it is, not 'pwned'"
    );
    assert_eq!(
        e.get("k2"),
        Some(forged_null.to_string()),
        "an envelope-shaped null must not delete the row"
    );
    assert_eq!(
        e.get("k3"),
        Some(forged_hidden.to_string()),
        "an envelope-shaped hidden value must stay visible"
    );
    assert!(
        e.next_txn_id() < 100,
        "next_txn_id must not be inflated by the forged xmin 999999, got {}",
        e.next_txn_id()
    );
    drop(e);
    cleanup(&dir);
}

#[test]
fn old_unprefixed_envelope_is_trusted_when_ids_are_plausible() {
    // M1, migration side: a REAL pre-fix envelope (unprefixed,
    // written by the old encoder) in a database whose meta.json
    // proves its ids are plausible must still read correctly —
    // the bound is a forgery check, not a format break.
    let dir = tmp_dir("envelope-migration");
    let old_envelope = r#"{"__zeno_mvcc":1,"versions":[{"xmin":1,"xmax":2,"value":"old"},{"xmin":2,"xmax":null,"value":"new"}]}"#;
    let lines = [
        "ZENO-SSTABLE-1".to_string(),
        "ff".repeat(1024),
        serde_json::to_string(&serde_json::json!({"k": "k", "v": old_envelope})).unwrap(),
    ];
    std::fs::write(dir.join("sst-000001.sst"), lines.join("\n") + "\n").unwrap();
    std::fs::write(
        dir.join("meta.json"),
        r#"{"puts":0,"gets":0,"flushes":0,"compactions":0,"deletes":0,"wal_corrupt_lines":0,"wal_corrupt_lines_current":0,"wal_size_seen":0,"next_txn_id":10}"#,
    )
    .unwrap();
    let mut e = Engine::open(&dir).unwrap();
    assert_eq!(e.get("k"), Some("new".to_string()));
    assert_eq!(e.version_chain_len("k"), 2);
    drop(e);
    cleanup(&dir);
}

#[test]
fn commit_succeeds_when_flush_fails() {
    // M3: the commit is durable in the WAL before any flush, so
    // a flush failure must not report the commit as failed (the
    // old code did exactly that, against its own comment).
    let dir = tmp_dir("commit-flush-fail");
    let mut e = Engine::open(&dir).unwrap();
    // Fill the memtable to the flush threshold inside one
    // transaction, arm the failure, then commit: the commit must
    // still return Ok, and the data must be readable.
    let txn = e.begin();
    for i in 0..64 {
        e.txn_put(txn, &format!("k{i:02}"), &format!("v{i}"))
            .unwrap();
    }
    e.set_flush_failure(true);
    e.commit(txn)
        .expect("commit must succeed even when its flush fails");
    assert_eq!(e.get("k00"), Some("v0".to_string()));
    assert_eq!(e.get("k63"), Some("v63".to_string()));
    // The flag is consumed: a manual flush now works.
    e.flush().unwrap();
    drop(e);
    // Same for the autocommit put path: 63 puts, arm the failure,
    // the 64th put triggers the flush and must still return Ok.
    let mut e2 = Engine::open(&dir).unwrap();
    for i in 0..63 {
        e2.put(&format!("p{i:02}"), "x").unwrap();
    }
    e2.set_flush_failure(true);
    e2.put("p63", "x")
        .expect("put must succeed even when its flush fails");
    assert_eq!(e2.get("p63"), Some("x".to_string()));
    drop(e2);
    cleanup(&dir);
}

fn write_wal(dir: &Path, lines: &[String]) {
    std::fs::write(dir.join("wal.log"), lines.join("\n") + "\n").unwrap();
}

#[test]
fn wal_replay_discards_txn_with_torn_write() {
    // M4: a committed transaction whose WAL lost a write line
    // (torn write) must be discarded WHOLE — never applied
    // partially. Txn 7 has 2 writes but only 1 survives; txn 8
    // is intact and must apply.
    let dir = tmp_dir("wal-torn-txn");
    let mut lines = vec![
        serde_json::to_string(&WalRecord::put_txn(7, "k1", "v1")).unwrap(),
        "{\"op\":\"put\",\"txn\":7,\"key\":\"k2\",\"val".to_string(), // torn line
        serde_json::to_string(&WalRecord::commit_count(7, 2)).unwrap(),
        serde_json::to_string(&WalRecord::put_txn(8, "k3", "v3")).unwrap(),
        serde_json::to_string(&WalRecord::commit_count(8, 1)).unwrap(),
    ];
    write_wal(&dir, &lines);
    lines.clear();
    let mut e = Engine::open(&dir).unwrap();
    assert_eq!(
        e.get("k1"),
        None,
        "txn 7 lost a write line, so NONE of it may apply (no partial commit)"
    );
    assert_eq!(e.get("k2"), None);
    assert_eq!(
        e.get("k3"),
        Some("v3".to_string()),
        "the intact transaction must still apply"
    );
    assert_eq!(e.stats().wal_discarded_txns, 1);
    drop(e);
    cleanup(&dir);
}

#[test]
fn wal_replay_discards_txn_with_torn_delete() {
    // M4, delete side: a torn `del` inside a transaction must not
    // resurrect the old value by applying the rest of the txn —
    // the whole transaction goes, so the old value stays because
    // the transaction never happened, not because the delete was
    // silently lost.
    let dir = tmp_dir("wal-torn-del");
    let lines = [
        "ZENO-SSTABLE-1".to_string(),
        "ff".repeat(1024),
        serde_json::to_string(&serde_json::json!({"k": "k4", "v": "oldval"})).unwrap(),
    ];
    std::fs::write(dir.join("sst-000001.sst"), lines.join("\n") + "\n").unwrap();
    let wal_lines = vec![
        serde_json::to_string(&WalRecord::del_txn(9, "k4")).unwrap(),
        "{\"op\":\"put\",\"txn\":9,\"key\":\"k5\",\"val".to_string(), // torn line
        serde_json::to_string(&WalRecord::commit_count(9, 2)).unwrap(),
    ];
    write_wal(&dir, &wal_lines);
    let mut e = Engine::open(&dir).unwrap();
    assert_eq!(
        e.get("k4"),
        Some("oldval".to_string()),
        "the torn transaction must not apply its delete either"
    );
    assert_eq!(e.get("k5"), None);
    assert_eq!(e.stats().wal_discarded_txns, 1);
    drop(e);
    cleanup(&dir);
}

#[test]
fn vacuum_prunes_old_versions_and_committed_set_but_keeps_live_snapshots() {
    // M5: VACUUM prunes versions no live snapshot can see, and
    // prunes the committed set to the oldest live snapshot's
    // watermark — while a live snapshot still sees its own old
    // version.
    let dir = tmp_dir("vacuum-live");
    let mut e = Engine::open(&dir).unwrap();
    e.put("k", "v1").unwrap();
    e.flush().unwrap();
    e.put("k", "v2").unwrap();
    e.flush().unwrap();
    e.put("k", "v3").unwrap();
    e.flush().unwrap();
    assert_eq!(e.version_chain_len("k"), 3);
    // A begins: its snapshot sees v3.
    let txn_a = e.begin();
    assert_eq!(e.txn_get(txn_a, "k").unwrap(), Some("v3".to_string()));
    // Two more versions land after A's BEGIN.
    e.put("k", "v4").unwrap();
    e.flush().unwrap();
    e.put("k", "v5").unwrap();
    e.flush().unwrap();
    assert_eq!(e.version_chain_len("k"), 5);
    let committed_before = e.stats().committed_txns;
    assert!(
        committed_before >= 5,
        "committed set must hold the puts: {committed_before}"
    );
    // VACUUM while A is live: keep v3 (A's visible version),
    // v4+v5 (created after A's snapshot) — v1, v2 go.
    let report = e.vacuum().unwrap();
    assert_eq!(report.pruned_versions, 2, "only v1 and v2 may be pruned");
    assert_eq!(e.version_chain_len("k"), 3);
    assert_eq!(e.get("k"), Some("v5".to_string()));
    assert_eq!(
        e.txn_get(txn_a, "k").unwrap(),
        Some("v3".to_string()),
        "the live snapshot must still see v3 after VACUUM"
    );
    assert!(
        e.stats().committed_txns < committed_before,
        "the committed set must shrink: {} -> {}",
        committed_before,
        e.stats().committed_txns
    );
    // A rolls back; a second VACUUM (no live snapshot) prunes to
    // the newest version only.
    e.rollback(txn_a).unwrap();
    let report = e.vacuum().unwrap();
    assert_eq!(
        report.pruned_versions, 2,
        "v3 and v4 go once no snapshot needs them"
    );
    assert_eq!(e.version_chain_len("k"), 1);
    assert_eq!(e.get("k"), Some("v5".to_string()));
    assert_eq!(e.stats().committed_txns, 0, "no live txn: the set empties");
    drop(e);
    cleanup(&dir);
}

#[test]
fn vacuum_drops_deleted_key_when_no_snapshot_needs_it() {
    let dir = tmp_dir("vacuum-delete");
    let mut e = Engine::open(&dir).unwrap();
    e.put("k", "v1").unwrap();
    e.flush().unwrap();
    e.put("k", "v2").unwrap();
    e.flush().unwrap();
    e.delete("k").unwrap();
    e.flush().unwrap();
    assert_eq!(e.version_chain_len("k"), 3);
    assert_eq!(e.get("k"), None);
    e.vacuum().unwrap();
    assert_eq!(
        e.version_chain_len("k"),
        0,
        "a deleted key must be physically gone"
    );
    assert!(e.scan_prefix_raw("k").is_empty());
    drop(e);
    cleanup(&dir);
}

fn wal_txn_summary(dir: &Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(dir.join("wal.log")).unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn autocommit_update_and_delete_are_single_wal_transactions() {
    // M6: one autocommit UPDATE over 3 rows must be ONE txn id
    // plus ONE commit marker in the WAL — not 3 transactions.
    let dir = tmp_dir("autocommit-atomic");
    let mut e = Engine::open(&dir).unwrap();
    let mut tables = TableStore::open(&dir).unwrap();
    tables
        .create_table("u", vec!["id".into(), "city".into()])
        .unwrap();
    for (id, city) in [("1", "A"), ("2", "B"), ("3", "C")] {
        tables
            .insert(&mut e, "u", vec![id.into(), city.into()])
            .unwrap();
    }
    tables.update(&mut e, "u", "city", "Z", None).unwrap();
    let records = wal_txn_summary(&dir);
    let last_commit = records
        .iter()
        .rev()
        .find(|r| r["op"] == "commit")
        .expect("an UPDATE must end with a commit record");
    let txn = last_commit["txn"].as_u64().expect("commit needs a txn id");
    assert_eq!(
        last_commit["count"],
        serde_json::json!(3),
        "commit must count 3 writes"
    );
    let writes: Vec<_> = records
        .iter()
        .filter(|r| r["txn"].as_u64() == Some(txn) && r["op"] == "put")
        .collect();
    assert_eq!(writes.len(), 3, "one txn id must carry all 3 UPDATE writes");
    assert_eq!(
        records
            .iter()
            .filter(|r| r["txn"].as_u64() == Some(txn) && r["op"] == "commit")
            .count(),
        1,
        "exactly one commit marker for the UPDATE"
    );
    let rows = tables.select(&mut e, "u", None).unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|(_, r)| r["city"] == "Z"));
    // Same for DELETE: 3 deletes, one txn, one commit.
    tables.delete(&mut e, "u", None).unwrap();
    let records = wal_txn_summary(&dir);
    let last_commit = records
        .iter()
        .rev()
        .find(|r| r["op"] == "commit")
        .expect("a DELETE must end with a commit record");
    let txn = last_commit["txn"].as_u64().unwrap();
    assert_eq!(last_commit["count"], serde_json::json!(3));
    assert_eq!(
        records
            .iter()
            .filter(|r| r["txn"].as_u64() == Some(txn) && r["op"] == "del")
            .count(),
        3
    );
    assert_eq!(tables.select(&mut e, "u", None).unwrap().len(), 0);
    drop(e);
    cleanup(&dir);
}

#[test]
fn reserved_key_prefixes_are_rejected_for_raw_puts() {
    // m2: a raw KV put of a `table:` / `doc:` key used to forge
    // table rows straight past the registry. The public put/del
    // refuse those prefixes now; the table/document stores still
    // work through their internal path.
    let dir = tmp_dir("reserved-prefix");
    let mut e = Engine::open(&dir).unwrap();
    assert!(
        e.put("table:users:00000000000000000099", "forged").is_err(),
        "a raw put must not forge a table row"
    );
    assert!(e.put("doc:profiles:u1", "{}").is_err());
    assert!(e.delete("table:users:00000000000000000001").is_err());
    assert_eq!(e.get("table:users:00000000000000000099"), None);
    // The real stores are unaffected.
    let mut tables = TableStore::open(&dir).unwrap();
    tables
        .create_table("users", vec!["id".into(), "name".into()])
        .unwrap();
    tables
        .insert(&mut e, "users", vec!["1".into(), "Sanjay".into()])
        .unwrap();
    assert_eq!(tables.select(&mut e, "users", None).unwrap().len(), 1);
    DocStore::put(&mut e, "profiles", "u1", r#"{"name":"Sanjay"}"#).unwrap();
    assert_eq!(
        DocStore::get(&mut e, "profiles", "u1").as_deref(),
        Some(r#"{"name":"Sanjay"}"#)
    );
    drop(e);
    cleanup(&dir);
}

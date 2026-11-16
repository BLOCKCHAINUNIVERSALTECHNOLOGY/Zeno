// Zeno V0.5 — library root. The binary in main.rs is a thin CLI over
// these modules; the integration tests use the same public API.

pub mod auth;
pub mod bench;
pub mod bloom;
pub mod doc;
pub mod engine;
pub mod extended;
pub mod lock;
pub mod memtable;
pub mod parser;
pub mod pgwire;
pub mod quarantine;
pub mod query;
pub mod sstable;
pub mod table;
pub mod tls;
pub mod txn;
pub mod wal;

/// Test-only helper (V0.11, review finding 12): a temp directory
/// that is unique per call — process id + wall-clock nanoseconds +
/// a per-process counter — so two concurrent runs of the same test
/// binary can never delete or overwrite each other's data. The old
/// helpers built a fixed path from the test name alone and then
/// `remove_dir_all`'d it, so a second concurrent run wiped the
/// first run's directory mid-test. The directory is created by
/// this function; callers remove it when they are done.
#[cfg(test)]
pub(crate) fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut p = std::env::temp_dir();
    p.push(format!("{prefix}-{}-{nanos}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create unique test dir");
    p
}

/// Test-only helper (V0.11, review finding 12): like
/// `unique_test_dir`, but a unique FILE path (not created) — for
/// tests that open a single file, such as the WAL tests.
#[cfg(test)]
pub(crate) fn unique_test_path(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut p = std::env::temp_dir();
    p.push(format!("{prefix}-{}-{nanos}-{n}.log", std::process::id()));
    p
}

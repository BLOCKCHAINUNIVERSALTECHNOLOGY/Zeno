// bench.rs — `zeno bench` (V0.8): measure Zeno's own throughput
// and latency, nothing else's.
//
// What it measures, honestly: the ENGINE API directly (not the
// wire protocol) — autocommit KV `put` / `get` and table
// `insert` / full `select`, at several row counts, with a warmup
// before each measured run. Every number printed is a measurement
// taken on this machine, in this run; there is no comparison with
// PostgreSQL or MongoDB here, because neither is installed in
// this sandbox (checked: `which psql mongod postgres` finds
// nothing) — see `docs/V1-READINESS.md`, which says so plainly.
//
// Method: a fresh temporary data directory (deleted afterwards),
// so the benchmark never touches the user's real data. For each
// row count N: warmup (100 puts + 100 gets, untimed), then THREE
// measured runs of N puts, N gets, N table inserts, and one full
// table select each — the reported numbers are the median across
// the three runs, because a single sample varies 2x run to run
// (review). Per-operation latencies are timed one by one
// (`Instant` around each call) and reported as median / p95 /
// mean, plus ops/s. The machine (CPU, core count,
// build mode) is printed next to the numbers, because a number
// without its machine is not a measurement.
//
// Known costs baked into the numbers: one autocommit `put` is TWO
// WAL fsyncs (write record + commit record — see `txn.rs`), so
// the put numbers are fsync-bound on most disks, not CPU-bound.
// A debug build is much slower than release — the output says
// which one ran, and a debug run's numbers are not representative.

use crate::engine::Engine;
use crate::table::TableStore;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Default row counts, in order: 100 / 1000 / 10000.
pub const DEFAULT_ROWS: &[usize] = &[100, 1000, 10000];

/// Largest single row count accepted (a runaway `bench --rows`
/// must not write forever) and largest list length.
const MAX_ROWS: usize = 100_000;
const MAX_LIST: usize = 10;

/// Number of measured runs per row count; the reported numbers
/// are the median across these runs. A single sample varied 2x
/// run to run (review: KV put 26536 -> 11352 -> 14111 ops/s,
/// p95 51.6 -> 189.1 -> 412.3 µs across three `--rows 1000` runs,
/// median stable) — one run's numbers are not a measurement.
pub const RUNS_PER_COUNT: usize = 3;

/// Parse a `--rows` value like "100,1000,10000" into row counts.
pub fn parse_rows(value: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for part in value.split(',') {
        let n: usize = part
            .trim()
            .parse()
            .map_err(|_| format!("--rows needs numbers like 100,1000,10000, got '{value}'"))?;
        if n == 0 || n > MAX_ROWS {
            return Err(format!("--rows needs counts from 1 to {MAX_ROWS}, got {n}"));
        }
        // M2 (V0.8 review): a duplicate count used to be accepted
        // and then failed mid-run, because both iterations tried to
        // create the same `bench{n}` table ("table 'bench100'
        // already exists"). Reject it here, with a clear error.
        if out.contains(&n) {
            return Err(format!(
                "--rows has duplicate count {n} — each row count may appear only once (got '{value}')"
            ));
        }
        out.push(n);
    }
    if out.is_empty() || out.len() > MAX_LIST {
        return Err(format!(
            "--rows needs 1 to {MAX_LIST} counts, got {}",
            out.len()
        ));
    }
    Ok(out)
}

/// Median / p95 / mean of per-operation latencies, in microseconds.
struct Latency {
    median_us: f64,
    p95_us: f64,
    mean_us: f64,
}

fn summarize(mut nanos: Vec<u64>) -> Latency {
    nanos.sort_unstable();
    let n = nanos.len();
    let median_us = if n == 0 {
        0.0
    } else if n % 2 == 1 {
        nanos[n / 2] as f64 / 1000.0
    } else {
        (nanos[n / 2 - 1] + nanos[n / 2]) as f64 / 2.0 / 1000.0
    };
    let p95_us = if n == 0 {
        0.0
    } else {
        // Nearest-rank p95: the element at ceil(0.95 * n), 1-based.
        let rank = (95 * n).div_ceil(100).max(1).min(n);
        nanos[rank - 1] as f64 / 1000.0
    };
    let mean_us = if n == 0 {
        0.0
    } else {
        nanos.iter().sum::<u64>() as f64 / n as f64 / 1000.0
    };
    Latency {
        median_us,
        p95_us,
        mean_us,
    }
}

/// One line of CPU model from /proc/cpuinfo (Linux), if readable.
fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|m| m.trim().to_string())
        })
        .unwrap_or_else(|| "(unknown CPU — /proc/cpuinfo not readable)".to_string())
}

/// Owns a bench temp directory and removes it when dropped — on
/// EVERY exit path: success, any `return Err`, or a panic
/// (unwind). M3 (V0.8 review): the old code removed the dir only
/// at the end of `run()`, so any error in the middle (duplicate
/// table, get-mismatch, select count mismatch) leaked
/// `/tmp/zeno-bench-<pid>-<nanos>/` after every failed run.
/// The guard is created before the engine opens, and it is
/// declared before the engine/tables, so on any early return the
/// engine and tables drop first and the dir goes last.
struct BenchTempDir {
    path: PathBuf,
}

impl BenchTempDir {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for BenchTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// One measured run at one row count: ops/s + latency summary
/// per operation, and the full-scan select time.
#[derive(Clone, Copy, Default)]
struct RunMetrics {
    put_ops: f64,
    put_median_us: f64,
    put_p95_us: f64,
    put_mean_us: f64,
    get_ops: f64,
    get_median_us: f64,
    get_p95_us: f64,
    get_mean_us: f64,
    insert_ops: f64,
    insert_median_us: f64,
    insert_p95_us: f64,
    insert_mean_us: f64,
    select_ms: f64,
    select_us_per_row: f64,
}

/// Median of each field across the runs (for 3 runs, the middle
/// value). The median run's numbers are what gets printed.
fn median_of_runs(runs: &[RunMetrics]) -> RunMetrics {
    let med = |f: fn(&RunMetrics) -> f64| -> f64 {
        let mut vals: Vec<f64> = runs.iter().map(f).collect();
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        vals[vals.len() / 2]
    };
    RunMetrics {
        put_ops: med(|m| m.put_ops),
        put_median_us: med(|m| m.put_median_us),
        put_p95_us: med(|m| m.put_p95_us),
        put_mean_us: med(|m| m.put_mean_us),
        get_ops: med(|m| m.get_ops),
        get_median_us: med(|m| m.get_median_us),
        get_p95_us: med(|m| m.get_p95_us),
        get_mean_us: med(|m| m.get_mean_us),
        insert_ops: med(|m| m.insert_ops),
        insert_median_us: med(|m| m.insert_median_us),
        insert_p95_us: med(|m| m.insert_p95_us),
        insert_mean_us: med(|m| m.insert_mean_us),
        select_ms: med(|m| m.select_ms),
        select_us_per_row: med(|m| m.select_us_per_row),
    }
}

/// One measured run at row count `n`: warmup, then N timed puts,
/// N timed gets (values verified), N timed inserts into a fresh
/// table, and one timed full select. The table name carries the
/// run index, so the runs of one row count never collide with
/// each other.
fn measure_once(
    engine: &mut Engine,
    tables: &mut TableStore,
    n: usize,
    run_idx: usize,
) -> Result<RunMetrics, String> {
    // Warmup (untimed): same operations, smaller count, so the
    // first measured put does not pay the cold-start cost.
    for i in 0..100 {
        let key = format!("warm:k{i:04}");
        let value = bench_value(i);
        engine
            .put(&key, &value)
            .map_err(|e| format!("warmup put failed: {e}"))?;
        let _ = engine.get(&key);
        engine
            .delete(&key)
            .map_err(|e| format!("warmup delete failed: {e}"))?;
    }

    // KV put: N timed puts, one latency sample each.
    let mut lat = Vec::with_capacity(n);
    let start = Instant::now();
    for i in 0..n {
        let key = format!("bench:k{i:06}");
        let value = bench_value(i);
        let t = Instant::now();
        engine
            .put(&key, &value)
            .map_err(|e| format!("bench put failed: {e}"))?;
        lat.push(t.elapsed().as_nanos() as u64);
    }
    let put_total = start.elapsed();
    let put = summarize(lat);

    // KV get: N timed gets, verifying every value matches.
    let mut lat = Vec::with_capacity(n);
    let mut mismatches = 0;
    let start = Instant::now();
    for i in 0..n {
        let key = format!("bench:k{i:06}");
        let t = Instant::now();
        let got = engine.get(&key);
        lat.push(t.elapsed().as_nanos() as u64);
        if got.as_deref() != Some(bench_value(i).as_str()) {
            mismatches += 1;
        }
    }
    let get_total = start.elapsed();
    let get = summarize(lat);
    if mismatches != 0 {
        return Err(format!(
            "bench get: {mismatches} of {n} values did not match"
        ));
    }

    // Table insert: N timed inserts into a fresh table.
    let table = format!("bench{n}-r{run_idx}");
    tables
        .create_table(&table, vec!["id".into(), "name".into(), "city".into()])
        .map_err(|e| e.to_string())?;
    let mut lat = Vec::with_capacity(n);
    let start = Instant::now();
    for i in 0..n {
        let values = vec![i.to_string(), format!("name{i}"), "Delhi".to_string()];
        let t = Instant::now();
        tables
            .insert(&mut *engine, &table, values)
            .map_err(|e| e.to_string())?;
        lat.push(t.elapsed().as_nanos() as u64);
    }
    let insert_total = start.elapsed();
    let insert = summarize(lat);

    // Table select: one full scan, timed as a whole.
    let start = Instant::now();
    let rows = tables
        .select(&mut *engine, &table, None)
        .map_err(|e| e.to_string())?;
    let select_total = start.elapsed();
    if rows.len() != n {
        return Err(format!(
            "bench select: expected {n} rows, got {}",
            rows.len()
        ));
    }

    let ops = |total: Duration| -> f64 {
        if total.as_secs_f64() > 0.0 {
            n as f64 / total.as_secs_f64()
        } else {
            0.0
        }
    };
    Ok(RunMetrics {
        put_ops: ops(put_total),
        put_median_us: put.median_us,
        put_p95_us: put.p95_us,
        put_mean_us: put.mean_us,
        get_ops: ops(get_total),
        get_median_us: get.median_us,
        get_p95_us: get.p95_us,
        get_mean_us: get.mean_us,
        insert_ops: ops(insert_total),
        insert_median_us: insert.median_us,
        insert_p95_us: insert.p95_us,
        insert_mean_us: insert.mean_us,
        select_ms: select_total.as_secs_f64() * 1000.0,
        select_us_per_row: select_total.as_secs_f64() * 1_000_000.0 / n as f64,
    })
}

/// Run the benchmark and print the results. The data directory is
/// a fresh temporary one, removed afterwards (best effort).
pub fn run(rows_list: &[usize]) -> Result<(), String> {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "zeno-bench-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    // M3: the guard owns the temp dir from here on — any return
    // below (Ok, Err, or panic unwind) removes it. It is dropped
    // explicitly at the end of the success path so the result can
    // be reported honestly.
    let bench_dir = BenchTempDir::new(dir.clone());
    let mut engine = Engine::open(&dir).map_err(|e| format!("cannot open bench dir: {e}"))?;
    let mut tables = TableStore::open(&dir).map_err(|e| format!("cannot open tables: {e}"))?;

    let mode = if cfg!(debug_assertions) {
        "debug (NOT representative — build with --release for real numbers)"
    } else {
        "release"
    };
    println!("Zeno bench — own engine only (no PostgreSQL/MongoDB comparison: neither is installed here)");
    println!(
        "  machine : {} / {} — {} CPU(s), {} CPUs available, build: {mode}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        cpu_model(),
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );
    println!(
        "  data dir: {} (fresh temp dir, removed after the run)",
        dir.display()
    );
    println!("  method  : warmup 100 puts + 100 gets, then {RUNS_PER_COUNT} measured runs per row count;");
    println!("            reported numbers are the median of the {RUNS_PER_COUNT} runs — a single sample");
    println!("            varies run to run, so one run's numbers are not a measurement.");
    println!("            KV put = 1 autocommit write (2 WAL fsyncs); values ~60 bytes;");
    println!("            table insert = 1 row (id, name, city); select = full scan, all rows.");

    for &n in rows_list {
        let mut runs = Vec::with_capacity(RUNS_PER_COUNT);
        for run_idx in 0..RUNS_PER_COUNT {
            runs.push(measure_once(&mut engine, &mut tables, n, run_idx)?);
        }
        let m = median_of_runs(&runs);
        println!();
        println!("  rows = {n} (median of {RUNS_PER_COUNT} runs)");
        println!(
            "    KV put       : {:>8.0} ops/s  median {:>8.1} µs  p95 {:>8.1} µs  mean {:>8.1} µs",
            m.put_ops, m.put_median_us, m.put_p95_us, m.put_mean_us
        );
        println!(
            "    KV get       : {:>8.0} ops/s  median {:>8.1} µs  p95 {:>8.1} µs  mean {:>8.1} µs",
            m.get_ops, m.get_median_us, m.get_p95_us, m.get_mean_us
        );
        println!(
            "    table insert : {:>8.0} ops/s  median {:>8.1} µs  p95 {:>8.1} µs  mean {:>8.1} µs",
            m.insert_ops, m.insert_median_us, m.insert_p95_us, m.insert_mean_us
        );
        println!(
            "    table select : {:>8} rows in {:>7.1} ms (full scan, {:.1} µs/row)",
            n, m.select_ms, m.select_us_per_row
        );
    }

    drop(tables);
    drop(engine);
    drop(bench_dir);
    if dir.exists() {
        println!("\nwarning: could not remove bench dir {}", dir.display());
    } else {
        println!("\nbench dir removed: {}", dir.display());
    }
    Ok(())
}

/// Deterministic ~60-byte value for row `i` (so `get` can verify it).
fn bench_value(i: usize) -> String {
    format!("v{i:06}-{}", "x".repeat(48))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_median_and_p95() {
        // 1..=100 µs in nanos: median 50.5 µs, p95 = 95 µs.
        let nanos: Vec<u64> = (1..=100).map(|v| v * 1000).collect();
        let s = summarize(nanos);
        assert!((s.median_us - 50.5).abs() < 1e-9, "median {}", s.median_us);
        assert!((s.p95_us - 95.0).abs() < 1e-9, "p95 {}", s.p95_us);
        assert!((s.mean_us - 50.5).abs() < 1e-9, "mean {}", s.mean_us);
    }

    #[test]
    fn summarize_empty_is_zero() {
        let s = summarize(vec![]);
        assert_eq!(s.median_us, 0.0);
        assert_eq!(s.p95_us, 0.0);
    }

    #[test]
    fn parse_rows_accepts_and_rejects() {
        assert_eq!(parse_rows("100,1000").unwrap(), vec![100, 1000]);
        assert_eq!(parse_rows(" 100 ").unwrap(), vec![100]);
        assert!(parse_rows("0").is_err());
        assert!(parse_rows("100001").is_err());
        assert!(parse_rows("abc").is_err());
        assert!(parse_rows("").is_err());
    }

    #[test]
    fn parse_rows_rejects_duplicates() {
        // M2 (V0.8 review): `--rows 100,100` used to be accepted
        // and then failed mid-run on the duplicate `bench100`
        // table. The error must name the duplicate count.
        let err = parse_rows("100,100").unwrap_err();
        assert!(
            err.contains("duplicate"),
            "error must say duplicate, got: {err}"
        );
        assert!(err.contains("100"), "error must name the count, got: {err}");
        assert!(parse_rows("100,1000,100").is_err());
        assert_eq!(parse_rows("100,200,1000").unwrap(), vec![100, 200, 1000]);
    }

    #[test]
    fn median_of_runs_takes_middle_value_per_field() {
        let mk = |put_ops: f64| RunMetrics {
            put_ops,
            ..RunMetrics::default()
        };
        let m = median_of_runs(&[mk(10.0), mk(30.0), mk(20.0)]);
        assert_eq!(m.put_ops, 20.0);
        assert_eq!(m.get_ops, 0.0);
    }

    #[test]
    fn bench_temp_dir_guard_removes_on_drop() {
        // M3 (V0.8 review): the guard must remove the directory
        // when it drops, whatever happened before.
        let dir =
            std::env::temp_dir().join(format!("zeno-bench-guard-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("probe.txt"), "x").unwrap();
        {
            let _guard = BenchTempDir::new(dir.clone());
        }
        assert!(!dir.exists(), "guard must remove the temp dir on drop");
    }

    #[test]
    fn run_error_path_removes_temp_dir() {
        // M3 (V0.8 review): `run(&[100, 100])` fails at the second
        // iteration (table `bench100-r0` already exists) — the temp
        // dir it created must be gone afterwards anyway. The dir
        // name carries this process's pid, so other test processes
        // running a bench at the same time cannot confuse the
        // check.
        let pid = std::process::id();
        let prefix = format!("zeno-bench-{pid}-");
        let own_dirs = || -> Vec<String> {
            std::fs::read_dir(std::env::temp_dir())
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(&prefix))
                .collect()
        };
        let before = own_dirs();
        let result = run(&[100, 100]);
        assert!(result.is_err(), "duplicate rows must fail, got {result:?}");
        assert_eq!(before, own_dirs(), "error path leaked a bench temp dir");
    }
}

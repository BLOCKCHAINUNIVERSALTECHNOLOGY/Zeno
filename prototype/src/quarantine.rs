// quarantine.rs — numbered quarantine names for corrupt files.
//
// V0.2 overwrote the old quarantine on the next corruption
// (`meta.json.corrupt` was deleted and re-created), so the FIRST
// corrupt file — the one an operator most wants to inspect — could
// silently disappear. V0.3 never overwrites a quarantine: the first
// free numbered name wins (`meta.json.corrupt.1`, then `.corrupt.2`,
// and so on). A quarantine file is never deleted by the engine.
//
// Naming: `<file>.corrupt.<n>` with n starting at 1. The legacy
// unnumbered name (`<file>.corrupt`, V0.2) is still recognised by
// `any_quarantine` so an old quarantine still fails a table open
// closed, but nothing new is ever written under that name.

use std::fs;
use std::path::{Path, PathBuf};

/// First free quarantine path for `base` (a file name, e.g.
/// `"meta.json"`) inside `dir`: `<base>.corrupt.1`, `.corrupt.2`, ...
pub fn next_path(dir: &Path, base: &str) -> PathBuf {
    let mut n: u64 = 1;
    loop {
        let candidate = dir.join(format!("{base}.corrupt.{n}"));
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// Move `path` (which must live in `dir`) to its next free numbered
/// quarantine name. Returns the quarantine path. The original file is
/// gone afterwards; the quarantine is kept for inspection.
pub fn quarantine_file(dir: &Path, path: &Path) -> std::io::Result<PathBuf> {
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let target = next_path(dir, &base);
    fs::rename(path, &target)?;
    Ok(target)
}

/// Any quarantine (numbered or legacy unnumbered) for `base` inside
/// `dir`, if one exists. Used by the table registry's fail-closed
/// check: a leftover quarantine means the registry was lost once and
/// nobody has dealt with it yet.
pub fn any_quarantine(dir: &Path, base: &str) -> Option<PathBuf> {
    // Legacy V0.2 name first, then the numbered names.
    let legacy = dir.join(format!("{base}.corrupt"));
    if legacy.exists() {
        return Some(legacy);
    }
    let prefix = format!("{base}.corrupt.");
    let Ok(entries) = fs::read_dir(dir) else {
        return None;
    };
    let mut found: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(&prefix) && name[prefix.len()..].parse::<u64>().is_ok() {
            found.push(entry.path());
        }
    }
    // m6: sort NUMERICALLY by the suffix, not lexicographically —
    // lexicographic order puts `.corrupt.10` before `.corrupt.2`,
    // so the oldest quarantine would be missed once there are 10+.
    found.sort_by_key(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix(&prefix))
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });
    found.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("zeno-quarantine-test-{name}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn first_quarantine_is_numbered_one() {
        let dir = tmp_dir("first");
        assert_eq!(
            next_path(&dir, "meta.json"),
            dir.join("meta.json.corrupt.1")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quarantine_never_overwrites_the_first_file() {
        let dir = tmp_dir("never-overwrite");
        let target = dir.join("tables.json");
        std::fs::write(&target, "corrupt-one").unwrap();
        let q1 = quarantine_file(&dir, &target).unwrap();
        assert_eq!(q1, dir.join("tables.json.corrupt.1"));
        assert_eq!(std::fs::read_to_string(&q1).unwrap(), "corrupt-one");
        assert!(!target.exists());

        // Corrupt it a second time: the first quarantine must survive.
        std::fs::write(&target, "corrupt-two").unwrap();
        let q2 = quarantine_file(&dir, &target).unwrap();
        assert_eq!(q2, dir.join("tables.json.corrupt.2"));
        assert_eq!(std::fs::read_to_string(&q1).unwrap(), "corrupt-one");
        assert_eq!(std::fs::read_to_string(&q2).unwrap(), "corrupt-two");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn any_quarantine_finds_numbered_and_legacy() {
        let dir = tmp_dir("any");
        assert!(any_quarantine(&dir, "tables.json").is_none());
        std::fs::write(dir.join("tables.json.corrupt.2"), "x").unwrap();
        assert_eq!(
            any_quarantine(&dir, "tables.json"),
            Some(dir.join("tables.json.corrupt.2"))
        );
        std::fs::write(dir.join("tables.json.corrupt"), "legacy").unwrap();
        assert_eq!(
            any_quarantine(&dir, "tables.json"),
            Some(dir.join("tables.json.corrupt"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn any_quarantine_sorts_numerically_not_lexicographically() {
        // m6: `.corrupt.10` sorts BEFORE `.corrupt.2` lexicographically,
        // so the old sort returned the wrong (newer) file once there
        // were 10+ quarantines. Numeric sort must return `.corrupt.2`.
        let dir = tmp_dir("numeric-sort");
        std::fs::write(dir.join("tables.json.corrupt.10"), "x").unwrap();
        std::fs::write(dir.join("tables.json.corrupt.2"), "x").unwrap();
        assert_eq!(
            any_quarantine(&dir, "tables.json"),
            Some(dir.join("tables.json.corrupt.2"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

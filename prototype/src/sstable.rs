// sstable.rs — Sorted String Table: an immutable, sorted file on disk.
//
// File format (plain text, one line per record — easy to inspect):
//   line 1:  ZENO-SSTABLE-1
//   line 2:  hex-encoded Bloom filter bits (see bloom.rs)
//   line 3+: {"k":"<key>","v":"<value>"}   or {"k":"<key>","v":null} for a tombstone
//
// Entries are written in sorted key order. The file is never modified
// after creation; old files are replaced wholesale by compaction.
//
// Honest note: V0.1 loads the whole SSTable into memory on open. That is
// simple and fine for a prototype, but a production engine would keep an
// on-disk index and read only the block it needs.
//
// V0.2: the Bloom filter on line 2 is now sized to the entry count
// (16 bits/key, minimum 1 KiB — see bloom.rs). Old V0.1 files with a
// fixed 1 KiB filter still open: `BloomFilter::from_hex` accepts any size.

use crate::bloom::BloomFilter;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

const MAGIC: &str = "ZENO-SSTABLE-1";

#[derive(Debug, Serialize, Deserialize)]
struct SstEntry {
    k: String,
    v: Option<String>,
}

/// One SSTable file on disk, with its entries and Bloom filter in memory.
#[derive(Debug)]
pub struct SsTable {
    pub path: PathBuf,
    pub id: u64,
    pub entries: BTreeMap<String, Option<String>>,
    pub filter: BloomFilter,
}

/// fsync a directory so a rename inside it survives a crash.
/// Best effort on platforms where opening a directory fails; callers
/// that need the guarantee propagate the error, others ignore it.
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// The SSTable manifest (V0.11, review finding 1): the single
/// commit point for which SSTable files are LIVE.
///
/// File `sst-manifest.json` in the data directory, JSON:
///   {"live":[3,4]}
/// meaning only `sst-000003.sst` and `sst-000004.sst` are part of
/// the database. Written atomically — tmp file + fsync + rename +
/// directory fsync, exactly like `save_meta` — so a crash leaves
/// either the old complete manifest or the new complete one, never
/// a half-written file.
///
/// Why this exists: before V0.11, `compact`/`vacuum` wrote the
/// merged SSTable and then deleted the old files with their errors
/// discarded (`let _ =`). A crash (or a failed unlink) between the
/// new file and the deletions left BOTH generations on disk, and
/// the next open loaded both — a deleted key's old value came back
/// to life, or an old version shadowed the new one. Now the order
/// is: (1) write + sync the new SSTable, (2) atomically commit the
/// manifest naming ONLY the new table, (3) delete the old files,
/// propagating every error, (4) sync the directory, propagating
/// the error. A crash before step 2 reopens the OLD generation
/// (the new file is an orphan, ignored); a crash after step 2
/// reopens the NEW generation (old files still on disk are
/// ignored, because they are not in the manifest). Either way the
/// reopened state is exactly one generation — never a mixture.
///
/// A directory with NO manifest is a pre-V0.11 (legacy) database:
/// every `sst-*.sst` file is live, as before. The first flush /
/// compaction / vacuum after the upgrade writes a manifest, and
/// from then on the manifest rules. Orphan SSTable files (not in
/// the manifest) are ignored on open, never loaded; they waste
/// disk until a later compaction's delete pass, which is safe
/// because nothing references them.
const MANIFEST_FILE: &str = "sst-manifest.json";

#[derive(Debug, Serialize, Deserialize)]
struct SstManifest {
    live: Vec<u64>,
}

/// Path of the manifest file inside `dir`.
pub fn manifest_path(dir: &Path) -> PathBuf {
    dir.join(MANIFEST_FILE)
}

/// Read the manifest, if one exists. `Ok(None)` = no manifest
/// (legacy directory — every SSTable is live). A manifest that
/// exists but does not parse is an ERROR, not a silent fallback
/// to "load everything": falling back would resurrect exactly the
/// deleted data the manifest exists to keep dead.
pub fn read_manifest(dir: &Path) -> std::io::Result<Option<Vec<u64>>> {
    let path = manifest_path(dir);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let manifest: SstManifest = serde_json::from_str(&text).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("corrupt SSTable manifest {}: {e}", path.display()),
        )
    })?;
    Ok(Some(manifest.live))
}

/// Atomically commit a new live set. Errors propagate: the caller
/// must NOT delete old files (or clear the WAL) until this has
/// succeeded — this write IS the commit point.
pub fn write_manifest(dir: &Path, live: &[u64]) -> std::io::Result<()> {
    let path = manifest_path(dir);
    let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
    let text = serde_json::to_string(&SstManifest {
        live: live.to_vec(),
    })
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    fs::write(&tmp_path, &text)?;
    {
        let f = fs::OpenOptions::new().write(true).open(&tmp_path)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &path)?;
    sync_dir(dir)?;
    Ok(())
}

impl SsTable {
    /// Write `entries` (already sorted) to a new SSTable file.
    ///
    /// Atomic: the file is written to `<path>.tmp`, fsynced, renamed
    /// onto the final name, and the directory is fsynced. A crash
    /// mid-write therefore leaves either no file or a complete file —
    /// never a truncated SSTable at the final name. A leftover `.tmp`
    /// file is ignored/deleted by `Engine::open`.
    pub fn write(
        path: &Path,
        id: u64,
        entries: &[(String, Option<String>)],
    ) -> std::io::Result<Self> {
        let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
        match Self::write_inner(&tmp_path, id, entries) {
            Ok(table) => {
                fs::rename(&tmp_path, path)?;
                if let Some(parent) = path.parent() {
                    sync_dir(parent)?;
                }
                Ok(Self {
                    path: path.to_path_buf(),
                    ..table
                })
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                Err(e)
            }
        }
    }

    fn write_inner(
        tmp_path: &Path,
        id: u64,
        entries: &[(String, Option<String>)],
    ) -> std::io::Result<Self> {
        let keys: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
        let filter = BloomFilter::from_keys(&keys);

        let file = File::create(tmp_path)?;
        let mut w = BufWriter::new(file);
        writeln!(w, "{MAGIC}")?;
        writeln!(w, "{}", filter.to_hex())?;
        let mut map = BTreeMap::new();
        for (k, v) in entries {
            let line = serde_json::to_string(&SstEntry {
                k: k.clone(),
                v: v.clone(),
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            writeln!(w, "{line}")?;
            map.insert(k.clone(), v.clone());
        }
        w.flush()?;
        w.get_ref().sync_all()?;
        Ok(Self {
            path: tmp_path.to_path_buf(),
            id,
            entries: map,
            filter,
        })
    }

    /// Open an existing SSTable file and load it.
    pub fn open(path: &Path, id: u64) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim() != MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad SSTable magic in {}", path.display()),
            ));
        }
        line.clear();
        reader.read_line(&mut line)?;
        let filter = BloomFilter::from_hex(line.trim()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad Bloom filter in {}", path.display()),
            )
        })?;
        let mut entries = BTreeMap::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: SstEntry = serde_json::from_str(&line)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            entries.insert(entry.k, entry.v);
        }
        Ok(Self {
            path: path.to_path_buf(),
            id,
            entries,
            filter,
        })
    }

    /// Look up a key. The Bloom filter lets us skip the scan entirely
    /// when the key is definitely absent.
    /// Returns `Some(Some(value))`, `Some(None)` (tombstone), or `None`
    /// (not in this SSTable) — same meaning as `MemTable::get`.
    pub fn get(&self, key: &str) -> Option<Option<String>> {
        if !self.filter.may_contain(key) {
            return None;
        }
        self.entries.get(key).cloned()
    }

    /// All live entries whose key starts with `prefix`, in sorted order.
    /// Tombstones are included (as `None`) so the caller can tell a
    /// deleted key apart from an absent one.
    pub fn scan_prefix(&self, prefix: &str) -> Vec<(String, Option<String>)> {
        self.entries
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// File name for SSTable `id` inside a data directory.
pub fn sstable_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("sst-{id:06}.sst"))
}

/// Extract the numeric id from a file name like `sst-000003.sst`.
pub fn parse_sstable_id(file_name: &str) -> Option<u64> {
    file_name
        .strip_prefix("sst-")?
        .strip_suffix(".sst")?
        .parse::<u64>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        crate::unique_test_dir(&format!("zeno-sst-test-{name}"))
    }

    #[test]
    fn write_then_read_back() {
        let dir = tmp_dir("basic");
        let path = sstable_path(&dir, 1);
        let entries = vec![
            ("a".to_string(), Some("1".to_string())),
            ("b".to_string(), None), // tombstone
            ("c".to_string(), Some("3".to_string())),
        ];
        SsTable::write(&path, 1, &entries).unwrap();
        let table = SsTable::open(&path, 1).unwrap();
        assert_eq!(table.get("a"), Some(Some("1".to_string())));
        assert_eq!(table.get("b"), Some(None));
        assert_eq!(table.get("c"), Some(Some("3".to_string())));
        assert_eq!(table.get("nope"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bloom_skips_absent_keys() {
        let dir = tmp_dir("bloom");
        let path = sstable_path(&dir, 1);
        let entries = vec![("only-key".to_string(), Some("v".to_string()))];
        let table = SsTable::write(&path, 1, &entries).unwrap();
        assert!(!table.filter.may_contain("something-else-entirely"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

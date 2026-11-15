// lock.rs — one process at a time per data directory (V0.2).
//
// Method chosen: a `LOCK` file holding the owner process's PID,
// created with `O_EXCL` (`create_new`), std-only — no `libc` crate,
// no `flock` (which is advisory, per-fd, and silently released on
// process exit in ways that are easy to misuse from a short-lived CLI
// that opens the engine many times). Why PID + O_EXCL instead of flock:
// the PID file survives as plain evidence on disk, a second process
// can tell WHO holds the lock, and — the important part — a stale lock
// left by a `kill -9` can be told apart from a live one.
//
// How it works:
// - `acquire` tries `create_new("LOCK")`. If it wins, it writes its own
//   PID, fsyncs, and — the part that closes the V0.2 race — RE-READS
//   the file and checks it still holds its own PID before returning.
//   Between `create_new` and the PID write the file is empty, and a
//   contender that deleted that empty file in the meantime would have
//   unlinked the winner's inode: the winner's write then lands in an
//   unlinked file and a second process could also hold "the" lock.
//   The re-read catches exactly that: if the file is gone, or holds a
//   different PID, acquisition FAILS instead of returning a lock that
//   is not really held.
// - If the file already exists, the PID inside is read and checked
//   against Linux `/proc/<pid>`: if that process is alive, open fails
//   with "data directory already in use / locked by another process".
// - If the PID is dead, the lock is stale: it is removed and
//   acquisition is retried. Two processes racing to take over a stale
//   lock cannot both win, because only one `create_new` succeeds.
// - An empty or unparseable file is NOT deleted at once. It may be a
//   live creator between `create_new` and its PID write, so a
//   contender polls it (20 ms at a time) until a PID appears or the
//   file has stayed empty/unparseable for at least ~100 ms (its mtime
//   is that old) — only then is it treated as torn and taken over.
//   A genuinely torn file left by a crash has an old mtime, so it is
//   taken over after one poll; a live creator normally writes its PID
//   within a millisecond, so the contender sees a live PID and fails
//   fast. And even if a contender ever deletes a live creator's file
//   too early, the creator's re-read verify fails it — so at most one
//   process can ever hold the lock.
// - `Drop` removes the file, but only if it still contains our PID,
//   so we never delete another process's live lock.
//
// Honest limits: this is a single-machine, same-OS check. It does not
// protect a data directory shared over NFS (where `/proc` of another
// machine is invisible), and a PID can in theory be reused by an
// unrelated process after the owner dies — in that rare case a stale
// lock would look live until that process also exits. The lock also
// only guards `Engine::open`; anything that edits the directory by
// hand bypasses it, as with any lock file.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long an empty/unparseable LOCK file must have stayed that way
/// (judged by its mtime) before a contender may treat it as torn.
/// A live creator writes its PID within ~1 ms of creating the file,
/// so 100 ms is a wide margin; a torn file from a crash is normally
/// far older than this and is taken over after a single poll.
const TORN_SETTLE_MS: u64 = 100;
/// Poll interval while waiting for a possibly-live creator to write
/// its PID into a fresh LOCK file.
const TORN_POLL_MS: u64 = 20;
/// Maximum polls per contender attempt (10 x 20 ms = 200 ms, past the
/// settle threshold even if the mtime clock is coarse).
const TORN_MAX_POLLS: u32 = 10;

/// Name of the lock file inside the data directory.
pub const LOCK_FILE_NAME: &str = "LOCK";

/// A held directory lock. Dropping it releases the lock.
#[derive(Debug)]
pub struct DirLock {
    path: PathBuf,
    pid: u32,
}

fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // On Linux, /proc/<pid> exists exactly while the process lives.
    Path::new(&format!("/proc/{pid}")).exists()
}

fn read_lock_pid(path: &Path) -> Option<u32> {
    let text = fs::read_to_string(path).ok()?;
    text.trim().parse::<u32>().ok()
}

/// What a contender found after waiting on an empty/unparseable LOCK.
enum LockContent {
    /// A PID appeared while polling (live, dead, or our own — the
    /// caller decides what it means).
    Pid(u32),
    /// The file vanished while polling (someone else took it over or
    /// released it): retry `create_new`.
    Gone,
    /// Still empty/unparseable after the settle wait: a torn write
    /// from a crash mid-create, safe to take over.
    Torn,
}

/// Poll an empty/unparseable LOCK file: a live creator writes its PID
/// almost immediately after `create_new`, so wait a little before
/// concluding the file is torn. Returns `Pid` as soon as a valid PID
/// shows up, `Gone` if the file disappears, and `Torn` only once the
/// file has stayed empty/unparseable for at least `TORN_SETTLE_MS`
/// (judged by its mtime — a crash-torn file is normally far older
/// than that, so it settles after one poll) or the poll budget runs
/// out (200 ms, still past the settle threshold for any file that
/// has not been rewritten in the meantime).
fn wait_for_lock_content(path: &Path) -> LockContent {
    for _ in 0..TORN_MAX_POLLS {
        std::thread::sleep(Duration::from_millis(TORN_POLL_MS));
        if let Some(pid) = read_lock_pid(path) {
            return LockContent::Pid(pid);
        }
        match fs::metadata(path) {
            Err(_) => return LockContent::Gone,
            Ok(meta) => match meta.modified() {
                Ok(modified) => match modified.elapsed() {
                    Ok(age) if age >= Duration::from_millis(TORN_SETTLE_MS) => {
                        return LockContent::Torn;
                    }
                    Ok(_) => {}  // too fresh: keep polling
                    Err(_) => {} // mtime in the future: keep polling
                },
                Err(_) => return LockContent::Torn,
            },
        }
    }
    LockContent::Torn
}

impl DirLock {
    /// Acquire the lock for `dir`, creating the directory if needed.
    /// Fails if another live process holds it.
    pub fn acquire(dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join(LOCK_FILE_NAME);
        let pid = std::process::id();
        // A few retries cover the stale-takeover race (remove + recreate).
        for _ in 0..10 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    writeln!(file, "{pid}")?;
                    file.sync_all()?;
                    drop(file);
                    // VERIFY: re-read the file and check it still holds
                    // our PID. If a contender deleted our still-empty
                    // file in the create/write window and created its
                    // own, our write went to an unlinked inode and the
                    // path now holds someone else's PID (or nothing):
                    // fail instead of returning a lock we do not hold.
                    return match read_lock_pid(&path) {
                        Some(owner) if owner == pid => Ok(Self { path, pid }),
                        Some(owner) => Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            format!(
                                "lost the lock race: LOCK is now held by pid {owner}; \
                                 data directory already in use"
                            ),
                        )),
                        None => Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "lost the lock race: LOCK file was removed or replaced \
                             before our PID was visible; data directory already in use",
                        )),
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    match read_lock_pid(&path) {
                        Some(owner) if owner == pid => {
                            // Our own PID in the file: this process already
                            // holds it (e.g. a second open in-process).
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                "data directory already in use / locked by this process",
                            ));
                        }
                        Some(owner) if pid_alive(owner) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                format!(
                                    "data directory already in use / locked by another \
                                     process (pid {owner}); open the same data directory \
                                     from only one process at a time"
                                ),
                            ));
                        }
                        Some(_) => {
                            // Dead owner: stale, take it over. If the
                            // file vanished in the meantime, the next
                            // loop iteration retries create_new.
                            let _ = fs::remove_file(&path);
                            continue;
                        }
                        None => {
                            // Empty or unparseable: do NOT delete at
                            // once — it may be a live creator between
                            // create_new and its PID write. Poll until
                            // a PID appears, the file vanishes, or it
                            // has stayed empty/unparseable past the
                            // settle threshold (then it is torn).
                            match wait_for_lock_content(&path) {
                                LockContent::Pid(owner) if owner == pid => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::AlreadyExists,
                                        "data directory already in use / locked by this process",
                                    ));
                                }
                                LockContent::Pid(owner) if pid_alive(owner) => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::AlreadyExists,
                                        format!(
                                            "data directory already in use / locked by another \
                                             process (pid {owner}); open the same data directory \
                                             from only one process at a time"
                                        ),
                                    ));
                                }
                                LockContent::Pid(_) => {
                                    // A PID appeared but its owner is
                                    // dead: stale, take it over.
                                    let _ = fs::remove_file(&path);
                                    continue;
                                }
                                LockContent::Gone => continue, // retry create_new
                                LockContent::Torn => {
                                    let _ = fs::remove_file(&path);
                                    continue;
                                }
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "data directory already in use / locked by another process \
             (could not acquire lock after retries)",
        ))
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        // Only remove the file if it is still ours — never delete a
        // lock another process has since taken over.
        if read_lock_pid(&self.path) == Some(self.pid) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("zeno-lock-test-{name}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn second_acquire_fails_while_first_held() {
        let dir = tmp_dir("held");
        let _first = DirLock::acquire(&dir).unwrap();
        let err = DirLock::acquire(&dir).expect_err("second acquire must fail");
        assert!(
            err.to_string().contains("already in use"),
            "error must say the directory is in use: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = tmp_dir("drop");
        {
            let _lock = DirLock::acquire(&dir).unwrap();
        }
        assert!(!dir.join(LOCK_FILE_NAME).exists(), "lock file must be gone");
        let _again = DirLock::acquire(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_lock_from_dead_pid_is_taken_over() {
        let dir = tmp_dir("stale");
        // A real, now-dead process: spawn `true`, wait for it, reuse its PID.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn `true`");
        let dead_pid = child.id();
        child.wait().unwrap();
        assert!(!pid_alive(dead_pid), "test setup: pid must be dead");
        fs::write(dir.join(LOCK_FILE_NAME), format!("{dead_pid}\n")).unwrap();
        let _lock = DirLock::acquire(&dir).expect("stale lock must be taken over");
        assert_eq!(
            read_lock_pid(&dir.join(LOCK_FILE_NAME)),
            Some(std::process::id())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_lock_file_is_taken_over() {
        let dir = tmp_dir("torn");
        fs::write(dir.join(LOCK_FILE_NAME), "not-a-pid").unwrap();
        let _lock = DirLock::acquire(&dir).expect("torn lock file must not block open");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

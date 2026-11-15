// auth.rs — SCRAM-SHA-256 password auth (RFC 5802, RFC 7677) for
// `zeno serve`, plus the `users.json` credential store.
//
// How it works, in one paragraph: a password is NEVER stored —
// not even hashed in a reversible way. `zeno user set-password`
// runs PBKDF2-HMAC-SHA256 (4096 iterations, random 16-byte salt)
// over the password and keeps only the SCRAM verifier material:
// SaltedPassword -> ClientKey -> StoredKey = SHA-256(ClientKey),
// and ServerKey = HMAC(SaltedPassword, "Server Key"). At login
// the server sends a challenge (salt + iterations + a fresh
// nonce); the client proves it knows the password by sending a
// proof derived from the StoredKey, never the password itself;
// the server then proves IT knows the ServerKey back to the
// client (mutual authentication). An attacker who steals
// `users.json` gets StoredKey/ServerKey, which are enough to
// impersonate the server but NOT to recover the password or to
// log in as the client without breaking SHA-256 — that is the
// point of SCRAM, and why a stolen verifier is far less bad than
// a stolen password hash.
//
// When auth is on (see below), the flow after the StartupMessage
// is:
//   server -> AuthenticationSASL 'R'(10) ["SCRAM-SHA-256"]
//   client -> SASLInitialResponse 'p' (client-first-message)
//   server -> AuthenticationSASLContinue 'R'(11) (server-first)
//   client -> SASLResponse 'p' (client-final-message)
//   server -> AuthenticationSASLFinal 'R'(12) (server-final)
//   server -> AuthenticationOk 'R'(0)   (sent by pgwire.rs)
// On any failure the server sends ErrorResponse 28P01
// (invalid_password) and closes the connection.
//
// When auth is OFF — `users.json` missing — the server
// uses trust auth (any local client, no password), exactly like
// V0.3. An EMPTY (0-byte) `users.json` is NOT "no users": it is
// corrupt JSON, and the server fails closed (see below). The
// switch is per-connection: `users.json` is re-read on every
// handshake, so `zeno user set-password` applies to NEW
// connections at once, without restarting the server. A CORRUPT
// users.json fails the connection (and fails `serve` at startup)
// instead of silently falling back to trust auth — silently
// switching password auth off would be a security hole.
//
// Unknown users get a FAKE exchange (a salt and stored key
// derived deterministically from the username and a per-data-dir
// server secret — see `fake_credentials`) that still ends in
// 28P01, so an attacker cannot tell whether a username exists by
// watching the handshake — the same trick PostgreSQL uses. The
// fake salt is the SAME on every handshake for the same username
// (and different for different usernames): a salt that changed on
// every connection would itself leak that the user is unknown.
//
// Passwords go through SASLprep (RFC 4013) before PBKDF2, on
// BOTH sides — `set_password` and the client computation in
// `scram_client_response` — so a libpq-style client that
// SASLpreps (e.g. mapping U+00A0 NO-BREAK SPACE to a plain space)
// logs in with the same verifier. See `saslprep` below.
//
// Honest limits (see README too): without `--tls` there is no
// SSL, so SCRAM still runs over a plaintext loopback connection
// — a local eavesdropper could capture the exchange, but SCRAM's
// proof cannot be replayed (the nonce is fresh every time) and
// the password never crosses the wire. With `--tls` the exchange
// runs inside TLS 1.2/1.3 (see `tls.rs`), but the certificate is
// self-signed — prototype only, a real CA cert is needed for
// production. No channel binding (a client that demands
// `p=tls-server-end-point` is rejected); PBKDF2 at 4096
// iterations is PostgreSQL's default — deliberately modest for a
// prototype; it is not a replacement for a strong password. The
// login rate limiter is in-memory: a server restart resets all
// failure counts and lockouts.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;

type HmacSha256 = Hmac<Sha256>;

/// File in the data directory holding the SCRAM verifiers.
pub const USERS_FILE: &str = "users.json";
/// File in the data directory holding the per-data-dir server
/// secret (32 random bytes) that makes the fake exchange for
/// unknown users deterministic. Mode 0600, like `users.json`.
pub const SERVER_SECRET_FILE: &str = "server-secret";
/// PBKDF2 iterations (PostgreSQL's default for SCRAM-SHA-256).
const ITERATIONS: u32 = 4096;
/// Minimum password length for `set_password` (characters, counted
/// AFTER SASLprep — a 1-character password is never accepted).
const MIN_PASSWORD_LEN: usize = 8;
/// Minimum client nonce length in the SCRAM client-first message
/// (characters). A 1-character nonce has almost no entropy and is
/// rejected as malformed (08P01).
const MIN_CLIENT_NONCE_LEN: usize = 8;
/// Random salt bytes per user.
const SALT_LEN: usize = 16;
/// Random bytes for each SCRAM server nonce.
const SERVER_NONCE_LEN: usize = 18;
/// Lock file serializing concurrent `set-password` / `remove`
/// read-modify-write cycles on `users.json` (see
/// `acquire_users_lock` below). A separate file from the data-dir
/// `LOCK`: the server holds the data-dir lock while running, and
/// `zeno user` must still work while it runs.
pub const USERS_LOCK_FILE: &str = "users.lock";
/// How long `set-password` / `remove` wait for the users lock
/// before giving up (the lock is held only for one PBKDF2 + one
/// atomic write, so a few seconds is plenty).
const USERS_LOCK_WAIT: Duration = Duration::from_secs(10);
/// Consecutive failed logins before a user/IP is locked out.
pub const MAX_LOGIN_FAILURES: u32 = 5;
/// How long a lockout lasts.
pub const LOGIN_LOCKOUT: Duration = Duration::from_secs(5 * 60);
/// Constant delay before EVERY failed-login answer (M3): the 1st
/// wrong password waits exactly as long as the 5th, and a
/// locked-out login waits exactly as long as a fresh one. The old
/// progressive delay (100 ms, 200 ms, …) leaked the lockout state
/// through timing — a locked login always took 2.0 s while a fresh
/// wrong password took 0.1 s — so an attacker could tell a locked
/// account from a fresh one by measuring. A constant delay also
/// keeps the per-attempt guessing cost at the maximum from the
/// first failure, not only after several.
const LOGIN_DELAY_MAX: Duration = Duration::from_secs(2);
/// Cap on tracked `user@IP` keys (m1): without one, an attacker
/// probing a new username@IP on every attempt could grow the
/// in-memory map without bound. At the cap, stale (unlocked)
/// entries are purged first; active lockouts are never dropped
/// by the purge (dropping a lockout would let an attacker
/// un-lock an account by flooding the map).
const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;

// ---------------------------------------------------------------------
// SCRAM login rate limiting / lockout (V0.5).
//
// One `LoginRateLimiter` lives in the server process (in
// `pgwire::Shared`) and is shared by all connections. It is
// deliberately IN-MEMORY: a server restart resets every counter
// (see the README — a persistent lockout store is future work).
// The key is `username@ip`, so locking one user never locks
// another, and the same username from a different IP starts
// fresh.
//
// Anti-enumeration: a locked-out login runs the EXACT same
// handshake as an unknown user (same server-first, same 28P01,
// same connection close) — and waits the SAME constant delay
// before the error as any wrong password (M3), so the timing
// leaks nothing either. A correct password during lockout still
// fails: the lockout must not be bypassable by guessing right.
// Attempts DURING a lockout do not extend it (otherwise an
// attacker could keep an account locked forever by knocking
// once a minute); the lockout ends a fixed 5 minutes after the
// failure that triggered it, and the next failure after expiry
// starts a fresh allowance.
// ---------------------------------------------------------------------

struct AttemptState {
    failures: u32,
    locked_until: Option<Instant>,
}

/// In-memory SCRAM rate limiter. See the module docs above for the
/// policy. `with_policy` exists so the unit tests can use short
/// lockouts instead of waiting out the real 5 minutes.
pub struct LoginRateLimiter {
    inner: Mutex<HashMap<String, AttemptState>>,
    max_failures: u32,
    lockout: Duration,
    delay_max: Duration,
    max_entries: usize,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self::with_policy(
            MAX_LOGIN_FAILURES,
            LOGIN_LOCKOUT,
            LOGIN_DELAY_MAX,
            MAX_RATE_LIMIT_ENTRIES,
        )
    }
    pub fn with_policy(
        max_failures: u32,
        lockout: Duration,
        delay_max: Duration,
        max_entries: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_failures,
            lockout,
            delay_max,
            max_entries,
        }
    }

    /// The limiter key: the SCRAM username plus the peer IP.
    pub fn key(username: &str, peer_ip: &str) -> String {
        format!("{username}@{peer_ip}")
    }

    /// True while this key is locked out. An expired lockout is
    /// cleared here, so the next failure after expiry starts a
    /// fresh allowance instead of re-locking at once.
    pub fn is_locked(&self, key: &str) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.get(key) {
            Some(state) => match state.locked_until {
                Some(until) if until > Instant::now() => true,
                Some(_) => {
                    inner.remove(key);
                    false
                }
                None => false,
            },
            None => false,
        }
    }

    /// Record a failed login. Returns `delay_max` — ALWAYS, on
    /// every failure (M3): a constant delay, so the wait before
    /// 28P01 can never reveal whether this key is fresh, has
    /// failed before, or is locked out. Reaching `max_failures`
    /// locks the key until `lockout` has passed.
    pub fn record_failure(&self, key: &str) -> Duration {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // m1: bound the map. At the cap, drop every entry that is
        // NOT currently locked (a dropped failure count only gives
        // that key a fresh allowance — it never drops a lockout).
        // If the map is still at the cap (all entries locked),
        // evict one arbitrary entry so the map cannot grow past
        // the cap at all.
        if inner.len() >= self.max_entries {
            Self::purge_unlocked(&mut inner);
            if inner.len() >= self.max_entries {
                if let Some(k) = inner.keys().next().cloned() {
                    inner.remove(&k);
                }
            }
        }
        let state = inner.entry(key.to_string()).or_insert(AttemptState {
            failures: 0,
            locked_until: None,
        });
        // A lockout that already expired must not make the next
        // single failure re-lock at once: start fresh.
        if let Some(until) = state.locked_until {
            if until <= Instant::now() {
                state.failures = 0;
                state.locked_until = None;
            }
        }
        state.failures += 1;
        if state.failures >= self.max_failures {
            state.locked_until = Some(Instant::now() + self.lockout);
        }
        self.delay_max
    }

    /// Drop every entry that is not currently locked out (m1
    /// helper for `record_failure`). Locked entries are kept:
    /// dropping one would silently un-lock that account.
    fn purge_unlocked(map: &mut HashMap<String, AttemptState>) {
        let now = Instant::now();
        map.retain(|_, state| matches!(state.locked_until, Some(until) if until > now));
    }

    /// Number of tracked keys (for tests of the m1 entry cap).
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Record a successful login: the key's failures are forgotten.
    pub fn record_success(&self, key: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.remove(key);
    }

    /// How long a locked-out login waits before its (identical)
    /// 28P01, so the wait itself does not distinguish "locked"
    /// from "wrong password after several failures".
    pub fn locked_delay(&self) -> Duration {
        self.delay_max
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Take the users lock, waiting (not failing) while another
/// `set-password` / `remove` process holds it. The lock is held
/// only for one PBKDF2 + one atomic write, so the wait is
/// normally a few milliseconds; 10 seconds is the give-up.
fn acquire_users_lock(dir: &Path) -> std::io::Result<crate::lock::DirLock> {
    let deadline = Instant::now() + USERS_LOCK_WAIT;
    loop {
        match crate::lock::DirLock::acquire_named(dir, USERS_LOCK_FILE) {
            Ok(lock) => return Ok(lock),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if Instant::now() >= deadline {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
}

/// One user's SCRAM verifier material. NOTHING here can be turned
/// back into the password: StoredKey is SHA-256 of the ClientKey,
/// and the SaltedPassword itself is never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScramCredentials {
    /// Base64 salt (16 random bytes).
    pub salt: String,
    /// PBKDF2 iterations.
    pub iterations: u32,
    /// Base64 StoredKey = SHA-256(HMAC(SaltedPassword, "Client Key")).
    pub stored_key: String,
    /// Base64 ServerKey = HMAC(SaltedPassword, "Server Key").
    pub server_key: String,
}

fn users_path(dir: &Path) -> PathBuf {
    dir.join(USERS_FILE)
}

/// Load the users map. A missing file means "no users yet" (trust
/// auth). A corrupt file is an ERROR — fail closed, never silently
/// trust auth (see module docs).
pub fn load_users(dir: &Path) -> std::io::Result<HashMap<String, ScramCredentials>> {
    match fs::read_to_string(users_path(dir)) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("corrupt {USERS_FILE}: {e}"),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(e),
    }
}

/// Atomic write of the users map: temp file + fsync + rename +
/// directory fsync, the same pattern as `tables.json` and
/// `meta.json` — a crash mid-save cannot leave a half-written
/// `users.json`. The file (and its `.tmp`) is explicitly mode
/// 0600 — the verifier material must never be world-readable, so
/// the mode does NOT depend on the process umask (under umask 022
/// a plain `fs::write` would leave 0644).
fn save_users(dir: &Path, users: &HashMap<String, ScramCredentials>) -> std::io::Result<()> {
    let path = users_path(dir);
    let text = serde_json::to_string_pretty(users)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let tmp_path = path.with_extension("json.tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        // `create` keeps a pre-existing file's mode, so set it
        // explicitly even though the open above asked for 0600.
        set_mode_0600(&tmp_path)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp_path, &text)?;
        let f = fs::OpenOptions::new().write(true).open(&tmp_path)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &path)?;
    #[cfg(unix)]
    set_mode_0600(&path)?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(buf)
}

fn check_username(username: &str) -> Result<(), String> {
    if username.is_empty() {
        return Err("username must not be empty".to_string());
    }
    if username.len() > 63 {
        return Err("username must be at most 63 characters".to_string());
    }
    if username.bytes().any(|b| b == 0 || b == b'=' || b == b',') {
        return Err("username must not contain NUL, '=' or ',' (SCRAM escaping)".to_string());
    }
    Ok(())
}

/// SASLprep (RFC 4013) for passwords: map, normalize, prohibit.
///
/// 1. Mapping (RFC 3454 Table B.1): NO-BREAK SPACE and the other
///    "space-like" characters map to a plain ASCII space U+0020.
///    This is the step that makes a libpq-style client work: libpq
///    SASLpreps the password, so a password set as "a\u{a0}b"
///    (NBSP) must verify as "a b".
/// 2. Normalization: NFKC (via the `unicode-normalization` crate).
/// 3. Prohibition (RFC 3454 Tables C.1.2, C.2.1, C.2.2, C.3, C.4,
///    C.6, C.7, C.8, C.9): control characters, private-use,
///    non-characters, deprecated/display-changing and tagging
///    characters are rejected. (Table C.5 surrogates cannot occur
///    in a Rust `str` at all.)
/// 4. Bidirectional check (RFC 3454 §6, simplified): if the
///    password contains a right-to-left character (Hebrew/Arabic
///    ranges), it must contain no ASCII letter or digit and must
///    start and end with a right-to-left character.
///
/// Both `set_password` and `scram_client_response` call this, so
/// the stored verifier and the client's proof are always computed
/// from the same prepared password. A password that fails SASLprep
/// is rejected at `set-password` time with a clear error — never
/// silently stored in a form the client cannot reproduce.
pub fn saslprep(password: &str) -> Result<String, String> {
    // Step 1: map Table B.1 characters to U+0020.
    let mapped: String = password
        .chars()
        .map(|c| {
            if matches!(
                c,
                '\u{00a0}' // NO-BREAK SPACE
                | '\u{1680}' // OGHAM SPACE MARK
                | '\u{2000}'
                    ..='\u{200b}' // EN QUAD .. ZERO WIDTH SPACE
                | '\u{202f}' // NARROW NO-BREAK SPACE
                | '\u{205f}' // MEDIUM MATHEMATICAL SPACE
                | '\u{3000}' // IDEOGRAPHIC SPACE
            ) {
                ' '
            } else {
                c
            }
        })
        .collect();
    // Step 2: NFKC.
    let normalized: String = mapped.nfkc().collect();
    // Step 3: prohibited output.
    for c in normalized.chars() {
        if saslprep_prohibited(c) {
            return Err(format!(
                "password contains a character prohibited by SASLprep (U+{:04X})",
                c as u32
            ));
        }
    }
    // Step 4: bidirectional check (simplified, see above).
    let has_ral = normalized.chars().any(is_rand_al_cat);
    if has_ral {
        let first = normalized.chars().next().unwrap_or(' ');
        let last = normalized.chars().last().unwrap_or(' ');
        if !is_rand_al_cat(first)
            || !is_rand_al_cat(last)
            || normalized.chars().any(|c| c.is_ascii_alphanumeric())
        {
            return Err(
                "password mixes right-to-left characters with left-to-right characters (SASLprep bidirectional rule)"
                    .to_string(),
            );
        }
    }
    Ok(normalized)
}

/// True for a character in one of the RFC 3454 prohibited tables
/// listed in `saslprep` (C.1.2 is already mapped away in step 1,
/// so it is not listed here).
fn saslprep_prohibited(c: char) -> bool {
    let cp = c as u32;
    matches!(cp,
        // C.2.1 ASCII control.
        0x0000..=0x001f | 0x007f
        // C.2.2 non-ASCII control.
        | 0x0080..=0x009f | 0x06dd | 0x070f | 0x180e | 0x200c | 0x200d
        | 0x2028 | 0x2029 | 0x2060..=0x2064 | 0x206a..=0x206f
        | 0xfeff | 0xfff9..=0xfffb | 0x1d173..=0x1d17a | 0xe0001
        | 0xe0020..=0xe007f
        // C.3 private use.
        | 0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x100000..=0x10fffd
        // C.4 non-characters: U+FDD0..U+FDEF and U+xFFFE/U+xFFFF.
        | 0xfdd0..=0xfdef | 0xfffe | 0xffff
        | 0x1fffe | 0x1ffff | 0x2fffe | 0x2ffff | 0x3fffe | 0x3ffff
        | 0x4fffe | 0x4ffff | 0x5fffe | 0x5ffff | 0x6fffe | 0x6ffff
        | 0x7fffe | 0x7ffff | 0x8fffe | 0x8ffff | 0x9fffe | 0x9ffff
        | 0xafffe | 0xaffff | 0xbfffe | 0xbffff | 0xcfffe | 0xcffff
        | 0xdfffe | 0xdffff | 0xefffe | 0xeffff | 0xffffe | 0xfffff
        | 0x10fffe | 0x10ffff
        // C.6 inappropriate for plain text, C.7 inappropriate for
        // canonical representation, C.8 change display properties
        // or deprecated (union of the three tables).
        | 0x0340 | 0x0341 | 0x200e | 0x200f | 0x202a..=0x202e
        | 0x2ff0..=0x2ffb | 0xfff9..=0xfffd)
}

/// Right-to-left (RandALCat) characters, RFC 3454 Table D.1:
/// Hebrew and Arabic blocks (simplified to the block ranges).
fn is_rand_al_cat(c: char) -> bool {
    matches!(c as u32,
        0x0590..=0x05ff // Hebrew
        | 0x0600..=0x06ff // Arabic
        | 0x0750..=0x077f // Arabic Supplement
        | 0x08a0..=0x08ff // Arabic Extended-A
        | 0xfb50..=0xfdff // Arabic Presentation Forms-A
        | 0xfe70..=0xfeff) // Arabic Presentation Forms-B
}

/// Load the per-data-dir server secret (32 random bytes), creating
/// it on first use. The secret makes the fake SCRAM exchange for
/// unknown users deterministic (see `fake_credentials`) while
/// staying secret: the file is mode 0600, and it is created with
/// `create_new` so two processes racing to create it do not
/// silently overwrite each other's secret. A file with the wrong
/// length is replaced (at most a few tries, then an error).
fn load_or_create_server_secret(dir: &Path) -> std::io::Result<[u8; 32]> {
    let path = dir.join(SERVER_SECRET_FILE);
    if let Ok(bytes) = fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes.try_into().expect("length checked"));
        }
    }
    for _ in 0..3 {
        #[cfg(unix)]
        let opened = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
        };
        #[cfg(not(unix))]
        let opened = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path);
        match opened {
            Ok(mut f) => {
                let secret = random_bytes(32)?;
                f.write_all(&secret)?;
                f.sync_all()?;
                #[cfg(unix)]
                set_mode_0600(&path)?;
                return Ok(secret.try_into().expect("32 random bytes"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Ok(bytes) = fs::read(&path) {
                    if bytes.len() == 32 {
                        return Ok(bytes.try_into().expect("length checked"));
                    }
                }
                // Wrong length (or unreadable) — but do NOT delete
                // it blindly (m2): the file may belong to a
                // concurrent creator that opened it with
                // `create_new` a moment ago and has not finished
                // writing its 32 bytes yet. The old code removed
                // the file here, so the loser could delete the
                // winner's secret mid-write and both threads would
                // then disagree about the secret. Only a STALE
                // wrong-length file (older than 5 s — a crashed
                // creator's partial write) is removed; a fresh one
                // is left alone and re-read on the next retry.
                let stale = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .map(|t| t.elapsed().unwrap_or(Duration::ZERO) > Duration::from_secs(5))
                    .unwrap_or(true);
                if stale {
                    let _ = fs::remove_file(&path);
                } else {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(
        "could not create a valid server-secret file",
    ))
}

/// Set (or replace) a user's password. The password itself is
/// never written anywhere: only the salt + StoredKey + ServerKey
/// land in `users.json`. The users file is written atomically, so
/// a server that re-reads it per connection never sees a torn
/// write. The password is SASLprep'd first (RFC 4013), then must
/// be at least 8 characters — a 1-character password is rejected
/// with a clear error. A nonexistent data directory is created
/// (instead of failing with a cryptic "No such file or directory").
pub fn set_password(dir: &Path, username: &str, password: &str) -> Result<(), String> {
    check_username(username)?;
    let password = saslprep(password)?;
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    fs::create_dir_all(dir)
        .map_err(|e| format!("cannot create data directory {}: {e}", dir.display()))?;
    // Serialize with any concurrent `set-password` / `remove`:
    // without this lock two processes can both load the same
    // `users.json`, each add their own user, and the second save
    // silently drops the first user's entry. The guard is held
    // until the save below, then released on drop.
    let _users_lock = acquire_users_lock(dir).map_err(|e| e.to_string())?;
    let salt = random_bytes(SALT_LEN).map_err(|e| e.to_string())?;
    let salted = salted_password(password.as_bytes(), &salt, ITERATIONS);
    let creds = ScramCredentials {
        salt: B64.encode(&salt),
        iterations: ITERATIONS,
        stored_key: B64.encode(stored_key(&client_key(&salted))),
        server_key: B64.encode(server_key(&salted)),
    };
    let mut users = load_users(dir).map_err(|e| e.to_string())?;
    users.insert(username.to_string(), creds);
    save_users(dir, &users).map_err(|e| e.to_string())?;
    Ok(())
}

/// Remove a user. Returns true when a user was actually removed.
/// Removing the LAST user switches the server back to trust auth
/// for new connections — that is by design (no users = no auth),
/// so the CLI prints a warning when it happens (see main.rs).
pub fn remove_user(dir: &Path, username: &str) -> Result<bool, String> {
    // Same lock as `set_password`: the read-modify-write must be
    // atomic against a concurrent password set, or the removal can
    // be silently undone by the other process's save.
    let _users_lock = acquire_users_lock(dir).map_err(|e| e.to_string())?;
    let mut users = load_users(dir).map_err(|e| e.to_string())?;
    let removed = users.remove(username).is_some();
    if removed {
        save_users(dir, &users).map_err(|e| e.to_string())?;
    }
    Ok(removed)
}

/// Sorted usernames, for `zeno user list`. No secrets are printed.
pub fn list_users(dir: &Path) -> Result<Vec<String>, String> {
    let users = load_users(dir).map_err(|e| e.to_string())?;
    let mut names: Vec<String> = users.keys().cloned().collect();
    names.sort();
    Ok(names)
}

// ---------------------------------------------------------------------
// Pure SCRAM math (RFC 5802 / RFC 7677). Every step here is covered
// by the RFC 7677 test vectors in the unit tests below.
// ---------------------------------------------------------------------

fn salted_password(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

fn client_key(salted: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(salted, b"Client Key")
}

fn stored_key(client_key: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(client_key).into()
}

fn server_key(salted: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(salted, b"Server Key")
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Escape a SCRAM username: `=` -> `=3D`, `,` -> `=2C` (RFC 5802).
/// Public so a client can build its client-first message (see
/// `scram_client_response`); the server only ever un-escapes.
pub fn escape_username(username: &str) -> String {
    let mut out = String::with_capacity(username.len());
    for c in username.chars() {
        match c {
            '=' => out.push_str("=3D"),
            ',' => out.push_str("=2C"),
            other => out.push(other),
        }
    }
    out
}

/// Un-escape a SCRAM username (`=3D` -> `=`, `=2C` -> `,`).
fn unescape_username(escaped: &str) -> String {
    escaped.replace("=2C", ",").replace("=3D", "=")
}

/// Verify a client's proof against stored verifier material.
/// `auth_message` is `client-first-bare + "," + server-first +
/// "," + client-final-without-proof`. Returns true only when the
/// proof reproduces the StoredKey — compared in constant time.
fn verify_proof(creds: &ScramCredentials, auth_message: &str, proof: &[u8]) -> bool {
    let Ok(stored) = B64.decode(&creds.stored_key) else {
        return false;
    };
    if stored.len() != 32 || proof.len() != 32 {
        return false;
    }
    let stored: [u8; 32] = stored.try_into().expect("length checked");
    let proof: [u8; 32] = proof.try_into().expect("length checked");
    let client_signature = hmac_sha256(&stored, auth_message.as_bytes());
    let recovered_client_key = xor32(&proof, &client_signature);
    let recovered_stored_key = stored_key(&recovered_client_key);
    recovered_stored_key.ct_eq(&stored).unwrap_u8() == 1
}

/// The server's proof back to the client (AuthenticationSASLFinal).
fn server_signature(creds: &ScramCredentials, auth_message: &str) -> Option<[u8; 32]> {
    let server_key = B64.decode(&creds.server_key).ok()?;
    if server_key.len() != 32 {
        return None;
    }
    Some(hmac_sha256(&server_key, auth_message.as_bytes()))
}

/// Client-side SCRAM computation, for the integration tests (which
/// act as an independent client) and for driver authors reading
/// this code. Given the password, the client-first-bare message
/// (`n=<user>,r=<client-nonce>`) and the server-first message
/// (`r=<nonce>,s=<salt>,i=<iterations>`), returns the
/// client-final message (`c=biws,r=<nonce>,p=<proof>`) and the
/// expected server signature (base64) to check the server's final
/// message against. Errors are plain strings: a bad server-first
/// message is the client's problem, not the server's.
pub fn scram_client_response(
    password: &str,
    client_first_bare: &str,
    server_first: &str,
) -> Result<(String, String), String> {
    let mut nonce = "";
    let mut salt_b64 = "";
    let mut iterations: u32 = 0;
    for part in server_first.split(',') {
        let Some((k, v)) = part.split_once('=') else {
            return Err(format!("bad server-first message: {server_first}"));
        };
        match k {
            "r" => nonce = v,
            "s" => salt_b64 = v,
            "i" => {
                iterations = v
                    .parse()
                    .map_err(|_| format!("bad iteration count in server-first: {server_first}"))?;
            }
            _ => {}
        }
    }
    if nonce.is_empty() || salt_b64.is_empty() || iterations == 0 {
        return Err(format!("bad server-first message: {server_first}"));
    }
    let salt = B64
        .decode(salt_b64)
        .map_err(|_| "bad base64 salt in server-first".to_string())?;
    // The client SASLpreps the password exactly like
    // `set_password` does, so a libpq-style client and this
    // helper agree on the verifier for non-ASCII passwords.
    let password = saslprep(password)?;
    let salted = salted_password(password.as_bytes(), &salt, iterations);
    let client_final_without_proof = format!("c=biws,r={nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_without_proof}");
    let client_signature = hmac_sha256(&stored_key(&client_key(&salted)), auth_message.as_bytes());
    let proof = xor32(&client_key(&salted), &client_signature);
    let server_sig = hmac_sha256(&server_key(&salted), auth_message.as_bytes());
    Ok((
        format!("{client_final_without_proof},p={}", B64.encode(proof)),
        B64.encode(server_sig),
    ))
}

// ---------------------------------------------------------------------
// Server-side handshake (called from pgwire::startup_handshake).
// ---------------------------------------------------------------------

/// Run the SCRAM exchange for one connection. `username` is the
/// `user` from the StartupMessage. `data_dir` is needed only for
/// the fake exchange of an unknown user (the server secret lives
/// there). `limiter` / `peer_ip` are the login rate limiter and the
/// connecting client's IP (see `LoginRateLimiter`): after 5 failed
/// logins for one user@IP the key is locked for 5 minutes, and
/// every failure waits the same constant 2 s delay before its
/// 28P01 (so the timing leaks nothing about the lockout). On
/// success returns Ok and the caller sends AuthenticationOk; on
/// failure an ErrorResponse has already been sent and the returned
/// Err closes the connection.
pub fn scram_handshake(
    reader: &mut impl Read,
    writer: &mut impl Write,
    username: &str,
    users: &HashMap<String, ScramCredentials>,
    data_dir: &Path,
    limiter: &LoginRateLimiter,
    peer_ip: &str,
) -> std::io::Result<()> {
    // 1. Offer SCRAM-SHA-256 (AuthenticationSASL, 'R' + 10).
    let mut body = Vec::new();
    body.extend_from_slice(&10i32.to_be_bytes());
    body.extend_from_slice(b"SCRAM-SHA-256\0");
    body.push(0);
    crate::pgwire::write_message(writer, b'R', &body)?;
    writer.flush()?;

    // 2. SASLInitialResponse 'p': mechanism + client-first-message.
    let Some((tag, initial)) = crate::pgwire::read_message(reader)? else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client closed the connection during SCRAM",
        ));
    };
    if tag != b'p' {
        let _ = auth_error(writer, "28P01", "expected SASLInitialResponse during SCRAM");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected SASLInitialResponse during SCRAM",
        ));
    }
    let (mechanism, client_first) = parse_sasl_initial(&initial).ok_or_else(|| {
        let _ = auth_error(writer, "08P01", "malformed SASLInitialResponse");
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed SASLInitialResponse",
        )
    })?;
    if mechanism != "SCRAM-SHA-256" {
        let _ = auth_error(
            writer,
            "0A000",
            &format!("unsupported SASL mechanism '{mechanism}' (only SCRAM-SHA-256)"),
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported SASL mechanism '{mechanism}'"),
        ));
    }
    let client_first = String::from_utf8_lossy(&client_first).into_owned();
    let Some((client_first_bare, scram_user, client_nonce)) = parse_client_first(&client_first)
    else {
        let _ = auth_error(writer, "08P01", "malformed SCRAM client-first message");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed SCRAM client-first message",
        ));
    };

    // The rate-limit key is the SCRAM username the client claims
    // (not the startup user — they may differ, and then the
    // exchange below is fake anyway). Whether this key is locked
    // is decided NOW, but the exchange still runs to completion
    // either way: a locked-out login must look exactly like an
    // unknown user (same messages, same 28P01), never an instant
    // rejection that would leak that the username exists and is
    // locked.
    let limit_key = LoginRateLimiter::key(&scram_user, peer_ip);
    let locked = limiter.is_locked(&limit_key);

    // 3. Look the user up. Unknown user (or a SCRAM username that
    // does not match the startup user) gets FAKE verifier material
    // so the exchange looks identical either way (see module docs).
    let creds = if scram_user == username {
        users.get(username).cloned()
    } else {
        None
    };
    let creds = match creds {
        Some(c) => c,
        None => fake_credentials(data_dir, &scram_user)?,
    };

    // 4. Server-first: fresh nonce + the (real or fake) salt.
    let server_nonce = B64.encode(random_bytes(SERVER_NONCE_LEN)?);
    let full_nonce = format!("{client_nonce}{server_nonce}");
    let server_first = format!("r={full_nonce},s={},i={}", creds.salt, creds.iterations);
    let mut body = Vec::new();
    body.extend_from_slice(&11i32.to_be_bytes());
    body.extend_from_slice(server_first.as_bytes());
    crate::pgwire::write_message(writer, b'R', &body)?;
    writer.flush()?;

    // 5. SASLResponse 'p': client-final-message.
    let Some((tag, final_body)) = crate::pgwire::read_message(reader)? else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "client closed the connection during SCRAM",
        ));
    };
    if tag != b'p' {
        let _ = auth_error(writer, "28P01", "expected SASLResponse during SCRAM");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected SASLResponse during SCRAM",
        ));
    }
    let client_final = String::from_utf8_lossy(&final_body).into_owned();
    let Some((proof_b64, final_without_proof)) = parse_client_final(&client_final, &full_nonce)
    else {
        let _ = auth_error(writer, "08P01", "malformed SCRAM client-final message");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed SCRAM client-final message",
        ));
    };

    // 6. Verify the proof. A wrong password (or an unknown user)
    // fails here with 28P01 — the password itself never crossed
    // the wire, so there is nothing to compare it against. A
    // locked-out key fails here too, even with the RIGHT password,
    // and waits the locked delay first — which is the SAME
    // constant delay as any failure (M3), so the response is
    // identical to a wrong password's and the lockout leaks
    // nothing. A failure is recorded (constant delay, lockout
    // at 5) and a success forgets the key's failures.
    let auth_message = format!("{client_first_bare},{server_first},{final_without_proof}");
    let Ok(proof) = B64.decode(proof_b64) else {
        let _ = auth_error(writer, "08P01", "bad base64 in SCRAM client proof");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad base64 in SCRAM client proof",
        ));
    };
    if locked {
        std::thread::sleep(limiter.locked_delay());
        let _ = auth_error(
            writer,
            "28P01",
            &format!("password authentication failed for user \"{username}\""),
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SCRAM login locked out after repeated failures",
        ));
    }
    if !verify_proof(&creds, &auth_message, &proof) {
        let delay = limiter.record_failure(&limit_key);
        std::thread::sleep(delay);
        let _ = auth_error(
            writer,
            "28P01",
            &format!("password authentication failed for user \"{username}\""),
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SCRAM proof verification failed",
        ));
    }
    limiter.record_success(&limit_key);

    // 7. Server-final: prove the server knows the ServerKey, then
    // the caller sends AuthenticationOk.
    let Some(sig) = server_signature(&creds, &auth_message) else {
        let _ = auth_error(writer, "XX000", "stored server key is corrupt");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored server key is corrupt",
        ));
    };
    let mut body = Vec::new();
    body.extend_from_slice(&12i32.to_be_bytes());
    body.extend_from_slice(format!("v={}", B64.encode(sig)).as_bytes());
    crate::pgwire::write_message(writer, b'R', &body)?;
    writer.flush()?;
    Ok(())
}

/// Send an ErrorResponse during auth and flush, best effort — the
/// connection is closed right after either way.
fn auth_error(writer: &mut impl Write, code: &str, message: &str) -> std::io::Result<()> {
    let r = crate::pgwire::error_response(writer, code, message);
    let _ = writer.flush();
    r
}

/// Fake verifier material for an unknown user: the salt and keys
/// are HMACs of the per-data-dir server secret and the username,
/// so the SAME unknown username gets the SAME salt on every
/// handshake (a salt that changed every time would itself leak
/// that the user does not exist), while different usernames get
/// different salts. The exchange proceeds normally and fails at
/// the proof check, so the handshake leaks nothing about whether
/// the username exists. The secret is never the password — the
/// fake StoredKey/ServerKey are random-looking HMAC outputs that
/// no password can reproduce.
fn fake_credentials(dir: &Path, username: &str) -> std::io::Result<ScramCredentials> {
    let secret = load_or_create_server_secret(dir)?;
    let salt_full = hmac_sha256(&secret, format!("zeno fake salt v1:{username}").as_bytes());
    let stored = hmac_sha256(
        &secret,
        format!("zeno fake stored key v1:{username}").as_bytes(),
    );
    let server = hmac_sha256(
        &secret,
        format!("zeno fake server key v1:{username}").as_bytes(),
    );
    Ok(ScramCredentials {
        salt: B64.encode(&salt_full[..SALT_LEN]),
        iterations: ITERATIONS,
        stored_key: B64.encode(stored),
        server_key: B64.encode(server),
    })
}

/// SASLInitialResponse body: String mechanism, Int32 length, bytes.
/// Returns (mechanism, initial-response bytes).
fn parse_sasl_initial(body: &[u8]) -> Option<(String, Vec<u8>)> {
    let nul = body.iter().position(|b| *b == 0)?;
    let mechanism = String::from_utf8_lossy(&body[..nul]).into_owned();
    let rest = &body[nul + 1..];
    if rest.len() < 4 {
        return None;
    }
    let len = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    if len < 0 || rest.len() - 4 < len as usize {
        return None;
    }
    Some((mechanism, rest[4..4 + len as usize].to_vec()))
}

/// Client-first-message: `n,,n=<user>,r=<nonce>` (gs2 header `n,,`
/// = no channel binding, no authzid). Returns (client-first-bare,
/// username, client nonce). Channel binding (`p=...`) is rejected:
/// there is no TLS to bind to. A duplicate `n=` or `r=` attribute
/// is rejected (strictly — silently taking the last one would let
/// two different usernames/nonces hide in one message), and a
/// client nonce shorter than 8 characters is rejected: it has
/// almost no entropy and the server nonce alone must not carry
/// the whole exchange.
fn parse_client_first(msg: &str) -> Option<(String, String, String)> {
    let bare = msg.strip_prefix("n,,")?;
    let mut user = None;
    let mut nonce = None;
    for part in bare.split(',') {
        let (k, v) = part.split_once('=')?;
        match k {
            "n" => {
                if user.is_some() {
                    return None; // duplicate n=
                }
                user = Some(unescape_username(v));
            }
            "r" => {
                if nonce.is_some() {
                    return None; // duplicate r=
                }
                nonce = Some(v.to_string());
            }
            _ => return None,
        }
    }
    let (user, nonce) = (user?, nonce?);
    if user.is_empty() || nonce.chars().count() < MIN_CLIENT_NONCE_LEN {
        return None;
    }
    Some((bare.to_string(), user, nonce))
}

/// Client-final-message: `c=biws,r=<full-nonce>,p=<proof>`.
/// Returns (proof-base64, message-without-proof). `c` must be
/// `biws` (base64 of the `n,,` gs2 header) and the nonce must be
/// exactly the server's full nonce, or the message is malformed.
fn parse_client_final<'a>(msg: &'a str, full_nonce: &str) -> Option<(&'a str, String)> {
    let mut channel = "";
    let mut nonce = "";
    let mut proof = "";
    for part in msg.split(',') {
        let (k, v) = part.split_once('=')?;
        match k {
            // A duplicate attribute is malformed, like in the
            // client-first message — never silently last-wins.
            "c" => {
                if !channel.is_empty() {
                    return None;
                }
                channel = v;
            }
            "r" => {
                if !nonce.is_empty() {
                    return None;
                }
                nonce = v;
            }
            "p" => {
                if !proof.is_empty() {
                    return None;
                }
                proof = v;
            }
            _ => return None,
        }
    }
    if channel != "biws" || nonce != full_nonce || proof.is_empty() {
        return None;
    }
    let without_proof = format!("c={channel},r={nonce}");
    Some((proof, without_proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7677 section 3: the full worked SCRAM-SHA-256 example.
    // user "user", password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ==,
    // 4096 iterations. (Do NOT confuse these with the RFC 5802
    // SCRAM-SHA-1 example — same username/password, different
    // nonces, salt and proof; the SHA-1 proof is only 28 base64
    // chars, the SHA-256 one is 44.)
    const RFC_PASSWORD: &str = "pencil";
    const RFC_SERVER_NONCE: &str = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    const RFC_SALT_B64: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
    const RFC_CLIENT_FIRST_BARE: &str = "n=user,r=rOprNGfwEbeRWgbNEkqO";
    const RFC_SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const RFC_CLIENT_FINAL: &str = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const RFC_SERVER_SIG_B64: &str = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn rfc_credentials() -> ScramCredentials {
        let salt = B64.decode(RFC_SALT_B64).unwrap();
        let salted = salted_password(RFC_PASSWORD.as_bytes(), &salt, 4096);
        ScramCredentials {
            salt: RFC_SALT_B64.to_string(),
            iterations: 4096,
            stored_key: B64.encode(stored_key(&client_key(&salted))),
            server_key: B64.encode(server_key(&salted)),
        }
    }

    #[test]
    fn rfc7677_client_response_vectors() {
        // The client side must reproduce the RFC's proof and server
        // signature byte for byte — this pins the PBKDF2, HMAC and
        // AuthMessage construction to the standard.
        let (client_final, server_sig) =
            scram_client_response(RFC_PASSWORD, RFC_CLIENT_FIRST_BARE, RFC_SERVER_FIRST)
                .expect("RFC example must compute");
        assert_eq!(client_final, RFC_CLIENT_FINAL);
        assert_eq!(server_sig, RFC_SERVER_SIG_B64);
    }

    #[test]
    fn rfc7677_server_verifies_rfc_proof() {
        let creds = rfc_credentials();
        let auth_message =
            format!("{RFC_CLIENT_FIRST_BARE},{RFC_SERVER_FIRST},c=biws,r={RFC_SERVER_NONCE}");
        let proof = B64
            .decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
            .unwrap();
        assert!(verify_proof(&creds, &auth_message, &proof));
        // A wrong password's proof must fail.
        let (wrong_final, _) =
            scram_client_response("wrong-password", RFC_CLIENT_FIRST_BARE, RFC_SERVER_FIRST)
                .unwrap();
        let wrong_proof = B64.decode(wrong_final.split("p=").nth(1).unwrap()).unwrap();
        assert!(!verify_proof(&creds, &auth_message, &wrong_proof));
        // And the server signature matches the RFC value.
        assert_eq!(
            B64.encode(server_signature(&creds, &auth_message).unwrap()),
            RFC_SERVER_SIG_B64
        );
    }

    #[test]
    fn set_password_never_stores_the_password() {
        let dir = std::env::temp_dir().join("zeno-auth-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_password(&dir, "sanjay", "correct horse battery staple").unwrap();
        let text = std::fs::read_to_string(dir.join(USERS_FILE)).unwrap();
        assert!(
            !text.contains("correct horse battery staple"),
            "users.json must never contain the password: {text}"
        );
        let users = load_users(&dir).unwrap();
        let creds = users.get("sanjay").expect("user must be stored");
        assert_eq!(creds.iterations, 4096);
        assert_eq!(B64.decode(&creds.salt).unwrap().len(), 16);
        assert_eq!(B64.decode(&creds.stored_key).unwrap().len(), 32);
        assert_eq!(B64.decode(&creds.server_key).unwrap().len(), 32);
        // The stored verifier really is the SCRAM verifier for that
        // password: a client proof built from it verifies.
        let salt = B64.decode(&creds.salt).unwrap();
        let salted = salted_password(b"correct horse battery staple", &salt, 4096);
        assert_eq!(
            B64.encode(stored_key(&client_key(&salted))),
            creds.stored_key
        );
        assert_eq!(B64.encode(server_key(&salted)), creds.server_key);
        // list + remove roundtrip.
        assert_eq!(list_users(&dir).unwrap(), vec!["sanjay".to_string()]);
        assert!(remove_user(&dir, "sanjay").unwrap());
        assert!(list_users(&dir).unwrap().is_empty());
        assert!(!remove_user(&dir, "sanjay").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_password_rejects_bad_inputs() {
        let dir = std::env::temp_dir().join("zeno-auth-test-bad");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(set_password(&dir, "u", "").is_err());
        assert!(set_password(&dir, "", "pw").is_err());
        assert!(set_password(&dir, "a=b", "pw").is_err());
        assert!(set_password(&dir, "a,b", "pw").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_users_file_fails_closed() {
        let dir = std::env::temp_dir().join("zeno-auth-test-corrupt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(USERS_FILE), "{not json").unwrap();
        assert!(load_users(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn username_escaping_roundtrips() {
        assert_eq!(escape_username("a=b,c"), "a=3Db=2Cc");
        assert_eq!(unescape_username("a=3Db=2Cc"), "a=b,c");
        // parse_client_first un-escapes the username.
        let (bare, user, nonce) =
            parse_client_first("n,,n=a=3Db=2Cc,r=abc12345").expect("must parse");
        assert_eq!(bare, "n=a=3Db=2Cc,r=abc12345");
        assert_eq!(user, "a=b,c");
        assert_eq!(nonce, "abc12345");
    }

    #[test]
    fn parse_client_first_rejects_channel_binding() {
        // "p=tls-server-end-point" is a channel-binding header, not
        // the "n,," this server accepts (there is no TLS).
        assert!(parse_client_first("p=tls-server-end-point,,n=u,r=x").is_none());
        assert!(parse_client_first("n,,n=u").is_none()); // no nonce
        assert!(parse_client_first("n,,r=x").is_none()); // no user
    }

    #[test]
    fn parse_client_final_checks_nonce_and_channel() {
        let (proof, without) =
            parse_client_final("c=biws,r=FULLNONCE,p=abc=", "FULLNONCE").expect("must parse");
        assert_eq!(proof, "abc=");
        assert_eq!(without, "c=biws,r=FULLNONCE");
        // Wrong nonce, wrong channel binding, missing proof.
        assert!(parse_client_final("c=biws,r=OTHER,p=abc=", "FULLNONCE").is_none());
        assert!(
            parse_client_final("c=e2VydmVyLXNpZ25hdHVyZQ==,r=FULLNONCE,p=abc=", "FULLNONCE")
                .is_none()
        );
        assert!(parse_client_final("c=biws,r=FULLNONCE", "FULLNONCE").is_none());
        // Duplicate attributes are malformed, never last-wins.
        assert!(parse_client_final("c=biws,r=FULLNONCE,r=FULLNONCE,p=abc=", "FULLNONCE").is_none());
        assert!(parse_client_final("c=biws,r=FULLNONCE,p=abc=,p=def=", "FULLNONCE").is_none());
    }

    #[test]
    fn parse_client_first_rejects_duplicates_and_short_nonce() {
        // Duplicate n= or r=: strict reject, never last-wins.
        assert!(parse_client_first("n,,n=sanjay,r=AAA12345,n=ghost,r=BBB12345").is_none());
        assert!(parse_client_first("n,,n=sanjay,r=AAA12345,r=BBB12345").is_none());
        // A 1-character (or any <8-character) client nonce is
        // rejected: it has almost no entropy.
        assert!(parse_client_first("n,,n=sanjay,r=x").is_none());
        assert!(parse_client_first("n,,n=sanjay,r=1234567").is_none());
        // Exactly 8 characters is accepted.
        assert!(parse_client_first("n,,n=sanjay,r=12345678").is_some());
    }

    #[test]
    fn set_password_requires_at_least_8_characters() {
        let dir = std::env::temp_dir().join("zeno-auth-test-minlen");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 1-char and 7-char passwords are rejected with a clear error.
        let err = set_password(&dir, "u", "a").unwrap_err();
        assert!(err.contains("at least 8"), "{err}");
        let err = set_password(&dir, "u", "pw12345").unwrap_err();
        assert!(err.contains("at least 8"), "{err}");
        // Exactly 8 characters works.
        set_password(&dir, "u", "pw123456").unwrap();
        assert_eq!(list_users(&dir).unwrap(), vec!["u".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_password_creates_a_missing_data_dir() {
        // A nonexistent data dir used to fail with a cryptic
        // "No such file or directory" from the users.json write.
        let dir = std::env::temp_dir().join("zeno-auth-test-mkdir/nested/dir");
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("zeno-auth-test-mkdir"));
        set_password(&dir, "u", "password123").unwrap();
        assert!(dir.join(USERS_FILE).exists());
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("zeno-auth-test-mkdir"));
    }

    #[test]
    #[cfg(unix)]
    fn users_json_is_mode_0600_regardless_of_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("zeno-auth-test-mode");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_password(&dir, "alice", "password123").unwrap();
        let mode = std::fs::metadata(dir.join(USERS_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "users.json must be 0600, got {mode:o}");
        // A second user re-saves the file: the mode must stay 0600
        // even though the .tmp file already existed.
        set_password(&dir, "bob", "password123").unwrap();
        let mode = std::fs::metadata(dir.join(USERS_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "users.json must stay 0600, got {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saslprep_maps_nbsp_to_space_and_normalizes() {
        // RFC 4013 Table B.1: U+00A0 NO-BREAK SPACE -> U+0020.
        assert_eq!(saslprep("a\u{a0}b").unwrap(), "a b");
        assert_eq!(saslprep("a\u{2003}b").unwrap(), "a b"); // EM SPACE
        assert_eq!(saslprep("a\u{3000}b").unwrap(), "a b"); // IDEOGRAPHIC SPACE
                                                            // NFKC: fullwidth "Ａ" (U+FF21) normalizes to "A", and the
                                                            // ligature "ﬁ" (U+FB01) to "fi".
        assert_eq!(saslprep("ＡＢＣ").unwrap(), "ABC");
        assert_eq!(saslprep("ﬁ").unwrap(), "fi");
        // Plain ASCII is untouched.
        assert_eq!(saslprep("password123").unwrap(), "password123");
        // Prohibited characters are rejected: ASCII control,
        // private use, non-character.
        assert!(saslprep("a\u{1}b").is_err());
        assert!(saslprep("a\u{e000}b").is_err());
        assert!(saslprep("a\u{fdd0}b").is_err());
    }

    #[test]
    fn saslprep_password_verifies_from_both_forms() {
        // A password set with a NBSP must verify when the client
        // sends the SASLprep'd form ("a b"), and the stored
        // verifier must be exactly the verifier for "a b".
        let dir = std::env::temp_dir().join("zeno-auth-test-saslprep");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 10 characters after prep: "pass word1".
        set_password(&dir, "u", "pass\u{a0}word1").unwrap();
        let users = load_users(&dir).unwrap();
        let creds = users.get("u").unwrap();
        let salt = B64.decode(&creds.salt).unwrap();
        let salted_plain = salted_password(b"pass word1", &salt, 4096);
        assert_eq!(
            B64.encode(stored_key(&client_key(&salted_plain))),
            creds.stored_key,
            "NBSP password must be stored as its SASLprep form"
        );
        // And the client side agrees: scram_client_response
        // SASLpreps too, so a proof built from the NBSP form
        // verifies against the stored verifier.
        let bare = "n=u,r=clientnonce123456";
        let server_first = format!("r=clientnonce123456servernonce,s={},i=4096", creds.salt);
        let (client_final, _) =
            scram_client_response("pass\u{a0}word1", bare, &server_first).unwrap();
        let proof = B64
            .decode(client_final.split("p=").nth(1).unwrap())
            .unwrap();
        let auth_message = format!("{bare},{server_first},c=biws,r=clientnonce123456servernonce");
        assert!(verify_proof(creds, &auth_message, &proof));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fake_salt_is_deterministic_per_username() {
        let dir = std::env::temp_dir().join("zeno-auth-test-fakesalt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let first = fake_credentials(&dir, "ghost").unwrap();
        let second = fake_credentials(&dir, "ghost").unwrap();
        assert_eq!(
            first.salt, second.salt,
            "same unknown username must get the same fake salt on every handshake"
        );
        assert_eq!(first.stored_key, second.stored_key);
        assert_eq!(first.server_key, second.server_key);
        let other = fake_credentials(&dir, "ghost2").unwrap();
        assert_ne!(
            first.salt, other.salt,
            "different usernames must get different fake salts"
        );
        assert_ne!(first.stored_key, other.stored_key);
        // The secret file exists, persists the determinism across
        // "restarts" (a fresh read of the same dir), and is 0600.
        assert!(dir.join(SERVER_SECRET_FILE).exists());
        let third = fake_credentials(&dir, "ghost").unwrap();
        assert_eq!(first.salt, third.salt);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(SERVER_SECRET_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "server-secret must be 0600, got {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rate_limiter_locks_after_max_failures() {
        // Short policy (3 failures, 5-minute lockout, no delay)
        // so the test runs in milliseconds, not minutes.
        let limiter = LoginRateLimiter::with_policy(
            3,
            Duration::from_secs(300),
            Duration::from_millis(0),
            100,
        );
        let key = LoginRateLimiter::key("sanjay", "127.0.0.1");
        assert!(!limiter.is_locked(&key));
        limiter.record_failure(&key);
        assert!(!limiter.is_locked(&key), "1 failure must not lock");
        limiter.record_failure(&key);
        assert!(!limiter.is_locked(&key), "2 failures must not lock");
        limiter.record_failure(&key);
        assert!(limiter.is_locked(&key), "3 failures must lock");
        // A success clears the lockout entirely.
        limiter.record_success(&key);
        assert!(!limiter.is_locked(&key));
    }

    #[test]
    fn rate_limiter_unlocks_after_lockout_expires() {
        let limiter = LoginRateLimiter::with_policy(
            2,
            Duration::from_millis(100),
            Duration::from_millis(0),
            100,
        );
        let key = LoginRateLimiter::key("sanjay", "127.0.0.1");
        limiter.record_failure(&key);
        limiter.record_failure(&key);
        assert!(limiter.is_locked(&key));
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !limiter.is_locked(&key),
            "lockout must expire after its duration"
        );
        // And the next failure after expiry starts a FRESH
        // allowance — it must not re-lock at once.
        limiter.record_failure(&key);
        assert!(!limiter.is_locked(&key), "fresh allowance after expiry");
        limiter.record_failure(&key);
        assert!(limiter.is_locked(&key), "2 fresh failures lock again");
    }

    #[test]
    fn rate_limiter_success_resets_the_failure_count() {
        let limiter = LoginRateLimiter::with_policy(
            3,
            Duration::from_secs(300),
            Duration::from_millis(0),
            100,
        );
        let key = LoginRateLimiter::key("sanjay", "127.0.0.1");
        limiter.record_failure(&key);
        limiter.record_failure(&key);
        limiter.record_success(&key);
        // Two failures after a success must not lock (the count
        // was reset, not merely paused).
        limiter.record_failure(&key);
        limiter.record_failure(&key);
        assert!(!limiter.is_locked(&key));
    }

    #[test]
    fn rate_limiter_keys_are_per_user_and_ip() {
        let limiter = LoginRateLimiter::with_policy(
            2,
            Duration::from_secs(300),
            Duration::from_millis(0),
            100,
        );
        let sanjay = LoginRateLimiter::key("sanjay", "127.0.0.1");
        let asha = LoginRateLimiter::key("asha", "127.0.0.1");
        let sanjay_elsewhere = LoginRateLimiter::key("sanjay", "10.0.0.9");
        limiter.record_failure(&sanjay);
        limiter.record_failure(&sanjay);
        assert!(limiter.is_locked(&sanjay));
        assert!(
            !limiter.is_locked(&asha),
            "locking one user must not lock another"
        );
        assert!(
            !limiter.is_locked(&sanjay_elsewhere),
            "locking one IP must not lock the same user from another IP"
        );
    }

    #[test]
    fn rate_limiter_failure_delay_is_constant() {
        // M3: EVERY failure waits exactly `delay_max` — the 1st
        // wrong password, the 5th, and a locked-out login all wait
        // the same, so the timing can never reveal whether the
        // key is fresh, failing, or locked. (The old progressive
        // delay — 100 ms, 200 ms, … — leaked exactly that: a
        // locked login always took 2.0 s, a fresh wrong password
        // 0.1 s.) `locked_delay` must equal it too.
        let limiter = LoginRateLimiter::with_policy(
            10,
            Duration::from_secs(60),
            Duration::from_millis(250),
            100,
        );
        let key = LoginRateLimiter::key("sanjay", "127.0.0.1");
        assert_eq!(limiter.record_failure(&key), Duration::from_millis(250));
        assert_eq!(limiter.record_failure(&key), Duration::from_millis(250));
        assert_eq!(limiter.record_failure(&key), Duration::from_millis(250));
        assert_eq!(
            limiter.record_failure(&key),
            Duration::from_millis(250),
            "the 4th failure must wait exactly as long as the 1st"
        );
        assert_eq!(
            limiter.locked_delay(),
            Duration::from_millis(250),
            "a locked-out login must wait the same constant delay"
        );
    }

    #[test]
    fn rate_limiter_entry_cap_evicts_unlocked_keys() {
        // m1: the map must never grow past `max_entries`, however
        // many distinct user@IP keys an attacker probes.
        let limiter =
            LoginRateLimiter::with_policy(5, Duration::from_secs(300), Duration::from_millis(0), 3);
        for i in 0..10 {
            limiter.record_failure(&LoginRateLimiter::key(&format!("user{i}"), "127.0.0.1"));
        }
        assert!(
            limiter.entry_count() <= 3,
            "10 distinct keys with a cap of 3 must leave at most 3 entries, got {}",
            limiter.entry_count()
        );
    }

    #[test]
    fn rate_limiter_entry_cap_never_drops_a_lockout() {
        // m1: the purge at the cap must keep locked entries — an
        // attacker flooding the map must not be able to un-lock
        // an account that way.
        let limiter =
            LoginRateLimiter::with_policy(2, Duration::from_secs(300), Duration::from_millis(0), 3);
        let locked_key = LoginRateLimiter::key("victim", "127.0.0.1");
        limiter.record_failure(&locked_key);
        limiter.record_failure(&locked_key);
        assert!(limiter.is_locked(&locked_key), "victim must be locked");
        for i in 0..10 {
            limiter.record_failure(&LoginRateLimiter::key(&format!("user{i}"), "127.0.0.1"));
        }
        assert!(
            limiter.is_locked(&locked_key),
            "flooding the map must not drop the victim's lockout"
        );
    }

    #[test]
    fn fake_credentials_agree_across_concurrent_calls() {
        // m2: concurrent first logins for unknown users race in
        // `load_or_create_server_secret`. The secret must be
        // created exactly once and every thread must derive the
        // SAME fake salt from it — the old code let the loser
        // delete the winner's file mid-write, so threads could
        // disagree (or error) about the secret.
        use std::sync::{Arc, Barrier};
        let dir = std::env::temp_dir().join("zeno-auth-test-fakesalt-race");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = Arc::new(dir);
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let dir = Arc::clone(&dir);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait(); // all 8 threads race at once
                fake_credentials(&dir, "ghost").unwrap().salt
            }));
        }
        let mut salts = Vec::new();
        for h in handles {
            salts.push(h.join().expect("thread must not panic"));
        }
        assert!(
            salts.iter().all(|s| s == &salts[0]),
            "all concurrent callers must derive the same fake salt: {salts:?}"
        );
        let _ = std::fs::remove_dir_all(&*dir);
    }
}

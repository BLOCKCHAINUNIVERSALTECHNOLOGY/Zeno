// pgwire.rs — PostgreSQL wire protocol (frontend/backend, v3.0),
// Simple Query + extended query protocol. Written from the official
// PostgreSQL docs ("Message Flow" and "Message Formats", protocol
// 3.0) — no pgwire crate, just `std::net::TcpListener`.
//
// What this implements:
// - Startup handshake: StartupMessage (protocol 3.0), SSLRequest
//   (answered 'N' without `--tls`; with `--tls` answered 'S'
//   followed by a real TLS handshake — see `tls.rs`),
//   CancelRequest (closed, no reply).
// - Auth: trust auth when no password is set (every client gets
//   AuthenticationOk, no password — **local prototype only, see the
//   BOLD warning in the README**); SCRAM-SHA-256 when users exist
//   in `users.json` (see `auth.rs`), with rate limiting / lockout
//   after 5 failed logins per user@IP (see `auth::LoginRateLimiter`).
// - ParameterStatus (server_version, client_encoding,
//   standard_conforming_strings), BackendKeyData, ReadyForQuery.
// - Simple Query 'Q': CREATE TABLE / INSERT / UPDATE / SELECT
//   / DELETE / VACUUM, plus BEGIN / COMMIT / ROLLBACK and
//   SAVEPOINT / ROLLBACK TO SAVEPOINT / RELEASE SAVEPOINT for
//   MVCC transactions (V0.6, see txn.rs; savepoints V0.7), mapped
//   onto the engine's table API through the real SQL parser in
//   `parser.rs` (V0.7: multi-condition WHERE, ORDER BY / LIMIT /
//   OFFSET, multi-row INSERT, multi-SET UPDATE). One Query message
//   may hold several statements separated by ';'; each runs in
//   turn, then one ReadyForQuery closes the cycle. The
//   ReadyForQuery status byte is 'T' while a transaction is open,
//   'I' otherwise, 'E' while the transaction is aborted (M2:
//   25P02 — only ROLLBACK and ROLLBACK TO SAVEPOINT run in that
//   state).
// - Extended query protocol (see `extended.rs`): Parse/Bind/
//   Describe/Execute/Close/Sync over the same statements,
//   with $1, $2 parameters (text format, plus binary int4/text),
//   named + unnamed statements and portals, PortalSuspended for
//   limited Execute, and the protocol's error rule — after an
//   extended-protocol error the server sends ONE ErrorResponse and
//   then reads and discards messages until Sync, so a pipelined
//   driver never desyncs. BEGIN / COMMIT / ROLLBACK work here
//   too (V0.6): the per-connection transaction session is shared
//   between Simple Query and the extended protocol.
// - Terminate 'X' closes the connection; a client disconnect never
//   stops the server; clients are served one thread each, sharing one
//   engine behind a Mutex (the data-dir LOCK still allows exactly one
//   server process per directory — a second `zeno serve` on the same
//   directory fails with the lock error).
//
// What it deliberately does NOT implement (see README, honest limits):
// - COPY, LISTEN/NOTIFY, cursors.
// - Two-phase commit, DDL inside a transaction, or SERIALIZABLE /
//   READ COMMITTED: transactions are snapshot isolation only
//   (V0.6, see txn.rs). Savepoints exist since V0.7; JOIN,
//   subqueries, GROUP BY and aggregates do not (the parser
//   reports them as 0A000, not supported).
//
// All values travel as text (type OID 25, `text`), because every
// Zeno table column is a string. RowDescription therefore always
// reports OID 25, typlen -1; the format code is 0 (text) unless the
// client asked for binary result format in Bind — binary text is the
// same bytes, so a binary DataRow carries the same UTF-8 string.
//
// `server_version` is reported as "18.0": that is the PostgreSQL
// version whose wire protocol this implements (the docs this code was
// written against), so clients that parse the version do not choke.
// Zeno is NOT PostgreSQL — the README says so plainly.

use crate::auth;
use crate::auth::LoginRateLimiter;
use crate::engine::Engine;
use crate::extended::ExtendedState;
use crate::parser::{parse_sql, CmpOp, Stmt as ParsedStmt, Value as ParsedValue};
use crate::table::{FilterOp, RowFilter, TableStore};
use crate::tls;
use crate::txn::CommitError;
use std::collections::BTreeSet;
use std::io::{BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How long a connection may sit idle (or half-way through a
/// message) before the server closes it: 60 seconds. Without this a
/// client that sends half a message and then goes quiet holds its
/// thread forever, and threads here are unbounded — a slow
/// denial-of-service. A timeout closes just that connection; the
/// server keeps running.
const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Cap on a single write stall: a client that stops reading must not
/// hold its thread forever either.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Absolute budget for the whole handshake (StartupMessage +
/// SCRAM exchange), from the moment the connection is accepted:
/// 60 seconds by default. `ZENO_HANDSHAKE_TIMEOUT_SECS` overrides
/// it (diagnostic/test hook, like `ZENO_TXN_IDLE_TIMEOUT_SECS`).
/// This is an ABSOLUTE deadline, not a per-read timeout — see
/// `DeadlineReader`.
pub(crate) fn handshake_timeout() -> Duration {
    std::env::var("ZENO_HANDSHAKE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60))
}

/// Absolute budget for ONE frontend message (frame), from its
/// first byte: 60 seconds by default. `ZENO_FRAME_TIMEOUT_SECS`
/// overrides it (diagnostic/test hook). A new frame gets a fresh
/// budget, so a legitimately idle connection is NOT cut off while
/// it waits between queries — the budget only starts when the
/// frame's first byte arrives, and the 60 s socket read timeout
/// still bounds the idle wait for that first byte, as before.
pub(crate) fn frame_timeout() -> Duration {
    std::env::var("ZENO_FRAME_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(60))
}

/// A reader that enforces an ABSOLUTE deadline (V0.11, review
/// finding 3). The old code set a 60 s read timeout on the socket,
/// but a socket timeout applies PER `read()` call — a client that
/// dribbled one byte every 59 s never tripped it and held its
/// connection slot (and thread) forever, starving the other 19
/// slots. This wrapper checks the deadline on EVERY `read()`:
/// once the budget is spent, the next read fails with `TimedOut`
/// no matter how recently a byte arrived, so a slow-drip client
/// is closed at most one budget after its frame started and its
/// slot is freed.
///
/// Two modes: an absolute deadline (`with_deadline`, used for the
/// handshake — the whole handshake must finish by one instant
/// counted from accept), or a lazily-started budget
/// (`reset_budget` + `start_frame`, used for frames — the budget
/// starts at the frame's first byte, so idle time between frames
/// does not consume it).
///
/// Honest limit: a single `read()` call can still block up to the
/// socket's own read timeout (60 s) if the client goes silent
/// mid-frame after the last byte — the deadline is checked
/// between reads, not inside one blocked syscall. A client that
/// keeps sending bytes, however slowly, is cut off at the
/// deadline; a client that sends one byte and then goes quiet is
/// cut off by the socket timeout instead. The TLS handshake
/// itself (inside `tls::handshake_tls`) is not wrapped — only the
/// pgwire handshake after it is.
pub(crate) struct DeadlineReader<R: Read> {
    inner: R,
    /// Absolute instant after which reads fail, or `None` when
    /// no deadline is armed (the budget starts on the next byte).
    deadline: Option<Instant>,
    /// Budget armed on the first byte read while no deadline is set.
    budget: Duration,
}

impl<R: Read> DeadlineReader<R> {
    /// A reader whose reads fail after the absolute `deadline`.
    pub(crate) fn with_deadline(inner: R, deadline: Instant) -> Self {
        Self {
            inner,
            deadline: Some(deadline),
            budget: Duration::from_secs(0),
        }
    }

    /// Arm a fresh per-frame budget: the deadline is cleared, so
    /// the next byte read starts a new budget from that moment.
    /// Call once per frame, before reading it.
    pub(crate) fn start_frame(&mut self) {
        self.deadline = None;
    }

    /// Replace the budget (and clear any armed deadline), e.g.
    /// when the handshake ends and per-frame budgets begin.
    pub(crate) fn reset_budget(&mut self, budget: Duration) {
        self.budget = budget;
        self.deadline = None;
    }
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(deadline) = self.deadline {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "deadline exceeded: the client sent data too slowly",
                ));
            }
        }
        let n = self.inner.read(buf)?;
        if n > 0 && self.deadline.is_none() {
            self.deadline = Some(Instant::now() + self.budget);
        }
        Ok(n)
    }
}

/// Protocol version 3.0, as sent in the StartupMessage.
const PROTOCOL_V3: i32 = 196608; // 3 << 16
/// First-message code asking for SSL; we always answer 'N'.
const SSL_REQUEST_CODE: i32 = 80877103;
/// First-message code asking for GSSAPI encryption (m3): like
/// PostgreSQL, Zeno answers 'N' — there is no GSSAPI here.
const GSSENC_REQUEST_CODE: i32 = 80877105;
/// First-message code asking to cancel another backend; no reply.
const CANCEL_REQUEST_CODE: i32 = 80877104;
/// Largest single message we will accept (64 MiB); anything bigger is
/// a corrupt or hostile frame, not a query.
const MAX_MESSAGE_LEN: i32 = 64 * 1024 * 1024;

static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);

/// The one engine + table registry shared by all connections of one
/// server process. Every statement locks this for its whole run, so
/// two clients can never interleave a read and a write halfway.
pub(crate) struct Shared {
    engine: Engine,
    tables: TableStore,
    /// The data directory, so the handshake can re-read `users.json`
    /// on every connection (a password set with `zeno user` takes
    /// effect for new connections without restarting the server).
    data_dir: PathBuf,
    /// The SCRAM login rate limiter, shared by all connections
    /// (one limiter per server process — a restart resets it).
    rate_limiter: Arc<LoginRateLimiter>,
}

/// Per-connection transaction session (V0.6): at most one open
/// transaction per connection, holding its engine transaction id.
/// The session owns nothing else — the engine owns the snapshot
/// and the write buffer. A transaction is per-connection state:
/// two connections never share one, and a transaction never
/// outlives its connection (see `handle_client`: a connection
/// that ends with a transaction still open rolls it back).
pub(crate) struct Session {
    pub(crate) txn: Option<u64>,
    /// M2 (25P02): true once a statement inside the transaction
    /// has failed. While aborted, every statement except ROLLBACK
    /// fails with 25P02 ("current transaction is aborted,
    /// commands ignored until end of transaction block") and
    /// COMMIT fails with 25P02 too — like PostgreSQL. Only
    /// ROLLBACK ends an aborted transaction. Set only by
    /// data-statement (INSERT/SELECT/UPDATE/DELETE) failures:
    /// a failed CREATE TABLE (0A000, DDL is not versioned) or a
    /// nested BEGIN (25001) does NOT abort the transaction, and
    /// neither does a Parse/Bind/Describe error — the extended
    /// protocol's planning errors leave the transaction alive.
    aborted: bool,
    /// B2: bumped every time a transaction of this connection
    /// ends (COMMIT or ROLLBACK, success or failure). Portals
    /// remember the generation they were bound in; a portal
    /// bound inside a transaction that has since ended is dead
    /// (PostgreSQL closes portals at transaction end), so its
    /// cached rows can never be served again.
    pub(crate) generation: u64,
    /// B2 (V0.7 review, second half): bumped every time this
    /// connection runs a successful ROLLBACK TO SAVEPOINT. A
    /// suspended portal's cached rows were computed from the
    /// transaction's write buffer BEFORE the rollback, so they
    /// may contain rows the rollback just undid. The portal
    /// itself survives — but ONLY when it was created BEFORE the
    /// savepoint (V0.8: portals created after it are closed
    /// outright, see `savepoint_cutoff`) — so the next Execute
    /// re-runs the statement fresh instead of serving the stale
    /// cache. See `CachedRows.epoch` in `extended.rs`.
    pub(crate) cache_epoch: u64,
    /// V0.8: a strictly increasing per-connection event number,
    /// bumped on every SAVEPOINT, Parse and Bind. A savepoint
    /// records the clock at its creation; a portal / prepared
    /// statement records the clock at its Parse/Bind. On
    /// ROLLBACK TO SAVEPOINT, every portal / statement with a
    /// clock HIGHER than the savepoint's was created after the
    /// savepoint, so PostgreSQL closes it — `savepoint_cutoff`
    /// carries that cutoff from `exec_rollback_to` to the caller
    /// (`client_loop` / `handle_execute`), which applies
    /// `ExtendedState::close_after_savepoint`. Never reset (not
    /// even at transaction end): a statement created before a
    /// transaction must keep its LOWER clock across later
    /// savepoints in later transactions, or it would be closed
    /// by a rollback it predates.
    pub(crate) sp_clock: u64,
    /// V0.8: set by a successful ROLLBACK TO SAVEPOINT to the
    /// named savepoint's clock (see `sp_clock`); the caller
    /// consumes it exactly once with `take_savepoint_cutoff`
    /// and closes the portals / statements created after that
    /// savepoint. `None` the rest of the time.
    savepoint_cutoff: Option<u64>,
    /// m1: the tables that existed when this transaction began
    /// (its DDL snapshot). A table created by another connection
    /// AFTER this BEGIN is invisible inside the transaction —
    /// statements against it fail with 42P01. `None` outside a
    /// transaction. CREATE TABLE inside a transaction is already
    /// refused (0A000), so this set only ever shrinks nothing —
    /// it is a snapshot of names, taken at BEGIN.
    txn_tables: Option<BTreeSet<String>>,
    /// m5: when this connection last executed a statement. A
    /// transaction idle longer than `txn_idle_timeout()` is
    /// rolled back automatically (its snapshot stops pinning old
    /// versions forever). Updated on every executed statement.
    last_activity: Instant,
}

impl Session {
    pub(crate) fn new() -> Self {
        Self {
            txn: None,
            aborted: false,
            generation: 0,
            cache_epoch: 0,
            sp_clock: 0,
            savepoint_cutoff: None,
            txn_tables: None,
            last_activity: Instant::now(),
        }
    }

    /// Advance the savepoint clock and return the new value (V0.8).
    /// Called on every SAVEPOINT, Parse and Bind, so the order in
    /// which those happened is exactly the order of their clocks.
    pub(crate) fn next_sp_clock(&mut self) -> u64 {
        self.sp_clock += 1;
        self.sp_clock
    }

    /// Take the pending savepoint-rollback cutoff, if a ROLLBACK
    /// TO SAVEPOINT set one (V0.8). Consuming it here — exactly
    /// once, by the message-loop caller — is what applies the
    /// portal / statement closing for that rollback.
    pub(crate) fn take_savepoint_cutoff(&mut self) -> Option<u64> {
        self.savepoint_cutoff.take()
    }

    /// ReadyForQuery status byte: 'T' while a transaction is
    /// open, 'I' otherwise, 'E' while the transaction is aborted
    /// (M2 — PostgreSQL's "in a failed transaction" status).
    pub(crate) fn status(&self) -> u8 {
        if self.aborted {
            b'E'
        } else if self.txn.is_some() {
            b'T'
        } else {
            b'I'
        }
    }
}

/// Idle-transaction timeout (m5): a transaction that executes no
/// statement for this long is rolled back automatically, so an
/// abandoned transaction cannot pin its snapshot (and block
/// VACUUM) forever. Default 5 minutes; the
/// `ZENO_TXN_IDLE_TIMEOUT_SECS` environment variable overrides
/// it (diagnostic/test hook — e.g. `1` for a fast test).
pub(crate) fn txn_idle_timeout() -> Duration {
    std::env::var("ZENO_TXN_IDLE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(300))
}

/// Lock the shared engine, RECOVERING from poisoning instead of
/// failing. A `Mutex` poisons when a thread panics while holding
/// it — without this, one panicking statement would make every
/// later statement fail with XX000 "server lock poisoned" and the
/// server would be wedged until restart. `into_inner` recovers
/// the guard and the data underneath (the engine itself is
/// untouched by the panic — the panic happened in statement code,
/// and the WAL + SSTables on disk are still consistent), so the
/// server keeps serving. The poisoning is logged once, loudly,
/// because a panic is still a bug worth fixing — recovery is not
/// a substitute for finding it.
pub(crate) fn recover_lock<'a, T>(lock: &'a Mutex<T>) -> MutexGuard<'a, T> {
    lock.lock().unwrap_or_else(|poisoned| {
        eprintln!(
            "pgwire: WARNING: shared lock was poisoned by a panicked thread — recovering and continuing"
        );
        poisoned.into_inner()
    })
}

/// Options for `serve`: TLS on/off, the connection cap, and the
/// auto-vacuum interval.
#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    /// Serve over TLS (`--tls`): SSLRequest is answered 'S' and
    /// the handshake runs before the startup message. Requires a
    /// certificate in the data directory (`zeno cert generate`).
    pub tls: bool,
    /// Maximum simultaneous connections (default 20). Past the
    /// limit a new connection gets ErrorResponse 53300
    /// (too_many_connections) and is closed; the server keeps
    /// running.
    pub max_connections: usize,
    /// Auto-vacuum (V0.7): `Some(secs)` runs `VACUUM` in a
    /// background thread every `secs` seconds (default 60);
    /// `None` disables it (`--no-auto-vacuum`). The vacuum is
    /// the same snapshot-safe `Engine::vacuum` the `VACUUM`
    /// statement runs — a live snapshot's data is never pruned.
    pub vacuum_interval_secs: Option<u64>,
}

/// Default connection limit for `serve` (also the CLI default).
pub const DEFAULT_MAX_CONNECTIONS: usize = 20;

/// Default auto-vacuum interval for `serve` (also the CLI default).
pub const DEFAULT_VACUUM_INTERVAL_SECS: u64 = 60;

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            tls: false,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            vacuum_interval_secs: Some(DEFAULT_VACUUM_INTERVAL_SECS),
        }
    }
}

/// Start the server: open the engine (this takes the data-dir lock —
/// a second server on the same directory fails here), bind
/// 127.0.0.1:port, and serve clients forever, one thread each.
/// Binding loopback only is deliberate: trust auth (no password) is
/// only acceptable on the local machine — see the README warning.
pub fn serve(data_dir: &Path, port: u16, opts: &ServeOptions) -> std::io::Result<()> {
    let engine = Engine::open(data_dir)?;
    let tables = TableStore::open(data_dir)?;
    // Fail closed: a corrupt users.json must never silently
    // become trust auth (that would switch password auth off). A
    // missing users.json simply means "no users yet" -> trust auth.
    let users = auth::load_users(data_dir)?;
    // With --tls the certificate is loaded ONCE, up front: a
    // missing cert fails the server start with a clear error
    // instead of failing every connection mid-handshake.
    let tls_config = if opts.tls {
        Some(tls::load_server_config(data_dir)?)
    } else {
        None
    };
    let shared = Arc::new(Mutex::new(Shared {
        engine,
        tables,
        data_dir: data_dir.to_path_buf(),
        rate_limiter: Arc::new(LoginRateLimiter::new()),
    }));
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!(
        "zeno 0.11.0 listening on 127.0.0.1:{} (data dir: {})",
        port,
        data_dir.display()
    );
    if users.is_empty() {
        println!("trust auth: any local client may connect, no password — local prototype only");
    } else {
        println!(
            "SCRAM-SHA-256 auth: {} user(s) configured, password required (5 failures lock a user@IP for 5 minutes) — local prototype only{}",
            users.len(),
            if opts.tls { ", TLS on" } else { ", no TLS" }
        );
    }
    if opts.tls {
        println!("TLS enabled: SSLRequest is answered 'S' (self-signed cert — prototype only, see README)");
    }
    println!("max connections: {}", opts.max_connections);
    // Auto-vacuum (V0.7): a background thread that runs
    // `Engine::vacuum` every interval. The stop flag + join at
    // the end of this function are the clean shutdown: the
    // thread never outlives the server process, and a vacuum
    // never runs concurrently with a statement (both take the
    // same shared lock — the vacuum simply waits its turn).
    let (vacuum_stop, vacuum_thread) = match opts.vacuum_interval_secs {
        Some(secs) => {
            let stop = Arc::new(AtomicBool::new(false));
            let thread = start_auto_vacuum(
                Arc::clone(&shared),
                Duration::from_secs(secs),
                Arc::clone(&stop),
            );
            println!("auto-vacuum: every {secs}s (disable with --no-auto-vacuum)");
            (Some(stop), Some(thread))
        }
        None => {
            println!("auto-vacuum: off (--no-auto-vacuum)");
            (None, None)
        }
    };
    // Live connection count. Incremented on accept (before the
    // thread starts) and decremented when the thread ends, so a
    // connection counts from the moment it is accepted — including
    // while it is still handshaking or sitting idle.
    let active = Arc::new(AtomicUsize::new(0));
    // Graceful shutdown (V0.8): a SIGINT/SIGTERM sets `shutdown`
    // (the accept loop below stops taking new connections); a
    // SECOND signal exits immediately (force). `ctrlc` runs the
    // handler on its own thread, so setting a flag is all it
    // does — the real shutdown work happens in this thread, in
    // the open, after the accept loop ends.
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signals = Arc::new(AtomicUsize::new(0));
    {
        let shutdown = Arc::clone(&shutdown);
        let shutdown_signals = Arc::clone(&shutdown_signals);
        ctrlc::set_handler(move || {
            let n = shutdown_signals.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                eprintln!(
                    "zeno: signal received — shutting down gracefully \
                     (no new connections; up to {}s for live queries to \
                     finish; send the signal again to force exit)",
                    SHUTDOWN_GRACE.as_secs()
                );
                shutdown.store(true, Ordering::SeqCst);
            } else {
                eprintln!("zeno: second signal received — exiting immediately");
                std::process::exit(130);
            }
        })
        .map_err(|e| std::io::Error::other(format!("cannot install the signal handler: {e}")))?;
    }
    // Sockets of live connections, kept so the shutdown below can
    // force-close them after the grace period (a thread blocked
    // in `read` wakes up with an error/EOF and exits). Clones
    // only — the connection thread owns its own copy, so dropping
    // this list never closes a socket by itself. Stale entries
    // (a client that already disconnected) fail their shutdown
    // harmlessly and are ignored. Each entry is removed by the
    // connection thread itself when it ends (`LiveSocketGuard`
    // below): a clone left behind after the thread ended would
    // keep the socket open forever, so the peer would never see
    // EOF — a failed login would look like a hang to the client
    // (its read waits out the whole timeout) instead of a clean
    // close. Keyed by connection id, so the thread can remove
    // exactly its own entry.
    let live_sockets: Arc<Mutex<Vec<(u32, TcpStream)>>> = Arc::new(Mutex::new(Vec::new()));
    // Non-blocking accept: the loop polls the listener and the
    // shutdown flag together, so a signal is noticed within
    // ~5 ms instead of only when the next client connects.
    listener.set_nonblocking(true)?;
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                // F2: bound how long one idle/half-talking client can
                // hold a thread. Set on the socket (shared with the
                // BufReader clone) before the thread starts, so the
                // handshake is covered too. A timeout closes just
                // that connection — see handle_client.
                if let Err(e) = stream.set_read_timeout(Some(READ_TIMEOUT)) {
                    eprintln!("pgwire: could not set read timeout: {e}");
                }
                if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
                    eprintln!("pgwire: could not set write timeout: {e}");
                }
                // Connection limit: increment FIRST, then check, so
                // two accepts racing each other cannot both slip
                // past the cap. Over the limit the connection is
                // refused on its own short-lived thread, NOT inline
                // (V0.11, review finding 4): `refuse_over_limit`
                // reads from the client, so doing it here would let
                // one slow handshaker stall the accept loop and
                // starve new clients. The refusal is best-effort:
                // if the thread cannot even spawn, the socket is
                // just dropped (the client sees a close, not a
                // hang) and the loop keeps accepting.
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                if count > opts.max_connections {
                    active.fetch_sub(1, Ordering::SeqCst);
                    let max = opts.max_connections;
                    if let Err(e) = std::thread::Builder::new().spawn(move || {
                        refuse_over_limit(stream, max);
                    }) {
                        eprintln!("pgwire: could not spawn refusal thread: {e}");
                    }
                    continue;
                }
                let peer_ip = stream
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_default();
                let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                // V0.8: remember a clone for the shutdown
                // force-close (see `live_sockets` above). The
                // connection thread removes it when it ends (see
                // `LiveSocketGuard` in the spawn below).
                if let Ok(clone) = stream.try_clone() {
                    recover_lock(&live_sockets).push((conn_id, clone));
                }
                let shared = Arc::clone(&shared);
                let tls_config = tls_config.clone();
                let live_sockets = Arc::clone(&live_sockets);
                // M2: the counted slot is owned by this RAII guard,
                // which the connection thread takes with it. Its
                // `Drop` runs when the thread returns AND when the
                // thread panics (unwind), so a panicking connection
                // can never leak its slot. If the spawn itself
                // fails, the closure (and the guard it captured) is
                // dropped, which frees the slot the same way.
                let slot = ConnectionSlot::counted(Arc::clone(&active));
                match std::thread::Builder::new().spawn(move || {
                    let _slot = slot;
                    let _live = LiveSocketGuard {
                        sockets: live_sockets,
                        conn_id,
                    };
                    let result = handle_connection(stream, shared, conn_id, tls_config, peer_ip);
                    if let Err(e) = result {
                        eprintln!("pgwire conn {conn_id}: {e}");
                    }
                }) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("pgwire: could not spawn connection thread: {e}");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection waiting: sleep briefly, then poll
                // again (this also re-checks the shutdown flag).
                // 5 ms keeps connection acceptance fast (the old
                // blocking accept answered at once) while the
                // loop still notices a signal within milliseconds.
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                eprintln!("pgwire accept error: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    // The accept loop ended — a signal asked for a graceful
    // shutdown, or the listener failed. Either way the server
    // stops serving now and shuts down in the open, in order:
    // stop the auto-vacuum, let live connections drain (then
    // force-close them), flush + save meta, exit 0.
    if shutdown.load(Ordering::SeqCst) {
        println!("zeno: shutting down gracefully — no longer accepting connections");
    }
    if let Some(stop) = vacuum_stop {
        stop.store(true, Ordering::Relaxed);
    }
    if let Some(thread) = vacuum_thread {
        let _ = thread.join();
    }
    // Live queries get SHUTDOWN_GRACE to finish and their clients
    // to disconnect. An idle-but-connected client never drains on
    // its own — that is what the grace period is for.
    if !wait_for_drain(&active, SHUTDOWN_GRACE) {
        eprintln!(
            "zeno: {} connection(s) still live after {}s — force-closing them \
             (a query running longer than the grace period may lose its reply; \
             its committed data is already safe in the WAL)",
            active.load(Ordering::SeqCst),
            SHUTDOWN_GRACE.as_secs()
        );
        {
            let sockets = recover_lock(&live_sockets);
            for (_, s) in sockets.iter() {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
        let _ = wait_for_drain(&active, SHUTDOWN_FORCE_WAIT);
        let still = active.load(Ordering::SeqCst);
        if still > 0 {
            eprintln!(
                "zeno: warning: {still} connection thread(s) did not exit — \
                 shutting down anyway (their data is safe: every commit already \
                 fsynced its WAL)"
            );
        }
    }
    // Persist: flush the memtable to an SSTable (which also
    // clears the WAL — its records are durable in the SSTable
    // now) and save meta.json with fresh counters. If the shared
    // lock is still held by a connection thread that would not
    // die, do not block forever: try for ~2s, then exit anyway
    // — the data is already durable in the WAL, so the next open
    // replays it; only the flush and the fresh meta are skipped.
    match lock_shared_for_shutdown(&shared) {
        Some(mut guard) => {
            if let Err(e) = guard.engine.shutdown_persist() {
                eprintln!(
                    "zeno: warning: shutdown flush/meta save failed ({e}) — \
                     data is still safe in the WAL and will be replayed on the next open"
                );
            } else {
                println!("zeno: flushed memtable to SSTable and saved meta.json");
            }
        }
        None => {
            eprintln!(
                "zeno: warning: could not lock the engine for the shutdown flush \
                 (a connection thread is still holding it) — data is still safe in the WAL"
            );
        }
    }
    println!("zeno: shutdown complete — exit 0");
    Ok(())
}

/// Graceful shutdown (V0.8): how long `serve` waits after a
/// SIGINT/SIGTERM for live connections to finish their queries
/// and disconnect, before force-closing the remaining sockets.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// After the force-close, how long to wait for the connection
/// threads to notice and exit before flushing anyway.
const SHUTDOWN_FORCE_WAIT: Duration = Duration::from_secs(2);

/// Wait up to `timeout` for the live-connection counter to reach
/// zero. Returns true when it drained, false on timeout.
fn wait_for_drain(active: &AtomicUsize, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if active.load(Ordering::SeqCst) == 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    active.load(Ordering::SeqCst) == 0
}

/// Lock the shared engine for the shutdown flush, but only for
/// ~2s: a connection thread that will not die must not block the
/// shutdown forever. `None` means "could not lock in time" — the
/// caller then exits without the flush (the WAL still has the
/// data). A poisoned lock is recovered, like `recover_lock`.
fn lock_shared_for_shutdown(shared: &Mutex<Shared>) -> Option<MutexGuard<'_, Shared>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match shared.try_lock() {
            Ok(guard) => return Some(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                return Some(poisoned.into_inner());
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Background auto-vacuum (V0.7): run `Engine::vacuum` every
/// `interval` until `stop` is set. The vacuum itself is the same
/// snapshot-safe prune the `VACUUM` statement runs — versions a
/// live snapshot can still see are kept, and the committed set is
/// pruned to the oldest live snapshot's watermark — so this thread
/// can never corrupt a running transaction's view. A vacuum
/// failure (e.g. an I/O error writing the merged SSTable) is
/// logged and retried at the next interval, never fatal: the
/// thread's job is housekeeping, not serving. The sleep is split
/// into 100 ms slices so a stop request is noticed promptly even
/// with a long interval.
/// Minimum auto-vacuum interval: m5 (V0.7 review) — an
/// interval of 0 (reachable only through the library API, the
/// CLI already rejects it) made the thread busy-spin, running
/// `VACUUM` back to back with no sleep at all. Clamp to 100 ms:
/// short enough that the tests' 50 ms interval still works (it
/// becomes 100 ms), long enough that no interval can ever turn
/// the thread into a tight loop.
fn clamp_vacuum_interval(interval: Duration) -> Duration {
    interval.max(Duration::from_millis(100))
}

pub(crate) fn start_auto_vacuum(
    shared: Arc<Mutex<Shared>>,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    let interval = clamp_vacuum_interval(interval);
    std::thread::Builder::new()
        .name("zeno-auto-vacuum".to_string())
        .spawn(move || {
            loop {
                let mut waited = Duration::ZERO;
                while waited < interval {
                    let step = std::cmp::min(Duration::from_millis(100), interval - waited);
                    std::thread::sleep(step);
                    waited += step;
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                }
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                // m6 (V0.7 review): a panic inside `vacuum`
                // used to kill this thread silently — the server
                // kept running, but no auto-vacuum ever ran
                // again and nothing said so. Catch the panic,
                // log it loudly, and keep the thread alive for
                // the next interval. (The shared lock is taken
                // through `recover_lock`, so a panic that
                // poisoned it does not wedge the server either.)
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut guard = recover_lock(&shared);
                    guard.engine.vacuum()
                }));
                match result {
                    Ok(Ok(report)) => {
                        if report.pruned_versions > 0 || report.committed_pruned > 0 {
                            eprintln!(
                                "auto-vacuum: pruned {} old version(s) and {} committed txn id(s); {} SSTable(s) remain",
                                report.pruned_versions, report.committed_pruned, report.sstables
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!(
                            "auto-vacuum: vacuum failed ({e}); will retry at the next interval"
                        );
                    }
                    Err(_) => {
                        eprintln!(
                            "auto-vacuum: vacuum panicked; thread continues and will retry at the next interval"
                        );
                    }
                }
            }
        })
        .expect("could not spawn the auto-vacuum thread")
}

/// One live socket clone in the shutdown list (V0.8). The
/// connection thread takes this guard with it, and its `Drop`
/// removes the thread's clone from the list when the thread ends
/// — on a normal return AND on a panic unwind. Without this, the
/// clone would outlive the connection and the peer would never
/// see EOF (a socket sends FIN only when its last fd closes):
/// a failed login would look like a hang to the client instead
/// of a clean close, and every test that waits for EOF would
/// wait out its whole read timeout. (That is exactly what the
/// first V0.8 build did — the pgwire suite went from ~21s to
/// ~57s before this guard existed.)
struct LiveSocketGuard {
    sockets: Arc<Mutex<Vec<(u32, TcpStream)>>>,
    conn_id: u32,
}

impl Drop for LiveSocketGuard {
    fn drop(&mut self) {
        recover_lock(&self.sockets).retain(|(id, _)| *id != self.conn_id);
    }
}

/// One counted connection slot (M2). The accept loop increments
/// the live-connection counter before spawning the thread; the
/// guard takes ownership of that counted slot, and its `Drop`
/// decrements the counter when the connection thread ends — on a
/// normal return AND when the thread panics (a `Drop` runs during
/// an unwind, a `fetch_sub` after `handle_connection` returns
/// does not). Without this, enough panicking connections would
/// leak every slot and the server would refuse all new
/// connections with 53300 until restart.
pub(crate) struct ConnectionSlot {
    active: Arc<AtomicUsize>,
}

impl ConnectionSlot {
    /// Count a new connection immediately (used by the unit test).
    #[cfg(test)]
    pub(crate) fn new(active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self::counted(Arc::clone(active))
    }

    /// Take ownership of a slot the accept loop already counted.
    pub(crate) fn counted(active: Arc<AtomicUsize>) -> Self {
        Self { active }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Refuse an over-limit connection (m6), without spawning a
/// thread. The first message is peeked at with a short timeout:
/// an SSLRequest is answered 'N' first, then the 53300
/// ErrorResponse — libpq (`sslmode=prefer`, the default) reads
/// one byte expecting 'S'/'N' after its SSLRequest, so sending
/// the ErrorResponse straight away would look like a broken
/// negotiation instead of a clean "too many connections". Any
/// other first message (a plain StartupMessage), a client that
/// sends nothing, or a read timeout gets the 53300 directly.
/// The peeked message is DRAINED before closing: with unread
/// bytes still in the socket buffer, Linux resets the connection
/// (RST) on close and the 53300 below may never reach the client.
/// The drain is capped at 64 KiB — a huge claimed length is not
/// read, the refusal is just sent (an abusive client gets RST,
/// a normal one gets its 53300).
fn refuse_over_limit(mut stream: TcpStream, max_connections: usize) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut first = [0u8; 8];
    if stream.read_exact(&mut first).is_ok() {
        let code = i32::from_be_bytes([first[4], first[5], first[6], first[7]]);
        if code == SSL_REQUEST_CODE {
            let _ = stream.write_all(b"N");
            let _ = stream.flush();
            // A StartupMessage pipelined behind the SSLRequest
            // may already be on the wire — drain it too, so the
            // close below is a clean FIN, not a RST.
            let mut next = [0u8; 8];
            if stream.read_exact(&mut next).is_ok() {
                drain_first_message(&mut stream, &next);
            }
        } else {
            drain_first_message(&mut stream, &first);
        }
    }
    let _ = error_response(
        &mut stream,
        "53300",
        &format!("too many connections (limit {max_connections}) — try again later"),
    );
    let _ = stream.flush();
    eprintln!("pgwire: refused a connection: too many connections ({max_connections})");
}

/// Read the remainder of a first message whose 8-byte header
/// (`length` + `code`) is in `header`, so the socket can be
/// closed cleanly. Capped: see `refuse_over_limit`.
fn drain_first_message(stream: &mut TcpStream, header: &[u8; 8]) {
    let total_len = i32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if (8..=65536).contains(&total_len) {
        let mut rest = vec![0u8; (total_len - 8) as usize];
        let _ = stream.read_exact(&mut rest);
    }
}

/// One accepted connection: read its first 8 bytes (length +
/// code), decide plain vs TLS, then hand it to `handle_client`.
///
/// The 8 bytes are read HERE, not in the handshake, because the
/// SSLRequest decision has to happen before any protocol bytes
/// are interpreted: on a TLS connection those 8 bytes are the
/// SSLRequest itself (consumed, then 'S' + TLS handshake), and on
/// a plain connection they are the start of the StartupMessage
/// (fed back to the handshake through a `Chain` so nothing is
/// lost). A client that connects and sends nothing hits the
/// read timeout and is closed quietly; a client that closes
/// immediately is an Ok (not an error).
fn handle_connection(
    mut stream: TcpStream,
    shared: Arc<Mutex<Shared>>,
    conn_id: u32,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    peer_ip: String,
) -> std::io::Result<()> {
    // V0.11 (review finding 3): the whole handshake — from the
    // first byte of the first message to the end of SCRAM — must
    // finish by this instant. The first 8 bytes are read through
    // a `DeadlineReader` armed with it, and `handle_client` gets
    // the same instant for the rest of the handshake.
    let handshake_deadline = Instant::now() + handshake_timeout();
    let mut first = [0u8; 8];
    let mut first_reader = DeadlineReader::with_deadline(stream.try_clone()?, handshake_deadline);
    match first_reader.read_exact(&mut first) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            eprintln!("pgwire conn {conn_id}: read timeout waiting for first message, closing");
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    drop(first_reader);
    let code = i32::from_be_bytes([first[4], first[5], first[6], first[7]]);
    match code {
        SSL_REQUEST_CODE => match tls_config {
            Some(ref config) => {
                stream.write_all(b"S")?;
                stream.flush()?;
                let (reader, writer) = tls::handshake_tls(stream, config)?;
                return handle_client(
                    reader,
                    writer,
                    shared,
                    conn_id,
                    peer_ip,
                    false,
                    handshake_deadline,
                );
            }
            None => {
                stream.write_all(b"N")?; // no TLS configured for this server
                stream.flush()?;
                // B1: the SSLRequest is CONSUMED here — the 8 bytes
                // must NOT be chained back to the handshake. The
                // old code chained them, so `startup_handshake`
                // saw the same SSLRequest again and sent a second
                // 'N' (clients saw `4e 4e 52 ...`). The next bytes
                // on the socket are the StartupMessage itself.
                let reader = BufReader::new(stream.try_clone()?);
                return handle_client(
                    reader,
                    stream,
                    shared,
                    conn_id,
                    peer_ip,
                    false,
                    handshake_deadline,
                );
            }
        },
        GSSENC_REQUEST_CODE => {
            // m3: PostgreSQL answers GSSENC with 'N' (no GSSAPI
            // here), and the request is consumed, like SSLRequest.
            // On a --tls server the handshake below still refuses
            // a plaintext StartupMessage (M1), so this 'N' can
            // never smuggle a plaintext login past TLS.
            stream.write_all(b"N")?;
            stream.flush()?;
            let reader = BufReader::new(stream.try_clone()?);
            return handle_client(
                reader,
                stream,
                shared,
                conn_id,
                peer_ip,
                tls_config.is_some(),
                handshake_deadline,
            );
        }
        _ => {
            // M1: --tls means TLS is REQUIRED. A plain
            // StartupMessage (or anything else that is not an
            // SSLRequest) is refused with ErrorResponse 08P01
            // instead of completing the handshake in plaintext.
            if tls_config.is_some() {
                let _ = error_response(
                    &mut stream,
                    "08P01",
                    "TLS is required by this server (serve --tls): send an SSLRequest first",
                );
                let _ = stream.flush();
                return Ok(());
            }
        }
    }
    // Plain connection: the 8 bytes already read are the start of
    // the StartupMessage (or CancelRequest) — chain them back in
    // front of the socket so the handshake sees the whole message.
    let reader = Cursor::new(first.to_vec()).chain(BufReader::new(stream.try_clone()?));
    handle_client(
        reader,
        stream,
        shared,
        conn_id,
        peer_ip,
        false,
        handshake_deadline,
    )
}

// ---------------------------------------------------------------------
// Wire framing: one-byte type + Int32 length (self-inclusive) + body.
// The StartupMessage is the only exception: no type byte, just a
// length and a 4-byte code.
// ---------------------------------------------------------------------

/// Read one framed backend-bound message. `Ok(None)` = the client
/// closed the connection cleanly (EOF before the type byte).
///
/// The length is validated against MAX_MESSAGE_LEN BEFORE the body
/// buffer is allocated, so a hostile frame claiming 64 MiB (or a
/// negative/garbage length) can never make us allocate before we
/// know the frame is legal.
pub(crate) fn read_message(reader: &mut impl Read) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut tag = [0u8; 1];
    match reader.read_exact(&mut tag) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = i32::from_be_bytes(len_buf);
    if !(4..=MAX_MESSAGE_LEN).contains(&len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad message length {len}"),
        ));
    }
    let mut body = vec![0u8; (len - 4) as usize];
    reader.read_exact(&mut body)?;
    Ok(Some((tag[0], body)))
}

/// Write one framed message: type byte, length, body.
pub(crate) fn write_message(writer: &mut impl Write, tag: u8, body: &[u8]) -> std::io::Result<()> {
    let len = (body.len() + 4) as i32;
    writer.write_all(&[tag])?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(body)?;
    Ok(())
}

pub(crate) fn put_i16(out: &mut Vec<u8>, v: i16) {
    out.extend_from_slice(&v.to_be_bytes());
}
pub(crate) fn put_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_be_bytes());
}
pub(crate) fn put_cstr(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// AuthenticationOk: 'R' + Int32(0).
fn auth_ok(writer: &mut impl Write) -> std::io::Result<()> {
    write_message(writer, b'R', &0i32.to_be_bytes())
}

/// ParameterStatus: 'S' + name + value (both NUL-terminated).
fn parameter_status(writer: &mut impl Write, name: &str, value: &str) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_cstr(&mut body, name);
    put_cstr(&mut body, value);
    write_message(writer, b'S', &body)
}

/// BackendKeyData: 'K' + pid + secret key (4 bytes here).
fn backend_key_data(writer: &mut impl Write, pid: i32, secret: i32) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_i32(&mut body, pid);
    put_i32(&mut body, secret);
    write_message(writer, b'K', &body)
}

/// ReadyForQuery: 'Z' + status byte ('I' = idle; Zeno has no
/// transactions yet, so it is always idle).
fn ready_for_query(writer: &mut impl Write, status: u8) -> std::io::Result<()> {
    // `status` is 'I' (idle), 'T' (in a transaction), or 'E'
    // (in a FAILED transaction — M2, 25P02: the transaction is
    // aborted and only ROLLBACK will end it). The caller passes
    // `session.status()`.
    write_message(writer, b'Z', &[status])
}

/// ErrorResponse: 'E' + fields ('S' severity, 'V' severity,
/// 'C' SQLSTATE code, 'M' message), terminated by a zero byte.
/// Sending this never closes the connection. Whether a
/// ReadyForQuery follows depends on the caller: after a Simple
/// Query ('Q') or Sync ('S') it does; after an extended-protocol
/// message (Parse/Bind/Describe/Execute/Close) it does NOT — the
/// PostgreSQL protocol sends ReadyForQuery only after Sync, and
/// sending one per extended message would desync pipelined drivers.
pub(crate) fn error_response(
    writer: &mut impl Write,
    code: &str,
    message: &str,
) -> std::io::Result<()> {
    let mut body = Vec::new();
    body.push(b'S');
    put_cstr(&mut body, "ERROR");
    body.push(b'V');
    put_cstr(&mut body, "ERROR");
    body.push(b'C');
    put_cstr(&mut body, code);
    body.push(b'M');
    put_cstr(&mut body, message);
    body.push(0);
    write_message(writer, b'E', &body)
}

/// EmptyQueryResponse: 'I', for a Query that held no statement at all.
pub(crate) fn empty_query_response(writer: &mut impl Write) -> std::io::Result<()> {
    write_message(writer, b'I', &[])
}

/// RowDescription: 'T' + Int16 field count, then per field: name,
/// table OID (0 = unknown), column number (0), type OID (25 = text),
/// type length (-1), type modifier (-1), format code (0 = text).
///
/// m8 note: the field count is an Int16, so `columns.len() as i16`
/// WRAPS past 32767 columns (a 40000-column table would report a
/// negative count). Zeno tables are small in practice and no guard
/// is added in V0.3 — a table with >32767 columns is a protocol
/// error waiting to happen, not a supported case.
pub(crate) fn row_description(
    writer: &mut impl Write,
    columns: &[String],
    formats: &[i16],
) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_i16(&mut body, columns.len() as i16);
    for (i, col) in columns.iter().enumerate() {
        put_cstr(&mut body, col);
        put_i32(&mut body, 0); // table OID
        put_i16(&mut body, 0); // column number
        put_i32(&mut body, 25); // type OID: text
        put_i16(&mut body, -1); // typlen: variable
        put_i32(&mut body, -1); // typmod
                                // Format code: 0 = text, 1 = binary. `formats` holds one per
                                // column (from Bind); a missing entry means text. Binary
                                // text is the same bytes as text, so DataRow is unchanged.
        put_i16(&mut body, formats.get(i).copied().unwrap_or(0));
    }
    write_message(writer, b'T', &body)
}

/// DataRow: 'D' + Int16 field count, then per field Int32 length
/// (-1 = NULL) + bytes. V0.9: a value CAN be NULL now (a LEFT
/// JOIN miss, an empty scalar subquery, an aggregate over no
/// rows), and it is sent as a real NULL (-1), not as "".
pub(crate) fn data_row(writer: &mut impl Write, values: &[Option<String>]) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_i16(&mut body, values.len() as i16);
    for v in values {
        match v {
            None => put_i32(&mut body, -1),
            Some(v) => {
                put_i32(&mut body, v.len() as i32);
                body.extend_from_slice(v.as_bytes());
            }
        }
    }
    write_message(writer, b'D', &body)
}

/// CommandComplete: 'C' + tag, e.g. "SELECT 2", "INSERT 0 1".
pub(crate) fn command_complete(writer: &mut impl Write, tag: &str) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_cstr(&mut body, tag);
    write_message(writer, b'C', &body)
}

// ---------------------------------------------------------------------
// One connection: startup handshake, then the query loop.
// ---------------------------------------------------------------------

fn handle_client<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    shared: Arc<Mutex<Shared>>,
    conn_id: u32,
    peer_ip: String,
    // True only when this connection answered 'N' to GSSENC on a
    // `--tls` server: the channel is still plaintext, so the
    // startup below must refuse a plain login (M1).
    tls_required: bool,
    // Absolute instant by which the whole handshake must finish
    // (V0.11, review finding 3 — counted from accept, passed in
    // by `handle_connection`).
    handshake_deadline: Instant,
) -> std::io::Result<()> {
    let (data_dir, limiter) = {
        let guard = recover_lock(&shared);
        (guard.data_dir.clone(), Arc::clone(&guard.rate_limiter))
    };
    // The handshake runs under the absolute deadline; afterwards
    // the same reader switches to a fresh budget per frame.
    let mut reader = DeadlineReader::with_deadline(reader, handshake_deadline);
    // A read timeout during the handshake is a quiet client, not a
    // server error: close this connection cleanly, keep serving.
    if let Err(e) = startup_handshake(
        &mut reader,
        &mut writer,
        &data_dir,
        conn_id,
        &limiter,
        &peer_ip,
        tls_required,
    ) {
        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
            eprintln!("pgwire conn {conn_id}: read timeout during handshake, closing");
            return Ok(());
        }
        return Err(e);
    }
    reader.reset_budget(frame_timeout());

    // Per-connection transaction session (V0.6) plus the
    // extended-protocol state for this connection (prepared
    // statements + portals, and the error flag — see the loop).
    // The session lives inside `ConnSession`, whose `Drop`
    // rolls back an abandoned transaction — on EVERY exit path,
    // including a panic unwinding this thread (m3: the old code
    // rolled back only after `client_loop` returned normally,
    // so a panicking connection leaked its transaction — and
    // its snapshot — in the engine forever).
    let mut conn = ConnSession::new(shared.clone(), conn_id);
    client_loop(
        &mut reader,
        &mut writer,
        &shared,
        conn_id,
        &mut conn.session,
    )
}

/// One connection's session, with a `Drop` guard that rolls back
/// an abandoned transaction (m3). The guard owns the session, so
/// its `Drop` runs when `handle_client` returns AND when the
/// connection thread panics (a `Drop` runs during an unwind — a
/// rollback written after `client_loop` returns does not).
/// The rollback is best-effort and never panics: a `Drop`
/// during an unwind must not panic again.
pub(crate) struct ConnSession {
    session: Session,
    shared: Arc<Mutex<Shared>>,
    conn_id: u32,
}

impl ConnSession {
    pub(crate) fn new(shared: Arc<Mutex<Shared>>, conn_id: u32) -> Self {
        Self {
            session: Session::new(),
            shared,
            conn_id,
        }
    }
}

impl Drop for ConnSession {
    fn drop(&mut self) {
        // A connection that ends with a transaction still open
        // abandons it: roll it back, so uncommitted writes never
        // leak into another connection's view. (COMMIT and
        // ROLLBACK already cleared `session.txn`; this only fires
        // on disconnect, Terminate, timeout, an error return, or
        // a panic in the connection thread.)
        if let Some(txn) = self.session.txn.take() {
            let mut guard = recover_lock(&self.shared);
            if let Err(e) = guard.engine.rollback(txn) {
                eprintln!(
                    "pgwire conn {}: could not roll back abandoned transaction {txn}: {e}",
                    self.conn_id
                );
            }
        }
    }
}

/// The per-message loop of one connection, split out of
/// `handle_client` so the connection state stays in one place.
/// Transaction rollback on exit is the `ConnSession` guard's
/// `Drop` in `handle_client` (m3) — it runs on disconnect,
/// Terminate, timeout, error, AND panic, which a rollback
/// written after this loop returns could not cover.
fn client_loop<R: Read, W: Write>(
    reader: &mut DeadlineReader<R>,
    mut writer: &mut W,
    shared: &Arc<Mutex<Shared>>,
    conn_id: u32,
    session: &mut Session,
) -> std::io::Result<()> {
    // Extended-protocol state for this connection: prepared
    // statements + portals, and the error flag (see the loop).
    let mut ext = ExtendedState::new();

    loop {
        // V0.11 (review finding 3): a fresh absolute budget for
        // this frame, starting at its first byte — a client that
        // dribbles a frame out byte by byte is closed at most one
        // budget after the frame started, and its slot is freed.
        reader.start_frame();
        let msg = match read_message(reader) {
            Ok(m) => m,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // F2: the client sent half a message (or nothing)
                // and then went quiet past READ_TIMEOUT. Close just
                // this connection; the server keeps running.
                eprintln!("pgwire conn {conn_id}: read timeout, closing");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let Some((tag, body)) = msg else {
            return Ok(()); // client disconnected; server keeps running
        };
        // Error recovery (protocol 54.2.3): after an error in an
        // extended-protocol message, the backend sends ONE
        // ErrorResponse and then reads and DISCARDS every message
        // until Sync — even a Simple Query ('Q') in the batch is
        // discarded, never run. Sync ends the skip with exactly one
        // ReadyForQuery; Terminate still closes the connection.
        if ext.in_error {
            match tag {
                b'S' => {
                    ext.in_error = false;
                    ready_for_query(&mut writer, session.status())?;
                }
                b'X' => return Ok(()),
                _ => {}
            }
            writer.flush()?;
            continue;
        }

        match tag {
            b'Q' => {
                // A simple Query destroys the unnamed statement and
                // portal (protocol docs, 54.2.3 note).
                ext.clear_unnamed();
                let sql = cstr_to_string(&body);
                // A write failure here means the client is gone; stop
                // this connection, not the server.
                let generation_before = session.generation;
                run_query(&mut writer, shared, &sql, session)?;
                // B2: a COMMIT/ROLLBACK in this Simple Query ended
                // the transaction — PostgreSQL closes every portal
                // at transaction end, so do that here too (the
                // extended path does the same via the portal
                // generation check in `handle_execute`).
                if session.generation != generation_before {
                    ext.close_all_portals();
                }
                // V0.8: a ROLLBACK TO SAVEPOINT in this Simple
                // Query closed the portals / statements created
                // after that savepoint — apply the cutoff now.
                if let Some(cutoff) = session.take_savepoint_cutoff() {
                    ext.close_after_savepoint(cutoff);
                }
                ready_for_query(&mut writer, session.status())?;
            }
            b'X' => return Ok(()), // Terminate
            b'P' | b'B' | b'D' | b'E' | b'C' => {
                // Extended query protocol (see extended.rs). Success
                // replies are written by the handler; on error ONE
                // ErrorResponse is sent, NO ReadyForQuery, and the
                // connection enters skip-until-Sync mode (above) —
                // that is what keeps a pipelined driver in sync.
                let result = match tag {
                    b'P' => {
                        crate::extended::handle_parse(&mut writer, shared, &mut ext, session, &body)
                    }
                    b'B' => {
                        crate::extended::handle_bind(&mut writer, shared, &mut ext, session, &body)
                    }
                    b'D' => crate::extended::handle_describe(&mut writer, shared, &mut ext, &body),
                    b'E' => crate::extended::handle_execute(
                        &mut writer,
                        shared,
                        &mut ext,
                        session,
                        &body,
                    ),
                    _ => crate::extended::handle_close(&mut writer, &mut ext, &body),
                };
                if let Err(e) = result {
                    error_response(&mut writer, e.code, &e.message)?;
                    ext.in_error = true;
                }
            }
            b'S' => {
                // Sync: end of an extended-query cycle. This is the
                // ONLY ReadyForQuery sent for extended messages — one
                // per Sync, however many Parse/Bind/Describe/Execute
                // messages came before it.
                ready_for_query(&mut writer, session.status())?;
            }
            b'H' => {
                // Flush: no reply message of its own — just push out
                // whatever is already queued.
            }
            _ => {
                error_response(
                    &mut writer,
                    "08P01",
                    &format!("unsupported frontend message type '{}'", tag as char),
                )?;
                ready_for_query(&mut writer, session.status())?;
            }
        }
        writer.flush()?;
    }
}

/// The startup handshake. Loops over SSLRequest (answer 'N', then
/// read the real startup message) and GSSENCRequest (answer 'N',
/// same); CancelRequest closes silently; anything else that is
/// not protocol 3.0 gets an ErrorResponse and the connection is
/// closed by the caller (returning Err).
///
/// Note: with `--tls` the SSLRequest is already consumed by
/// `handle_connection` before this runs (the TLS handshake runs
/// first), so the SSLRequest arm below only ever fires on a plain
/// connection — it is kept so a client that sends SSLRequest
/// twice, or a future caller that skips `handle_connection`,
/// still gets the documented 'N' instead of a protocol error.
/// (B1: `handle_connection` must never feed an already-answered
/// SSLRequest back in here — that sent a second 'N'.)
fn startup_handshake(
    reader: &mut impl Read,
    writer: &mut impl Write,
    data_dir: &Path,
    conn_id: u32,
    limiter: &LoginRateLimiter,
    peer_ip: &str,
    tls_required: bool,
) -> std::io::Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?; // EOF here = client gave up
        let len = i32::from_be_bytes(len_buf);
        if !(8..=MAX_MESSAGE_LEN).contains(&len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad startup message length {len}"),
            ));
        }
        let mut body = vec![0u8; (len - 4) as usize];
        reader.read_exact(&mut body)?;
        if body.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "startup message too short",
            ));
        }
        let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        match code {
            SSL_REQUEST_CODE => {
                writer.write_all(b"N")?; // no TLS on this connection
                writer.flush()?;
                continue; // the real StartupMessage follows
            }
            GSSENC_REQUEST_CODE => {
                // m3: like PostgreSQL, answer GSSENC with 'N'
                // (no GSSAPI here) and read the real startup next.
                writer.write_all(b"N")?;
                writer.flush()?;
                continue;
            }
            CANCEL_REQUEST_CODE => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "CancelRequest: nothing to cancel, closing",
                ));
            }
            PROTOCOL_V3 => {
                // M1: a --tls server that reached here over a
                // plaintext channel (GSSENC 'N' path) refuses the
                // plain login with 08P01 — TLS is required.
                if tls_required {
                    let _ = error_response(
                        writer,
                        "08P01",
                        "TLS is required by this server (serve --tls): send an SSLRequest first",
                    );
                    let _ = writer.flush();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "plaintext startup on a TLS-required server",
                    ));
                }
                // Parameters are NUL-separated name/value pairs after
                // the version, ending with an empty string. We accept
                // any user/database and ignore the rest.
                let params = parse_startup_params(&body[4..]);
                let user = params
                    .iter()
                    .find(|(k, _)| k == "user")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                // Auth: `users.json` is re-read on EVERY connection,
                // so a password set with `zeno user` applies to new
                // connections at once. No users configured -> trust
                // auth (any local client, no password). Users
                // configured -> SCRAM-SHA-256 is required for every
                // connection (see auth.rs). A corrupt users.json
                // fails the connection rather than silently falling
                // back to trust auth.
                let users = auth::load_users(data_dir)?;
                if users.is_empty() {
                    auth_ok(writer)?;
                } else {
                    auth::scram_handshake(
                        reader, writer, &user, &users, data_dir, limiter, peer_ip,
                    )?;
                    auth_ok(writer)?;
                }
                // server_version "18.0" = the PostgreSQL version whose
                // wire protocol this implements (see module docs).
                // Zeno is not PostgreSQL; this only keeps clients that
                // parse the version from choking.
                parameter_status(writer, "server_version", "18.0")?;
                parameter_status(writer, "client_encoding", "UTF8")?;
                parameter_status(writer, "standard_conforming_strings", "on")?;
                let pid = std::process::id() as i32;
                // Secret key: a fresh random 32-bit value per
                // connection (CSPRNG). It used to be `pid ^
                // conn_id * constant` — predictable, which would
                // let anyone cancel anyone else's backend the day
                // CancelRequest is implemented. Cancel is still
                // unimplemented, but the secret is random now, so
                // that day needs no protocol change. (The pid ^
                // conn_id value is only the fallback if the OS
                // RNG is unavailable, which never happens on a
                // supported platform.)
                let secret = {
                    let mut buf = [0u8; 4];
                    match getrandom::getrandom(&mut buf) {
                        Ok(()) => i32::from_be_bytes(buf),
                        Err(_) => pid ^ (conn_id as i32).wrapping_mul(0x9E37_79B9u32 as i32),
                    }
                };
                backend_key_data(writer, pid, secret)?;
                ready_for_query(writer, b'I')?;
                writer.flush()?;
                return Ok(());
            }
            other => {
                let _ = error_response(
                    writer,
                    "08P01",
                    &format!("unsupported startup message code {other} (only protocol 3.0)"),
                );
                let _ = writer.flush();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsupported startup message code {other}"),
                ));
            }
        }
    }
}

/// Parse the NUL-separated name/value pairs of a StartupMessage into
/// (name, value) pairs. Malformed tails are ignored, not fatal.
fn parse_startup_params(body: &[u8]) -> Vec<(String, String)> {
    let mut params = Vec::new();
    let parts: Vec<&[u8]> = body.split(|b| *b == 0).collect();
    let mut i = 0;
    while i + 1 < parts.len() {
        let name = String::from_utf8_lossy(parts[i]).into_owned();
        if name.is_empty() {
            break;
        }
        let value = String::from_utf8_lossy(parts[i + 1]).into_owned();
        params.push((name, value));
        i += 2;
    }
    params
}

/// A NUL-terminated string at the start of `body`, lossy-decoded.
/// The Query message body is exactly one such string.
fn cstr_to_string(body: &[u8]) -> String {
    let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).into_owned()
}

// ---------------------------------------------------------------------
// Simple Query execution: split on ';' (outside quotes), run each
// statement, write its responses. Errors are per-statement: an
// ErrorResponse is sent and the next statement still runs.
// ---------------------------------------------------------------------

fn run_query(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    sql: &str,
    session: &mut Session,
) -> std::io::Result<()> {
    let statements = split_statements(sql);
    if statements.iter().all(|s| s.trim().is_empty()) {
        empty_query_response(writer)?;
        return Ok(());
    }
    for stmt in statements {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        match execute_statement(shared, stmt, session) {
            Ok(outcome) => write_outcome(writer, &outcome, &[])?,
            Err(e) => {
                // SQL error: report it, keep the connection alive.
                error_response(writer, e.code, &e.message)?;
            }
        }
    }
    writer.flush()
}

/// Write one statement's result messages (Simple Query path: the
/// whole result at once). `formats` holds one format code per output
/// column (0 = text, 1 = binary); an empty slice means "all text",
/// which is what Simple Query always uses. Extended Execute writes
/// its own slices (PortalSuspended), so it does not use this.
pub(crate) fn write_outcome(
    writer: &mut impl Write,
    outcome: &StmtOutcome,
    formats: &[i16],
) -> std::io::Result<()> {
    match outcome {
        StmtOutcome::Empty => Ok(()),
        StmtOutcome::Command(tag) => command_complete(writer, tag),
        StmtOutcome::Rows { columns, rows } => {
            row_description(writer, columns, formats)?;
            for values in rows {
                data_row(writer, values)?;
            }
            command_complete(writer, &format!("SELECT {}", rows.len()))
        }
    }
}

/// Split SQL on ';' that sits outside single-quoted strings,
/// double-quoted identifiers, `--` line comments and `/* */`
/// block comments. `''` inside a string is an escaped quote, not
/// the end of it, and `""` inside a double-quoted identifier is
/// the same. Comment text (including any ';' in it) is dropped;
/// the newline ending a line comment is kept so the statements
/// stay separated, and a block comment is replaced by one space
/// so the tokens around it never merge (`SELECT/*c*/*` stays two
/// tokens, not one).
pub(crate) fn split_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_string = false; // '...'
    let mut in_ident = false; // "..."
    let mut in_comment = false; // -- to end of line
    let mut in_block_comment = false; // /* ... */
    while let Some(c) = chars.next() {
        if in_block_comment {
            // A `/*` inside a block comment does not nest (like
            // PostgreSQL): the first `*/` ends the comment.
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue; // comment text (and its ';') is dropped
        }
        if in_comment {
            if c == '\n' {
                in_comment = false;
                cur.push(c);
            }
            continue; // comment text (and its ';') is dropped
        }
        if in_string {
            cur.push(c);
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    cur.push(chars.next().unwrap()); // escaped ''
                } else {
                    in_string = false;
                }
            }
            continue;
        }
        if in_ident {
            cur.push(c);
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push(chars.next().unwrap()); // escaped ""
                } else {
                    in_ident = false;
                }
            }
            continue;
        }
        match c {
            '\'' => {
                in_string = true;
                cur.push(c);
            }
            '"' => {
                in_ident = true;
                cur.push(c);
            }
            '-' if chars.peek() == Some(&'-') => {
                chars.next(); // consume the second '-'
                in_comment = true;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next(); // consume the '*'
                in_block_comment = true;
                cur.push(' '); // keep the tokens around it apart
            }
            ';' => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// One SQL error: a PostgreSQL SQLSTATE code + message. `code` is
/// "42601" (syntax error), "42P01" (undefined table), "42703"
/// (undefined column), "42P07" (table already exists), "0A000"
/// (feature not supported), or one of the extended-protocol codes
/// ("08P01" protocol violation, "26000" unknown prepared statement
/// or portal, "42P05"/"42P03" duplicate statement/portal, "42P18"
/// indeterminate parameter type, "22P02"/"22P03" bad parameter
/// value, "54000" too many parameters).
#[derive(Debug)]
pub(crate) struct SqlError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

pub(crate) fn sql_err(code: &'static str, message: impl Into<String>) -> SqlError {
    SqlError {
        code,
        message: message.into(),
    }
}

/// The result of running one statement, without any wire bytes:
/// the caller decides how to write it — Simple Query writes it all
/// at once (`write_outcome`); extended Execute may stream it in
/// slices and end with PortalSuspended instead of CommandComplete.
pub(crate) enum StmtOutcome {
    /// SELECT: output columns + all rows (values in column
    /// order; `None` = SQL NULL — V0.9: a LEFT JOIN miss, an
    /// empty scalar subquery, or an aggregate over no rows).
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
    },
    /// CREATE / INSERT / DELETE: the CommandComplete tag.
    Command(String),
    /// An empty statement: nothing to send.
    Empty,
}

/// Run one statement given as SQL text. The raw text is passed
/// through to `execute_tokens_with_sql` so the V0.7 parser can
/// report syntax errors with their real line and column; the
/// extended protocol has no raw text (its tokens already carry
/// substituted parameter values) and goes through `execute_tokens`
/// instead, which reconstructs the SQL from the tokens.
pub(crate) fn execute_statement(
    shared: &Arc<Mutex<Shared>>,
    stmt: &str,
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let tokens = match tokenize(stmt) {
        Some(tokens) => tokens,
        None => {
            // The old tokenizer only fails on an unterminated
            // string literal or block comment — the new parser
            // reports the same failure with its line and column.
            if let Err(e) = parse_sql(stmt) {
                return Err(sql_err(e.code, e.to_sql_message()));
            }
            return Err(sql_err("42601", "unterminated string literal"));
        }
    };
    execute_tokens_with_sql(shared, &tokens, session, Some(stmt))
}

/// Run one statement given as tokens. Extended Execute uses this
/// after substituting the bound parameter values for the `$n`
/// placeholders, so parameters can never be re-parsed as SQL.
/// `session` carries this connection's transaction (if any):
/// statements inside a transaction run against its snapshot and
/// buffer, statements outside one autocommit.
pub(crate) fn execute_tokens(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    execute_tokens_with_sql(shared, tokens, session, None)
}

/// The shared execution path: `raw_sql` is `Some` for Simple
/// Query (the statement text as the client sent it) and `None`
/// for the extended protocol (whose SQL is reconstructed from the
/// substituted tokens — line numbers there are approximate, but
/// the statement is the same one Parse already accepted).
fn execute_tokens_with_sql(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
    raw_sql: Option<&str>,
) -> Result<StmtOutcome, SqlError> {
    let kind = classify_statement(tokens)?;
    // M2: in an aborted transaction only ROLLBACK and ROLLBACK TO
    // SAVEPOINT run. Anything else — including COMMIT — is 25P02,
    // and the transaction stays open (aborted) until one of them.
    // (V0.7: ROLLBACK TO SAVEPOINT is PostgreSQL's way back out
    // of the aborted state, so it is allowed here too.)
    if session.aborted && !matches!(kind, StmtKind::Rollback | StmtKind::RollbackTo) {
        return Err(sql_err(
            "25P02",
            "current transaction is aborted, commands ignored until end of transaction block",
        ));
    }
    // m5: a transaction that has executed no statement for
    // longer than the idle timeout is rolled back here, so its
    // snapshot stops pinning old versions (and blocking VACUUM)
    // forever. The generation bump also kills its portals (B2).
    if let Some(txn) = session.txn {
        if session.last_activity.elapsed() > txn_idle_timeout() {
            let idle_secs = txn_idle_timeout().as_secs();
            {
                let mut guard = recover_lock(shared);
                let _ = guard.engine.rollback(txn);
            }
            session.txn = None;
            session.aborted = false;
            session.txn_tables = None;
            session.generation += 1;
            return Err(sql_err(
                "57014",
                format!(
                    "transaction aborted: idle for longer than {idle_secs}s \
                     (idle-transaction timeout) — it was rolled back"
                ),
            ));
        }
    }
    session.last_activity = Instant::now();
    let outcome = match kind {
        // V0.7: data statements go through the real parser
        // (`parser.rs`) — Simple Query parses the raw text (real
        // line/column errors), the extended protocol parses the
        // SQL reconstructed from its substituted tokens.
        StmtKind::Create
        | StmtKind::Insert
        | StmtKind::Select
        | StmtKind::Delete
        | StmtKind::Update => {
            let sql = match raw_sql {
                Some(text) => text.to_string(),
                None => tokens_to_sql(tokens),
            };
            let parsed = parse_sql(&sql).map_err(|e| sql_err(e.code, e.to_sql_message()))?;
            execute_parsed(shared, &parsed, session)
        }
        StmtKind::Begin => exec_begin(shared, tokens, session),
        StmtKind::Commit => exec_commit(shared, tokens, session),
        StmtKind::Rollback => exec_rollback(shared, tokens, session),
        StmtKind::Savepoint => exec_savepoint(shared, tokens, session),
        StmtKind::RollbackTo => exec_rollback_to(shared, tokens, session),
        StmtKind::Release => exec_release(shared, tokens, session),
        StmtKind::Vacuum => exec_vacuum(shared, tokens, session),
        StmtKind::Empty => Ok(StmtOutcome::Empty),
    };
    // M2: a data-statement failure (INSERT/SELECT/UPDATE/
    // DELETE) inside a transaction aborts it — the connection
    // is in the 25P02 state until ROLLBACK. Deliberately NOT
    // set for DDL (CREATE: 0A000 — the transaction survives a
    // failed CREATE, as the `txn_errors` test pins), nested
    // BEGIN (25001), or COMMIT/ROLLBACK themselves (a failed
    // COMMIT already ended the transaction in the engine).
    if outcome.is_err()
        && session.txn.is_some()
        && matches!(
            kind,
            StmtKind::Insert | StmtKind::Select | StmtKind::Delete | StmtKind::Update
        )
    {
        session.aborted = true;
    }
    outcome
}

/// Which of the supported statements (if any) `tokens` holds.
/// Extended Parse reuses this, so a bad statement fails at Parse
/// time with the same error a Simple Query would get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StmtKind {
    Create,
    Insert,
    Select,
    Delete,
    Update,
    Begin,
    Commit,
    Rollback,
    /// `SAVEPOINT <name>` (V0.7).
    Savepoint,
    /// `ROLLBACK TO [SAVEPOINT] <name>` (V0.7).
    RollbackTo,
    /// `RELEASE [SAVEPOINT] <name>` (V0.7).
    Release,
    Vacuum,
    Empty,
}

pub(crate) fn classify_statement(tokens: &[Token]) -> Result<StmtKind, SqlError> {
    let first = tokens
        .first()
        .map(|t| t.text.to_ascii_uppercase())
        .unwrap_or_default();
    match first.as_str() {
        "CREATE" => Ok(StmtKind::Create),
        "INSERT" => Ok(StmtKind::Insert),
        "SELECT" => Ok(StmtKind::Select),
        "DELETE" => Ok(StmtKind::Delete),
        "UPDATE" => Ok(StmtKind::Update),
        "BEGIN" | "START" => Ok(StmtKind::Begin),
        "COMMIT" | "END" => Ok(StmtKind::Commit),
        // `ROLLBACK TO ...` is a savepoint rollback, not a full
        // rollback — it keeps the transaction open (V0.7).
        "ROLLBACK" | "ABORT" => {
            if tokens
                .get(1)
                .map(|t| t.text.eq_ignore_ascii_case("TO"))
                .unwrap_or(false)
            {
                Ok(StmtKind::RollbackTo)
            } else {
                Ok(StmtKind::Rollback)
            }
        }
        "SAVEPOINT" => Ok(StmtKind::Savepoint),
        "RELEASE" => Ok(StmtKind::Release),
        "VACUUM" => Ok(StmtKind::Vacuum),
        "DROP" | "ALTER" | "SET" | "SHOW" | "GRANT" | "REVOKE" | "TRUNCATE" | "COPY"
        | "EXPLAIN" => Err(sql_err(
            "0A000",
            format!("{first} is not supported in Zeno 0.11.0 (only CREATE TABLE, INSERT, UPDATE, SELECT, DELETE, VACUUM, BEGIN, COMMIT, ROLLBACK, SAVEPOINT, RELEASE SAVEPOINT, ROLLBACK TO SAVEPOINT)"),
        )),
        "" => Ok(StmtKind::Empty),
        other => Err(sql_err(
            "42601",
            format!("syntax error: unsupported statement starting with '{other}'"),
        )),
    }
}

/// Rebuild SQL text from old-style tokens (extended protocol):
/// quoted strings are re-quoted with `''` escaping, quoted
/// identifiers with `""` escaping, everything else is its text.
/// The result is re-parsed by the V0.7 parser, so a substituted
/// parameter value can never be re-parsed as SQL — it arrives
/// here as a quoted-string token and leaves as a quoted literal.
/// `;` tokens are dropped (Simple Query splits on them first,
/// and the extended protocol forbids multi-statement strings).
pub(crate) fn tokens_to_sql(tokens: &[Token]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(tokens.len());
    for t in tokens {
        if t.text == ";" {
            continue;
        }
        if t.quoted_string {
            parts.push(format!("'{}'", t.text.replace('\'', "''")));
        } else if t.quoted_ident {
            parts.push(format!("\"{}\"", t.text.replace('"', "\"\"")));
        } else {
            parts.push(t.text.clone());
        }
    }
    parts.join(" ")
}

// ---------------------------------------------------------------------
// A tiny tokenizer: identifiers (bare or "double-quoted"), string
// literals ('single-quoted', '' = escaped quote), numbers, and the
// punctuation ( ) , = * . Nothing else is needed for the V0.3 subset.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Token {
    /// The token text, unquoted: for 'abc' this is `abc`, for "col"
    /// this is `col`, for bare words/numbers the word itself.
    pub(crate) text: String,
    /// True only for a 'single-quoted' string literal.
    pub(crate) quoted_string: bool,
    /// True only for a "double-quoted" identifier. A `$1` inside
    /// one is an identifier, not a parameter placeholder.
    pub(crate) quoted_ident: bool,
}

pub(crate) fn tokenize(sql: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = sql.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '\'' => {
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None => return None, // unterminated string
                        Some('\'') => {
                            if chars.peek() == Some(&'\'') {
                                chars.next();
                                s.push('\'');
                            } else {
                                break;
                            }
                        }
                        Some(ch) => s.push(ch),
                    }
                }
                tokens.push(Token {
                    text: s,
                    quoted_string: true,
                    quoted_ident: false,
                });
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None => return None,
                        // `""` inside a double-quoted identifier is
                        // an escaped quote, not the end of it.
                        Some('"') => {
                            if chars.peek() == Some(&'"') {
                                chars.next();
                                s.push('"');
                            } else {
                                break;
                            }
                        }
                        Some(ch) => s.push(ch),
                    }
                }
                tokens.push(Token {
                    text: s,
                    quoted_string: false,
                    quoted_ident: true,
                });
            }
            '/' => {
                chars.next();
                if chars.peek() == Some(&'*') {
                    // `/* ... */` block comment: skipped entirely,
                    // like whitespace. A `/*` inside a string or
                    // identifier never reaches here (those loops
                    // consume it first), and an unterminated block
                    // comment is a syntax error (None -> 42601).
                    chars.next();
                    loop {
                        match chars.next() {
                            None => return None,
                            Some('*') if chars.peek() == Some(&'/') => {
                                chars.next();
                                break;
                            }
                            Some(_) => {}
                        }
                    }
                } else {
                    tokens.push(Token {
                        text: "/".to_string(),
                        quoted_string: false,
                        quoted_ident: false,
                    });
                }
            }
            '(' | ')' | ',' | '=' | '*' | '.' | ';' => {
                tokens.push(Token {
                    text: c.to_string(),
                    quoted_string: false,
                    quoted_ident: false,
                });
                chars.next();
            }
            _ => {
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    // '/' ends a bare token too: `SELECT/*c*/FROM`
                    // must tokenize as SELECT, FROM — the '/' arm
                    // above then skips the block comment.
                    if ch.is_whitespace() || "()',=\";*/".contains(ch) {
                        break;
                    }
                    s.push(ch);
                    chars.next();
                }
                if !s.is_empty() {
                    tokens.push(Token {
                        text: s,
                        quoted_string: false,
                        quoted_ident: false,
                    });
                }
            }
        }
    }
    Some(tokens)
}

/// Case-insensitive keyword match at `tokens[i]`; returns the index
/// after the keyword, or None.
pub(crate) fn expect_keyword(tokens: &[Token], i: usize, kw: &str) -> Option<usize> {
    if tokens
        .get(i)
        .map(|t| t.text.eq_ignore_ascii_case(kw))
        .unwrap_or(false)
    {
        Some(i + 1)
    } else {
        None
    }
}

/// A table/column name: any non-quoted-string token that is not
/// punctuation. (Keywords as names are allowed here — this is a
/// prototype subset, not full PostgreSQL.)
pub(crate) fn expect_name(tokens: &[Token], i: usize) -> Option<(String, usize)> {
    let t = tokens.get(i)?;
    if t.quoted_string || ["(", ")", ",", "=", "*", "."].contains(&t.text.as_str()) {
        return None;
    }
    Some((t.text.clone(), i + 1))
}

// ---------------------------------------------------------------------
// The four statements (V0.7: parsed by `parser.rs`, executed below).
// ---------------------------------------------------------------------

/// m1: a table is visible inside a transaction only if it
/// existed when the transaction began (its DDL snapshot, taken
/// in `exec_begin`). A table created by another connection
/// after this BEGIN is invisible here — 42P01, as if it did not
/// exist yet. Outside a transaction every registered table is
/// visible. (CREATE TABLE inside a transaction is refused with
/// 0A000, so a transaction can never see its own DDL.)
pub(crate) fn check_table_visible_in_txn(session: &Session, name: &str) -> Result<(), SqlError> {
    if let Some(tables) = &session.txn_tables {
        if !tables.contains(name) {
            return Err(sql_err(
                "42P01",
                format!(
                    "no such table '{name}' (it was created after this transaction began — \
                     DDL is not snapshot-isolated in the registry, so a transaction only \
                     sees the tables that existed at its BEGIN; COMMIT or ROLLBACK first)"
                ),
            ));
        }
    }
    Ok(())
}

/// Run a parsed data statement (V0.7): the AST from `parser.rs`
/// against the engine/table registry. Transaction control never
/// reaches here — it is dispatched from `execute_tokens_with_sql`
/// on the old token list.
fn execute_parsed(
    shared: &Arc<Mutex<Shared>>,
    parsed: &ParsedStmt,
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    match parsed {
        ParsedStmt::Create { table, columns } => exec_create_ast(shared, table, columns, session),
        ParsedStmt::Insert {
            table,
            columns,
            rows,
        } => exec_insert_ast(shared, table, columns, rows, session),
        ParsedStmt::Select { .. } => exec_select_ast(shared, parsed, session),
        ParsedStmt::Delete { table, conditions } => {
            exec_delete_ast(shared, table, conditions, session)
        }
        ParsedStmt::Update {
            table,
            sets,
            conditions,
        } => exec_update_ast(shared, table, sets, conditions, session),
    }
}

/// A parsed value as a stored cell. `None` is a SQL NULL (V0.11):
/// a bare `NULL` stores as a real NULL, and a quoted `'NULL'` is
/// still the text "NULL" (the parser only produces `Null` for the
/// bare word). A `$n` placeholder that survived substitution (a
/// prepared statement executed without Bind, which cannot happen
/// through the wire protocol) is a syntax error, not data — storing
/// the literal "$1" would be a silent corruption of the row.
fn resolve_value(value: &ParsedValue) -> Result<Option<String>, SqlError> {
    match value {
        ParsedValue::Text(text) => Ok(Some(text.clone())),
        ParsedValue::Null => Ok(None),
        ParsedValue::Param(n) => Err(sql_err(
            "42601",
            format!("parameter ${n} has no bound value — Bind the statement before executing it"),
        )),
    }
}

/// A WHERE column that is not in the table's registry columns is
/// 42703 (V0.11, review finding 13 — the same rule as SELECT).
/// Called by UPDATE / DELETE before the filter runs, so a typo
/// fails the statement instead of silently matching no rows.
/// A qualified column naming another table is rejected by
/// `to_filter` already; this only checks the bare name.
fn check_where_columns_exist(
    tables: &TableStore,
    table: &str,
    conditions: &[crate::parser::Condition],
) -> Result<(), SqlError> {
    let Some(columns) = tables.columns(table) else {
        return Err(sql_err("42P01", format!("no such table '{table}'")));
    };
    for cond in conditions {
        if !columns.iter().any(|c| c == &cond.column.name) {
            return Err(sql_err(
                "42703",
                format!(
                    "column '{}' does not exist in table '{table}'",
                    cond.column.name
                ),
            ));
        }
    }
    Ok(())
}

/// A parsed WHERE (AND-joined conditions) as a `RowFilter` for
/// the table store. Only literal comparisons reach here — the
/// parser rejects subqueries in UPDATE / DELETE (0A000), and a
/// qualified column must name this table (42703 otherwise).
fn to_filter(table: &str, conditions: &[crate::parser::Condition]) -> Result<RowFilter, SqlError> {
    let mut filter = RowFilter::default();
    for cond in conditions {
        if let Some(q) = &cond.column.qualifier {
            if q != table {
                return Err(sql_err(
                    "42703",
                    format!("missing FROM-clause entry for table '{q}'"),
                ));
            }
        }
        let op = match cond.op {
            CmpOp::Eq => FilterOp::Eq,
            CmpOp::Ne => FilterOp::Ne,
            CmpOp::Lt => FilterOp::Lt,
            CmpOp::Gt => FilterOp::Gt,
            CmpOp::Le => FilterOp::Le,
            CmpOp::Ge => FilterOp::Ge,
        };
        let crate::parser::CondRhs::Value(value) = &cond.rhs else {
            return Err(sql_err(
                "0A000",
                match &cond.rhs {
                    crate::parser::CondRhs::Column(_) => {
                        "a column-to-column comparison is not supported in UPDATE / DELETE \
                         in Zeno 0.11.0 — use a literal value"
                    }
                    _ => {
                        "subqueries are not supported in UPDATE / DELETE in Zeno 0.11.0 — \
                         use a literal value"
                    }
                },
            ));
        };
        filter
            .conditions
            .push((cond.column.name.clone(), op, resolve_value(value)?));
    }
    Ok(filter)
}

/// Map a table-store error to its SQLSTATE: "no such table" is
/// 42P01, an unknown column is 42703, anything else is 42601
/// (a count mismatch or a registry error).
pub(crate) fn table_err(e: String) -> SqlError {
    if e.contains("no such table") {
        sql_err("42P01", e)
    } else if e.contains("does not exist") {
        sql_err("42703", e)
    } else {
        sql_err("42601", e)
    }
}

/// CREATE TABLE name (col [type ...], ...) — column types are
/// parsed by `parser.rs` and ignored: every Zeno column is text.
/// `CREATE TABLE users (id int, name text)` therefore also works,
/// and so does `VARCHAR(10)` (V0.6 rejected it).
/// DDL inside a transaction is NOT supported in V0.7 either: the
/// table registry (`tables.json`) is not versioned, so a CREATE
/// that later rolled back could not be undone — it fails with
/// 0A000. Run DDL outside transactions (COMMIT or ROLLBACK first).
fn exec_create_ast(
    shared: &Arc<Mutex<Shared>>,
    name: &str,
    columns: &[(String, Option<String>)],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    if session.txn.is_some() {
        return Err(sql_err(
            "0A000",
            "CREATE TABLE is not supported inside a transaction in Zeno 0.11.0 \
             (DDL is not versioned — run it outside a transaction, after COMMIT or ROLLBACK)",
        ));
    }
    // Poison recovery (V0.5): a thread that panicked while holding
    // this lock must not wedge the server — see `recover_lock`.
    let mut guard = recover_lock(shared);
    guard
        .tables
        .create_table(name, columns.iter().map(|(c, _)| c.clone()).collect())
        .map_err(|e| {
            if e.contains("already exists") {
                sql_err("42P07", e)
            } else {
                sql_err("42601", e)
            }
        })?;
    Ok(StmtOutcome::Command("CREATE TABLE".to_string()))
}

/// INSERT INTO name [(cols)] VALUES (...), (...), ... — values are
/// quoted strings, numbers or bare words; the count must match
/// the table's columns (or the column list, when given). With a
/// column list the values are stored in registry column order,
/// so `INSERT INTO t (city, id) VALUES ('Delhi', 1)` lands in
/// the right columns. Inside a transaction the rows are buffered
/// (visible to this connection only) until COMMIT.
fn exec_insert_ast(
    shared: &Arc<Mutex<Shared>>,
    name: &str,
    columns: &Option<Vec<String>>,
    rows: &[Vec<ParsedValue>],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    check_table_visible_in_txn(session, name)?;
    // Poison recovery (V0.5): see `recover_lock`.
    let mut guard = recover_lock(shared);
    let registry_columns = guard
        .tables
        .columns(name)
        .ok_or_else(|| sql_err("42P01", format!("no such table '{name}'")))?
        .to_vec();
    // Resolve every value first, then map each row onto the
    // registry column order (validating the column list here,
    // before any row is written — a bad column must fail the
    // whole statement, not half of it).
    let mut full_rows: Vec<Vec<Option<String>>> = Vec::with_capacity(rows.len());
    match columns {
        Some(list) => {
            for col in list {
                if !registry_columns.iter().any(|c| c == col) {
                    return Err(sql_err(
                        "42703",
                        format!("column '{col}' does not exist in table '{name}'"),
                    ));
                }
            }
            if list.len() != registry_columns.len() {
                // A column list that names only some columns
                // would leave the rest unspecified — Zeno has no
                // defaults, so every column must be given exactly
                // once (write NULL for a column with no value).
                return Err(sql_err(
                    "42601",
                    format!(
                        "INSERT column list has {} columns but table '{name}' has {} — \
                         every column must be listed exactly once (Zeno has no defaults; \
                         use NULL for an empty value)",
                        list.len(),
                        registry_columns.len()
                    ),
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            for col in list {
                if !seen.insert(col) {
                    return Err(sql_err(
                        "42601",
                        format!("column '{col}' is listed twice in the INSERT column list"),
                    ));
                }
            }
            for row in rows {
                let mut full = vec![None; registry_columns.len()];
                for (col, value) in list.iter().zip(row.iter()) {
                    let pos = registry_columns
                        .iter()
                        .position(|c| c == col)
                        .expect("column list was validated against the registry above");
                    full[pos] = resolve_value(value)?;
                }
                full_rows.push(full);
            }
        }
        None => {
            for row in rows {
                if row.len() != registry_columns.len() {
                    return Err(sql_err(
                        "42601",
                        format!(
                            "table '{name}' has {} columns, got {} values",
                            registry_columns.len(),
                            row.len()
                        ),
                    ));
                }
                let mut full = Vec::with_capacity(row.len());
                for value in row {
                    full.push(resolve_value(value)?);
                }
                full_rows.push(full);
            }
        }
    }
    let Shared { engine, tables, .. } = &mut *guard;
    let mut inserted = 0usize;
    for values in full_rows {
        match session.txn {
            Some(txn) => {
                tables
                    .insert_txn(engine, txn, name, values)
                    .map_err(table_err)?;
            }
            None => {
                tables.insert(engine, name, values).map_err(table_err)?;
            }
        }
        inserted += 1;
    }
    Ok(StmtOutcome::Command(format!("INSERT 0 {inserted}")))
}

/// A parsed SELECT, ready to run: output columns (resolved
/// against the registry — `*` becomes all columns in registry
/// order). Extended Bind/Describe reuse this so a prepared SELECT
/// is checked the same way a Simple Query SELECT is, without
/// executing it. (V0.7: the SQL is rebuilt from the tokens and
/// re-parsed by the real parser, so ORDER BY / LIMIT /
/// multi-condition WHERE parse here too — but only the output
/// columns are needed for Describe, so the rest of the AST is
/// dropped.)
pub(crate) struct SelectPlan {
    pub columns: Vec<String>,
}

/// Parse `SELECT ... FROM name ...` from old-style tokens and
/// resolve its output columns. The WHERE column is NOT checked
/// against the registry here — it is checked at execution time
/// in `query::eval_condition`, which returns 42703 for an unknown
/// column since V0.11 (review finding 13).
/// (V0.9: the output columns come from `query::output_columns`,
/// which also resolves JOINs, aliases and aggregates — a
/// `SELECT *` over a JOIN expands to every column of every
/// table in scope.)
pub(crate) fn parse_select(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
) -> Result<SelectPlan, SqlError> {
    let sql = tokens_to_sql(tokens);
    let parsed = parse_sql(&sql).map_err(|e| sql_err(e.code, e.to_sql_message()))?;
    let ParsedStmt::Select { .. } = parsed else {
        return Err(sql_err("42601", "expected SELECT"));
    };
    let guard = recover_lock(shared);
    let columns = crate::query::output_columns(&guard.tables, &parsed)?;
    Ok(SelectPlan { columns })
}

/// SELECT in V0.9 (see `query.rs` for the executor): JOINs,
/// subqueries, GROUP BY + aggregates, ORDER BY / LIMIT /
/// OFFSET. Inside a transaction this reads the transaction's
/// BEGIN snapshot (plus its own writes) — never newer commits
/// — including the JOINed tables and any subquery.
fn exec_select_ast(
    shared: &Arc<Mutex<Shared>>,
    parsed: &ParsedStmt,
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let ParsedStmt::Select { .. } = parsed else {
        // `execute_parsed` only calls this for a SELECT — this
        // arm is unreachable, but returning an error beats
        // panicking if the dispatch ever changes.
        return Err(sql_err(
            "XX000",
            "internal error: exec_select_ast called with a non-SELECT statement",
        ));
    };
    // B2 (V0.9 review): a SELECT used to hold the shared lock
    // for its whole run, so one slow query blocked every other
    // connection. Now only the snapshot is taken under the lock
    // (one scan per table, fast); the join / WHERE / grouping
    // runs against the snapshot with the lock released, under a
    // statement timeout (see `query::statement_deadline`).
    // Poison recovery (V0.5): a thread that panicked while holding
    // this lock must not wedge the server — see `recover_lock`.
    let snapshot = {
        let mut guard = recover_lock(shared);
        let Shared { engine, tables, .. } = &mut *guard;
        crate::query::collect_snapshot(engine, tables, session, parsed)?
    };
    let (columns, rows) = crate::query::execute_select_snapshot(&snapshot, parsed)?;
    Ok(StmtOutcome::Rows { columns, rows })
}

/// DELETE FROM name [WHERE ...] — without WHERE, all rows go.
/// Inside a transaction the deletes are buffered until COMMIT.
fn exec_delete_ast(
    shared: &Arc<Mutex<Shared>>,
    name: &str,
    conditions: &[crate::parser::Condition],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let filter = to_filter(name, conditions)?;
    check_table_visible_in_txn(session, name)?;
    // Poison recovery (V0.5): a thread that panicked while holding
    // this lock must not wedge the server — see `recover_lock`.
    let mut guard = recover_lock(shared);
    check_where_columns_exist(&guard.tables, name, conditions)?;
    let Shared { engine, tables, .. } = &mut *guard;
    let deleted = match session.txn {
        Some(txn) => tables
            .delete_filtered(engine, Some(txn), name, Some(&filter))
            .map_err(table_err)?,
        None => tables
            .delete_filtered(engine, None, name, Some(&filter))
            .map_err(table_err)?,
    };
    Ok(StmtOutcome::Command(format!("DELETE {deleted}")))
}

/// UPDATE name SET col = value [, col = value ...] [WHERE ...]
/// (V0.7: several SET assignments, multi-condition WHERE). Each
/// matching row is rewritten as a new version; the CommandComplete
/// tag reports the row count (`UPDATE n`). Inside a transaction
/// the new versions are buffered until COMMIT, and the rows
/// matched are the ones the transaction's snapshot sees.
fn exec_update_ast(
    shared: &Arc<Mutex<Shared>>,
    name: &str,
    sets: &[(String, ParsedValue)],
    conditions: &[crate::parser::Condition],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let filter = to_filter(name, conditions)?;
    let mut resolved_sets: Vec<(String, Option<String>)> = Vec::with_capacity(sets.len());
    for (col, value) in sets {
        resolved_sets.push((col.clone(), resolve_value(value)?));
    }
    let set_refs: Vec<(&str, Option<&str>)> = resolved_sets
        .iter()
        .map(|(c, v)| (c.as_str(), v.as_deref()))
        .collect();
    check_table_visible_in_txn(session, name)?;
    // Poison recovery (V0.5): a thread that panicked while holding
    // this lock must not wedge the server — see `recover_lock`.
    let mut guard = recover_lock(shared);
    check_where_columns_exist(&guard.tables, name, conditions)?;
    let Shared { engine, tables, .. } = &mut *guard;
    let updated = match session.txn {
        Some(txn) => tables
            .update_many_filtered(engine, Some(txn), name, &set_refs, Some(&filter))
            .map_err(table_err)?,
        None => tables
            .update_many_filtered(engine, None, name, &set_refs, Some(&filter))
            .map_err(table_err)?,
    };
    Ok(StmtOutcome::Command(format!("UPDATE {updated}")))
}

/// BEGIN [TRANSACTION] / START TRANSACTION (V0.6): open a
/// transaction for this connection. A second BEGIN while one is
/// open fails with 25001 — Zeno has no nested transactions
/// (PostgreSQL would warn and keep the old one; Zeno reports the
/// mistake instead — see README).
fn exec_begin(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let first = tokens
        .first()
        .map(|t| t.text.to_ascii_uppercase())
        .unwrap_or_default();
    let mut i = 1;
    if first == "START" {
        i = expect_keyword(tokens, i, "TRANSACTION")
            .ok_or_else(|| sql_err("42601", "expected START TRANSACTION"))?;
    } else if let Some(next) = expect_keyword(tokens, i, "TRANSACTION") {
        i = next;
    }
    if i != tokens.len() {
        return Err(sql_err("42601", "unexpected text after BEGIN"));
    }
    if session.txn.is_some() {
        return Err(sql_err(
            "25001",
            "already in a transaction — COMMIT or ROLLBACK first \
             (Zeno 0.11.0 has no nested transactions)",
        ));
    }
    // Poison recovery (V0.5): see `recover_lock`.
    let mut guard = recover_lock(shared);
    let txn = guard.engine.begin();
    // m1: snapshot the table names at BEGIN — tables created
    // after this are invisible inside the transaction.
    session.txn_tables = Some(guard.tables.list_tables().into_iter().collect());
    session.txn = Some(txn);
    Ok(StmtOutcome::Command("BEGIN".to_string()))
}

/// COMMIT [TRANSACTION] / END (V0.6): commit this connection's
/// transaction. A write-write conflict fails with 40001
/// (serialization failure) and the transaction is aborted; the
/// connection is idle again afterwards. COMMIT with no
/// transaction open fails with 25P01 (PostgreSQL would warn and
/// return COMMIT; Zeno reports the mistake instead — see README).
/// COMMIT of an ABORTED transaction (M2) fails with 25P02 and the
/// transaction stays open until ROLLBACK — that case is caught in
/// `execute_tokens` before this runs.
fn exec_commit(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let mut i = 1;
    if let Some(next) = expect_keyword(tokens, i, "TRANSACTION") {
        i = next;
    }
    if i != tokens.len() {
        return Err(sql_err("42601", "unexpected text after COMMIT"));
    }
    let txn = session.txn.take().ok_or_else(|| {
        sql_err(
            "25P01",
            "there is no transaction in progress — COMMIT outside a transaction",
        )
    })?;
    // Poison recovery (V0.5): see `recover_lock`.
    let mut guard = recover_lock(shared);
    let result = guard.engine.commit(txn).map_err(|e| match e {
        CommitError::Conflict(conflict) => sql_err("40001", conflict.to_string()),
        CommitError::Unknown(msg) => sql_err("25P01", msg),
        CommitError::Io(e) => sql_err("XX000", e.to_string()),
    });
    // The transaction has ended, whatever the outcome (success,
    // conflict, or I/O error): clear the aborted flag and the
    // DDL snapshot, and bump the generation so portals bound
    // inside it die (B2).
    session.aborted = false;
    session.txn_tables = None;
    session.generation += 1;
    result?;
    Ok(StmtOutcome::Command("COMMIT".to_string()))
}

/// ROLLBACK [TRANSACTION] / ABORT (V0.6): drop this connection's
/// transaction and all its buffered writes. ROLLBACK with no
/// transaction open fails with 25P01, like COMMIT. ROLLBACK is
/// the ONLY statement that runs in an aborted transaction (M2).
fn exec_rollback(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let mut i = 1;
    if let Some(next) = expect_keyword(tokens, i, "TRANSACTION") {
        i = next;
    }
    if i != tokens.len() {
        return Err(sql_err("42601", "unexpected text after ROLLBACK"));
    }
    let txn = session.txn.take().ok_or_else(|| {
        sql_err(
            "25P01",
            "there is no transaction in progress — ROLLBACK outside a transaction",
        )
    })?;
    // Poison recovery (V0.5): see `recover_lock`.
    let mut guard = recover_lock(shared);
    let result = guard.engine.rollback(txn).map_err(|e| sql_err("25P01", e));
    session.aborted = false;
    session.txn_tables = None;
    session.generation += 1;
    result?;
    Ok(StmtOutcome::Command("ROLLBACK".to_string()))
}

/// SAVEPOINT <name> (V0.7): remember this transaction's write
/// buffer under `name`. Only inside a transaction — outside one
/// it fails with 25P01, like COMMIT/ROLLBACK do. A savepoint with
/// the same name hides the earlier one (see
/// `Engine::txn_savepoint`): RELEASE of the new one reveals the
/// old one again.
fn exec_savepoint(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let (name, next) = expect_name(tokens, 1)
        .ok_or_else(|| sql_err("42601", "expected a savepoint name after SAVEPOINT"))?;
    if next != tokens.len() {
        return Err(sql_err("42601", "unexpected text after SAVEPOINT <name>"));
    }
    let txn = session.txn.ok_or_else(|| {
        sql_err(
            "25P01",
            "there is no transaction in progress — SAVEPOINT outside a transaction (BEGIN first)",
        )
    })?;
    // V0.8: stamp the savepoint with the session clock, so a
    // later ROLLBACK TO can tell which portals / statements were
    // created after it (higher clock) and close them.
    let clock = session.next_sp_clock();
    // Poison recovery (V0.5): see `recover_lock`.
    let mut guard = recover_lock(shared);
    guard
        .engine
        .txn_savepoint(txn, &name, clock)
        .map_err(|e| sql_err("25P01", e))?;
    Ok(StmtOutcome::Command("SAVEPOINT".to_string()))
}

/// ROLLBACK TO [SAVEPOINT] <name> (V0.7): restore this
/// transaction's write buffer to the named savepoint's snapshot,
/// dropping every write made after it. The savepoint itself
/// stays, so rolling back to it again still works. Unknown name:
/// 3B001 (invalid savepoint specification). This is the one
/// statement besides ROLLBACK that runs in an aborted transaction
/// (M2) — it recovers the transaction, so `session.aborted` is
/// cleared here; the failed statement's effects never reached the
/// buffer, so there is nothing else to undo.
fn exec_rollback_to(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let mut i = expect_keyword(tokens, 1, "TO")
        .ok_or_else(|| sql_err("42601", "expected ROLLBACK TO [SAVEPOINT] <name>"))?;
    // The SAVEPOINT keyword is optional in PostgreSQL.
    if let Some(next) = expect_keyword(tokens, i, "SAVEPOINT") {
        i = next;
    }
    let (name, next) = expect_name(tokens, i)
        .ok_or_else(|| sql_err("42601", "expected a savepoint name after ROLLBACK TO"))?;
    if next != tokens.len() {
        return Err(sql_err(
            "42601",
            "unexpected text after ROLLBACK TO SAVEPOINT <name>",
        ));
    }
    let txn = session.txn.ok_or_else(|| {
        sql_err(
            "25P01",
            "there is no transaction in progress — ROLLBACK TO SAVEPOINT outside a transaction (BEGIN first)",
        )
    })?;
    // Poison recovery (V0.5): see `recover_lock`.
    let mut guard = recover_lock(shared);
    let clock = guard
        .engine
        .txn_rollback_to_savepoint(txn, &name)
        .map_err(|e| {
            if e.contains("no such savepoint") {
                sql_err("3B001", e)
            } else {
                sql_err("25P01", e)
            }
        })?;
    session.aborted = false;
    // B2 (V0.7 review): the rollback rewound the transaction's
    // write buffer, so any suspended portal's cached rows may
    // contain rows that no longer exist. Bump the cache epoch
    // so the next Execute of such a portal re-runs its
    // statement fresh instead of serving the stale cache (the
    // portal itself stays alive — see `Session::cache_epoch`).
    session.cache_epoch += 1;
    // V0.8 (PostgreSQL behaviour): portals and prepared
    // statements created AFTER this savepoint are closed — the
    // caller applies this cutoff to the extended-protocol state,
    // so a later Execute / Describe of one fails with 26000
    // ("does not exist") instead of running. Portals from
    // BEFORE the savepoint survive (their stale cache is what
    // the epoch bump above re-runs).
    session.savepoint_cutoff = Some(clock);
    Ok(StmtOutcome::Command("ROLLBACK".to_string()))
}

/// RELEASE [SAVEPOINT] <name> (V0.7): forget the named savepoint
/// (and every savepoint made after it). A later ROLLBACK TO that
/// name fails with 3B001, because the name no longer exists.
/// Only inside a transaction — outside one it fails with 25P01.
fn exec_release(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    let mut i = 1;
    // The SAVEPOINT keyword is optional in PostgreSQL.
    if let Some(next) = expect_keyword(tokens, i, "SAVEPOINT") {
        i = next;
    }
    let (name, next) = expect_name(tokens, i)
        .ok_or_else(|| sql_err("42601", "expected a savepoint name after RELEASE"))?;
    if next != tokens.len() {
        return Err(sql_err(
            "42601",
            "unexpected text after RELEASE SAVEPOINT <name>",
        ));
    }
    let txn = session.txn.ok_or_else(|| {
        sql_err(
            "25P01",
            "there is no transaction in progress — RELEASE SAVEPOINT outside a transaction (BEGIN first)",
        )
    })?;
    // Poison recovery (V0.5): see `recover_lock`.
    let mut guard = recover_lock(shared);
    guard
        .engine
        .txn_release_savepoint(txn, &name)
        .map_err(|e| {
            if e.contains("no such savepoint") {
                sql_err("3B001", e)
            } else {
                sql_err("25P01", e)
            }
        })?;
    Ok(StmtOutcome::Command("RELEASE".to_string()))
}

/// VACUUM (V0.6-fix, M5): online vacuum — prune version chains
/// and the committed set while the server runs (see
/// `Engine::vacuum`). No arguments are supported yet (`VACUUM`
/// alone). It cannot run inside a transaction block (25001,
/// like PostgreSQL): a transaction's own snapshot is exactly
/// what a VACUUM must respect, and running one from inside the
/// transaction it would prune is not sane.
fn exec_vacuum(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
    session: &mut Session,
) -> Result<StmtOutcome, SqlError> {
    if tokens.len() != 1 {
        return Err(sql_err("42601", "VACUUM takes no arguments in Zeno 0.11.0"));
    }
    if session.txn.is_some() {
        return Err(sql_err(
            "25001",
            "VACUUM cannot run inside a transaction block — COMMIT or ROLLBACK first",
        ));
    }
    let mut guard = recover_lock(shared);
    guard
        .engine
        .vacuum()
        .map_err(|e| sql_err("XX000", e.to_string()))?;
    // The pruned counts are in `stats` (vacuums, committed
    // txns); the CommandComplete tag stays plain "VACUUM", like
    // PostgreSQL.
    Ok(StmtOutcome::Command("VACUUM".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_respects_quoted_semicolons() {
        let stmts = split_statements("INSERT INTO t VALUES ('a;b'); SELECT * FROM t;");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("'a;b'"));
    }

    #[test]
    fn split_handles_escaped_quotes() {
        let stmts = split_statements("INSERT INTO t VALUES ('it''s'); SELECT * FROM t");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("'it''s'"));
    }

    #[test]
    fn split_respects_double_quoted_identifiers() {
        // m4: a ';' inside a "double-quoted" identifier must not split.
        let stmts = split_statements("CREATE TABLE \"a;b\" (id); SELECT * FROM \"a;b\"");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("\"a;b\""));
    }

    #[test]
    fn split_handles_escaped_double_quotes() {
        let stmts = split_statements("CREATE TABLE \"a\"\"b\" (id); SELECT 1");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("\"a\"\"b\""));
    }

    #[test]
    fn split_handles_block_comments() {
        // A ';' inside a /* */ comment must not split, and the
        // comment text itself is dropped.
        let stmts = split_statements("SELECT * FROM t /* ; comment ; */ WHERE a = 1; SELECT 2");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("SELECT * FROM t"));
        assert!(!stmts[0].contains("comment"));
        // A comment that is the whole statement leaves nothing.
        let stmts = split_statements("/* ; */");
        assert!(stmts.is_empty(), "a comment-only query has no statements");
        // A comment between tokens must not merge them.
        let stmts = split_statements("SELECT/*c*/* FROM t");
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("SELECT"));
        assert!(stmts[0].contains("FROM t"));
        // A /* inside a string literal is data, not a comment.
        let stmts = split_statements("INSERT INTO t VALUES ('/* not a comment */'); SELECT 2");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("'/* not a comment */'"));
        // An unterminated block comment drops the rest, like a
        // trailing line comment does.
        let stmts = split_statements("SELECT 1 /* never closed");
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("SELECT 1"));
    }

    #[test]
    fn tokenize_handles_block_comments_and_escaped_ident_quotes() {
        // `$2` inside a block comment is not a token at all.
        let tokens = tokenize("SELECT * FROM t WHERE a = $1 /* $2 */").unwrap();
        assert_eq!(tokens.iter().filter(|t| t.text.starts_with('$')).count(), 1);
        assert_eq!(tokens.iter().find(|t| t.text == "$1").unwrap().text, "$1");
        // `/*` inside a string literal is data, not a comment.
        let tokens = tokenize("SELECT '/* $1 */' FROM t WHERE a = $1").unwrap();
        assert_eq!(tokens.iter().filter(|t| t.text.starts_with('$')).count(), 1);
        // `""` inside a double-quoted identifier is an escaped
        // quote: "a""b" is one identifier, `a"b`.
        let tokens = tokenize("CREATE TABLE \"a\"\"b\" (id)").unwrap();
        let ident = tokens.iter().find(|t| t.quoted_ident).unwrap();
        assert_eq!(ident.text, "a\"b");
        // A comment between tokens never merges them.
        let tokens = tokenize("SELECT/*c*/* FROM t").unwrap();
        assert_eq!(tokens[0].text, "SELECT");
        assert_eq!(tokens[1].text, "*");
        assert_eq!(tokens[2].text, "FROM");
        // An unterminated block comment is a syntax error.
        assert!(tokenize("SELECT 1 /* never closed").is_none());
    }

    #[test]
    fn split_ignores_line_comments() {
        // m4: a ';' inside a `--` comment must not split, and the
        // comment text itself is dropped.
        let stmts = split_statements("SELECT 1; -- a comment; with a semicolon\nSELECT 2");
        assert_eq!(stmts.len(), 2);
        assert!(!stmts[0].contains("comment"));
        // A comment at the very end, with no newline, still ends cleanly.
        let stmts = split_statements("SELECT 1 -- trailing; comment");
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("SELECT 1"));
    }

    #[test]
    fn read_message_rejects_oversized_and_tiny_lengths() {
        // F2: a length over the 64 MiB cap is rejected BEFORE any
        // body buffer is allocated (a hostile frame must not make us
        // allocate 64 MiB, let alone more).
        let mut buf = vec![b'Q'];
        buf.extend_from_slice(&(MAX_MESSAGE_LEN + 1).to_be_bytes());
        let err = read_message(&mut std::io::Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // A length below 4 (the length field is self-inclusive).
        let mut buf = vec![b'Q'];
        buf.extend_from_slice(&3i32.to_be_bytes());
        let err = read_message(&mut std::io::Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // A negative length: same rejection, no allocation.
        let mut buf = vec![b'Q'];
        buf.extend_from_slice(&(-1i32).to_be_bytes());
        let err = read_message(&mut std::io::Cursor::new(buf)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_message_reads_a_valid_frame() {
        let mut buf = vec![b'Q'];
        buf.extend_from_slice(&8i32.to_be_bytes());
        buf.extend_from_slice(b"abcd");
        let msg = read_message(&mut std::io::Cursor::new(buf)).unwrap();
        assert_eq!(msg, Some((b'Q', b"abcd".to_vec())));
    }

    /// V0.11 (review finding 3): a reader that dribbles one byte
    /// at a time, forever, must still hit the absolute deadline —
    /// the old per-read socket timeout never fired on such a
    /// client, because every read returned a byte in time. Here
    /// the drip yields a byte every 50 ms and the budget is
    /// 300 ms: the third `read_exact` (past the deadline) must
    /// fail with `TimedOut`, and the whole test must finish in
    /// well under 5 s.
    #[test]
    fn deadline_reader_closes_a_slow_drip_client() {
        use std::io::Read;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        /// Yields one byte per `read()`, forever, sleeping
        /// `interval` between bytes — the slow-drip client.
        struct Drip {
            sent: Arc<AtomicUsize>,
            interval: Duration,
        }
        impl Read for Drip {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(self.interval);
                self.sent.fetch_add(1, Ordering::SeqCst);
                buf[0] = b'x';
                Ok(1)
            }
        }

        let sent = Arc::new(AtomicUsize::new(0));
        let drip = Drip {
            sent: Arc::clone(&sent),
            interval: Duration::from_millis(50),
        };
        // Absolute deadline 300 ms from now (the frame budget
        // starts at the first byte in production; here the
        // deadline is armed up front — same 300 ms window).
        let mut reader =
            DeadlineReader::with_deadline(drip, Instant::now() + Duration::from_millis(300));
        let started = Instant::now();
        // The first bytes arrive inside the budget...
        let mut first = [0u8; 2];
        reader.read_exact(&mut first).unwrap();
        // ...but a frame that never finishes must fail at the
        // deadline instead of dribbling forever.
        let mut rest = [0u8; 64];
        let err = reader.read_exact(&mut rest).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "deadline must fire promptly, took {:?}",
            started.elapsed()
        );
        // And a fresh frame gets a fresh budget (reset_budget +
        // start_frame).
        reader.reset_budget(Duration::from_millis(300));
        reader.start_frame();
        let mut again = [0u8; 1];
        reader.read_exact(&mut again).unwrap();
        assert!(sent.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn read_timeout_closes_a_half_talking_client() {
        // F2: a client that sends half a message and then goes quiet
        // must NOT hold its server thread forever. The server stream
        // here gets a 200ms read timeout (the real server uses 60s);
        // handle_client must return cleanly and close the socket.
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = crate::unique_test_dir("zeno-pgwire-timeout-test");
        let engine = Engine::open(&dir).unwrap();
        let tables = TableStore::open(&dir).unwrap();
        let shared = Arc::new(Mutex::new(Shared {
            engine,
            tables,
            data_dir: dir.clone(),
            rate_limiter: Arc::new(LoginRateLimiter::new()),
        }));

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let shared_clone = Arc::clone(&shared);
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            // handle_client now takes (reader, writer): the plain
            // path is a BufReader over a clone + the stream itself.
            // (In the real server `handle_connection` feeds the
            // first 8 bytes back through a Chain first; this test
            // speaks the startup message directly, so no prefix
            // is needed here.)
            let reader = BufReader::new(stream.try_clone().unwrap());
            let _ = tx.send(handle_client(
                reader,
                stream,
                shared_clone,
                1,
                "127.0.0.1".to_string(),
                false,
                Instant::now() + Duration::from_secs(60),
            ));
        });

        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // Startup handshake.
        let mut body = Vec::new();
        body.extend_from_slice(&196608i32.to_be_bytes());
        body.extend_from_slice(b"user\0zeno\0database\0zeno\0\0");
        let mut frame = Vec::new();
        frame.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        frame.extend_from_slice(&body);
        client.write_all(&frame).unwrap();
        // Read reply messages until ReadyForQuery ('Z').
        loop {
            let mut tag = [0u8; 1];
            client.read_exact(&mut tag).unwrap();
            let mut len_buf = [0u8; 4];
            client.read_exact(&mut len_buf).unwrap();
            let len = i32::from_be_bytes(len_buf);
            let mut msg_body = vec![0u8; (len - 4) as usize];
            client.read_exact(&mut msg_body).unwrap();
            if tag[0] == b'Z' {
                break;
            }
        }
        // Send HALF a Query message — just the tag, no length, no
        // body — then go quiet.
        client.write_all(b"Q").unwrap();
        client.flush().unwrap();

        let result = rx.recv_timeout(Duration::from_secs(5)).expect(
            "server thread did not return after a half-message + silence (no read timeout?)",
        );
        assert!(
            result.is_ok(),
            "timeout close must be a clean Ok: {result:?}"
        );

        // And the server must have closed the socket: a read gets EOF.
        let mut one = [0u8; 1];
        assert_eq!(
            client.read(&mut one).unwrap(),
            0,
            "server must close the timed-out connection"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tokenize_strings_and_punctuation() {
        let tokens = tokenize("SELECT * FROM users WHERE city = 'New Delhi'").unwrap();
        assert_eq!(tokens[0].text, "SELECT");
        assert_eq!(tokens[1].text, "*");
        assert_eq!(tokens[7].text, "New Delhi");
        assert!(tokens[7].quoted_string);
    }

    #[test]
    fn tokenize_unterminated_string_is_none() {
        assert!(tokenize("SELECT 'abc").is_none());
    }

    #[test]
    fn startup_params_parse() {
        let mut body = Vec::new();
        body.extend_from_slice(b"user\0zeno\0database\0zeno\0\0");
        let params = parse_startup_params(&body);
        assert_eq!(
            params,
            vec![
                ("user".to_string(), "zeno".to_string()),
                ("database".to_string(), "zeno".to_string()),
            ]
        );
    }

    #[test]
    fn poisoned_lock_recovers_and_keeps_serving() {
        // V0.5: a thread that panics while holding a Mutex poisons
        // it. `recover_lock` must hand the data back instead of
        // failing every later statement with XX000 — this is the
        // path every `exec_*` statement uses (via `recover_lock`).
        let lock = Arc::new(Mutex::new("engine-data".to_string()));
        let poisoner = Arc::clone(&lock);
        let handle = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("injected panic while holding the lock");
        });
        assert!(handle.join().is_err(), "the thread must panic");
        assert!(lock.is_poisoned(), "the mutex must be poisoned now");
        // Recovery: the data underneath is intact, and the lock
        // works again afterwards (a second recovery + mutation).
        let guard = recover_lock(&lock);
        assert_eq!(*guard, "engine-data", "poisoned data must survive");
        drop(guard);
        // The poison FLAG itself is sticky in std (only the
        // unstable `clear_poison` would clear it) — but that does
        // not matter here: every server path locks through
        // `recover_lock`, which recovers on every call. Prove a
        // second recovery works on the still-flagged mutex.
        assert!(lock.is_poisoned(), "std keeps the poison flag set");
        let mut guard = recover_lock(&lock);
        guard.push_str("-still-works");
        assert_eq!(*guard, "engine-data-still-works");
    }

    #[test]
    fn conn_session_drop_rolls_back_abandoned_txn_even_on_panic() {
        // m3: the `ConnSession` Drop guard must roll back an
        // abandoned transaction when the connection thread ends
        // — including when it PANICS (a rollback written after
        // `client_loop` returns never runs on that path, and the
        // transaction — with its snapshot — leaked in the engine
        // forever).
        use std::panic::AssertUnwindSafe;
        let dir = crate::unique_test_dir("zeno-pgwire-connsession-test");
        let engine = Engine::open(&dir).unwrap();
        let tables = TableStore::open(&dir).unwrap();
        let shared = Arc::new(Mutex::new(Shared {
            engine,
            tables,
            data_dir: dir.clone(),
            rate_limiter: Arc::new(LoginRateLimiter::new()),
        }));
        // Normal drop: the transaction is rolled back.
        let txn = {
            let mut guard = recover_lock(&shared);
            guard.engine.begin()
        };
        assert!(recover_lock(&shared).engine.txn_active(txn));
        {
            let mut conn = ConnSession::new(Arc::clone(&shared), 1);
            conn.session.txn = Some(txn);
            // `conn` drops here, at the end of the block.
        }
        assert!(
            !recover_lock(&shared).engine.txn_active(txn),
            "dropping the session must roll the transaction back"
        );
        // Panic unwind: the guard's Drop still runs, and the
        // transaction is still rolled back.
        let txn2 = {
            let mut guard = recover_lock(&shared);
            guard.engine.begin()
        };
        let shared2 = Arc::clone(&shared);
        let panicked = std::panic::catch_unwind(AssertUnwindSafe(move || {
            let mut conn = ConnSession::new(shared2, 2);
            conn.session.txn = Some(txn2);
            panic!("injected connection-thread panic");
        }));
        assert!(panicked.is_err(), "the closure must panic");
        assert!(
            !recover_lock(&shared).engine.txn_active(txn2),
            "a panicking connection must still roll its transaction back"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connection_slot_freed_on_normal_return() {
        // M2: dropping the guard (normal end of a connection)
        // returns the slot to the pool.
        let active = Arc::new(AtomicUsize::new(0));
        {
            let _slot = ConnectionSlot::new(&active);
            assert_eq!(active.load(Ordering::SeqCst), 1, "slot must be counted");
        }
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "dropping the guard must free the slot"
        );
    }

    #[test]
    fn connection_slot_freed_on_panic() {
        // M2: the whole point of the RAII guard — a connection
        // thread that PANICS must still free its slot, or enough
        // panics would leak every slot and the server would
        // refuse all new connections with 53300 until restart.
        // (The old code did `fetch_sub` only after
        // `handle_connection` returned, which a panic skips.)
        let active = Arc::new(AtomicUsize::new(0));
        let active_in_thread = Arc::clone(&active);
        let panicked = std::panic::catch_unwind(move || {
            let _slot = ConnectionSlot::new(&active_in_thread);
            assert_eq!(
                active_in_thread.load(Ordering::SeqCst),
                1,
                "slot must be counted while held"
            );
            panic!("injected connection-thread panic");
        });
        assert!(panicked.is_err(), "the closure must panic");
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "a panicking connection must still free its slot"
        );
    }

    #[test]
    fn vacuum_interval_zero_is_clamped_not_busy_spin() {
        // m5: an interval of 0 used to make the auto-vacuum
        // thread run VACUUM back to back with no sleep. The
        // clamp floors it (and any sub-100 ms interval) at
        // 100 ms; longer intervals pass through unchanged.
        assert_eq!(
            clamp_vacuum_interval(Duration::ZERO),
            Duration::from_millis(100)
        );
        assert_eq!(
            clamp_vacuum_interval(Duration::from_millis(50)),
            Duration::from_millis(100)
        );
        assert_eq!(
            clamp_vacuum_interval(Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn auto_vacuum_prunes_dead_versions_but_keeps_live_snapshot_data() {
        // V0.7: the background auto-vacuum thread must prune
        // versions no live snapshot can see, and must NEVER prune
        // a version a live snapshot still needs. The test builds
        // one key with four versions — v1, v2, then a BEGIN whose
        // snapshot sees v2, then v3 and v4 — and runs the real
        // thread on a 50 ms interval.
        let dir = crate::unique_test_dir("zeno-pgwire-autovacuum-test");
        let engine = Engine::open(&dir).unwrap();
        let tables = TableStore::open(&dir).unwrap();
        let shared = Arc::new(Mutex::new(Shared {
            engine,
            tables,
            data_dir: dir.clone(),
            rate_limiter: Arc::new(LoginRateLimiter::new()),
        }));

        let txn = {
            let mut guard = recover_lock(&shared);
            guard.engine.put("k", "v1").unwrap();
            guard.engine.put("k", "v2").unwrap();
            let txn = guard.engine.begin(); // snapshot sees v2
            guard.engine.put("k", "v3").unwrap();
            guard.engine.put("k", "v4").unwrap();
            assert_eq!(guard.engine.version_chain_len("k"), 4);
            txn
        };

        let stop = Arc::new(AtomicBool::new(false));
        let handle = start_auto_vacuum(
            Arc::clone(&shared),
            Duration::from_millis(50),
            Arc::clone(&stop),
        );
        std::thread::sleep(Duration::from_millis(400));
        {
            let mut guard = recover_lock(&shared);
            // v1 is dead to everyone (superseded before the
            // snapshot began); v2 is what the live snapshot
            // sees; v3/v4 are newer than its watermark. Only v1
            // may go — the chain must shrink 4 -> 3, not to 1.
            assert_eq!(
                guard.engine.version_chain_len("k"),
                3,
                "auto-vacuum must prune only the version no snapshot needs"
            );
            assert_eq!(
                guard.engine.txn_get(txn, "k").unwrap().as_deref(),
                Some("v2"),
                "the live snapshot must still read v2 after auto-vacuum runs"
            );
            assert_eq!(
                guard.engine.get("k").as_deref(),
                Some("v4"),
                "outside the snapshot the newest value must still read"
            );
            guard.engine.rollback(txn).unwrap();
        }
        // With the snapshot gone, the next auto-vacuum may prune
        // everything but the newest version.
        std::thread::sleep(Duration::from_millis(300));
        {
            let mut guard = recover_lock(&shared);
            assert_eq!(
                guard.engine.version_chain_len("k"),
                1,
                "once the snapshot is gone the chain must prune to the newest version"
            );
            assert_eq!(guard.engine.get("k").as_deref(), Some("v4"));
        }
        // Clean shutdown: the stop flag must end the thread, and
        // the join must return (no hung thread left behind).
        stop.store(true, Ordering::Relaxed);
        handle.join().expect("auto-vacuum thread must join cleanly");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

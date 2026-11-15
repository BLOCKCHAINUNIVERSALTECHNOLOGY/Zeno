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
// - Simple Query 'Q': CREATE TABLE / INSERT / SELECT (WHERE
//   column=value) / DELETE, mapped onto the engine's table API.
//   One Query message may hold several statements separated by ';';
//   each runs in turn, then one ReadyForQuery closes the cycle.
// - Extended query protocol (see `extended.rs`): Parse/Bind/
//   Describe/Execute/Close/Sync over the same four statements,
//   with $1, $2 parameters (text format, plus binary int4/text),
//   named + unnamed statements and portals, PortalSuspended for
//   limited Execute, and the protocol's error rule — after an
//   extended-protocol error the server sends ONE ErrorResponse and
//   then reads and discards messages until Sync, so a pipelined
//   driver never desyncs.
// - Terminate 'X' closes the connection; a client disconnect never
//   stops the server; clients are served one thread each, sharing one
//   engine behind a Mutex (the data-dir LOCK still allows exactly one
//   server process per directory — a second `zeno serve` on the same
//   directory fails with the lock error).
//
// What it deliberately does NOT implement (see README, honest limits):
// - COPY, LISTEN/NOTIFY, cursors.
// - MVCC/transactions: every statement sees the latest value.
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
use crate::table::TableStore;
use crate::tls;
use std::io::{BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

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

/// Options for `serve`: TLS on/off and the connection cap.
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
}

/// Default connection limit for `serve` (also the CLI default).
pub const DEFAULT_MAX_CONNECTIONS: usize = 20;

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            tls: false,
            max_connections: DEFAULT_MAX_CONNECTIONS,
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
        "zeno 0.5.0 listening on 127.0.0.1:{} (data dir: {})",
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
    // Live connection count. Incremented on accept (before the
    // thread starts) and decremented when the thread ends, so a
    // connection counts from the moment it is accepted — including
    // while it is still handshaking or sitting idle.
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
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
                // refused inline (no thread) — see
                // `refuse_over_limit` (m6): an SSLRequest is
                // answered 'N' first, then the 53300 ErrorResponse,
                // so libpq reads a valid negotiation answer.
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                if count > opts.max_connections {
                    active.fetch_sub(1, Ordering::SeqCst);
                    refuse_over_limit(stream, opts.max_connections);
                    continue;
                }
                let peer_ip = stream
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_default();
                let shared = Arc::clone(&shared);
                let tls_config = tls_config.clone();
                let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
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
            Err(e) => eprintln!("pgwire accept error: {e}"),
        }
    }
    Ok(())
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
    let mut first = [0u8; 8];
    match stream.read_exact(&mut first) {
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
    let code = i32::from_be_bytes([first[4], first[5], first[6], first[7]]);
    match code {
        SSL_REQUEST_CODE => match tls_config {
            Some(ref config) => {
                stream.write_all(b"S")?;
                stream.flush()?;
                let (reader, writer) = tls::handshake_tls(stream, config)?;
                return handle_client(reader, writer, shared, conn_id, peer_ip, false);
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
                return handle_client(reader, stream, shared, conn_id, peer_ip, false);
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
    handle_client(reader, stream, shared, conn_id, peer_ip, false)
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
fn ready_for_query(writer: &mut impl Write) -> std::io::Result<()> {
    write_message(writer, b'Z', b"I")
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
/// (-1 = NULL) + bytes. Zeno values are never NULL, so -1 never
/// appears here — a missing column is sent as an empty string.
pub(crate) fn data_row(writer: &mut impl Write, values: &[String]) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_i16(&mut body, values.len() as i16);
    for v in values {
        put_i32(&mut body, v.len() as i32);
        body.extend_from_slice(v.as_bytes());
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
    mut reader: R,
    mut writer: W,
    shared: Arc<Mutex<Shared>>,
    conn_id: u32,
    peer_ip: String,
    // True only when this connection answered 'N' to GSSENC on a
    // `--tls` server: the channel is still plaintext, so the
    // startup below must refuse a plain login (M1).
    tls_required: bool,
) -> std::io::Result<()> {
    let (data_dir, limiter) = {
        let guard = recover_lock(&shared);
        (guard.data_dir.clone(), Arc::clone(&guard.rate_limiter))
    };
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

    // Extended-protocol state for this connection: prepared
    // statements + portals, and the error flag (see the loop).
    let mut ext = ExtendedState::new();

    loop {
        let msg = match read_message(&mut reader) {
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
                    ready_for_query(&mut writer)?;
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
                run_query(&mut writer, &shared, &sql)?;
                ready_for_query(&mut writer)?;
            }
            b'X' => return Ok(()), // Terminate
            b'P' | b'B' | b'D' | b'E' | b'C' => {
                // Extended query protocol (see extended.rs). Success
                // replies are written by the handler; on error ONE
                // ErrorResponse is sent, NO ReadyForQuery, and the
                // connection enters skip-until-Sync mode (above) —
                // that is what keeps a pipelined driver in sync.
                let result = match tag {
                    b'P' => crate::extended::handle_parse(&mut writer, &shared, &mut ext, &body),
                    b'B' => crate::extended::handle_bind(&mut writer, &shared, &mut ext, &body),
                    b'D' => crate::extended::handle_describe(&mut writer, &shared, &mut ext, &body),
                    b'E' => crate::extended::handle_execute(&mut writer, &shared, &mut ext, &body),
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
                ready_for_query(&mut writer)?;
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
                ready_for_query(&mut writer)?;
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
                ready_for_query(writer)?;
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
        match execute_statement(shared, stmt) {
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
    /// SELECT: output columns + all rows (values in column order).
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// CREATE / INSERT / DELETE: the CommandComplete tag.
    Command(String),
    /// An empty statement: nothing to send.
    Empty,
}

/// Run one statement given as SQL text.
pub(crate) fn execute_statement(
    shared: &Arc<Mutex<Shared>>,
    stmt: &str,
) -> Result<StmtOutcome, SqlError> {
    let tokens = tokenize(stmt).ok_or_else(|| sql_err("42601", "unterminated string literal"))?;
    execute_tokens(shared, &tokens)
}

/// Run one statement given as tokens. Extended Execute uses this
/// after substituting the bound parameter values for the `$n`
/// placeholders, so parameters can never be re-parsed as SQL.
pub(crate) fn execute_tokens(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
) -> Result<StmtOutcome, SqlError> {
    match classify_statement(tokens)? {
        StmtKind::Create => exec_create(shared, tokens),
        StmtKind::Insert => exec_insert(shared, tokens),
        StmtKind::Select => exec_select(shared, tokens),
        StmtKind::Delete => exec_delete(shared, tokens),
        StmtKind::Empty => Ok(StmtOutcome::Empty),
    }
}

/// Which of the four supported statements (if any) `tokens` holds.
/// Extended Parse reuses this, so a bad statement fails at Parse
/// time with the same error a Simple Query would get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StmtKind {
    Create,
    Insert,
    Select,
    Delete,
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
        "UPDATE" | "DROP" | "ALTER" | "BEGIN" | "COMMIT" | "ROLLBACK" | "SET" | "SHOW"
        | "GRANT" | "REVOKE" | "TRUNCATE" | "COPY" | "VACUUM" | "EXPLAIN" => Err(sql_err(
            "0A000",
            format!("{first} is not supported in Zeno 0.5.0 (only CREATE TABLE, INSERT, SELECT, DELETE)"),
        )),
        "" => Ok(StmtKind::Empty),
        other => Err(sql_err(
            "42601",
            format!("syntax error: unsupported statement starting with '{other}'"),
        )),
    }
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

pub(crate) fn expect_punct(tokens: &[Token], i: usize, p: &str) -> Option<usize> {
    if tokens.get(i).map(|t| t.text.as_str()) == Some(p) {
        Some(i + 1)
    } else {
        None
    }
}

/// `WHERE col = value` at `tokens[i]`; `value` may be a quoted string
/// or a bare token (number or word). Returns (column, value, next).
pub(crate) fn parse_where(tokens: &[Token], i: usize) -> Option<(String, String, usize)> {
    let mut i = expect_keyword(tokens, i, "WHERE")?;
    let (col, next) = expect_name(tokens, i)?;
    i = next;
    i = expect_punct(tokens, i, "=")?;
    let value = tokens.get(i)?.text.clone();
    Some((col, value, i + 1))
}

// ---------------------------------------------------------------------
// The four statements.
// ---------------------------------------------------------------------

/// CREATE TABLE name (col1, col2, ...) — column types are NOT parsed:
/// every Zeno column is text. `CREATE TABLE users (id int, name text)`
/// therefore also works: the type words are skipped.
fn exec_create(shared: &Arc<Mutex<Shared>>, tokens: &[Token]) -> Result<StmtOutcome, SqlError> {
    let mut i =
        expect_keyword(tokens, 0, "CREATE").ok_or_else(|| sql_err("42601", "expected CREATE"))?;
    i = expect_keyword(tokens, i, "TABLE")
        .ok_or_else(|| sql_err("42601", "expected CREATE TABLE"))?;
    let (name, next) = expect_name(tokens, i)
        .ok_or_else(|| sql_err("42601", "expected a table name after CREATE TABLE"))?;
    i = next;
    i = expect_punct(tokens, i, "(").ok_or_else(|| {
        sql_err(
            "42601",
            "expected a column list in parentheses after the table name",
        )
    })?;
    let mut columns: Vec<String> = Vec::new();
    loop {
        let (col, next) = expect_name(tokens, i)
            .ok_or_else(|| sql_err("42601", "expected a column name in the column list"))?;
        columns.push(col);
        i = next;
        // A type word after the column (e.g. `id int`) is skipped:
        // every column is text in V0.3. Only known type words are
        // skipped, so a missing comma (`(id name)`) is an error
        // instead of silently dropping the `name` column.
        if let Some((ty, next)) = expect_name(tokens, i) {
            if matches!(
                ty.to_ascii_uppercase().as_str(),
                "INT"
                    | "INTEGER"
                    | "BIGINT"
                    | "SMALLINT"
                    | "TEXT"
                    | "VARCHAR"
                    | "CHAR"
                    | "BOOLEAN"
                    | "BOOL"
                    | "REAL"
                    | "DOUBLE"
                    | "NUMERIC"
                    | "DECIMAL"
                    | "SERIAL"
                    | "BIGSERIAL"
                    | "TIMESTAMP"
                    | "DATE"
                    | "TIME"
                    | "UUID"
                    | "JSONB"
                    | "JSON"
            ) {
                i = next;
            }
        }
        if let Some(next) = expect_punct(tokens, i, ",") {
            i = next;
            continue;
        }
        break;
    }
    i = expect_punct(tokens, i, ")")
        .ok_or_else(|| sql_err("42601", "expected ')' after the column list"))?;
    if i != tokens.len() {
        return Err(sql_err("42601", "unexpected text after CREATE TABLE"));
    }
    if columns.is_empty() {
        return Err(sql_err("42601", "a table needs at least one column"));
    }
    // Poison recovery (V0.5): a thread that panicked while holding
    // this lock must not wedge the server — see `recover_lock`.
    let mut guard = recover_lock(shared);
    guard.tables.create_table(&name, columns).map_err(|e| {
        if e.contains("already exists") {
            sql_err("42P07", e)
        } else {
            sql_err("42601", e)
        }
    })?;
    Ok(StmtOutcome::Command("CREATE TABLE".to_string()))
}

/// INSERT INTO name VALUES (v1, v2, ...) — values are quoted strings
/// or bare tokens; the count must match the table's columns.
fn exec_insert(shared: &Arc<Mutex<Shared>>, tokens: &[Token]) -> Result<StmtOutcome, SqlError> {
    let mut i =
        expect_keyword(tokens, 0, "INSERT").ok_or_else(|| sql_err("42601", "expected INSERT"))?;
    i = expect_keyword(tokens, i, "INTO")
        .ok_or_else(|| sql_err("42601", "expected INSERT INTO"))?;
    let (name, next) = expect_name(tokens, i)
        .ok_or_else(|| sql_err("42601", "expected a table name after INSERT INTO"))?;
    i = next;
    i = expect_keyword(tokens, i, "VALUES")
        .ok_or_else(|| sql_err("42601", "expected VALUES after the table name"))?;
    i = expect_punct(tokens, i, "(")
        .ok_or_else(|| sql_err("42601", "expected a value list in parentheses after VALUES"))?;
    let mut values: Vec<String> = Vec::new();
    loop {
        let t = tokens
            .get(i)
            .ok_or_else(|| sql_err("42601", "expected a value in the value list"))?;
        // Only an UNQUOTED ')' closes the value list: a quoted
        // string value of ')' (or any other punctuation) is data,
        // not syntax — `VALUES (9, ')', 'Delhi')` must insert.
        if t.text == ")" && !t.quoted_string {
            break;
        }
        values.push(t.text.clone());
        i += 1;
        if let Some(next) = expect_punct(tokens, i, ",") {
            i = next;
            continue;
        }
        break;
    }
    i = expect_punct(tokens, i, ")")
        .ok_or_else(|| sql_err("42601", "expected ')' after the value list"))?;
    if i != tokens.len() {
        return Err(sql_err("42601", "unexpected text after INSERT"));
    }
    // Poison recovery (V0.5): a thread that panicked while holding
    // this lock must not wedge the server — see `recover_lock`.
    let mut guard = recover_lock(shared);
    let Shared { engine, tables, .. } = &mut *guard;
    tables.insert(engine, &name, values).map_err(|e| {
        if e.contains("no such table") {
            sql_err("42P01", e)
        } else {
            sql_err("42601", e)
        }
    })?;
    Ok(StmtOutcome::Command("INSERT 0 1".to_string()))
}

/// A parsed SELECT, ready to run: output columns (resolved
/// against the registry — `*` becomes all columns in registry
/// order), table name, and the optional WHERE filter. Extended
/// Bind/Describe reuse this so a prepared SELECT is checked the
/// same way a Simple Query SELECT is, without executing it.
pub(crate) struct SelectPlan {
    pub columns: Vec<String>,
    pub table: String,
    pub filter: Option<(String, String)>,
}

/// Parse `SELECT * | col1, col2 FROM name [WHERE col = value]` and
/// resolve its output columns. The WHERE column is NOT checked
/// against the registry here — matching `exec_select`'s V0.3
/// behaviour, a filter on an unknown column simply matches no rows.
pub(crate) fn parse_select(
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
) -> Result<SelectPlan, SqlError> {
    let mut i =
        expect_keyword(tokens, 0, "SELECT").ok_or_else(|| sql_err("42601", "expected SELECT"))?;
    // Column list: '*' or comma-separated names.
    let mut columns: Option<Vec<String>> = None; // None = *
    if tokens.get(i).map(|t| t.text.as_str()) == Some("*") {
        i += 1;
    } else {
        let mut cols = Vec::new();
        loop {
            let (col, next) = expect_name(tokens, i)
                .ok_or_else(|| sql_err("42601", "expected a column name or * after SELECT"))?;
            cols.push(col);
            i = next;
            if let Some(next) = expect_punct(tokens, i, ",") {
                i = next;
                continue;
            }
            break;
        }
        columns = Some(cols);
    }
    i = expect_keyword(tokens, i, "FROM")
        .ok_or_else(|| sql_err("42601", "expected FROM after the column list"))?;
    let (name, next) = expect_name(tokens, i)
        .ok_or_else(|| sql_err("42601", "expected a table name after FROM"))?;
    i = next;
    let mut filter: Option<(String, String)> = None;
    if i < tokens.len() {
        let (col, value, next) = parse_where(tokens, i).ok_or_else(|| {
            sql_err(
                "42601",
                "expected WHERE column = value after the table name",
            )
        })?;
        filter = Some((col, value));
        i = next;
    }
    if i != tokens.len() {
        return Err(sql_err("42601", "unexpected text after SELECT"));
    }

    let guard = recover_lock(shared);
    let all_columns = guard
        .tables
        .columns(&name)
        .ok_or_else(|| sql_err("42P01", format!("no such table '{name}'")))?
        .to_vec();
    // Resolve the output columns; '*' = all columns, registry order.
    let out_columns: Vec<String> = match &columns {
        None => all_columns.clone(),
        Some(want) => {
            for col in want {
                if !all_columns.iter().any(|c| c == col) {
                    return Err(sql_err(
                        "42703",
                        format!("column '{col}' does not exist in table '{name}'"),
                    ));
                }
            }
            want.clone()
        }
    };
    Ok(SelectPlan {
        columns: out_columns,
        table: name,
        filter,
    })
}

/// SELECT * | col1, col2 FROM name [WHERE col = value]
fn exec_select(shared: &Arc<Mutex<Shared>>, tokens: &[Token]) -> Result<StmtOutcome, SqlError> {
    let plan = parse_select(shared, tokens)?;
    // Poison recovery (V0.5): a thread that panicked while holding
    // this lock must not wedge the server — see `recover_lock`.
    let mut guard = recover_lock(shared);
    let Shared { engine, tables, .. } = &mut *guard;
    let rows = tables
        .select(
            engine,
            &plan.table,
            plan.filter.as_ref().map(|(c, v)| (c.as_str(), v.as_str())),
        )
        .map_err(|e| sql_err("42P01", e))?;
    let out_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|(_, row)| {
            plan.columns
                .iter()
                .map(|c| row.get(c).cloned().unwrap_or_default())
                .collect()
        })
        .collect();
    Ok(StmtOutcome::Rows {
        columns: plan.columns,
        rows: out_rows,
    })
}

/// DELETE FROM name [WHERE col = value] — without WHERE, all rows go.
fn exec_delete(shared: &Arc<Mutex<Shared>>, tokens: &[Token]) -> Result<StmtOutcome, SqlError> {
    let mut i =
        expect_keyword(tokens, 0, "DELETE").ok_or_else(|| sql_err("42601", "expected DELETE"))?;
    i = expect_keyword(tokens, i, "FROM")
        .ok_or_else(|| sql_err("42601", "expected DELETE FROM"))?;
    let (name, next) = expect_name(tokens, i)
        .ok_or_else(|| sql_err("42601", "expected a table name after DELETE FROM"))?;
    i = next;
    let mut filter: Option<(String, String)> = None;
    if i < tokens.len() {
        let (col, value, next) = parse_where(tokens, i).ok_or_else(|| {
            sql_err(
                "42601",
                "expected WHERE column = value after the table name",
            )
        })?;
        filter = Some((col, value));
        i = next;
    }
    if i != tokens.len() {
        return Err(sql_err("42601", "unexpected text after DELETE"));
    }
    // Poison recovery (V0.5): a thread that panicked while holding
    // this lock must not wedge the server — see `recover_lock`.
    let mut guard = recover_lock(shared);
    let Shared { engine, tables, .. } = &mut *guard;
    let deleted = tables
        .delete(
            engine,
            &name,
            filter.as_ref().map(|(c, v)| (c.as_str(), v.as_str())),
        )
        .map_err(|e| {
            if e.contains("no such table") {
                sql_err("42P01", e)
            } else {
                sql_err("42601", e)
            }
        })?;
    Ok(StmtOutcome::Command(format!("DELETE {deleted}")))
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

    #[test]
    fn read_timeout_closes_a_half_talking_client() {
        // F2: a client that sends half a message and then goes quiet
        // must NOT hold its server thread forever. The server stream
        // here gets a 200ms read timeout (the real server uses 60s);
        // handle_client must return cleanly and close the socket.
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = std::env::temp_dir().join("zeno-pgwire-timeout-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
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
}

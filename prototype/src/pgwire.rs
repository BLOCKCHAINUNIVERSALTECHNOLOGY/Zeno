// pgwire.rs — PostgreSQL wire protocol (frontend/backend, v3.0),
// Simple Query only. Written from the official PostgreSQL docs
// ("Message Flow" and "Message Formats", protocol 3.0) — no pgwire
// crate, no new dependency, just `std::net::TcpListener`.
//
// What this implements:
// - Startup handshake: StartupMessage (protocol 3.0), SSLRequest
//   (answered 'N' — no SSL), CancelRequest (closed, no reply).
// - Trust auth: every client gets AuthenticationOk, no password.
//   **Local prototype only — see the BOLD warning in the README.**
// - ParameterStatus (server_version, client_encoding,
//   standard_conforming_strings), BackendKeyData, ReadyForQuery.
// - Simple Query 'Q': CREATE TABLE / INSERT / SELECT (WHERE
//   column=value) / DELETE, mapped onto the engine's table API.
//   One Query message may hold several statements separated by ';';
//   each runs in turn, then one ReadyForQuery closes the cycle.
// - Terminate 'X' closes the connection; a client disconnect never
//   stops the server; clients are served one thread each, sharing one
//   engine behind a Mutex (the data-dir LOCK still allows exactly one
//   server process per directory — a second `zeno serve` on the same
//   directory fails with the lock error).
//
// What it deliberately does NOT implement (see README, honest limits):
// - Extended query protocol: Parse/Bind/Describe/Execute/Close get
//   a clear ErrorResponse ("not supported") and NO ReadyForQuery —
//   per the PostgreSQL protocol ReadyForQuery is sent ONLY after
//   Sync, so a driver that pipelines P/B/D/E/S in one flush and
//   reads until the first ReadyForQuery stays in sync and its next
//   Simple Query is answered normally. The connection stays alive.
// - SSL, password/SCRAM auth, COPY, LISTEN/NOTIFY, cursors.
// - MVCC/transactions: every statement sees the latest value.
//
// All values travel as text (type OID 25, `text`), because every
// Zeno table column is a string. RowDescription therefore always
// reports OID 25, typlen -1, format 0 (text).
//
// `server_version` is reported as "18.0": that is the PostgreSQL
// version whose wire protocol this implements (the docs this code was
// written against), so clients that parse the version do not choke.
// Zeno is NOT PostgreSQL — the README says so plainly.

use crate::engine::Engine;
use crate::table::TableStore;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
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
/// First-message code asking to cancel another backend; no reply.
const CANCEL_REQUEST_CODE: i32 = 80877104;
/// Largest single message we will accept (64 MiB); anything bigger is
/// a corrupt or hostile frame, not a query.
const MAX_MESSAGE_LEN: i32 = 64 * 1024 * 1024;

static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);

/// The one engine + table registry shared by all connections of one
/// server process. Every statement locks this for its whole run, so
/// two clients can never interleave a read and a write halfway.
struct Shared {
    engine: Engine,
    tables: TableStore,
}

/// Start the server: open the engine (this takes the data-dir lock —
/// a second server on the same directory fails here), bind
/// 127.0.0.1:port, and serve clients forever, one thread each.
/// Binding loopback only is deliberate: trust auth (no password) is
/// only acceptable on the local machine — see the README warning.
pub fn serve(data_dir: &Path, port: u16) -> std::io::Result<()> {
    let engine = Engine::open(data_dir)?;
    let tables = TableStore::open(data_dir)?;
    let shared = Arc::new(Mutex::new(Shared { engine, tables }));
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!(
        "zeno 0.3.0 listening on 127.0.0.1:{} (data dir: {})",
        port,
        data_dir.display()
    );
    println!("trust auth: any local client may connect, no password — local prototype only");
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
                let shared = Arc::clone(&shared);
                let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(stream, shared, conn_id) {
                        eprintln!("pgwire conn {conn_id}: {e}");
                    }
                });
            }
            Err(e) => eprintln!("pgwire accept error: {e}"),
        }
    }
    Ok(())
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
fn read_message(reader: &mut impl Read) -> std::io::Result<Option<(u8, Vec<u8>)>> {
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
fn write_message(writer: &mut impl Write, tag: u8, body: &[u8]) -> std::io::Result<()> {
    let len = (body.len() + 4) as i32;
    writer.write_all(&[tag])?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(body)?;
    Ok(())
}

fn put_i16(out: &mut Vec<u8>, v: i16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_cstr(out: &mut Vec<u8>, s: &str) {
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
fn error_response(writer: &mut impl Write, code: &str, message: &str) -> std::io::Result<()> {
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
fn empty_query_response(writer: &mut impl Write) -> std::io::Result<()> {
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
fn row_description(writer: &mut impl Write, columns: &[String]) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_i16(&mut body, columns.len() as i16);
    for col in columns {
        put_cstr(&mut body, col);
        put_i32(&mut body, 0); // table OID
        put_i16(&mut body, 0); // column number
        put_i32(&mut body, 25); // type OID: text
        put_i16(&mut body, -1); // typlen: variable
        put_i32(&mut body, -1); // typmod
        put_i16(&mut body, 0); // format: text
    }
    write_message(writer, b'T', &body)
}

/// DataRow: 'D' + Int16 field count, then per field Int32 length
/// (-1 = NULL) + bytes. Zeno values are never NULL, so -1 never
/// appears here — a missing column is sent as an empty string.
fn data_row(writer: &mut impl Write, values: &[String]) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_i16(&mut body, values.len() as i16);
    for v in values {
        put_i32(&mut body, v.len() as i32);
        body.extend_from_slice(v.as_bytes());
    }
    write_message(writer, b'D', &body)
}

/// CommandComplete: 'C' + tag, e.g. "SELECT 2", "INSERT 0 1".
fn command_complete(writer: &mut impl Write, tag: &str) -> std::io::Result<()> {
    let mut body = Vec::new();
    put_cstr(&mut body, tag);
    write_message(writer, b'C', &body)
}

// ---------------------------------------------------------------------
// One connection: startup handshake, then the query loop.
// ---------------------------------------------------------------------

fn handle_client(
    stream: TcpStream,
    shared: Arc<Mutex<Shared>>,
    conn_id: u32,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    // A read timeout during the handshake is a quiet client, not a
    // server error: close this connection cleanly, keep serving.
    if let Err(e) = startup_handshake(&mut reader, &mut writer, conn_id) {
        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
            eprintln!("pgwire conn {conn_id}: read timeout during handshake, closing");
            return Ok(());
        }
        return Err(e);
    }

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
        match tag {
            b'Q' => {
                let sql = cstr_to_string(&body);
                // A write failure here means the client is gone; stop
                // this connection, not the server.
                run_query(&mut writer, &shared, &sql)?;
                ready_for_query(&mut writer)?;
            }
            b'X' => return Ok(()), // Terminate
            b'P' | b'B' | b'D' | b'E' | b'C' => {
                // Extended query protocol: not in V0.3. Say so clearly
                // and keep the connection alive for the next message —
                // but send NO ReadyForQuery here. The PostgreSQL
                // protocol sends ReadyForQuery only after Sync; a
                // driver pipelines Parse+Bind+Describe+Execute+Sync
                // in one flush and reads until the FIRST ReadyForQuery,
                // so one ReadyForQuery per extended message would
                // leave stale replies that get read as the answers to
                // the NEXT Simple Query (desync). Sync below is the
                // one message that closes the cycle with ReadyForQuery.
                error_response(
                    &mut writer,
                    "0A000",
                    "extended query protocol (Parse/Bind/Describe/Execute/Sync) is not \
                     supported in Zeno 0.3.0 — use the Simple Query protocol",
                )?;
                writer.flush()?;
            }
            b'S' => {
                // Sync: end of an extended-query cycle. This is the
                // ONLY ReadyForQuery sent for extended messages — one
                // per Sync, however many Parse/Bind/Describe/Execute
                // messages came before it.
                ready_for_query(&mut writer)?;
                writer.flush()?;
            }
            b'H' => {
                // Flush: no reply message of its own — just push out
                // whatever is already queued (here: nothing, since
                // every extended message above already answered).
                writer.flush()?;
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
    }
}

/// The startup handshake. Loops over SSLRequest (answer 'N', then
/// read the real startup message); CancelRequest closes silently;
/// anything else that is not protocol 3.0 gets an ErrorResponse and
/// the connection is closed by the caller (returning Err).
fn startup_handshake(
    reader: &mut impl Read,
    writer: &mut impl Write,
    conn_id: u32,
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
                writer.write_all(b"N")?; // no SSL in this prototype
                writer.flush()?;
                continue; // the real StartupMessage follows
            }
            CANCEL_REQUEST_CODE => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "CancelRequest: nothing to cancel, closing",
                ));
            }
            PROTOCOL_V3 => {
                // Parameters are NUL-separated name/value pairs after
                // the version, ending with an empty string. We accept
                // any user/database — trust auth — and ignore the rest.
                let _params = parse_startup_params(&body[4..]);
                auth_ok(writer)?;
                // server_version "18.0" = the PostgreSQL version whose
                // wire protocol this implements (see module docs).
                // Zeno is not PostgreSQL; this only keeps clients that
                // parse the version from choking.
                parameter_status(writer, "server_version", "18.0")?;
                parameter_status(writer, "client_encoding", "UTF8")?;
                parameter_status(writer, "standard_conforming_strings", "on")?;
                let pid = std::process::id() as i32;
                // Secret key: connection id mixed with the pid; only
                // used to match a CancelRequest, which we do not
                // implement — it just has to be stable per connection.
                // m7: this secret is PREDICTABLE (pid ^ conn_id) and
                // is only harmless because Cancel is unimplemented.
                // The day CancelRequest is implemented, this MUST
                // become a random per-connection secret (CSPRNG, e.g.
                // from /dev/urandom) — a guessable secret would let
                // anyone cancel anyone else's backend.
                let secret = pid ^ (conn_id as i32).wrapping_mul(0x9E37_79B9u32 as i32);
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
        match execute_statement(writer, shared, stmt) {
            Ok(()) => {}
            Err(e) => {
                // SQL error: report it, keep the connection alive.
                error_response(writer, e.code, &e.message)?;
            }
        }
    }
    writer.flush()
}

/// Split SQL on ';' that sits outside single-quoted strings,
/// double-quoted identifiers, and `--` line comments.
/// `''` inside a string is an escaped quote, not the end of it, and
/// `""` inside a double-quoted identifier is the same. Comment text
/// (including any ';' in it) is dropped; the newline ending the
/// comment is kept so the statements stay separated.
fn split_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_string = false; // '...'
    let mut in_ident = false; // "..."
    let mut in_comment = false; // -- to end of line
    while let Some(c) = chars.next() {
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
/// (undefined column), "42P07" (table already exists) or "0A000"
/// (feature not supported).
struct SqlError {
    code: &'static str,
    message: String,
}

fn sql_err(code: &'static str, message: impl Into<String>) -> SqlError {
    SqlError {
        code,
        message: message.into(),
    }
}

/// Run one statement and write its RowDescription/DataRow/
/// CommandComplete (or return its SqlError for the caller to report).
fn execute_statement(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    stmt: &str,
) -> Result<(), SqlError> {
    let tokens = tokenize(stmt).ok_or_else(|| sql_err("42601", "unterminated string literal"))?;
    let first = tokens
        .first()
        .map(|t| t.text.to_ascii_uppercase())
        .unwrap_or_default();
    match first.as_str() {
        "CREATE" => exec_create(writer, shared, &tokens),
        "INSERT" => exec_insert(writer, shared, &tokens),
        "SELECT" => exec_select(writer, shared, &tokens),
        "DELETE" => exec_delete(writer, shared, &tokens),
        "UPDATE" | "DROP" | "ALTER" | "BEGIN" | "COMMIT" | "ROLLBACK" | "SET" | "SHOW"
        | "GRANT" | "REVOKE" | "TRUNCATE" | "COPY" | "VACUUM" | "EXPLAIN" => Err(sql_err(
            "0A000",
            format!("{first} is not supported in Zeno 0.3.0 (only CREATE TABLE, INSERT, SELECT, DELETE)"),
        )),
        "" => Ok(()),
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
struct Token {
    /// The token text, unquoted: for 'abc' this is `abc`, for "col"
    /// this is `col`, for bare words/numbers the word itself.
    text: String,
    /// True only for a 'single-quoted' string literal.
    quoted_string: bool,
}

fn tokenize(sql: &str) -> Option<Vec<Token>> {
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
                });
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None => return None,
                        Some('"') => break,
                        Some(ch) => s.push(ch),
                    }
                }
                tokens.push(Token {
                    text: s,
                    quoted_string: false,
                });
            }
            '(' | ')' | ',' | '=' | '*' | '.' | ';' => {
                tokens.push(Token {
                    text: c.to_string(),
                    quoted_string: false,
                });
                chars.next();
            }
            _ => {
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_whitespace() || "()',=\";*".contains(ch) {
                        break;
                    }
                    s.push(ch);
                    chars.next();
                }
                if !s.is_empty() {
                    tokens.push(Token {
                        text: s,
                        quoted_string: false,
                    });
                }
            }
        }
    }
    Some(tokens)
}

/// Case-insensitive keyword match at `tokens[i]`; returns the index
/// after the keyword, or None.
fn expect_keyword(tokens: &[Token], i: usize, kw: &str) -> Option<usize> {
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
fn expect_name(tokens: &[Token], i: usize) -> Option<(String, usize)> {
    let t = tokens.get(i)?;
    if t.quoted_string || ["(", ")", ",", "=", "*", "."].contains(&t.text.as_str()) {
        return None;
    }
    Some((t.text.clone(), i + 1))
}

fn expect_punct(tokens: &[Token], i: usize, p: &str) -> Option<usize> {
    if tokens.get(i).map(|t| t.text.as_str()) == Some(p) {
        Some(i + 1)
    } else {
        None
    }
}

/// `WHERE col = value` at `tokens[i]`; `value` may be a quoted string
/// or a bare token (number or word). Returns (column, value, next).
fn parse_where(tokens: &[Token], i: usize) -> Option<(String, String, usize)> {
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
fn exec_create(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
) -> Result<(), SqlError> {
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
    let mut guard = shared
        .lock()
        .map_err(|_| sql_err("XX000", "server lock poisoned"))?;
    guard.tables.create_table(&name, columns).map_err(|e| {
        if e.contains("already exists") {
            sql_err("42P07", e)
        } else {
            sql_err("42601", e)
        }
    })?;
    command_complete(writer, "CREATE TABLE").map_err(|e| sql_err("XX000", e.to_string()))?;
    Ok(())
}

/// INSERT INTO name VALUES (v1, v2, ...) — values are quoted strings
/// or bare tokens; the count must match the table's columns.
fn exec_insert(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
) -> Result<(), SqlError> {
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
        if t.text == ")" {
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
    let mut guard = shared
        .lock()
        .map_err(|_| sql_err("XX000", "server lock poisoned"))?;
    let Shared { engine, tables } = &mut *guard;
    tables.insert(engine, &name, values).map_err(|e| {
        if e.contains("no such table") {
            sql_err("42P01", e)
        } else {
            sql_err("42601", e)
        }
    })?;
    command_complete(writer, "INSERT 0 1").map_err(|e| sql_err("XX000", e.to_string()))?;
    Ok(())
}

/// SELECT * | col1, col2 FROM name [WHERE col = value]
fn exec_select(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
) -> Result<(), SqlError> {
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

    let mut guard = shared
        .lock()
        .map_err(|_| sql_err("XX000", "server lock poisoned"))?;
    let Shared { engine, tables } = &mut *guard;
    let all_columns = tables
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
    let rows = tables
        .select(
            engine,
            &name,
            filter.as_ref().map(|(c, v)| (c.as_str(), v.as_str())),
        )
        .map_err(|e| sql_err("42P01", e))?;
    row_description(writer, &out_columns).map_err(|e| sql_err("XX000", e.to_string()))?;
    for (_, row) in &rows {
        let values: Vec<String> = out_columns
            .iter()
            .map(|c| row.get(c).cloned().unwrap_or_default())
            .collect();
        data_row(writer, &values).map_err(|e| sql_err("XX000", e.to_string()))?;
    }
    command_complete(writer, &format!("SELECT {}", rows.len()))
        .map_err(|e| sql_err("XX000", e.to_string()))?;
    Ok(())
}

/// DELETE FROM name [WHERE col = value] — without WHERE, all rows go.
fn exec_delete(
    writer: &mut impl Write,
    shared: &Arc<Mutex<Shared>>,
    tokens: &[Token],
) -> Result<(), SqlError> {
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
    let mut guard = shared
        .lock()
        .map_err(|_| sql_err("XX000", "server lock poisoned"))?;
    let Shared { engine, tables } = &mut *guard;
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
    command_complete(writer, &format!("DELETE {deleted}"))
        .map_err(|e| sql_err("XX000", e.to_string()))?;
    Ok(())
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
        let shared = Arc::new(Mutex::new(Shared { engine, tables }));

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let shared_clone = Arc::clone(&shared);
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let _ = tx.send(handle_client(stream, shared_clone, 1));
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
}

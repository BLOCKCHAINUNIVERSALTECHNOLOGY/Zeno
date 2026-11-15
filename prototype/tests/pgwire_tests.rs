// pgwire_tests.rs — integration tests for the PostgreSQL wire
// protocol (src/pgwire.rs), speaking raw TCP.
//
// `psql` is NOT installed in this sandbox (checked: `which psql`
// finds nothing), so there is no real PostgreSQL client to test
// against. Instead this file is its own minimal client: it builds the
// StartupMessage and Query ('Q') frames by hand, reads the server's
// reply bytes, and parses them into messages (AuthenticationOk,
// RowDescription, DataRow, CommandComplete, ErrorResponse,
// ReadyForQuery) to verify each one. That checks the framing and the
// message flow exactly as a real client would see them — only the
// client side is hand-rolled. On a machine with `psql`, the same
// server can be checked with:
//   psql -h 127.0.0.1 -p 5433 -U zeno -d zeno
// (see the README; trust auth, no password — local prototype only).
//
// Each test starts a real `zeno serve` child process on its own free
// port and data directory, so the server binary — not just the
// library — is what gets exercised, including the data-dir lock.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

// `PemObject` brings `CertificateDer::pem_slice_iter` into scope
// (used by the TLS test to trust the generated self-signed cert).
use rustls::pki_types::pem::PemObject;

// ---------------------------------------------------------------------
// Server process management
// ---------------------------------------------------------------------

fn tmp_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("zeno-pgwire-test-{name}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A free TCP port on loopback: bind :0, read the port, release it.
// The server then binds the same port; a race with another process
// grabbing it in between is possible in theory, but the tests retry
// the server start once if the bind fails.
fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Server {
    fn start(name: &str) -> Server {
        Self::start_with_args(name, &[])
    }

    /// Start with extra `serve` arguments (e.g. `["--tls"]` or
    /// `["--max-connections", "2"]`).
    fn start_with_args(name: &str, extra: &[&str]) -> Server {
        let dir = tmp_dir(name);
        Self::start_with_args_on_dir(dir, extra)
    }

    /// Like `start_with_args`, but on an already-prepared directory
    /// (the TLS test generates its certificate there first — the
    /// `tmp_dir` helper wipes the directory, so the cert must be
    /// made AFTER the wipe and BEFORE the server starts).
    fn start_with_args_on_dir(dir: PathBuf, extra: &[&str]) -> Server {
        let bin = env!("CARGO_BIN_EXE_zeno");
        // `free_port` binds :0 and releases it, so two tests starting
        // at the same moment can be handed the SAME port — and the
        // second server then fails to bind. Retry with a fresh port
        // when the child exits (bind failure) instead of connecting
        // to the other test's server by mistake.
        for _attempt in 0..5 {
            let port = free_port();
            let mut argv: Vec<String> = vec![
                "--data".to_string(),
                dir.to_str().unwrap().to_string(),
                "serve".to_string(),
                "--port".to_string(),
                port.to_string(),
            ];
            argv.extend(extra.iter().map(|s| s.to_string()));
            let mut child = Command::new(bin)
                .args(&argv)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to start zeno serve");
            // Wait until the server accepts connections (up to ~5s).
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    // The child must still be alive: if it exited
                    // (bind failed) we may have connected to another
                    // test's server on the same port instead. Wait a
                    // moment first — a bind failure exits within
                    // milliseconds of spawn, so a live child after
                    // this delay really owns the port.
                    std::thread::sleep(Duration::from_millis(150));
                    match child.try_wait() {
                        Ok(None) => return Server { child, port, dir },
                        _ => break, // exited — retry with a new port
                    }
                }
                if std::time::Instant::now() > deadline {
                    break; // child never listened — retry
                }
                if child.try_wait().map(|s| s.is_some()).unwrap_or(false) {
                    break; // exited early (e.g. bind failed) — retry
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("zeno serve did not start listening in 5 attempts");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Server {
    /// Kill the server WITHOUT cleaning up the data directory, so
    /// a new server can be started on the same directory (a
    /// restart / crash-recovery test). `mem::forget` skips the
    /// `Drop` above, which would delete the directory; the caller
    /// owns cleanup from here (usually by starting a second
    /// `Server` on the returned directory, whose `Drop` removes it).
    fn stop_keep_dir(mut self) -> PathBuf {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let dir = self.dir.clone();
        std::mem::forget(self);
        dir
    }
}

// ---------------------------------------------------------------------
// Minimal PostgreSQL client: builds frames, parses reply messages.
// ---------------------------------------------------------------------

/// One parsed backend message. Only the fields the tests check are kept.
/// (`#[allow(dead_code)]`: some variants are matched on, not read from —
/// e.g. BackendKeyData's pid/secret are verified by parsing, not by value.)
#[derive(Debug)]
#[allow(dead_code)]
enum Msg {
    AuthOk,
    ParameterStatus(String, String),
    BackendKeyData(i32, i32),
    ReadyForQuery(u8),
    RowDescription(Vec<String>, Vec<i16>), // (column names, format codes)
    DataRow(Vec<Option<String>>),
    CommandComplete(String),
    ErrorResponse(String, String), // (SQLSTATE code, message)
    EmptyQueryResponse,
    ParseComplete,
    BindComplete,
    CloseComplete,
    ParameterDescription(Vec<i32>), // parameter type OIDs
    NoData,
    PortalSuspended,
    AuthSasl(String),         // AuthenticationSASL mechanisms (joined)
    AuthSaslContinue(String), // AuthenticationSASLContinue data
    AuthSaslFinal(String),    // AuthenticationSASLFinal data
    Other(u8),
}

struct Client {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

fn read_cstr(data: &[u8], pos: &mut usize) -> String {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    let s = String::from_utf8_lossy(&data[start..*pos]).into_owned();
    *pos += 1; // skip the NUL
    s
}

fn read_i16(data: &[u8], pos: &mut usize) -> i16 {
    let v = i16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    v
}

fn read_i32(data: &[u8], pos: &mut usize) -> i32 {
    let v = i32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    v
}

fn parse_message(tag: u8, body: &[u8]) -> Msg {
    let mut pos = 0;
    match tag {
        b'R' => {
            let code = read_i32(body, &mut pos);
            match code {
                0 => Msg::AuthOk,
                10 => {
                    // AuthenticationSASL: NUL-separated mechanisms,
                    // then a zero-byte terminator.
                    let mut mechs = Vec::new();
                    while pos < body.len() {
                        let m = read_cstr(body, &mut pos);
                        if m.is_empty() {
                            break;
                        }
                        mechs.push(m);
                    }
                    Msg::AuthSasl(mechs.join(","))
                }
                11 => Msg::AuthSaslContinue(String::from_utf8_lossy(&body[pos..]).into_owned()),
                12 => Msg::AuthSaslFinal(String::from_utf8_lossy(&body[pos..]).into_owned()),
                _ => Msg::Other(b'R'),
            }
        }
        b'S' => {
            let name = read_cstr(body, &mut pos);
            let value = read_cstr(body, &mut pos);
            Msg::ParameterStatus(name, value)
        }
        b'K' => Msg::BackendKeyData(read_i32(body, &mut pos), read_i32(body, &mut pos)),
        b'Z' => Msg::ReadyForQuery(body[0]),
        b'T' => {
            let n = read_i16(body, &mut pos);
            let mut cols = Vec::new();
            let mut formats = Vec::new();
            for _ in 0..n {
                let name = read_cstr(body, &mut pos);
                let _table_oid = read_i32(body, &mut pos);
                let _attr = read_i16(body, &mut pos);
                let type_oid = read_i32(body, &mut pos);
                let _typlen = read_i16(body, &mut pos);
                let _typmod = read_i32(body, &mut pos);
                let format = read_i16(body, &mut pos);
                assert_eq!(type_oid, 25, "all Zeno columns are text (OID 25)");
                cols.push(name);
                formats.push(format);
            }
            Msg::RowDescription(cols, formats)
        }
        b'D' => {
            let n = read_i16(body, &mut pos);
            let mut values = Vec::new();
            for _ in 0..n {
                let len = read_i32(body, &mut pos);
                if len == -1 {
                    values.push(None);
                } else {
                    let v = String::from_utf8_lossy(&body[pos..pos + len as usize]).into_owned();
                    pos += len as usize;
                    values.push(Some(v));
                }
            }
            Msg::DataRow(values)
        }
        b'C' => Msg::CommandComplete(read_cstr(body, &mut pos)),
        b'E' => {
            let mut code = String::new();
            let mut message = String::new();
            while pos < body.len() && body[pos] != 0 {
                let field = body[pos];
                pos += 1;
                let value = read_cstr(body, &mut pos);
                match field {
                    b'C' => code = value,
                    b'M' => message = value,
                    _ => {}
                }
            }
            Msg::ErrorResponse(code, message)
        }
        b'I' => Msg::EmptyQueryResponse,
        b'1' => Msg::ParseComplete,
        b'2' => Msg::BindComplete,
        b'3' => Msg::CloseComplete,
        b't' => {
            let n = read_i16(body, &mut pos);
            let mut types = Vec::new();
            for _ in 0..n {
                types.push(read_i32(body, &mut pos));
            }
            Msg::ParameterDescription(types)
        }
        b'n' => Msg::NoData,
        b's' => Msg::PortalSuspended,
        other => Msg::Other(other),
    }
}

// ---------------------------------------------------------------------
// Extended-protocol frame builders (frontend messages, protocol 54.7).
// ---------------------------------------------------------------------

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut f = vec![tag];
    f.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    f.extend_from_slice(body);
    f
}

fn parse_frame(name: &str, sql: &str, param_types: &[i32]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(name.as_bytes());
    b.push(0);
    b.extend_from_slice(sql.as_bytes());
    b.push(0);
    b.extend_from_slice(&(param_types.len() as i16).to_be_bytes());
    for t in param_types {
        b.extend_from_slice(&t.to_be_bytes());
    }
    frame(b'P', &b)
}

/// A Bind frame. Each param is (format code is given separately,
/// value: None = SQL NULL, Some(bytes) = the value).
fn bind_frame(
    portal: &str,
    stmt: &str,
    param_formats: &[i16],
    params: &[Option<Vec<u8>>],
    result_formats: &[i16],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(portal.as_bytes());
    b.push(0);
    b.extend_from_slice(stmt.as_bytes());
    b.push(0);
    b.extend_from_slice(&(param_formats.len() as i16).to_be_bytes());
    for f in param_formats {
        b.extend_from_slice(&f.to_be_bytes());
    }
    b.extend_from_slice(&(params.len() as i16).to_be_bytes());
    for v in params {
        match v {
            None => b.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(bytes) => {
                b.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                b.extend_from_slice(bytes);
            }
        }
    }
    b.extend_from_slice(&(result_formats.len() as i16).to_be_bytes());
    for f in result_formats {
        b.extend_from_slice(&f.to_be_bytes());
    }
    frame(b'B', &b)
}

fn text_param(value: &str) -> Option<Vec<u8>> {
    Some(value.as_bytes().to_vec())
}

fn int4_param(value: i32) -> Option<Vec<u8>> {
    Some(value.to_be_bytes().to_vec())
}

fn describe_frame(kind: u8, name: &str) -> Vec<u8> {
    let mut b = vec![kind];
    b.extend_from_slice(name.as_bytes());
    b.push(0);
    frame(b'D', &b)
}

fn execute_frame(portal: &str, max_rows: i32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(portal.as_bytes());
    b.push(0);
    b.extend_from_slice(&max_rows.to_be_bytes());
    frame(b'E', &b)
}

fn close_frame(kind: u8, name: &str) -> Vec<u8> {
    let mut b = vec![kind];
    b.extend_from_slice(name.as_bytes());
    b.push(0);
    frame(b'C', &b)
}

fn sync_frame() -> Vec<u8> {
    frame(b'S', &[])
}

fn sasl_initial_response(mechanism: &str, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(mechanism.as_bytes());
    b.push(0);
    b.extend_from_slice(&(data.len() as i32).to_be_bytes());
    b.extend_from_slice(data);
    frame(b'p', &b)
}

fn sasl_response(data: &[u8]) -> Vec<u8> {
    frame(b'p', data)
}

fn startup_frame(user: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
    for (k, v) in [("user", user), ("database", "zeno")] {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut frame = Vec::new();
    frame.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// Run `zeno user set-password` with the password on stdin (twice).
fn set_password(dir: &std::path::Path, user: &str, password: &str) {
    let bin = env!("CARGO_BIN_EXE_zeno");
    let mut child = Command::new(bin)
        .args([
            "--data",
            dir.to_str().unwrap(),
            "user",
            "set-password",
            user,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn zeno user set-password");
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(format!("{password}\n{password}\n").as_bytes())
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().expect("wait zeno user");
    assert!(
        output.status.success(),
        "set-password failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl Client {
    /// Connect and run the startup handshake. Returns the messages
    /// received up to and including ReadyForQuery.
    /// Connect the socket only — no startup message sent yet.
    /// The SCRAM tests drive the handshake by hand from here.
    fn connect_socket(port: u16) -> Client {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to server");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        Client {
            stream: stream.try_clone().unwrap(),
            reader: BufReader::new(stream),
        }
    }

    fn connect(port: u16) -> (Client, Vec<Msg>) {
        let mut client = Self::connect_socket(port);
        client.stream.write_all(&startup_frame("zeno")).unwrap();
        client.stream.flush().unwrap();
        let msgs = client.read_until_ready();
        (client, msgs)
    }

    /// Read messages until ReadyForQuery (inclusive) and return them.
    fn read_until_ready(&mut self) -> Vec<Msg> {
        let mut msgs = Vec::new();
        loop {
            let mut tag = [0u8; 1];
            self.reader.read_exact(&mut tag).expect("read message tag");
            let mut len_buf = [0u8; 4];
            self.reader
                .read_exact(&mut len_buf)
                .expect("read message length");
            let len = i32::from_be_bytes(len_buf);
            assert!(len >= 4, "message length {len} is too small");
            let mut body = vec![0u8; (len - 4) as usize];
            self.reader
                .read_exact(&mut body)
                .expect("read message body");
            let is_ready = tag[0] == b'Z';
            msgs.push(parse_message(tag[0], &body));
            if is_ready {
                return msgs;
            }
        }
    }

    /// Read exactly one backend message. Used mid-handshake (SCRAM)
    /// and for single extended messages sent without Sync, where
    /// there is no ReadyForQuery to read until.
    fn read_one(&mut self) -> Msg {
        let mut tag = [0u8; 1];
        self.reader.read_exact(&mut tag).expect("read message tag");
        let mut len_buf = [0u8; 4];
        self.reader
            .read_exact(&mut len_buf)
            .expect("read message length");
        let len = i32::from_be_bytes(len_buf);
        assert!(len >= 4, "message length {len} is too small");
        let mut body = vec![0u8; (len - 4) as usize];
        self.reader
            .read_exact(&mut body)
            .expect("read message body");
        parse_message(tag[0], &body)
    }

    /// Read one backend message, or None if the server closed the
    /// connection (EOF). Used after a failed login, where the
    /// server closes the socket instead of answering.
    fn try_read_one(&mut self) -> Option<Msg> {
        let mut tag = [0u8; 1];
        match self.reader.read_exact(&mut tag) {
            Ok(()) => {}
            Err(_) => return None,
        }
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf).ok()?;
        let len = i32::from_be_bytes(len_buf);
        if len < 4 {
            return None;
        }
        let mut body = vec![0u8; (len - 4) as usize];
        self.reader.read_exact(&mut body).ok()?;
        Some(parse_message(tag[0], &body))
    }

    /// Send extended-protocol frames (a batch ending in Sync) and
    /// return the replies up to and including ReadyForQuery.
    fn extended(&mut self, frames: &[Vec<u8>]) -> Vec<Msg> {
        for f in frames {
            self.send_raw(f);
        }
        self.read_until_ready()
    }

    /// Send one Simple Query ('Q') and return its reply messages,
    /// up to and including ReadyForQuery.
    fn query(&mut self, sql: &str) -> Vec<Msg> {
        let mut frame = Vec::new();
        frame.push(b'Q');
        let body_len = sql.len() + 1 + 4;
        frame.extend_from_slice(&(body_len as i32).to_be_bytes());
        frame.extend_from_slice(sql.as_bytes());
        frame.push(0);
        self.stream.write_all(&frame).unwrap();
        self.stream.flush().unwrap();
        self.read_until_ready()
    }

    /// Send already-framed bytes (e.g. a pipelined extended-protocol
    /// batch) without reading a reply yet.
    fn send_raw(&mut self, frame: &[u8]) {
        self.stream.write_all(frame).unwrap();
        self.stream.flush().unwrap();
    }

    /// Send Terminate ('X') and close.
    fn terminate(mut self) {
        let _ = self.stream.write_all(&[b'X', 0, 0, 0, 4]);
        let _ = self.stream.flush();
    }

    /// The rows of the last query: DataRow values, in order.
    fn rows(msgs: &[Msg]) -> Vec<Vec<Option<String>>> {
        msgs.iter()
            .filter_map(|m| match m {
                Msg::DataRow(values) => Some(values.clone()),
                _ => None,
            })
            .collect()
    }

    /// The CommandComplete tag of the last query, if any.
    fn tag(msgs: &[Msg]) -> Option<String> {
        msgs.iter().find_map(|m| match m {
            Msg::CommandComplete(t) => Some(t.clone()),
            _ => None,
        })
    }

    /// The LAST CommandComplete tag (a multi-statement query sends
    /// one per statement; `tag` above is only the first).
    fn last_tag(msgs: &[Msg]) -> Option<String> {
        msgs.iter().rev().find_map(|m| match m {
            Msg::CommandComplete(t) => Some(t.clone()),
            _ => None,
        })
    }

    /// The ErrorResponse of the last query, if any.
    fn error(msgs: &[Msg]) -> Option<(String, String)> {
        msgs.iter().find_map(|m| match m {
            Msg::ErrorResponse(code, msg) => Some((code.clone(), msg.clone())),
            _ => None,
        })
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[test]
fn startup_handshake_auth_ok_and_ready() {
    let server = Server::start("handshake");
    let (client, msgs) = Client::connect(server.port);
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::AuthOk)),
        "handshake must include AuthenticationOk: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::ParameterStatus(name, _) if name == "server_version"
        )),
        "handshake must include a server_version ParameterStatus: {msgs:?}"
    );
    assert!(
        matches!(msgs.last(), Some(Msg::ReadyForQuery(b'I'))),
        "handshake must end with ReadyForQuery 'I' (idle): {msgs:?}"
    );
    client.terminate();
}

#[test]
fn ssl_request_is_answered_n_then_handshake_works() {
    // B1 REGRESSION: the server used to answer SSLRequest with
    // 'N' TWICE — once in `handle_connection`, once again in the
    // handshake, which was fed the same 8 bytes back — so a
    // client saw `4e 4e 52 ...` (two 'N's, then AuthOk) and
    // libpq (sslmode=prefer, the default) could never connect to
    // a plain server. The old test only read the FIRST 'N' and
    // dropped the connection, so it never caught this. This test
    // completes the handshake on the SAME connection and asserts
    // exactly one 'N' followed by AuthenticationOk + ReadyForQuery.
    let server = Server::start("ssl");
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&ssl_request_bytes()).unwrap();
    stream.flush().unwrap();
    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer).unwrap();
    assert_eq!(answer, [b'N'], "SSLRequest must be answered 'N' (no SSL)");
    // The SAME connection now sends its StartupMessage — the next
    // byte must start AuthenticationOk ('R'), not a second 'N'.
    stream.write_all(&startup_frame("zeno")).unwrap();
    stream.flush().unwrap();
    let mut client = Client {
        stream: stream.try_clone().unwrap(),
        reader: BufReader::new(stream),
    };
    let msgs = client.read_until_ready();
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::AuthOk)),
        "handshake on the same connection must include AuthenticationOk: {msgs:?}"
    );
    assert!(
        matches!(msgs.last(), Some(Msg::ReadyForQuery(b'I'))),
        "handshake must end with ReadyForQuery 'I' (idle): {msgs:?}"
    );
    client.terminate();
}

/// The 8-byte SSLRequest frame (length 8, code 80877103).
fn ssl_request_bytes() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&8i32.to_be_bytes());
    b.extend_from_slice(&80877103i32.to_be_bytes());
    b
}

#[test]
fn ssl_request_and_startup_pipelined_sends_exactly_one_n() {
    // B1, pipelined flavour: a client may send SSLRequest and the
    // StartupMessage in a single flush. The server must still
    // answer exactly one 'N', then run the handshake.
    let server = Server::start("ssl-pipelined");
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = ssl_request_bytes();
    bytes.extend_from_slice(&startup_frame("zeno"));
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer).unwrap();
    assert_eq!(
        answer,
        [b'N'],
        "pipelined SSLRequest must be answered with exactly one 'N'"
    );
    let mut client = Client {
        stream: stream.try_clone().unwrap(),
        reader: BufReader::new(stream),
    };
    let msgs = client.read_until_ready();
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::AuthOk)),
        "pipelined handshake must include AuthenticationOk: {msgs:?}"
    );
    assert!(
        matches!(msgs.last(), Some(Msg::ReadyForQuery(b'I'))),
        "pipelined handshake must end with ReadyForQuery: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn gssenc_request_is_answered_n_then_handshake_works() {
    // m3: PostgreSQL answers GSSENCRequest (code 80877105) with
    // 'N', just like SSLRequest — Zeno has no GSSAPI. The request
    // is consumed, and the same connection then handshakes.
    let server = Server::start("gssenc");
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut req = Vec::new();
    req.extend_from_slice(&8i32.to_be_bytes());
    req.extend_from_slice(&80877105i32.to_be_bytes());
    stream.write_all(&req).unwrap();
    stream.flush().unwrap();
    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer).unwrap();
    assert_eq!(
        answer,
        [b'N'],
        "GSSENCRequest must be answered 'N' (no GSSAPI)"
    );
    stream.write_all(&startup_frame("zeno")).unwrap();
    stream.flush().unwrap();
    let mut client = Client {
        stream: stream.try_clone().unwrap(),
        reader: BufReader::new(stream),
    };
    let msgs = client.read_until_ready();
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::AuthOk)),
        "handshake after GSSENC must include AuthenticationOk: {msgs:?}"
    );
    assert!(
        matches!(msgs.last(), Some(Msg::ReadyForQuery(b'I'))),
        "handshake after GSSENC must end with ReadyForQuery: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn backend_key_data_secret_is_random_per_connection() {
    // Pre-existing fix (bonus): the BackendKeyData secret used to
    // be `pid ^ conn_id * constant` — predictable, which would let
    // anyone cancel anyone else's backend the day CancelRequest is
    // implemented. Two connections must now get different secrets.
    let server = Server::start("keydata");
    let (_, msgs1) = Client::connect(server.port);
    let (_, msgs2) = Client::connect(server.port);
    let secret = |msgs: &[Msg]| {
        msgs.iter().find_map(|m| match m {
            Msg::BackendKeyData(_, s) => Some(*s),
            _ => None,
        })
    };
    let s1 = secret(&msgs1).expect("first handshake must include BackendKeyData");
    let s2 = secret(&msgs2).expect("second handshake must include BackendKeyData");
    assert_ne!(
        s1, s2,
        "two connections must get different BackendKeyData secrets"
    );
}

#[test]
fn create_insert_select_roundtrip() {
    let server = Server::start("roundtrip");
    let (mut client, _) = Client::connect(server.port);

    let msgs = client.query("CREATE TABLE users (id, name, city)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );

    let msgs = client.query("INSERT INTO users VALUES (1, 'Sanjay', 'Delhi')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    let msgs = client.query("INSERT INTO users VALUES (2, 'Asha', 'Mumbai')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );

    // SELECT * returns both rows, all three columns, in insert order.
    let msgs = client.query("SELECT * FROM users");
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::RowDescription(cols, _) if cols == &["id".to_string(), "name".to_string(), "city".to_string()]
        )),
        "RowDescription must name id, name, city: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&msgs),
        vec![
            vec![
                Some("1".into()),
                Some("Sanjay".into()),
                Some("Delhi".into())
            ],
            vec![Some("2".into()), Some("Asha".into()), Some("Mumbai".into())],
        ],
        "DataRows must hold the inserted values"
    );
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 2"), "{msgs:?}");

    // WHERE filters to one row.
    let msgs = client.query("SELECT * FROM users WHERE city = 'Delhi'");
    assert_eq!(Client::rows(&msgs).len(), 1, "{msgs:?}");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 1"), "{msgs:?}");

    // Column list: only the named columns come back, in that order.
    let msgs = client.query("SELECT name, city FROM users WHERE id = 2");
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::RowDescription(cols, _) if cols == &["name".to_string(), "city".to_string()]
        )),
        "RowDescription must name only name, city: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("Asha".into()), Some("Mumbai".into())]],
    );
    client.terminate();
}

#[test]
fn create_table_with_types_and_multi_statement_query() {
    let server = Server::start("types-multi");
    let (mut client, _) = Client::connect(server.port);

    // Type words are accepted (and ignored — every column is text).
    let msgs = client.query("CREATE TABLE t (id int, name text)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );

    // Several statements in ONE Query message all run, in order.
    let msgs = client
        .query("INSERT INTO t VALUES (1, 'one'); INSERT INTO t VALUES (2, 'two'); SELECT * FROM t");
    assert_eq!(Client::rows(&msgs).len(), 2, "{msgs:?}");
    assert_eq!(
        Client::last_tag(&msgs).as_deref(),
        Some("SELECT 2"),
        "{msgs:?}"
    );
    assert!(
        msgs.iter()
            .filter(|m| matches!(m, Msg::CommandComplete(_)))
            .count()
            >= 3,
        "one CommandComplete per statement: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn delete_removes_rows() {
    let server = Server::start("delete");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, name, city)");
    client.query("INSERT INTO users VALUES (1, 'Sanjay', 'Delhi')");
    client.query("INSERT INTO users VALUES (2, 'Asha', 'Mumbai')");
    client.query("INSERT INTO users VALUES (3, 'Ravi', 'Delhi')");

    let msgs = client.query("DELETE FROM users WHERE city = 'Delhi'");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("DELETE 2"), "{msgs:?}");
    let msgs = client.query("SELECT * FROM users");
    assert_eq!(Client::rows(&msgs).len(), 1, "only Asha must remain");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 1"), "{msgs:?}");

    // No WHERE: every remaining row goes.
    let msgs = client.query("DELETE FROM users");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("DELETE 1"), "{msgs:?}");
    let msgs = client.query("SELECT * FROM users");
    assert_eq!(Client::rows(&msgs).len(), 0, "table must be empty now");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 0"), "{msgs:?}");
    client.terminate();
}

#[test]
fn unsupported_sql_errors_but_connection_survives() {
    let server = Server::start("errors");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, name)");
    client.query("INSERT INTO users VALUES (1, 'Sanjay')");

    // UPDATE is supported since V0.6: it changes the row and
    // reports UPDATE 1 (this block used to assert 0A000 when
    // UPDATE was not in the subset).
    let msgs = client.query("UPDATE users SET name = 'X' WHERE id = 1");
    assert!(
        Client::error(&msgs).is_none(),
        "UPDATE must succeed in V0.6: {msgs:?}"
    );
    assert_eq!(Client::tag(&msgs).as_deref(), Some("UPDATE 1"), "{msgs:?}");
    let msgs = client.query("SELECT * FROM users");
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("1".to_string()), Some("X".to_string())]],
        "the row must show the updated name: {msgs:?}"
    );

    // DROP TABLE is still unsupported: 0A000, then ReadyForQuery.
    let msgs = client.query("DROP TABLE users");
    let (code, message) = Client::error(&msgs).expect("DROP TABLE must produce an ErrorResponse");
    assert_eq!(
        code, "0A000",
        "unsupported feature must be 0A000: {message}"
    );
    assert!(
        matches!(msgs.last(), Some(Msg::ReadyForQuery(b'I'))),
        "an error must still end with ReadyForQuery: {msgs:?}"
    );

    // Unknown table: 42P01.
    let msgs = client.query("SELECT * FROM no_such_table");
    let (code, _) = Client::error(&msgs).expect("missing table must produce an ErrorResponse");
    assert_eq!(code, "42P01", "undefined table must be 42P01");

    // Garbage SQL: syntax error 42601.
    let msgs = client.query("BOGUS SYNTAX HERE");
    let (code, _) = Client::error(&msgs).expect("garbage must produce an ErrorResponse");
    assert_eq!(code, "42601", "syntax error must be 42601");

    // Duplicate table: 42P07.
    let msgs = client.query("CREATE TABLE users (id, name)");
    let (code, _) = Client::error(&msgs).expect("duplicate table must produce an ErrorResponse");
    assert_eq!(code, "42P07", "duplicate table must be 42P07");

    // The connection is STILL usable after all those errors — the
    // server never crashed it and never closed it.
    let msgs = client.query("SELECT * FROM users");
    assert!(
        Client::error(&msgs).is_none(),
        "SELECT after errors must succeed: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&msgs).len(),
        1,
        "the one row must still be there"
    );
    client.terminate();
}

#[test]
fn empty_query_gets_empty_query_response() {
    let server = Server::start("empty");
    let (mut client, _) = Client::connect(server.port);
    let msgs = client.query("   ");
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::EmptyQueryResponse)),
        "a blank query must get EmptyQueryResponse ('I'): {msgs:?}"
    );
    assert!(matches!(msgs.last(), Some(Msg::ReadyForQuery(b'I'))));
    client.terminate();
}

#[test]
fn disconnect_and_reconnect_sees_the_same_data() {
    let server = Server::start("reconnect");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, name)");
    client.query("INSERT INTO users VALUES (1, 'Sanjay')");
    client.terminate(); // client disconnect must not stop the server

    let (mut client2, _) = Client::connect(server.port);
    let msgs = client2.query("SELECT * FROM users");
    assert_eq!(
        Client::rows(&msgs).len(),
        1,
        "data must survive a client disconnect"
    );
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("1".into()), Some("Sanjay".into())]],
    );
    client2.terminate();
}

#[test]
fn concurrent_clients_share_one_engine() {
    let server = Server::start("concurrent");
    let port = server.port;
    // Create the table first, in the main thread, so the four client
    // threads only insert (no create race between them).
    let (mut setup, _) = Client::connect(port);
    let msgs = setup.query("CREATE TABLE shared (id, name)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );
    setup.terminate();

    let mut handles = Vec::new();
    for i in 0..4 {
        handles.push(std::thread::spawn(move || {
            let (mut client, _) = Client::connect(port);
            let msgs = client.query(&format!("INSERT INTO shared VALUES ({i}, 'c{i}')"));
            assert!(
                Client::error(&msgs).is_none(),
                "concurrent insert failed: {msgs:?}"
            );
            assert_eq!(Client::tag(&msgs).as_deref(), Some("INSERT 0 1"));
            client.terminate();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let (mut client, _) = Client::connect(port);
    let msgs = client.query("SELECT * FROM shared");
    assert_eq!(
        Client::rows(&msgs).len(),
        4,
        "all four concurrent inserts must land: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_batch_then_simple_query_stays_in_sync() {
    // V0.4: the extended protocol WORKS now. A driver pipelines
    // Parse+Bind+Describe+Execute+Sync in ONE flush and reads until
    // the first ReadyForQuery. The server must answer each message
    // in order — ParseComplete, BindComplete, RowDescription (from
    // Describe), RowDescription + DataRow + CommandComplete (from
    // Execute) — and exactly ONE ReadyForQuery, from Sync. The NEXT
    // Simple Query on the same connection must then work normally.
    let server = Server::start("extended-sync");
    let (mut client, _) = Client::connect(server.port);

    // Seed a table first, on a second connection, so the SELECT
    // below has a real row to return.
    let (mut seeder, _) = Client::connect(server.port);
    seeder.query("CREATE TABLE t (id, name)");
    seeder.query("INSERT INTO t VALUES (1, 'Sanjay')");
    seeder.terminate();

    // Parse+Bind+Describe+Execute+Sync in one flush, like psycopg/JDBC.
    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM t", &[]),
        bind_frame("", "", &[], &[], &[]),
        describe_frame(b'P', ""),
        execute_frame("", 0),
        sync_frame(),
    ]);

    assert!(
        msgs.iter().any(|m| matches!(m, Msg::ParseComplete)),
        "Parse must answer ParseComplete: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::BindComplete)),
        "Bind must answer BindComplete: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::RowDescription(cols, _) if cols == &["id".to_string(), "name".to_string()]
        )),
        "Describe/Execute must send RowDescription: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("1".into()), Some("Sanjay".into())]],
        "Execute must return the seeded row: {msgs:?}"
    );
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 1"), "{msgs:?}");
    assert!(
        Client::error(&msgs).is_none(),
        "no error in a good extended batch: {msgs:?}"
    );
    let readies = msgs
        .iter()
        .filter(|m| matches!(m, Msg::ReadyForQuery(_)))
        .count();
    assert_eq!(
        readies, 1,
        "exactly one ReadyForQuery (from Sync): {msgs:?}"
    );
    assert!(matches!(msgs.last(), Some(Msg::ReadyForQuery(b'I'))));

    // The NEXT Simple Query on the SAME connection must now work —
    // no stale replies, no desync.
    let msgs = client.query("SELECT * FROM t");
    assert!(
        Client::error(&msgs).is_none(),
        "SELECT after an extended batch must not see a stale error: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("1".into()), Some("Sanjay".into())]],
        "SELECT must return the seeded row: {msgs:?}"
    );
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 1"), "{msgs:?}");

    // And the one after that, too — the connection is not off by one.
    let msgs = client.query("SELECT * FROM t");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 1"), "{msgs:?}");
    client.terminate();
}

#[test]
fn extended_unnamed_select_with_params() {
    // The full extended flow with a $1 parameter: Parse, Describe
    // statement (ParameterDescription + RowDescription), Bind,
    // Describe portal, Execute, Sync. Then Execute the same portal
    // again — a completed portal re-runs from the start.
    let server = Server::start("ext-params");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, name, city)");
    client.query("INSERT INTO users VALUES (1, 'Sanjay', 'Delhi')");
    client.query("INSERT INTO users VALUES (2, 'Asha', 'Mumbai')");
    client.query("INSERT INTO users VALUES (3, 'Ravi', 'Delhi')");

    let msgs = client.extended(&[
        parse_frame("", "SELECT id, name FROM users WHERE city = $1", &[]),
        describe_frame(b'S', ""),
        bind_frame("", "", &[], &[text_param("Delhi")], &[]),
        describe_frame(b'P', ""),
        execute_frame("", 0),
        sync_frame(),
    ]);
    // ParameterDescription: one param, inferred as text (25).
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::ParameterDescription(types) if types == &[25]
        )),
        "Describe statement must report one text param: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::RowDescription(cols, _) if cols == &["id".to_string(), "name".to_string()]
        )),
        "RowDescription must name id, name: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&msgs),
        vec![
            vec![Some("1".into()), Some("Sanjay".into())],
            vec![Some("3".into()), Some("Ravi".into())],
        ],
        "only the Delhi rows must come back: {msgs:?}"
    );
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 2"), "{msgs:?}");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");

    // Re-Bind the unnamed portal with another city and re-Execute.
    let msgs = client.extended(&[
        bind_frame("", "", &[], &[text_param("Mumbai")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("2".into()), Some("Asha".into())]],
        "re-Bind with Mumbai must return only Asha: {msgs:?}"
    );
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 1"), "{msgs:?}");
    client.terminate();
}

#[test]
fn extended_named_statement_and_portal_reuse() {
    // Named statements and portals live across Syncs; two portals
    // from one statement are independent; Close removes them.
    let server = Server::start("ext-named");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, name, city)");
    client.query("INSERT INTO users VALUES (1, 'Sanjay', 'Delhi')");
    client.query("INSERT INTO users VALUES (2, 'Asha', 'Mumbai')");

    // One named statement, two named portals with different values.
    let msgs = client.extended(&[
        parse_frame("find_city", "SELECT name FROM users WHERE city = $1", &[]),
        bind_frame("p_delhi", "find_city", &[], &[text_param("Delhi")], &[]),
        bind_frame("p_mumbai", "find_city", &[], &[text_param("Mumbai")], &[]),
        execute_frame("p_delhi", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("Sanjay".into())]],
        "{msgs:?}"
    );
    let msgs = client.extended(&[execute_frame("p_mumbai", 0), sync_frame()]);
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("Asha".into())]],
        "{msgs:?}"
    );
    // p_delhi still holds Delhi — portals are independent.
    let msgs = client.extended(&[execute_frame("p_delhi", 0), sync_frame()]);
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("Sanjay".into())]],
        "{msgs:?}"
    );

    // Close the portal: Execute must now fail with 26000.
    let msgs = client.extended(&[
        close_frame(b'P', "p_delhi"),
        execute_frame("p_delhi", 0),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::CloseComplete)),
        "Close must answer CloseComplete: {msgs:?}"
    );
    let (code, _) = Client::error(&msgs).expect("closed portal must error");
    assert_eq!(code, "26000", "unknown portal must be 26000: {msgs:?}");

    // Close the statement: its remaining portal (p_mumbai) goes
    // with it, and the statement itself is gone.
    let msgs = client.extended(&[
        close_frame(b'S', "find_city"),
        execute_frame("p_mumbai", 0),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("portal of a closed statement must error");
    assert_eq!(code, "26000", "{msgs:?}");
    let msgs = client.extended(&[
        bind_frame("p3", "find_city", &[], &[text_param("Delhi")], &[]),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("closed statement must error");
    assert_eq!(code, "26000", "{msgs:?}");

    // The connection still works after all that.
    let msgs = client.query("SELECT * FROM users");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    assert_eq!(Client::rows(&msgs).len(), 2);
    client.terminate();
}

#[test]
fn extended_insert_with_int_param_text_and_binary() {
    // $1 declared int4 (23): text "42" and binary 4-byte int4 both
    // bind; a non-integer text value fails with 22P02.
    let server = Server::start("ext-int");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (id, name)");

    // Text-format int param.
    let msgs = client.extended(&[
        parse_frame("", "INSERT INTO t VALUES ($1, $2)", &[23]),
        bind_frame(
            "",
            "",
            &[],
            &[text_param("42"), text_param("text-int")],
            &[],
        ),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );

    // Binary-format int param (4 bytes big-endian) + text param.
    let msgs = client.extended(&[
        bind_frame(
            "",
            "",
            &[1, 0],
            &[int4_param(-7), text_param("bin-int")],
            &[],
        ),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );

    // Bad text int: 22P02, then the connection recovers via Sync.
    let msgs = client.extended(&[
        bind_frame("", "", &[], &[text_param("abc"), text_param("x")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("bad int must error");
    assert_eq!(code, "22P02", "{msgs:?}");
    let msgs = client.query("SELECT * FROM t");
    assert_eq!(
        Client::rows(&msgs),
        vec![
            vec![Some("42".into()), Some("text-int".into())],
            vec![Some("-7".into()), Some("bin-int".into())],
        ],
        "both good inserts must be there, the bad one must not: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_error_skips_messages_until_sync() {
    // Protocol 54.2.3: after an extended-protocol error the server
    // sends ONE ErrorResponse and discards everything until Sync —
    // including a Simple Query smuggled into the same pipeline.
    // The discarded Query must NEVER run.
    let server = Server::start("ext-skip");
    let (mut client, _) = Client::connect(server.port);

    // Bad Parse, then a CREATE TABLE as a Simple Query, then Sync —
    // all in one flush. The CREATE must be discarded.
    let mut batch = Vec::new();
    batch.extend_from_slice(&parse_frame("", "BOGUS SYNTAX HERE", &[]));
    let mut q = Vec::new();
    q.push(b'Q');
    let sql = "CREATE TABLE should_not_exist (a)";
    q.extend_from_slice(&((sql.len() + 1 + 4) as i32).to_be_bytes());
    q.extend_from_slice(sql.as_bytes());
    q.push(0);
    batch.extend_from_slice(&q);
    batch.extend_from_slice(&sync_frame());
    client.send_raw(&batch);
    let msgs = client.read_until_ready();
    let errors = msgs
        .iter()
        .filter(|m| matches!(m, Msg::ErrorResponse(_, _)))
        .count();
    assert_eq!(
        errors, 1,
        "exactly ONE ErrorResponse for the bad Parse: {msgs:?}"
    );
    assert_eq!(
        msgs.iter()
            .filter(|m| matches!(m, Msg::ReadyForQuery(_)))
            .count(),
        1,
        "exactly one ReadyForQuery (from Sync): {msgs:?}"
    );
    // The CREATE was discarded: the table does not exist.
    let msgs = client.query("SELECT * FROM should_not_exist");
    let (code, _) = Client::error(&msgs).expect("missing table must error");
    assert_eq!(code, "42P01", "{msgs:?}");

    // And a bad Bind (wrong param count) recovers the same way.
    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM users WHERE city = $1", &[]),
        bind_frame("", "", &[], &[], &[]), // 0 params, 1 needed
        execute_frame("", 0),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("param count mismatch must error");
    assert_eq!(code, "08P01", "{msgs:?}");
    assert_eq!(
        msgs.iter()
            .filter(|m| matches!(m, Msg::ErrorResponse(_, _)))
            .count(),
        1,
        "one error only — the Execute after the bad Bind is skipped: {msgs:?}"
    );
    // The connection is fully usable after recovery.
    let msgs = client.query("CREATE TABLE t2 (a)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );
    let msgs = client.query("INSERT INTO t2 VALUES ('ok')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_portal_suspended_and_resume() {
    // Execute with max_rows stops early with PortalSuspended; the
    // next Execute resumes from the same rows; a later Execute
    // re-runs the statement from the start.
    let server = Server::start("ext-suspend");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (id, name)");
    for i in 1..=3 {
        client.query(&format!("INSERT INTO t VALUES ({i}, 'n{i}')"));
    }

    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM t", &[]),
        bind_frame("", "", &[], &[], &[]),
        execute_frame("", 2),
        sync_frame(),
    ]);
    assert_eq!(
        Client::rows(&msgs).len(),
        2,
        "first Execute sends 2 rows: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::PortalSuspended)),
        "must end with PortalSuspended, not CommandComplete: {msgs:?}"
    );
    assert!(
        Client::tag(&msgs).is_none(),
        "no CommandComplete while suspended: {msgs:?}"
    );

    // Resume: the last row, then CommandComplete SELECT 3 (total).
    let msgs = client.extended(&[execute_frame("", 2), sync_frame()]);
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("3".into()), Some("n3".into())]],
        "resume must send the remaining row: {msgs:?}"
    );
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 3"), "{msgs:?}");
    assert!(
        !msgs.iter().any(|m| matches!(m, Msg::PortalSuspended)),
        "completed Execute must not suspend: {msgs:?}"
    );

    // Execute again: the portal re-runs from the start.
    let msgs = client.extended(&[execute_frame("", 0), sync_frame()]);
    assert_eq!(Client::rows(&msgs).len(), 3, "{msgs:?}");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 3"), "{msgs:?}");
    client.terminate();
}

#[test]
fn extended_close_and_redefine_rules() {
    // Named statements/portals must be Closed before redefinition
    // (42P05 / 42P03); closing a nonexistent name is NOT an error.
    let server = Server::start("ext-close");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a)");

    let msgs = client.extended(&[
        parse_frame("s1", "SELECT * FROM t", &[]),
        parse_frame("s1", "SELECT * FROM t", &[]),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("re-Parse must error");
    assert_eq!(code, "42P05", "{msgs:?}");
    // The error skipped nothing else here (Sync was next), and the
    // FIRST statement is still the stored one.
    let msgs = client.extended(&[
        close_frame(b'S', "s1"),
        parse_frame("s1", "SELECT * FROM t", &[]),
        close_frame(b'S', "never_existed"),
        close_frame(b'P', "never_existed"),
        sync_frame(),
    ]);
    assert!(
        msgs.iter()
            .filter(|m| matches!(m, Msg::CloseComplete))
            .count()
            >= 2,
        "both Closes (one real, one nonexistent) answer CloseComplete: {msgs:?}"
    );
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");

    // Named portal re-Bind without Close: 42P03.
    let msgs = client.extended(&[
        bind_frame("p1", "s1", &[], &[], &[]),
        bind_frame("p1", "s1", &[], &[], &[]),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("re-Bind must error");
    assert_eq!(code, "42P03", "{msgs:?}");
    client.terminate();
}

#[test]
fn extended_describe_unknown_empty_and_nodata() {
    // Describe of unknown objects: 26000. An empty query parses,
    // describes as ParameterDescription([]) + NoData, and executes
    // as EmptyQueryResponse. Non-SELECT statements describe NoData.
    let server = Server::start("ext-desc");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a)");

    let msgs = client.extended(&[
        describe_frame(b'S', "nope"),
        describe_frame(b'P', "nope"),
        sync_frame(),
    ]);
    assert_eq!(
        msgs.iter()
            .filter(|m| matches!(m, Msg::ErrorResponse(code, _) if code == "26000"))
            .count(),
        1,
        "only the FIRST Describe errors — the second is skipped until Sync: {msgs:?}"
    );

    let msgs = client.extended(&[
        parse_frame("", "", &[]),
        describe_frame(b'S', ""),
        bind_frame("", "", &[], &[], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::ParameterDescription(types) if types.is_empty()
        )),
        "empty statement has no params: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::NoData)),
        "empty statement describes NoData: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::EmptyQueryResponse)),
        "empty statement executes as EmptyQueryResponse: {msgs:?}"
    );

    // INSERT describes ParameterDescription + NoData.
    let msgs = client.extended(&[
        parse_frame("", "INSERT INTO t VALUES ($1)", &[]),
        describe_frame(b'S', ""),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::ParameterDescription(types) if types == &[25]
        )),
        "{msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::NoData)),
        "INSERT must describe NoData: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_create_insert_delete_roundtrip() {
    // CREATE / INSERT / DELETE through the extended protocol, with
    // params, verified afterwards over Simple Query.
    let server = Server::start("ext-ddl");
    let (mut client, _) = Client::connect(server.port);

    let msgs = client.extended(&[
        parse_frame("", "CREATE TABLE users (id, name, city)", &[]),
        bind_frame("", "", &[], &[], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );

    let msgs = client.extended(&[
        parse_frame("", "INSERT INTO users VALUES ($1, $2, $3)", &[]),
        bind_frame(
            "",
            "",
            &[],
            &[text_param("1"), text_param("Sanjay"), text_param("Delhi")],
            &[],
        ),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    let msgs = client.extended(&[
        bind_frame(
            "",
            "",
            &[],
            &[text_param("2"), text_param("Asha"), text_param("Mumbai")],
            &[],
        ),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );

    let msgs = client.extended(&[
        parse_frame("", "DELETE FROM users WHERE city = $1", &[]),
        bind_frame("", "", &[], &[text_param("Mumbai")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(Client::tag(&msgs).as_deref(), Some("DELETE 1"), "{msgs:?}");

    let msgs = client.query("SELECT * FROM users");
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![
            Some("1".into()),
            Some("Sanjay".into()),
            Some("Delhi".into())
        ]],
        "{msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_binary_result_format() {
    // Bind with result format 1 (binary): Describe portal reports
    // format 1 per column, and the DataRow values are still the
    // same text bytes (binary text = raw UTF-8).
    let server = Server::start("ext-binfmt");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (id, name)");
    client.query("INSERT INTO t VALUES (1, 'Sanjay')");

    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM t", &[]),
        bind_frame("", "", &[], &[], &[1]),
        describe_frame(b'P', ""),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::RowDescription(_, formats) if formats == &[1, 1]
        )),
        "binary result format must be reported per column: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("1".into()), Some("Sanjay".into())]],
        "binary text rows carry the same bytes: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_parse_rejects_gaps_and_multi_statement() {
    // $1 + $3 with no $2: 42P18. Two statements in one Parse: 42601.
    // Both recover via Sync.
    let server = Server::start("ext-parse-err");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a)");

    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM t WHERE a = $1 AND a = $3", &[]),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("param gap must error");
    assert_eq!(code, "42P18", "{msgs:?}");

    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM t; SELECT * FROM t", &[]),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("multi-statement Parse must error");
    assert_eq!(code, "42601", "{msgs:?}");

    // Unsupported statement kind fails at Parse with 0A000.
    // (V0.6: UPDATE is supported now, so DROP TABLE stands in
    // for the unsupported kind here.)
    let msgs = client.extended(&[parse_frame("", "DROP TABLE t", &[]), sync_frame()]);
    let (code, _) = Client::error(&msgs).expect("DROP TABLE Parse must error");
    assert_eq!(code, "0A000", "{msgs:?}");

    // Unsupported declared param type: 0A000.
    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM t WHERE a = $1", &[16]),
        sync_frame(),
    ]);
    let (code, _) = Client::error(&msgs).expect("bad param type must error");
    assert_eq!(code, "0A000", "{msgs:?}");

    // And the connection is fine afterwards.
    let msgs = client.query("SELECT * FROM t");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    client.terminate();
}

#[test]
fn extended_null_param_becomes_empty_string() {
    // Zeno has no NULLs: a bound NULL stores as "" (documented).
    let server = Server::start("ext-null");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a, b)");
    let msgs = client.extended(&[
        parse_frame("", "INSERT INTO t VALUES ($1, $2)", &[]),
        bind_frame("", "", &[], &[text_param("x"), None], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    let msgs = client.query("SELECT * FROM t");
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("x".into()), Some("".into())]],
        "{msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_simple_query_clears_unnamed() {
    // A Simple Query destroys the unnamed statement and portal:
    // after one, Bind/Execute on "" must fail with 26000.
    let server = Server::start("ext-clear");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a)");
    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM t", &[]),
        bind_frame("", "", &[], &[], &[]),
        sync_frame(),
    ]);
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    client.query("SELECT * FROM t"); // Simple Query clears unnamed
    let msgs = client.extended(&[execute_frame("", 0), sync_frame()]);
    let (code, _) = Client::error(&msgs).expect("cleared portal must error");
    assert_eq!(code, "26000", "{msgs:?}");
    client.terminate();
}

#[test]
fn second_server_on_same_data_dir_fails_lock() {
    let server = Server::start("lock");
    // A second server on the SAME data directory must fail at open
    // (the LOCK file), not corrupt the first server's files.
    let bin = env!("CARGO_BIN_EXE_zeno");
    let output = Command::new(bin)
        .args([
            "--data",
            server.dir.to_str().unwrap(),
            "serve",
            "--port",
            &free_port().to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run second server");
    assert!(
        !output.status.success(),
        "second server on the same data dir must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lock"),
        "second server must fail with a lock error, got: {stderr}"
    );
    // And the first server is still alive and answering.
    let (mut client, _) = Client::connect(server.port);
    let msgs = client.query("CREATE TABLE t (a)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );
    client.terminate();
}

// ---------------------------------------------------------------------
// SCRAM-SHA-256 tests. The client side here uses the library's own
// `zeno::auth::scram_client_response` (whose math is pinned to the
// RFC 7677 vectors in the unit tests) but drives the framing,
// nonce echo and server-signature check itself, so the handshake
// flow is verified end to end against a real server.
// ---------------------------------------------------------------------

/// Drive a full SCRAM login on an already-connected socket.
/// Returns the messages after AuthenticationSASLFinal (AuthOk,
/// ParameterStatus, BackendKeyData, ReadyForQuery).
fn scram_login(client: &mut Client, user: &str, password: &str) -> Vec<Msg> {
    client.stream.write_all(&startup_frame(user)).unwrap();
    client.stream.flush().unwrap();
    let first = client.read_one();
    assert!(
        matches!(first, Msg::AuthSasl(ref m) if m == "SCRAM-SHA-256"),
        "server must offer SCRAM-SHA-256, got: {first:?}"
    );
    let client_nonce = "test-client-nonce-123";
    let client_first_bare = format!("n={},r={}", user, client_nonce);
    let client_first = format!("n,,{client_first_bare}");
    client
        .stream
        .write_all(&sasl_initial_response(
            "SCRAM-SHA-256",
            client_first.as_bytes(),
        ))
        .unwrap();
    client.stream.flush().unwrap();
    let second = client.read_one();
    let Msg::AuthSaslContinue(server_first) = second else {
        panic!("expected AuthenticationSASLContinue, got: {second:?}");
    };
    let (client_final, expected_sig) =
        zeno::auth::scram_client_response(password, &client_first_bare, &server_first)
            .expect("client SCRAM computation must work");
    client
        .stream
        .write_all(&sasl_response(client_final.as_bytes()))
        .unwrap();
    client.stream.flush().unwrap();
    let third = client.read_one();
    let Msg::AuthSaslFinal(server_final) = third else {
        panic!("expected AuthenticationSASLFinal, got: {third:?}");
    };
    assert_eq!(
        server_final,
        format!("v={expected_sig}"),
        "server-final signature must match the client's expectation (mutual auth)"
    );
    client.read_until_ready()
}

#[test]
fn scram_login_success_then_query_works() {
    let server = Server::start("scram-ok");
    set_password(&server.dir, "sanjay", "correct horse battery staple");

    let mut client = Client::connect_socket(server.port);
    let msgs = scram_login(&mut client, "sanjay", "correct horse battery staple");
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::AuthOk)),
        "SCRAM login must end with AuthenticationOk: {msgs:?}"
    );
    assert!(matches!(msgs.last(), Some(Msg::ReadyForQuery(b'I'))));

    let msgs = client.query("CREATE TABLE t (a)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );
    let msgs = client.query("INSERT INTO t VALUES ('scram-works')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    client.terminate();
}

#[test]
fn scram_wrong_password_rejected_and_connection_closed() {
    let server = Server::start("scram-wrong");
    set_password(&server.dir, "sanjay", "correct horse battery staple");

    // Drive the handshake by hand with the WRONG password: the
    // server must answer the client-final with ErrorResponse 28P01
    // and then close the connection.
    let mut client = Client::connect_socket(server.port);
    client.stream.write_all(&startup_frame("sanjay")).unwrap();
    client.stream.flush().unwrap();
    assert!(matches!(client.read_one(), Msg::AuthSasl(_)));
    let client_first_bare = "n=sanjay,r=test-client-nonce-123";
    client
        .stream
        .write_all(&sasl_initial_response(
            "SCRAM-SHA-256",
            format!("n,,{client_first_bare}").as_bytes(),
        ))
        .unwrap();
    client.stream.flush().unwrap();
    let second = client.read_one();
    let Msg::AuthSaslContinue(server_first) = second else {
        panic!("expected AuthenticationSASLContinue, got: {second:?}");
    };
    let (client_final, _) =
        zeno::auth::scram_client_response("wrong password", client_first_bare, &server_first)
            .unwrap();
    client
        .stream
        .write_all(&sasl_response(client_final.as_bytes()))
        .unwrap();
    client.stream.flush().unwrap();
    let third = client.read_one();
    let (code, _) = match &third {
        Msg::ErrorResponse(code, msg) => (code.clone(), msg.clone()),
        other => panic!("expected ErrorResponse 28P01, got: {other:?}"),
    };
    assert_eq!(code, "28P01", "wrong password must be 28P01");
    assert!(
        client.try_read_one().is_none(),
        "server must close the connection after a failed login"
    );

    // The server itself is still alive: a correct login works.
    let mut client2 = Client::connect_socket(server.port);
    let msgs = scram_login(&mut client2, "sanjay", "correct horse battery staple");
    assert!(msgs.iter().any(|m| matches!(m, Msg::AuthOk)), "{msgs:?}");
    client2.terminate();
}

#[test]
fn scram_unknown_user_gets_fake_exchange_then_rejected() {
    // An unknown user still gets a full server-first (fake salt),
    // so the exchange looks identical — and still ends in 28P01.
    let server = Server::start("scram-ghost");
    set_password(&server.dir, "sanjay", "correct horse battery staple");

    let mut client = Client::connect_socket(server.port);
    client.stream.write_all(&startup_frame("ghost")).unwrap();
    client.stream.flush().unwrap();
    assert!(matches!(client.read_one(), Msg::AuthSasl(_)));
    let client_first_bare = "n=ghost,r=test-client-nonce-123";
    client
        .stream
        .write_all(&sasl_initial_response(
            "SCRAM-SHA-256",
            format!("n,,{client_first_bare}").as_bytes(),
        ))
        .unwrap();
    client.stream.flush().unwrap();
    let second = client.read_one();
    let Msg::AuthSaslContinue(server_first) = second else {
        panic!("unknown user must still get a server-first, got: {second:?}");
    };
    let (client_final, _) =
        zeno::auth::scram_client_response("whatever", client_first_bare, &server_first).unwrap();
    client
        .stream
        .write_all(&sasl_response(client_final.as_bytes()))
        .unwrap();
    client.stream.flush().unwrap();
    let third = client.read_one();
    match &third {
        Msg::ErrorResponse(code, _) => assert_eq!(code, "28P01", "{third:?}"),
        other => panic!("expected ErrorResponse 28P01, got: {other:?}"),
    }
    assert!(client.try_read_one().is_none());
    client.terminate();
}

#[test]
fn scram_password_set_after_server_start_applies_at_once() {
    // users.json is re-read on every connection: setting a
    // password while the server runs must flip NEW connections
    // from trust auth to SCRAM, with no restart.
    let server = Server::start("scram-late");
    // Trust auth first: a plain handshake works.
    let (client, msgs) = Client::connect(server.port);
    assert!(msgs.iter().any(|m| matches!(m, Msg::AuthOk)), "{msgs:?}");
    client.terminate();

    set_password(&server.dir, "sanjay", "late password");

    // The next connection must be offered SCRAM, not AuthOk.
    let mut client = Client::connect_socket(server.port);
    client.stream.write_all(&startup_frame("sanjay")).unwrap();
    client.stream.flush().unwrap();
    assert!(
        matches!(client.read_one(), Msg::AuthSasl(_)),
        "after set-password the server must offer SCRAM"
    );
    // Finish the login on this same socket.
    let client_nonce = "test-client-nonce-123";
    let client_first_bare = format!("n=sanjay,r={client_nonce}");
    client
        .stream
        .write_all(&sasl_initial_response(
            "SCRAM-SHA-256",
            format!("n,,{client_first_bare}").as_bytes(),
        ))
        .unwrap();
    client.stream.flush().unwrap();
    let second = client.read_one();
    let Msg::AuthSaslContinue(server_first) = second else {
        panic!("expected AuthenticationSASLContinue, got: {second:?}");
    };
    let (client_final, expected_sig) =
        zeno::auth::scram_client_response("late password", &client_first_bare, &server_first)
            .unwrap();
    client
        .stream
        .write_all(&sasl_response(client_final.as_bytes()))
        .unwrap();
    client.stream.flush().unwrap();
    let third = client.read_one();
    assert!(
        matches!(third, Msg::AuthSaslFinal(ref v) if v == &format!("v={expected_sig}")),
        "server-final must verify: {third:?}"
    );
    let msgs = client.read_until_ready();
    assert!(msgs.iter().any(|m| matches!(m, Msg::AuthOk)), "{msgs:?}");
    client.terminate();
}

// ---------------------------------------------------------------------
// V0.4 review fixes: regression tests for the eight must-fix issues
// (failed Parse/Bind dropping stored state, Describe(S) ordering,
// block comments, INSERT ')' literal, 32767 param cap) and the
// SCRAM minors (deterministic fake salt, SASLprep login, strict
// client-first parsing, short-nonce rejection, set-password on a
// missing data directory).
// ---------------------------------------------------------------------

fn seed_users(client: &mut Client) {
    client.query("CREATE TABLE users (id, name, city)");
    client.query("INSERT INTO users VALUES (1, 'Sanjay', 'Delhi')");
    client.query("INSERT INTO users VALUES (2, 'Asha', 'Mumbai')");
    client.query("INSERT INTO users VALUES (3, 'Ravi', 'Delhi')");
}

#[test]
fn extended_failed_parse_drops_the_old_statement() {
    // Reviewer repro (issue 1): Parse a good SELECT, Bind Delhi
    // (rows come back), then re-Parse the unnamed statement with
    // garbage SQL (42601) — the OLD statement must be gone, so a
    // later Bind + Execute fails with 26000 instead of silently
    // running the old query for Mumbai.
    let server = Server::start("ext-failed-parse");
    let (mut client, _) = Client::connect(server.port);
    seed_users(&mut client);

    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM users WHERE city = $1", &[]),
        bind_frame("", "", &[], &[text_param("Delhi")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 2"), "{msgs:?}");

    let msgs = client.extended(&[parse_frame("", "SELEC oops broken", &[]), sync_frame()]);
    assert_eq!(
        Client::error(&msgs).map(|(c, _)| c).as_deref(),
        Some("42601"),
        "garbage re-Parse must fail with 42601: {msgs:?}"
    );

    let msgs = client.extended(&[
        bind_frame("", "", &[], &[text_param("Mumbai")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::error(&msgs).map(|(c, _)| c).as_deref(),
        Some("26000"),
        "Bind after a failed Parse must fail (old statement is gone), not run Mumbai: {msgs:?}"
    );
    assert!(
        Client::rows(&msgs).is_empty(),
        "no rows may come back from a dropped statement: {msgs:?}"
    );

    // And a fresh Parse works again on the same connection.
    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM users WHERE city = $1", &[]),
        bind_frame("", "", &[], &[text_param("Mumbai")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 1"), "{msgs:?}");
    client.terminate();
}

#[test]
fn extended_failed_bind_drops_the_old_portal() {
    // Issue 1, Bind half: a portal that Bound fine, then a Bind
    // with a bad int4 value (22P02) — the OLD portal must be gone,
    // so a later Execute fails with 26000 instead of silently
    // re-running the old query.
    let server = Server::start("ext-failed-bind");
    let (mut client, _) = Client::connect(server.port);
    seed_users(&mut client);

    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM users WHERE id = $1", &[23]),
        bind_frame("", "", &[], &[text_param("1")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 1"), "{msgs:?}");

    let msgs = client.extended(&[
        bind_frame("", "", &[], &[text_param("xx")], &[]),
        sync_frame(),
    ]);
    assert_eq!(
        Client::error(&msgs).map(|(c, _)| c).as_deref(),
        Some("22P02"),
        "bad int4 Bind must fail with 22P02: {msgs:?}"
    );

    let msgs = client.extended(&[execute_frame("", 0), sync_frame()]);
    assert_eq!(
        Client::error(&msgs).map(|(c, _)| c).as_deref(),
        Some("26000"),
        "Execute after a failed Bind must fail (old portal is gone): {msgs:?}"
    );
    assert!(Client::rows(&msgs).is_empty(), "{msgs:?}");

    // A fresh Bind works again on the same connection.
    let msgs = client.extended(&[
        bind_frame("", "", &[], &[text_param("2")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![
            Some("2".into()),
            Some("Asha".into()),
            Some("Mumbai".into())
        ]],
        "{msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_describe_missing_table_sends_only_error() {
    // Issue 5: Describe(S) on SELECT * FROM ghost used to send
    // ParameterDescription FIRST and then the ErrorResponse. Now
    // the table/column check runs first, so the reply is ONLY the
    // ErrorResponse (42P01) — no ParameterDescription before it.
    let server = Server::start("ext-desc-ghost");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a)");

    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM ghost", &[]),
        describe_frame(b'S', ""),
        sync_frame(),
    ]);
    assert!(
        !msgs
            .iter()
            .any(|m| matches!(m, Msg::ParameterDescription(_))),
        "Describe(S) on a missing table must NOT send ParameterDescription first: {msgs:?}"
    );
    assert_eq!(
        Client::error(&msgs).map(|(c, _)| c).as_deref(),
        Some("42P01"),
        "{msgs:?}"
    );

    // Control: Describe(S) on a real table still sends
    // ParameterDescription + RowDescription.
    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM t", &[]),
        describe_frame(b'S', ""),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::ParameterDescription(types) if types.is_empty()
        )),
        "{msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::RowDescription(cols, _) if cols == &["a".to_string()]
        )),
        "{msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_block_comments_are_ignored() {
    // Issue 6: `/* */` comments in Parse (a `$2` inside one is
    // not a parameter) and in Simple Query (a `/* ; */` must not
    // split, and a comment must not break the statement).
    let server = Server::start("ext-block-comment");
    let (mut client, _) = Client::connect(server.port);
    seed_users(&mut client);

    let msgs = client.extended(&[
        parse_frame("", "SELECT * FROM users WHERE city = $1 /* $2 */", &[]),
        describe_frame(b'S', ""),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(
            m,
            Msg::ParameterDescription(types) if types == &[25]
        )),
        "only $1 counts — the $2 in the block comment is not a param: {msgs:?}"
    );
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");

    let msgs = client.query("SELECT * FROM users /* comment */ WHERE city = 'Delhi'");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 2"), "{msgs:?}");

    // "/* ; */" alone is an empty query, not two statements.
    let msgs = client.query("/* ; */");
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::EmptyQueryResponse)),
        "{msgs:?}"
    );
    let msgs = client.query("SELECT * FROM users /* ; */");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 3"), "{msgs:?}");
    client.terminate();
}

#[test]
fn insert_literal_closing_paren_and_escaped_ident() {
    // Issue 7 + minor: a literal ')' value must insert, and a
    // double-quoted identifier with an escaped "" must work.
    let server = Server::start("insert-paren");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (id, name, city)");

    let msgs = client.query("INSERT INTO t VALUES (9, ')', 'Delhi')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    let msgs = client.query("SELECT * FROM t WHERE name = ')'");
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![
            Some("9".into()),
            Some(")".into()),
            Some("Delhi".into())
        ]],
        "{msgs:?}"
    );

    let msgs = client.query("CREATE TABLE \"a\"\"b\" (id, name)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );
    let msgs = client.query("INSERT INTO \"a\"\"b\" VALUES (1, 'x')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    let msgs = client.query("SELECT * FROM \"a\"\"b\"");
    assert_eq!(
        Client::rows(&msgs),
        vec![vec![Some("1".into()), Some("x".into())]],
        "{msgs:?}"
    );
    client.terminate();
}

#[test]
fn extended_parse_rejects_more_than_32767_params() {
    // Issue 8: a ParameterDescription count is an Int16, so 32768
    // parameters would wrap to -32768. Parse rejects them with
    // 54000; exactly 32767 still parses.
    let server = Server::start("ext-param-cap");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (id)");

    let over: String = (1..=32768)
        .map(|i| format!("id = ${i}"))
        .collect::<Vec<_>>()
        .join(" AND ");
    let msgs = client.extended(&[
        parse_frame("", &format!("SELECT * FROM t WHERE {over}"), &[]),
        sync_frame(),
    ]);
    assert_eq!(
        Client::error(&msgs).map(|(c, _)| c).as_deref(),
        Some("54000"),
        "32768 params must fail with 54000, not wrap: {msgs:?}"
    );

    let at_cap: String = (1..=32767)
        .map(|i| format!("id = ${i}"))
        .collect::<Vec<_>>()
        .join(" AND ");
    let msgs = client.extended(&[
        parse_frame("", &format!("SELECT * FROM t WHERE {at_cap}"), &[]),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::ParseComplete)),
        "32767 params must still parse: {msgs:?}"
    );
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    client.terminate();
}

/// Drive a SCRAM handshake only up to the server-first message and
/// return it (the `r=...,s=<salt>,i=...` string). The socket is
/// left open for the caller to close.
fn scram_server_first(client: &mut Client, user: &str, client_nonce: &str) -> String {
    client.stream.write_all(&startup_frame(user)).unwrap();
    client.stream.flush().unwrap();
    assert!(matches!(client.read_one(), Msg::AuthSasl(_)));
    let client_first_bare = format!("n={user},r={client_nonce}");
    client
        .stream
        .write_all(&sasl_initial_response(
            "SCRAM-SHA-256",
            format!("n,,{client_first_bare}").as_bytes(),
        ))
        .unwrap();
    client.stream.flush().unwrap();
    match client.read_one() {
        Msg::AuthSaslContinue(server_first) => server_first,
        other => panic!("expected AuthenticationSASLContinue, got: {other:?}"),
    }
}

fn server_first_salt(server_first: &str) -> String {
    server_first
        .split(',')
        .find_map(|p| p.strip_prefix("s=").map(str::to_string))
        .expect("server-first must carry s=<salt>")
}

#[test]
fn scram_fake_salt_is_deterministic_per_unknown_user() {
    // Issue 4, end to end: two handshakes for the same unknown
    // user must carry the SAME fake salt; a different unknown
    // user must get a different one.
    let server = Server::start("scram-fake-salt");
    set_password(&server.dir, "sanjay", "correct horse battery staple");

    let mut c1 = Client::connect_socket(server.port);
    let sf1 = scram_server_first(&mut c1, "ghost", "test-client-nonce-123");
    c1.terminate();
    let mut c2 = Client::connect_socket(server.port);
    let sf2 = scram_server_first(&mut c2, "ghost", "test-client-nonce-456");
    c2.terminate();
    let mut c3 = Client::connect_socket(server.port);
    let sf3 = scram_server_first(&mut c3, "ghost2", "test-client-nonce-123");
    c3.terminate();

    assert_eq!(
        server_first_salt(&sf1),
        server_first_salt(&sf2),
        "same unknown user must get the same fake salt: {sf1} vs {sf2}"
    );
    assert_ne!(
        server_first_salt(&sf1),
        server_first_salt(&sf3),
        "different unknown users must get different fake salts"
    );
}

#[test]
fn scram_nbsp_password_logs_in_with_saslprep_form() {
    // Issue 3, end to end: a password set with a NBSP (U+00A0)
    // must log in when the client sends the SASLprep'd form
    // ("pass word1"), because both sides SASLprep.
    let server = Server::start("scram-nbsp");
    set_password(&server.dir, "sanjay", "pass\u{a0}word1"); // NBSP between pass/word1

    let mut client = Client::connect_socket(server.port);
    let msgs = scram_login(&mut client, "sanjay", "pass word1");
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::AuthOk)),
        "SASLprep'd login must succeed: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn scram_client_first_strictness() {
    // Minors: a duplicate n=/r= in client-first is rejected, and
    // a 1-character client nonce is rejected — both with 08P01
    // and the connection closed.
    let server = Server::start("scram-strict");
    set_password(&server.dir, "sanjay", "correct horse battery staple");

    for first in [
        "n,,n=sanjay,r=AAA12345,n=ghost,r=BBB12345",
        "n,,n=sanjay,r=x",
    ] {
        let mut client = Client::connect_socket(server.port);
        client.stream.write_all(&startup_frame("sanjay")).unwrap();
        client.stream.flush().unwrap();
        assert!(matches!(client.read_one(), Msg::AuthSasl(_)));
        client
            .stream
            .write_all(&sasl_initial_response("SCRAM-SHA-256", first.as_bytes()))
            .unwrap();
        client.stream.flush().unwrap();
        match client.read_one() {
            Msg::ErrorResponse(code, _) => assert_eq!(code, "08P01", "{first}"),
            other => panic!("{first} must fail with 08P01, got: {other:?}"),
        }
        assert!(
            client.try_read_one().is_none(),
            "server must close the connection after a malformed client-first: {first}"
        );
        client.terminate();
    }
}

#[test]
fn set_password_on_missing_data_dir_succeeds() {
    // Minor: `user set-password` on a nonexistent data directory
    // used to fail with a cryptic "No such file or directory".
    // It now creates the directory and sets the password.
    let dir = std::env::temp_dir().join("zeno-pgwire-test-missing-dir/sub/dir");
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("zeno-pgwire-test-missing-dir"));
    let bin = env!("CARGO_BIN_EXE_zeno");
    // Password twice on stdin.
    let mut child = Command::new(bin)
        .args([
            "--data",
            dir.to_str().unwrap(),
            "user",
            "set-password",
            "u1",
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
    let output = child.wait_with_output().expect("wait zeno user");
    assert!(
        output.status.success(),
        "set-password on a missing data dir must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        dir.join("users.json").exists(),
        "users.json must exist after set-password"
    );
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join("zeno-pgwire-test-missing-dir"));
}

// ---------------------------------------------------------------------
// V0.5 tests: TLS, SCRAM rate limiting / lockout, connection limit.
// ---------------------------------------------------------------------

/// Run `zeno cert generate` in `dir` (asserts success).
fn generate_cert(dir: &std::path::Path) {
    let bin = env!("CARGO_BIN_EXE_zeno");
    let output = Command::new(bin)
        .args(["--data", dir.to_str().unwrap(), "cert", "generate"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run zeno cert generate");
    assert!(
        output.status.success(),
        "cert generate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Read one backend message from any `Read` (used for the TLS
/// stream, where the test-file `Client`'s TcpStream framing does
/// not apply).
fn read_msg_from(stream: &mut impl Read) -> Msg {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).expect("read message tag");
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .expect("read message length");
    let len = i32::from_be_bytes(len_buf);
    assert!(len >= 4, "message length {len} is too small");
    let mut body = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut body).expect("read message body");
    parse_message(tag[0], &body)
}

/// Read backend messages until ReadyForQuery (inclusive).
fn read_until_ready_from(stream: &mut impl Read) -> Vec<Msg> {
    let mut msgs = Vec::new();
    loop {
        let msg = read_msg_from(stream);
        let ready = matches!(msg, Msg::ReadyForQuery(_));
        msgs.push(msg);
        if ready {
            return msgs;
        }
    }
}

/// Drive a SCRAM login and return the message that follows the
/// client-final: AuthSaslFinal on success, ErrorResponse (28P01)
/// on failure. Unlike `scram_login` this does NOT panic on
/// failure, so the rate-limit tests can assert on it.
fn scram_login_outcome(client: &mut Client, user: &str, password: &str) -> Msg {
    client.stream.write_all(&startup_frame(user)).unwrap();
    client.stream.flush().unwrap();
    let first = client.read_one();
    assert!(
        matches!(first, Msg::AuthSasl(_)),
        "expected a SASL offer, got: {first:?}"
    );
    let client_nonce = "test-client-nonce-123";
    let client_first_bare = format!("n={user},r={client_nonce}");
    client
        .stream
        .write_all(&sasl_initial_response(
            "SCRAM-SHA-256",
            format!("n,,{client_first_bare}").as_bytes(),
        ))
        .unwrap();
    client.stream.flush().unwrap();
    let second = client.read_one();
    let Msg::AuthSaslContinue(server_first) = second else {
        panic!("expected AuthenticationSASLContinue, got: {second:?}");
    };
    let (client_final, _) =
        zeno::auth::scram_client_response(password, &client_first_bare, &server_first).unwrap();
    client
        .stream
        .write_all(&sasl_response(client_final.as_bytes()))
        .unwrap();
    client.stream.flush().unwrap();
    client.read_one()
}

#[test]
fn tls_handshake_then_query_works() {
    // A real TLS client (rustls, trusting exactly the generated
    // self-signed cert) speaks the whole protocol inside the
    // encrypted stream: SSLRequest -> 'S' -> TLS handshake ->
    // startup -> CREATE / INSERT / SELECT.
    let dir = tmp_dir("tls-ok");
    generate_cert(&dir);
    let server = Server::start_with_args_on_dir(dir.clone(), &["--tls"]);

    let mut sock = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    sock.write_all(&8i32.to_be_bytes()).unwrap();
    sock.write_all(&80877103i32.to_be_bytes()).unwrap();
    sock.flush().unwrap();
    let mut answer = [0u8; 1];
    sock.read_exact(&mut answer).unwrap();
    assert_eq!(
        answer,
        [b'S'],
        "with --tls the server must answer SSLRequest with 'S'"
    );

    let cert_pem = std::fs::read(dir.join("server-cert.pem")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);

    tls.write_all(&startup_frame("zeno")).unwrap();
    tls.flush().unwrap();
    let msgs = read_until_ready_from(&mut tls);
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::AuthOk)),
        "TLS handshake must end with AuthenticationOk: {msgs:?}"
    );

    let mut frame = Vec::new();
    let sql = "CREATE TABLE t (a)";
    frame.push(b'Q');
    frame.extend_from_slice(&((sql.len() + 1 + 4) as i32).to_be_bytes());
    frame.extend_from_slice(sql.as_bytes());
    frame.push(0);
    tls.write_all(&frame).unwrap();
    tls.flush().unwrap();
    let msgs = read_until_ready_from(&mut tls);
    assert_eq!(
        msgs.iter()
            .find_map(|m| match m {
                Msg::CommandComplete(t) => Some(t.clone()),
                _ => None,
            })
            .as_deref(),
        Some("CREATE TABLE"),
        "query over TLS must work: {msgs:?}"
    );
    let mut frame = Vec::new();
    let sql = "INSERT INTO t VALUES ('tls-works')";
    frame.push(b'Q');
    frame.extend_from_slice(&((sql.len() + 1 + 4) as i32).to_be_bytes());
    frame.extend_from_slice(sql.as_bytes());
    frame.push(0);
    tls.write_all(&frame).unwrap();
    tls.flush().unwrap();
    let msgs = read_until_ready_from(&mut tls);
    assert!(
        msgs.iter()
            .any(|m| matches!(m, Msg::CommandComplete(t) if t == "INSERT 0 1")),
        "insert over TLS must work: {msgs:?}"
    );
    // m7: after Terminate the server must close TLS cleanly with
    // `close_notify`, so the client reads a clean EOF (0 bytes)
    // instead of a truncated connection.
    tls.write_all(&[b'X', 0, 0, 0, 4]).unwrap();
    tls.flush().unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(
        tls.read(&mut buf).unwrap(),
        0,
        "the server must end the TLS session with close_notify (clean EOF)"
    );
}

#[test]
fn tls_server_rejects_plaintext_startup_with_08p01() {
    // M1: `--tls` means TLS is REQUIRED. A plain StartupMessage
    // (no SSLRequest first) must be refused with ErrorResponse
    // 08P01 — the old code completed the whole handshake in
    // plaintext even on a --tls server.
    let dir = tmp_dir("tls-plain-reject");
    generate_cert(&dir);
    let server = Server::start_with_args_on_dir(dir, &["--tls"]);
    let mut client = Client::connect_socket(server.port);
    client.stream.write_all(&startup_frame("zeno")).unwrap();
    client.stream.flush().unwrap();
    match client.try_read_one() {
        Some(Msg::ErrorResponse(code, _)) => assert_eq!(
            code, "08P01",
            "a plaintext startup on a --tls server must be refused with 08P01"
        ),
        other => panic!("expected an 08P01 ErrorResponse, got: {other:?}"),
    }
    assert!(
        client.try_read_one().is_none(),
        "the server must close the connection after refusing a plaintext startup"
    );
}

#[test]
fn tls_server_without_cert_refuses_to_start() {
    let dir = tmp_dir("tls-nocert");
    let bin = env!("CARGO_BIN_EXE_zeno");
    let output = Command::new(bin)
        .args([
            "--data",
            dir.to_str().unwrap(),
            "serve",
            "--port",
            &free_port().to_string(),
            "--tls",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run server");
    assert!(
        !output.status.success(),
        "serve --tls without a certificate must fail to start"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cert generate"),
        "the error must point at `cert generate`, got: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scram_rate_limit_locks_after_five_failures() {
    let server = Server::start("scram-ratelimit");
    set_password(&server.dir, "sanjay", "correct horse battery staple");
    set_password(&server.dir, "asha", "another password here");

    // 5 wrong passwords for sanjay: each is a full SCRAM exchange
    // ending in 28P01 (each waits the constant 2 s failure delay
    // server-side — see `scram_failure_delay_is_constant_*`).
    for attempt in 1..=5 {
        let mut client = Client::connect_socket(server.port);
        let outcome = scram_login_outcome(&mut client, "sanjay", "wrong password");
        match &outcome {
            Msg::ErrorResponse(code, _) => assert_eq!(
                code, "28P01",
                "attempt {attempt} must be 28P01, got: {outcome:?}"
            ),
            other => panic!("attempt {attempt}: expected 28P01, got: {other:?}"),
        }
        assert!(
            client.try_read_one().is_none(),
            "the server must close the connection after a failed login"
        );
    }
    // 6th attempt, now with the CORRECT password: still 28P01 —
    // the account is locked out for 5 minutes.
    let mut client = Client::connect_socket(server.port);
    let outcome = scram_login_outcome(&mut client, "sanjay", "correct horse battery staple");
    match &outcome {
        Msg::ErrorResponse(code, _) => assert_eq!(
            code, "28P01",
            "a locked-out login must still be 28P01, got: {outcome:?}"
        ),
        other => panic!("locked-out login with the right password must fail, got: {other:?}"),
    }
    // A different user is NOT locked: asha logs in fine.
    let mut client = Client::connect_socket(server.port);
    let msgs = scram_login(&mut client, "asha", "another password here");
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::AuthOk)),
        "another user must still log in: {msgs:?}"
    );
    client.terminate();
}

#[test]
fn scram_rate_limit_unknown_user_gets_same_response() {
    // An unknown user gets the same response shape before AND
    // after the lockout trips: full server-first (fake salt),
    // then 28P01 — so the lockout leaks nothing about whether
    // the username exists.
    let server = Server::start("scram-ratelimit-ghost");
    set_password(&server.dir, "sanjay", "correct horse battery staple");
    for attempt in 1..=6 {
        let mut client = Client::connect_socket(server.port);
        let outcome = scram_login_outcome(&mut client, "ghost", "whatever");
        match &outcome {
            Msg::ErrorResponse(code, _) => assert_eq!(
                code, "28P01",
                "attempt {attempt} for an unknown user must be 28P01, got: {outcome:?}"
            ),
            other => panic!("attempt {attempt}: expected 28P01, got: {other:?}"),
        }
        assert!(client.try_read_one().is_none());
    }
}

#[test]
fn scram_failure_delay_is_constant_for_fresh_and_locked_logins() {
    // M3: a FRESH wrong password and a LOCKED-OUT correct password
    // must take the SAME time (the constant 2 s failure delay).
    // The old progressive delay made the 1st failure take 0.1 s
    // and a locked login 2.0 s — measurable, so the timing alone
    // revealed whether an account was locked. The bounds below
    // are loose (parallel tests load the machine), but the old
    // 0.1 s fresh failure cannot pass the 1.5 s lower bound.
    let server = Server::start("scram-timing");
    set_password(&server.dir, "victim", "correct horse battery staple");
    set_password(&server.dir, "fresh", "another password here");

    // A FRESH wrong password (1st failure for this user@IP).
    let mut client = Client::connect_socket(server.port);
    let start = std::time::Instant::now();
    let outcome = scram_login_outcome(&mut client, "fresh", "wrong password");
    let fresh_elapsed = start.elapsed();
    match &outcome {
        Msg::ErrorResponse(code, _) => assert_eq!(
            code, "28P01",
            "a fresh wrong password must be 28P01, got: {outcome:?}"
        ),
        other => panic!("a fresh wrong password must be 28P01, got: {other:?}"),
    }
    assert!(client.try_read_one().is_none());

    // Lock "victim" with 5 wrong passwords.
    for attempt in 1..=5 {
        let mut client = Client::connect_socket(server.port);
        let outcome = scram_login_outcome(&mut client, "victim", "wrong password");
        match &outcome {
            Msg::ErrorResponse(code, _) => assert_eq!(
                code, "28P01",
                "attempt {attempt} must be 28P01, got: {outcome:?}"
            ),
            other => panic!("attempt {attempt}: expected 28P01, got: {other:?}"),
        }
        assert!(client.try_read_one().is_none());
    }
    // The LOCKED login, with the CORRECT password: still 28P01.
    let mut client = Client::connect_socket(server.port);
    let start = std::time::Instant::now();
    let outcome = scram_login_outcome(&mut client, "victim", "correct horse battery staple");
    let locked_elapsed = start.elapsed();
    match &outcome {
        Msg::ErrorResponse(code, _) => assert_eq!(
            code, "28P01",
            "a locked-out login must still be 28P01, got: {outcome:?}"
        ),
        other => panic!("a locked-out login with the right password must fail, got: {other:?}"),
    }
    assert!(client.try_read_one().is_none());

    assert!(
        fresh_elapsed >= Duration::from_millis(1500),
        "a fresh failure must wait the constant delay, took {fresh_elapsed:?}"
    );
    assert!(
        locked_elapsed >= Duration::from_millis(1500),
        "a locked-out login must wait the constant delay, took {locked_elapsed:?}"
    );
    assert!(
        fresh_elapsed < Duration::from_secs(6),
        "a fresh failure took suspiciously long: {fresh_elapsed:?}"
    );
    assert!(
        locked_elapsed < Duration::from_secs(6),
        "a locked-out login took suspiciously long: {locked_elapsed:?}"
    );
    let diff = fresh_elapsed.abs_diff(locked_elapsed);
    assert!(
        diff < Duration::from_secs(2),
        "fresh ({fresh_elapsed:?}) and locked ({locked_elapsed:?}) logins must take about the same time, diff {diff:?}"
    );
}

/// Try a plain startup handshake; true only if it ends in
/// ReadyForQuery (i.e. the server had a free connection slot).
fn try_connect(port: u16) -> bool {
    let Ok(mut sock) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
    if sock.write_all(&startup_frame("zeno")).is_err() {
        return false;
    }
    let _ = sock.flush();
    let mut reader = BufReader::new(sock.try_clone().unwrap());
    loop {
        let mut tag = [0u8; 1];
        if reader.read_exact(&mut tag).is_err() {
            return false;
        }
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).is_err() {
            return false;
        }
        let len = i32::from_be_bytes(len_buf);
        if len < 4 {
            return false;
        }
        let mut body = vec![0u8; (len - 4) as usize];
        if reader.read_exact(&mut body).is_err() {
            return false;
        }
        match tag[0] {
            b'Z' => return true,
            b'E' => return false,
            _ => {}
        }
    }
}

#[test]
fn connection_limit_rejects_over_limit_with_53300() {
    let server = Server::start_with_args("connlimit", &["--max-connections", "2"]);
    // Give the start-up probe connection a moment to be reaped,
    // so it cannot steal one of the two slots below.
    std::thread::sleep(Duration::from_millis(300));
    // Two IDLE connections (handshake done, no queries) hold both slots.
    let (mut c1, _) = Client::connect(server.port);
    let (c2, _) = Client::connect(server.port);
    // A third connection gets ErrorResponse 53300 instead of a handshake.
    let mut sock = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).unwrap();
    assert_eq!(
        tag,
        [b'E'],
        "an over-limit connection must get ErrorResponse, not a handshake"
    );
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).unwrap();
    let len = i32::from_be_bytes(len_buf);
    let mut body = vec![0u8; (len - 4) as usize];
    sock.read_exact(&mut body).unwrap();
    match parse_message(b'E', &body) {
        Msg::ErrorResponse(code, _) => assert_eq!(code, "53300", "must be 53300"),
        other => panic!("expected a 53300 ErrorResponse, got: {other:?}"),
    }
    drop(sock);
    // The server is still alive and serving the idle connections.
    let msgs = c1.query("CREATE TABLE t (a)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );
    // Free a slot: closing c2 lets a new connection in.
    c2.terminate();
    let mut connected = false;
    for _ in 0..20 {
        if try_connect(server.port) {
            connected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        connected,
        "a new connection must succeed after a slot frees up"
    );
    c1.terminate();
}

#[test]
fn connection_limit_ssl_request_gets_n_then_53300() {
    // m6: an over-limit client that starts with SSLRequest (what
    // libpq sends by default) must first get a valid 'N'
    // negotiation answer, THEN the 53300 ErrorResponse. The old
    // code sent the ErrorResponse straight away, so libpq read
    // 'E' where it expected 'S'/'N' — a broken negotiation
    // instead of a clean "too many connections".
    let server = Server::start_with_args("connlimit-ssl", &["--max-connections", "2"]);
    // Give the start-up probe connection a moment to be reaped,
    // so it cannot steal one of the two slots below.
    std::thread::sleep(Duration::from_millis(300));
    // Two IDLE connections (handshake done, no queries) hold both slots.
    let (mut c1, _) = Client::connect(server.port);
    let (c2, _) = Client::connect(server.port);
    // A third connection, starting with SSLRequest.
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&ssl_request_bytes()).unwrap();
    stream.flush().unwrap();
    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer).unwrap();
    assert_eq!(
        answer,
        [b'N'],
        "an over-limit SSLRequest must still be answered 'N' first"
    );
    let mut client = Client {
        stream: stream.try_clone().unwrap(),
        reader: BufReader::new(stream),
    };
    match client.try_read_one() {
        Some(Msg::ErrorResponse(code, _)) => assert_eq!(
            code, "53300",
            "the over-limit connection must then get ErrorResponse 53300"
        ),
        other => panic!("expected a 53300 ErrorResponse after 'N', got: {other:?}"),
    }
    assert!(
        client.try_read_one().is_none(),
        "the server must close the refused connection"
    );
    // The server is still alive and serving the idle connections.
    let msgs = c1.query("CREATE TABLE t (a)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );
    c2.terminate();
    c1.terminate();
}

// ---------------------------------------------------------------------
// V0.6 tests: MVCC transactions over the wire protocol.
// ---------------------------------------------------------------------

/// ReadyForQuery 'T' means "in a transaction", 'I' means idle.
fn ready_status(msgs: &[Msg]) -> u8 {
    match msgs.last() {
        Some(Msg::ReadyForQuery(status)) => *status,
        other => panic!("last message must be ReadyForQuery, got {other:?} in {msgs:?}"),
    }
}

#[test]
fn txn_snapshot_isolation_two_connections() {
    let server = Server::start("txn-isolation");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    a.query("INSERT INTO users VALUES (1, 'Delhi')");

    // A begins: ReadyForQuery turns 'T'. Its INSERT is visible to
    // A itself, invisible to B.
    let msgs = a.query("BEGIN");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("BEGIN"), "{msgs:?}");
    assert_eq!(ready_status(&msgs), b'T', "BEGIN must report status 'T'");
    a.query("INSERT INTO users VALUES (2, 'Mumbai')");
    assert_eq!(Client::rows(&a.query("SELECT * FROM users")).len(), 2);
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM users")).len(),
        1,
        "B must not see A's uncommitted row"
    );

    // A commits: ReadyForQuery back to 'I', and B sees both rows.
    let msgs = a.query("COMMIT");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("COMMIT"), "{msgs:?}");
    assert_eq!(ready_status(&msgs), b'I', "COMMIT must report status 'I'");
    assert_eq!(Client::rows(&b.query("SELECT * FROM users")).len(), 2);
    a.terminate();
    b.terminate();
}

#[test]
fn txn_rollback_hides_writes() {
    let server = Server::start("txn-rollback");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    a.query("INSERT INTO users VALUES (1, 'Delhi')");
    a.query("BEGIN");
    a.query("INSERT INTO users VALUES (2, 'Mumbai')");
    a.query("DELETE FROM users WHERE id = 1");
    assert_eq!(
        Client::rows(&a.query("SELECT * FROM users")).len(),
        1,
        "inside the txn the delete + insert apply"
    );
    let msgs = a.query("ROLLBACK");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("ROLLBACK"), "{msgs:?}");
    assert_eq!(ready_status(&msgs), b'I');
    // Both writes are gone: the original row is back, the new one never was.
    assert_eq!(Client::rows(&a.query("SELECT * FROM users")).len(), 1);
    assert_eq!(Client::rows(&b.query("SELECT * FROM users")).len(), 1);
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM users"))[0][1],
        Some("Delhi".to_string())
    );
    a.terminate();
    b.terminate();
}

#[test]
fn txn_update_visible_only_after_commit() {
    let server = Server::start("txn-update");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    a.query("INSERT INTO users VALUES (1, 'Delhi')");
    a.query("BEGIN");
    let msgs = a.query("UPDATE users SET city = 'Mumbai' WHERE id = 1");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("UPDATE 1"), "{msgs:?}");
    assert_eq!(
        Client::rows(&a.query("SELECT * FROM users"))[0][1],
        Some("Mumbai".to_string()),
        "own UPDATE must be visible inside the txn"
    );
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM users"))[0][1],
        Some("Delhi".to_string()),
        "uncommitted UPDATE must be invisible to others"
    );
    a.query("COMMIT");
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM users"))[0][1],
        Some("Mumbai".to_string()),
        "committed UPDATE must become visible"
    );
    // UPDATE with no matching row: UPDATE 0, no error.
    let msgs = a.query("UPDATE users SET city = 'X' WHERE id = 99");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("UPDATE 0"), "{msgs:?}");
    // UPDATE on an unknown column: 42703.
    let msgs = a.query("UPDATE users SET nope = 'X' WHERE id = 1");
    let (code, _) = Client::error(&msgs).expect("unknown SET column must error");
    assert_eq!(code, "42703", "{msgs:?}");
    a.terminate();
    b.terminate();
}

#[test]
fn txn_write_write_conflict_returns_40001() {
    let server = Server::start("txn-conflict");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    a.query("INSERT INTO users VALUES (1, 'Delhi')");
    // Both connections begin on the same snapshot and UPDATE the
    // same row: first-committer-wins.
    a.query("BEGIN");
    b.query("BEGIN");
    a.query("UPDATE users SET city = 'Mumbai' WHERE id = 1");
    b.query("UPDATE users SET city = 'Jaipur' WHERE id = 1");
    let msgs = a.query("COMMIT");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("COMMIT"), "{msgs:?}");
    let msgs = b.query("COMMIT");
    let (code, message) = Client::error(&msgs).expect("losing COMMIT must error");
    assert_eq!(
        code, "40001",
        "write-write conflict must be 40001: {message}"
    );
    // The loser's transaction is already aborted: the connection
    // is idle again ('I') and can BEGIN anew.
    assert_eq!(
        ready_status(&msgs),
        b'I',
        "after 40001 the txn is gone: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM users"))[0][1],
        Some("Mumbai".to_string()),
        "the winner's value must stand, the loser's must be gone"
    );
    // And B can start a fresh transaction right away.
    let msgs = b.query("BEGIN");
    assert_eq!(ready_status(&msgs), b'T');
    b.query("ROLLBACK");
    a.terminate();
    b.terminate();
}

#[test]
fn txn_errors_without_transaction_and_ddl_inside() {
    let server = Server::start("txn-errors");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, city)");
    // COMMIT / ROLLBACK with no transaction: 25P01.
    let msgs = client.query("COMMIT");
    let (code, _) = Client::error(&msgs).expect("COMMIT without txn must error");
    assert_eq!(code, "25P01", "{msgs:?}");
    let msgs = client.query("ROLLBACK");
    let (code, _) = Client::error(&msgs).expect("ROLLBACK without txn must error");
    assert_eq!(code, "25P01", "{msgs:?}");
    // A second BEGIN while one is open: 25001.
    client.query("BEGIN");
    let msgs = client.query("BEGIN");
    let (code, _) = Client::error(&msgs).expect("nested BEGIN must error");
    assert_eq!(code, "25001", "{msgs:?}");
    // DDL inside a transaction: 0A000 — and the transaction is
    // still open afterwards (the failed statement did not kill it).
    let msgs = client.query("CREATE TABLE other (id)");
    let (code, _) = Client::error(&msgs).expect("DDL inside txn must error");
    assert_eq!(code, "0A000", "{msgs:?}");
    assert_eq!(
        ready_status(&msgs),
        b'T',
        "txn must survive the failed DDL: {msgs:?}"
    );
    // Clean up: the failed CREATE left no table behind.
    client.query("ROLLBACK");
    let msgs = client.query("SELECT * FROM other");
    let (code, _) = Client::error(&msgs).expect("other must not exist");
    assert_eq!(code, "42P01", "{msgs:?}");
    client.terminate();
}

#[test]
fn txn_multi_statement_simple_query() {
    // BEGIN / INSERT / COMMIT in ONE Simple Query message: the
    // session is threaded through every statement in the batch.
    let server = Server::start("txn-multi");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    let msgs = a.query("BEGIN; INSERT INTO users VALUES (1, 'Delhi'); COMMIT;");
    assert!(
        msgs.iter()
            .any(|m| matches!(m, Msg::CommandComplete(t) if t == "COMMIT")),
        "the batch must run BEGIN + INSERT + COMMIT: {msgs:?}"
    );
    assert_eq!(ready_status(&msgs), b'I');
    assert_eq!(Client::rows(&b.query("SELECT * FROM users")).len(), 1);
    // And a ROLLBACK batch leaves nothing behind.
    a.query("BEGIN; INSERT INTO users VALUES (2, 'Mumbai'); ROLLBACK;");
    assert_eq!(Client::rows(&b.query("SELECT * FROM users")).len(), 1);
    a.terminate();
    b.terminate();
}

#[test]
fn txn_extended_protocol_begin_commit() {
    // BEGIN / INSERT ($1 parameter) / COMMIT over the extended
    // protocol, then visibility from a second connection.
    let server = Server::start("txn-extended");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    // Parse + Bind + Execute + Sync: Parse alone only validates,
    // the statement runs at Execute.
    let msgs = a.extended(&[
        parse_frame("", "BEGIN", &[]),
        bind_frame("", "", &[], &[], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert!(
        Client::error(&msgs).is_none(),
        "BEGIN over extended protocol must work: {msgs:?}"
    );
    assert_eq!(ready_status(&msgs), b'T');
    // INSERT with a bound parameter, inside the transaction.
    let msgs = a.extended(&[
        parse_frame("", "INSERT INTO users VALUES ($1, $2)", &[]),
        bind_frame("", "", &[], &[text_param("7"), text_param("Pune")], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM users")).len(),
        0,
        "B must not see the uncommitted extended-protocol INSERT"
    );
    // A SELECT over the extended protocol inside the txn sees it.
    let msgs = a.extended(&[
        parse_frame("", "SELECT * FROM users", &[]),
        bind_frame("", "", &[], &[], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert_eq!(Client::rows(&msgs).len(), 1, "{msgs:?}");
    let msgs = a.extended(&[
        parse_frame("", "COMMIT", &[]),
        bind_frame("", "", &[], &[], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    assert_eq!(ready_status(&msgs), b'I');
    assert_eq!(Client::rows(&b.query("SELECT * FROM users")).len(), 1);
    a.terminate();
    b.terminate();
}

#[test]
fn txn_disconnect_rolls_back() {
    // A connection that goes away with a transaction open
    // abandons it: the uncommitted row never becomes visible.
    let server = Server::start("txn-disconnect");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    a.query("BEGIN");
    a.query("INSERT INTO users VALUES (1, 'Delhi')");
    a.terminate(); // no COMMIT — the server must roll back
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM users")).len(),
        0,
        "a disconnected transaction must roll back"
    );
    b.terminate();
}

#[test]
fn txn_crash_recovery_only_committed_data_survives() {
    // Kill -9 the server with a transaction still open (and one
    // committed row): after restart only the committed row is
    // there. This is the crash test — the server process is
    // killed, not shut down cleanly.
    let server = Server::start("txn-crash");
    let (mut a, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    a.query("INSERT INTO users VALUES (1, 'Delhi')");
    a.query("BEGIN");
    a.query("INSERT INTO users VALUES (2, 'Mumbai')");
    // Kill the server mid-transaction (no COMMIT, no clean exit).
    let dir = server.stop_keep_dir();
    let server2 = Server::start_with_args_on_dir(dir, &[]);
    let (mut b, _) = Client::connect(server2.port);
    let rows = Client::rows(&b.query("SELECT * FROM users"));
    assert_eq!(
        rows.len(),
        1,
        "only the committed row may survive: {rows:?}"
    );
    assert_eq!(rows[0][1], Some("Delhi".to_string()));
    // The server still works after the restart.
    b.query("INSERT INTO users VALUES (3, 'Jaipur')");
    assert_eq!(Client::rows(&b.query("SELECT * FROM users")).len(), 2);
    b.terminate();
}

#[test]
fn txn_aborted_state_returns_25p02_until_rollback() {
    // M2: a failed statement inside a transaction aborts it
    // (PostgreSQL 25P02). Afterwards only ROLLBACK runs; SELECT,
    // INSERT and COMMIT all fail with 25P02, the transaction
    // reports status 'E', and nothing it wrote commits.
    let server = Server::start("txn-aborted");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE t (id, city)");
    a.query("INSERT INTO t VALUES (1, 'Delhi')");
    a.query("BEGIN");
    let msgs = a.query("INSERT INTO nosuch VALUES (9, 'X')");
    let (code, _) = Client::error(&msgs).expect("bad INSERT must error");
    assert_eq!(code, "42P01", "{msgs:?}");
    assert_eq!(
        ready_status(&msgs),
        b'E',
        "an aborted transaction reports status 'E': {msgs:?}"
    );
    for sql in [
        "SELECT * FROM t",
        "INSERT INTO t VALUES (4, 'Pune')",
        "COMMIT",
    ] {
        let msgs = a.query(sql);
        let (code, _) = Client::error(&msgs).expect("aborted txn must error");
        assert_eq!(
            code, "25P02",
            "{sql} in an aborted txn must be 25P02: {msgs:?}"
        );
    }
    // ROLLBACK is the only way out — and it works.
    let msgs = a.query("ROLLBACK");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("ROLLBACK"), "{msgs:?}");
    assert_eq!(ready_status(&msgs), b'I');
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM t")).len(),
        1,
        "nothing from the aborted transaction may commit"
    );
    // A fresh transaction works again right away.
    a.query("BEGIN");
    a.query("INSERT INTO t VALUES (2, 'Mumbai')");
    a.query("COMMIT");
    assert_eq!(Client::rows(&b.query("SELECT * FROM t")).len(), 2);
    // Multi-statement batch: a bad middle statement aborts the
    // batch's transaction, so the later INSERT and COMMIT fail
    // and row 5 never lands.
    a.query(
        "BEGIN; INSERT INTO nosuch VALUES (1, 'x'); INSERT INTO t VALUES (5, 'Indore'); COMMIT",
    );
    a.query("ROLLBACK");
    assert!(
        !Client::rows(&b.query("SELECT * FROM t"))
            .iter()
            .any(|r| r[0] == Some("5".to_string())),
        "row 5 must not land from an aborted multi-statement batch"
    );
    a.terminate();
    b.terminate();
}

#[test]
fn portal_cache_dies_with_transaction() {
    // B2: a portal bound inside a transaction must not serve
    // its cached rows after that transaction ends — its cache
    // can hold rows that never committed (ROLLBACK) or that
    // belong to a snapshot that no longer exists (COMMIT).
    let server = Server::start("portal-txn-end");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE t (id, city)");
    a.query("INSERT INTO t VALUES (1, 'Delhi')");

    // ROLLBACK case: suspend a SELECT portal inside the txn,
    // roll back, then resume the same portal.
    a.query("BEGIN");
    a.query("INSERT INTO t VALUES (7, 'Bhopal')");
    let msgs = a.extended(&[
        parse_frame("sel", "SELECT * FROM t", &[]),
        bind_frame("selp", "sel", &[], &[], &[]),
        execute_frame("selp", 1),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::PortalSuspended)),
        "first Execute must suspend: {msgs:?}"
    );
    a.query("ROLLBACK");
    let msgs = a.extended(&[execute_frame("selp", 0), sync_frame()]);
    let (code, _) = Client::error(&msgs).expect("resuming a dead portal must error");
    assert_eq!(
        code, "26000",
        "a portal closed at ROLLBACK must be gone: {msgs:?}"
    );
    assert!(
        !Client::rows(&msgs)
            .iter()
            .any(|r| r[0] == Some("7".to_string())),
        "the rolled-back row must never come back: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM t")).len(),
        1,
        "row 7 is gone for everyone"
    );

    // COMMIT case: suspend inside the txn, COMMIT via Simple
    // Query (which closes all portals), then resume.
    a.query("BEGIN");
    a.query("INSERT INTO t VALUES (8, 'Patna')");
    let msgs = a.extended(&[
        parse_frame("sel2", "SELECT * FROM t", &[]),
        bind_frame("selp2", "sel2", &[], &[], &[]),
        execute_frame("selp2", 1),
        sync_frame(),
    ]);
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::PortalSuspended)),
        "first Execute must suspend: {msgs:?}"
    );
    a.query("COMMIT");
    let msgs = a.extended(&[execute_frame("selp2", 0), sync_frame()]);
    let (code, _) = Client::error(&msgs).expect("resuming a dead portal must error");
    assert_eq!(
        code, "26000",
        "a portal closed at COMMIT must be gone: {msgs:?}"
    );
    // The committed row itself is visible through a fresh query.
    assert!(
        Client::rows(&b.query("SELECT * FROM t"))
            .iter()
            .any(|r| r[0] == Some("8".to_string())),
        "row 8 committed and is visible normally"
    );
    a.terminate();
    b.terminate();
}

#[test]
fn ddl_created_after_begin_is_invisible_in_txn() {
    // m1: a table created by another connection AFTER this
    // transaction began is invisible inside it (42P01) — the
    // transaction only sees the tables that existed at BEGIN.
    let server = Server::start("ddl-snapshot");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE t (id, city)");
    a.query("BEGIN");
    b.query("CREATE TABLE late (id, x)");
    let msgs = a.query("INSERT INTO late VALUES (1, 'y')");
    let (code, _) = Client::error(&msgs).expect("INSERT into a later table must error");
    assert_eq!(code, "42P01", "{msgs:?}");
    a.query("ROLLBACK");
    // Outside the transaction the table is there, as normal.
    b.query("INSERT INTO late VALUES (1, 'y')");
    assert_eq!(Client::rows(&b.query("SELECT * FROM late")).len(), 1);
    a.terminate();
    b.terminate();
}

#[test]
fn txn_idle_timeout_rolls_back() {
    // m5: a transaction that executes no statement for longer
    // than the idle timeout is rolled back automatically, so an
    // abandoned transaction cannot pin its snapshot forever.
    // The timeout is 1s here via the diagnostic env var (the
    // default is 5 minutes).
    std::env::set_var("ZENO_TXN_IDLE_TIMEOUT_SECS", "1");
    let server = Server::start("txn-idle-timeout");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE t (id, city)");
    a.query("BEGIN");
    a.query("INSERT INTO t VALUES (1, 'Delhi')");
    std::thread::sleep(Duration::from_millis(1500));
    let msgs = a.query("SELECT * FROM t");
    let (code, _) = Client::error(&msgs).expect("an idle-timed-out txn must error");
    assert_eq!(code, "57014", "idle timeout must be 57014: {msgs:?}");
    assert_eq!(
        ready_status(&msgs),
        b'I',
        "the timed-out txn is gone: {msgs:?}"
    );
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM t")).len(),
        0,
        "the timed-out transaction's row must be rolled back"
    );
    // And the connection can BEGIN again right away.
    let msgs = a.query("BEGIN");
    assert_eq!(ready_status(&msgs), b'T');
    a.query("ROLLBACK");
    std::env::remove_var("ZENO_TXN_IDLE_TIMEOUT_SECS");
    a.terminate();
    b.terminate();
}

#[test]
fn vacuum_sql_prunes_versions_and_keeps_live_snapshot() {
    // M5: VACUUM runs while the server is live, prunes old row
    // versions, and never disturbs a live snapshot.
    let server = Server::start("vacuum-sql");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE t (id, city)");
    a.query("INSERT INTO t VALUES (1, 'Delhi')");
    for city in ["Mumbai", "Goa", "Pune", "Agra"] {
        a.query(&format!("UPDATE t SET city = '{city}' WHERE id = 1"));
    }
    let msgs = a.query("VACUUM");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("VACUUM"), "{msgs:?}");
    assert_eq!(
        Client::rows(&a.query("SELECT * FROM t"))[0][1],
        Some("Agra".to_string()),
        "the newest value must survive VACUUM"
    );
    // VACUUM inside a transaction is refused.
    a.query("BEGIN");
    let msgs = a.query("VACUUM");
    let (code, _) = Client::error(&msgs).expect("VACUUM in a txn must error");
    assert_eq!(code, "25001", "{msgs:?}");
    a.query("ROLLBACK");
    // A live snapshot still sees its own old version after a
    // VACUUM run by another connection.
    a.query("BEGIN");
    assert_eq!(
        Client::rows(&a.query("SELECT * FROM t"))[0][1],
        Some("Agra".to_string())
    );
    b.query("UPDATE t SET city = 'Nagpur' WHERE id = 1");
    let msgs = b.query("VACUUM");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("VACUUM"), "{msgs:?}");
    assert_eq!(
        Client::rows(&a.query("SELECT * FROM t"))[0][1],
        Some("Agra".to_string()),
        "the live snapshot must still see Agra after VACUUM"
    );
    assert_eq!(
        Client::rows(&b.query("SELECT * FROM t"))[0][1],
        Some("Nagpur".to_string()),
        "the new value is visible outside the snapshot"
    );
    a.query("ROLLBACK");
    a.terminate();
    b.terminate();
}

// ---------------------------------------------------------------------
// V0.7 tests: savepoints, the real SQL parser, auto-vacuum flags.
// ---------------------------------------------------------------------

/// Seed the four-row users table every parser test uses, and
/// return the row count afterwards.
fn seed_users_four(client: &mut Client) {
    client.query("CREATE TABLE users (id, name, city)");
    client.query("INSERT INTO users VALUES (1, 'Sanjay', 'Delhi')");
    client.query("INSERT INTO users VALUES (2, 'Asha', 'Mumbai')");
    client.query("INSERT INTO users VALUES (3, 'Ravi', 'Delhi')");
    client.query("INSERT INTO users VALUES (4, 'Meera', 'Pune')");
}

#[test]
fn savepoint_rollback_keeps_earlier_writes_drops_later_ones() {
    let server = Server::start("savepoint-rollback");
    let (mut a, _) = Client::connect(server.port);
    let (mut b, _) = Client::connect(server.port);
    a.query("CREATE TABLE users (id, city)");
    a.query("INSERT INTO users VALUES (1, 'Delhi')");

    a.query("BEGIN");
    a.query("INSERT INTO users VALUES (2, 'Mumbai')");
    let msgs = a.query("SAVEPOINT sp1");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SAVEPOINT"), "{msgs:?}");
    assert_eq!(
        ready_status(&msgs),
        b'T',
        "savepoint must keep the txn open"
    );
    a.query("INSERT INTO users VALUES (3, 'Jaipur')");
    a.query("UPDATE users SET city = 'Agra' WHERE id = 1");
    assert_eq!(
        Client::rows(&a.query("SELECT * FROM users")).len(),
        3,
        "inside the txn all three rows are visible"
    );
    // Roll back to the savepoint: row 3 and the Agra update go,
    // rows 1 (Delhi) and 2 (Mumbai) stay.
    let msgs = a.query("ROLLBACK TO SAVEPOINT sp1");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("ROLLBACK"), "{msgs:?}");
    assert_eq!(ready_status(&msgs), b'T', "ROLLBACK TO keeps the txn open");
    let rows = Client::rows(&a.query("SELECT * FROM users"));
    assert_eq!(rows.len(), 2, "only the pre-savepoint rows must remain");
    assert_eq!(rows[0][1], Some("Delhi".to_string()));
    assert_eq!(rows[1][1], Some("Mumbai".to_string()));
    // The savepoint itself survives: rolling back to it again is
    // still fine (a no-op now, not an error).
    let msgs = a.query("ROLLBACK TO SAVEPOINT sp1");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    // COMMIT lands exactly the pre-savepoint writes.
    a.query("COMMIT");
    assert_eq!(Client::rows(&b.query("SELECT * FROM users")).len(), 2);
    a.terminate();
    b.terminate();
}

#[test]
fn savepoint_release_and_unknown_name_errors() {
    let server = Server::start("savepoint-release");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, city)");
    client.query("INSERT INTO users VALUES (1, 'Delhi')");

    // SAVEPOINT / RELEASE / ROLLBACK TO outside a transaction: 25P01.
    for sql in [
        "SAVEPOINT sp",
        "RELEASE SAVEPOINT sp",
        "ROLLBACK TO SAVEPOINT sp",
    ] {
        let msgs = client.query(sql);
        let (code, _) = Client::error(&msgs).expect("must error outside a txn");
        assert_eq!(code, "25P01", "{sql}: {msgs:?}");
    }

    client.query("BEGIN");
    // Unknown name: 3B001, for both ROLLBACK TO and RELEASE.
    for sql in ["ROLLBACK TO SAVEPOINT nope", "RELEASE SAVEPOINT nope"] {
        let msgs = client.query(sql);
        let (code, _) = Client::error(&msgs).expect("unknown savepoint must error");
        assert_eq!(code, "3B001", "{sql}: {msgs:?}");
    }
    assert_eq!(
        ready_status(&client.query("SELECT * FROM users")),
        b'T',
        "a failed savepoint statement must not end the transaction"
    );

    // RELEASE removes the name: ROLLBACK TO afterwards is 3B001.
    client.query("SAVEPOINT sp");
    client.query("INSERT INTO users VALUES (2, 'Mumbai')");
    let msgs = client.query("RELEASE SAVEPOINT sp");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("RELEASE"), "{msgs:?}");
    let msgs = client.query("ROLLBACK TO SAVEPOINT sp");
    let (code, _) = Client::error(&msgs).expect("released savepoint must error");
    assert_eq!(code, "3B001", "{msgs:?}");
    // The insert made after the (now released) savepoint is still
    // in the transaction — RELEASE only forgets the name.
    assert_eq!(Client::rows(&client.query("SELECT * FROM users")).len(), 2);
    client.query("COMMIT");
    assert_eq!(Client::rows(&client.query("SELECT * FROM users")).len(), 2);
    client.terminate();
}

#[test]
fn savepoint_rollback_recovers_aborted_transaction() {
    // PostgreSQL lets ROLLBACK TO SAVEPOINT recover from the
    // aborted (25P02) state; a plain statement cannot.
    let server = Server::start("savepoint-aborted");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, city)");
    client.query("INSERT INTO users VALUES (1, 'Delhi')");
    client.query("BEGIN");
    client.query("SAVEPOINT sp");
    // A failing statement aborts the transaction...
    let msgs = client.query("INSERT INTO nosuch VALUES (9, 'X')");
    let (code, _) = Client::error(&msgs).expect("insert into a missing table must error");
    assert_eq!(code, "42P01", "{msgs:?}");
    let msgs = client.query("SELECT * FROM users");
    let (code, _) = Client::error(&msgs).expect("aborted txn must refuse SELECT");
    assert_eq!(code, "25P02", "{msgs:?}");
    assert_eq!(ready_status(&msgs), b'E');
    // ...but ROLLBACK TO SAVEPOINT runs, and clears the abort.
    let msgs = client.query("ROLLBACK TO SAVEPOINT sp");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    assert_eq!(ready_status(&msgs), b'T', "txn must be usable again");
    let msgs = client.query("INSERT INTO users VALUES (2, 'Mumbai')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    client.query("COMMIT");
    assert_eq!(Client::rows(&client.query("SELECT * FROM users")).len(), 2);
    client.terminate();
}

#[test]
fn savepoint_works_over_the_extended_protocol() {
    // SAVEPOINT / ROLLBACK TO go through Parse/Bind/Execute too.
    let server = Server::start("savepoint-extended");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, city)");
    client.query("INSERT INTO users VALUES (1, 'Delhi')");

    let run = |client: &mut Client, sql: &str| -> Vec<Msg> {
        client.extended(&[
            parse_frame("", sql, &[]),
            bind_frame("", "", &[], &[], &[]),
            execute_frame("", 0),
            sync_frame(),
        ])
    };
    let msgs = run(&mut client, "BEGIN");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("BEGIN"), "{msgs:?}");
    let msgs = run(&mut client, "SAVEPOINT sp");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SAVEPOINT"), "{msgs:?}");
    let msgs = run(&mut client, "INSERT INTO users VALUES (2, 'Mumbai')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    let msgs = run(&mut client, "ROLLBACK TO SAVEPOINT sp");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("ROLLBACK"), "{msgs:?}");
    let msgs = run(&mut client, "COMMIT");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("COMMIT"), "{msgs:?}");
    // The rolled-back insert never landed.
    assert_eq!(Client::rows(&client.query("SELECT * FROM users")).len(), 1);
    client.terminate();
}

#[test]
fn parser_select_order_by_limit_offset() {
    let server = Server::start("parser-order-limit");
    let (mut client, _) = Client::connect(server.port);
    seed_users_four(&mut client);

    // ORDER BY id DESC + LIMIT 2: the two highest ids first.
    let rows = Client::rows(&client.query("SELECT * FROM users ORDER BY id DESC LIMIT 2"));
    assert_eq!(
        rows.iter().map(|r| r[0].clone()).collect::<Vec<_>>(),
        vec![Some("4".to_string()), Some("3".to_string())],
        "ORDER BY id DESC LIMIT 2 must return ids 4, 3"
    );
    // OFFSET skips, LIMIT caps: ids 3, 2.
    let rows =
        Client::rows(&client.query("SELECT id FROM users ORDER BY id DESC LIMIT 2 OFFSET 1"));
    assert_eq!(
        rows,
        vec![vec![Some("3".to_string())], vec![Some("2".to_string())]]
    );
    // ORDER BY on text sorts lexicographically; ties keep row-id
    // order (stable sort over the row-id-ordered scan).
    let rows = Client::rows(&client.query("SELECT city FROM users ORDER BY city ASC"));
    assert_eq!(
        rows.iter().map(|r| r[0].clone()).collect::<Vec<_>>(),
        vec![
            Some("Delhi".to_string()),
            Some("Delhi".to_string()),
            Some("Mumbai".to_string()),
            Some("Pune".to_string()),
        ]
    );
    // LIMIT 0 returns no rows (but still a valid SELECT).
    let msgs = client.query("SELECT * FROM users LIMIT 0");
    assert_eq!(Client::rows(&msgs).len(), 0);
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 0"), "{msgs:?}");
    // ORDER BY on an unknown column: 42703.
    let msgs = client.query("SELECT * FROM users ORDER BY nope");
    let (code, _) = Client::error(&msgs).expect("unknown ORDER BY column must error");
    assert_eq!(code, "42703", "{msgs:?}");
    client.terminate();
}

#[test]
fn review_bigint_where_and_order_by_are_exact_above_2_pow_53() {
    // B1 (V0.7 review): 2^53 and 2^53+1 are the SAME f64, so a
    // WHERE on the odd value used to match both rows.
    let server = Server::start("review-bigint");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (id, v)");
    client.query("INSERT INTO t VALUES (9007199254740992, 'even')");
    client.query("INSERT INTO t VALUES (9007199254740993, 'odd')");
    let rows = Client::rows(&client.query("SELECT * FROM t WHERE id = 9007199254740993"));
    assert_eq!(rows.len(), 1, "only the odd row must match: {rows:?}");
    assert_eq!(rows[0][1], Some("odd".to_string()));
    let rows = Client::rows(&client.query("SELECT * FROM t WHERE id > 9007199254740992"));
    assert_eq!(rows.len(), 1, "only the odd row is greater: {rows:?}");
    let rows = Client::rows(&client.query("SELECT * FROM t WHERE id < 9007199254740993"));
    assert_eq!(rows.len(), 1, "only the even row is smaller: {rows:?}");
    let rows = Client::rows(&client.query("SELECT * FROM t ORDER BY id"));
    assert_eq!(
        rows.iter().map(|r| r[0].clone()).collect::<Vec<_>>(),
        vec![
            Some("9007199254740992".to_string()),
            Some("9007199254740993".to_string()),
        ],
        "ORDER BY must put the even row first: {rows:?}"
    );
    let rows = Client::rows(&client.query("SELECT * FROM t ORDER BY id DESC"));
    assert_eq!(rows[0][1], Some("odd".to_string()));
    client.terminate();
}

#[test]
fn review_portal_cache_invalidated_after_rollback_to_savepoint() {
    // B2 (V0.7 review): a suspended portal's cached rows
    // included a row the ROLLBACK TO SAVEPOINT had just undone,
    // and resuming the portal served it. The cache must be
    // re-run fresh (resuming from the rows already sent).
    let server = Server::start("fix-portal-stale");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (id, name)");
    client.query("INSERT INTO t VALUES (1, 'n1')");
    client.query("INSERT INTO t VALUES (2, 'n2')");
    client.query("BEGIN");
    client.query("SAVEPOINT sp");
    client.query("INSERT INTO t VALUES (3, 'n3')");
    let msgs = client.extended(&[
        parse_frame("s1", "SELECT * FROM t", &[]),
        bind_frame("p1", "s1", &[], &[], &[]),
        execute_frame("p1", 1),
        sync_frame(),
    ]);
    assert_eq!(
        Client::rows(&msgs).len(),
        1,
        "first Execute sends 1 row: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| matches!(m, Msg::PortalSuspended)),
        "must suspend: {msgs:?}"
    );
    // Roll back the insert of row 3, via the extended protocol.
    let msgs = client.extended(&[
        parse_frame("", "ROLLBACK TO SAVEPOINT sp", &[]),
        bind_frame("", "", &[], &[], &[]),
        execute_frame("", 0),
        sync_frame(),
    ]);
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    assert_eq!(
        Client::rows(&client.query("SELECT * FROM t")).len(),
        2,
        "row 3 must be gone after ROLLBACK TO"
    );
    // Resume the suspended portal: only row 2 remains to send.
    let msgs = client.extended(&[execute_frame("p1", 0), sync_frame()]);
    let rows = Client::rows(&msgs);
    assert_eq!(rows.len(), 1, "resume must serve only row 2: {rows:?}");
    assert_eq!(
        rows[0][0],
        Some("2".to_string()),
        "resumed row must be row 2: {rows:?}"
    );
    assert_eq!(Client::tag(&msgs).as_deref(), Some("SELECT 2"), "{msgs:?}");
    client.query("COMMIT");
    client.terminate();
}

#[test]
fn review_duplicate_savepoint_release_reveals_older_one() {
    // M1 (V0.7 review): SAVEPOINT s twice hides the first s;
    // RELEASE of the newest reveals it, so ROLLBACK TO s rolls
    // back to the FIRST savepoint (PostgreSQL behaviour). The
    // old code dropped the first s, so ROLLBACK TO failed with
    // 3B001 and every write stayed.
    let server = Server::start("fix-dup-savepoint");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (id, city)");
    client.query("INSERT INTO t VALUES (1, 'Delhi')");
    client.query("BEGIN");
    client.query("SAVEPOINT s");
    client.query("INSERT INTO t VALUES (2, 'Mumbai')");
    client.query("SAVEPOINT s");
    client.query("INSERT INTO t VALUES (3, 'Jaipur')");
    client.query("RELEASE SAVEPOINT s");
    let msgs = client.query("ROLLBACK TO SAVEPOINT s");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    let rows = Client::rows(&client.query("SELECT * FROM t"));
    assert_eq!(rows.len(), 1, "only row 1 must remain: {rows:?}");
    assert_eq!(rows[0][1], Some("Delhi".to_string()));
    // Rolling back to the (still present) first savepoint again
    // is a no-op, not an error.
    let msgs = client.query("ROLLBACK TO SAVEPOINT s");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    client.query("ROLLBACK");
    client.terminate();
}

#[test]
fn review_create_table_rejects_duplicate_column_names() {
    // M2 (V0.7 review): CREATE TABLE t (id, id) used to be
    // accepted, and INSERT (1, 2) then stored only {"id": "2"}.
    let server = Server::start("review-dup-col");
    let (mut client, _) = Client::connect(server.port);
    let msgs = client.query("CREATE TABLE t (id, id)");
    let (code, _) = Client::error(&msgs).expect("duplicate column must error");
    assert_eq!(code, "42601", "{msgs:?}");
    // The rejected table does not exist: creating it properly
    // now works, and the old name is free.
    let msgs = client.query("CREATE TABLE t (id, v)");
    assert!(Client::error(&msgs).is_none(), "{msgs:?}");
    client.query("INSERT INTO t VALUES (1, 2)");
    let rows = Client::rows(&client.query("SELECT * FROM t"));
    assert_eq!(
        rows,
        vec![vec![Some("1".to_string()), Some("2".to_string())]],
        "both values must be stored under their own columns"
    );
    client.terminate();
}

#[test]
fn review_update_rejects_duplicate_set_column() {
    // M4 (V0.7 review): UPDATE t SET a = 1, a = 2 used to be
    // silently last-wins. PostgreSQL rejects it — so does Zeno.
    let server = Server::start("review-dup-set");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a, b)");
    client.query("INSERT INTO t VALUES (0, 'x')");
    let msgs = client.query("UPDATE t SET a = 1, a = 2");
    let (code, _) = Client::error(&msgs).expect("duplicate SET column must error");
    assert_eq!(code, "42601", "{msgs:?}");
    let rows = Client::rows(&client.query("SELECT * FROM t"));
    assert_eq!(
        rows[0][0],
        Some("0".to_string()),
        "a failed UPDATE must change nothing: {rows:?}"
    );
    // Two different columns in one SET still work.
    let msgs = client.query("UPDATE t SET a = 1, b = 'y'");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("UPDATE 1"), "{msgs:?}");
    client.terminate();
}

#[test]
fn review_offset_before_limit_and_multi_column_order_by() {
    // M5 (V0.7 review): OFFSET before LIMIT, and several ORDER
    // BY keys, both used to fail with 42601.
    let server = Server::start("fix-offset-limit");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a, b)");
    client.query("INSERT INTO t VALUES (1, 2)");
    client.query("INSERT INTO t VALUES (1, 1)");
    client.query("INSERT INTO t VALUES (2, 9)");
    let rows = Client::rows(&client.query("SELECT * FROM t OFFSET 0 LIMIT 1"));
    assert_eq!(rows.len(), 1, "OFFSET before LIMIT must work: {rows:?}");
    let rows = Client::rows(&client.query("SELECT * FROM t ORDER BY a, b"));
    assert_eq!(
        rows,
        vec![
            vec![Some("1".to_string()), Some("1".to_string())],
            vec![Some("1".to_string()), Some("2".to_string())],
            vec![Some("2".to_string()), Some("9".to_string())],
        ],
        "ORDER BY a, b must sort by a, then by b: {rows:?}"
    );
    let rows = Client::rows(&client.query("SELECT * FROM t ORDER BY a ASC, b DESC"));
    assert_eq!(
        rows[0],
        vec![Some("1".to_string()), Some("2".to_string())],
        "per-key direction must apply: {rows:?}"
    );
    // LIMIT then OFFSET still works, and OFFSET before LIMIT
    // with a real offset skips rows.
    let rows = Client::rows(&client.query("SELECT * FROM t ORDER BY a, b OFFSET 1 LIMIT 1"));
    assert_eq!(
        rows,
        vec![vec![Some("1".to_string()), Some("2".to_string())]],
        "{rows:?}"
    );
    client.terminate();
}

#[test]
fn review_unsupported_constructs_are_0a000() {
    // m1 (V0.7 review): known-but-unsupported constructs fail
    // with 0A000 (feature not supported), not 42601.
    let server = Server::start("review-0a000");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE t (a, b)");
    for sql in [
        "SELECT * FROM t WHERE a LIKE '1'",
        "SELECT * FROM t WHERE a IS NULL",
        "SELECT * FROM t WHERE a IS NOT NULL",
        "SELECT * FROM t WHERE a = upper('x')",
        "INSERT INTO t SELECT * FROM t",
        "CREATE TABLE u (id, PRIMARY KEY (id))",
    ] {
        let msgs = client.query(sql);
        let (code, _) = Client::error(&msgs).unwrap_or_else(|| panic!("{sql} must error"));
        assert_eq!(code, "0A000", "{sql}: {msgs:?}");
    }
    client.terminate();
}

#[test]
fn parser_multi_condition_where_with_comparisons() {
    let server = Server::start("parser-where");
    let (mut client, _) = Client::connect(server.port);
    seed_users_four(&mut client);

    // AND-joined conditions, `=` and `>`.
    let rows =
        Client::rows(&client.query("SELECT name FROM users WHERE city = 'Delhi' AND id > 1"));
    assert_eq!(rows, vec![vec![Some("Ravi".to_string())]]);
    // Range with >= and <=.
    let rows =
        Client::rows(&client.query("SELECT id FROM users WHERE id >= 2 AND id <= 3 ORDER BY id"));
    assert_eq!(
        rows,
        vec![vec![Some("2".to_string())], vec![Some("3".to_string())]]
    );
    // `!=` and `<=`: numeric comparison, not lexicographic
    // ("10" > "9" numerically — a string compare would disagree).
    let rows = Client::rows(
        &client.query("SELECT id FROM users WHERE city != 'Delhi' AND id <= 4 ORDER BY id"),
    );
    assert_eq!(
        rows,
        vec![vec![Some("2".to_string())], vec![Some("4".to_string())]]
    );
    // A condition on an unknown column matches no rows (as before).
    let rows = Client::rows(&client.query("SELECT * FROM users WHERE nope = 'x'"));
    assert_eq!(rows.len(), 0);
    client.terminate();
}

#[test]
fn parser_multi_row_insert_and_column_list() {
    let server = Server::start("parser-insert");
    let (mut client, _) = Client::connect(server.port);
    client.query("CREATE TABLE users (id, name, city)");

    // Two rows in one statement: one CommandComplete, INSERT 0 2.
    let msgs =
        client.query("INSERT INTO users VALUES (1, 'Sanjay', 'Delhi'), (2, 'Asha', 'Mumbai')");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 2"),
        "{msgs:?}"
    );
    // Column list, in a different order than the registry: the
    // values must land in the right columns.
    let msgs = client.query("INSERT INTO users (city, name, id) VALUES ('Jaipur', 'Vikram', 3)");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("INSERT 0 1"),
        "{msgs:?}"
    );
    let rows = Client::rows(&client.query("SELECT * FROM users WHERE id = 3"));
    assert_eq!(
        rows,
        vec![vec![
            Some("3".to_string()),
            Some("Vikram".to_string()),
            Some("Jaipur".to_string()),
        ]]
    );
    // A column list with an unknown column: 42703, nothing inserted.
    let msgs = client.query("INSERT INTO users (id, nope) VALUES (9, 'x')");
    let (code, _) = Client::error(&msgs).expect("unknown INSERT column must error");
    assert_eq!(code, "42703", "{msgs:?}");
    assert_eq!(Client::rows(&client.query("SELECT * FROM users")).len(), 3);
    // A row with the wrong value count: 42601.
    let msgs = client.query("INSERT INTO users VALUES (9, 'only-two')");
    let (code, _) = Client::error(&msgs).expect("short row must error");
    assert_eq!(code, "42601", "{msgs:?}");
    client.terminate();
}

#[test]
fn parser_multi_set_update() {
    let server = Server::start("parser-update");
    let (mut client, _) = Client::connect(server.port);
    seed_users_four(&mut client);

    // Two SET assignments, one WHERE with AND.
    let msgs = client
        .query("UPDATE users SET city = 'Pune', name = 'Asha2' WHERE id = 2 AND city = 'Mumbai'");
    assert_eq!(Client::tag(&msgs).as_deref(), Some("UPDATE 1"), "{msgs:?}");
    let rows = Client::rows(&client.query("SELECT * FROM users WHERE id = 2"));
    assert_eq!(
        rows,
        vec![vec![
            Some("2".to_string()),
            Some("Asha2".to_string()),
            Some("Pune".to_string()),
        ]]
    );
    // The other rows are untouched.
    assert_eq!(
        Client::rows(&client.query("SELECT * FROM users WHERE id = 1"))[0][1],
        Some("Sanjay".to_string())
    );
    // An unknown SET column is still 42703.
    let msgs = client.query("UPDATE users SET nope = 'x', city = 'Y' WHERE id = 1");
    let (code, _) = Client::error(&msgs).expect("unknown SET column must error");
    assert_eq!(code, "42703", "{msgs:?}");
    client.terminate();
}

#[test]
fn parser_syntax_errors_carry_line_and_column() {
    let server = Server::start("parser-errors");
    let (mut client, _) = Client::connect(server.port);
    seed_users_four(&mut client);

    // A missing value after `=`: 42601, with the position.
    let msgs = client.query("SELECT * FROM users WHERE city =");
    let (code, message) = Client::error(&msgs).expect("bad SQL must error");
    assert_eq!(code, "42601", "{msgs:?}");
    assert!(
        message.contains("line 1, column"),
        "syntax error must carry its position: {message}"
    );
    // Multi-line SQL: the error points at line 3, not line 1.
    let msgs = client.query("SELECT *\nFROM users\nWHERE city =");
    let (code, message) = Client::error(&msgs).expect("bad multi-line SQL must error");
    assert_eq!(code, "42601", "{msgs:?}");
    assert!(
        message.contains("line 3, column"),
        "multi-line syntax error must point at line 3: {message}"
    );
    // JOIN is a clean "not supported" (0A000), not a syntax error.
    let msgs = client.query("SELECT * FROM users JOIN other ON users.id = other.id");
    let (code, message) = Client::error(&msgs).expect("JOIN must error");
    assert_eq!(code, "0A000", "{msgs:?}");
    assert!(message.contains("JOIN"), "{message}");
    // Aggregates are "not supported" too.
    let msgs = client.query("SELECT COUNT(*) FROM users");
    let (code, _) = Client::error(&msgs).expect("COUNT(*) must error");
    assert_eq!(code, "0A000", "{msgs:?}");
    // A missing comma in CREATE TABLE is still a syntax error.
    let msgs = client.query("CREATE TABLE broken (id name)");
    let (code, _) = Client::error(&msgs).expect("bad CREATE TABLE must error");
    assert_eq!(code, "42601", "{msgs:?}");
    // ...but a typed CREATE TABLE now works (V0.6 rejected it).
    let msgs = client.query("CREATE TABLE typed (id SERIAL PRIMARY KEY, name VARCHAR(10))");
    assert_eq!(
        Client::tag(&msgs).as_deref(),
        Some("CREATE TABLE"),
        "{msgs:?}"
    );
    // The connection survives every error above.
    assert_eq!(Client::rows(&client.query("SELECT * FROM users")).len(), 4);
    client.terminate();
}

#[test]
fn serve_accepts_vacuum_interval_and_no_auto_vacuum_flags() {
    // The flags must at least start a working server: a 1-second
    // auto-vacuum and a disabled one both serve queries fine.
    // (The pruning itself is covered by the unit test in pgwire.rs.)
    for (name, extra) in [
        ("autovacuum-flag", ["--vacuum-interval", "1"].as_slice()),
        ("no-autovacuum-flag", ["--no-auto-vacuum"].as_slice()),
    ] {
        let server = Server::start_with_args(name, extra);
        let (mut client, _) = Client::connect(server.port);
        client.query("CREATE TABLE t (id, city)");
        client.query("INSERT INTO t VALUES (1, 'Delhi')");
        assert_eq!(Client::rows(&client.query("SELECT * FROM t")).len(), 1);
        client.terminate();
    }
}

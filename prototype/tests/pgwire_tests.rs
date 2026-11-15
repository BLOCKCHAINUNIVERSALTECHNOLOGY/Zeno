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
use std::time::Duration;

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
        let dir = tmp_dir(name);
        let bin = env!("CARGO_BIN_EXE_zeno");
        // `free_port` binds :0 and releases it, so two tests starting
        // at the same moment can be handed the SAME port — and the
        // second server then fails to bind. Retry with a fresh port
        // when the child exits (bind failure) instead of connecting
        // to the other test's server by mistake.
        for _attempt in 0..5 {
            let port = free_port();
            let mut child = Command::new(bin)
                .args([
                    "--data",
                    dir.to_str().unwrap(),
                    "serve",
                    "--port",
                    &port.to_string(),
                ])
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
    RowDescription(Vec<String>),
    DataRow(Vec<Option<String>>),
    CommandComplete(String),
    ErrorResponse(String, String), // (SQLSTATE code, message)
    EmptyQueryResponse,
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
            assert_eq!(
                read_i32(body, &mut pos),
                0,
                "expected AuthenticationOk (R, 0)"
            );
            Msg::AuthOk
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
            for _ in 0..n {
                let name = read_cstr(body, &mut pos);
                let _table_oid = read_i32(body, &mut pos);
                let _attr = read_i16(body, &mut pos);
                let type_oid = read_i32(body, &mut pos);
                let _typlen = read_i16(body, &mut pos);
                let _typmod = read_i32(body, &mut pos);
                let _format = read_i16(body, &mut pos);
                assert_eq!(type_oid, 25, "all Zeno columns are text (OID 25)");
                cols.push(name);
            }
            Msg::RowDescription(cols)
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
        other => Msg::Other(other),
    }
}

impl Client {
    /// Connect and run the startup handshake. Returns the messages
    /// received up to and including ReadyForQuery.
    fn connect(port: u16) -> (Client, Vec<Msg>) {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to server");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut client = Client {
            stream: stream.try_clone().unwrap(),
            reader: BufReader::new(stream),
        };
        // StartupMessage: length + protocol 3.0 (196608) + params.
        let mut body = Vec::new();
        body.extend_from_slice(&196608i32.to_be_bytes());
        for (k, v) in [("user", "zeno"), ("database", "zeno")] {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        let mut frame = Vec::new();
        frame.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        frame.extend_from_slice(&body);
        client.stream.write_all(&frame).unwrap();
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
    // libpq sends SSLRequest first unless sslmode=disable; the server
    // must answer 'N' (no SSL) and then accept a normal startup.
    let server = Server::start("ssl");
    let stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut stream = stream;
    stream.write_all(&8i32.to_be_bytes()).unwrap();
    stream.write_all(&80877103i32.to_be_bytes()).unwrap();
    stream.flush().unwrap();
    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer).unwrap();
    assert_eq!(answer, [b'N'], "SSLRequest must be answered 'N' (no SSL)");
    drop(stream);
    // A fresh connection must still complete the normal handshake.
    let (client, msgs) = Client::connect(server.port);
    assert!(msgs.iter().any(|m| matches!(m, Msg::AuthOk)));
    client.terminate();
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
            Msg::RowDescription(cols) if cols == &["id".to_string(), "name".to_string(), "city".to_string()]
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
            Msg::RowDescription(cols) if cols == &["name".to_string(), "city".to_string()]
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

    // UPDATE is not in the V0.3 subset: ErrorResponse, then ReadyForQuery.
    let msgs = client.query("UPDATE users SET name = 'X' WHERE id = 1");
    let (code, message) = Client::error(&msgs).expect("UPDATE must produce an ErrorResponse");
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
    // F1 regression (reviewer repro): a driver pipelines
    // Parse+Bind+Describe+Execute+Sync in ONE flush and reads until
    // the first ReadyForQuery. The server must answer each extended
    // message with an ErrorResponse and NO ReadyForQuery, and Sync
    // with exactly one ReadyForQuery — so the NEXT Simple Query on
    // the same connection is answered normally, not with a stale
    // "extended query protocol not supported" error.
    let server = Server::start("extended-sync");
    let (mut client, _) = Client::connect(server.port);

    // Seed a table first, on a second connection, so the SELECT
    // below has a real row to return.
    let (mut seeder, _) = Client::connect(server.port);
    seeder.query("CREATE TABLE t (id, name)");
    seeder.query("INSERT INTO t VALUES (1, 'Sanjay')");
    seeder.terminate();

    // Parse+Bind+Describe+Execute+Sync in one flush, like psycopg/JDBC.
    let mut frame = Vec::new();
    let parse_body = {
        let mut b = Vec::new();
        b.push(0); // unnamed statement
        b.extend_from_slice(b"SELECT 1\0");
        b.extend_from_slice(&0u16.to_be_bytes()); // 0 param types
        b
    };
    frame.push(b'P');
    frame.extend_from_slice(&((parse_body.len() + 4) as i32).to_be_bytes());
    frame.extend_from_slice(&parse_body);
    let bind_body = {
        let mut b = Vec::new();
        b.push(0); // unnamed portal
        b.push(0); // unnamed statement
        b.extend_from_slice(&0u16.to_be_bytes()); // 0 param format codes
        b.extend_from_slice(&0u16.to_be_bytes()); // 0 params
        b.extend_from_slice(&0u16.to_be_bytes()); // 0 result format codes
        b
    };
    frame.push(b'B');
    frame.extend_from_slice(&((bind_body.len() + 4) as i32).to_be_bytes());
    frame.extend_from_slice(&bind_body);
    let desc_body = b"S\0".to_vec(); // Describe portal (unnamed)
    frame.push(b'D');
    frame.extend_from_slice(&((desc_body.len() + 4) as i32).to_be_bytes());
    frame.extend_from_slice(&desc_body);
    let exec_body = {
        let mut b = Vec::new();
        b.push(0); // unnamed portal
        b.extend_from_slice(&0i32.to_be_bytes()); // 0 rows
        b
    };
    frame.push(b'E');
    frame.extend_from_slice(&((exec_body.len() + 4) as i32).to_be_bytes());
    frame.extend_from_slice(&exec_body);
    frame.push(b'S');
    frame.extend_from_slice(&4i32.to_be_bytes());
    client.send_raw(&frame);
    let msgs = client.read_until_ready();

    // Exactly one ErrorResponse per extended message (4: P/B/D/E),
    // then exactly ONE ReadyForQuery — the Sync reply.
    let errors = msgs
        .iter()
        .filter(|m| matches!(m, Msg::ErrorResponse(_, _)))
        .count();
    assert_eq!(errors, 4, "one ErrorResponse per P/B/D/E message: {msgs:?}");
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
    // no stale "extended query protocol not supported" error.
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

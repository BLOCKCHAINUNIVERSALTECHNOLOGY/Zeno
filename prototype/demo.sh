#!/usr/bin/env bash
# demo.sh — Zeno V0.8 end-to-end demo.
#
# Runs a full scenario against one data directory:
#   1. Key-value put / get / delete
#   2. Table create / insert / select
#   3. JSON document put / get / find
#   4. 70 puts to force a memtable flush to SSTables
#   5. Compaction (merges SSTables, drops old versions + tombstones)
#   6. STOP — then REOPEN the same data directory in a fresh process
#      and show the data is still there (crash-recovery proof).
#   7. LOCK — a background holder keeps the data dir locked: a second
#      process is refused with a clear error; then the holder is
#      killed with kill -9 and the SAME directory reopens fine
#      (stale lock, dead PID, taken over).
#   8. WAL STRICTNESS — a torn line is appended to wal.log: the next
#      open warns about it, `stats` counts it, and the data is safe.
#   9. POSTGRESQL WIRE PROTOCOL (V0.3) — `zeno serve` listens on
#      127.0.0.1:5433; a small Python client speaks raw TCP (startup
#      handshake + Simple Query) because psql is NOT installed in this
#      sandbox, and prints the decoded messages. A second server on
#      the same data dir is refused (LOCK).
#  10. EXTENDED QUERY PROTOCOL + SCRAM-SHA-256 AUTH (V0.4) — the same
#      Python client pipelines Parse+Bind+Describe+Execute+Sync with
#      a $1 parameter, fetches one row at a time (PortalSuspended),
#      then sets a password with `zeno user set-password` and logs in
#      with a full SCRAM-SHA-256 handshake (Python hashlib client),
#      plus a wrong-password rejection.
#  11. TLS + SCRAM RATE LIMIT + CONNECTION LIMIT (V0.5) — `zeno cert
#      generate` makes a self-signed cert (0600), the server runs
#      with --tls (SSLRequest answered 'S', TLS 1.3 handshake, SCRAM
#      login + query inside the encrypted stream), then 5 wrong
#      SCRAM logins lock the 'ratelimit' user and even the right
#      password is still 28P01 — and a --max-connections 2 server
#      refuses its 3rd (idle) connection with 53300, then lets a
#      new one in once a slot frees up.
#  12. MVCC TRANSACTIONS (V0.6) — two connections on a fresh data
#      dir: BEGIN + INSERT is invisible to the other connection
#      until COMMIT (snapshot isolation), ROLLBACK undoes an
#      UPDATE, a write-write conflict on the same row fails the
#      second COMMIT with 40001, and kill -9 mid-transaction loses
#      only the uncommitted row on restart.
#  13. AUTO-VACUUM + SAVEPOINTS + REAL SQL PARSER (V0.7) — the
#      server runs with --vacuum-interval 2 (a background thread
#      prunes dead versions every 2s while a live snapshot still
#      reads its old data); SAVEPOINT / ROLLBACK TO SAVEPOINT /
#      RELEASE; and the new parser: multi-row INSERT, ORDER BY /
#      LIMIT, multi-condition WHERE, multi-SET UPDATE, plus a bad
#      SQL line/column error and a JOIN "not supported" error.
#  14. GRACEFUL SHUTDOWN + BENCH (V0.8) — a server writes two rows,
#      gets SIGTERM, and exits 0 after flushing + saving meta.json
#      (no meta.json exists before the signal); a restart reads the
#      rows back. Then `zeno bench --rows 100,1000` prints real
#      measured throughput/latency numbers on this machine.
#
# No fake numbers: everything printed below is real output of the binary.
set -euo pipefail

cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

DATA="./demo-data"
ZENO="./target/release/zeno"

# Build if the release binary is missing.
if [ ! -x "$ZENO" ]; then
  echo "Building release binary first..."
  cargo build --release
fi

# Start clean.
rm -rf "$DATA"

say() { echo; echo "== $1 =="; }

say "1. KEY-VALUE — put / get / delete"
$ZENO --data "$DATA" put greeting "hello zeno"
$ZENO --data "$DATA" put language "rust"
$ZENO --data "$DATA" get greeting
$ZENO --data "$DATA" put language "rust + lsm"
$ZENO --data "$DATA" get language
$ZENO --data "$DATA" del language
$ZENO --data "$DATA" get language

say "2. TABLE — create / insert / select (simple scan filter, not real SQL)"
$ZENO --data "$DATA" table create users id,name,city
$ZENO --data "$DATA" table insert users 1,Sanjay,Delhi
$ZENO --data "$DATA" table insert users 2,Asha,Mumbai
$ZENO --data "$DATA" table insert users 3,Ravi,Delhi
$ZENO --data "$DATA" table select users
$ZENO --data "$DATA" table select users city=Delhi

say "3. JSON DOCUMENT — put / get / find (linear scan in V0.4)"
$ZENO --data "$DATA" doc put profiles u1 '{"name":"Sanjay","city":"Delhi","role":"builder"}'
$ZENO --data "$DATA" doc put profiles u2 '{"name":"Asha","city":"Mumbai","role":"designer"}'
$ZENO --data "$DATA" doc put profiles u3 '{"name":"Ravi","city":"Delhi","role":"tester"}'
$ZENO --data "$DATA" doc get profiles u1
$ZENO --data "$DATA" doc find profiles city=Delhi

say "4. FORCE FLUSHES — 70 puts (memtable flushes at 64 entries)"
for i in $(seq 1 70); do
  $ZENO --data "$DATA" put "bulk-key-$i" "bulk-value-$i" >/dev/null
done
$ZENO --data "$DATA" get bulk-key-1
$ZENO --data "$DATA" get bulk-key-70
$ZENO --data "$DATA" stats

say "5. COMPACTION — merge SSTables, drop overwritten values + tombstones"
$ZENO --data "$DATA" compact
$ZENO --data "$DATA" stats
ls -la "$DATA"

say "6. CRASH-RECOVERY PROOF — stop, then reopen the SAME data dir"
echo "(each command above was already a separate process; now a fresh"
echo " process reopens the same directory and reads everything back)"
$ZENO --data "$DATA" get greeting
$ZENO --data "$DATA" get bulk-key-42
$ZENO --data "$DATA" table select users city=Delhi
$ZENO --data "$DATA" doc get profiles u2
$ZENO --data "$DATA" doc find profiles city=Delhi
$ZENO --data "$DATA" get language

say "7. LOCK FILE (V0.2) — second process refused, kill -9 does not jam the lock"
echo "(a background 'hold' process keeps the data dir locked for 30s)"
$ZENO --data "$DATA" hold 30 &
HOLDER=$!
sleep 1
echo "-- second process tries to open the same data dir while it is held:"
if $ZENO --data "$DATA" get greeting 2>&1; then
  echo "ERROR: second process should have been refused!"
else
  echo "(expected: the second process was refused — data dir locked)"
fi
echo "-- now kill -9 the holder (a crash leaves a stale lock file behind):"
kill -9 $HOLDER || true
wait $HOLDER 2>/dev/null || true
echo "-- same data dir reopens fine after the kill (stale lock taken over):"
$ZENO --data "$DATA" get greeting
$ZENO --data "$DATA" get bulk-key-42

say "8. WAL STRICTNESS (V0.2) — a torn line is warned about and counted, data stays safe"
$ZENO --data "$DATA" put wal-demo-key "wal-demo-value"
echo "-- appending a torn/corrupt line to wal.log:"
printf 'garbage-not-json\n' >> "$DATA/wal.log"
echo "-- next open warns (stderr) but the data is still there:"
$ZENO --data "$DATA" get wal-demo-key
echo "-- stats counts the corrupt line:"
$ZENO --data "$DATA" stats

say "9. POSTGRESQL WIRE PROTOCOL (V0.3) — serve + raw TCP client"
echo "(psql is NOT installed in this sandbox, so the demo speaks the"
echo " protocol directly with a small Python client — the same bytes"
echo " psql/libpq would send. See README for the psql commands.)"
$ZENO --data "$DATA" serve --port 5433 &
SERVER=$!
sleep 1
python3 - <<'PYEOF'
import socket, struct

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

def read_until_ready(s, label):
    print(f"-- {label}:")
    while True:
        tag, body = read_msg(s)
        if tag == b'R':
            print("   AuthenticationOk")
        elif tag == b'S':
            name, _, rest = body.partition(b"\0")
            print(f"   ParameterStatus {name.decode()}={rest.split(bytes([0]))[0].decode()}")
        elif tag == b'K':
            print("   BackendKeyData")
        elif tag == b'T':
            n = struct.unpack("!H", body[:2])[0]
            cols, p = [], 2
            for _ in range(n):
                end = body.index(b"\0", p)
                cols.append(body[p:end].decode())
                p = end + 1 + 18  # 4+2+4+2+4+2 bytes of field metadata
            print(f"   RowDescription {cols}")
        elif tag == b'D':
            n = struct.unpack("!H", body[:2])[0]
            vals, p = [], 2
            for _ in range(n):
                (ln,) = struct.unpack("!i", body[p:p + 4]); p += 4
                vals.append(body[p:p + ln].decode()); p += ln
            print(f"   DataRow {vals}")
        elif tag == b'C':
            print(f"   CommandComplete {body.split(bytes([0]))[0].decode()}")
        elif tag == b'E':
            code, msg, p = "", "", 0
            while p < len(body) and body[p] != 0:
                f = chr(body[p]); p += 1
                end = body.index(b"\0", p)
                v = body[p:end].decode(); p = end + 1
                if f == 'C': code = v
                if f == 'M': msg = v
            print(f"   ErrorResponse [{code}] {msg}")
        elif tag == b'I':
            print("   EmptyQueryResponse")
        elif tag == b'Z':
            print(f"   ReadyForQuery '{body.decode()}'")
            return
        else:
            print(f"   (other message {tag!r})")

s = socket.create_connection(("127.0.0.1", 5433))
params = b"user\0zeno\0database\0zeno\0\0"
body = struct.pack("!I", 196608) + params  # protocol 3.0
s.sendall(struct.pack("!I", len(body) + 4) + body)
read_until_ready(s, "startup handshake")

def query(sql):
    body = sql.encode() + b"\0"
    s.sendall(b"Q" + struct.pack("!I", len(body) + 4) + body)
    read_until_ready(s, f"QUERY: {sql}")

query("CREATE TABLE demo_users (id, name, city)")
query("INSERT INTO demo_users VALUES (1, 'Sanjay', 'Delhi')")
query("INSERT INTO demo_users VALUES (2, 'Asha', 'Mumbai')")
query("SELECT * FROM demo_users WHERE city = 'Delhi'")
query("UPDATE demo_users SET name = 'X'")
query("SELECT * FROM demo_users")
s.sendall(b"X" + struct.pack("!I", 4))  # Terminate
s.close()
print("demo client done — connection closed cleanly, server still running")
PYEOF
echo "-- stopping the server, then proving a second server is refused (LOCK):"
kill $SERVER || true
wait $SERVER 2>/dev/null || true
$ZENO --data "$DATA" serve --port 5433 &
SERVER2=$!
sleep 1
if $ZENO --data "$DATA" serve --port 5434 2>&1; then
  echo "ERROR: second server should have been refused!"
else
  echo "(expected: the second server was refused — data dir locked)"
fi
kill $SERVER2 || true
wait $SERVER2 2>/dev/null || true
say "10. EXTENDED QUERY PROTOCOL + SCRAM-SHA-256 AUTH (V0.4)"
echo "(prepared statements with \$1 params, PortalSuspended resume,"
echo " then a password set with 'zeno user' and a full SCRAM login)"
$ZENO --data "$DATA" serve --port 5433 &
SERVER=$!
sleep 1
python3 - <<'PYEOF'
import socket, struct

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

def show(s, label):
    print(f"-- {label}:")
    while True:
        tag, body = read_msg(s)
        if tag == b'R': print("   AuthenticationOk")
        elif tag == b'S':
            name, _, rest = body.partition(b"\0")
            print(f"   ParameterStatus {name.decode()}={rest.split(bytes([0]))[0].decode()}")
        elif tag == b'K': print("   BackendKeyData")
        elif tag == b'1': print("   ParseComplete")
        elif tag == b'2': print("   BindComplete")
        elif tag == b'3': print("   CloseComplete")
        elif tag == b't':
            n = struct.unpack("!H", body[:2])[0]
            oids = [struct.unpack("!i", body[2 + 4 * i:6 + 4 * i])[0] for i in range(n)]
            print(f"   ParameterDescription {oids}")
        elif tag == b'n': print("   NoData")
        elif tag == b's': print("   PortalSuspended")
        elif tag == b'T':
            n = struct.unpack("!H", body[:2])[0]
            cols, p = [], 2
            for _ in range(n):
                end = body.index(b"\0", p)
                cols.append(body[p:end].decode())
                p = end + 1 + 18
            print(f"   RowDescription {cols}")
        elif tag == b'D':
            n = struct.unpack("!H", body[:2])[0]
            vals, p = [], 2
            for _ in range(n):
                (ln,) = struct.unpack("!i", body[p:p + 4]); p += 4
                vals.append(body[p:p + ln].decode()); p += ln
            print(f"   DataRow {vals}")
        elif tag == b'C':
            print(f"   CommandComplete {body.split(bytes([0]))[0].decode()}")
        elif tag == b'E':
            code, msg, p = "", "", 0
            while p < len(body) and body[p] != 0:
                f = chr(body[p]); p += 1
                end = body.index(b"\0", p)
                v = body[p:end].decode(); p = end + 1
                if f == 'C': code = v
                if f == 'M': msg = v
            print(f"   ErrorResponse [{code}] {msg}")
        elif tag == b'Z':
            print(f"   ReadyForQuery '{body.decode()}'")
            return
        else:
            print(f"   (other message {tag!r})")

def frame(tag, body):
    return tag + struct.pack("!I", len(body) + 4) + body

def parse(name, sql, types=()):
    b = name.encode() + b"\0" + sql.encode() + b"\0" + struct.pack("!H", len(types))
    for t in types:
        b += struct.pack("!i", t)
    return frame(b'P', b)

def bind(portal, stmt, params, result_formats=()):
    b = portal.encode() + b"\0" + stmt.encode() + b"\0"
    b += struct.pack("!H", 0)  # all params text format
    b += struct.pack("!H", len(params))
    for v in params:
        if v is None:
            b += struct.pack("!i", -1)
        else:
            vb = v.encode()
            b += struct.pack("!i", len(vb)) + vb
    b += struct.pack("!H", len(result_formats))
    for f in result_formats:
        b += struct.pack("!H", f)
    return frame(b'B', b)

def describe(kind, name):
    return frame(b'D', kind.encode() + name.encode() + b"\0")

def execute(portal, max_rows):
    return frame(b'E', portal.encode() + b"\0" + struct.pack("!i", max_rows))

def sync():
    return frame(b'S', b"")

s = socket.create_connection(("127.0.0.1", 5433))
params = b"user\0zeno\0database\0zeno\0\0"
body = struct.pack("!I", 196608) + params
s.sendall(struct.pack("!I", len(body) + 4) + body)
show(s, "startup handshake (trust auth — no users set yet)")

# One pipelined batch: Parse + Describe(statement) + Bind($1) +
# Describe(portal) + Execute + Sync, all in one flush.
s.sendall(
    parse("", "SELECT name FROM demo_users WHERE city = $1")
    + describe("S", "")
    + bind("", "", ["Delhi"])
    + describe("P", "")
    + execute("", 0)
    + sync()
)
show(s, "extended batch: Parse+Describe+Bind+Describe+Execute+Sync ($1='Delhi')")

# PortalSuspended: fetch the 2 demo_users rows one at a time.
s.sendall(parse("all", "SELECT * FROM demo_users") + bind("", "all", []) + sync())
show(s, "Parse named 'all' + Bind (unnamed portal)")
s.sendall(execute("", 1) + sync())
show(s, "Execute max_rows=1 -> PortalSuspended after 1 row")
s.sendall(execute("", 1) + sync())
show(s, "Execute again -> last row + CommandComplete SELECT 2")
s.sendall(frame(b'C', b'Sall\0') + sync())
show(s, "Close statement 'all'")
s.sendall(b"X" + struct.pack("!I", 4))
s.close()
print("extended demo done — connection closed cleanly")
PYEOF
kill $SERVER || true
wait $SERVER 2>/dev/null || true

echo "-- setting a password for user 'sanjay' (typed twice on stdin):"
printf '%s\n%s\n' "demo-password" "demo-password" | $ZENO --data "$DATA" user set-password sanjay
$ZENO --data "$DATA" user list
echo "-- restarting the server: new connections now need SCRAM-SHA-256:"
$ZENO --data "$DATA" serve --port 5433 &
SERVER=$!
sleep 1
python3 - <<'PYEOF'
import socket, struct, hashlib, hmac, base64

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

def read_until_ready(s, label):
    print(f"-- {label}:")
    while True:
        tag, body = read_msg(s)
        if tag == b'R' and struct.unpack("!I", body[:4])[0] == 0:
            print("   AuthenticationOk")
        elif tag == b'S':
            print("   ParameterStatus")
        elif tag == b'K':
            print("   BackendKeyData")
        elif tag == b'T':
            print("   RowDescription")
        elif tag == b'D':
            print("   DataRow")
        elif tag == b'C':
            print(f"   CommandComplete {body.split(bytes([0]))[0].decode()}")
        elif tag == b'E':
            print("   ErrorResponse")
        elif tag == b'Z':
            print(f"   ReadyForQuery '{body.decode()}'")
            return
        else:
            print(f"   (other message {tag!r})")

def scram_login(user, password, expect_ok):
    s = socket.create_connection(("127.0.0.1", 5433))
    params = f"user\0{user}\0database\0zeno\0\0".encode()
    body = struct.pack("!I", 196608) + params
    s.sendall(struct.pack("!I", len(body) + 4) + body)
    tag, body = read_msg(s)
    assert tag == b'R' and struct.unpack("!I", body[:4])[0] == 10, f"expected AuthenticationSASL, got {tag} {body!r}"
    print(f"-- SCRAM login as '{user}': server offered SCRAM-SHA-256")
    client_nonce = "demo-nonce-12345"
    client_first_bare = f"n={user},r={client_nonce}"
    client_first = f"n,,{client_first_bare}".encode()
    pbody = b"SCRAM-SHA-256\0" + struct.pack("!I", len(client_first)) + client_first
    s.sendall(b"p" + struct.pack("!I", len(pbody) + 4) + pbody)
    tag, body = read_msg(s)
    assert tag == b'R' and struct.unpack("!I", body[:4])[0] == 11, f"expected SASLContinue, got {tag}"
    server_first = body[4:].decode()
    parts = dict(kv.split("=", 1) for kv in server_first.split(","))
    salt = base64.b64decode(parts["s"])
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(parts["i"]), 32)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    client_final_wo = f"c=biws,r={parts['r']}"
    auth_msg = f"{client_first_bare},{server_first},{client_final_wo}".encode()
    sig = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, sig))
    client_final = f"{client_final_wo},p={base64.b64encode(proof).decode()}"
    s.sendall(b"p" + struct.pack("!I", len(client_final) + 4) + client_final.encode())
    tag, body = read_msg(s)
    if expect_ok:
        assert tag == b'R' and struct.unpack("!I", body[:4])[0] == 12, f"expected SASLFinal, got {tag} {body!r}"
        want = "v=" + base64.b64encode(hmac.new(server_key, auth_msg, hashlib.sha256).digest()).decode()
        assert body[4:].decode() == want, "server signature mismatch"
        print("   server signature verified (mutual auth — server proved itself too)")
        read_until_ready(s, "post-SCRAM handshake")
    else:
        assert tag == b'E', f"expected ErrorResponse, got {tag}"
        print("   ErrorResponse 28P01 (wrong password, as expected)")
        try:
            read_msg(s)
            print("   (unexpected: server sent more after the error)")
        except EOFError:
            print("   connection closed by the server, as expected")
    return s

s = scram_login("sanjay", "demo-password", expect_ok=True)
body = b"SELECT * FROM demo_users\0"
s.sendall(b"Q" + struct.pack("!I", len(body) + 4) + body)
read_until_ready(s, "QUERY after SCRAM login: SELECT * FROM demo_users")
s.sendall(b"X" + struct.pack("!I", 4))
s.close()
scram_login("sanjay", "wrong-password", expect_ok=False)
print("SCRAM demo done")
PYEOF
kill $SERVER || true
wait $SERVER 2>/dev/null || true

say "11. TLS + SCRAM RATE LIMIT + CONNECTION LIMIT (V0.5)"
echo "(self-signed certificate, TLS handshake, then 5 wrong SCRAM"
echo " logins lock the account — and a 2-connection server refuses"
echo " the 3rd connection with 53300)"
echo "-- generating a self-signed certificate for the demo data dir:"
$ZENO --data "$DATA" cert generate
ls -l "$DATA/server-cert.pem" "$DATA/server-key.pem"
echo "-- starting the server with --tls (same data dir, same users):"
$ZENO --data "$DATA" serve --port 5433 --tls &
SERVER=$!
sleep 1
echo "-- setting a password for a second user 'ratelimit' (typed twice on stdin):"
printf '%s\n%s\n' "rate-password" "rate-password" | $ZENO --data "$DATA" user set-password ratelimit
python3 - <<'PYEOF'
import socket, ssl, struct, hashlib, hmac, base64

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

def read_until_ready(s, label):
    print(f"-- {label}:")
    while True:
        tag, body = read_msg(s)
        if tag == b'R' and struct.unpack("!I", body[:4])[0] == 0:
            print("   AuthenticationOk")
        elif tag == b'S':
            print("   ParameterStatus")
        elif tag == b'K':
            print("   BackendKeyData")
        elif tag == b'T':
            print("   RowDescription")
        elif tag == b'D':
            print("   DataRow")
        elif tag == b'C':
            print(f"   CommandComplete {body.split(bytes([0]))[0].decode()}")
        elif tag == b'E':
            print("   ErrorResponse")
        elif tag == b'Z':
            print(f"   ReadyForQuery '{body.decode()}'")
            return
        else:
            print(f"   (other message {tag!r})")

def tls_connect():
    raw = socket.create_connection(("127.0.0.1", 5433))
    raw.sendall(struct.pack("!II", 8, 80877103))  # SSLRequest
    ans = raw.recv(1)
    assert ans == b"S", f"expected 'S' to SSLRequest, got {ans!r}"
    print("-- SSLRequest answered 'S' (TLS, not 'N')")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # self-signed demo cert: no verification
    tls = ctx.wrap_socket(raw, server_hostname="localhost")
    print(f"   TLS handshake done: {tls.version()} {tls.cipher()[0]}")
    return tls

def scram_login(s, user, password, expect_ok):
    params = f"user\0{user}\0database\0zeno\0\0".encode()
    body = struct.pack("!I", 196608) + params
    s.sendall(struct.pack("!I", len(body) + 4) + body)
    tag, body = read_msg(s)
    assert tag == b'R' and struct.unpack("!I", body[:4])[0] == 10, f"expected AuthenticationSASL, got {tag}"
    client_nonce = "demo-nonce-12345"
    client_first_bare = f"n={user},r={client_nonce}"
    client_first = f"n,,{client_first_bare}".encode()
    pbody = b"SCRAM-SHA-256\0" + struct.pack("!I", len(client_first)) + client_first
    s.sendall(b"p" + struct.pack("!I", len(pbody) + 4) + pbody)
    tag, body = read_msg(s)
    assert tag == b'R' and struct.unpack("!I", body[:4])[0] == 11, "expected SASLContinue"
    server_first = body[4:].decode()
    parts = dict(kv.split("=", 1) for kv in server_first.split(","))
    salt = base64.b64decode(parts["s"])
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(parts["i"]), 32)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    client_final_wo = f"c=biws,r={parts['r']}"
    auth_msg = f"{client_first_bare},{server_first},{client_final_wo}".encode()
    sig = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, sig))
    client_final = f"{client_final_wo},p={base64.b64encode(proof).decode()}"
    s.sendall(b"p" + struct.pack("!I", len(client_final) + 4) + client_final.encode())
    tag, body = read_msg(s)
    if expect_ok:
        assert tag == b'R' and struct.unpack("!I", body[:4])[0] == 12, f"expected SASLFinal, got {tag}"
        print(f"   SCRAM login as '{user}' over TLS: OK (server signature verified)")
        read_until_ready(s, f"post-login handshake for '{user}'")
    else:
        assert tag == b'E', f"expected ErrorResponse, got {tag}"
        code = ""
        p = 0
        while p < len(body) and body[p] != 0:
            f = chr(body[p]); p += 1
            end = body.index(b"\0", p)
            if f == 'C': code = body[p:end].decode()
            p = end + 1
        print(f"   SCRAM login as '{user}': ErrorResponse {code} (rejected, as expected)")
        try:
            read_msg(s)
            print("   (unexpected: server sent more after the error)")
        except EOFError:
            print("   connection closed by the server, as expected")
    return s

print("-- TLS + SCRAM login as 'sanjay' (correct password, over TLS):")
s = tls_connect()
s = scram_login(s, "sanjay", "demo-password", expect_ok=True)
body = b"SELECT * FROM demo_users\0"
s.sendall(b"Q" + struct.pack("!I", len(body) + 4) + body)
read_until_ready(s, "QUERY over TLS: SELECT * FROM demo_users")
s.sendall(b"X" + struct.pack("!I", 4))
s.close()

print("-- RATE LIMIT: 5 wrong passwords for 'ratelimit', then the RIGHT one:")
for attempt in range(1, 6):
    s = tls_connect()
    print(f"   wrong-password attempt {attempt}/5:")
    scram_login(s, "ratelimit", "wrong-password", expect_ok=False)
    s.close()
print("-- 6th attempt with the CORRECT password (account is now locked for 5 minutes):")
s = tls_connect()
scram_login(s, "ratelimit", "rate-password", expect_ok=False)
s.close()
print("   (the locked-out login looks exactly like a wrong password: same 28P01,")
print("    same closed connection — it leaks nothing about the lockout or the user)")
print("TLS + rate-limit demo done")
PYEOF
kill $SERVER || true
wait $SERVER 2>/dev/null || true

echo "-- connection limit (fresh data dir, --max-connections 2):"
rm -rf ./demo-data-limit
$ZENO --data ./demo-data-limit serve --port 5434 --max-connections 2 &
SERVER3=$!
sleep 1
python3 - <<'PYEOF'
import socket, struct, time

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

def idle_conn(label):
    s = socket.create_connection(("127.0.0.1", 5434))
    params = b"user\0zeno\0database\0zeno\0\0"
    body = struct.pack("!I", 196608) + params
    s.sendall(struct.pack("!I", len(body) + 4) + body)
    while True:
        tag, body = read_msg(s)
        if tag == b'Z':
            break
    print(f"   {label}: handshake done, connection held idle (no query)")
    return s

a = idle_conn("idle connection 1")
b = idle_conn("idle connection 2")
c = socket.create_connection(("127.0.0.1", 5434))
tag, body = read_msg(c)
assert tag == b'E', f"expected ErrorResponse, got {tag!r}"
code = ""
p = 0
while p < len(body) and body[p] != 0:
    f = chr(body[p]); p += 1
    end = body.index(b"\0", p)
    if f == 'C': code = body[p:end].decode()
    p = end + 1
print(f"   3rd connection: ErrorResponse {code} (too many connections), as expected")
c.close()
b.close()
time.sleep(0.5)  # let the server reap the freed slot
d = idle_conn("new connection after one slot freed")
print("   (the server itself kept running throughout — only the extra connection was refused)")
for s in (a, d):
    s.sendall(b"X" + struct.pack("!I", 4))
    s.close()
print("connection-limit demo done")
PYEOF
kill $SERVER3 || true
wait $SERVER3 2>/dev/null || true
rm -rf ./demo-data-limit

say "12. MVCC TRANSACTIONS (V0.6) — snapshot isolation, two connections"
echo "(fresh data dir, trust auth: connection A BEGINs and writes,"
echo " connection B must not see it until A COMMITs; then a ROLLBACK,"
echo " a 40001 write-write conflict, and a kill -9 mid-transaction)"
rm -rf ./demo-data-txn
$ZENO --data ./demo-data-txn serve --port 5435 &
SERVER4=$!
sleep 1
# If anything below fails (set -e), do not leave this server
# orphaned on port 5435: it is killed when the demo exits
# (the variable is read when the trap fires, so it also covers
# the restarted server below, which reuses $SERVER4).
trap 'kill $SERVER4 2>/dev/null || true' EXIT
SERVER_PID=$SERVER4 python3 - <<'PYEOF'
import socket, struct, time, os, signal

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

def connect(label):
    s = socket.create_connection(("127.0.0.1", 5435))
    params = b"user\0zeno\0database\0zeno\0\0"
    body = struct.pack("!I", 196608) + params
    s.sendall(struct.pack("!I", len(body) + 4) + body)
    while True:
        tag, body = read_msg(s)
        if tag == b'Z':
            break
    print(f"-- {label}: connected (trust auth)")
    return s

def q(s, sql, label):
    """Send one Simple Query, print its outcome, return the rows."""
    body = sql.encode() + b"\0"
    s.sendall(b"Q" + struct.pack("!I", len(body) + 4) + body)
    rows = []
    while True:
        tag, body = read_msg(s)
        if tag == b'T':
            pass  # RowDescription
        elif tag == b'D':
            n = struct.unpack("!H", body[:2])[0]
            vals, pos = [], 2
            for _ in range(n):
                (ln,) = struct.unpack("!I", body[pos:pos + 4]); pos += 4
                vals.append(body[pos:pos + ln].decode() if ln >= 0 else None)
                pos += max(ln, 0)
            rows.append(vals)
        elif tag == b'C':
            print(f"   [{label}] {sql} -> {body.split(bytes([0]))[0].decode()}")
        elif tag == b'E':
            code = ""
            p = 0
            while p < len(body) and body[p] != 0:
                f = chr(body[p]); p += 1
                end = body.index(b"\0", p)
                if f == 'C': code = body[p:end].decode()
                p = end + 1
            print(f"   [{label}] {sql} -> ErrorResponse {code}")
        elif tag == b'Z':
            print(f"   [{label}] ReadyForQuery '{body.decode()}' ({len(rows)} row(s): {rows})")
            return rows
        else:
            print(f"   [{label}] (other message {tag!r})")

a = connect("connection A")
b = connect("connection B")
q(a, "CREATE TABLE txn_demo (id, city)", "A")
q(a, "INSERT INTO txn_demo VALUES (1, 'Delhi')", "A")
print("-- A BEGINs and inserts a row B must NOT see yet:")
q(a, "BEGIN", "A")
q(a, "INSERT INTO txn_demo VALUES (2, 'Mumbai')", "A")
q(a, "SELECT * FROM txn_demo", "A")
q(b, "SELECT * FROM txn_demo", "B")
print("-- A COMMITs: now B sees both rows:")
q(a, "COMMIT", "A")
q(b, "SELECT * FROM txn_demo", "B")
print("-- A BEGINs, UPDATEs, then ROLLBACKs: B never sees Jaipur:")
q(a, "BEGIN", "A")
q(a, "UPDATE txn_demo SET city = 'Jaipur' WHERE id = 1", "A")
q(b, "SELECT * FROM txn_demo", "B")
q(a, "ROLLBACK", "A")
q(b, "SELECT * FROM txn_demo", "B")
print("-- write-write conflict: A and B UPDATE the same row, A commits first:")
q(a, "BEGIN", "A")
q(b, "BEGIN", "B")
q(a, "UPDATE txn_demo SET city = 'Agra' WHERE id = 1", "A")
q(b, "UPDATE txn_demo SET city = 'Pune' WHERE id = 1", "B")
q(a, "COMMIT", "A")
q(b, "COMMIT", "B")
q(b, "SELECT * FROM txn_demo", "B")
print("-- crash mid-transaction: A BEGINs + INSERTs, then the server is killed -9:")
q(a, "BEGIN", "A")
q(a, "INSERT INTO txn_demo VALUES (3, 'Goa')", "A")
print("-- killing the server -9 NOW, with A's transaction still open (no COMMIT, no clean shutdown):")
os.kill(int(os.environ["SERVER_PID"]), signal.SIGKILL)
time.sleep(0.5)
print("   server killed mid-transaction")
PYEOF
wait $SERVER4 2>/dev/null || true
echo "-- server killed -9 with an open transaction; restarting on the same data dir:"
$ZENO --data ./demo-data-txn serve --port 5435 &
SERVER4=$!
sleep 1
python3 - <<'PYEOF'
import socket, struct

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

s = socket.create_connection(("127.0.0.1", 5435))
params = b"user\0zeno\0database\0zeno\0\0"
body = struct.pack("!I", 196608) + params
s.sendall(struct.pack("!I", len(body) + 4) + body)
while True:
    tag, body = read_msg(s)
    if tag == b'Z':
        break
body = b"SELECT * FROM txn_demo\0"
s.sendall(b"Q" + struct.pack("!I", len(body) + 4) + body)
rows = []
while True:
    tag, body = read_msg(s)
    if tag == b'D':
        n = struct.unpack("!H", body[:2])[0]
        vals, pos = [], 2
        for _ in range(n):
            (ln,) = struct.unpack("!I", body[pos:pos + 4]); pos += 4
            vals.append(body[pos:pos + ln].decode() if ln >= 0 else None)
            pos += max(ln, 0)
        rows.append(vals)
    elif tag == b'Z':
        break
print(f"-- after restart: SELECT * FROM txn_demo -> {rows}")
print("   (row 3 'Goa' is gone — its transaction never committed;")
print("    rows 1 'Agra' and 2 'Mumbai' survived, exactly as committed)")
s.sendall(b"X" + struct.pack("!I", 4))
s.close()
print("MVCC demo done")
PYEOF
kill $SERVER4 || true
wait $SERVER4 2>/dev/null || true
rm -rf ./demo-data-txn

say "13. AUTO-VACUUM + SAVEPOINTS + REAL SQL PARSER (V0.7)"
echo "(server runs with --vacuum-interval 2: a background thread"
echo " prunes dead versions every 2s; a live snapshot still reads"
echo " its old data while that happens. Then savepoints, then the"
echo " new parser: multi-row INSERT, ORDER BY/LIMIT, multi-condition"
echo " WHERE, multi-SET UPDATE, and two honest errors.)"
rm -rf ./demo-data-v7
$ZENO --data ./demo-data-v7 serve --port 5436 --vacuum-interval 2 &
SERVER4=$!
sleep 1
python3 - <<'PYEOF'
import socket, struct, time

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

def connect(label):
    s = socket.create_connection(("127.0.0.1", 5436))
    params = b"user\0zeno\0database\0zeno\0\0"
    body = struct.pack("!I", 196608) + params
    s.sendall(struct.pack("!I", len(body) + 4) + body)
    while True:
        tag, body = read_msg(s)
        if tag == b'Z':
            break
    print(f"-- {label}: connected (trust auth)")
    return s

def q(s, sql, label):
    body = sql.encode() + b"\0"
    s.sendall(b"Q" + struct.pack("!I", len(body) + 4) + body)
    rows = []
    while True:
        tag, body = read_msg(s)
        if tag == b'D':
            n = struct.unpack("!H", body[:2])[0]
            vals, pos = [], 2
            for _ in range(n):
                (ln,) = struct.unpack("!I", body[pos:pos + 4]); pos += 4
                vals.append(body[pos:pos + ln].decode() if ln >= 0 else None)
                pos += max(ln, 0)
            rows.append(vals)
        elif tag == b'C':
            print(f"   [{label}] {sql} -> {body.split(bytes([0]))[0].decode()}")
        elif tag == b'E':
            code, msg, p = "", "", 0
            while p < len(body) and body[p] != 0:
                f = chr(body[p]); p += 1
                end = body.index(b"\0", p)
                v = body[p:end].decode(); p = end + 1
                if f == 'C': code = v
                if f == 'M': msg = v
            print(f"   [{label}] {sql} -> ErrorResponse [{code}] {msg}")
        elif tag == b'Z':
            print(f"   [{label}] ReadyForQuery '{body.decode()}' ({len(rows)} row(s): {rows})")
            return rows

a = connect("connection A")
b = connect("connection B")
q(a, "CREATE TABLE v7_users (id, name, city)", "A")
print("-- parser: one INSERT, two rows at once:")
q(a, "INSERT INTO v7_users VALUES (1, 'Sanjay', 'Delhi'), (2, 'Asha', 'Mumbai')", "A")
print("-- parser: column list in a different order than the table:")
q(a, "INSERT INTO v7_users (city, name, id) VALUES ('Jaipur', 'Vikram', 3)", "A")
print("-- auto-vacuum: UPDATE the same row 3 times (3 dead versions);")
print("   the background thread prunes them every 2s — wait 3s, then read:")
q(a, "UPDATE v7_users SET city = 'Pune' WHERE id = 1", "A")
q(a, "UPDATE v7_users SET city = 'Agra' WHERE id = 1", "A")
q(a, "UPDATE v7_users SET city = 'Delhi' WHERE id = 1", "A")
time.sleep(3)
print("   (auto-vacuum ticked at least once by now — the row still reads 'Delhi')")
q(b, "SELECT * FROM v7_users WHERE id = 1", "B")
print("-- live snapshot safety: A BEGINs and UPDATEs; B must still see")
print("   the old value even after the auto-vacuum ticks again:")
q(a, "BEGIN", "A")
q(a, "UPDATE v7_users SET city = 'Goa' WHERE id = 1", "A")
time.sleep(3)
q(b, "SELECT * FROM v7_users WHERE id = 1", "B")
q(a, "SELECT * FROM v7_users WHERE id = 1", "A")
q(a, "COMMIT", "A")
q(b, "SELECT * FROM v7_users WHERE id = 1", "B")
print("-- parser: ORDER BY + LIMIT, multi-condition WHERE, multi-SET UPDATE:")
q(a, "SELECT * FROM v7_users ORDER BY id DESC LIMIT 2", "A")
q(a, "SELECT name FROM v7_users WHERE city = 'Goa' AND id = 1", "A")
q(a, "UPDATE v7_users SET city = 'Indore', name = 'Asha2' WHERE id = 2 AND city = 'Mumbai'", "A")
q(a, "SELECT * FROM v7_users WHERE id = 2", "A")
print("-- savepoints: BEGIN, INSERT, SAVEPOINT, INSERT, ROLLBACK TO, SELECT:")
q(a, "BEGIN", "A")
q(a, "INSERT INTO v7_users VALUES (4, 'Meera', 'Pune')", "A")
q(a, "SAVEPOINT sp1", "A")
q(a, "INSERT INTO v7_users VALUES (5, 'Kiran', 'Goa')", "A")
q(a, "ROLLBACK TO SAVEPOINT sp1", "A")
q(a, "SELECT * FROM v7_users", "A")
q(a, "RELEASE SAVEPOINT sp1", "A")
q(a, "ROLLBACK TO SAVEPOINT sp1", "A")
q(a, "COMMIT", "A")
q(b, "SELECT * FROM v7_users", "B")
print("-- honest errors: bad SQL gets a line/column, JOIN gets 'not supported':")
q(a, "SELECT * FROM v7_users WHERE city =", "A")
q(a, "SELECT * FROM v7_users JOIN other ON v7_users.id = other.id", "A")
a.sendall(b"X" + struct.pack("!I", 4)); a.close()
b.sendall(b"X" + struct.pack("!I", 4)); b.close()
print("V0.7 demo done")
PYEOF
kill $SERVER4 || true
wait $SERVER4 2>/dev/null || true
rm -rf ./demo-data-v7

say "14. GRACEFUL SHUTDOWN + BENCH (V0.8)"
echo "(a server writes two rows, gets SIGTERM, and must exit 0"
echo " after flushing + saving meta.json — which does not exist"
echo " before the signal. A restart then reads the rows back."
echo " Then 'zeno bench' prints real measured numbers.)"
rm -rf ./demo-data-v8
$ZENO --data ./demo-data-v8 serve --port 5437 --no-auto-vacuum > ./demo-v8-server.log 2>&1 &
SERVER5=$!
sleep 1
python3 - <<'PYEOF'
import socket, struct

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

s = socket.create_connection(("127.0.0.1", 5437))
params = b"user\0zeno\0database\0zeno\0\0"
body = struct.pack("!I", 196608) + params
s.sendall(struct.pack("!I", len(body) + 4) + body)
while True:
    tag, _ = read_msg(s)
    if tag == b'Z':
        break

def q(sql):
    body = sql.encode() + b"\0"
    s.sendall(b"Q" + struct.pack("!I", len(body) + 4) + body)
    rows = []
    while True:
        tag, b = read_msg(s)
        if tag == b'Z':
            break
        if tag == b'D':
            (ncols,) = struct.unpack("!h", b[:2])
            pos, vals = 2, []
            for _ in range(ncols):
                (ln,) = struct.unpack("!i", b[pos:pos+4])
                pos += 4
                vals.append(None if ln < 0 else b[pos:pos+ln].decode())
                pos += max(ln, 0)
            rows.append(vals)
        elif tag == b'C':
            print(f"   {sql} -> {b[:-1].decode()}")
    return rows

q("CREATE TABLE v8_t (id, name)")
q("INSERT INTO v8_t VALUES (1, 'Sanjay')")
q("INSERT INTO v8_t VALUES (2, 'Asha')")
print("   SELECT * FROM v8_t ->", q("SELECT * FROM v8_t"))
s.sendall(b"X" + struct.pack("!I", 4))
s.close()
print("   client disconnected")
PYEOF
if [ -f ./demo-data-v8/meta.json ]; then
  echo "ERROR: meta.json already exists before the shutdown (it should not)"
  exit 1
fi
echo "(no meta.json yet — the server only saves it on shutdown)"
echo "-- SIGTERM to the server (pid $SERVER5):"
kill -TERM $SERVER5
wait $SERVER5
echo "(server exit code: $? — 0 means graceful shutdown)"
echo "-- server log:"
cat ./demo-v8-server.log
echo "-- meta.json now exists (saved by the shutdown):"
ls -l ./demo-data-v8/meta.json
echo "-- restart the server and read the rows back:"
$ZENO --data ./demo-data-v8 serve --port 5437 --no-auto-vacuum > ./demo-v8-server2.log 2>&1 &
SERVER6=$!
sleep 1
python3 - <<'PYEOF'
import socket, struct

def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf

def read_msg(s):
    tag = recvn(s, 1)
    (ln,) = struct.unpack("!I", recvn(s, 4))
    return tag, recvn(s, ln - 4)

s = socket.create_connection(("127.0.0.1", 5437))
params = b"user\0zeno\0database\0zeno\0\0"
body = struct.pack("!I", 196608) + params
s.sendall(struct.pack("!I", len(body) + 4) + body)
while True:
    tag, _ = read_msg(s)
    if tag == b'Z':
        break
body = b"SELECT * FROM v8_t\0"
s.sendall(b"Q" + struct.pack("!I", len(body) + 4) + body)
rows = []
while True:
    tag, b = read_msg(s)
    if tag == b'Z':
        break
    if tag == b'D':
        (ncols,) = struct.unpack("!h", b[:2])
        pos, vals = 2, []
        for _ in range(ncols):
            (ln,) = struct.unpack("!i", b[pos:pos+4])
            pos += 4
            vals.append(None if ln < 0 else b[pos:pos+ln].decode())
            pos += max(ln, 0)
        rows.append(vals)
print("   rows after restart:", rows)
s.sendall(b"X" + struct.pack("!I", 4))
s.close()
PYEOF
kill -TERM $SERVER6
wait $SERVER6
echo "(second server also exited 0)"
rm -rf ./demo-data-v8 ./demo-v8-server.log ./demo-v8-server2.log

say "14b. BENCH (V0.8) — Zeno's own engine, this machine only"
echo "(fresh temp dir, removed afterwards; no PostgreSQL/MongoDB"
echo " comparison — neither is installed here.)"
$ZENO bench --rows 100,1000


echo
echo "PostgreSQL demo done. Try it yourself with psql (on a machine that has it):"
echo "  ./target/release/zeno --data $DATA serve --port 5433"
echo "  psql -h 127.0.0.1 -p 5433 -U zeno -d zeno   # no password (trust auth, local only)"
echo "  (with a password set: PGPASSWORD=<password> psql -h 127.0.0.1 -p 5433 -U sanjay -d zeno)"
echo
echo "Demo done. Data directory kept at: $DATA"
echo "Note: the torn line stays in $DATA/wal.log, so later opens will"
echo "keep warning about it (same line number) until a flush rewrites"
echo "the WAL — but the lifetime total in stats counts that line once,"
echo "not once per open, and a flush does not erase the total."
echo "Try it yourself: ./target/release/zeno --data $DATA stats"

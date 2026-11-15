#!/usr/bin/env bash
# demo.sh — Zeno V0.3 end-to-end demo.
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

say "3. JSON DOCUMENT — put / get / find (linear scan in V0.3)"
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
echo
echo "PostgreSQL demo done. Try it yourself with psql (on a machine that has it):"
echo "  ./target/release/zeno --data $DATA serve --port 5433"
echo "  psql -h 127.0.0.1 -p 5433 -U zeno -d zeno   # no password (trust auth, local only)"
echo
echo "Demo done. Data directory kept at: $DATA"
echo "Note: the torn line stays in $DATA/wal.log, so later opens will"
echo "keep warning about it (same line number) until a flush rewrites"
echo "the WAL — but the lifetime total in stats counts that line once,"
echo "not once per open, and a flush does not erase the total."
echo "Try it yourself: ./target/release/zeno --data $DATA stats"

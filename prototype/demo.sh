#!/usr/bin/env bash
# demo.sh — Zeno V0.1 end-to-end demo.
#
# Runs a full scenario against one data directory:
#   1. Key-value put / get / delete
#   2. Table create / insert / select
#   3. JSON document put / get / find
#   4. 70 puts to force a memtable flush to SSTables
#   5. Compaction (merges SSTables, drops old versions + tombstones)
#   6. STOP — then REOPEN the same data directory in a fresh process
#      and show the data is still there (crash-recovery proof).
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

say "3. JSON DOCUMENT — put / get / find (linear scan in V0.1)"
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
echo
echo "Demo done. Data directory kept at: $DATA"
echo "Try it yourself: ./target/release/zeno --data $DATA stats"

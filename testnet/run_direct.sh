#!/usr/bin/env bash
# run_direct.sh — Step 1 S1 direct-LAN measurement inside two isolated namespaces.
#
# Runs the Windows-built spike binary (the WSL kernel is shared) so the same artifact
# that ships is what gets measured. Serve in ns_a, dial from ns_b, collect NDJSON.
#
# Usage: sudo bash testnet/run_direct.sh <rounds> <outdir>
set -euo pipefail

ROUNDS=${1:-10}
OUT=${2:-/tmp/s1}
BIN=/root/s1target/release/iroh-offline

mkdir -p "$OUT"
rm -f "$OUT"/direct-serve.ndjson "$OUT"/direct-dial.ndjson

# 1. Start the listener and wait for its "listening" line.
ip netns exec splice-a "$BIN" serve --rounds "$ROUNDS" \
    >"$OUT/direct-serve.ndjson" 2>"$OUT/direct-serve.err" &
SERVE_PID=$!

for _ in $(seq 1 100); do
    if grep -q '"event":"listening"' "$OUT/direct-serve.ndjson" 2>/dev/null; then break; fi
    if ! kill -0 "$SERVE_PID" 2>/dev/null; then
        echo "SERVE_DIED"; cat "$OUT/direct-serve.err"; exit 1
    fi
    sleep 0.1
done

LISTEN=$(grep -m1 '"event":"listening"' "$OUT/direct-serve.ndjson")
ID=$(printf '%s' "$LISTEN" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
PORT=$(printf '%s' "$LISTEN" | sed -n 's/.*"sockets":\["\([^"]*\)".*/\1/p' | sed 's/.*://')
echo "LISTENING id=$ID port=$PORT"

# 2. Dial from the other namespace, IPv4 direct address only.
set +e
ip netns exec splice-b "$BIN" dial --id "$ID" --addr "10.200.0.1:$PORT" --rounds "$ROUNDS" \
    >"$OUT/direct-dial.ndjson" 2>"$OUT/direct-dial.err"
DIAL_RC=$?
set -e

wait "$SERVE_PID" 2>/dev/null || true

echo "DIAL_RC=$DIAL_RC"
echo "--- dial output ---"
cat "$OUT/direct-dial.ndjson"
if [ -s "$OUT/direct-dial.err" ]; then echo "--- dial stderr ---"; cat "$OUT/direct-dial.err"; fi
echo "--- serve output ---"
cat "$OUT/direct-serve.ndjson"
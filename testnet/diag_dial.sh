#!/usr/bin/env bash
# Diagnose a dial failure: server debug logs + a packet check, inside the namespaces.
set -euo pipefail
BIN=/root/s1target/release/iroh-offline
OUT=/tmp/s1
mkdir -p "$OUT"

ip netns exec splice-a env RUST_LOG=iroh=trace "$BIN" serve --rounds 1 \
    >"$OUT/d-serve.json" 2>"$OUT/d-serve.err" &
SP=$!
for _ in $(seq 1 100); do
    grep -q listening "$OUT/d-serve.json" 2>/dev/null && break; sleep 0.1
done
ID=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$OUT/d-serve.json" | tail -1)
PORT=$(sed -n 's/.*"sockets":\["\([^"]*\)".*/\1/p' "$OUT/d-serve.json" | sed 's/.*://')
echo "id=$ID port=$PORT"

ss -lunp | grep "$PORT" || echo "no listener on $PORT"

timeout 20 ip netns exec splice-b env RUST_LOG=iroh=trace "$BIN" dial \
    --id "$ID" --addr "10.200.0.1:$PORT" --rounds 1 \
    >"$OUT/d-dial.json" 2>"$OUT/d-dial.err" || echo "DIAL_FAILED rc=$?"

kill $SP 2>/dev/null || true
echo "=== dial tail ==="
tail -25 "$OUT/d-dial.err"
echo "=== serve tail ==="
tail -25 "$OUT/d-serve.err"
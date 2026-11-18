#!/usr/bin/env bash
# mdns_host_bench.sh — 30 cold-start discovery runs on WSL2's default interface.
#
# Each iteration: fresh advertiser process, fresh probe process, so the number is the
# cold-start case. Also checks that the announced base32 label decodes back to the NodeId,
# which is what makes it a leak rather than just a random string.
set -euo pipefail
BIN=/root/s1target/release/iroh-offline
OUT=/root/s1out
SVC=splice-s1
mkdir -p "$OUT"
: >"$OUT/h-mdns.ndjson"

for i in $(seq 1 30); do
    "$BIN" mdns-serve --service "$SVC" >"$OUT/hb-serve.json" 2>/dev/null &
    SP=$!
    for _ in $(seq 1 100); do
        grep -q listening "$OUT/hb-serve.json" 2>/dev/null && break
        sleep 0.05
    done
    ID=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$OUT/hb-serve.json" | tail -1)
    START=$(date +%s%N)
    timeout 25 "$BIN" mdns-probe --id "$ID" --service "$SVC" --timeout-secs 20 \
        >"$OUT/hb-probe.json" 2>/dev/null || true
    END=$(date +%s%N)
    WALL=$(( (END - START) / 1000000 ))
    FOUND=$(grep -c '"found":true' "$OUT/hb-probe.json" 2>/dev/null || true)
    APPEAR=$(sed -n 's/.*"appear_ms":\([0-9.]*\).*/\1/p' "$OUT/hb-probe.json" | tail -1)
    echo "{\"iter\":$i,\"found\":${FOUND:-0},\"wall_ms\":$WALL,\"appear_ms\":${APPEAR:-null}}" \
        >>"$OUT/h-mdns.ndjson"
    kill $SP 2>/dev/null || true
    wait $SP 2>/dev/null || true
    sleep 0.2
done

echo "=== appear_ms (cold start, 30 runs, WSL2 eth0) ==="
bash /mnt/c/EXPERIMENT/Splice/testnet/stats.sh appear_ms "$OUT/h-mdns.ndjson"
echo "=== found=true count ==="
grep -c '"found":1' "$OUT/h-mdns.ndjson" || echo 0

echo "=== is the announced label the NodeId? (base32 decode) ==="
LABEL=$(sed -n 's/.*"base32_label":"\([^"]*\)".*/\1/p' "$OUT/h-serve.json" | tail -1)
ID=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$OUT/h-serve.json" | tail -1)
python3 - "$LABEL" "$ID" <<'PY'
import sys
label, nodeid = sys.argv[1], sys.argv[2]
alpha = "abcdefghijklmnopqrstuvwxyz234567"
buf = bits = 0
out = bytearray()
for ch in label:
    buf = (buf << 5) | alpha.index(ch)
    bits += 5
    if bits >= 8:
        bits -= 8
        out.append((buf >> bits) & 0xFF)
print("label          :", label)
print("decoded hex    :", out.hex())
print("node id        :", nodeid)
print("LABEL_IS_NODEID:", out.hex() == nodeid)
PY
#!/usr/bin/env bash
# mdns_host.sh — does `swarm-discovery` announce/browse at all on WSL2's default interface?
#
# Run *outside* the namespaces: the namespace run showed "Network is unreachable" because
# there is no default route, which may be a swarm-discovery implementation limit rather
# than a multicast problem. This isolates the two.
#
# Also captures packets so the NodeId-leak question (§5.3) can be answered from bytes,
# not from reading the source alone.
set -euo pipefail
BIN=/root/s1target/release/iroh-offline
OUT=/root/s1out
SVC=splice-s1
mkdir -p "$OUT"

echo "=== interfaces ==="
ip -br addr

echo "=== start advertiser ==="
"$BIN" mdns-serve --service "$SVC" >"$OUT/h-serve.json" 2>"$OUT/h-serve.err" &
SP=$!
for _ in $(seq 1 100); do
    grep -q listening "$OUT/h-serve.json" 2>/dev/null && break
    sleep 0.1
done
ID=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$OUT/h-serve.json" | tail -1)
LABEL=$(sed -n 's/.*"base32_label":"\([^"]*\)".*/\1/p' "$OUT/h-serve.json" | tail -1)
echo "id=$ID"
echo "expected instance label=$LABEL"

echo "=== packet capture on eth0 (5353) ==="
timeout 12 tcpdump -i eth0 -n -s0 -w "$OUT/mdns.pcap" 'udp port 5353' \
    >"$OUT/tcpdump.log" 2>&1 &
TCP=$!
sleep 1

echo "=== probe (fresh process) ==="
START=$(date +%s%N)
timeout 25 "$BIN" mdns-probe --id "$ID" --service "$SVC" --timeout-secs 20 \
    >"$OUT/h-probe.json" 2>"$OUT/h-probe.err" || echo "PROBE_RC=$?"
END=$(date +%s%N)
echo "PROBE_WALL_MS=$(( (END - START) / 1000000 ))"
cat "$OUT/h-probe.json" || true

wait $TCP 2>/dev/null || true
kill $SP 2>/dev/null || true
wait $SP 2>/dev/null || true

echo "=== capture size ==="
ls -la "$OUT/mdns.pcap" 2>/dev/null || echo "NO_PCAP"
echo "=== does any 5353 packet contain the instance label? ==="
if [ -s "$OUT/mdns.pcap" ]; then
    if strings "$OUT/mdns.pcap" | grep -qF "$LABEL"; then
        echo "NODE_ID_VISIBLE: base32 label found in cleartext"
    else
        echo "node_id_label_absent_from_capture"
    fi
    echo "--- qnames seen ---"
    strings "$OUT/mdns.pcap" | grep -i "local" | sort -u | head -20
fi
echo "=== advertiser warnings ==="
grep -c "error sending mDNS" "$OUT/h-serve.err" 2>/dev/null || echo 0
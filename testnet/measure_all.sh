#!/usr/bin/env bash
# measure_all.sh — run every Step-1 S1 measurement in one WSL session.
#
# WSL tears the distro down between separate invocations, which drops network
# namespaces, so up/measure/down must happen in a single process tree.
#
# Usage: sudo bash testnet/measure_all.sh
set -euo pipefail

OUT=/root/s1out
BIN=/root/s1target/release/iroh-offline
mkdir -p "$OUT"

echo "=== 1. namespaces up ==="
bash /mnt/c/EXPERIMENT/Splice/testnet/netns_up.sh >"$OUT/netns_up.txt" 2>&1
tail -2 "$OUT/netns_up.txt"

echo "=== 2. no-internet proof ==="
{
  echo "# default route must be absent"
  ip -n splice-a route | grep -c default || echo "no-default-route ns_a OK"
  ip -n splice-b route | grep -c default || echo "no-default-route ns_b OK"
  echo "# off-link reachability must fail"
  ip netns exec splice-a timeout 5 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 \
    && echo "PING_1.1.1.1_OK (unexpected)" || echo "PING_1.1.1.1_FAIL (expected)"
  ip netns exec splice-a timeout 5 getent hosts relay.iroh.link >/dev/null 2>&1 \
    && echo "DNS_RESOLVE_OK (unexpected)" || echo "DNS_RESOLVE_FAIL (expected)"
} >"$OUT/offline_proof.txt" 2>&1
cat "$OUT/offline_proof.txt"

echo "=== 3. direct LAN, 30 rounds ==="
bash /mnt/c/EXPERIMENT/Splice/testnet/run_direct.sh 30 "$OUT" >"$OUT/direct_summary.txt" 2>&1
bash /mnt/c/EXPERIMENT/Splice/testnet/stats.sh connect_ms "$OUT/direct-dial.ndjson" \
  | tee "$OUT/direct_stats.txt"
bash /mnt/c/EXPERIMENT/Splice/testnet/stats.sh rtt_ms "$OUT/direct-dial.ndjson" \
  | tee -a "$OUT/direct_stats.txt"

echo "=== 4. relay probe (relay preset, offline) ==="
set +e
ip netns exec splice-a timeout 90 "$BIN" relay-probe --timeout-secs 20 \
  >"$OUT/relay.ndjson" 2>"$OUT/relay.err"
echo "RELAY_PROBE_RC=$?" | tee "$OUT/relay_summary.txt"
set -e
cat "$OUT/relay.ndjson" | tee -a "$OUT/relay_summary.txt"

echo "=== 5. keys ==="
set +e
ip netns exec splice-a timeout 40 "$BIN" keys --dir /root/s1out/keys \
  >"$OUT/keys.ndjson" 2>"$OUT/keys.err"
echo "KEYS_RC=$?" | tee "$OUT/keys_summary.txt"
set -e
cat "$OUT/keys.ndjson" | tee -a "$OUT/keys_summary.txt"

echo "=== 6. alpn ==="
set +e
ip netns exec splice-a timeout 60 "$BIN" alpn >"$OUT/alpn.ndjson" 2>"$OUT/alpn.err"
echo "ALPN_RC=$?" | tee "$OUT/alpn_summary.txt"
set -e
cat "$OUT/alpn.ndjson" | tee -a "$OUT/alpn_summary.txt"

echo "=== 7. mdns cold-start, 30 iterations ==="
# A fresh serving process per iteration, so this measures discovery cold start
# (publish + one lookup window), not a warm cache.
: >"$OUT/mdns.ndjson"
for i in $(seq 1 30); do
  ip netns exec splice-a timeout 30 "$BIN" mdns-serve --service splice-s1 \
      >"$OUT/mdns-serve-$i.json" 2>"$OUT/mdns-serve-$i.err" &
  SP=$!
  for _ in $(seq 1 100); do
    grep -q listening "$OUT/mdns-serve-$i.json" 2>/dev/null && break
    sleep 0.1
  done
  ID=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$OUT/mdns-serve-$i.json" | tail -1)
  RSTART=$(date +%s%N)
  ip netns exec splice-b timeout 30 "$BIN" mdns-probe --id "$ID" --service splice-s1 \
      --timeout-secs 25 >"$OUT/mdns-probe-$i.json" 2>"$OUT/mdns-probe-$i.err" || true
  REND=$(date +%s%N)
  DISCOVERED=$(grep -c '"event":"mdns_appear".*"found":true\|"found":true' "$OUT/mdns-probe-$i.json" 2>/dev/null || true)
  DISCOVERED=${DISCOVERED:-0}
  WALL=$(( (REND - RSTART) / 1000000 ))
  APPEAR=$(sed -n 's/.*"appear_ms":\([0-9.]*\).*/\1/p' "$OUT/mdns-probe-$i.json" | tail -1)
  echo "{\"iter\":$i,\"discovered\":$DISCOVERED,\"wall_ms\":$WALL,\"appear_ms\":${APPEAR:-null}}" >>"$OUT/mdns.ndjson"
  kill $SP 2>/dev/null || true
  wait $SP 2>/dev/null || true
done
bash /mnt/c/EXPERIMENT/Splice/testnet/stats.sh wall_ms "$OUT/mdns.ndjson" \
  | tee "$OUT/mdns_stats.txt"

echo "=== 8. teardown ==="
bash /mnt/c/EXPERIMENT/Splice/testnet/netns_down.sh >"$OUT/netns_down.txt" 2>&1
echo "DONE"
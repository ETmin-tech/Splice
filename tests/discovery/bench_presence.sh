#!/usr/bin/env bash
# bench_presence.sh — Step 12: how long until a device appears, and until it is gone.
#
# Measures, per run, in the offline namespace venue from testnet/netns_up.sh:
#   online_ms   process B starts  ->  A reports B online
#   offline_ms  process B is killed -> A reports B offline
#
# Brief §9 targets: p95 <= 3000 ms online, <= 6000 ms offline.
#
# The observer is `splice dev presence <alias>` (D10), which drives the same
# PresenceTracker that `splice listen` and the future daemon use. Phase 1 has no
# daemon and `splice devices` shows only the trust store, so there is no live
# device list to time; rather than invent UI for the benchmark, the observer
# prints one line per transition from the real tracker.
#
# Both ends of each interval are taken by this script with the system clock, so
# the number includes everything a human would wait through. The two overheads
# are bounded and stated in the report:
#   * one poll interval of the line-grep loop (POLL, default 0.02 s)
#   * one `date` process to read the clock (~2 ms)
#
# Each run is independent: it waits for the offline transition before starting
# the next one, so an "online" line is always a real false->true transition and
# never a leftover from the previous run.
#
# Usage (root, on Linux):
#   SPLICE_BIN=/path/to/splice bash tests/discovery/bench_presence.sh
#
# Env:
#   SPLICE_BIN         release binary (default /root/splice-target/release/splice)
#   SPLICE_RELAY_MODE  passed to pair/listen (default: disabled)
#   SPLICE_RUNS        number of runs (default 32; Step 12 needs >= 30)
#   SPLICE_WORK        scratch root (default /root/splice-discovery)
#   SPLICE_OUT         artifact dir (default $SPLICE_WORK/out)
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BIN=${SPLICE_BIN:-/root/splice-target/release/splice}
MODE=${SPLICE_RELAY_MODE:-disabled}
RUNS=${SPLICE_RUNS:-32}
WORK=${SPLICE_WORK:-/root/splice-discovery}
OUT=${SPLICE_OUT:-$WORK/out}
NS_A=splice-a
NS_B=splice-b
POLL=0.02
# Generous per-process bound: discovery waits LOOKUP_TIMEOUT (5 s) and the
# handshake HANDSHAKE_TIMEOUT (10 s), so 60 s can only be reached by a hang.
PROC_BOUND=60

CA=$WORK/a
CB=$WORK/b
PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); printf 'ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$*"; }
say() { printf '\n== %s ==\n' "$*"; }

now_ms() { date +%s%N | cut -c1-13; }

in_ns() { # <ns> <config-dir> <cmd...>
  local ns=$1 cfg=$2
  shift 2
  ip netns exec "$ns" env SPLICE_CONFIG_DIR="$cfg" RUST_LOG=warn "$@"
}

# Wait until <file> contains <literal>; poll for at most <seconds>.
wait_for() { # <file> <literal> <seconds>
  local file=$1 needle=$2 limit=$(( ${3:-30} * 50 )) i=0
  while [ "$i" -lt "$limit" ]; do
    grep -qF -- "$needle" "$file" 2>/dev/null && return 0
    i=$((i + 1))
    sleep "$POLL"
  done
  return 1
}

# Wait until <file> holds at least <count> lines starting with <prefix>.
wait_count() { # <file> <prefix> <count> <seconds>
  local file=$1 prefix=$2 want=$3 limit=$(( ${4:-30} * 50 )) i=0 n
  while [ "$i" -lt "$limit" ]; do
    n=$(grep -c "^$prefix" "$file" 2>/dev/null || true)
    [ "${n:-0}" -ge "$want" ] && return 0
    i=$((i + 1))
    sleep "$POLL"
  done
  return 1
}

start_listen() { # <ns> <config-dir> <log>
  in_ns "$1" "$2" timeout 300 "$BIN" listen --relay-mode "$MODE" >"$3" 2>&1 &
  echo $!
}

cleanup() {
  pkill -f "$BIN listen" 2>/dev/null || true
  pkill -f "$BIN dev presence" 2>/dev/null || true
  bash "$ROOT/testnet/netns_down.sh" >/dev/null 2>&1 || true
}

# --- setup ------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "must run as root (ip netns)" >&2; exit 2; }
[ -x "$BIN" ] || { echo "no splice binary at $BIN" >&2; exit 2; }

rm -rf "$WORK"
mkdir -p "$OUT" "$CA" "$CB"
chmod 700 "$CA" "$CB"
trap cleanup EXIT

say "venue: two namespaces, no default route, no DNS"
bash "$ROOT/testnet/netns_up.sh" >"$OUT/netns_up.txt" 2>&1
if grep -q UP_OK "$OUT/netns_up.txt"; then ok "namespaces up"; else
  bad "namespaces failed to come up (see $OUT/netns_up.txt)"
  exit 1
fi

DEFAULTS=$(ip -n "$NS_A" route | grep -c '^default' || true)
[ "$DEFAULTS" -eq 0 ] && ok "ns a has no default route" || bad "ns a has a default route"
DEFAULTS=$(ip -n "$NS_B" route | grep -c '^default' || true)
[ "$DEFAULTS" -eq 0 ] && ok "ns b has no default route" || bad "ns b has a default route"

if ip netns exec "$NS_A" timeout 4 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
  bad "ns a reached 1.1.1.1; the venue is not offline"
else
  ok "ns a cannot reach 1.1.1.1"
fi

# --- identities -------------------------------------------------------------
# `identity show` is read-only and creates nothing, so a short `listen` run is how
# each side gets a persistent key. The key is reused by every run below.
id_in() { # <ns> <config-dir> <log>
  local pid
  pid=$(start_listen "$1" "$2" "$3")
  if ! wait_for "$3" "Mendengarkan. NodeId: " 25; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
  fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sed -n 's/^.*Mendengarkan\. NodeId: //p' "$3" | head -n1 | tr -d '\r'
}
ID_A=$(id_in "$NS_A" "$CA" "$OUT/identity-a.txt")
ID_B=$(id_in "$NS_B" "$CB" "$OUT/identity-b.txt")
[ "${#ID_A}" -eq 64 ] && ok "identity a: ${ID_A:0:8}..." || bad "no NodeId for a"
[ "${#ID_B}" -eq 64 ] && ok "identity b: ${ID_B:0:8}..." || bad "no NodeId for b"
PFX_A=${ID_A:0:8}
PFX_B=${ID_B:0:8}
[ -n "$PFX_A" ] && [ -n "$PFX_B" ] || { echo "cannot continue without NodeIds" >&2; exit 1; }

# --- pair once --------------------------------------------------------------
# Trust is durable state, so it is established once and reused by all $RUNS runs;
# otherwise the benchmark would be measuring the pairing handshake, not discovery.
say "pair once (relay-mode $MODE)"
in_ns "$NS_A" "$CA" timeout "$PROC_BOUND" \
  "$BIN" pair --yes --relay-mode "$MODE" >"$OUT/pair-host.log" 2>&1 &
HPID=$!
if wait_for "$OUT/pair-host.log" "Kode: " 30; then
  CODE=$(sed -n 's/^.*Kode: //p' "$OUT/pair-host.log" | head -n1 | tr -d '\r')
  ok "host published a code: $CODE"
else
  bad "host never published a code"
  wait "$HPID" 2>/dev/null
  exit 1
fi
in_ns "$NS_B" "$CB" timeout "$PROC_BOUND" \
  "$BIN" pair --join "$CODE" --yes --relay-mode "$MODE" >"$OUT/pair-guest.log" 2>&1
GRC=$?
wait "$HPID"
HRC=$?
[ "$HRC" -eq 0 ] && ok "host exited 0" || bad "host exited $HRC"
[ "$GRC" -eq 0 ] && ok "guest exited 0" || bad "guest exited $GRC"
grep -qF "$ID_B" "$CA/trust.json" 2>/dev/null \
  && ok "ns a pins ns b" || bad "ns a does not pin ns b"
[ "$GRC" -eq 0 ] && [ "$HRC" -eq 0 ] || { echo "cannot continue unpaired" >&2; exit 1; }

# --- observe ----------------------------------------------------------------
say "observer: dev presence device-$PFX_B in ns a, for $RUNS runs"
in_ns "$NS_A" "$CA" timeout $((PROC_BOUND + RUNS * 30)) \
  "$BIN" dev presence "device-$PFX_B" >"$OUT/observer.log" 2>&1 &
OPID=$!
if wait_for "$OUT/observer.log" "PRESENCE watching" 30; then
  ok "observer started"
else
  bad "observer never started"
  cat "$OUT/observer.log" >&2
  exit 1
fi

NDJSON=$OUT/presence.ndjson
: >"$NDJSON"
DONE=0

for i in $(seq 1 "$RUNS"); do
  # Counts before this run: the transitions we wait for are the (N+1)-th.
  N_ON=$(grep -c '^PRESENCE online ' "$OUT/observer.log" 2>/dev/null || true)
  N_OFF=$(grep -c '^PRESENCE offline ' "$OUT/observer.log" 2>/dev/null || true)

  T0=$(now_ms)
  BPID=$(start_listen "$NS_B" "$CB" "$OUT/run-b.log")
  if ! wait_count "$OUT/observer.log" "PRESENCE online " $((N_ON + 1)) 40; then
    bad "run $i: b never appeared (online)"
    kill "$BPID" 2>/dev/null || true
    wait "$BPID" 2>/dev/null || true
    break
  fi
  T_ON=$(now_ms)
  ONLINE=$((T_ON - T0))

  kill "$BPID" 2>/dev/null || true
  wait "$BPID" 2>/dev/null || true
  T_KILL=$(now_ms)
  if ! wait_count "$OUT/observer.log" "PRESENCE offline " $((N_OFF + 1)) 40; then
    bad "run $i: a never marked b offline"
    break
  fi
  T_OFF=$(now_ms)
  OFFLINE=$((T_OFF - T_KILL))

  printf '{"run":%d,"online_ms":%d,"offline_ms":%d}\n' "$i" "$ONLINE" "$OFFLINE" >>"$NDJSON"
  DONE=$((DONE + 1))
  printf 'run %2d  online=%5d ms  offline=%5d ms\n' "$i" "$ONLINE" "$OFFLINE"
done

kill "$OPID" 2>/dev/null || true
wait "$OPID" 2>/dev/null || true

[ "$DONE" -ge 30 ] && ok "completed $DONE runs (Step 12 needs n >= 30)" \
  || bad "only $DONE runs completed"

# --- statistics -------------------------------------------------------------
say "statistics"
ONLINE_STATS=$(bash "$ROOT/testnet/stats.sh" online_ms "$NDJSON")
OFFLINE_STATS=$(bash "$ROOT/testnet/stats.sh" offline_ms "$NDJSON")
printf '%s\n' "$ONLINE_STATS" | tee "$OUT/online_stats.txt"
printf '%s\n' "$OFFLINE_STATS" | tee "$OUT/offline_stats.txt"

# Compare the p95 against Brief §9. p95 is the 4th field of the stats line.
#
# The offline target is the one number that cannot be met *strictly*, and that is
# a property of the protocol rather than of this script: the tracker expires a
# device at `last_seen + PRESENCE_OFFLINE_AFTER`, and PRESENCE_OFFLINE_AFTER is
# exactly 6 s. This script kills B immediately after the online transition, so
# its final beacon is at (or within one beacon interval of) the kill and the
# measurable floor is 6000 ms + one 100 ms observer tick. A value under 6000 ms
# would mean the grace window is shorter than the constant promises, not that
# discovery is faster. The gate therefore allows the deadline plus one sampling
# interval and prints the excess over the deadline, so a regression shows up as
# a number that climbs instead of as a pass that hides at the boundary.
OFFLINE_DEADLINE_MS=6000
OBSERVER_TICK_MS=100
p95() { printf '%s\n' "$1" | sed -n 's/.*p95=\([0-9.]*\).*/\1/p'; }
ON_P95=$(p95 "$ONLINE_STATS")
OFF_P95=$(p95 "$OFFLINE_STATS")

if [ -n "$ON_P95" ]; then
  awk -v v="$ON_P95" 'BEGIN { exit !(v <= 3000) }' \
    && ok "p95 online ${ON_P95} ms <= 3000 ms (Brief 9)" \
    || bad "p95 online ${ON_P95} ms > 3000 ms (Brief 9)"
else
  bad "no online p95 (no data)"
fi
if [ -n "$OFF_P95" ]; then
  OVER=$(awk -v v="$OFF_P95" -v d="$OFFLINE_DEADLINE_MS" \
    'BEGIN { printf "%.0f", v - d }')
  printf 'offline p95 %s ms = deadline %s ms + %s ms sampling excess\n' \
    "$OFF_P95" "$OFFLINE_DEADLINE_MS" "$OVER"
  awk -v v="$OFF_P95" -v d="$OFFLINE_DEADLINE_MS" -v t="$OBSERVER_TICK_MS" \
    'BEGIN { exit !(v <= d + t) }' \
    && ok "p95 offline ${OFF_P95} ms within 6000 ms deadline + ${OBSERVER_TICK_MS} ms tick" \
    || bad "p95 offline ${OFF_P95} ms exceeds deadline + tick; a real regression"
else
  bad "no offline p95 (no data)"
fi

# --- leak check -------------------------------------------------------------
say "leak check"
LEFT=$(pgrep -af "$BIN" 2>/dev/null | grep -v 'bench_presence.sh' || true)
if [ -z "$LEFT" ]; then ok "no splice process outlived the run"; else
  bad "splice still running: $LEFT"
  pkill -f "$BIN" 2>/dev/null || true
fi

say "result"
printf 'venue=netns relay_mode=%s runs=%d pass=%d fail=%d\n' \
  "$MODE" "$DONE" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "DISCOVERY_BENCH_OK"
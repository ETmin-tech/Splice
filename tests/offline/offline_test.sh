#!/usr/bin/env bash
# offline_test.sh — Step 11: pair and ping with no internet at all.
#
# Venue: two network namespaces joined by a veth pair, no default route, no DNS
# (testnet/netns_up.sh). Every splice process below runs *inside* one namespace,
# so neither side can reach a relay, a DNS resolver, or the public internet.
#
# Phases, each asserted:
#   1. `splice pair`      (ns a)  <->  `splice pair --join CODE` (ns b)
#   2. `splice listen`    (ns a)  <->  `splice dev ping device-<id>` (ns b)
#
# Phase 2 finds ns a only through presence beacons, which is the discovery path
# that must work without a relay.
#
# Bounds: no process may outlive the handshake budget. Guest-side discovery can
# wait LOOKUP_TIMEOUT (5 s) and the handshake HANDSHAKE_TIMEOUT (10 s), so a
# 60 s `timeout` wrapper is generous; exit code 124 means it hung and is a
# failure, not a slow pass.
#
# Usage (root, on Linux):
#   SPLICE_BIN=/path/to/splice SPLICE_RELAY_MODE=disabled \
#       bash tests/offline/offline_test.sh
#
# Env:
#   SPLICE_BIN         release binary (default /root/splice-target/release/splice)
#   SPLICE_RELAY_MODE  `disabled` or `default` (default: disabled)
#   SPLICE_OUT         artifact dir (default /root/splice-offline/out)
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BIN=${SPLICE_BIN:-/root/splice-target/release/splice}
MODE=${SPLICE_RELAY_MODE:-disabled}
WORK=${SPLICE_WORK:-/root/splice-offline}
OUT=${SPLICE_OUT:-$WORK/out}
NS_A=splice-a
NS_B=splice-b
# Everything a process may take, with room for mDNS + handshake + teardown.
PROC_BOUND=60

CA=$WORK/a
CB=$WORK/b
PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf 'ok   %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$*"; }
say()  { printf '\n== %s ==\n' "$*"; }

now_ms() { date +%s%N | cut -c1-13; }

# Run a command in a namespace with its own config dir.
in_ns() { # <ns> <config-dir> <cmd...>
  local ns=$1 cfg=$2
  shift 2
  ip netns exec "$ns" env SPLICE_CONFIG_DIR="$cfg" RUST_LOG=warn "$@"
}

# Wait until <file> contains <literal>; poll for at most <seconds>.
wait_for() { # <file> <literal> <seconds>
  local file=$1 needle=$2 limit=$(( ${3:-30} * 10 )) i=0
  while [ "$i" -lt "$limit" ]; do
    grep -qF -- "$needle" "$file" 2>/dev/null && return 0
    i=$((i + 1))
    sleep 0.1
  done
  return 1
}

cleanup() {
  # A leftover listener is the one process that can outlive a phase.
  pkill -f "$BIN listen" 2>/dev/null || true
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

# Prove the venue is actually offline before trusting any result measured in it.
DEFAULTS=$(ip -n "$NS_A" route | grep -c '^default' || true)
[ "$DEFAULTS" -eq 0 ] && ok "ns a has no default route" || bad "ns a has a default route"
DEFAULTS=$(ip -n "$NS_B" route | grep -c '^default' || true)
[ "$DEFAULTS" -eq 0 ] && ok "ns b has no default route" || bad "ns b has a default route"

if ip netns exec "$NS_A" timeout 4 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
  bad "ns a reached 1.1.1.1; the venue is not offline"
else
  ok "ns a cannot reach 1.1.1.1"
fi
if ip netns exec "$NS_A" timeout 4 getent hosts relay.iroh.link >/dev/null 2>&1; then
  bad "ns a resolved a public name; the venue is not offline"
else
  ok "ns a cannot resolve public names"
fi

# --- identities -------------------------------------------------------------
# `identity show` is read-only: it reports that no key exists yet. The persistent
# key is created by `pair`/`listen`, so start a listener just long enough to
# learn each NodeId, then stop it. Both later phases reuse the key it wrote.
id_in() { # <ns> <config-dir> <log>
  in_ns "$1" "$2" timeout 30 "$BIN" listen >"$3" 2>&1 &
  local pid=$!
  if ! wait_for "$3" "👂 Mendengarkan. NodeId: " 25; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
  fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sed -n 's/^👂 Mendengarkan\. NodeId: //p' "$3" | head -n1 | tr -d '\r'
}
ID_A=$(id_in "$NS_A" "$CA" "$OUT/identity-a.txt")
ID_B=$(id_in "$NS_B" "$CB" "$OUT/identity-b.txt")
[ "${#ID_A}" -eq 64 ] && ok "identity a: ${ID_A:0:8}…" || bad "no NodeId for a"
[ "${#ID_B}" -eq 64 ] && ok "identity b: ${ID_B:0:8}…" || bad "no NodeId for b"
PFX_A=${ID_A:0:8}
PFX_B=${ID_B:0:8}
[ -n "$PFX_A" ] && [ -n "$PFX_B" ] || { echo "cannot continue without NodeIds" >&2; exit 1; }

# --- phase 1: pairing -------------------------------------------------------
say "phase 1: pair (relay-mode $MODE)"
T0=$(now_ms)
in_ns "$NS_A" "$CA" timeout "$PROC_BOUND" \
  "$BIN" pair --yes --relay-mode "$MODE" >"$OUT/pair-host.log" 2>&1 &
HPID=$!

if wait_for "$OUT/pair-host.log" "🔑 Kode: " 30; then
  CODE=$(sed -n 's/^🔑 Kode: //p' "$OUT/pair-host.log" | head -n1 | tr -d '\r')
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
T1=$(now_ms)

[ "$HRC" -eq 0 ] && ok "host exited 0" || bad "host exited $HRC"
[ "$GRC" -eq 0 ] && ok "guest exited 0" || bad "guest exited $GRC"
[ "$HRC" -eq 124 ] && bad "host exceeded ${PROC_BOUND}s (hung on an outbound attempt)"
[ "$GRC" -eq 124 ] && bad "guest exceeded ${PROC_BOUND}s (hung on an outbound attempt)"

grep -qF "device-$PFX_B" "$OUT/pair-host.log" \
  && ok "host stored device-$PFX_B" || bad "host did not store device-$PFX_B"
grep -qF "device-$PFX_A" "$OUT/pair-guest.log" \
  && ok "guest stored device-$PFX_A" || bad "guest did not store device-$PFX_A"

grep -qF "$ID_B" "$CA/trust.json" 2>/dev/null \
  && ok "ns a trust.json pins ns b" || bad "ns a trust.json does not pin ns b"
grep -qF "$ID_A" "$CB/trust.json" 2>/dev/null \
  && ok "ns b trust.json pins ns a" || bad "ns b trust.json does not pin ns a"

printf 'pair_ms=%s\n' "$((T1 - T0))"
[ $((T1 - T0)) -lt $((PROC_BOUND * 1000)) ] \
  && ok "pairing finished within the process bound" || bad "pairing took too long"

# --- phase 2: listen <-> dev ping -------------------------------------------
say "phase 2: listen <-> dev ping (relay-mode $MODE)"
T0=$(now_ms)
in_ns "$NS_A" "$CA" timeout 120 \
  "$BIN" listen --relay-mode "$MODE" >"$OUT/listen.log" 2>&1 &
LPID=$!

if wait_for "$OUT/listen.log" "👂 Mendengarkan." 30; then
  ok "listener announced presence"
else
  bad "listener never started"
  pkill -f "$BIN listen" 2>/dev/null || true
  exit 1
fi

in_ns "$NS_B" "$CB" timeout "$PROC_BOUND" \
  "$BIN" dev ping "device-$PFX_A" --relay-mode "$MODE" >"$OUT/ping.log" 2>&1
PRC=$?
T1=$(now_ms)

[ "$PRC" -eq 0 ] && ok "dev ping exited 0" || bad "dev ping exited $PRC"
[ "$PRC" -eq 124 ] && bad "dev ping exceeded ${PROC_BOUND}s (hung on an outbound attempt)"
grep -qF "✅ Pong dari device-$PFX_A" "$OUT/ping.log" \
  && ok "got a Pong over the trusted connection" || bad "no Pong in the ping log"
printf 'ping_ms=%s\n' "$((T1 - T0))"

pkill -f "$BIN listen" 2>/dev/null || true
wait "$LPID" 2>/dev/null || true

# --- nothing may outlive the phases ----------------------------------------
say "leak check"
LEFT=$(pgrep -af "$BIN" 2>/dev/null | grep -v 'offline_test.sh' || true)
if [ -z "$LEFT" ]; then ok "no splice process outlived the run"; else
  bad "splice still running: $LEFT"
  pkill -f "$BIN" 2>/dev/null || true
fi

say "result"
printf 'relay_mode=%s pass=%d fail=%d\n' "$MODE" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "OFFLINE_OK"
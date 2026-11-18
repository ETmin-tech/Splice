#!/usr/bin/env bash
# netns_up.sh — build two isolated namespaces joined by a veth pair.
#
# Properties (this is the "no internet" venue used by the offline test):
#   * ns_a 10.200.0.1/24, ns_b 10.200.0.2/24
#   * NO default route in either namespace
#   * NO DNS resolver reachable (no default route => nothing off-link is routable)
#   * loopback up, IPv4 multicast enabled on the veth ends
#
# Usage: sudo bash testnet/netns_up.sh
set -euo pipefail

A=splice-a
B=splice-b
VETH_A=splice-va
VETH_B=splice-vb

cleanup() {
  ip netns del "$A" 2>/dev/null || true
  ip netns del "$B" 2>/dev/null || true
  ip link del "$VETH_A" 2>/dev/null || true
}

cleanup

ip netns add "$A"
ip netns add "$B"

ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$A"
ip link set "$VETH_B" netns "$B"

ip -n "$A" link set lo up
ip -n "$B" link set lo up

ip -n "$A" addr add 10.200.0.1/24 dev "$VETH_A"
ip -n "$B" addr add 10.200.0.2/24 dev "$VETH_B"

ip -n "$A" link set "$VETH_A" up
ip -n "$B" link set "$VETH_B" up

# Explicitly guarantee "no internet": drop any default route the kernel added.
ip -n "$A" route del default 2>/dev/null || true
ip -n "$B" route del default 2>/dev/null || true

# Make sure multicast is on and the veth ends share one L2 segment for mDNS.
ip -n "$A" link set "$VETH_A" multicast on
ip -n "$B" link set "$VETH_B" multicast on

echo "== ns_a =="
ip -n "$A" -br addr
ip -n "$A" route
echo "== ns_b =="
ip -n "$B" -br addr
ip -n "$B" route
echo "UP_OK"
#!/usr/bin/env bash
# netns_down.sh — tear down the two test namespaces.
set -uo pipefail
ip netns del splice-a 2>/dev/null || true
ip netns del splice-b 2>/dev/null || true
ip link del splice-va 2>/dev/null || true
echo "DOWN_OK"
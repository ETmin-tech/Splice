#!/usr/bin/env bash
# build_linux.sh — build the spike as a *native Linux* binary inside WSL2.
#
# Why: the Windows-built `iroh-offline.exe` runs under WSL interop on the Windows
# network stack, so `ip netns exec` has no effect on it. Offline measurements must
# use a Linux build to actually live inside the namespace.
#
# Usage: sudo bash testnet/build_linux.sh
set -euo pipefail
export PATH=/root/.cargo/bin:$PATH
export CARGO_TARGET_DIR=/root/s1target
cd /mnt/c/EXPERIMENT/Splice/spikes/iroh-offline
cargo build --release
ls -la /root/s1target/release/iroh-offline
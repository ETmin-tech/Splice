#!/usr/bin/env bash
# stats.sh — p50/p95/max for one numeric field in NDJSON.
#
# Usage: bash testnet/stats.sh <metric> <file.ndjson>
set -euo pipefail
metric=${1:?metric name}
file=${2:?ndjson file}
python3 - "$metric" "$file" <<'PY'
import json, sys
key, path = sys.argv[1], sys.argv[2]
vals = []
with open(path, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            v = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(v, dict) and isinstance(v.get(key), (int, float)):
            vals.append(float(v[key]))
if not vals:
    print(f"{key}: NO_DATA")
    sys.exit(0)
vals.sort()
n = len(vals)
def pct(p):
    # nearest-rank: ceil(p/100 * n), 1-based
    import math
    idx = min(n - 1, max(0, math.ceil(p / 100.0 * n) - 1))
    return vals[idx]
print(f"{key}: n={n} min={vals[0]:.3f} p50={pct(50):.3f} p95={pct(95):.3f} "
      f"max={vals[-1]:.3f} mean={sum(vals)/n:.3f}")
PY
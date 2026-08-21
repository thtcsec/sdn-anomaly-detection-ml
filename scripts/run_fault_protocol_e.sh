#!/usr/bin/env bash
# Protocol E fault collection. Does not touch flow_stats.csv / 326k anomaly pool.
# Does not delete Protocol D dirs under dataset/fault_runs/.
set -euo pipefail
ROOT=/mnt/d/tu_projects/sdn-anomaly-detection-ml
cd "$ROOT"
export OSKEN_HUB_TYPE=eventlet
export PYTHONUNBUFFERED=1

mkdir -p "$ROOT/tmp" "$ROOT/dataset/fault_live"

if ss -lntp 2>/dev/null | grep -q ':6633'; then
  echo "[!] :6633 busy — not starting a second controller"
  ss -lntp | grep 6633 || true
  exit 1
fi

echo "[*] clean leftover mininet"
mn -c >/dev/null 2>&1 || true

echo "[*] start fault_monitor (venv, NO dist-packages PYTHONPATH)"
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"
setsid python "$ROOT/controller/run_fault_monitor.py" \
  > "$ROOT/tmp/fault_monitor_e.log" 2>&1 &
echo $! > "$ROOT/tmp/fault_monitor_e.pid"
for i in $(seq 1 40); do
  if ss -lntp 2>/dev/null | grep -q ':6633'; then
    echo "[✓] :6633 listening (${i}s)"
    break
  fi
  sleep 1
done
if ! ss -lntp 2>/dev/null | grep -q ':6633'; then
  echo "[!] :6633 not listening; log:"
  tail -40 "$ROOT/tmp/fault_monitor_e.log" || true
  exit 1
fi

echo "[*] collect Protocol E (Mininet PYTHONPATH=dist-packages only)"
# Default: 36 scenario × 3 × 75s. Override with extra args, e.g. --only EN_high,EB_2M_tu --repeat 1
exec sudo env PYTHONPATH=/usr/lib/python3/dist-packages PYTHONUNBUFFERED=1 \
  "$ROOT/.venv/bin/python" "$ROOT/src/collect_independent_fault_runs.py" --protocol e "$@"

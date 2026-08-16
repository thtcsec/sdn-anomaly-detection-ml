#!/usr/bin/env bash
# Full fault collection: 12 scenarios x 3 runs. Requires root + os-ken T1.
set -euo pipefail
ROOT=/mnt/d/tu_projects/sdn-anomaly-detection-ml
cd "$ROOT"
export OSKEN_HUB_TYPE=eventlet

echo "[*] clean mininet / leftover controller"
mn -c >/dev/null 2>&1 || true
pkill -f 'controller/run_fault_monitor.py' >/dev/null 2>&1 || true
pkill -f 'controller.fault_monitor' >/dev/null 2>&1 || true
sleep 2

if ss -lntp 2>/dev/null | grep -q ':6633'; then
  echo "[!] :6633 still busy"
  ss -lntp | grep 6633 || true
  exit 1
fi

echo "[*] start fault_monitor"
mkdir -p "$ROOT/tmp" "$ROOT/dataset/fault_live"
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"
nohup python "$ROOT/controller/run_fault_monitor.py" \
  > "$ROOT/tmp/fault_monitor.log" 2>&1 &
echo $! > "$ROOT/tmp/fault_monitor.pid"
sleep 6
if ! grep -q 'Listening OpenFlow\|Fault monitor\|tcp:6633' "$ROOT/tmp/fault_monitor.log"; then
  echo "[!] monitor did not print ready banner; tail:"
  tail -30 "$ROOT/tmp/fault_monitor.log" || true
fi

echo "[*] collect 12x3"
export PYTHONPATH=/usr/lib/python3/dist-packages:${PYTHONPATH:-}
/usr/bin/python3 "$ROOT/src/collect_independent_fault_runs.py" "$@"
echo "[*] merge"
"$ROOT/.venv/bin/python" "$ROOT/src/merge_fault_runs.py"
echo "[*] eval LOSO"
"$ROOT/.venv/bin/python" "$ROOT/src/eval_fault_loso.py" || true
echo "[✓] done"

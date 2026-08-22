#!/usr/bin/env bash
# Protocol D fault collect wrapper. Keep. Requires root + free :6633 (do not run during SOC demo).
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
export PYTHONUNBUFFERED=1
nohup python "$ROOT/controller/run_fault_monitor.py" \
  > "$ROOT/tmp/fault_monitor.log" 2>&1 &
echo $! > "$ROOT/tmp/fault_monitor.pid"
for i in $(seq 1 40); do
  if grep -q 'tcp:6633\|Fault monitor\|writing' "$ROOT/tmp/fault_monitor.log" 2>/dev/null; then
    echo "[✓] monitor ready ($i s)"
    break
  fi
  if [ -f "$ROOT/dataset/fault_live/flow_polls.csv" ]; then
    echo "[✓] flow_polls.csv exists ($i s)"
    break
  fi
  sleep 1
done
if ! ss -lntp 2>/dev/null | grep -q ':6633'; then
  echo "[!] :6633 not listening; log:"
  tail -40 "$ROOT/tmp/fault_monitor.log" || true
  exit 1
fi

echo "[*] collect protocol D (override: pass --protocol legacy)"
export PYTHONPATH=/usr/lib/python3/dist-packages:${PYTHONPATH:-}
"$ROOT/.venv/bin/python" "$ROOT/src/collect_independent_fault_runs.py" --protocol d "$@"
echo "[*] merge"
"$ROOT/.venv/bin/python" "$ROOT/src/merge_fault_runs.py"
echo "[*] eval LOSO"
"$ROOT/.venv/bin/python" "$ROOT/src/eval_fault_loso.py" || true
echo "[✓] done"

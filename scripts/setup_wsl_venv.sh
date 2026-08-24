#!/usr/bin/env bash
# Recreate WSL venv: Python 3.11, uninstall CUDA xgboost, install xgboost-cpu.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if command -v python3.11 >/dev/null 2>&1; then
  PY=python3.11
else
  echo "Need python3.11 (deadsnakes). Do not use 3.12/3.14 for this lock." >&2
  exit 1
fi

if [[ -d .venv ]]; then
  echo "Removing old .venv"
  rm -rf .venv
fi

"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -U pip
pip uninstall -y xgboost xgboost-cpu || true
pip install -r requirements.txt
python - <<'PY'
import sklearn
import xgboost
print("sklearn", sklearn.__version__, "(lock 1.7.2)")
print("xgboost", xgboost.__version__, "(need xgboost-cpu 3.2.0, not CUDA)")
PY
ls -lh models/random_forest_binary_realtime.pkl models/random_forest_binary_realtime_scaler.pkl || {
  echo "RF pickle missing after pull. Copy models/ from Tu or: python src/train_realtime_binary.py" >&2
}
echo "OK. Next: source .venv/bin/activate && python controller/run_realtime.py"
echo "Expect: LOADING RANDOM_FOREST_BINARY"

#!/bin/bash
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml

echo "[*] Activating Virtual Environment..."
source .venv/bin/activate

echo "[*] Cleaning old dataset..."
rm -f dataset/flow_stats.csv

echo "[*] Starting os-ken Controller in background..."
python controller/run_controller.py > controller.log 2>&1 &
CONTROLLER_PID=$!
sleep 5

echo "[*] Starting Mininet and Traffic Generation..."
# Run mininet using system python because mininet is installed globally
/usr/bin/python3 auto_traffic.py

echo "[*] Stopping os-ken Controller..."
kill $CONTROLLER_PID

echo "[*] Preprocessing data..."
python src/preprocess.py

echo "[*] Training XGBoost model..."
python src/train_model.py

echo "[*] Done! Check the reports/ folder for results."

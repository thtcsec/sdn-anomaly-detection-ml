# Máy đồng đội (WSL) — venv mới + artifact RF-binary

Clone GitHub **không** chứa `.venv`. File `*.pkl` từng bị `.gitignore`, nên máy Thiện thiếu `random_forest_binary_realtime.pkl` và controller nạp **xgboost** (wheel CUDA → `cudaErrorNoDevice`).

## Việc cần làm

1. Python **3.11** (không 3.12 / 3.14). Lock: sklearn **1.7.2**, `xgboost-cpu==3.2.0`.
2. Xóa venv cũ, cài lại từ `requirements.txt`.
3. `git pull` — lấy pickle RF-binary (~14 MB) và `dataset/controller_config.json` (`selected_model`: `random_forest_binary`).
4. Không `pip install xgboost` (bản CUDA). Đúng: `pip uninstall xgboost` rồi `pip install xgboost-cpu==3.2.0` (đã có trong requirements).

## Lệnh (WSL)

```bash
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml   # sửa path cho đúng máy
git pull
git checkout -- dataset/controller_config.json

rm -rf .venv
python3.11 -m venv .venv
source .venv/bin/activate
pip uninstall -y xgboost xgboost-cpu
pip install -r requirements.txt

ls -lh models/random_forest_binary_realtime.pkl models/random_forest_binary_realtime_scaler.pkl
python -c "import sklearn, xgboost; print(sklearn.__version__, xgboost.__version__)"
# kỳ vọng: 1.7.2  và  xgboost-cpu 3.2.0

python controller/run_realtime.py
```

Log đúng: `LOADING RANDOM_FOREST_BINARY`. Sai: `LOADING XGBOOST` rồi `cudaErrorNoDevice`.

Script gộp: `bash scripts/setup_wsl_venv.sh`.

## Nếu vẫn thiếu pickle RF

- Tú copy thư mục `models/` (Drive/USB), **không** bịa file pickle.
- Hoặc huấn luyện lại (chậm): `python src/train_realtime_binary.py`.

Khi RF thiếu, controller **fallback SVM**, không fallback XGBoost.

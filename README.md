# SDN Anomaly Detection using Machine Learning

Hệ thống phát hiện bất thường / phân loại tấn công trên SDN (Mininet + **os-ken**), kết hợp học máy có giám sát và không giám sát, kèm inference realtime + auto-mitigation + dashboard.

## Thành viên

| STT | Họ và tên | MSSV | Vai trò chính |
|-----|-----------|------|----------------|
| 1 | Trịnh Hoàng Tú | 23DH113972 | Lab SDN, thu thập flow, realtime, dashboard |
| 2 | Trần Minh Thiện | 23DH113375 | Pipeline ML, đánh giá, báo cáo Word |

**GVHD:** ThS. Cao Tiến Thành · An ninh mạng · Khóa 29 · HUFLIT

## Mô hình

| Model | Vai trò |
|-------|---------|
| **XGBoost** | Supervised multiclass (Normal / DDoS / Portscan) — **deploy realtime** |
| **Random Forest** | Supervised đối chứng (Acc cao trên lab; latency cao hơn) |
| **Isolation Forest** | Unsupervised binary (Normal vs Anomaly) |
| **Autoencoder** | Unsupervised binary (reconstruction error) |

Metric: XGB/RF dùng **macro**; AE/IF dùng **Anomaly-class** cho P/R/F1 — xem `reports/METRICS_SCOPE_NOTE.txt`.

## Yêu cầu

- WSL2 Ubuntu + Mininet + Open vSwitch + hping3/nmap/iperf  
- Python **3.11+** (lab đã chạy 3.11/3.12)  
- Cài đúng bản pin trong `requirements.txt` (không dùng “latest”)

```bash
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Gói chính (pin trong requirements): `os-ken`, `xgboost`, `scikit-learn`, `imbalanced-learn`, `tensorflow`/`tf_keras`, `pandas`, `numpy`, `matplotlib`, `seaborn`, `shap`, `flask`.

## Pipeline dữ liệu (thứ tự đúng)

```
flow_stats.csv
  → clean / extract features
  → train_test_split (stratified)
  → SMOTE chỉ trên TRAIN
  → train.csv / test.csv
  → mỗi model tự fit StandardScaler trên TRAIN
```

Lưu ý: mặc định `run_pipeline.py` có thể **bootstrap DDoS trước split** (semi-synthetic trong pool). Đây là hạn chế độc lập test — xem `WORD_EDIT_FOR_THIEN.md` / protocol grouped real-only.

```bash
python src/run_pipeline.py --bootstrap 0   # hoặc 400
python src/sync_ae_threshold_metrics.py    # đồng bộ AE threshold + metrics CSV
```

AE threshold = **95th percentile MSE trên Normal-TRAIN** → `models/autoencoder_threshold.pkl` (~**0.0473**). Không tính lại threshold trên test.

## Demo realtime

```bash
# Terminal 1
python controller/run_realtime.py

# Terminal 2
sudo python3 topology/custom_topo.py

# Terminal 3 (tuỳ chọn)
python dashboard/app.py   # http://127.0.0.1:5000
```

Polling ~5s/lần. Auto-mitigation: 3 alert liên tiếp → DROP source IP (~120s).

## Báo cáo Word

Checklist chỉnh luận văn (tiếng Việt): `WORD_EDIT_FOR_THIEN.md`  
Số liệu: `reports/model_comparison.csv`, `autoencoder_metrics.csv`, `isolation_forest_metrics.csv`, `full_vs_real_only_comparison.csv`

## Cấu trúc thư mục (rút gọn)

```
controller/   # os-ken monitor + realtime_detector + launcher
topology/     # Mininet topo
dataset/      # flow_stats, train/test
src/          # preprocess, train_*, compare, bootstrap, eval_*
models/       # .pkl / .keras + autoencoder_threshold.pkl
reports/      # metrics + plots
dashboard/    # Flask UI
docs/         # protocol provenance / evaluation
```

---
Khóa luận tốt nghiệp | HUFLIT | Khóa 29

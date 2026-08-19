# Fault Dataset — cùng topology, tách khỏi bộ anomaly

**Giữ nguyên** `dataset/flow_stats_grouped.csv` (79.114 snapshot · 32 run · 19 scenario · DDoS/Port Scan/Normal).  
Fault là **tập thứ hai**, không merge vào CSV anomaly, không train lại XGBoost realtime.

Bộ **legacy 12×3 = 392 snapshot** (Acc 4-class ~0,30) **không đủ** để bảo vệ claim phân loại lỗi. Protocol D mở diversity (mức severity × workload × cặp host), không đổi topology 2s6h.

## Hai câu hỏi (không gộp)

| Protocol | Nhãn | Câu khoa học |
|----------|------|----------------|
| **D1** | Normal vs Fault | Hệ thống có *phát hiện* lỗi liên kết không? |
| **D2** | normal / bandwidth / loss / delay | Hệ thống có *phân loại loại* lỗi không? |

Rule-based baseline (ngưỡng RTT / probe loss / throughput calibrate trên fold train) bắt buộc nằm cạnh RF/XGB.

## Thu (WSL)

```bash
# T1
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
source .venv/bin/activate
python controller/run_fault_monitor.py

# T2 — Protocol D (mặc định): ~36 scenario × 3 run × 90s ≈ 4 giờ
sudo PYTHONPATH=/usr/lib/python3/dist-packages python3 src/collect_independent_fault_runs.py --protocol d

# smoke 2 scenario
# sudo ... collect_independent_fault_runs.py --protocol d --only N_ping,B_10M_t --repeat 1

python src/merge_fault_runs.py
python src/eval_fault_loso.py
```

Legacy (bộ cũ): `--protocol legacy` (12 scenario × 3 × 45s).

Không dùng `run_controller.py` lúc thu fault — app đó append `flow_stats.csv` (anomaly).

## Protocol D — inject `s1↔s2`, đổi cặp h1→h4 / h2→h5 / h3→h6 theo repeat

| Family | Severity (ground truth, không vào model) | Workload |
|--------|------------------------------------------|----------|
| Normal | ping / http / iperf TCP / UDP / mixed low / mixed high | 6 scenario |
| Bandwidth | 1 / 2 / 5 / 10 / 20 Mbit/s | × TCP và mixed |
| Loss | 1 / 3 / 5 / 10 / 20 % | × TCP và mixed |
| Delay | 10 / 25 / 50 / 100 / 200 ms | × TCP và mixed |

`configured_*`, `fault_label`, `run_id`, `scenario_id`, IP **không** vào model (`FAULT_MODEL_FEATURES` / `FAULT_FORBIDDEN_FEATURES`).

## File

| Path | Vai trò |
|------|---------|
| `dataset/fault_live/` | poll sống (Flow + Port) |
| `dataset/fault_runs/fault_*/` | từng run |
| `dataset/fault_stats_grouped.csv` | snapshot 5s sau merge |
| `reports/fault_protocol_d1_loso.csv` | D1 LOSO + rule |
| `reports/fault_protocol_d2_loso.csv` | D2 LOSO + rule |
| `reports/fault_protocol_d*_per_class.csv` | Precision/Recall/F1 từng lớp |
| `reports/fault_loso_summary.csv` | alias D2 (tương thích Word cũ) |

## Word — hai tập, hai bài; D2 chưa thắng random thì nói thẳng

> Khóa luận giữ tập phát hiện bất thường lưu lượng (DDoS, Port Scan, Normal) gồm 79.114 snapshot trên 19 kịch bản. Bổ sung tập lỗi liên kết trên **cùng** topology Mininet 2 switch / 6 host. Hai tập không trộn feature và không dùng chung số Acc. Kết quả fault là nhận xét testbed. Nếu 4-class không vượt baseline ngẫu nhiên (~0,25) một cách ổn định, khóa luận **không** khẳng định đã phân loại được loại lỗi — chỉ báo cáo D1 (phát hiện) và hạn chế D2.

[15] S. M. Srinivasan, T. Truong-Huu, and M. Gurusamy, “Machine learning-based link fault identification and localization in complex networks,” IEEE Internet of Things Journal, vol. 6, no. 4, pp. 6556–6566, 2019.

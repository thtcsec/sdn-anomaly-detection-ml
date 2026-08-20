# Fault Dataset — cùng topology, tách khỏi bộ anomaly

**Giữ nguyên** `dataset/flow_stats_grouped.csv` (326.961 snapshot · 206 run · 21 scenario · DDoS/Port Scan/Normal).  
Fault là **tập thứ hai**, không merge vào CSV anomaly, không train lại XGBoost realtime.

Bộ **legacy 12×3** (Acc 4-class ~0,30) **không đủ** để bảo vệ claim phân loại lỗi. Protocol D mở diversity (mức severity × workload × cặp host), không đổi topology 2s6h.

**Hiện có trên đĩa:** `fault_stats_grouped.csv` = **6666** snapshot · **324 `run_id`** · **36 `scenario_id`**.

## Hai câu hỏi (không gộp)

| Protocol | Nhãn | Câu khoa học | Pooled LOSO (n_test=5370) |
|----------|------|----------------|---------------------------|
| **D1** | Normal vs Fault | Hệ thống có *phát hiện* lỗi liên kết không? | RF Acc **0,9339** F1-macro **0,8636** · XGB 0,9272 / 0,8527 |
| **D2** | normal / bandwidth / loss / delay | Hệ thống có *phân loại loại* lỗi không? | RF Acc 0,3726 F1 **0,4168** · XGB **0,3793 / 0,4200** |

D2 **yếu**: Acc ~0,37–0,38 chỉ nhỉnh random 4-lớp (~0,25). Không khẳng định đã phân loại được loại lỗi.

Rule-based baseline (ngưỡng RTT / probe loss / throughput calibrate trên fold train) bắt buộc nằm cạnh RF/XGB (D1/D2 Acc rule ≈ 0,16).

Phân bố nhãn grouped: delay 1864 · bandwidth 1857 · loss 1839 · normal 1106.

## Thu (WSL)

```bash
# T1
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
source .venv/bin/activate
python controller/run_fault_monitor.py

# T2 — Protocol D (mặc định)
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
| `dataset/fault_stats_grouped.csv` | snapshot 5s sau merge (6666) |
| `reports/fault_protocol_d1_loso.csv` | D1 LOSO + rule |
| `reports/fault_protocol_d2_loso.csv` | D2 LOSO + rule |
| `reports/fault_protocol_d*_per_class.csv` | Precision/Recall/F1 từng lớp |
| `reports/fault_loso_summary.csv` | alias D2 (tương thích Word cũ) |

## Word — hai tập, hai bài; D2 chưa thắng

> Khóa luận giữ tập phát hiện bất thường lưu lượng (DDoS, Port Scan, Normal) gồm 326.961 snapshot trên 21 kịch bản. Bổ sung tập lỗi liên kết trên **cùng** topology Mininet 2 switch / 6 host (6666 snapshot, 324 run, 36 kịch bản). Hai tập không trộn feature và không dùng chung số Acc. D1 (Normal vs Fault): RF Acc 0,9339 / F1-macro 0,8636. D2 (4 lớp): Acc ~0,37–0,38 / F1-macro ~0,42 — **chưa giải được** phân loại loại lỗi; chỉ báo cáo D1 và hạn chế D2.

[15] S. M. Srinivasan, T. Truong-Huu, and M. Gurusamy, “Machine learning-based link fault identification and localization in complex networks,” IEEE Internet of Things Journal, vol. 6, no. 4, pp. 6556–6566, 2019.

# Fault Dataset — cùng topology, tách khỏi bộ anomaly

**Giữ nguyên** `dataset/flow_stats_grouped.csv` (79.114 snapshot · 32 run · 19 scenario · DDoS/Port Scan/Normal).  
Fault là **tập thứ hai**, không merge vào CSV anomaly, không train lại XGBoost realtime.

Hướng đo: FlowStats cửa sổ Δ + PortStats + probe RTT/throughput, gần ML-LFIL (aggregate flow rate, delay, loss) trên Mininet [15].

## Thu (WSL, không bịa CSV)

```bash
# T1
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
source .venv/bin/activate
python controller/run_fault_monitor.py

# T2
sudo PYTHONPATH=/usr/lib/python3/dist-packages python3 src/collect_independent_fault_runs.py
# smoke: --only N1,B3 --repeat 1
# mặc định: 12 scenario × 3 run ≈ 40–50 phút

python src/merge_fault_runs.py
python src/eval_fault_loso.py
```

Không dùng `run_controller.py` lúc thu fault — app đó append `flow_stats.csv` (anomaly).

## 12 scenario × 3 run — inject `s1↔s2`

| ID | Ground truth | Severity |
|----|----------------|----------|
| N1 | Normal ping/HTTP | baseline |
| N2 | Normal iperf TCP | baseline |
| N3 | Normal mixed | baseline |
| B1–B3 | Bandwidth | 50 / 20 / 10 Mbit/s |
| L1–L3 | Packet loss | 1 / 5 / 10 % |
| D1–D3 | Delay | 20 / 50 / 100 ms |

`configured_bw/loss/delay`, `fault_label`, `run_id`, `scenario_id`, IP **không** vào model (`FAULT_MODEL_FEATURES` / `FAULT_FORBIDDEN_FEATURES`).

## File

| Path | Vai trò |
|------|---------|
| `dataset/fault_live/` | poll sống (Flow + Port), không phải tập chính |
| `dataset/fault_runs/fault_*/` | từng run: flows, ports, probes, meta |
| `dataset/fault_stats_grouped.csv` | snapshot 5s sau merge — tập fault |
| `reports/fault_loso_summary.csv` | LOSO theo `scenario_id`, nhãn `fault_family` |

## Word — hai tập, hai bài

> Khóa luận giữ tập phát hiện bất thường lưu lượng (DDoS, Port Scan, Normal) gồm 79.114 snapshot trên 19 kịch bản. Bổ sung tập lỗi liên kết trên **cùng** topology Mininet 2 switch / 6 host: suy giảm băng thông, mất gói, trễ trên `s1–s2`, 12 kịch bản × 3 run độc lập. Hai tập không trộn feature và không dùng chung số Acc. Kết quả fault là nhận xét testbed, không khẳng định mạng thật.

[15] S. M. Srinivasan, T. Truong-Huu, and M. Gurusamy, “Machine learning-based link fault identification and localization in complex networks,” IEEE Internet of Things Journal, vol. 6, no. 4, pp. 6556–6566, 2019.

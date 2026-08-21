# Fault Dataset — cùng topology, tách khỏi bộ anomaly

**Giữ nguyên** `dataset/flow_stats_grouped.csv` (326.961 snapshot · 206 run · 21 scenario · DDoS/Port Scan/Normal).  
Fault là **tập thứ hai**, không merge vào CSV anomaly, không train lại XGBoost realtime.

## Headline vs lịch sử

| Bộ | File grouped | D2 4-class (LOSO pooled) | Dùng trong Word |
|----|--------------|---------------------------|-----------------|
| **Protocol E (headline D2)** | `dataset/fault_stats_grouped_e.csv` (1.982 · 112 run · 36 scen) | RF Acc **0,923** / F1 **0,926** · XGB 0,902 / 0,903 · SVM 0,886 / 0,889 | **Hiện tại — lab only.** Headline = RF. Không campus SDN. |
| **Protocol D (lịch sử)** | `dataset/fault_stats_grouped.csv` (= `fault_stats_grouped_protocol_d.csv`; 6666 · 324 run · 36 scen) | RF Acc **0,3726** / F1 **0,4168** · XGB **0,3793 / 0,4200** | Phụ lục: thí nghiệm inject hỏng (`tc` không gắn) |

Protocol D **không đủ** vì nhãn đổi nhưng datapath không đổi (xem dưới). Protocol E sửa tín hiệu; không xóa thư mục `fault_*` 20260818 / overnight D.

Link-down **không** thêm vào 4-class luận văn. Nếu làm thêm, đó là thí nghiệm D3 riêng, không đổi nhãn D2.

## Vì sao Protocol D fail (Acc ~0,37)

Trên FlowStats 5s, Bandwidth / Loss / Delay đều trông như “ít gói hơn”. Random 4-lớp ≈ 0,25.

Hai lỗi thu thập (đã đọc confusion + CSV):

1. Topology mặc định dùng `Intf`, không `TCLink`. `intf.config(bw/delay/loss)` **không** gắn netem/HTB lên cổng OVS. `drop_rate_core` luôn 0; `probe_loss_pct` luôn 0 kể cả loss 20%; RTT median ~0,03 ms kể cả “delay 200 ms”.
2. Probe iperf chạy **h6→h4** (cùng s2), không đi qua s1↔s2 → throughput ~40 Gbit mọi lớp.

D1 vẫn cao (~0,93) vì Normal (ping/http) khác tốc độ iperf, không vì phân biệt được loại lỗi.

## Protocol E — tín hiệu có thể tách (lab, không phải campus)

Cùng topo 2s6h, inject **explicit `tc`** trên `s1-eth*` / `s2-eth*` (không dựa `Intf.config`).

| Family | Severity (metadata, không vào model) | Workload |
|--------|--------------------------------------|----------|
| Normal | ping / http / TCP / UDP / mixed low / mixed high | 6 scenario `EN_*` |
| Bandwidth | **1 / 2 / 3 / 4 / 5 Mbit/s** (HTB + pfifo ngắn) | × `tu` (TCP+UDP) và `mixed` |
| Loss | **5 / 8 / 12 / 16 / 20 %** (netem loss) | × `tu` / `mixed` |
| Delay | **50 / 80 / 120 / 160 / 200 ms** (netem delay) | × `tu` / `mixed` |

36 `scenario_id` (khác id Protocol D: tiền tố `E*`) × `--repeat 3` = 108 run. Duration mặc định 75 s.

Probe **h6→h1** (bắt buộc đi core): ping RTT/loss, iperf TCP throughput, iperf UDP jitter/lost.

Feature model (`FAULT_MODEL_FEATURES`): window delta pps/bps, `n_flows`, TCP/UDP split (`tcp_share`, `n_tcp_flows`, …), PortStats core (`rx/tx_bps`, `delta_*_dropped`, `drop_rate`, errors), probe RTT/loss/throughput/`udp_lost_pct`. Cấm `configured_*`, id, IP.

OVS PortStats `rx/tx_dropped` trên lab này **vẫn 0** khi netem drop (qdisc, không phải counter OVS). Loss nhìn thấy qua `probe_loss_pct` (ping xuyên core) và rate TCP/UDP, không bịa drop OpenFlow.

### Smoke 2026-08-20 (4 run, chưa phải bảng LOSO)

| Lớp | RTT median | probe_loss | TCP tput median | Ghi chú |
|-----|------------|------------|-----------------|---------|
| Normal `EN_high` | 0,07 ms | 0 % | ~55 Gbit | không tc |
| Bandwidth `EB_2M_tu` | hàng trăm ms queue (trước khi siết pfifo) rồi rate ~1–2 Mbit | 0 % | ~1,2 Mbit | HTB ceiling |
| Loss `EL_12pct_tu` | 0,15 ms | **12,5 %** | ~2 Mbit | khớp netem 12 % |
| Delay `ED_120ms_tu` | **240 ms** (= 2×120) | 0 % | ~46 Mbit | RTT tách khỏi loss |

`qdisc show` lúc thu: HTB trên BW, `netem loss 12%` / `netem delay 120ms` trên Loss/Delay. Đây là bằng chứng vật lý trước LOSO đủ 36 scenario.

### LOSO Protocol E (đủ 36 scenario — số khóa 2026-08-21)

Pooled n_test = 1534. Nguồn: `reports/fault_protocol_e_d1_loso.csv`, `fault_protocol_e_d1_per_class.csv`, `fault_protocol_e_d2_loso.csv`, `fault_protocol_e_d2_per_class.csv`.

D1 — năm mô hình (Normal vs Fault). IF/AE train **Normal-only** từng fold LOSO; scaler fit trên subset đó; ngưỡng AE = percentile 95 MSE train-normal (cùng protocol anomaly LOSO). Keras 3 / TF 2.21 CPU.

| Model | Acc | F1-macro | Recall Normal | Recall Fault |
|-------|-----|----------|---------------|--------------|
| Random Forest | **0,9811** | **0,9652** | 0,9213 | 0,9930 |
| XGBoost | 0,9759 | 0,9554 | 0,9016 | 0,9906 |
| SVM (RBF) | 0,9681 | 0,9414 | 0,8858 | 0,9844 |
| Autoencoder | 0,5456 | 0,4899 | 0,6496 | 0,5250 |
| Isolation Forest | 0,1382 | 0,1314 | 0,6850 | 0,0297 |
| Rule-based | 0,4954 | 0,4814 | 1,0000 | 0,3953 |

D2 — 4 lớp. IF/AE **phải** để trống: mô hình không giám sát không gán 4 nhãn (cần head có giám sát riêng). Không bịa Acc 4-class.

| Bài | RF Acc / F1-macro | XGB | SVM (RBF) | Rule Acc | IF / AE |
|-----|-------------------|-----|-----------|----------|---------|
| D2 | **0,923 / 0,926** | 0,902 / 0,903 | 0,886 / 0,889 | 0,411 | **N/A** |

RF D2 recall: Bandwidth 0,883 · Loss 0,874 · Delay 0,996 · Normal 0,941. **Headline = RF.** SVM không thay RF. Unsupervised chỉ trả lời D1.

D2 **được phép** trên Protocol E lab; **không** được phép suy ra mạng trường / production. 112 `run_id` (36 scenario; gồm run smoke gộp thêm, không phải đúng 36×3=108).

## Thu (WSL)

```bash
# T1 — os-ken, KHÔNG set PYTHONPATH dist-packages
cd /mnt/d/tu_projects/sdn-anomaly-detection-ml
source .venv/bin/activate
python controller/run_fault_monitor.py

# T2 — Mininet: PYTHONPATH dist-packages ONLY
# Protocol E (headline)
sudo PYTHONPATH=/usr/lib/python3/dist-packages python3 src/collect_independent_fault_runs.py --protocol e --repeat 3

python src/merge_fault_runs.py --protocol e
python src/eval_fault_loso.py --data dataset/fault_stats_grouped_e.csv --prefix fault_protocol_e
```

Không dùng `run_controller.py` lúc thu fault. Không mở controller thứ hai trên :6633.

Protocol D (chỉ replay lịch sử): `--protocol d` → `merge_fault_runs.py --protocol d --out dataset/fault_stats_grouped.csv`.

## SVM (model thứ 5)

SVM là baseline có giám sát cổ điển, **không** thay RF/XGB và **không** tự chữa D2 nếu feature còn chồng.

- Fault D1: `SVC(kernel="rbf")`, `StandardScaler` fit trên fold train. IF/AE cùng protocol (Normal-only, scaler train-fold). IF/AE **N/A trên D2 4-class** — unsupervised chỉ trả lời D1.
- Anomaly LOSO binary: `LinearSVC(dual=False, max_iter=4000)`, cap train 40k; không RBF trên 326k.

## File

| Path | Vai trò |
|------|---------|
| `dataset/fault_live/` | poll sống (Flow + Port) |
| `dataset/fault_runs/fault_*/` | từng run (D và E cùng thư mục, lọc bằng `meta.protocol`) |
| `dataset/fault_stats_grouped.csv` | Protocol D lịch sử (6666 · 324 run · 36 scen) |
| `dataset/fault_stats_grouped_e.csv` | Protocol E hiện tại (1.982 · 112 run · 36 scen) |
| `reports/fault_protocol_d1_loso.csv` / `d2_*` | D1/D2 Protocol D (phụ lục ~0,38) |
| `reports/fault_protocol_e_d1_loso.csv` / `e_d2_*` | D1/D2 Protocol E + SVM |

## Word

> Hai tập không trộn. Hai câu hỏi: D1 = phát hiện fault vs normal; D2 = 4 lớp. Headline hiện tại là **Protocol E** (`fault_stats_grouped_e.csv`, 1.982 snapshot, 112 run, 36 scenario): D1 RF Acc 0,9811 / F1-macro 0,9652; AE 0,5456 / 0,4899; IF 0,1382 / 0,1314. D2 RF Acc 0,923 / F1-macro 0,926; recall Bandwidth/Loss/Delay 0,883 / 0,874 / 0,996. SVM D2 0,886 / 0,889 — kém RF, không chiếu. D2 E chỉ nhận xét lab Mininet 2s6h, **không** campus SDN. Protocol D (6666 snapshot) là thí nghiệm inject hỏng: D2 Acc ~0,37–0,38 — phụ lục, không phải số hiện tại. IF/AE chạy D1; **không** chạy 4-class D2 (N/A).

[15] S. M. Srinivasan, T. Truong-Huu, and M. Gurusamy, “Machine learning-based link fault identification and localization in complex networks,” IEEE Internet of Things Journal, vol. 6, no. 4, pp. 6556–6566, 2019.

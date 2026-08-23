# Cẩm nang bảo vệ khóa luận — kiến thức đầy đủ

**Đối tượng:** Trịnh Hoàng Tú (nói miệng, demo) · Trần Minh Thiện (Word, số liệu).  
**Khóa:** K29 · HUFLIT · GVHD ThS. Cao Tiến Thành.  
**Đề:** *Phát hiện bất thường và phân loại lỗi mạng SDN bằng học máy.*  
**Khóa số:** 2026-08-23. Mọi Acc/F1/N trong file này lấy từ CSV trong `reports/`, không nhớ miệng.  
**Word kiểm:** `KhoaLuanTotNghiep.docx` mtime **2026-08-23 22:00:48** (5,2 MB).  
**Slides kiểm:** `Thesis Defense Presentation (1).pptx` mtime **2026-08-23 22:04:07** (22 slide). Không có `slides-kltn.pptx` / `KhoaLuan*.pptx` khác trên đĩa.

---

## 0. Một phút mở đầu (nói đúng, không phóng)

> Nhóm tự thu OpenFlow Flow Statistics trên Mininet **2 switch / 6 host**, controller **os-ken 4.2.0**, OpenFlow 1.3 cổng **6633**. Hai bài **tách nhau**: (1) phát hiện bất thường an ninh Normal–Attack, (2) phân loại lỗi hiệu năng Protocol E. Số generalization anomaly là LOSO 21 scenario, 8 feature, 3 poll đầu: **Random Forest Acc 0,7724**. Artifact live là **RF nhị phân 8 feature**, nhãn `NORMAL`/`ANOMALY`. Fault D2 hiện tại là Protocol E audited: **RF Acc 0,9250 / F1-macro 0,9281**, chỉ lab. Không syslog HUFLIT, không train CICIDS, không Acc 0,999, không 0,33 ms, không XGBoost deploy.

Nếu hội đồng chỉ cho 90 giây: nói đoạn trên rồi dừng. Chi tiết ở dưới.

---

## 1. Khóa đề (lock đề) — nói trước khi bị hỏi

| Được | Không được |
|------|------------|
| Testbed Mininet + OVS + os-ken, OpenFlow 1.3 | Syslog / SOC tường lửa HUFLIT |
| Tự thu Flow Statistics (poll 5 s) | CICIDS2017 / InSDN làm tập train controller |
| Anomaly = DDoS (hping3) + Port Scan (nmap) + Normal | “Phát hiện mọi tấn công SDN” |
| Fault = Bandwidth / Loss / Delay giả lập bằng `tc` trên s1↔s2 | Hỏng NIC, đứt cáp vật lý, lỗi VLAN campus |
| Nhận xét trên **21 scenario lab** (anomaly) và **36 scenario Protocol E** (fault) | Suy ra production / mạng trường |

CICIDS/InSDN nếu bị hỏi: *tài liệu liên quan / benchmark phụ lục*, **không** nằm trong `flow_stats_grouped.csv`, **không** train artifact live.

Đề có chữ “phân loại lỗi mạng”: đó là **nhánh fault riêng** (`fault_stats_grouped_e.csv`), không trộn nhãn DDoS vào Bandwidth. DDoS ≠ lỗi mạng.

---

## 2. Kiến trúc ứng dụng (phải vẽ miệng được)

Ba lớp, **hai app controller không chạy cùng cổng 6633**:

| Thành phần | File | Cổng / vai trò |
|------------|------|----------------|
| Topology | `topology/custom_topo.py` | 2 OVS (`s1` h1–h3, `s2` h4–h6), 10.0.0.1–6 |
| Thu CSV | `controller/run_controller.py` + `monitor.py` | Poll 5 s → `dataset/flow_stats.csv` |
| Live | `controller/run_realtime.py` + `realtime_detector.py` | OpenFlow **tcp:6633**, suy luận + DROP |
| Fault thu | `controller/run_fault_monitor.py` | FlowStats **delta** + PortStats; **không** dùng `run_controller.py` lúc thu fault |
| SOC | `dashboard/app.py` | **http://127.0.0.1:5000** (loopback mặc định) |

**Năm (+1) artifact trong `models/` — RAM chỉ giữ một.** Đổi radio trên SOC; mặc định `dataset/controller_config.json`:

```json
"selected_model": "random_forest_binary"
```

| Radio SOC | File | Feature | Nhãn live | Vai trò |
|-----------|------|---------|-----------|---------|
| **random_forest_binary** (default) | `random_forest_binary_realtime.pkl` + scaler riêng | **8**, không cổng | `NORMAL` / `ANOMALY` | **Artifact luận / demo headline** |
| xgboost | `xgboost_model.pkl` + `scaler.pkl` | 10, có cổng | Normal/DDoS/Portscan | Legacy đa lớp |
| random_forest | `random_forest_model.pkl` | 10 | đa lớp | Legacy |
| svm | `svm_model.pkl` | 10 | đa lớp | **Demo baseline random-split**, **≠ LOSO** |
| isolation_forest | `isolation_forest_model.pkl` | 10 | binary | Đối chứng; LOSO fail |
| autoencoder | `autoencoder_model.keras` | 10 | binary | Đối chứng; **`load_model` trên lab này có thể fail** (Dense mismatch). TF import 30–180 s |

Nguồn catalog: `src/model_catalog.py`. Câu RAM một model: comment trong `controller/realtime_detector.py`.

**PYTHONPATH:** collector Mininet được phép `PYTHONPATH=/usr/lib/python3/dist-packages`. **Cấm** export cái đó cho os-ken — sẽ kéo `eventlet` hệ thống, gãy hub. Controller: chỉ `.venv` + `OSKEN_HUB_TYPE=eventlet`.

---

## 3. Dataset — bảng khóa (đọc đúng file)

### 3.1 Anomaly (headline)

Nguồn: `dataset/flow_stats_grouped.csv`. Đếm Word/Bảng 2 = README.

| | Snapshot | run_id | scenario_id |
|--|----------|--------|-------------|
| **Tổng** | **326.961** | **206** | **21** |
| Normal | 198.810 | 135 | 4 |
| DDoS | 93.648 | 44 | 9 |
| Port Scan | 34.503 | 27 | 8 |

21 `scenario_id` (`reports/scenario_inventory.csv`):  
DDoS: `ddos_icmp_multi_h4h6_h1h3`, `ddos_syn_multi_h4h5_h1h2`, `ddos_syn_multiport_h4_h1`, `ddos_syn_multiport_multi_h4h6_h1h3`, `ddos_syn_single_h4_h1`, `ddos_syn_slow_h4_h2`, `ddos_udp_h5_h1`, `ddos_udp_multi_h5h6_h2h3`, `ddos_udp_multiport_h5_h2`.  
Normal: `normal_mesh_ping_iperf_http_a/b`, `normal_mesh_udp_tcp_c`, `normal_ping_iperf_light`.  
Portscan: `portscan_connect_h6_h3_p20_120_r60`, **`portscan_nmap_h4_h1`** (lỗ recall 0), `portscan_nmap_h5_h2`, `portscan_syn_*` (5 id).

**Không còn 79k / 32-run / 19-scenario.** Word text không còn “79.000”. Nếu slide/hình cũ còn 79k → sửa ngay.

### 3.2 Fault Protocol E (headline D2)

`dataset/fault_stats_grouped_e.csv`: **1.982** snapshot thô · **112** run · **36** scenario.  
Steady-state LOSO: **n_test pooled = 1.534** (`fault_protocol_e_audited_d*_loso.csv`, dòng `_pooled`).

Phân bố thô (README): delay 570 · bandwidth 553 · loss 529 · normal 330.

36 scenario tiền tố `E*`: `EN_*` (6 Normal), `EB_*M_{m|tu}` (5×2 Bandwidth 1–5 Mbit), `EL_*pct_{m|tu}` (5×2 Loss 5–20 %), `ED_*ms_{m|tu}` (5×2 Delay 50–200 ms).

### 3.3 Fault Protocol D (phụ lục — inject hỏng)

`dataset/fault_stats_grouped.csv` (= `fault_stats_grouped_protocol_d.csv`): **6.666** · 324 run · 36 scenario.  
D2 RF Acc **0,3726** / F1 **0,4168**; XGB **0,3793** / **0,4200** (`reports/fault_protocol_d2_loso.csv`, `_pooled`, n_test=5370).  
**Cấm** nói đây là số hiện tại.

### 3.4 File cấm headline

| File | Vì sao |
|------|--------|
| `dataset/train.csv` / `test.csv` | Random-flow split + SMOTE → Acc ~0,999 |
| `dataset/flow_stats.csv` | Dump monitor, không phải pool khóa |
| `reports/model_comparison.csv` | Leakage; phụ lục |
| CICIDS/InSDN parquet | Không train controller |

---

## 4. Snapshot ≠ run ≠ scenario — vì sao 326k không i.i.d.

| Đơn vị | Nghĩa | Ví dụ |
|--------|--------|--------|
| **Snapshot** | Một dòng FlowStats tại một poll 5 s | TCP sống 30 s ≈ 6 dòng |
| **5-tuple / flow identity** | `run_id + datapath + ip_src/dst + proto + ports` | Nhiều snapshot cùng flow |
| **run_id** | Một phiên thu (bật/tắt traffic, ghi meta) | 206 phiên anomaly |
| **scenario_id** | Một *cách* tạo traffic (công cụ, host, dải cổng) | 21 kịch bản; nhiều run lặp cùng scenario |

326.961 là số **cửa sổ poll**, không phải 326.961 phiên độc lập. Cùng lab 2s6h, thêm run — **không** đa dạng kiểu CICIDS.

LOSO giữ **cả scenario** làm test → các run lặp cùng kịch bản không lọt sang train. GroupKFold theo `run_id` **yếu hơn**: cùng `scenario_id` vẫn có thể nằm hai phía.

Evaluation pool anomaly (3 poll đầu / 5-tuple / run): **211.004** snapshot. Artifact live fit trên pool này *sau* khi chọn cấu hình (`reports/realtime_binary_artifact_benchmark.csv`, cột `n_training_snapshots=211004`). **Không** tính Acc trên chính tập fit.

---

## 5. Tám đặc trưng + scaler train-only

Công thức (`src/model_catalog.py` · `build_flow_features`; thu `controller/monitor.py`):

```
duration      = duration_sec + duration_nsec / 1e9     →  flow_duration
pkt_per_sec   = packet_count / duration                 (0 nếu duration=0)
byte_per_sec  = byte_count / duration
pkt_size_avg  = byte_count / packet_count               (0 nếu count=0)
```

**8 cột LOSO + RF-binary live** (`PORT_AGNOSTIC_FEATURE_COLS`):

`ip_proto`, `packet_count`, `byte_count`, `duration_sec`, `packet_count_per_sec`, `byte_count_per_sec`, `packet_size_avg`, `flow_duration`.

**Bỏ `tp_src`, `tp_dst`:** hping3 hay `-p 80`, nmap quét dải cổng → cây học shortcut cổng, không học hành vi.

**10 cột legacy** (XGB/RF/SVM đa lớp demo): 8 cột trên **cộng** `tp_src`, `tp_dst`.

**Scaler:** `StandardScaler` **fit trên train fold / train set thôi**. Test/held-out chỉ `transform`. Cây không *bắt buộc* scale; AE/SVM/IF thì có. Pipeline live vẫn scale để khớp artifact.

**SMOTE:** không dùng trong LOSO anomaly. Chỉ phụ lục random-split.

Fault E: **31** feature (16 FlowStats + 8 PortStats + 7 probe). Cấm `configured_*`, IP, `run_id`, `scenario_id`. Imputer median + scaler **per train fold**.

---

## 6. Protocol LOSO anomaly (số miệng)

Script: `python src/eval_binary_realtime_scenario_held_out.py`  
Khóa: `reports/binary_realtime_loso_summary.csv` + `binary_realtime_loso_per_scenario.csv`.

1. Pool `flow_stats_grouped.csv`, `is_synthetic=0`, `run_id`/`scenario_id` hợp lệ.  
2. **LeaveOneGroupOut theo `scenario_id`** → **21 fold**.  
3. Mỗi 5-tuple trong mỗi run: **tối đa 3 poll đầu** (`early_poll_snapshots`, `src/realtime_protocol.py`).  
4. Nhị phân: Normal vs Attack (DDoS∪Portscan).  
5. 8 feature, không SMOTE, scaler trong fold.  
6. Metric pooled **và** Mean/Min Attack Recall, Mean/Max Normal FPR theo scenario.

Lỗ cố định: cả RF, XGB, LinearSVC đều **recall = 0** trên `portscan_nmap_h4_h1` (149 snapshot test, `binary_realtime_loso_per_scenario.csv`). Vì thế **min recall = 0**. Không giấu.

---

## 7. Bảng năm mô hình — nói đúng file

Làm tròn như Word Bảng 8; nguyên bản CSV bên cạnh.

### 7.1 Anomaly LOSO — `reports/binary_realtime_loso_summary.csv`

| Model | Acc pooled | Prec Attack | Rec Attack | F1 Attack | Mean Attack Rec | Min | Mean Normal FPR |
|-------|------------|-------------|------------|-----------|-----------------|-----|-----------------|
| **Random Forest** | **0,7724** | 0,7808 | 0,7684 | **0,7746** | 0,7301 | 0 | **0,1616** |
| XGBoost | 0,7520 | 0,7577 | 0,7535 | 0,7556 | 0,7223 | 0 | 0,1805 |
| LinearSVC | 0,7491 | 0,7096 | 0,8579 | 0,7768 | **0,8524** | 0 | 0,2871 (max 0,5613) |
| Autoencoder | 0,4759 | 0,3122 | 0,0250 | 0,0463 | 0,0495 | 0 | 0,0614 |
| Isolation Forest | 0,4665 | 0,0029 | 0,0001 | 0,0003 | 0,0036 | 0 | 0,0484 |

CSV thô RF Acc `0.7724308543913859`.  
**Chọn RF:** Acc + FPR tốt hơn; SVM nhạy hơn nhưng FPR xấu. **Không** chọn XGB vì “nhanh 0,33 ms”.

AE/IF **thất bại trên anomaly LOSO** (F1 Attack ≈ 0). Không kết luận “unsupervised vô dụng với SDN” — chỉ cấu hình + phân bố Normal lab này.

### 7.2 Fault E D1 (Normal vs Fault) — `reports/fault_protocol_e_audited_d1_loso.csv` `_pooled`

| Model | Acc | F1-macro |
|-------|-----|----------|
| Random Forest | **0,9804** | **0,9640** |
| XGBoost | 0,9759 | 0,9554 |
| SVM-RBF | 0,9681 | 0,9414 |
| Autoencoder | 0,5502 | 0,4903 |
| Isolation Forest | 0,3787 | 0,3643 |
| Rule-based | 0,5189 | 0,5013 |

Recall D1 RF (`fault_protocol_e_audited_d1_per_class.csv`): Normal **0,9213** · Fault **0,9922**. Support 254 / 1280.

### 7.3 Fault E D2 (4 lớp) — `reports/fault_protocol_e_audited_d2_loso.csv` `_pooled`

| Model | Acc | F1-macro |
|-------|-----|----------|
| **Random Forest** | **0,9250** | **0,9281** |
| XGBoost | 0,8990 | 0,9001 |
| SVM-RBF | 0,8846 | 0,8882 |
| Rule-based | 0,4107 | 0,3873 |
| **IF / AE** | **N/A** | **N/A** |

IF/AE **không gán 4 nhãn**. Cấm bịa Acc D2 cho chúng.

Recall D2 RF (`fault_protocol_e_audited_d2_per_class.csv`):

| Lớp | Recall | Support |
|-----|--------|---------|
| Normal | 0,9449 | 254 |
| Bandwidth | 0,8881 | 429 |
| Loss | 0,8765 | 405 |
| Delay | 0,9933 | 446 |

Confusion RF D2 (Word Bảng 9 = file `fault_protocol_e_audited_d2_random_forest_confusion.csv` nếu đối chiếu): chủ yếu Bandwidth↔Loss.

Min scenario Acc D2 RF = **0,525** (`EB_2M_m`). Pooled 0,925 **lạc quan hơn** trung bình scenario. Nói kèm.

Ablation RF D2 (`fault_protocol_e_audited_d2_ablation_loso.csv` `_pooled`): FlowStats-only Acc **0,9009** · PortStats **0,7249** · probe-only **0,6252** · Flow+Port **0,9055** · đủ 31 feat **0,9250**. → Không phải “chỉ nhờ ping RTT”.

---

## 8. Mitigation (demo — thuộc lòng)

Mã: `src/mitigation_policy.py` + `controller/realtime_detector.py`.  
Config: `alert_threshold=3`, `block_timeout=120`, `polling_interval=5`.

1. Mỗi **poll hoàn chỉnh** (đủ FlowStatsReply), gộp theo `ipv4_src`.  
2. Nhiều flow ANOMALY cùng IP **trong một poll** = +1 streak (không +N).  
3. Một poll không ANOMALY → streak = 0.  
4. Streak ≥ 3 **và** mitigation bật → `OFPFlowMod` DROP, match `eth_type=IP, ipv4_src=...`, **actions rỗng**.  
5. **`priority=1000`** (`BLOCK_FLOW_PRIORITY`; forwarding thường priority 1).  
6. **`hard_timeout=120`**, **`idle_timeout=0`**, cookie + `OFPFF_SEND_FLOW_REM`.  
7. Controller chỉ gỡ trạng thái BLOCKED khi nhận đủ FlowRemoved.

**Không** nói “chặn trong đúng 15 giây”. Phụ thuộc lệch pha poll. Word 4.7.5 đã viết đúng.

---

## 9. Độ trễ — ba số, ba nghĩa

| Số | Nghĩa | Nguồn | Được nói? |
|----|--------|--------|-----------|
| **12,990 ms** (p50) | `StandardScaler.transform` + `RandomForest.predict`, batch-1, n=1000, n_jobs=1 | `reports/realtime_binary_artifact_benchmark.csv` (`latency_batch1_p50_ms=12.9898`; p95=17,592; p99=22,481) | Có — **suy luận artifact RF** |
| **~5 s** | Chu kỳ poll FlowStats | config | Có — phát hiện phụ thuộc poll |
| **0,33 / 0,44 ms** | XGB cũ / slide | **Không** phải artifact hiện tại | **Cấm** gắn cho live RF |
| E2E (traffic → DROP có hiệu lực) | Poll + OpenFlow + extract + infer + FlowMod | **Chưa đo** | **Cấm** lấy 12,99 ms thay |

Câu khóa: *12,990 ms ≠ end-to-end ≠ 0,33 ms.*

---

## 10. Protocol D vs Protocol E

| | D (lịch sử) | E (hiện tại) |
|--|-------------|--------------|
| File | `fault_stats_grouped.csv` | `fault_stats_grouped_e.csv` |
| N | 6.666 / 324 run / 36 scen | 1.982 / 112 run / 36 scen |
| Inject | `Intf.config` **không** gắn netem/HTB lên OVS | `tc` **trực tiếp** `s1-eth*` / `s2-eth*` |
| Probe | h6→h4 (cùng s2, **không** qua core) | h6→h1 (**qua** s1↔s2) |
| D2 | ~0,38 ≈ ngẫu nhiên 4 lớp | RF **0,9250 / 0,9281** |
| D1 | RF ~0,93 (vì Normal ping/http ≠ iperf, **không** vì tách được loại lỗi) | RF 0,9804 |

Hai lỗi D (nói được): (1) topology mặc định không `TCLink` → `drop_rate_core`/`probe_loss` = 0, RTT ~0,03 ms dù “delay 200 ms”; (2) iperf cùng switch → ~40 Gbit mọi lớp.

E **đồng thời** đổi vị trí tc, đường probe, severity, workload. **Không** phải ablation một biến. Không nói “chỉ vì sửa tc mà Acc từ 0,38 lên 0,93”.

OVS `rx/tx_dropped` lab này **vẫn 0** khi netem drop (qdisc). Loss nhìn bằng `probe_loss_pct` + rate, không bịa counter OpenFlow.

Link-down **không** nằm D2. Taxonomy chưa có: jitter độc lập, reorder, flapping, lỗi controller, flow-table exhaustion, campus.

---

## 11. Demo — checklist Tú

### Windows → WSL

```powershell
.\start_demo.ps1
```

Ba cửa sổ: os-ken `:6633` · Flask `http://127.0.0.1:5000` · Mininet `topology/custom_topo.py`.

### Thủ công (WSL, Python **3.11**)

```bash
source .venv/bin/activate
python controller/run_realtime.py
python dashboard/app.py
sudo /usr/bin/python3 topology/custom_topo.py
```

Trên lab này `python3` có thể là 3.14 — **lock 3.11** (`reports/environment_lock.txt`: sklearn 1.7.2, xgboost 3.2.0, TF 2.21.0, os-ken 4.2.0).  
**`pip install xgboost-cpu==3.2.0`**, không wheel CUDA (`cudaErrorNoDevice` khi unpickle `xgboost_model.pkl`).

SOC “Bắn”: `scripts/trigger_traffic.py` (chỉ 10.0.0.1–6).

### Cấm trên sân khấu

- Đổi radio sang **SVM** rồi đọc Acc pickle như số luận. SVM live = random-split 10-feat `train.csv`, **không** phải LOSO 0,7491.  
- Headline XGB latency.  
- Load Autoencoder rồi im lặng 2 phút / crash keras — giải thích trước hoặc **đừng chọn**.  
- Nói “dashboard đang tính Acc 0,77” — SOC chỉ đọc JSON; Acc ở Bảng 8 offline.

---

## 12. Mười hai câu hội đồng — trả lời thật

**1. Đề này lấy syslog HUFLIT / SOC trường?**  
Không. Mininet OpenFlow tự thu. HUFLIT chỉ là nơi học. Không có dump syslog trong dataset.

**2. Dữ liệu CICIDS hay của nhóm?**  
Của nhóm, 2s6h. CICIDS/InSDN không train controller. Acc chỉ nhận xét lab.

**3. 326 nghìn mẫu độc lập?**  
Không. Snapshot poll 5 s. 206 run, 21 scenario. Cùng topology.

**4. Sao Acc chỉ 0,77, paper khác 0,99?**  
0,99 là random-split cùng flow 5 s lọt train/test. LOSO giữ nguyên một kịch bản chưa thấy, bỏ cổng thô, 3 poll đầu. So protocol, không so vanity Acc.

**5. Sao không để XGBoost realtime? Nó nhanh hơn.**  
Live **đã** là RF binary 8 feature, cùng schema LOSO. XGB đa lớp 10 cổng là legacy. Latency khóa RF p50 **12,990 ms**, không 0,33 ms. Chọn RF vì Acc/FPR LOSO, không vì ms.

**6. 8 hay 10 feature?**  
LOSO + live: **8**. Demo XGB/RF/SVM cũ: **10**. Không trộn khi đọc số.

**7. SVM trên SOC Acc cao?**  
Pickle SVM = baseline `train.csv`/`test.csv`. **Không** phải LinearSVC LOSO 0,7491. Đừng đọc số demo.

**8. AE/IF kém thì sao còn để?**  
Baseline one-class đã công bố. Cùng protocol để công bằng. Fail trên lab này. D2 bốn lớp: **N/A**.

**9. Lỗi mạng khác DDoS thế nào? Protocol D 0,38?**  
Hai tập. D = `tc` không gắn + probe sai đường. E sửa tín hiệu, D2 RF 0,925 lab-only. D chỉ phụ lục.

**10. 12,99 ms có phải chặn xong trong 13 ms?**  
Không. Chỉ infer+scale. E2E chưa đo. Poll 5 s + 3 streak. Slide nào viết “phản ứng 12,99 ms” là **sai**.

**11. Đóng góp thuật toán mới?**  
Không. RF/XGB/SVM/IF/AE là baseline. Đóng góp: tự thu có provenance, LOSO, hai bài tách, prototype RF-binary + DROP trên cùng testbed.

**12. Đưa lên mạng trường / switch hàng được không?**  
Chưa. 2s6h, FPR Normal ~0,16, min attack recall 0, min D2 scenario 0,525. Prototype lab.

---

## 13. Word vs project — verdict và punch list còn lại

**Verdict: gần ổn.**

Số khóa (Bảng 8, 326.961/206/21, 211.004, fault E audited, 8 vs 10, priority 1000, 12,990 ms, bác 0,33 ms, RF live) **khớp CSV**. Hình 1 **caption** là pipeline thu thập — **không còn 79k trong text**.

### Còn lệch (sửa Word nếu còn giờ)

1. **4.7.1 caption Hình 8** (P507): “controller đã nạp mô hình **XGBoost**” — body 4.7.1 đã là RF. Đổi caption + screenshot nếu log vẫn `xgboost`.  
2. **4.7.2 caption Hình 9** (P514): “**XGBoost được sử dụng làm mô hình realtime chính**, Random Forest đối chứng” — **sai**. Default `random_forest_binary`. Đây là lệch 4.7.2–4.7.5 còn sót (đúng mục hội đồng hỏi).  
3. **§2.3.1** (P319): “XGBoost đa lớp được sử dụng trong prototype realtime” — mâu thuẫn Ch.4. Sửa thành legacy.  
4. **§2.6.1** (P330): RF “đối chứng với XGBoost” — RF giờ là artifact.  
5. **Phụ lục** (P675): “Bảng phân bố 11.283” + “không thay thế … Bảng 5” — Bảng LOSO hiện là **Bảng 8**.  
6. **Bảng phân công:** Thiện “huấn luyện AE và XGBoost” — thiếu RF-binary / SVM / Protocol E.  
7. Hình 8/9 **pixel** (không OCR được ở đây): nếu UI vẫn tick XGBoost → chụp lại với RF-binary.

**Không lệch (đã khớp):** Bảng 8 từng ô; D1/D2 E; 8 feature live; priority 1000; 12,990 ms; “không dùng 0,33 ms”; 326k; Protocol E 1982/112/36/1534.

---

## 14. Slides vs sự thật — punch list **phải đổi**

Nguồn: `Thesis Defense Presentation (1).pptx`, 22 slide, 2026-08-23 22:04.  
So với Word mới + CSV. **Slide đang lạc Word.** Ưu tiên sửa trước bảo vệ.

| Slide | Claim trên slide | Sự thật (CSV/code/Word) | Việc phải làm |
|-------|------------------|-------------------------|---------------|
| **1** (tagline) | “phân loại … DDoS & Port Scan” trên controller | Live = `NORMAL`/`ANOMALY`, 8 feat | Đổi tagline: phát hiện nhị phân; đa lớp = legacy |
| **4** | “thời gian phản ứng p50 = 12,99 ms” | 12,99 = infer RF, **không** mitigation | Bỏ “phản ứng”; ghi “suy luận batch-1 p50” |
| **4** | “SVM Autoencoder” dính chữ | 5 mô hình, SVM tách | Thêm dấu phẩy: SVM, AE, IF |
| **6** | “tổng quát hóa cao” vì bỏ cổng | Min recall vẫn 0 | Đổi: giảm shortcut cổng, **không** đảm bảo generalization |
| **7** | So sánh RF, XGB, AE, IF — **thiếu SVM** | Bảng 8 có LinearSVC | Thêm SVM; 5 mô hình |
| **7** | Tên feat `packet_rate`, `ratio_bytes_per_pkt` | Code: `packet_count_per_sec`, `packet_size_avg` | Đổi đúng tên cột |
| **10** | RF latency **~1,12 ms** | p50 **12,990 ms** | Sửa 12,99 ms; bỏ cột latency nếu không cùng protocol |
| **10** | XGB “**~0,44 ms (Realtime)**” | Live **không** phải XGB | Xóa nhãn Realtime |
| **10** | AE Acc **0,4930** F1 **0,6160** FPR **0,4210** | CSV **0,4759 / 0,0463 / 0,0614** | **Thay cả hàng** bằng Bảng 8 |
| **10** | IF Acc **0,1710** F1 **0,1710** FPR **0,6850** | CSV **0,4665 / 0,0003 / 0,0484** | **Thay cả hàng** |
| **10** | XGB P **0,7612** R **0,7490** | CSV 0,7577 / 0,7535 | Copy Bảng 8 |
| **10** | **Thiếu SVM** | 0,7491 / 0,7768 / FPR 0,2871 | Thêm hàng |
| **11** | “XGBoost … lựa chọn tối ưu cho Realtime Pipeline” | Default RF-binary | **Xóa**; nói RF live, XGB legacy |
| **11** | “~77% = chống Zero-day ngoài đời thực” | 21 scenario lab | Hạ: unseen **trong testbed**, không zero-day production |
| **13** | Delay **99,55%** · Normal **94,09%** · BW **88,35%** · Loss **87,41%** | 0,9933 · 0,9449 · 0,8881 · 0,8765 | Sửa đúng `*_d2_per_class.csv` |
| **13** | D1 “gần như tuyệt đối” | Acc 0,9804; Normal rec 0,921 | Bỏ “tuyệt đối” |
| **14** | SHAP “8 đặc trưng” tên `packet_rate` / `ratio_bytes_per_pkt` | 8 cột code khác tên; SHAP Word = XGB **đa lớp 10** feat | Tách: SHAP legacy 10 cổng ≠ schema live 8 |
| **15** | 12,99 / 17,59 = “**Độ trễ Thực tế**” | Chỉ infer | Đổi nhãn: inference p50/p95 |
| **15** | Không nêu priority 1000 | Code 1000 | Thêm priority + hard_timeout 120 |
| **16** | “Auto-Mitigation Trigger (**~12.99 ms**)” | 12,99 ≠ FlowMod | **Sửa bắt buộc** — hội đồng bắt ở đây |
| **18** | “XGB tối ưu Realtime (**~0,44 ms**)” | Sai artifact | Xóa; RF Acc 0,7724 + 12,99 ms infer |
| **8, 20, 21** | Không extract được chữ (ảnh) | — | Mở file: nếu còn 79k / XGB deploy / Acc 0,99 → thay |

**Slide tạm ổn (chữ):** 2 mục lục; 3 bối cảnh (đừng biến Packet-In thành input ML — input là FlowStats); 5 kiến trúc 2s6h; 6 số 326961/206/21; 9 hai bài tách; 12 E 1982/112/36/1534; 17 hạn chế FPR 16 % + Mininet; 22 cảm ơn.

**Nếu chỉ kịp 5 chỗ:** slide **10** (bảng), **11** (XGB realtime), **16** (12,99 ms trigger), **18** (kết luận 0,44 ms), **4** (phản ứng 12,99 ms).

---

## 15. Câu được nói / cấm nói

### Được nói

- “Tự thu Mininet 2s6h, os-ken, OpenFlow 1.3.”  
- “326.961 snapshot, 206 run, 21 scenario — không i.i.d.”  
- “LOSO RF Acc 0,7724, F1 Attack 0,7746, FPR 0,1616; min recall 0 tại `portscan_nmap_h4_h1`.”  
- “Live: Random Forest binary, 8 feature, NORMAL/ANOMALY.”  
- “Protocol E D2 RF 0,9250 / 0,9281, 1534 snapshot, lab only; IF/AE N/A.”  
- “DROP priority 1000, hard_timeout 120, 3 poll hoàn chỉnh.”  
- “12,990 ms là suy luận RF, không phải E2E.”  
- “Protocol D D2 ~0,38 vì tc/probe hỏng — phụ lục.”  
- “Năm mô hình; AE/IF fail anomaly LOSO.”  
- “SVM SOC ≠ SVM LOSO.”

### Cấm nói

- Acc ~0,999 / 0,9991 / “tốt nhất tuyệt đối”.  
- 79k, 11k, XGB Acc 0,9191 (bảng LOSO cũ).  
- “XGBoost là mô hình triển khai.”  
- “0,33 ms” hoặc “0,44 ms” cho hệ live.  
- “12,99 ms là thời gian chặn / phản ứng.”  
- “326k phiên độc lập” / “quy mô CICIDS”.  
- “Dataset syslog HUFLIT” / “train trên CICIDS”.  
- “D2 IF/AE Acc = …”  
- “Protocol D 0,38 là kết quả hiện tại.”  
- “Đưa lên mạng trường được.”  
- “AE keras chắc chắn load được.”  
- “Dashboard Acc = LOSO.”  
- So “hơn bài báo X”.

---

## 16. Phân công miệng (nếu hỏi)

| | Việc thật trên repo |
|--|---------------------|
| **Tú** | Mininet, os-ken, thu thập, realtime, dashboard, mitigation, Git, demo |
| **Thiện** | Pipeline đánh giá, Word, đồng bộ số CSV, SHAP, bảng |

Nói “em phụ trách …” đúng cột. Đừng nhận train model nếu không phải mình bấm.

---

## 17. Chỉ mục file khóa (mang USB)

```
dataset/flow_stats_grouped.csv
dataset/fault_stats_grouped_e.csv
dataset/controller_config.json          → random_forest_binary
models/random_forest_binary_realtime.pkl
reports/binary_realtime_loso_summary.csv
reports/fault_protocol_e_audited_d1_loso.csv
reports/fault_protocol_e_audited_d2_loso.csv
reports/fault_protocol_e_audited_d1_per_class.csv
reports/fault_protocol_e_audited_d2_per_class.csv
reports/realtime_binary_artifact_benchmark.csv
reports/environment_lock.txt
KhoaLuanTotNghiep.docx
docs/CAM_NANG_BAO_VE_FULL.md            ← file này
```

Tái lập bảng anomaly: `python src/eval_binary_realtime_scenario_held_out.py`

---

*Hết cẩm nang. In 2 bản. Slide sửa 5 chỗ đỏ trước khi lên hội đồng. Word gần ổn — còn caption Hình 8–9.*

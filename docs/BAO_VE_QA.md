# Tài liệu ôn bảo vệ KLTN — Lý thuyết + Q&A

**Đề tài:** Phát hiện bất thường và phân loại lỗi mạng SDN bằng học máy  
**Nhóm:** Trịnh Hoàng Tú · Trần Minh Thiện | HUFLIT · An ninh mạng · K29  
**GVHD:** ThS. Cao Tiến Thành  

**Cách dùng:** đọc phần A (lý thuyết ngắn) → luyện phần B (Q&A) toạc miệng, không đọc nguyên văn.  
Số liệu lấy từ `reports/` tại thời điểm nộp (làm tròn như trong luận văn).

---

# A. LÝ THUYẾT CỐT LÕI (ôn nhanh)

## A1. SDN & lỗ hổng

- **SDN** tách Control Plane (controller) và Data Plane (switch).  
- **OpenFlow:** switch hỏi controller khi chưa có flow → **Packet-In**.  
- Điểm yếu: controller là **SPOF**; tấn công flood flow mới → bão hòa control channel / flow table.  
- Đề tài tập trung: **phát hiện bất thường trên Flow Statistics** (không deep packet inspection payload).

## A2. Pipeline hệ thống (1 câu)

```
Mininet (A4 topo 2SW/6H)
  → os-ken monitor: thu flow → flow_stats.csv
  → preprocess: clean → split → SMOTE(train) → train.csv/test.csv
  → train: XGB / RF / IF / AE (+ scaler riêng từng model)
  → realtime: controller/realtime_detector.py (XGB) + DROP rule + dashboard
```

**Hai app controller (nhớ rõ):**

| App | Launcher | Việc |
|-----|----------|------|
| `controller/monitor.py` | `run_controller.py` | Thu CSV (dataset) |
| `controller/realtime_detector.py` | `run_realtime.py` | Predict + alert + auto-block |

## A3. Dataset & provenance

- Bảng luận văn cũ: ~**11.283** mẫu: Portscan 10.565 · Normal 312 · DDoS 406 (6 lab thật + 400 bootstrap)
- **Pool train/controller hiện tại:** **79.114 snapshot / 5s** (không phải 79k phiên) · **23.843** 5-tuple last-poll · **19 `scenario_id`** · **32 `run_id`** · DDoS **43.206** · Portscan **20.238** · Normal **15.670**
- **Không dùng** `flow_stats.csv` 155k dump (nhãn portscan bẩn) và **không dùng** 20k Normal random.
- ~38k DDoS lúc đầu là nhãn cửa sổ + leftover nmap — không phải số chính.
- CICIDS2017 / InSDN chỉ đối chứng công khai, không train controller.

## A4. 10 đặc trưng

Controller / random-split vẫn 10 cột: `ip_proto, tp_src, tp_dst, packet_count, byte_count, duration_sec, packet_count_per_sec, byte_count_per_sec, packet_size_avg, flow_duration`.

Số generalization (LOSO) **bỏ `tp_src`/`tp_dst` thô** — model hay học dấu vết cách tạo traffic, không chỉ hành vi.

## A5. Tiền xử lý (thứ tự THẬT)

```
clean → extract → encode
→ train_test_split (80/20, stratify)
→ SMOTE chỉ TRAIN
→ lưu CSV
→ (khi train) StandardScaler fit TRAIN → transform TRAIN/TEST → model.fit
```

Scaler **không** nằm trong `preprocess.py`; nằm trong từng `train_*.py`.

## A6. Bốn mô hình

| Model | Học | Bài toán | Metric P/R/F1 | Vai trò |
|-------|-----|----------|---------------|---------|
| **XGBoost** | Supervised | Multiclass N/D/P | **Macro** | **Deploy realtime** |
| **Random Forest** | Supervised | Multiclass | **Macro** | Đối chứng (Acc cao nhất trên lab) |
| **Isolation Forest** | Unsupervised | Binary Normal vs Anomaly | **Anomaly-class** | Unsupervised nhẹ |
| **Autoencoder** | Unsupervised | Binary (MSE threshold) | **Anomaly-class** | Unsupervised học sâu |

**Ngưỡng AE:** percentile 95 MSE trên Normal-TRAIN pool 79.114 ≈ **0.0014**.

## A7. Số liệu nhớ thuộc (làm tròn)

**Số chính — 4 model binary LOSO (Normal vs Attack), 19 scenario, 3 poll đầu, bỏ cổng:**

| Model | Acc pooled | F1 anom | Recall scenario (min) | Normal FPR |
|-------|------------|---------|------------------------|------------|
| XGB | 0.919 | 0.954 | 0.907 (0.134) | 0.247 |
| RF | 0.887 | 0.935 | 0.862 (0) | 0.192 |
| AE | 0.083 | 0.007 | 0.102 (0) | 0.100 |
| IF | 0.081 | 0.001 | 0.071 (0) | 0.101 |

Pooled không đứng một mình. XGB/RF sót `portscan_nmap_h4_h1`. AE/IF baseline chết. Acc 0.9999 **cấm**.

**Grouped-by-run (trung gian, còn overlap scenario):** RF Acc 0.987 ± 0.008 · XGB 0.982 ± 0.017.

**Realtime:** poll **5 s**; block sau **3** alert liên tiếp → ~**≤15 s**; DROP `hard_timeout` **120 s**.

**Real-only XGB/RF:** Acc holdout **1.0000** nhưng `n_ddos_real=6`.  
**RF Real-only CV K=5:** Acc ≈ 0.9997±0.0004 · **F1_macro ≈ 0.8994±0.1343**.

**LOSO binary realtime (số generalization 4 model):**
- XGB F1-anom 0.954 · recall attack-scenario 0.907 (min 0.134) · Normal FPR 0.247
- RF F1-anom 0.935 · 0.862 (min 0) · FPR 0.192
- AE/IF Acc ~0.08 — không tô hồng.

**Public CICIDS2017 3-class (bổ sung, không phải OpenFlow):**
- 880.176 flows · Normal 662.383 · DDoS 127.175 · PortScan 90.618
- XGB Acc 0.9994 · F1_macro 0.9991 · RF Acc 0.9995 · F1_macro 0.9993
- IF / AE tụt mạnh (F1_anomaly 0.05 / 0.22)

**Public InSDN binary (bổ sung, domain SDN hơn CICIDS, nhưng chỉ 2 lớp):**
- 343.889 flows · Normal 68.424 · Anomaly 275.465
- XGB Acc 0.9986 · F1 0.9991 · RF Acc 0.9987 · F1 0.9992
- Không trộn vào train controller; không gọi đây là 3-class như lab.

## A8. Ba câu “không được nói sai”

1. Không nói Acc=1.0 = mạng thật / production.  
2. Không nói đã làm thí nghiệm zero-day độc lập.  
3. Không nói bootstrap chỉ sinh sau split (hiện tại bootstrap **trước** split — đã disclose hạn chế).

---

# B. Q&A KHẢ NĂNG XẢY RA

Mỗi câu: **Ý trả lời ngắn** → **Câu nói miệng** → **Bẫy / đừng nói**.

---

## B1. Tổng quan đề tài

### Q1. Đề tài làm gì? Đóng góp gì?

**Ý:** Pipeline SDN lab + ML đa mô hình + realtime mitigation.  
**Nói:**  
> Em xây testbed Mininet + os-ken, thu Flow Statistics, huấn luyện XGB/RF/IF/AE, và triển khai realtime trên controller: phát hiện rồi tự DROP IP nguồn. Đóng góp là **hệ thống khép kín** có so sánh supervised/unsupervised, baseline luật tĩnh, SHAP, và phần hạn chế/provenance — không chỉ train CSV.  

**Đừng:** “em invent thuật toán mới”.

### Q2. Vì sao chọn SDN / OpenFlow flow chứ không packet payload?

**Nói:**  
> Flow stats sẵn từ OpenFlow, chi phí thấp, phù hợp control plane. DPI payload nặng và thường không có trên switch OpenFlow thuần. Mục tiêu là phát hiện hành vi bất thường mức luồng.  

### Q3. os-ken là gì? Sao không Ryu?

**Nói:**  
> Ryu ngừng maintain / kém hỗ trợ Python mới. os-ken là fork OpenStack, API gần như Ryu, pin **4.2.0** trong requirements.  

---

## B2. Dataset & imbalance (HỎI NHIỀU)

### Q4. Dataset lấy ở đâu? Có dùng CICIDS/InSDN không?

**Nói:**  
> Benchmark chính là dữ liệu tự thu trên Mininet/OpenFlow. Em không train controller bằng dataset công khai. Ngoài lab, em có hai đối chứng: **CICIDS2017 3-class (~880k)** và **InSDN binary (~344k, domain SDN hơn)**. InSDN bản em tải được chỉ có nhãn 0/1 nên không thay 3 lớp `normal/ddos/portscan` của đề tài.  

**Nếu muốn trả lời chắc hơn:**  
> Quan trọng hơn public data, em đã thu thêm run độc lập trong chính lab SDN: **20 `run_id`**, khoảng **43k mẫu DDoS lab** sau khi lọc leftover, rồi đánh giá GroupKFold theo phiên thu. 

### Q5. Tại sao Portscan áp đảo? Có bias không?

**Nói:**  
> nmap sinh nhiều flow ngắn → số mẫu lớn. Em xử lý bằng SMOTE trên train + đánh giá macro / per-class, không chỉ Accuracy.  

### Q6. DDoS chỉ 6 mẫu thật — có đủ không?

**Nói (thẳng):**  
> Với bảng cũ thì không đủ — chỉ 6 DDoS lab thật. Em không lấy con số ~38k lúc thu ồ ạt vì đó là nhãn cả cửa sổ, dính flow nmap còn trong bảng OpenFlow. Sau khi lọc attacker↔target và thu thêm flood đa cổng, pool grouped có khoảng **43k DDoS lab** trên **11 run DDoS**. Vẫn tách public CICIDS/InSDN ra, không trộn vào controller. 

### Q7. Bootstrap / synthetic có phải “bịa số” không?

**Nói:**  
> Bootstrap từ phân phối seed lab để giảm thiểu số lớp DDoS trước SMOTE. Em **disclose** và không diễn giải như traffic doanh nghiệp.  

### Q8. Bootstrap trước split có leakage không?

**Nói:**  
> Có rủi ro độc lập test vì synthetic vào pool trước split. Luận văn đã ghi hạn chế; hướng cải thiện: chỉ bootstrap từ DDoS thuộc TRAIN sau split.  

---

## B3. SMOTE & pipeline

### Q9. SMOTE làm gì? Sao không oversample test?

**Nói:**  
> SMOTE nội suy mẫu thiểu số trên **train only**. Oversample test → rò thông tin, metric ảo.  

### Q10. SMOTE nằm file nào? Phụ lục train sao không thấy SMOTE?

**Nói:**  
> Trong `src/preprocess.py` sau `train_test_split`. `train.csv` đã SMOTE sẵn; `train_model.py` chỉ scaler + fit — **không** SMOTE lần hai.  

### Q11. Thứ tự scaler và SMOTE?

**Nói:**  
> Code thật: **split → SMOTE → lưu CSV → (train) StandardScaler**. Scaler fit trên train đã cân bằng.  

---

## B4. Mô hình & metric (HỎI NHIỀU)

### Q12. Vì sao 4 mô hình?

**Nói:**  
> XGB/RF: phân loại tấn công đã biết (multiclass). IF/AE: phát hiện anomaly không cần nhãn đầy đủ (binary). So sánh trade-off độ chính xác / chi phí / latency.  

### Q13. Macro vs Anomaly-class — giải thích?

**Nói:**  
> XGB/RF: P/R/F1 **macro** (trung bình các lớp). AE/IF: P/R/F1 của lớp **Anomaly** (positive), Acc là overall binary. Không trộn hai kiểu.  

### Q14. AE threshold lấy sao? Sao không 2.355?

**Nói:**  
> 95th percentile MSE trên Normal **train** sau StandardScaler. Pool 79.114 hiện tại ≈ **0.0014**. Số 0.0473 là ngưỡng của bảng 11k cũ; 2.355 là sai thang. Threshold **không** tính trên test.  

### Q15. AE Recall Anomaly = 100% nghĩa là gì? Macro thì sao?

**Nói:**  
> Không bỏ sót anomaly trên test (FN=0). Macro Recall thấp hơn vì Normal Recall ~95% (có FP).  

### Q16. Isolation Forest contamination = 0.05?

**Nói:**  
> Siêu tham số giả định tỷ lệ outlier khi fit trên Normal lab — **không** phải tỷ lệ attack ~97% trong dataset.  

### Q17. Hình IF score âm dương?

**Nói:**  
> Plot dùng `−decision_function` sklearn; cao hơn = bất thường hơn. Không đồng nhất công thức s(x)∈[0,1] lý thuyết Liu.  

### Q18. Baseline luật tĩnh kém thế?

**Nói:**  
> Static/Multi-Rule/Z-score: Precision cao nhưng Recall rất thấp trên bài binary Attack vs Normal. ML tận dụng tổ hợp nhiều feature. So sánh **không** đồng nhất hoàn toàn với multiclass XGB/RF — đã ghi chú.  

### Q19. SHAP nói gì? Khác Feature Importance?

**Nói:**  
> Gain FI (XGB) và mean \|SHAP\| có thể xếp hạng khác nhau. SHAP nổi `tp_src`/`tp_dst` + cường độ luồng → hợp lab portscan/ddos; đồng thời là hạn chế nếu attacker đổi pattern cổng.  

---

## B5. Random Forest = 1.0000 (CÂU SỢ NHẤT)

### Q20. Sao RF (và Real-only) Acc = 1.0000? Overfit à?

**Nói (thuộc lòng):**  
> Trên lab Mininet, traffic hping3/nmap tách rất rõ so với ping/iperf trên 10 feature tabular — RF/XGB dễ đạt gần tuyệt đối. Real-only Acc=1.0 trên holdout **không** chứng minh production: chỉ có **6 DDoS thật**. CV 5-fold real-only: Acc vẫn cao nhưng **F1-macro ≈ 0.90 ± 0.13** — một fold sai 1 mẫu DDoS là macro-F1 tụt. Em báo cáo cả hai góc nhìn và chọn **XGB realtime** vì latency thấp hơn (~0.3 vs ~15 ms), không chọn RF dù Acc bảng cao hơn.  

**Nếu bị vặn tiếp:**  
> Em còn chạy benchmark công khai CICIDS2017 đã map về cùng schema 10 feature. Trên đó RF vẫn đạt **Acc ~0.9995, F1-macro ~0.9993** và XGB đạt **Acc ~0.9994, F1-macro ~0.9991**. Như vậy kết quả không chỉ sống nhờ `6` mẫu DDoS lab, nhưng em vẫn không gọi đó là production vì benchmark công khai này không phải môi trường SDN realtime của bài toán gốc.  

**Nếu hội đồng xoáy đúng hướng SDN:**  
> Quan trọng hơn public benchmark, em đánh giá grouped theo `run_id` ngay trong lab. RF: **Acc ~0.9981 ± 0.004, F1_macro ~0.988**. XGB trung bình thấp hơn và **lệch fold** (một fold portscan Acc ~0.25) dù DDoS recall vẫn ~1.0. CICIDS/InSDN chỉ đối chứng phụ. 

**Đừng:** “model hoàn hảo” / “chắc chắn bắt mọi DDoS”.

### Q21. Vậy kết quả có ý nghĩa gì?

**Nói:**  
> Chứng minh pipeline và feature OpenFlow **khả thi** trên testbed có kiểm soát; so sánh được supervised/unsupervised và baseline; có đường triển khai controller. Ý nghĩa engineering + phương pháp, không phải benchmark IDS thực địa.  

### Q22. Sao không hạ hyperparameter RF cho Acc “trông thật” hơn?

**Nói:**  
> Em đã thử ràng buộc sâu cây — lab vẫn dễ tách. Hạ số giả tạo không trung thực; cách đúng là disclose + CV + hạn chế dữ liệu.  

---

## B6. Realtime & mitigation

### Q23. Realtime chạy file nào?

**Nói:**  
> `python controller/run_realtime.py` → `realtime_detector.py`. Không nhầm `run_controller.py` / `monitor.py` (thu data).  

### Q24. Detect xong làm gì?

**Nói:**  
> Log ALERT; đủ **3** lần liên tiếp từ cùng IP → cài DROP OpenFlow trên mọi switch, timeout **120 s**, ghi `alerts.json` cho dashboard.  

### Q25. Độ trễ phát hiện?

**Nói:**  
> Chu kỳ poll **5 s** + inference. Mitigation khoảng **≤ ~15 s** nếu đủ 3 alert. Tách với latency per-flow inference (~0.3 ms).  

### Q26. Demo DDoS “không ăn” / ping được?

**Nói:**  
> Dùng `hping3 -S -k --flood -p 80 <victim>` (**có -k** giữ sport) để flow gộp packet_count cao giống data train. Flood không `-k` tạo micro-flow → dễ lệch PORTSCAN/NORMAL hoặc bão Packet-In.  

### Q27. Có false positive block host lành không?

**Nói:**  
> Có rủi ro. Threshold 3 alert + timeout 120s giảm block vĩnh viễn. Lab sạch → FP thấp hơn mạng thật — hạn chế đã nêu.  

---

## B7. Hạn chế & hướng phát triển

### Q28. Hạn chế chính?

**Nói:**  
> (1) Chỉ 3 nhãn; (2) Mininet ít nhiễu; (3) Bảng cũ DDoS thật ít + bootstrap trước split; (4) CICIDS mirror thiếu `Protocol/Source Port`; (5) InSDN public chỉ binary; (6) XGB grouped vẫn gãy trên fold portscan dù DDoS đã nhiều. 

### Q29. Sao không dùng log HUFLIT luôn?

**Nói:**  
> Em có audit log FortiGate HUFLIT, nhưng đó là firewall/session log khác modality so với OpenFlow flow statistics của hệ thống hiện tại và chưa có nhãn `normal/ddos/portscan` tương thích trực tiếp. Nếu ép dùng gấp sẽ phải ETL và heuristic labeling khá mạnh, nên em không chọn nó làm benchmark chính ở giai đoạn này.  

### Q30. Làm tiếp gì?

**Nói:**  
> Thu thêm DDoS/Normal thật theo `run_id`; bootstrap sau split; đánh giá cross-topo; tinh chỉnh mitigation; nếu có thời gian thì làm ETL riêng cho FortiGate HUFLIT như external stress test.  

**Nếu hỏi “ưu tiên cái gì nhất?”**  
> Em ưu tiên benchmark grouped trong chính lab SDN trước, vì nó đúng đề tài hơn mọi benchmark ngoài.  

### Q31. Đóng góp cá nhân Tú / Thiện?

**Nói theo đúng bảng phân công luận văn** (Tú: lab/controller/demo; Thiện: ML/báo cáo). Không nhận phần của người kia.

---

## B8. Câu “đánh nhanh” kỹ thuật

### Q32. Packet-In là gì?

> Switch gửi gói/header lên controller khi không khớp flow (hoặc gửi controller theo rule).

### Q33. Flow table saturation?

> Bảng flow đầy → flow hợp lệ khó cài. Em **mô phỏng flood tải cao**; không đo occupancy chi tiết trừ khi có số liệu — tránh claim quá mạnh.

### Q34. Supervised vs unsupervised khi nào?

> Có nhãn rõ, kiểu tấn công biết trước → XGB/RF. Í thường sạch, cần cờ anomaly / biến thể → IF/AE. Hệ thống thực tế có thể xếp tầng.

### Q35. Vì sao không Deep Learning phức tạp hơn?

> 10 feature tabular; XGB/RF đã rất mạnh; AE đủ minh họa DL; latency/control plane ưu tiên mô hình nhẹ.

### Q36. Stratify / SMOTE / contamination / hard_timeout?

> Stratify: giữ tỷ lệ lớp khi split. SMOTE: oversample train. Contamination: tỷ lệ outlier giả định IF. hard_timeout: rule tự hết hạn.

---

# C. CHEAT SHEET 60 GIÂY (trước vào phòng)

1. Làm **hệ thống SDN+ML khép kín**, không invent algo.  
2. Data = **79.114 snapshot / 5s** (23.843 5-tuple · 19 scenario · 32 run). Không 231k. Không nói “79k phiên”.  
3. SMOTE **train only** trong `preprocess.py`.  
4. RF Acc=1.0 = **lab dễ tách**, không = production; xem CV F1-macro.  
5. Deploy **XGB** vì **latency**.  
6. Realtime = **`realtime_detector.py`**; monitor = thu CSV.  
7. AE threshold **≈ 0.0014** trên Normal-train pool 79k.  
8. Số chính = binary LOSO: XGB F1-anom 0.954 · recall scenario 0.907 (min 0.13) · Normal FPR 0.25. AE/IF ~0.08. Acc 0.9999 cấm.  

---

# D. CÂU HỎI “XẤU” — trả lời mẫu 1 câu

| Hỏi | Trả lời 1 câu |
|-----|----------------|
| Đồ chơi Mininet thôi à? | Đúng là testbed giả lập; giá trị nằm ở pipeline + realtime có kiểm soát, em không claim production. |
| 100% là gian lận? | Không — lab tách lớp + mẫu DDoS thật ít; em đã disclose và đưa CV F1 thấp hơn. |
| Sao không dataset chuẩn? | Scope là OpenFlow tự thu; CICIDS ~880k và InSDN ~344k chỉ đối chứng, không train controller. |
| Block nhầm user thì sao? | Có rủi ro FP; threshold 3 + timeout 120s; mạng thật cần tinh chỉnh thêm. |
| Em hay Thiện code phần này? | Trả lời đúng phân công — không nhận bừa. |

---

**Tái tạo số liệu nếu bị hỏi “chạy lại được không?”**

```bash
python src/preprocess.py
python src/train_model.py
python src/train_random_forest.py
python src/compare_models.py
python src/eval_real_only.py
python controller/run_realtime.py   # demo
```

Ôn xong: mỗi người trả lời toạc **Q20, Q10, Q23, Q6, Q28** không nhìn tài liệu.

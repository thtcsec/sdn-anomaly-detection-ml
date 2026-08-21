# Hướng dẫn sửa Word & Slides (Thiện copy số ở đây)

Hội đồng hỏi pipeline / lý thuyết / CSV: dán `docs/VA_HOI_DONG_LY_THUYET_VA_SO_DO.md` + 4 hình method trong mục 7.

Chỉ dùng số mục 1–2 trên slide/chương Kết quả. **Không** dùng 231.314 / 20k Normal giả / Acc 0,80 / Acc 0,9999 làm số chính.

Người sửa: Trần Minh Thiện. Nguồn số: `reports/binary_realtime_loso_summary.csv`.

### Môi trường (sửa Word cho khớp `requirements.txt`)

Bảng kết quả cuối chạy trên Python 3.11.9 với:

| Gói | Version khóa | Không ghi |
|-----|--------------|-----------|
| XGBoost | **3.2.0** | 2.0.3 |
| scikit-learn | **1.7.2** | 1.4.2 |
| TensorFlow | **2.21.0** | 2.16.1 |
| pandas | **2.3.1** | 2.2.2 |
| numpy | **2.2.6** | 1.26.4 |
| os-ken | **4.2.0** | |

Nguồn: `reports/environment_lock.txt`.

---

## 1. Dataset (bảng phân phối + slide Dataset)

Pool train/controller: independent OpenFlow, `run_id` thật. Nguồn: `dataset/flow_stats_grouped.csv` + `reports/grouped_real_only_STATUS.csv`.

| Nhãn | Số mẫu (poll 5s) | Tỷ lệ | Nguồn |
|------|------------------|-------|--------|
| Normal | **198.810** | 60,81% | 135 run ping/iperf/HTTP/UDP qua switch |
| DDoS | **93.648** | 28,64% | 44 run hping3 (SYN/UDP/ICMP, multiport) |
| Portscan | **34.503** | 10,55% | 27 run nmap (SYN/connect, nhiều dải cổng) |
| **Tổng** | **326.961 snapshot** | 100% | **206 `run_id` · 21 `scenario_id`** |

Phải viết ngay dưới bảng:

> 326.961 là số lần controller poll OpenFlow mỗi 5 giây, không phải 326.961 phiên traffic độc lập. Last-poll theo 5-tuple còn **113.226** mẫu (`scenario_held_out_STATUS.csv`). Đánh giá generalization tách theo **21 kịch bản**. Đây là thêm run độc lập trên **cùng lab 2 switch / 6 host** — không phải quy mô đa dạng kiểu CICIDS2017.

- Bảng luận văn cũ **11.283** (DDoS lúc đầu 6 mẫu thật + 400 bootstrap) và mốc **79.114 / 32 run / 19 scenario** **giữ như lịch sử**.
- Train 80/20 + SMOTE chỉ là pipeline phụ lục, không phải số chính.

### Đoạn phương pháp — Normal (paste Word)

> Tập Normal không sinh ngẫu nhiên. Dữ liệu thu từ 135 phiên Mininet độc lập (`run_id` riêng) trên 4 kịch bản: ICMP (ping), TCP (iperf/HTTP), UDP (iperf), đi qua switch OpenFlow 1.3, os-ken ghi flow stats mỗi 5 giây. Nhóm không dùng bộ sinh 20.000 dòng đã thử rồi loại.

**Cấm viết:** 231.314 mẫu; Normal 20k HTTP/DNS/SSH; `flow_stats.csv` 155k là nmap thật; Acc random-split ~0,999 làm số chính.

---

## 2. Bảng model — DUY NHẤT được chiếu là Kết quả (headline = Random Forest)

Nguồn: `reports/binary_realtime_loso_summary.csv` (pool 326.961 · **21** scenario). **Không** dùng bảng LOSO cũ 79k (XGB Acc 0,9191 / F1 0,9544 / min-recall 0,1342).

Cùng bài: **Normal vs Attack** · LOSO 21 scenario · 3 poll đầu/5-tuple · 8 feature **bỏ `tp_src`/`tp_dst`** · không SMOTE.

| Model | Acc pooled | F1 anomaly | P anomaly | R anomaly | Recall theo scenario tấn công | Normal FPR (mean / max) |
|-------|------------|------------|-----------|-----------|-------------------------------|-------------------------|
| Random Forest | **0,7724** | **0,7746** | 0,7808 | 0,7684 | **0,7301** (min **0**) | **0,1616 / 0,2928** |
| **XGBoost** | 0,7520 | 0,7556 | 0,7577 | 0,7535 | **0,7223** (min **0**) | **0,1805 / 0,3150** |
| Autoencoder | 0,4759 | 0,0463 | 0,3122 | 0,0250 | 0,0495 (min 0) | 0,0614 / 0,0746 |
| Isolation Forest | 0,4665 | 0,0003 | 0,0029 | 0,0001 | 0,0036 (min 0) | 0,0484 / 0,0638 |

### Đoạn bắt buộc dưới bảng (paste Word)

> Acc/F1 pooled không đứng một mình. Trên protocol LOSO mới, RF hơi cao hơn XGB, nhưng **min attack recall = 0** (cả hai sót `portscan_nmap_h4_h1`, 149 snapshot). Normal FPR trung bình ~0,16–0,18 (max ~0,29–0,32). AE/IF thất bại trên lab này và chỉ giữ làm baseline. Accuracy ~0,999 của random-flow split phản ánh rò cùng 5-tuple khi poll 5 giây, không dùng để suy rộng. LOSO min-recall = 0 là điểm yếu phải nói thẳng.

**Headline anomaly LOSO = Random Forest** (Acc 0,7724 / F1 0,7746 / FPR mean 0,1616). LinearSVC F1 nhỉnh hơn một chút nhưng FPR Normal xấu hơn (~0,29) — **không** chiếu SVM. XGBoost chỉ thắng latency (~0,44 ms). AE/IF thất bại trên lab (binary only). **Không** dùng Acc ~0,999 random-split.

Deploy realtime vẫn XGBoost prototype (latency ~0,44 ms trên `model_comparison.csv`). Candidate 8-feature **không** bật DROP vì FPR Normal.

## 2b. Fault — hai câu hỏi D1 vs D2, không trộn vào anomaly

Hai câu hỏi **không gộp**: D1 = phát hiện fault vs normal; D2 = 4 lớp normal / bandwidth / loss / delay.

### Headline — Protocol E (lab 2s6h, **không** phải campus SDN)

Nguồn: `dataset/fault_stats_grouped_e.csv` (**1.982** snapshot · **112 `run_id`** · **36 `scenario_id`** · delay 570 · bandwidth 553 · loss 529 · normal 330) · `reports/fault_protocol_e_d1_loso.csv` / `fault_protocol_e_d1_per_class.csv` / `fault_protocol_e_d2_loso.csv` / `fault_protocol_e_d2_per_class.csv` (pooled n_test = **1534**).

D1 — năm mô hình (Normal vs Fault). IF/AE train **Normal-only** từng fold LOSO; scaler fit train-fold; ngưỡng AE = percentile 95 MSE train-normal. Keras 3 / TF 2.21 CPU. Nguồn: `fault_protocol_e_d1_loso.csv`, `fault_protocol_e_d1_per_class.csv`.

| Model | Acc | F1-macro | Recall Normal | Recall Fault |
|-------|-----|----------|---------------|--------------|
| Random Forest | **0,9811** | **0,9652** | 0,9213 | 0,9930 |
| XGBoost | 0,9759 | 0,9554 | 0,9016 | 0,9906 |
| SVM (RBF) | 0,9681 | 0,9414 | 0,8858 | 0,9844 |
| Autoencoder | 0,5456 | 0,4899 | 0,6496 | 0,5250 |
| Isolation Forest | 0,1382 | 0,1314 | 0,6850 | 0,0297 |
| Rule-based | 0,4954 | 0,4814 | 1,0000 | 0,3953 |

D2 — 4 lớp. IF/AE **N/A** (unsupervised không gán 4 nhãn; không bịa Acc 4-class).

| Bài | RF Acc / F1-macro | XGB | SVM (RBF) | Rule Acc | IF / AE |
|-----|-------------------|-----|-----------|----------|---------|
| **D2** 4 lớp | **0,923 / 0,926** | 0,902 / 0,903 | 0,886 / 0,889 | 0,411 | **N/A** |

Recall D2 RF (LOSO pooled): Bandwidth **0,883** · Loss **0,874** · Delay **0,996** (cả ba ≥ 0,82) · Normal 0,941.

> **Headline D2 = Random Forest.** SVM nằm trong bảng, kém RF, không chiếu. Unsupervised chỉ trả lời D1. D2 Protocol E **được nói** trên lab Mininet 2 switch / 6 host sau khi gắn `tc` đúng cổng OVS và probe xuyên s1↔s2. **Không** suy ra campus SDN / production.

### Phụ lục — Protocol D (thí nghiệm inject hỏng, **không** phải số hiện tại)

Nguồn: `dataset/fault_stats_grouped.csv` (= `fault_stats_grouped_protocol_d.csv`) · 6666 snapshot · 324 run · 36 scenario · delay 1864 · bandwidth 1857 · loss 1839 · normal 1106 · pooled n_test = 5370.

| Bài | RF Acc / F1-macro | XGB | Rule Acc |
|-----|-------------------|-----|----------|
| D1 | 0,9339 / 0,8636 | 0,9272 / 0,8527 | 0,1598 |
| D2 | 0,3726 / 0,4168 | 0,3793 / 0,4200 | 0,1598 |

> Protocol D: `tc` không gắn lên OVS + probe iperf cùng switch → D2 Acc ~0,38. **Cấm** đưa ~0,38 làm kết quả hiện tại. Giữ như lịch sử / bài học thu thập.

## 2c. SVM — model thứ 5 (baseline, không thay RF/XGB)

SVM là baseline có giám sát cổ điển cho bảng so sánh. Không thay Random Forest / XGBoost trên deploy, không kỳ vọng tự chữa D2 nếu feature còn chồng.

SOC dropdown: SVM có trên radio; pickle live là LinearSVC 10-feature random-split — **không** dùng số demo làm LOSO.

Anomaly LOSO binary (`reports/binary_realtime_loso_summary.csv`):

| Model | Acc pooled | F1 anomaly | Mean attack recall (min) | Normal FPR mean (max) |
|-------|------------|------------|--------------------------|------------------------|
| Random Forest | **0,7724** | 0,7746 | 0,7301 (**0**) | **0,1616 / 0,2928** |
| XGBoost | 0,7520 | 0,7556 | 0,7223 (**0**) | 0,1805 / 0,3150 |
| LinearSVC | 0,7491 | **0,7768** | 0,8524 (**0**) | 0,2871 / 0,5613 |
| Autoencoder | 0,4759 | 0,0463 | 0,0495 (0) | 0,0614 / 0,0746 |
| Isolation Forest | 0,4665 | 0,0003 | 0,0036 (0) | 0,0484 / 0,0638 |

LinearSVC F1 nhỉnh RF một chút nhưng FPR Normal xấu hơn (~0,29 vs 0,16); min-recall vẫn 0. **Không** chiếu SVM như model thắng trên anomaly. Fault D2 Protocol E: SVM Acc 0,886 / F1 0,889 — kém RF 0,923 / 0,926, chỉ là cột thứ 5. IF/AE chạy D1 (AE Acc 0,546 / IF Acc 0,138); **N/A trên D2 4-class**.

---

## 3. Phụ lục — được phép một đoạn, không phải slide Kết quả

### 3a. Random-flow (leakage)

`reports/model_comparison.csv` — chỉ giải thích “lab dễ tách + latency”.

| Model | Acc | F1 | Latency |
|-------|-----|-----|---------|
| XGBoost | 0,9999 | 0,9999 | ~0,44 ms |
| Random Forest | 0,9997 | 0,9995 | ~26 ms |
| Autoencoder | 0,9867 | 0,9918 (anom) | ~34 ms |
| Isolation Forest | 0,1878 | 0,0008 | ~4 ms |

> Số này không phải generalization.

### 3b. Grouped-by-run (còn overlap scenario)

RF Acc 0,9931 ± 0,0082 · F1-macro 0,9863 ± 0,0093. XGB Acc 0,9937 ± 0,0049 · F1-macro 0,9872 ± 0,0055. Ghi rõ cùng `scenario_id` có thể nằm cả train và test — **không** phải số generalization.

### 3c. Public (không train controller) — PHẠM VI BẮT BUỘC

Paste nguyên văn vào Word/slides khi nhắc InSDN hoặc CICIDS. **Không** dùng số public thay Bảng 5 / mô hình realtime.

**InSDN (external SDN-security benchmark, không thay testbed):**

> Sử dụng InSDN như một external benchmark cho nhánh phát hiện bất thường an ninh trong môi trường SDN, nhằm đánh giá khả năng của XGBoost và Random Forest trên dữ liệu SDN độc lập với testbed tự xây dựng. Kết quả được báo cáo như thực nghiệm bổ sung và không được sử dụng thay thế cho benchmark chính hoặc mô hình realtime.

Số khóa: 343.889 · XGB/RF F1 ≈ 0,999 · chỉ 2 lớp. Nguồn: `reports/public_benchmark/INSDN_BINARY_SUMMARY.md`.

**CICIDS2017 (appendix / intrusion-detection tham khảo, không phải SDN):**

> CICIDS2017 được sử dụng ở mức tham khảo/benchmark bổ sung cho bài toán intrusion detection nói chung. Do dataset không được thu thập từ kiến trúc SDN/OpenFlow, kết quả không được sử dụng để đánh giá khả năng tổng quát hóa của pipeline SDN hoặc mô hình triển khai trên os-ken Controller.

Số khóa: 880.176 · XGB/RF F1-macro ≈ 0,999 — không phải OpenFlow 5s. Nguồn: `reports/public_benchmark/CICIDS2017_3CLASS_SUMMARY.md`.

---

## 4. Checklist sửa Word (làm lần lượt)

1. Chương dataset: 326.961 **snapshot** / 113.226 5-tuple / 21 scenario / 206 run. Giữ 11.283 và 79.114 như lịch sử.
2. Không xóa câu “DDoS từng chỉ 6 mẫu thật”.
3. Thay bảng kết quả bằng **mục 2** (LOSO: RF Acc 0,7724 · XGB 0,7520 · LinearSVC Acc 0,7491 FPR xấu hơn · min-recall **0**). SVM là cột thứ 5, không phải model thắng. Xóa Acc 0,9999 / AE 0,98 / bảng LOSO 79k khỏi bảng chính.
4. Thêm đoạn hạn chế: Mininet 1 topo 2s6h; 326k ≠ đa dạng CICIDS; sót `portscan_nmap_h4_h1` (min-recall 0); FPR Normal ~0,16–0,32; AE/IF fail; D2 Protocol E chỉ lab (không campus); Protocol D ~0,38 là thí nghiệm hỏng; chưa production.
5. Realtime: poll 5s · 3 polling reply / nguồn · DROP `hard_timeout` **120s** (không viết 60s). Không Acc 99,91%.
6. PCA/t-SNE: lab tách lớp → giải thích Acc random cao. Không bịa “chồng lấn mạnh”.
7. 3 lớp: một đoạn “phát hiện binary ổn hơn phân loại DDoS vs Portscan khi bỏ cổng thô”.
8. Không viết zero-day, không viết IDS tổng quát.
9. InSDN = thực nghiệm bổ sung SDN-security, **không** thay benchmark chính/realtime (dán đoạn 3c).
10. CICIDS2017 = phụ lục intrusion detection, **không** dùng đánh giá pipeline SDN / os-ken (dán đoạn 3c).
11. Fault: dán mục **2b**. Hai câu D1 vs D2. Headline = Protocol E (RF D2 Acc 0,923 / F1 0,926). Protocol D ~0,38 chỉ phụ lục. D2 E = lab only, không campus SDN.

---

## 5. Checklist slides

| Slide | Đúng | Sai |
|-------|------|-----|
| Dataset | 326.961 snapshot 5s · 113.226 5-tuple · 21 scenario · 206 run | “326k phiên” / CICIDS-scale / 79k như số hiện tại |
| Kết quả | Bảng mục 2 + mục 2c SVM + min recall **0** + FPR | Acc 0,9999 / LOSO 79k cũ / “5 model đều tốt” |
| Fault | **E D2 RF Acc 0,923 F1 0,926** (lab) · D1 E RF 0,981/0,965 · D = phụ lục ~0,38 | “D2 campus/production” / Acc 0,999 / Protocol D ~0,38 như số hiện tại |
| Hạn chế | Mininet 2s6h · min-recall 0 · FPR ~0,16–0,32 · D2 E chỉ lab | Campus SDN / production / zero-day |
| Realtime | Prototype XGB · poll 5s · DROP 120s | Acc 99,91% / Candidate robust đã bật |
| Phụ lục | 0,9999 = leakage · InSDN/CICIDS không train controller | Acc 1,000 tuyệt đối |

---

## 6. File số liệu

- **Chính anomaly:** `reports/binary_realtime_loso_summary.csv` · `binary_realtime_loso_per_scenario.csv` · `reports/THESIS_NUMBERS.md`
- **Chính fault E:** `reports/fault_protocol_e_d1_loso.csv` · `fault_protocol_e_d1_per_class.csv` · `fault_protocol_e_d2_loso.csv` · `fault_protocol_e_d2_per_class.csv`
- Trung gian: `reports/grouped_real_only_summary.csv` · `scenario_held_out_summary.csv`
- Phụ lục: `reports/model_comparison.csv` · `reports/fault_protocol_d*_loso.csv` (Protocol D, broken tc)
- Quay video: `HUONG_DAN_QUAY_VIDEO_DEMO.md`

---

## 7. Chèn ảnh vào Word (khớp `KLTN.pdf`)

Danh mục hình hiện tại của PDF chỉ có **3 chỗ đã đánh số**. Chèn đúng file dưới đây; **không** lấy `model_comparison_chart.png` (Acc ~1.0, random-split) làm Hình 1.

### Bắt buộc — đúng chỗ PDF đã để caption

| PDF | Mục | File chèn | Ghi chú caption |
|-----|-----|-----------|-----------------|
| **Hình 1** · tr. 27 · mục 4.2 | So sánh 4 mô hình LOSO | `reports/binary_realtime_loso_comparison.png` | Đây là **hình kết quả chính**. Ba cột: F1-anomaly, Mean Attack Recall, Normal FPR. |
| **Hình 2** · tr. 46 · Phụ lục H / mục 4.7.3 | Dashboard lúc DDoS | `reports/dashboard_live_alert.png` (cùng file `reports/thesis_shots/04_dashboard_ddos.png`) | Phiên lab 16/08/2026: h4 `hping3` → 10.0.0.1. Có ALERT, DROP `10.0.0.4`. Latency trên KPI là **lần suy luận live lúc flood**, không phải benchmark 0,33 ms. |
| **Hình 3** · tr. 47 · Phụ lục H / mục 4.7.2 | Log ALERT controller | `reports/controller_alert_terminal.png` | Log thật: `ALERT ... 10.0.0.4 -> 10.0.0.1 ... prediction=DDOS` rồi `BLOCKED ... 10.0.0.4`. **Không** còn warning feature names. |

Văn + Q&A hội đồng (lý thuyết Mininet/os-ken/4 model, sinh CSV, quyền khẳng định): `docs/VA_HOI_DONG_LY_THUYET_VA_SO_DO.md`.

### Nên chèn thêm (đánh số Hình 4…, cập nhật Danh mục hình)

| Vị trí Word | File | Vì sao |
|-------------|------|--------|
| **Ch.2 đầu** (trước mô tả dataset) | `reports/system_architecture_method.png` | Hai đường Control: `monitor.py` thu CSV / `realtime_detector.py` DROP. |
| **1.1** hoặc **3.2** (sau mô tả topo 2 switch / 6 host) | `reports/network_topology_method.png` | Sơ đồ Mininet h1–h6, s1–s2, os-ken, mũi tên h4→h1. |
| **Ch.2 thu thập** | `reports/data_collection_pipeline_method.png` | 8 bước sinh CSV + provenance `run_id`. |
| **Ch.2 method** | `reports/input_method_pipeline_method.png` | Input Flow Stats, 10 vs 8 feature, LOSO = nhận xét lab. |
| **4.7.2** startup | `reports/controller_startup.png` | Load XGBoost, mitigation 3 / 120s / poll 5s. |
| **4.7.3** idle | `reports/dashboard_idle.png` | 0 flow, 6 host NORMAL. |
| **4.7.3** Normal | `reports/dashboard_normal.png` | ping/iperf, nhãn NORMAL, 0 DROP. |
| **4.7.4** | `reports/dashboard_auto_mitigation.png` | DROP `10.0.0.4`. `10.0.0.1` cũng bị DROP — FPR lab, ghi vào hạn chế. |
| **4.7.5** Cấu hình SOC | `reports/dashboard_settings_models.png` | Không Acc 99.91%. Benchmark ~0,33 / ~15,25 ms/flow. |
| **4.3** (sau đoạn `portscan_nmap_h4_h1`) | Bảng từ `reports/binary_realtime_loso_per_scenario.csv` | Không có PNG sẵn; dán bảng 21 scenario (Recall/FPR). Có thể vẽ bar trong Word. |
| **4.5** | `reports/feature_importance_xgboost.png` | `tp_dst`/`tp_src` cao → giải thích vì sao LOSO **bỏ cổng thô**. Đây là model **10 feature đa lớp**, không phải LOSO 8 feature. |
| **4.5** (tuỳ chọn) | `reports/feature_importance_random_forest.png` hoặc `permutation_importance_random_forest.png` | Đối chứng RF. |
| **4.8** Thực nghiệm bổ sung | `reports/pca_2d_visualization.png` rồi `reports/tsne_2d_visualization.png` | Lab tách/chồng lớp → Acc random-split cao. Không viết “chồng lấn mạnh” nếu hình tách rõ. |
| **4.8** hoặc Phụ lục | `reports/split_vs_grouped.png` | Random-flow ~1.0 vs GroupKFold ~0.98. **Không** thay Hình 1. |
| Phụ lục (CM random-split) | `reports/confusion_matrix_xgboost.png` … `_random_forest.png` … `_autoencoder.png` … `_isolation_forest.png` | Chỉ phụ lục; ghi “random-flow, có rò 5-tuple”. |
| Phụ lục AE/IF | `reports/autoencoder_loss.png`, `autoencoder_error_dist.png`, `roc_curve_autoencoder.png`, `isolation_forest_score_dist.png` | Baseline thất bại trên LOSO; đừng để cạnh Hình 1 như “cả 4 model tốt”. |

### Cấm chèn làm kết quả chính

- `reports/model_comparison_chart.png` — Acc 1.000 / 0.9999
- Mọi CM/SHAP từ `reports/public_benchmark/` — CICIDS/InSDN, không phải OpenFlow lab
- Ảnh cũ Acc **1.0000** (Bảng 6–7 / Hình 10–11 bản Word cũ, support 63/81/2113)

### Caption mẫu Hình 1 (paste Word)

> Hình 1. So sánh bốn mô hình trên benchmark Leave-One-Scenario-Out (nhị phân Normal–Attack, 8 đặc trưng, không cổng thô, tối đa 3 snapshot đầu mỗi flow, 21 kịch bản). Random Forest/XGBoost giữ F1 lớp Attack ~0,75–0,77 nhưng min attack recall = 0 và Normal FPR trung bình ~0,16–0,18; Autoencoder và Isolation Forest thất bại trên protocol này.

---

## 8. Đoạn cần thay trong Word (PDF 64 trang, đọc lại 16/08)

Chương 4.1–4.7 và Kết luận **đã đúng số LOSO**. Chỉ sửa các chỗ dưới. Không dán Acc 0,9999 / 1,0000 vào Kết luận.

### 8.1. Mục 4.2 — một cụm từ

**Xóa:** `tại Bảng và biểu đồ so sánh ở Hình 1`  
**Thay:** `tại Bảng 5 và biểu đồ so sánh ở Hình 1`

### 8.2. Mục 4.3 — chèn hình sau đoạn `portscan_nmap_h4_h1`

**File:** `reports/loso_attack_recall_per_scenario.png`  
**Caption:**

> Hình 8. Recall của XGBoost và Random Forest trên từng attack scenario trong protocol Leave-One-Scenario-Out. Kịch bản `portscan_nmap_h4_h1` làm giảm Min Attack Recall xuống **0** (cả XGBoost và Random Forest).

**Câu chèn ngay dưới hình:**

> Biểu đồ cho thấy phần lớn kịch bản DDoS được nhận diện khá, trong khi `portscan_nmap_h4_h1` là lỗ thủng (recall 0). Mean Attack Recall ~0,72–0,73 **không** che được Min Attack Recall = 0.

### 8.3. Mục 4.8 — thay toàn bộ (đang viết “rất cao”, chưa có số, chưa có hình)

**Xóa** từ tiêu đề 4.8 đến hết mục (trước chữ KẾT LUẬN). **Dán:**

> **4.8. Thực nghiệm bổ sung và đối chiếu thiết kế đánh giá**
>
> Bên cạnh protocol Leave-One-Scenario-Out, nghiên cứu duy trì hai phép đánh giá thứ cấp nhằm đối chiếu ảnh hưởng của cách phân chia dữ liệu. Cả hai phép này **không** thay thế Bảng 5 khi kết luận về khả năng tổng quát hóa.
>
> Phép thứ nhất là Stratified random-split 80/20 trên bài toán đa lớp, sử dụng 10 đặc trưng có `tp_src` và `tp_dst`. SMOTE chỉ được fit trên tập Train sau khi đã tách Test. Trong điều kiện Train và Test cùng miền phân bố, XGBoost đạt Accuracy 0,9999 và F1-macro 0,9999; Random Forest đạt Accuracy 0,9997 và F1-macro 0,9995. Kết quả gần tuyệt đối phản ánh khả năng tách lớp trên lab khi các snapshot của cùng flow identity có thể xuất hiện ở cả hai tập, chứ không chứng minh mô hình nhận diện tốt một kịch bản chưa quan sát.
>
> Phép thứ hai là GroupKFold theo `run_id`. Accuracy trung bình đạt 0,9931 ± 0,0082 với Random Forest và 0,9937 ± 0,0049 với XGBoost. So với random-split, chỉ số vẫn rất cao vì các run khác nhau vẫn có thể thuộc cùng `scenario_id` — không thay Bảng 5.
>
> Hình 9. Đối chiếu Accuracy và F1-macro giữa random-flow 80/20 và GroupKFold theo `run_id`.
>
> Hình 10. Biểu diễn PCA 2D của hồ sơ đặc trưng Flow Statistics trên tập lab.
>
> Trên mặt phẳng PCA, các lớp có vùng tách được nhưng vẫn chồng lấn gần gốc tọa độ. Điều này phù hợp với việc các mô hình có giám sát đạt chỉ số rất cao khi Train–Test cùng miền, trong khi Autoencoder và Isolation Forest suy giảm mạnh khi toàn bộ một scenario được giữ làm Test.

**Chèn ảnh 4.8:**

| Caption | File |
|---------|------|
| Hình 9 | `reports/split_vs_grouped.png` |
| Hình 10 | `reports/pca_2d_visualization.png` |

Không chèn `model_comparison_chart.png` vào 4.8 như hình “kết quả chính”.

### 8.4. Kết luận — phải đổi số cho khớp Bảng 5 mới

Các số cũ 0,9191 / 0,9544 / 0,9074 / 0,1342 / 0,2469 **không còn đúng**. Thay bằng mục 2: RF Acc 0,7724 · F1 0,7746 · min-recall 0 · FPR 0,1616; XGB Acc 0,7520 · F1 0,7556 · min-recall 0 · FPR 0,1805. Giữ 0,33–0,44 ms / 120 giây.

**Xóa:** `nghiênên cứu`  
**Thay:** `nghiên cứu`

### 8.5. Phụ lục G — số 0,9991 / 0,9898 / 0,9987 **không** còn đúng trên bộ hiện tại

Đó là số giai đoạn tập **11.283** (có augmentation). CSV khóa hiện tại `reports/model_comparison.csv` (random-split 80/20, phụ lục) là:

| Mô hình | Accuracy | F1 | Ghi chú |
|---------|----------|-----|---------|
| XGBoost | **0,9999** | 0,9999 (macro) | Đa lớp, 10 feature |
| Random Forest | **0,9997** | 0,9995 (macro) | Đa lớp, 10 feature |
| Autoencoder | **0,9867** | 0,9918 (anomaly) | Nhị phân |
| Isolation Forest | **0,1878** | 0,0008 | Nhị phân; **không** còn 0,9898 |

**Thay cả khối Phụ lục G bằng:**

> Phụ lục G. Kết quả random-split 80/20 trên tập hiện tại (thứ cấp, không thay Bảng 5)
>
> XGBoost (đa lớp): Accuracy 0,9999 · F1-macro 0,9999  
> Random Forest (đa lớp): Accuracy 0,9997 · F1-macro 0,9995  
> Autoencoder (nhị phân): Accuracy 0,9867 · F1 anomaly 0,9918  
> Isolation Forest (nhị phân): Accuracy 0,1878 · F1 anomaly 0,0008
>
> Các chỉ số gần 1,0 của XGBoost/Random Forest phản ánh Train và Test cùng miền, có thể dùng chung flow identity khi poll 5 giây. Isolation Forest thất bại trên cùng phép chia. Không dùng phụ lục này để kết luận khả năng tổng quát hóa; số chính vẫn là Bảng 5 (LOSO).

### 8.6. Hình đã có sẵn — chỉ việc chèn / thay file

| PDF | File mới (đã vẽ lại từ CSV khóa) |
|-----|----------------------------------|
| **Hình 1** · 4.2 | `reports/binary_realtime_loso_comparison.png` |
| **Hình 2–6** · 4.7 | giữ screenshot demo đã chụp (`dashboard_*.png`, `controller_*.png`) |
| **Hình 8** · 4.3 (mới) | `reports/loso_attack_recall_per_scenario.png` |
| **Hình 9** · 4.8 (mới) | `reports/split_vs_grouped.png` |
| **Hình 10** · 4.8 (mới) | `reports/pca_2d_visualization.png` |

Cập nhật **Danh mục hình** cho khớp số Hình 8–10. Sửa caption Hình 5: `DdoS` → `DDoS`.

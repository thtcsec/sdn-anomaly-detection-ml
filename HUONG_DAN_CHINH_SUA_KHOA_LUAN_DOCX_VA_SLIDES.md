# Hướng dẫn sửa Word & Slides (Thiện copy số ở đây)

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

Pool train/controller: independent OpenFlow, `run_id` thật.

| Nhãn | Số mẫu (poll 5s) | Tỷ lệ | Nguồn |
|------|------------------|-------|--------|
| DDoS | **43.206** | 54,61% | 11 run hping3 (SYN/UDP/ICMP, multiport) |
| Portscan | **20.238** | 25,58% | 12 run nmap (SYN/connect, nhiều dải cổng) |
| Normal | **15.670** | 19,81% | 9 run ping/iperf/HTTP thật qua switch |
| **Tổng** | **79.114 snapshot** | 100% | **32 `run_id` · 19 `scenario_id`** |

Phải viết ngay dưới bảng:

> 79.114 là số lần controller poll OpenFlow mỗi 5 giây, không phải 79.114 phiên traffic độc lập. Gộp last-poll theo 5-tuple còn **23.843** mẫu. Đánh giá generalization tách theo **19 kịch bản**.

- Bảng luận văn cũ **11.283** (DDoS lúc đầu 6 mẫu thật + 400 bootstrap) **giữ như lịch sử**.
- Train 80/20 + SMOTE chỉ là pipeline phụ lục, không phải số chính.

### Đoạn phương pháp — Normal (paste Word)

> Tập Normal không sinh ngẫu nhiên. Dữ liệu thu từ 9 phiên Mininet độc lập (`run_id` riêng): ICMP (ping), TCP (iperf/HTTP), UDP (iperf), đi qua switch OpenFlow 1.3, os-ken ghi flow stats mỗi 5 giây. Nhóm không dùng bộ sinh 20.000 dòng đã thử rồi loại.

**Cấm viết:** 231.314 mẫu; Normal 20k HTTP/DNS/SSH; `flow_stats.csv` 155k là nmap thật.

---

## 2. Bảng 4 model — DUY NHẤT được chiếu là Kết quả

Nguồn: `reports/binary_realtime_loso_summary.csv`

Cùng bài: **Normal vs Attack** · LOSO 19 scenario · 3 poll đầu/5-tuple · 8 feature **bỏ `tp_src`/`tp_dst`** · không SMOTE.

| Model | Acc pooled | F1 anomaly | P anomaly | R anomaly | Recall theo scenario tấn công | Normal FPR |
|-------|------------|------------|-----------|-----------|-------------------------------|------------|
| **XGBoost** | 0,9191 | 0,9544 | 0,9832 | 0,9274 | **0,9074** (min **0,1342**) | **0,2469** |
| Random Forest | 0,8866 | 0,9349 | 0,9842 | 0,8902 | **0,8619** (min **0**) | **0,1915** |
| Autoencoder | 0,0831 | 0,0074 | 0,3504 | 0,0037 | 0,1022 (min 0) | 0,0999 |
| Isolation Forest | 0,0813 | 0,0005 | 0,0426 | 0,0002 | 0,0707 (min 0) | 0,1014 |

### Đoạn bắt buộc dưới bảng (paste Word)

> Acc/F1 pooled không đứng một mình vì số dòng tấn công chiếm đa số. XGBoost/Random Forest vẫn bỏ sót ít nhất một kịch bản nmap (`portscan_nmap_h4_h1`: XGB 0,134 · RF 0). Tỷ lệ báo động nhầm trên snapshot Normal khoảng 19–25%. Autoencoder và Isolation Forest thất bại trên lab này và chỉ giữ làm baseline nhị phân. Accuracy 0,9999 của random-flow split phản ánh rò rỉ cùng 5-tuple khi poll 5 giây, không dùng để suy rộng.

Deploy realtime vẫn XGBoost prototype (latency ~0,44 ms). Candidate 8-feature **không** bật DROP vì FPR Normal.

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

RF Acc 0,987 ± 0,008 · XGB 0,982 ± 0,017. Ghi rõ cùng `scenario_id` có thể nằm cả train và test.

### 3c. Public (không train controller)

- CICIDS2017 3-class: 880.176 · XGB/RF F1-macro ≈ 0,999 — không phải OpenFlow 5s.
- InSDN binary: 343.889 · XGB/RF F1 ≈ 0,999 — chỉ 2 lớp.

---

## 4. Checklist sửa Word (làm lần lượt)

1. Chương dataset: 79.114 **snapshot** / 23.843 5-tuple / 19 scenario / 32 run. Giữ 11.283 lịch sử.
2. Không xóa câu “DDoS từng chỉ 6 mẫu thật”.
3. Thay bảng 4 model bằng **mục 2**. Xóa Acc 0,9999 / AE 0,98 khỏi bảng chính.
4. Thêm đoạn hạn chế: Mininet 1 topo; không mixed traffic; sót 1 kịch bản nmap; FPR Normal 19–25%; AE/IF fail; chưa production.
5. Realtime: poll 5s · 3 polling reply / nguồn · DROP `hard_timeout` **120s** (không viết 60s).
6. PCA/t-SNE: lab tách lớp → giải thích Acc random cao. Không bịa “chồng lấn mạnh”.
7. 3 lớp: một đoạn “phát hiện binary ổn hơn phân loại DDoS vs Portscan khi bỏ cổng thô”.
8. Không viết zero-day, không viết IDS tổng quát.

---

## 5. Checklist slides

| Slide | Đúng | Sai |
|-------|------|-----|
| Dataset | 79.114 snapshot 5s · 23.843 5-tuple · 19 scenario · 32 run | “79k phiên” / 231k |
| Kết quả | Bảng mục 2 + min recall + FPR | Acc 0,9999 / “4 model đều tốt” |
| Hạn chế | Mininet · FPR 0,25 · sót nmap · AE/IF ~0,08 | Production / zero-day |
| Realtime | Prototype XGB · poll 5s · DROP 120s | Candidate robust đã bật |
| Phụ lục | 0,9999 = leakage | Acc 1,000 tuyệt đối |

---

## 6. File số liệu

- **Chính:** `reports/binary_realtime_loso_summary.csv` · `binary_realtime_loso_per_scenario.csv`
- Trung gian: `reports/grouped_real_only_summary.csv` · `scenario_held_out_summary.csv`
- Phụ lục: `reports/model_comparison.csv`
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

### Nên chèn thêm (đánh số Hình 4…, cập nhật Danh mục hình)

| Vị trí Word | File | Vì sao |
|-------------|------|--------|
| **1.1** hoặc **3.2** (sau mô tả topo 2 switch / 6 host) | `reports/network_topology.png` | Sơ đồ Mininet h1–h6, s1–s2, os-ken. |
| **3.2** Bước 1–8 hoặc **4.7.1** | `reports/system_architecture.png` | Pipeline thu thập → train → realtime. Caption: SMOTE chỉ dùng random-split phụ, **không** dùng LOSO. |
| **4.7.2** startup | `reports/controller_startup.png` | Load XGBoost, mitigation 3 / 120s / poll 5s. |
| **4.7.3** idle | `reports/dashboard_idle.png` | 0 flow, 6 host NORMAL. |
| **4.7.3** Normal | `reports/dashboard_normal.png` | ping/iperf, nhãn NORMAL, 0 DROP. |
| **4.7.4** | `reports/dashboard_auto_mitigation.png` | DROP `10.0.0.4`. `10.0.0.1` cũng bị DROP — FPR lab, ghi vào hạn chế. |
| **4.7.5** Cấu hình SOC | `reports/dashboard_settings_models.png` | Không Acc 99.91%. Benchmark ~0,33 / ~15,25 ms/flow. |
| **4.3** (sau đoạn `portscan_nmap_h4_h1`) | Bảng từ `reports/binary_realtime_loso_per_scenario.csv` | Không có PNG sẵn; dán bảng 19 scenario (Recall/FPR). Có thể vẽ bar trong Word. |
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

> Hình 1. So sánh bốn mô hình trên benchmark Leave-One-Scenario-Out (nhị phân Normal–Attack, 8 đặc trưng, không cổng thô, tối đa 3 snapshot đầu mỗi flow). XGBoost/Random Forest giữ F1 lớp Attack cao nhưng Normal FPR khoảng 0,19–0,25; Autoencoder và Isolation Forest thất bại trên protocol này.

---

## 8. Đoạn cần thay trong Word (PDF 64 trang, đọc lại 16/08)

Chương 4.1–4.7 và Kết luận **đã đúng số LOSO**. Chỉ sửa các chỗ dưới. Không dán Acc 0,9999 / 1,0000 vào Kết luận.

### 8.1. Mục 4.2 — một cụm từ

**Xóa:** `tại Bảng và biểu đồ so sánh ở Hình 1`  
**Thay:** `tại Bảng 5 và biểu đồ so sánh ở Hình 1`

### 8.2. Mục 4.3 — chèn hình sau đoạn `portscan_nmap_h4_h1`

**File:** `reports/loso_attack_recall_per_scenario.png`  
**Caption:**

> Hình 8. Recall của XGBoost và Random Forest trên từng attack scenario trong protocol Leave-One-Scenario-Out. Kịch bản `portscan_nmap_h4_h1` làm giảm Min Attack Recall xuống 0,1342 (XGBoost) và 0 (Random Forest).

**Câu chèn ngay dưới hình:**

> Biểu đồ cho thấy phần lớn kịch bản DDoS và một số kịch bản Port Scan được nhận diện với Recall cao, trong khi `portscan_nmap_h4_h1` là trường hợp suy giảm rõ. Điều này giải thích vì sao Mean Attack Recall vẫn ở mức 0,9074 và 0,8619 nhưng Min Attack Recall thấp hơn nhiều.

### 8.3. Mục 4.8 — thay toàn bộ (đang viết “rất cao”, chưa có số, chưa có hình)

**Xóa** từ tiêu đề 4.8 đến hết mục (trước chữ KẾT LUẬN). **Dán:**

> **4.8. Thực nghiệm bổ sung và đối chiếu thiết kế đánh giá**
>
> Bên cạnh protocol Leave-One-Scenario-Out, nghiên cứu duy trì hai phép đánh giá thứ cấp nhằm đối chiếu ảnh hưởng của cách phân chia dữ liệu. Cả hai phép này **không** thay thế Bảng 5 khi kết luận về khả năng tổng quát hóa.
>
> Phép thứ nhất là Stratified random-split 80/20 trên bài toán đa lớp, sử dụng 10 đặc trưng có `tp_src` và `tp_dst`. SMOTE chỉ được fit trên tập Train sau khi đã tách Test. Trong điều kiện Train và Test cùng miền phân bố, XGBoost đạt Accuracy 0,9999 và F1-macro 0,9999; Random Forest đạt Accuracy 0,9997 và F1-macro 0,9995. Kết quả gần tuyệt đối phản ánh khả năng tách lớp trên lab khi các snapshot của cùng flow identity có thể xuất hiện ở cả hai tập, chứ không chứng minh mô hình nhận diện tốt một kịch bản chưa quan sát.
>
> Phép thứ hai là GroupKFold theo `run_id`. Accuracy trung bình đạt 0,987 ± 0,008 với Random Forest và 0,982 ± 0,017 với XGBoost. So với random-split, chỉ số giảm nhưng vẫn cao hơn rõ so với Leave-One-Scenario-Out, vì các run khác nhau vẫn có thể thuộc cùng `scenario_id`.
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

### 8.4. Kết luận — chỉ sửa lỗi chính tả

**Xóa:** `nghiênên cứu`  
**Thay:** `nghiên cứu`

Các số trong Kết luận (0,9191 / 0,9544 / 0,9074 / 0,1342 / 0,2469 / 0,33 ms / 120 giây) **đã khớp Bảng 5**. Không viết lại cả chương.

### 8.5. Phụ lục G — số 0,9991 / 0,9898 / 0,9987 **không** còn đúng trên bộ hiện tại

Đó là số giai đoạn tập **11.283** (có augmentation). CSV khóa hiện tại `reports/model_comparison.csv` (random-split 80/20, bộ 79.114) là:

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

# Hướng dẫn sửa Word & Slides (Thiện copy số ở đây)

Chỉ dùng số mục 1–2 trên slide/chương Kết quả. **Không** dùng 231.314 / 20k Normal giả / Acc 0,80 / Acc 0,9999 làm số chính.

Người sửa: Trần Minh Thiện. Nguồn số: `reports/binary_realtime_loso_summary.csv`.

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

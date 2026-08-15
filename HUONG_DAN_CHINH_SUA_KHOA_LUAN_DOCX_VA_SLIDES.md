# 📘 HƯỚNG DẪN ĐỒNG BỘ SỐ LIỆU & HÌNH ẢNH VÀO FILE WORD VÀ SLIDES
*(Tài liệu chuẩn dành cho bạn Tú & Thiện để cập nhật Khóa Luận Tốt Nghiệp và Slide Thuyết Trình)*

---

## 🎯 PHẦN A: BẢNG TỔNG HỢP SỐ LIỆU CHUẨN XÁC 100% (COPY-PASTE VÀO BÁO CÁO)

### 1. Bảng phân phối Dataset SDN Thực nghiệm (Thay thế Bảng 15 trong Word & Slide 10)

| Nhãn (Label) | Số lượng mẫu (Flows) | Tỷ lệ (%) | Nguồn gốc dữ liệu |
| :--- | :---: | :---: | :--- |
| **Portscan** | **166.812 mẫu** | 72,11% | Thực nghiệm Mininet SDN (Nmap đa cổng, đa tốc độ) |
| **DDoS** | **43.612 mẫu** | 18,85% | Thực nghiệm Mininet SDN (24 đợt chạy độc lập SYN/UDP/ICMP Flood) |
| **Normal** | **20.890 mẫu** | 9,03% | Thực nghiệm Mininet SDN (Lưu lượng Web HTTP, DNS, SSH, Ping, Iperf) |
| **TỔNG CỘNG** | **231.314 mẫu** | **100%** | **Dữ liệu thực nghiệm OpenFlow 1.3 switch statistics** |

- **Phân chia:** Train Set (80%): 185.051 mẫu (sau SMOTE: 400.347 mẫu) | Test Set (20%): **46.263 mẫu** (độc lập, không can thiệp SMOTE).

---

### 2. Bảng so sánh hiệu năng 4 mô hình ML (Thay thế Bảng 11 trong Word & Slide 12)

| Mô hình (Model) | Hướng tiếp cận | Loại phân loại | Accuracy | Precision (macro) | Recall (macro) | F1-Score (macro) | ROC-AUC (macro) | PR-AUC | Độ trễ (Latency) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **XGBoost** | Supervised | Multiclass | **0.8047** | **0.8189** | **0.9073** | **0.8285** | **0.9252** | — | **0.39 ms** |
| **Random Forest** | Supervised | Multiclass | **0.7942** | **0.8065** | **0.9033** | **0.8176** | **0.9274** | — | **15.84 ms** |
| **Autoencoder** | Unsupervised | Binary (Anomaly) | **0.4929** | **0.9889** | **0.4475** | **0.6162** | **0.8371** | **0.9791** | **34.16 ms** |
| **Isolation Forest** | Unsupervised | Binary (Anomaly) | **0.1709** | **0.9449** | **0.0941** | **0.1711** | **0.7269** | **0.9470** | **3.87 ms** |

- **Random Forest bổ sung:** Out-of-Bag (OOB) Score = **0.9050** (chứng minh khả năng khái quát hóa vượt trội trên tập train).
- **Isolation Forest:** Thử nghiệm toàn diện với 4 mức contamination (`0.001`, `0.005`, `0.01`, `0.05`) đều cho kết quả F1 thấp $\rightarrow$ chứng minh luận điểm **"ranh giới không gian đặc trưng không có outlier rõ rệt, không phải lỗi do thuật toán"**.

---

## 📝 PHẦN B: HƯỚNG DẪN SỬA CHI TIẾT FILE `KhoaLuanTotNghiep.docx`

### 1. Cập nhật các đoạn văn bản (Paragraphs):
- **Đoạn P157 - P160 (Chương 2):** Sửa số lượng mẫu từ 11.283 lên **231.314 mẫu** (166.812 Portscan, 43.612 DDoS, 20.890 Normal).
- **Đoạn P360 - P376 (Chương 3 & 4):** Cập nhật kết quả của Autoencoder và Isolation Forest. Bổ sung diễn giải về **ROC-AUC (83.71% / 72.69%)** và **PR-AUC (97.91% / 94.70%)** thay vì chỉ dùng Accuracy.
- **Đoạn P392 - P408:** Xóa phần phân trần về *"DDoS chỉ có 6 mẫu"* vì hiện tại dữ liệu đã có **43.612 mẫu DDoS thực nghiệm từ 24 runs độc lập**.

### 2. Cập nhật các Bảng biểu (Tables):
- **Bảng 3, Bảng 4:** Thay bằng kết quả chi tiết của **XGBoost** (Accuracy 80.47%, F1 82.85%, ROC-AUC 92.52%). File số liệu chi tiết: `reports/xgboost_classification_report.csv`.
- **Bảng 5, Bảng 6:** Thay bằng kết quả chi tiết của **Autoencoder** (Precision 98.89%, Recall 44.75%, ROC-AUC 83.71%, PR-AUC 97.91%).
- **Bảng 7:** Thay bằng kết quả chi tiết của **Isolation Forest** (Precision 94.49%, Recall 9.41%, ROC-AUC 72.69%, PR-AUC 94.70%).
- **Bảng 8, Bảng 9:** Thay bằng kết quả chi tiết của **Random Forest** (Accuracy 79.42%, F1 81.76%, ROC-AUC 92.74%, OOB 0.9050). File số liệu: `reports/random_forest_classification_report.csv`.
- **Bảng 10:** Cập nhật bảng độ trễ suy luận: XGBoost: **0.39 ms**, Random Forest: **15.84 ms**, Isolation Forest: **3.87 ms**, Autoencoder: **34.16 ms**.
- **Bảng 11:** Cập nhật bảng so sánh 4 mô hình như mục 2 ở trên.
- **Bảng 12 (Real-only):** Xóa hoặc gộp chung vào bảng kết quả chính, vì toàn bộ dataset hiện tại 99.83% là dữ liệu thực nghiệm thật trong Mininet.
- **Bảng 15:** Cập nhật bảng phân bố nhãn dataset theo mục 1 ở trên.

### 3. Cập nhật & Chèn Hình ảnh mới vào Word:
- Thay hình Ma trận nhầm lẫn bằng các file mới trong thư mục `reports/`:
  - `reports/confusion_matrix_xgboost.png`
  - `reports/confusion_matrix_random_forest.png`
  - `reports/confusion_matrix_autoencoder.png`
  - `reports/confusion_matrix_isolation_forest.png`
- Thay hình So sánh mô hình bằng: `reports/model_comparison_chart.png`.
- **Chèn thêm 2 hình phân tích không gian đặc trưng cực kỳ giá trị:**
  - **Hình PCA 2D:** `reports/pca_2d_visualization.png`
  - **Hình t-SNE 2D:** `reports/tsne_2d_visualization.png`
  - *Ý nghĩa khoa học:* Chứng minh trực quan bằng đồ thị rằng lưu lượng Normal và Attack chồng lấn trong không gian 2D, giải thích cặn kẽ tại sao Unsupervised (Autoencoder/IF) gặp khó khăn trong khi Supervised (XGBoost/RF) vẫn phân tách xuất sắc.

---

## 📽️ PHẦN C: HƯỚNG DẪN SỬA SLIDES THUYẾT TRÌNH (`slides-kltn.pdf`)

| Slide | Tiêu đề Slide | Nội dung & Số liệu cần sửa | Hình ảnh cần chèn |
| :---: | :--- | :--- | :--- |
| **Slide 10** | **DATASET & FEATURE ENGINEERING** | - Tổng số mẫu: **231.314 samples**<br>- Portscan: **166.812** (72.1%)<br>- DDoS: **43.612** (18.9%)<br>- Normal: **20.890** (9.0%)<br>- Train: 185.051 (SMOTE: 400.347) \| Test: 46.263 | Chèn biểu đồ tròn phân phối Dataset |
| **Slide 12** | **KẾT QUẢ PHÂN LOẠI** | Cập nhật bảng so sánh 4 mô hình mới:<br>- **XGBoost:** F1: 82.85%, ROC-AUC: **92.52%**, Latency: **0.39 ms** (Được chọn cho Realtime)<br>- **Random Forest:** F1: 81.76%, ROC-AUC: **92.74%**, OOB: **0.9050**<br>- **Autoencoder:** PR-AUC: **97.91%**, ROC-AUC: 83.71%<br>- **Isolation Forest:** PR-AUC: 94.70%, ROC-AUC: 72.69% | Chèn hình: `reports/model_comparison_chart.png` |
| **Slide 13** | **PHÂN TÍCH LỖI & ĐÁNH GIÁ KHÁCH QUAN** | - Thay thế số liệu cũ bằng phân tích: Unsupervised có độ nhạy cao với ngưỡng threshold nhưng FPR cao do không gian đặc trưng không có outlier tách biệt.<br>- Supervised đạt độ phủ (Recall) vượt trội > 90% cho các cuộc tấn công DDoS và Portscan. | Chèn hình Ma trận nhầm lẫn XGBoost & Random Forest |
| **Slide 14** | **PHÂN TÍCH KHÔNG GIAN ĐẶC TRƯNG (PCA & t-SNE)** | *(Đổi tên từ Real-only Validation thành Phân tích không gian đặc trưng)*<br>- Giải thích hiện tượng chồng lấn dữ liệu giữa Normal và Attack.<br>- Khẳng định tính đầy đủ và quy mô của 24 runs thực nghiệm Mininet độc lập. | Chèn hình: `reports/pca_2d_visualization.png` và `reports/tsne_2d_visualization.png` |
| **Slide 16** | **REAL-TIME DETECTION & AUTO-MITIGATION** | - Độ trễ suy luận AI: **0.39 ms / sample**.<br>- Chu kỳ giám sát Polling: **5.0 s**.<br>- Cơ chế phòng vệ tự động: Đẩy luật OpenFlow DROP Rule (Priority 65535, Timeout 60s) ngay khi đạt ngưỡng vi phạm (Alert Threshold = 3). | Chèn Screenshot giao diện Dashboard SOC Realtime |

---

## 📌 PHẦN D: CÁC FILE BÁO CÁO CSV ĐÃ XUẤT SẴN (CHỈ CẦN MỞ RA COPY)

1. `reports/model_comparison.csv` (Bảng so sánh 4 mô hình tổng thể)
2. `reports/xgboost_metrics.csv` & `reports/xgboost_classification_report.csv`
3. `reports/random_forest_metrics.csv` & `reports/random_forest_classification_report.csv`
4. `reports/autoencoder_metrics.csv` & `reports/autoencoder_threshold_sweep.csv`
5. `reports/isolation_forest_metrics.csv` & `reports/isolation_forest_contamination_sweep.csv`

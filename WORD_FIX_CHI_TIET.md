# Checklist sửa Word — WORD_FIX_CHI_TIET.md

Thiện ơi, kéo code mới nhất về rồi mở **đúng file này**.

Làm từ trên xuống dưới; mục TÌM → THAY thì Ctrl+F. Đã đối chiếu codebase + KhoaLuanTotNghiep.docx (09/08/2026). Các mục DDoS/Portscan/realtime đã khóa theo collect_data.py / preprocess.py / realtime_detector.py.

Làm xong mục nào thì tick [x].

---

## [ ] 1. SMOTE — SỬA PHỤ LỤC B

### TÌM

```python
# 5. Split train/test TRƯỚC SMOTE / scaler

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print(f"[*] Train size: {len(X_train)}, Test size: {len(X_test)}")
```

### THAY BẰNG

```python
# 5. Split train/test TRƯỚC SMOTE

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print(f"[*] Train size: {len(X_train)}, Test size: {len(X_test)}")

# 6. SMOTE chỉ trên TRAIN — không áp dụng trên TEST
from imblearn.over_sampling import SMOTE

smote = SMOTE(random_state=42)
X_train, y_train = smote.fit_resample(X_train, y_train)

print(f"[*] After SMOTE: {len(X_train)} train samples")
```

Phần lưu CSV phải là:

```python
train_df = pd.DataFrame(X_train, columns=X.columns)
train_df['label'] = y_train
train_df.to_csv(TRAIN_CSV, index=False)

test_df = pd.DataFrame(X_test, columns=X.columns)
test_df['label'] = y_test
test_df.to_csv(TEST_CSV, index=False)
```

**Không thêm SMOTE vào `train_model.py`.**

---

## [ ] 2. PHỤ LỤC C — GHI RÕ TRAIN.CSV ĐÃ SMOTE

Trong `train_model.py`, ngay dưới:

```python
model.fit(X_train, y_train)
```

THÊM:

```python
# train.csv đã được cân bằng bằng SMOTE trong src/preprocess.py
# trước khi lưu. Script này chỉ fit StandardScaler trên TRAIN
# và huấn luyện mô hình, không thực hiện SMOTE lần hai.
```

---

## [ ] 3. CHƯƠNG 3 — SỬA THỨ TỰ PIPELINE

### TÌM

```text
sau đó fit StandardScaler trên tập TRAIN và transform TRAIN/TEST; cuối cùng áp dụng SMOTE chỉ trên tập TRAIN (không SMOTE trên TEST) trước khi huấn luyện mô hình để giải quyết bài toán dữ liệu mất cân bằng.
```

### THAY BẰNG

```text
sau đó áp dụng SMOTE chỉ trên tập TRAIN (không áp dụng trên TEST) để cân bằng dữ liệu trước khi lưu các tập CSV. Khi huấn luyện, script train_model.py mới fit StandardScaler trên tập TRAIN và transform TRAIN/TEST trước khi huấn luyện mô hình.
```

Pipeline thật:

```text
split
→ SMOTE TRAIN
→ save train.csv/test.csv
→ train_model.py
→ StandardScaler
→ model.fit
```

---

## [ ] 4. BẢNG 3 — SỬA PRECISION AUTOENCODER

Trong ô **Precision** của Autoencoder:

### TÌM

```text
0.9987
```

### THAY

```text
0.9986
```

Chỉ sửa ô Precision của Autoencoder, không sửa Accuracy/F1.

---

## [ ] 5. BẢNG 8 — ĐIỀN ĐỦ HÀNG AUTOENCODER

DOCX hiện hàng AE thiếu Precision/Recall (ô trống). Phải điền đủ:

| Accuracy | Precision (Anomaly) | Recall (Anomaly) | F1 (Anomaly) |
|----------|---------------------|------------------|--------------|
| **0.9987** | **0.9986** | **1.0000** | **0.9993** |

(Nguồn: `reports/autoencoder_metrics.csv` — Acc≈0.99867, P_Anomaly≈0.99863.)

---

## [ ] 6. BẢNG 6 — ĐỔI TÊN CỘT CHO RÕ

### TÌM

```text
Accuracy    Precision    Recall    F1
```

trong **Bảng 6** (Random Forest).

### THAY

```text
Accuracy    Precision (macro)    Recall (macro)    F1-Score (macro)
```

Chỉ đổi tên cột, không đổi số (vẫn 1.0000).

---

## [ ] 7. BẢNG 9 — PHẢI ĐIỀN SỐ (đang trống trên DOCX)

**Không bỏ qua.** Hiện XGB Real-only / RF Full / RF Real-only còn ô trống.

Điền đúng `reports/full_vs_real_only_comparison.csv`:

| Model | Setting | Accuracy | Precision (macro) | Recall (macro) | F1 (macro) |
|-------|---------|----------|-------------------|----------------|------------|
| XGBoost | Full | 0.9991 | 0.9997 | 0.9918 | 0.9957 |
| XGBoost | Real-only | **1.0000** | **1.0000** | **1.0000** | **1.0000** |
| Random Forest | Full | **1.0000** | **1.0000** | **1.0000** | **1.0000** |
| Random Forest | Real-only | **1.0000** | **1.0000** | **1.0000** | **1.0000** |

Header cột metric: `Precision (macro)` / `Recall (macro)` / `F1-Score (macro)`.

Nếu bảng bị bẻ row qua trang:
- Table Properties → Row → bỏ `Allow row to break across pages`
- bật Repeat Header Row nếu cần.

---

## [ ] 8. STANDARD SCALER — SỬA CÁCH DIỄN GIẢI

### TÌM

```text
đưa dữ liệu về phân phối chuẩn có giá trị trung bình bằng 0 và độ lệch chuẩn bằng 1
```

### THAY

```text
đưa dữ liệu về thang đo có giá trị trung bình bằng 0 và độ lệch chuẩn bằng 1 theo từng đặc trưng
```

---

## [ ] 9. AUC — SỬA CÁCH DIỄN GIẢI

### TÌM

```text
Chỉ số AUC đặc biệt quan trọng trong việc đánh giá mô hình Autoencoder do nó phản ánh khả năng chọn ngưỡng Threshold tối ưu của hệ thống.
```

### THAY

```text
Chỉ số AUC phản ánh khả năng phân biệt giữa lưu lượng bình thường và bất thường trên toàn bộ các ngưỡng phân loại. Ngưỡng vận hành cụ thể được lựa chọn riêng dựa trên mục tiêu kiểm soát tỷ lệ cảnh báo giả và khả năng phát hiện bất thường.
```

---

## [ ] 10. RECALL — SỬA CLAIM

### TÌM

```text
Chỉ số này phản ánh khả năng phát hiện và ngăn chặn triệt để mối đe dọa của mô hình, Recall càng cao thì tỷ lệ bỏ sót các cuộc tấn công nguy hại càng thấp.
```

### THAY

```text
Chỉ số này phản ánh khả năng phát hiện các mẫu tấn công của mô hình; Recall càng cao thì tỷ lệ bỏ sót các cuộc tấn công càng thấp.
```

---

## [ ] 11. ENTROPY — XÓA CLAIM KHÔNG DÙNG

### TÌM

```text
Trích xuất các đặc trưng dòng (Flow features) và tính toán các chỉ số thống kê (Entropy).
```

### THAY

```text
Trích xuất các đặc trưng dòng (Flow features) phục vụ huấn luyện và đánh giá mô hình.
```

Không thêm entropy vào code.

---

## [ ] 12. “TẬP DỮ LIỆU CHUẨN” — SỬA CHO ĐÚNG NGHIÊN CỨU

### TÌM

```text
Sử dụng tập dữ liệu chuẩn và tự sinh traffic thực tế.
```

### THAY

```text
Sử dụng dữ liệu Flow Statistics tự thu thập từ môi trường SDN giả lập và các mẫu DDoS semi-synthetic được tạo bằng bootstrap.
```

---

## [ ] 13. NORMAL TRAFFIC — GIỮ ĐÚNG CODE THU THẬP

`src/collect_data.py` → `generate_normal()` dùng **ping + iperf** (không phải curl làm chính).

### TÌM (nếu Word đang viết sai)

```text
traffic normal (HTTP/curl và iperf)
```

### THAY / GIỮ

```text
traffic normal (ping và iperf)
```

Không đổi thành curl nếu dataset chính sinh từ `collect_data.py`.

---

## [ ] 14. ISOLATION FOREST — SỬA CÔNG THỨC

Công thức cũ:

```text
c(n) = 2ln(n-1) + γ - 2(n-1)/n
```

Sửa trực tiếp Equation trong Word thành:

```text
c(n) ≈ 2ln(n-1) + 2γ - 2(n-1)/n
```

Hoặc dạng chính xác:

```text
c(n) = 2H(n-1) - 2(n-1)/n
```

---

## [ ] 15. ISOLATION FOREST — SỬA CÂU HÌNH 9

### TÌM

```text
nơi ranh giới điểm số s → 1 phân tách tường minh giữa hai nhóm lưu lượng
```

### THAY

```text
nơi phân phối điểm số cho thấy sự tách biệt rõ giữa hai nhóm lưu lượng trong thang điểm được sử dụng bởi mô hình thực nghiệm
```

---

## [ ] 16. ISOLATION FOREST — THÊM NOTE VỀ SCORE

Ngay sau đoạn mô tả Hình 9, THÊM:

```text
Lưu ý rằng Hình 9 sử dụng decision score của triển khai Isolation Forest trong thực nghiệm, có thang điểm khác với anomaly score s(x,n) được trình bày ở phần lý thuyết. Vì vậy, giá trị âm/dương trên trục của Hình 9 không được diễn giải trực tiếp theo khoảng 0–1 của anomaly score lý thuyết.
```

---

## [ ] 17. XGBOOST — SỬA `mlogloss`

### TÌM

```text
làm tiêu chí đánh giá và tối ưu hóa chính trong suốt các vòng lặp huấn luyện
```

### THAY

```text
làm tiêu chí đánh giá hiệu năng trong quá trình huấn luyện và theo dõi chất lượng dự đoán đa lớp
```

---

## [ ] 18. RETRAIN — GIẢM CLAIM

### TÌM

```text
cho phép hệ thống tự động cập nhật lại mô hình (Retrain) định kỳ với chi phí tính toán tối thiểu
```

### THAY

```text
phù hợp cho các kịch bản cần xây dựng quy trình retrain định kỳ với chi phí tính toán thấp; tuy nhiên, khóa luận chưa triển khai cơ chế retrain tự động trong hệ thống realtime
```

---

# CHECK CODE TRƯỚC KHI SỬA WORD

## [ ] 19. DDoS — KHÓA THEO `src/collect_data.py`

Script thu thập chính: `src/collect_data.py`  
`DDOS_DURATION = 45`; h4→h1 (SYN), h5→h2 (UDP), h6→h3 (ICMP).

### TÌM

```text
Tấn công DDoS: Chạy hping3 --flood từ h4 và h5 nhắm thẳng vào h1 và h2 trong vòng 30 giây
```

### THAY

```text
Tấn công DDoS: Chạy hping3 --flood từ h4, h5 và h6 lần lượt nhắm vào h1, h2 và h3 trong vòng 45 giây (SYN/UDP/ICMP) để tạo lưu lượng flood với cường độ cao.
```

(Phụ lục code attack cũng phải khớp đoạn này.)

---

## [ ] 20. PORTSCAN — KHÓA THEO `src/collect_data.py`

### TÌM

```text
Cho h6 sử dụng lệnh nmap -sS quét toàn bộ dải cổng của h1 trong 30 giây
```

### THAY

```text
Tấn công Port Scan (30 giây): h4 thực hiện SYN scan tới h1 trên các cổng 1–1024 (--max-rate 200); h5 quét h2 trên các cổng 1–500 (--max-rate 150); h6 quét subnet 10.0.0.0/24 trên các cổng 22, 80, 443, 8080 và 3306.
```

---

## [ ] 21. `monitor.py` VS `realtime_detector.py` — GIỮ CẢ HAI ĐÚNG VAI TRÒ

Repo có cả hai. **Không** đổi hết realtime thành monitor.

### THAY mô tả đoạn realtime thành:

```text
Đoạn mã trích xuất đặc trưng và dự đoán real-time được triển khai trong controller/realtime_detector.py; controller/monitor.py đảm nhiệm việc thu thập Flow Statistics (ghi CSV) từ các switch.
```

Snippet realtime trong phụ lục: lấy từ `realtime_detector.py`.  
Snippet thu thập CSV: lấy từ `monitor.py`.

---

## [ ] 22. `LABEL_MAP` — GIỮ NGUYÊN

`controller/realtime_detector.py` dùng:

```python
LABEL_MAP = {0: 'DDOS', 1: 'NORMAL', 2: 'PORTSCAN'}
label = LABEL_MAP.get(prediction, 'UNKNOWN')
```

`monitor.py` dùng `self.label_mapping` — chỉ khi trích snippet monitor mới đổi.  
Snippet realtime: **giữ `LABEL_MAP`**.

---

## [ ] 23. AUTO-MITIGATION — GIỮ `dp_match` / `dp_inst`

Code thật trong `_block_attacker` tạo `dp_match` / `dp_inst` rồi `match=dp_match`.  
Giữ nguyên; đảm bảo snippet phụ lục **có đủ vài dòng định nghĩa** `dp_match`/`dp_inst` (không để biến từ trên trời).

---

## [ ] 24. OS-KEN VERSION

`requirements.txt` pin: **os-ken==4.2.0**

### TÌM

```text
os-ken (v4.3.0)
```

### THAY

```text
os-ken (v4.2.0)
```

---

# HÌNH / SCREENSHOT

## [ ] 25. HÌNH 13

Trong ảnh đang ghi:

```text
Train vs Test Accuracy per Fold
```

Sửa trực tiếp trong hình thành:

```text
Train vs Validation Accuracy per Fold
```

Trong phần text:

### TÌM

```text
Đường Train Accuracy và Test Accuracy gần như trùng khớp qua 10 fold.
```

### THAY

```text
Đường Train Accuracy và Validation Accuracy gần như trùng khớp qua 10 fold.
```

---

## [ ] 26. HÌNH 17 — KHÔNG CROP WARNING

Hình 17 nếu còn warning:

```text
UserWarning: X does not have valid feature names, but StandardScaler was fitted with feature names
```

**Không crop/che warning.**

Code `realtime_detector.py` đã dùng `DataFrame(..., columns=FEATURE_COLS)` để hết warning.  
Thiện: chạy lại demo realtime → xác nhận terminal sạch warning → chụp screenshot mới thay Hình 17.

---

# CÁC CÂU NHỎ

## [ ] 27. MODEL SIZE

Nếu 2 MB là file size:

TÌM:

```text
Model XGBoost chỉ chiếm ~2MB RAM, scaler ~1KB.
```

THAY:

```text
Model XGBoost có kích thước lưu trữ khoảng 2 MB, scaler khoảng 1 KB.
```

Nếu thật sự đo RAM process thì giữ nguyên nhưng báo lại cách đo.

---

## [ ] 28. “ĐẢM BẢO KHÔNG ẢNH HƯỞNG”

TÌM:

```text
đảm bảo không ảnh hưởng đến hiệu năng chuyển mạch của controller
```

THAY:

```text
cho thấy chi phí tính toán của bước suy luận thấp trong môi trường thực nghiệm
```

---

## [ ] 29. TYPO

TÌM:

```text
nhấu nhiên
```

THAY:

```text
ngẫu nhiên
```

---

## [ ] 30. TYPO

TÌM:

```text
hoàn toàn.. Đây
```

THAY:

```text
hoàn toàn. Đây
```

---

## [ ] 31. KHOẢNG TRẮNG

TÌM:

```text
Mininet,os-ken
```

THAY:

```text
Mininet, os-ken
```

---

## [ ] 32. KHOẢNG TRẮNG

TÌM:

```text
Chương 1, 2, 3,đồng bộ
```

THAY:

```text
Chương 1, 2, 3, đồng bộ
```

---

## [ ] 33. GIẢNG VIÊN HƯỚNG DẪN

TÌM:

```text
Ths. Cao Tiến Thành
```

THAY:

```text
ThS. Cao Tiến Thành
```

---

## [ ] 34. BÌA

TÌM:

```text
Khóa Khóa 29 – K29
```

THAY:

```text
Khóa 29 – K29
```

---

## [ ] 35. NGÀY

TÌM:

```text
Tp. Hồ Chí Minh, ngày     tháng 08 năm 2026
```

THAY BẰNG NGÀY NỘP THẬT:

```text
TP. Hồ Chí Minh, ngày [NGÀY NỘP] tháng 08 năm 2026
```

---

## [ ] 36. DDoS / DDOS

Trong văn bản/bảng/caption:

```text
DDOS
```

→

```text
DDoS
```

**Không Ctrl+H toàn file**, vì code có thể dùng label `DDOS`.

---

## [ ] 37. LOG KÝ TỰ RÁC

Nếu output có:

```text
 ALERT
료룍 BLOCKED
꼅꼆꼇 UNBLOCKED
```

THAY thành:

```text
[ALERT]
[BLOCKED]
[UNBLOCKED]
```

Ví dụ:

```text
[ALERT] [2026-05-15 14:02:35] 10.0.0.4 -> 10.0.0.1 | prediction=DDOS
[ALERT] [2026-05-15 14:02:40] 10.0.0.4 -> 10.0.0.1 | prediction=DDOS
[ALERT] [2026-05-15 14:02:45] 10.0.0.4 -> 10.0.0.1 | prediction=DDOS
[BLOCKED] Attacker IP 10.0.0.4 on ALL switches | Attack: DDOS | Duration: 120s
...
[UNBLOCKED] IP 10.0.0.4 - block timeout expired (120s)
```

---

# CITATION

## [ ] 38. ISOLATION FOREST

TÌM:

```text
Isolation Forest (Rừng cô lập) do Liu et al. (2008)
```

THAY:

```text
Isolation Forest (Rừng cô lập) được Liu et al. giới thiệu [5]
```

## [ ] 39. THÊM CITATION

Những chỗ tương ứng nên có:

```text
SDN [1]
InSDN [2]
Random Forest [3]
XGBoost [4]
Isolation Forest [5]
SDN Security [6]
Anomaly Detection [7]
OpenFlow [8]
SMOTE [9]
```

Không sửa bibliography [1]–[9], chỉ bổ sung citation trong body.

---

# FINAL CHECK

## [ ] 40. CTRL+F FINAL

Sau khi sửa hết, tìm lần lượt:

```text
Precision 0.9987
```

→ kiểm tra không còn `0.9987` ở Precision Autoencoder.

```text
Entropy
```

→ kiểm tra không còn claim dùng Entropy ngoài chỗ thật sự cần.

```text
Train vs Test Accuracy per Fold
```

→ không còn.

```text
Test Accuracy
```

→ kiểm tra các chỗ CV có dùng nhầm Test không.

```text
nhấu nhiên
```

→ không còn.

```text
hoàn toàn..
```

→ không còn.

```text
Ths.
```

→ không còn nếu đó là tên giảng viên.

```text
Khóa Khóa
```

→ không còn.

```text
realtime_detector.py
```

→ phải đúng với repo.

```text
LABEL_MAP
```

→ phải đúng với repo.

```text
dp_match
```

→ phải có định nghĩa nếu còn dùng.

---

## [ ] 41. UPDATE WORD

Sau khi sửa hết:

1. Update Table of Contents.
2. Update List of Figures.
3. Update List of Tables.
4. Kiểm tra caption hình/bảng.
5. Kiểm tra header/footer.
6. Export PDF mới.

**Đừng export PDF trước khi làm xong checklist.**

---

## [ ] 42. BÁO LẠI

Xong thì nhắn:

> `đã sửa tới mục X, các mục CHECK CODE đã đối chiếu repo, chưa export PDF`

Nếu có mục nào không làm được:

> `BLOCKED – mục X: [lý do]`

**Không tự bỏ qua mục nào.**

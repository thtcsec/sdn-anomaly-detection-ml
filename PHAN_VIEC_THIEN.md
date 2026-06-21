# PHÂN VIỆC CHO THIỆN - Cập nhật 20/06/2026

## Tình hình hiện tại

Tú đã hoàn thành:
- ✅ Thu thập thêm DDoS data (6 → 506 mẫu, gồm SYN/UDP/ICMP flood)
- ✅ Train lại XGBoost: **99.91% accuracy** (trước đó 100% do data quá ít)
- ✅ Train lại Isolation Forest: **97% accuracy, AUC 0.9521**
- ✅ Viết section 4.6 Real-time chi tiết (file `docs/section_4_6_realtime.md`)
- ✅ Viết phụ lục code mẫu (file `docs/phu_luc.md`)
- ✅ Push code lên nhánh `Tu` và merge vào `main`

---

## VIỆC CẦN LÀM CỦA THIỆN

### ƯU TIÊN CAO (Làm trước)

---

### Việc 1: Tạo file `src/train_autoencoder.py`

File này **chưa có trong repo**. Hướng dẫn chi tiết đã có trong `HUONG_DAN.md` (Bước 6).

**Tóm tắt nhanh:**

```bash
cd ~/sdn-anomaly-detection-ml
source .venv/bin/activate
code src/train_autoencoder.py
```

Kiến trúc Autoencoder: `10 → 8 → 6 → 4 → 6 → 8 → 10`

**LƯU Ý QUAN TRỌNG:** 
- Label mapping đã thay đổi: `ddos=0, normal=1, portscan=2`
- Trong code, train chỉ với data **label == 1** (NORMAL)
- Threshold tại percentile 95 của MSE trên tập normal
- Copy code từ `HUONG_DAN.md` Bước 6

**Sau khi xong:**
```bash
python src/train_autoencoder.py
```

Kết quả mong đợi:
- File `models/autoencoder_model.keras`
- File `models/autoencoder_scaler.pkl`
- File `reports/autoencoder_error_dist.png`
- File `reports/roc_curve_autoencoder.png`

---

### Việc 2: Thêm SMOTE vào `src/preprocess.py`

Mở file `src/preprocess.py`, tìm đoạn:

```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"[*] Train size: {len(X_train)}, Test size: {len(X_test)}")
```

**Thêm ngay BÊN DƯỚI:**

```python
    # SMOTE - cân bằng dữ liệu (chỉ áp dụng cho tập TRAIN)
    from imblearn.over_sampling import SMOTE
    smote = SMOTE(random_state=42)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    print(f"[*] After SMOTE: {len(X_train)} train samples")
```

> ⚠️ **TUYỆT ĐỐI KHÔNG** oversample tập test. Chỉ SMOTE tập train.

**Sau khi thêm SMOTE, chạy lại pipeline:**
```bash
python src/preprocess.py
python src/train_model.py
python src/train_isolation_forest.py
python src/train_autoencoder.py  # nếu đã tạo xong
python src/compare_models.py
```

---

### Việc 3: Viết đầy đủ Chương 1 trong báo cáo

Hiện tại Chương 1 trong khóa luận còn **placeholder** (trang 12):
- Section 1.1: Chỉ ghi "Phân tích 3 lớp (Application, Control, Data) và giao thức OpenFlow"
- Section 1.2: Chỉ ghi tiêu đề

**Cần viết đầy đủ:**

#### Section 1.1: Kiến trúc SDN
- Giải thích 3 lớp: Application Plane, Control Plane, Data Plane
- Giao thức OpenFlow: flow table, match fields, actions
- So sánh SDN vs mạng truyền thống
- Vẽ hình minh họa kiến trúc 3 lớp

#### Section 1.2: Thách thức bảo mật SDN
- Single Point of Failure ở Controller
- DDoS nhắm vào Control Plane
- Flow Table Saturation ở Data Plane
- Tham khảo: [1] Kreutz et al. 2015, [6] Scott-Hayward et al. 2016

**Độ dài:** Mỗi section khoảng 1-1.5 trang A4.

---

### Việc 4: Bổ sung nhận xét Section 4.3.2 (Isolation Forest)

Hiện tại chỉ có 1 dòng: "Nhận xét: AUC 0.98 → phân tách tốt..."

**Cần viết thêm (khoảng nửa trang):**

```
Nhận xét phân tích kết quả Isolation Forest:

- Về năng lực phát hiện bất thường: Mô hình Isolation Forest đạt Accuracy 97% 
  và AUC 0.9521, cho thấy khả năng phân tách rất tốt giữa lưu lượng bình thường 
  và lưu lượng tấn công trong môi trường SDN.

- So sánh với Autoencoder: Isolation Forest vượt trội hoàn toàn so với Autoencoder 
  (AUC 0.95 vs 0.57) do thuật toán random partitioning phù hợp hơn với dữ liệu 
  tabular có ít đặc trưng (10 features). Autoencoder cần không gian đặc trưng 
  cao chiều hơn để phát huy ưu thế.

- Về tốc độ: Isolation Forest có thời gian huấn luyện và inference nhanh hơn 
  đáng kể so với Autoencoder, không yêu cầu GPU, phù hợp cho triển khai 
  edge/real-time.

- Hạn chế: Chỉ phân loại binary (Normal vs Anomaly), không phân biệt được 
  loại tấn công cụ thể (DDoS vs Portscan) như XGBoost.
```

---

### Việc 5: Bổ sung Section 4.4 (So sánh 3 model)

Hiện tại chỉ 1 dòng. **Viết thêm khoảng 1 trang:**

Nội dung cần có:
- Bảng so sánh (đã có Bảng 6) → viết nhận xét phân tích
- Giải thích tại sao XGBoost tốt nhất (supervised + data tabular)
- Giải thích tại sao Autoencoder yếu (feature space hẹp, 10 features không đủ cho deep learning)
- Giải thích Isolation Forest khá tốt (phù hợp anomaly detection trên tabular data)
- Kết luận: Đề xuất XGBoost cho real-time detection, Isolation Forest backup cho zero-day

---

## ƯU TIÊN THẤP (Nếu còn thời gian)

### Việc 6: Chạy `compare_models.py` và cập nhật kết quả

Sau khi train xong tất cả model:
```bash
python src/compare_models.py
```

Lấy kết quả mới cập nhật vào Bảng 6 trong báo cáo.

---

## GIT WORKFLOW

```bash
# 1. Pull code mới nhất
cd ~/sdn-anomaly-detection-ml
git checkout main
git pull origin main

# 2. Tạo nhánh làm việc
git checkout -b Thien

# 3. Làm việc... (tạo file, sửa file)

# 4. Commit
git add src/train_autoencoder.py
git add src/preprocess.py
git commit -m "feat: add autoencoder training + SMOTE to preprocess"

# 5. Push
git push -u origin Thien

# 6. Tạo Pull Request trên GitHub → Tú sẽ review và merge
```

---

## DEADLINE

- **Việc 1 + 2:** Hoàn thành trong 2 ngày
- **Việc 3 + 4 + 5:** Hoàn thành trong 4 ngày
- **Tổng:** 1 tuần kể từ ngày nhận task

---

## LIÊN HỆ

Nếu gặp lỗi khi chạy code:
1. Đảm bảo đã `source .venv/bin/activate`
2. Đảm bảo đã `pip install -r requirements.txt`
3. Check file dataset có đầy đủ không: `ls dataset/`
4. Hỏi Tú trên chat/Zalo

**Tú - 20/06/2026**

# PHÂN VIỆC CHO THIỆN - Cập nhật 20/06/2026

## Tình hình hiện tại

Tú đã hoàn thành:
- ✅ Thu thập thêm DDoS data (6 → 506 mẫu, gồm SYN/UDP/ICMP flood)
- ✅ Train lại XGBoost: **99.91% accuracy**
- ✅ Train lại Isolation Forest: **97% accuracy, AUC 0.9521**
- ✅ Viết section 4.6 Real-time + Phụ lục
- ✅ Push code lên nhánh `Tu` và merge vào `master`

---

## VIỆC CẦN LÀM CỦA THIỆN

### Việc 1: Code — Tạo `src/train_autoencoder.py` + thêm SMOTE vào preprocess

- Tạo file `src/train_autoencoder.py` — tự viết dựa trên kiến trúc `10→8→6→4→6→8→10`, train only normal data (label==1), threshold 95th percentile MSE.
- Thêm SMOTE vào `src/preprocess.py` sau `train_test_split` — chỉ apply cho tập train.
- Chạy lại full pipeline, đảm bảo model ra kết quả hợp lý.
- Chạy `src/compare_models.py` cập nhật bảng so sánh.

### Việc 2: Báo cáo — Viết đầy đủ các phần còn thiếu

- **Chương 1** (Section 1.1 + 1.2): Đang là placeholder, cần viết nội dung.
- **Section 4.3.2**: Nhận xét Isolation Forest — hiện chỉ 1 dòng.
- **Section 4.4**: So sánh 3 model — hiện chỉ 1 dòng.

---

## GIT WORKFLOW

```bash
git checkout master && git pull origin master
git checkout -b Thien
# ... làm việc ...
git add -A && git commit -m "feat: autoencoder + SMOTE + báo cáo bổ sung"
git push -u origin Thien
```

Sau đó báo Tú để review + merge.

---

## DEADLINE

- **Việc 1 (code):** 2 ngày
- **Việc 2 (báo cáo):** 4 ngày
- **Tổng:** 1 tuần

**Tú - 20/06/2026**

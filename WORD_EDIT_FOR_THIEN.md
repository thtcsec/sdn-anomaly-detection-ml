# Hướng dẫn chỉnh Word — KhoaLuanTotNghiep.docx

Dành cho Thiện khi hoàn thiện bản khóa luận.

- File chính: `KhoaLuanTotNghiep.docx`
- Backup: `KhoaLuanTotNghiep.backup.docx`
- Patch cũ (tham khảo): `DOCX_CHANGES.txt`

Cách làm: đóng Word → mở lại → Ctrl+F cụm **Tìm** → chỉnh theo **Sửa thành** / **Chèn sau**.

---

## 1) Trang bìa phụ

**Tìm:** bảng `SV thực hiện` còn cột trống / chỉ có dấu `:`

**Sửa thành:**
```
SV thực hiện    : Trịnh Hoàng Tú, Trần Minh Thiện
Chuyên ngành    : An ninh mạng
MSSV            : 23DH113972, 23DH113375
Khóa            : Khóa 29 – K29
GVHD            : Ths. Cao Tiến Thành
```

Nếu có hai bảng bìa, bảng nào thiếu thì điền; bảng đã đủ thì giữ. Sau đó xuất PDF và cập nhật `docs/NOTE_FIX_TRANG_BIA.md`.

---

## 2) §0.7 Bố cục

**Tìm:** `Cấu trúc 3 chương chính`

**Sửa thành:** `Cấu trúc 4 chương chính (cùng phần mở đầu, kết luận và phụ lục).`

---

## 3) §2.1 Mô tả tập dữ liệu

**Tìm:** `Mininet kết hợp với Ryu Controller`

**Sửa thành:** `Mininet kết hợp với os-ken Controller (fork của Ryu).`

**Tìm** đoạn thống kê mẫu (có DDoS / synthetic) và **làm rõ provenance**, ví dụ:

> Lớp DDoS gồm mẫu thu trên lab Mininet và mẫu semi-synthetic bootstrap từ phân phối seed lab (`real_seed_bootstrap`). Cột `is_synthetic` trong `flow_stats.csv` dùng để theo dõi nguồn mẫu. Các chỉ số hiệu năng cao cần được đọc trong bối cảnh testbed giả lập.

**Số liệu tham chiếu (pipeline 24/07/2026):**
- Tổng ~11.283 mẫu (portscan 10.565, normal 312, ddos 406)
- DDoS: 6 lab + 400 bootstrap
- Full: `reports/model_comparison.csv` — XGB ≈ 0.9991 / 0.9957; IF ≈ 0.9898 / 0.9947; AE ≈ 0.9982 / 0.9991
- Real-only: `reports/real_only_metrics.csv` — Acc/F1 = 1.0 trên 10.883 mẫu real (ddos lab vẫn ít; nêu trong hạn chế)

---

## 4) §2.2 Đoạn SMOTE

**Tìm:** `lớp DDoS chỉ có 6 mẫu`

**Gợi ý sửa:** nêu rõ *ban đầu lab ít mẫu DDoS*; sau bổ sung semi-synthetic/bootstrap tổng DDoS tăng trước khi SMOTE trên tập train (SMOTE vẫn chỉ trên train).

---

## 5) §4.5 Hạn chế

**Tìm:** `4.5. Hạn chế`

**Có thể bổ sung** (diễn đạt lại cho khớp văn phong bài):

- Đánh giá real-only (`reports/real_only_metrics.csv`) và tỷ lệ mẫu semi-synthetic khi diễn giải Accuracy cao trên tập full.
- Lab Mininet tách lớp khá rõ; `tp_src`/`tp_dst` quan trọng trên SHAP — trên mạng thật cần thu thập thêm trước khi production.

---

## 6) Mục real-only (đề xuất chèn mới)

**Chèn sau** `4.7.3` (SHAP), trước Kết luận:

### 4.7.4. Đánh giá bổ sung trên tập real-only

Tóm tắt: tách `is_synthetic=0`, train/eval lại XGBoost; nêu Accuracy / F1 / số mẫu theo CSV thời điểm thí nghiệm. Đây là góc nhìn bổ sung bên cạnh bảng 4.4, không thay thế bảng chính.

Viết thêm 1 đoạn nhận xét ngắn theo số thật trong CSV.

---

## 7) Đồng bộ số liệu sau retrain

Nguồn chính:
- `reports/model_comparison.csv`
- `reports/cross_validation_results.csv`
- `reports/baseline_comparison.csv`
- `reports/real_only_metrics.csv`

Rà các chỗ có thể lệch: §4.6 (99.91% vs số mới), phụ lục Isolation Forest cũ, bảng 4.4 / 4.7.2, Kết luận.

---

## 8) Kết luận

Cập nhật AE / IF / XGB theo CSV mới. Có thể thêm một câu về provenance (`is_synthetic`) và đánh giá real-only để bài nhất quán với phần hạn chế.

---

## 9) Bảng phân công

**Tìm:** `Ryu` (cột Tú) → **os-ken**

Bổ sung phía Thiện (nếu chưa có): đồng bộ số liệu Ch.4, SHAP, real-only, hoàn thiện Word/PDF.

---

## Checklist trước nộp

- [ ] Bìa phụ đủ thông tin + Update TOC
- [ ] §0.7 / §2.1 (os-ken + provenance dataset)
- [ ] §2.2 SMOTE khớp số hiện tại
- [ ] §4.5 + (nếu chèn) §4.7.4 real-only
- [ ] Số liệu thống nhất với `reports/*.csv`
- [ ] Kết luận + bảng phân công
- [ ] Screenshot demo (Tú gửi) vào phụ lục
- [ ] Notebook SHAP (nếu làm H4)
- [ ] Xuất PDF và rà lại trang bìa

# Phân việc nhóm — cập nhật 24/07/2026

Phân theo thế mạnh: Tú phụ trách lab / demo hệ thống; Thiện phụ trách hoàn thiện báo cáo Word, đồng bộ số liệu và phần giải thích mô hình.

Hướng dẫn chỉnh Word chi tiết: `WORD_EDIT_FOR_THIEN.md`

---

## Đã cập nhật trong repo gần đây

- Realtime canonical: `python controller/run_realtime.py` (+ dashboard)
- Provenance: `is_synthetic` / `source` trên `dataset/flow_stats.csv`
- Bootstrap DDoS từ seed lab: `src/bootstrap_real_ddos.py`
- Đánh giá real-only: `src/eval_real_only.py` → `reports/real_only_metrics.csv`
- Pipeline gộp: `python src/run_pipeline.py`

```bash
# Retrain đầy đủ (nếu cần)
python src/run_pipeline.py --bootstrap 0

# Demo
python controller/run_realtime.py
python dashboard/app.py
# http://127.0.0.1:5000
```

Số liệu tham chiếu hiện tại: `reports/model_comparison.csv`, `reports/real_only_metrics.csv`

---

## Việc của Tú — Lab & demo

### T1. (Nếu còn thời gian) Thu thêm Normal / DDoS trên Mininet
`sudo python3 src/collect_ddos_extra.py`, tăng traffic normal (iperf/curl), rồi chạy lại provenance + pipeline.

### T2. Demo bảo vệ + screenshot phụ lục
Chụp alert log, dashboard, blocked IP, topology — gửi Thiện để chèn phụ lục.

---

## Việc của Thiện — Báo cáo & đồng bộ số liệu

### H1. Trang bìa + mục lục
1. Điền thông tin bìa phụ còn thiếu (`docs/NOTE_FIX_TRANG_BIA.md`)
2. Cập nhật trường Mục lục (Update Field)
3. Kiểm tra caption Hình 13 (SHAP)

### H2. Chỉnh nội dung theo checklist Word
Làm theo từng mục trong `WORD_EDIT_FOR_THIEN.md` (phạm vi, dataset, SMOTE, hạn chế, real-only, kết luận, phân công).

### H3. Đồng bộ số liệu Chương 4
Cập nhật bảng/đoạn theo `reports/*.csv` sau lần train mới; thống nhất với phần Kết luận.

### H4. (Khuyến nghị) Notebook demo SHAP
`notebooks/shap_demo.ipynb` để trình bày nhanh khi bảo vệ.

### H5. Báo cáo markdown cũ
`Bao_cao_khoa_luan.md` là bản nháp cũ — ưu tiên Word làm bản chính; nếu giữ file markdown thì cập nhật số cho khớp hoặc ghi chú là bản lưu trữ.

---

## Timeline gợi ý

| Người | Việc | Gợi ý |
|-------|------|--------|
| Thiện | H1 + H2 | sớm |
| Thiện | H3 | ngay khi có CSV mới |
| Tú | T2 screenshots | trước bảo vệ khoảng 1 tuần |
| Thiện | H4 | trước bảo vệ vài ngày |

InSDN chỉ nên làm thêm nếu phần Word/số liệu chính đã xong. Không mở rộng sang CICIDS2017.

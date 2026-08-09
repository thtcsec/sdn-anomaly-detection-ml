# Phân việc nhóm — cập nhật 09/08/2026

Phân theo thế mạnh: Tú — lab / demo; Thiện — hoàn thiện Word theo checklist.

## Thiện — ưu tiên ngay

Mở và làm hết: **`WORD_FIX_CHI_TIET.md`** (Ctrl+F từng mục).

Đặc biệt không bỏ:
1. Phụ lục B — chèn SMOTE (code thật có trong `src/preprocess.py`)
2. Ch.3 — sửa thứ tự: split → SMOTE → (train) StandardScaler
3. Bảng 3/8 AE Precision **0.9986**; Bảng 8 điền đủ P/R
4. **Bảng 9 điền đủ số** Full/Real-only (đang trống trên DOCX)
5. DDoS/Portscan khớp `src/collect_data.py` (45s / 3 host)
6. Update TOC + xuất PDF

## Tú

- Demo realtime: `python controller/run_realtime.py` + dashboard
- DDoS demo dùng: `h4 hping3 -S -k --flood -p 80 10.0.0.1` (có `-k`)
- Screenshot phụ lục gửi Thiện

## Lệnh nhanh

```bash
git pull
python src/run_pipeline.py --bootstrap 0
python controller/run_realtime.py
python dashboard/app.py
```

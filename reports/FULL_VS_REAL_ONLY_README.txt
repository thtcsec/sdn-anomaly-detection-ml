FULL vs REAL-ONLY — cách đọc bảng so sánh
=============================================

Full (official test.csv từ preprocess)
--------------------------------------
- Tập test sau pipeline preprocess: gồm traffic lab + DDoS bootstrap
  trong pool dữ liệu (đánh dấu provenance qua is_synthetic).
- SMOTE chỉ áp dụng trên tập train, KHÔNG áp dụng trên test.
- Metrics lấy từ reports/model_comparison.csv (và random_forest_metrics.csv).

Real-only (is_synthetic == 0)
-----------------------------
- Chỉ giữ mẫu thực (is_synthetic==0); loại synthetic / bootstrap khỏi đánh giá này.
- DDoS real trong pool hiện tại: 6 mẫu (rất ít).
- Split stratified 80/20 (random_state=42) → tập test real-only RF có thể chỉ còn
  ~1 mẫu DDoS; Accuracy=1.0 trên holdout nhỏ là KẾT QUẢ LAB HỢP LỆ nhưng
  KHÔNG được diễn giải như bằng chứng tổng quát hóa production.
- XGBoost real-only: reports/real_only_metrics.csv (eval_real_only.py)
- RF real-only: reports/random_forest_real_only_metrics.csv (eval_rf_real_only.py), NO SMOTE.

Cách viết trong luận văn (khuyến nghị)
--------------------------------------
- Acc=1.0 của RF trên tập thực nghiệm hiện tại: viết "cao nhất trên tập thực nghiệm
  hiện tại" — KHÔNG viết "tốt nhất tuyệt đối" / "tối ưu mọi điều kiện".
- RF Acc=1.0 vs XGBoost Acc≈0.9991 trên Full KHÔNG chứng minh RF vượt trội cho
  production: chênh lệch rất nhỏ; hệ realtime ưu tiên XGBoost vì latency suy luận.
- Luôn nêu hạn chế: bootstrap DDoS, số DDoS real ít, real-only test nhỏ.

Tái tạo bảng
------------
  python src/build_full_vs_real_only.py
Nếu thiếu real-only CSV:
  python src/eval_real_only.py
  python src/eval_rf_real_only.py

Real-only StratifiedKFold (RF — kiểm chứng độ vững)
----------------------------------------------------
- Script: python src/train_random_forest_thesis.py
- Outputs: reports/random_forest_cv_results.csv, random_forest_cv_folds.csv
- K=5 trên is_synthetic==0, NO SMOTE, cùng hyperparams official RF.
- Acc mean±std và F1_macro mean±std (F1 thường <1.0 vì n_ddos_real=6).
- Đọc hướng dẫn viết luận văn: reports/rf_protocol_note.txt
- Bảng tóm tắt mọi probe: reports/random_forest_thesis_protocols.csv

Tái tạo thêm:
  python src/train_random_forest_thesis.py


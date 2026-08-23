# Prompt phản biện — dán nguyên file này cho AI khác (kèm zip)

**Cách dùng:** giải nén `sdn_ml_review_pack.zip` → dán **toàn bộ** file này vào AI phản biện → bắt AI đọc pack **trước** khi kết luận.  
**Ngôn ngữ bắt buộc của báo cáo phản biện:** tiếng Việt.  
**Không** viết lại số Acc/F1 “đẹp hơn”. CSV trong pack là trọng tài.

---

Bạn là **hội đồng phản biện khắt khe** khóa luận tốt nghiệp **K29 HUFLIT** (ngành mạng / an ninh / học máy). Vai trò: phản biện đối kháng, không phải trợ giảng sửa điểm. Sinh viên nộp pack code + số liệu đã khóa; Word/slide **không** nằm trong zip (xem mục 6).

Đề tài (lock đề, không được nới): *Phát hiện bất thường và phân loại lỗi mạng SDN bằng học máy* trên **testbed Mininet 2 switch / 6 host**, controller **os-ken**, OpenFlow 1.3 — **không** phải syslog / SOC tường lửa HUFLIT, **không** train CICIDS/InSDN cho artifact live.

## 0. Bắt buộc làm trước khi viết một câu nhận xét

1. Giải nén pack. Đọc `MANIFEST.txt` (có gì / cố ý loại gì / vì sao).
2. Đọc `README.md` và `docs/CAM_NANG_BAO_VE_FULL.md`.
3. **Đối chiếu số** với CSV, không tin markdown nếu lệch:
   - `reports/binary_realtime_loso_summary.csv`
   - `reports/binary_realtime_loso_per_scenario.csv`
   - `reports/fault_protocol_e_audited_d1_loso.csv` + `*_d1_per_class.csv`
   - `reports/fault_protocol_e_audited_d2_loso.csv` + `*_d2_per_class.csv`
   - `reports/realtime_binary_artifact_benchmark.csv`
   - `reports/grouped_real_only_summary.csv` (protocol yếu hơn LOSO — **cấm** lấy Acc ~0.99 làm generalization)
4. Đọc code nhỏ: `src/model_catalog.py`, `src/mitigation_policy.py`, `src/realtime_protocol.py`, `controller/realtime_detector.py`, `dashboard/app.py`, `dataset/controller_config.json`.
5. `docs/FAULT_DATASET.md` và `docs/THESIS_EVALUATION_PROTOCOL.md` **có thể lệch** số audited (ví dụ D2 0.923 vs 0.925). **CSV audited thắng.** Hãy ghi rõ chỗ doc cũ.
6. File `dataset/flow_stats_grouped.csv` (~96 MB, ~326 961 dòng) **không** có trong zip. Schema/đếm dòng: `reports/DATASET_SCHEMA_NOTE.md`. **Không** bịa phân bố nhãn khác README.

Nếu thiếu file must-have, ghi `THIẾU BẰNG CHỨNG` — không suy diễn có lợi cho sinh viên.

## 1. Khóa sự thật (vi phạm = overclaim)

| Lock | Đúng | Cấm |
|------|------|-----|
| Nguồn dữ liệu | Tự thu OpenFlow FlowStats trên Mininet 2s6h | “Dataset syslog HUFLIT”, “train CICIDS”, “production campus” |
| Đơn vị mẫu anomaly | **326 961 snapshot poll 5 s**, 206 `run_id`, 21 `scenario_id` | 326k phiên độc lập / i.i.d. / quy mô CICIDS |
| Protocol generalization | **LOSO theo `scenario_id`**, 8 feature (bỏ cổng), 3 poll đầu, không SMOTE | Acc random-split ~0.999; GroupKFold theo run như LOSO |
| Headline anomaly | **Random Forest Acc 0.7724** (CSV thô ~0.77243085), F1 Attack ~0.7746, FPR Normal mean ~0.1616 | XGB là mô hình triển khai; Acc 0.99; bảng LOSO cũ 79k / XGB 0.9191 |
| Lỗ cố định | **Min attack recall = 0** tại `portscan_nmap_h4_h1` (RF/XGB/LinearSVC) | Giấu min-recall; nói “generalize cao vì bỏ cổng” |
| Artifact live | `random_forest_binary`, 8 feat, nhãn `NORMAL`/`ANOMALY` | XGBoost realtime; SVM SOC = số luận |
| SVM | LinearSVC **LOSO** Acc ~0.7491 (FPR xấu). Pickle SVM trên SOC = **demo random-split 10 feat** | Trộn hai số SVM |
| Fault hiện tại | **Protocol E audited**, lab only. D2 RF Acc **0.9250** / F1-macro **0.9281**, n_test pooled **1534**. IF/AE D2 = **N/A** | Protocol D D2 ~0.38 là số hiện tại; bịa Acc D2 cho IF/AE |
| Fault D | Phụ lục: `tc` không gắn, probe sai đường | “Chỉ sửa tc thì Acc từ 0.38 lên 0.93” (E đổi nhiều biến cùng lúc) |
| Latency | p50 **12.9898 ms** = `transform` + `predict` batch-1 | 12.99 ms = mitigation E2E; 0.33 / 0.44 ms cho live RF; “phản ứng 13 ms” |
| Mitigation | 3 poll hoàn chỉnh → DROP `priority=1000`, `hard_timeout=120` | “Chặn trong đúng 15 s”; E2E đã đo |

Làm tròn như Word được; **không** làm tròn thành 0.80 / 0.93 “cho đẹp”. Không bịa số tốt hơn CSV.

## 2. Việc phải trả về (đúng thứ tự)

### A. Bảng claim vs evidence

Mỗi hàng: **Claim** (README / cẩm nang / comment code) | **File bằng chứng** | **Số/đoạn trích** | **Khớp / lệch / không kiểm được**.  
Bắt buộc phủ: LOSO 5 mô hình; min-recall 0; RF live 8 feat; D1/D2 E audited; IF/AE N/A trên D2; 12.99 ms; SVM demo ≠ LOSO; 326k không i.i.d.; grouped_real_only ≠ headline.

### B. Overclaim còn sót trong pack

Liệt kê chỗ markdown/code/comment vẫn phóng (kể cả `docs/FAULT_DATASET.md` / `THESIS_EVALUATION_PROTOCOL.md` nếu số cũ). Phân mức: **nặng** (sai artifact, sai protocol) / **vừa** (số lệch 0.002) / **nhẹ** (diễn đạt).

### C. Mười câu hỏi hội đồng (khó)

Đúng 10 câu, giọng hội đồng bắt bẻ, **kèm hướng trả lời đúng theo pack** (không gợi ý nói dối). Ưu tiên: generalization, lỗ nmap, FPR 16 %, D vs E, latency vs DROP, SVM SOC, AE load fail, 2s6h không phải campus, ablation D2, đóng góp thuật toán (baseline chứ không SOTA).

### D. Word / slide

**Zip gần như chắc không chứa** `KhoaLuanTotNghiep.docx` / PDF / `Thesis Defense Presentation (1).pptx`.  
Viết rõ: *không đối chiếu được Word/slide từ pack này.*  
Lấy punch list trong `docs/CAM_NANG_BAO_VE_FULL.md` (mục Word vs project, Slides vs sự thật) và đánh giá **rủi ro bảo vệ** nếu slide chưa sửa: XGB realtime, 0.44 ms, “phản ứng 12.99 ms”, bảng AE/IF sai, thiếu SVM, 79k. Không bịa nội dung slide ngoài cẩm nang.

### E. Kết luận hội đồng (ngắn)

1 đoạn: đề có đứng trên testbed không; số generalization có trung thực không; demo có khớp artifact không; **điểm yếu không thể trốn**. Không chấm điểm 10/10. Không khen “SOTA”. Không đề xuất Acc mới.

## 3. Phạm vi — đừng lạc

- Không yêu cầu train lại / không bịa thí nghiệm chưa chạy.
- Không kết luận “unsupervised vô dụng với SDN” — chỉ fail protocol + lab này.
- Public CICIDS/InSDN trong repo (nếu không có trong zip) = phụ lục, không phải tập train controller.
- `reports/model_comparison.csv` = leakage; phụ lục.

Hết prompt. Bắt đầu bằng việc liệt kê file đã đọc trong pack.

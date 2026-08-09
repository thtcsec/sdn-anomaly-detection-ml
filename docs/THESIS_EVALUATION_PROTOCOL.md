# Thesis evaluation protocol (SDN anomaly detection)

## Two benchmarks — do not confuse them

### 1) Legacy internal benchmark (already in thesis tables)
- Source: `dataset/train.csv` / `test.csv` from random stratified **flow** split on full `flow_stats` (lab + bootstrap DDoS).
- SMOTE on train only.
- Metrics: `reports/model_comparison.csv`
- **Interpretation:** high scores (including RF Acc=1.0) show class separability **inside this Mininet lab split**.
- **Do NOT write:** “RF tốt nhất tuyệt đối”, “generalize to production”, “perfect DDoS detection”.
- **Do write:** “cao nhất trên tập thực nghiệm hiện tại (lab + bootstrap trong pool).”
- Realtime still uses **XGBoost** (latency ~0.3 ms vs RF ~15 ms).

### 2) Grouped real-only protocol (primary for robustness claims)
- Only `is_synthetic==0` **and** known `run_id` (exclude `unknown` legacy).
- Split by **run_id** (GroupKFold / LeaveOneGroupOut), not by flow.
- Scaler / optional SMOTE fit **inside train fold only**; test fold never synthetic.
- Scripts:
  - `python src/ensure_legacy_provenance.py`
  - `python src/merge_independent_runs.py`
  - `sudo python3 src/collect_independent_ddos_runs.py`  # when collecting new runs
  - `python src/eval_grouped_real_only.py`
  - `python src/audit_feature_overlap.py --grouped`
- Outputs: `reports/grouped_real_only_summary.csv`, `grouped_real_only_per_fold.csv`, `feature_overlap_audit.csv`, `grouped_real_only_STATUS.csv`

If STATUS says `insufficient_groups` / `insufficient_labels`:
> Protocol is ready, but **not enough independent labeled runs** to conclude. Do **not** invent metrics.

## Safety
Collection targets only Mininet hosts `10.0.0.1`–`10.0.0.6`. No Internet / external IPs.

## Suggested Word wording (RF Acc=1.0)
> Trên benchmark nội bộ (random-flow split, có mẫu bootstrap trong pool), Random Forest đạt Accuracy=1,0000 — cao nhất trên tập thực nghiệm hiện tại. Kết quả phản ánh traffic lab dễ tách lớp và không được diễn giải như hiệu năng tuyệt đối trên mạng thật. Để đánh giá độ vững theo phiên thu thập độc lập, nghiên cứu bổ sung protocol grouped real-only (tách theo `run_id`, loại synthetic khỏi test). Khi chưa đủ số run độc lập, protocol được mô tả nhưng chưa dùng để kết luận số liệu chính.

## Autoencoder / Isolation Forest metric labels
- AE/IF **Precision/Recall/F1** in tables = **Anomaly-class** (binary positive), not macro.
- AE Acc must match confusion matrix with **train** threshold (`models/autoencoder_threshold.pkl`, ~0.0473). Never use prose threshold 2.355.
- Sync helper: `python src/sync_ae_threshold_metrics.py`
- Details for Word edits: `WORD_EDIT_FOR_THIEN.md`

## Suggested placement
After the 4-model comparison table: section “Đánh giá bổ sung Full / Real-only / Grouped-by-run”.

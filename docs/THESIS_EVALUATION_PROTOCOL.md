# Thesis evaluation protocol (SDN anomaly detection)

## Four benchmarks — do not confuse them

### 0) Primary generalization — Leave-One-Scenario-Out (protocol D)

- Script: `python src/eval_scenario_held_out.py --feature-set all`
- Pool: `dataset/flow_stats_grouped.csv` (79,114 poll rows → **23,843** last-poll 5-tuples · **19** `scenario_id` · 32 `run_id`)
- Split: **LeaveOneGroupOut on `scenario_id`**. Repeats of the same scenario stay together.
- One eval sample = last OpenFlow poll of each 5-tuple per run, not every 5s snapshot.
- Primary features: **drop raw `tp_src` / `tp_dst`**. `with_raw_ports` is diagnostic only.
- Headline metric: **recall of the held-out scenario label** (mean / min / max). Do not headline row Accuracy or 3-class F1-macro on single-class holdouts (those F1 values sit near 0.25–0.33 by construction).
- Outputs: `reports/scenario_held_out_summary.csv`, `scenario_held_out_per_scenario.csv`, `scenario_inventory.csv`, `scenario_held_out_STATUS.csv`
- **Do NOT cite** random-split Acc 0.9999 or grouped-by-run Acc ≈ 0.98 as generalization.

#### Fair 4-model binary table (locked)

`python src/eval_binary_realtime_scenario_held_out.py` ·
`reports/binary_realtime_loso_summary.csv`

Same task for all four: Normal vs Attack, LOSO 19 scenarios, first 3 polls,
no raw ports, no SMOTE.

| Model | Acc pooled | F1 anom | Attack-scenario recall (min) | Normal FPR |
|-------|------------|---------|------------------------------|------------|
| XGBoost | 0.9191 | 0.9544 | 0.9074 (0.1342) | 0.2469 |
| Random Forest | 0.8866 | 0.9349 | 0.8619 (0) | 0.1915 |
| Autoencoder | 0.0831 | 0.0074 | 0.1022 (0) | 0.0999 |
| Isolation Forest | 0.0813 | 0.0005 | 0.0707 (0) | 0.1014 |

Pooled scores are not the sole headline. XGB/RF miss `portscan_nmap_h4_h1`.
AE/IF fail on this lab. Dataset is enough for an honest Mininet table, not
production. New hold-out runs require interactive WSL sudo; do not fabricate.

#### Current LOSO results (equal weight per scenario)

| Feature set | Model | Held-out recall | min–max |
|-------------|-------|-----------------|---------|
| no_raw_ports (primary) | RF | 0.726 ± 0.386 | 0.00–1.00 |
| no_raw_ports (primary) | XGB | 0.694 ± 0.373 | 0.00–1.00 |
| with_raw_ports (diagnostic) | RF | 0.861 ± 0.309 | 0.00–1.00 |
| with_raw_ports (diagnostic) | XGB | 0.826 ± 0.364 | 0.00–1.00 |

Repeated holes without raw ports: `ddos_syn_multi_h4h5_h1h2`, `portscan_nmap_h4_h1`, `portscan_syn_h5_h3_p1_96_r90`, `normal_ping_iperf_light`.

Controller XGB is **not** retrained on this protocol. It remains the Mininet realtime prototype.

Do **not** collect more rows until a behavior hole repeats under this protocol. Adding HTTP-many-ports or DDoS multiport under the old split only inflates correlated snapshots.

### 1) Legacy internal benchmark (already in thesis tables)
- Source: `dataset/train.csv` / `test.csv` from random stratified **flow** split on full `flow_stats` (lab + bootstrap DDoS).
- SMOTE on train only.
- Metrics: `reports/model_comparison.csv`
- **Interpretation:** high scores (including RF Acc=1.0) show class separability **inside this Mininet lab split**.
- **Do NOT write:** “RF tốt nhất tuyệt đối”, “generalize to production”, “perfect DDoS detection”.
- **Do write:** “cao nhất trên tập thực nghiệm hiện tại (lab + bootstrap trong pool).”
- Realtime still uses **XGBoost** (latency ~0.3 ms vs RF ~15 ms).

### 2) Grouped real-only protocol (intermediate — scenario overlap remains)
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

#### Current grouped dataset status
- Legacy thesis table still has only `6` real DDoS rows in the original labeled pool.
- Do **not** cite raw `flow_stats.csv` after later collection dumps (monitor append
  inflates unlabeled/portscan rows).
- The first “~38k DDoS” dump was a **time-window label**, including leftover nmap
  flows still in the OVS table. After attacker↔target + L4 filtering it was ~5.3k.
- After multiport DDoS + diverse Portscan + real Normal (HTTP/iperf/ping) collection,
  the honest independent pool is:
  - **32** known `run_id` groups
  - **79,114** rows: DDoS **43,206** · Portscan **20,238** · Normal **15,670**
  - `9` normal · `12` portscan · `11` non-empty ddos runs
- Merge output: `dataset/flow_stats_grouped.csv`

#### Current grouped results (run-isolated, K=5 by run_id)
- Random Forest:
  - `Accuracy = 0.9873 ± 0.0080`
  - `F1_macro = 0.9646 ± 0.0259`
  - `DDoS recall ≈ 0.999`
- XGBoost:
  - `Accuracy = 0.9823 ± 0.0174`
  - `F1_macro = 0.9610 ± 0.0459`
  - `DDoS recall ≈ 1.000`
  - Weakest fold Acc ≈ **0.95** (one unseen nmap style). No more Acc 0.25/0.44 fold.
- Autoencoder / Isolation Forest in this file are **binary anomaly protocols** and
  should not be compared directly against the multiclass RF/XGB rows.

#### Interpretation
- Grouped-by-run is stricter than random-flow but **weaker than LOSO**: the same
  `scenario_id` can appear in both train and test.
- Cite it only as an intermediate analysis, with the words “scenario overlap”.
- Do not sell RF/XGB Acc ≈ 0.98 as production or as the thesis generalization number.

### 3) Public supplementary benchmark (CICIDS2017, 3-class)
- Purpose: patch the thesis's weakest point (`ddos` real lab too small) with a
  larger **external** labeled flow benchmark.
- Source files:
  - `Monday-WorkingHours.pcap_ISCX.csv.parquet`
  - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet`
  - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet`
- Import script: `python src/import_public_cicids2017.py`
- Benchmark runner: `python src/run_public_benchmark.py`
- Canonical dataset:
  - `dataset/public_benchmark/cicids2017_3class/flow_stats.csv`
  - `dataset/public_benchmark/cicids2017_3class/train.csv`
  - `dataset/public_benchmark/cicids2017_3class/test.csv`
- Reports:
  - `reports/public_benchmark/cicids2017_3class/model_comparison.csv`
  - `reports/public_benchmark/cicids2017_3class/benchmark_note.json`

#### Public benchmark facts
- Rows after clean/dedup: **880,176**
- Label counts:
  - `normal`: **662,383**
  - `ddos`: **127,175**
  - `portscan`: **90,618**
- Split protocol: stratified random flow split on the canonical public CSV
- Train after SMOTE: **1,589,718**
- Test rows: **176,036**
- Runtime cap used for practicality:
  - supervised train cap: **100,000 / class**
  - unsupervised normal-train cap: **100,000**

#### Public benchmark results
- XGBoost: `Acc=0.9994`, `P=0.9989`, `R=0.9993`, `F1_macro=0.9991`
- Random Forest: `Acc=0.9995`, `P=0.9993`, `R=0.9993`, `F1_macro=0.9993`
- Isolation Forest: `Acc=0.7224`, `P_anom=0.1672`, `R_anom=0.0306`, `F1_anom=0.0518`
- Autoencoder: `Acc=0.7509`, `P_anom=0.4886`, `R_anom=0.1452`, `F1_anom=0.2238`

#### Interpretation
- The public benchmark is **not** an SDN/OpenFlow deployment benchmark; it is a
  larger external flow benchmark used to show the models are not supported only
  by `6` real DDoS lab rows.
- Supervised models stay very strong on the public benchmark.
- Unsupervised models degrade sharply on this external flow distribution, which
  is a useful honesty point in the defense.
- Do **not** compare public-benchmark latency and lab realtime latency as if
  they were the same deployment environment.
- This mirror dropped `Protocol` / `Source Port`; import fallback:
  - infer TCP (`6`) when TCP flag counts are present, else `0`
  - set `tp_src=-1` sentinel when source port is absent
  - disclose this as a mirror limitation, not as a property of the original lab data

### 4) Public supplementary benchmark (InSDN, binary)
- Purpose: SDN-domain public contrast. Official UCD zip was unreachable;
  Hugging Face `Sharukesh/INSDN` mirror is **binary** (`0=Normal`, `1=Attack`).
- Rows: **343,889** · Normal **68,424** · Anomaly **275,465**
- Import: `python src/import_public_insdn.py`
- Eval: `python src/run_public_insdn_binary.py`
- Results: XGB `Acc=0.9986 F1=0.9991` · RF `Acc=0.9987 F1=0.9992`
- Do **not** treat this as 3-class or as controller training data.

Other public sets (CIC-DDoS2019, CSE-CIC-IDS2018, UNSW-NB15) exist but are
large and still not OpenFlow poll stats. Do not download them just to inflate
row counts.

## Safety
Collection targets only Mininet hosts `10.0.0.1`–`10.0.0.6`. No Internet / external IPs.

## Suggested Word wording (RF Acc=1.0)
> Trên benchmark nội bộ (random-flow split, có mẫu bootstrap trong pool), Random Forest đạt Accuracy=1,0000 — cao nhất trên tập thực nghiệm hiện tại. Kết quả phản ánh traffic lab dễ tách lớp và không được diễn giải như hiệu năng tuyệt đối trên mạng thật. Để đánh giá độ vững theo phiên thu thập độc lập, nghiên cứu bổ sung protocol grouped real-only (tách theo `run_id`, loại synthetic khỏi test). Khi chưa đủ số run độc lập, protocol được mô tả nhưng chưa dùng để kết luận số liệu chính.

## Suggested Word wording (grouped run-isolated result)
> Để xử lý hạn chế số mẫu DDoS thực trong tập cũ, nhóm thu bổ sung các phiên lab độc lập có `run_id` và đánh giá theo GroupKFold. Pool hiện tại có 32 phiên, 79.114 mẫu OpenFlow (DDoS 43.206 · Portscan 20.238 · Normal 15.670). Random Forest đạt Accuracy `0,9873 ± 0,0080`, `F1-macro ≈ 0,9646 ± 0,0259`. XGBoost đạt Accuracy `0,9823 ± 0,0174`, `F1-macro ≈ 0,9610 ± 0,0459`, recall DDoS ≈ 1,0. Fold yếu nhất của XGBoost khoảng 0,95 trên một kiểu nmap chưa thấy. Kết quả cho thấy các lớp lab đã tách được theo phiên độc lập, nhưng random-flow Acc 0,9999 vẫn không được dùng làm số robustness.

## Suggested Word wording (public supplementary benchmark)
> Nghiên cứu bổ sung hai benchmark công khai, không trộn vào tập train controller. CICIDS2017 (3 lớp, 880.176 flows) cho XGBoost/Random Forest F1-macro khoảng 0,999. InSDN (domain SDN, 343.889 flows) chỉ có nhãn nhị phân trên mirror hiện có; XGBoost/Random Forest đạt F1 khoảng 0,999. Cả hai chỉ là đối chứng quy mô, không thay thế pipeline OpenFlow tự thu.

## Autoencoder / Isolation Forest metric labels
- AE/IF **Precision/Recall/F1** in tables = **Anomaly-class** (binary positive), not macro.
- AE Acc must match confusion matrix with **train** threshold (`models/autoencoder_threshold.pkl`, ~0.0014 on the 79,114 pool). Never use prose threshold 2.355 or the old 0.0473 from the 11k table.
- Sync helper: `python src/sync_ae_threshold_metrics.py`
- Details for Word edits: `HUONG_DAN_CHINH_SUA_KHOA_LUAN_DOCX_VA_SLIDES.md`

## Suggested placement
After the 4-model comparison table: section “Đánh giá bổ sung Full / Real-only / Grouped-by-run / Public benchmark”.

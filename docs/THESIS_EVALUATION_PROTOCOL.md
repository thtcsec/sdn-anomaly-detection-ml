# Thesis evaluation protocol (SDN anomaly detection)

## Five tracks — do not mix anomaly and fault

### Fault dataset (second pool — same topology, not a public dump)

- Does **not** replace the 326,961 DDoS/Portscan/Normal snapshots.
- Collect on `s1↔s2` with Mininet `tc` (bw / loss / delay). Two questions: **D1** = fault vs normal; **D2** = 4-class normal/bw/loss/delay. Do not merge the questions.
- **Protocol E (current):** `dataset/fault_stats_grouped_e.csv` — **1,982** rows · **112** runs · **36** scenarios. LOSO pooled n_test=1534. D1 five models (Normal-only unsupervised, scaler train-fold, AE threshold = 95th percentile train-normal MSE): RF Acc **0.9811** / F1 **0.9652** (R_n 0.9213 · R_f 0.9930); XGB 0.9759 / 0.9554; SVM 0.9681 / 0.9414; Autoencoder 0.5456 / 0.4899 (R_n 0.6496 · R_f 0.5250); Isolation Forest 0.1382 / 0.1314 (R_n 0.6850 · R_f 0.0297). D2 RF Acc **0.923** / F1-macro **0.926**; XGB 0.902/0.903; SVM 0.886/0.889. RF D2 recall Bandwidth 0.883 · Loss 0.874 · Delay 0.996 (all ≥ 0.82). Headline D2 = **RF**. D2 is classifiable on this **lab** only — not campus SDN. Unsupervised models answer **D1 only**.
- **Protocol D (historical / broken tc):** 36 scenarios · 324 runs · 6,666 rows — D2 Acc ~0.38. Appendix only. Never headline as current.
- Controller: `python controller/run_fault_monitor.py` (FlowStats **delta** + PortStats). Never `run_controller.py` during fault capture.
- Scripts: `src/collect_independent_fault_runs.py --protocol e`, `src/merge_fault_runs.py --protocol e`, `src/eval_fault_loso.py --prefix fault_protocol_e`
- Files: `dataset/fault_stats_grouped_e.csv` (E), `dataset/fault_stats_grouped.csv` (D), `docs/FAULT_DATASET.md`
- Fifth supervised model: SVM (RBF on fault; LinearSVC on anomaly LOSO). Worse than RF on both tasks. Isolation Forest / Autoencoder run on **D1** (binary). They stay **N/A on 4-class D2** — they cannot assign four family labels without a separate supervised head. Do not invent 4-class Acc for IF/AE.
- Model features: `FAULT_MODEL_FEATURES`. Forbidden: labels, `configured_*`, IPs, ids.
- Cite as lab observations. Related work: ML-LFIL on Mininet (rate / delay / loss), not as our dataset.

## Four anomaly benchmarks — do not confuse them

### 0) Primary generalization — Leave-One-Scenario-Out (protocol D)

- Script: `python src/eval_scenario_held_out.py --feature-set all`
- Pool: `dataset/flow_stats_grouped.csv` (326,961 poll rows → **113,226** last-poll 5-tuples · **21** `scenario_id` · 206 `run_id`)
- Split: **LeaveOneGroupOut on `scenario_id`**. Repeats of the same scenario stay together.
- One eval sample = last OpenFlow poll of each 5-tuple per run, not every 5s snapshot.
- Primary features: **drop raw `tp_src` / `tp_dst`**. `with_raw_ports` is diagnostic only.
- Headline metric: **recall of the held-out scenario label** (mean / min / max). Do not headline row Accuracy or 3-class F1-macro on single-class holdouts (those F1 values sit near 0.25–0.33 by construction).
- Outputs: `reports/scenario_held_out_summary.csv`, `scenario_held_out_per_scenario.csv`, `scenario_inventory.csv`, `scenario_held_out_STATUS.csv`
- **Do NOT cite** random-split Acc 0.9999 or grouped-by-run Acc ≈ 0.98 as generalization.

#### Fair 5-model binary table (locked)

`python src/eval_binary_realtime_scenario_held_out.py` ·
`reports/binary_realtime_loso_summary.csv`

Same task: Normal vs Attack, LOSO 21 scenarios, first 3 polls,
no raw ports, no SMOTE. Headline = **Random Forest**. LinearSVC is a 5th supervised baseline (not the deploy model; higher Normal FPR).

| Model | Acc pooled | F1 anom | Attack-scenario recall (min) | Normal FPR mean |
|-------|------------|---------|------------------------------|-----------------|
| Random Forest | 0.7724 | 0.7746 | 0.7301 (0) | 0.1616 |
| XGBoost | 0.7520 | 0.7556 | 0.7223 (0) | 0.1805 |
| LinearSVC | 0.7491 | 0.7768 | 0.8524 (0) | 0.2871 |
| Autoencoder | 0.4759 | 0.0463 | 0.0495 (0) | 0.0614 |
| Isolation Forest | 0.4665 | 0.0003 | 0.0036 (0) | 0.0484 |

Do not headline LinearSVC: FPR is worse than RF. All supervised models still miss `portscan_nmap_h4_h1` (min recall **0**).

Pooled scores are not the sole headline. XGB/RF miss `portscan_nmap_h4_h1` (min recall **0**).
AE/IF fail on this lab. 326k is more independent runs on the same 2s6h Mininet lab, not
CICIDS-scale diversity. Do not cite the retired 79k LOSO table (XGB Acc 0.9191).

#### Current LOSO results (equal weight per scenario)

| Feature set | Model | Held-out recall | min–max |
|-------------|-------|-----------------|---------|
| no_raw_ports (primary) | RF | 0.787 ± 0.299 | 0.00–1.00 |
| no_raw_ports (primary) | XGB | 0.774 ± 0.296 | 0.00–1.00 |
| with_raw_ports (diagnostic) | RF | 0.926 ± 0.227 | 0.00–1.00 |
| with_raw_ports (diagnostic) | XGB | 0.932 ± 0.222 | 0.00–1.00 |

Repeated hole without raw ports: `portscan_nmap_h4_h1` (recall 0). 3-class F1-macro on single-class holdouts is noisy (~0.28) — do not headline it.

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
  - **206** known `run_id` groups
  - **326,961** rows: Normal **198,810** · DDoS **93,648** · Portscan **34,503**
  - `135` normal · `27` portscan · `44` ddos runs · **21** scenarios
- Merge output: `dataset/flow_stats_grouped.csv`

#### Current grouped results (run-isolated, K=5 by run_id)
- Random Forest:
  - `Accuracy = 0.9931 ± 0.0082`
  - `F1_macro = 0.9863 ± 0.0093`
  - `DDoS recall ≈ 0.993`
- XGBoost:
  - `Accuracy = 0.9937 ± 0.0049`
  - `F1_macro = 0.9872 ± 0.0055`
  - `DDoS recall ≈ 0.992`
- Autoencoder / Isolation Forest in this file are **binary anomaly protocols** and
  should not be compared directly against the multiclass RF/XGB rows.

#### Interpretation
- Grouped-by-run is stricter than random-flow but **weaker than LOSO**: the same
  `scenario_id` can appear in both train and test.
- Cite it only as an intermediate analysis, with the words “scenario overlap”.
- Do not sell RF/XGB Acc ≈ 0.99 as production or as the thesis generalization number.

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
> Để xử lý hạn chế số mẫu DDoS thực trong tập cũ, nhóm thu bổ sung các phiên lab độc lập có `run_id` và đánh giá theo GroupKFold. Pool hiện tại có 206 phiên, 326.961 mẫu OpenFlow (Normal 198.810 · DDoS 93.648 · Portscan 34.503) trên cùng topology 2s6h. Random Forest đạt Accuracy `0,9931 ± 0,0082`, `F1-macro 0,9863 ± 0,0093`. XGBoost đạt Accuracy `0,9937 ± 0,0049`, `F1-macro 0,9872 ± 0,0055`. Cùng `scenario_id` vẫn có thể nằm ở train và test nên **không** dùng làm số generalization. Số chính vẫn là LOSO binary (RF Acc 0,7724 · XGB 0,7520 · min-recall 0).

## Suggested Word wording (public supplementary benchmark)
> Nghiên cứu bổ sung hai benchmark công khai, không trộn vào tập train controller. CICIDS2017 (3 lớp, 880.176 flows) cho XGBoost/Random Forest F1-macro khoảng 0,999. InSDN (domain SDN, 343.889 flows) chỉ có nhãn nhị phân trên mirror hiện có; XGBoost/Random Forest đạt F1 khoảng 0,999. Cả hai chỉ là đối chứng quy mô, không thay thế pipeline OpenFlow tự thu.

## Autoencoder / Isolation Forest metric labels
- AE/IF **Precision/Recall/F1** in tables = **Anomaly-class** (binary positive), not macro.
- AE Acc must match confusion matrix with **train** threshold (`models/autoencoder_threshold.pkl`). Never use prose threshold 2.355 or the old 0.0473 from the 11k table. Do not recycle the 79k-era 0.0014 as if it were re-measured on 326k.
- Sync helper: `python src/sync_ae_threshold_metrics.py`
- Details for Word edits: `HUONG_DAN_CHINH_SUA_KHOA_LUAN_DOCX_VA_SLIDES.md`

## Suggested placement
After the 4-model comparison table: section “Đánh giá bổ sung Full / Real-only / Grouped-by-run / Public benchmark”.

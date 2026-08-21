# SDN Anomaly Detection using Machine Learning

Mininet + os-ken OpenFlow 1.3 + machine learning. Realtime controller and Flask dashboard.

| | |
|---|---|
| Trịnh Hoàng Tú | 23DH113972 · lab SDN, thu thập, realtime, dashboard |
| Trần Minh Thiện | 23DH113375 · pipeline ML, đánh giá, Word |
| GVHD | ThS. Cao Tiến Thành · HUFLIT · K29 |

## Environment (locked)

Python **3.11**. Versions in `requirements.txt` and `reports/environment_lock.txt` are the ones that produced `reports/binary_realtime_loso_summary.csv`.

```
xgboost 3.2.0
scikit-learn 1.7.2
tensorflow 2.21.0
pandas 2.3.1
numpy 2.2.6
os-ken 4.2.0
```

Do not install unpinned latest. Do not write XGBoost 2.0.3 / sklearn 1.4.2 in the thesis unless you re-run the table on that stack.

```bash
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

WSL2 + Mininet + OVS + hping3/nmap/iperf are required only for live demo, not for the evaluation command below.

## Reproduce the main table

Needs `dataset/flow_stats_grouped.csv` (included in the submission zip).

```bash
python src/eval_binary_realtime_scenario_held_out.py --skip-autoencoder
python src/eval_binary_realtime_scenario_held_out.py
```

Writes `reports/binary_realtime_loso_summary.csv` and `reports/binary_realtime_loso_per_scenario.csv`.

Protocol: binary Normal-vs-Attack, Leave-One-Scenario-Out, first 3 polls per 5-tuple, 8 features (no raw ports), no SMOTE.

## Demo realtime

```bash
# Windows: start_demo.bat
python controller/run_realtime.py
python dashboard/app.py            # http://127.0.0.1:5000
sudo /usr/bin/python3 topology/custom_topo.py
```

Poll 5 s. Three consecutive source-level alerts → OpenFlow DROP, hard_timeout 120 s. Demo uses the legacy XGBoost artifact in `models/`.

## Data

| File | Role | Rows | Labels / groups |
|------|------|------|-----------------|
| `dataset/flow_stats_grouped.csv` | Anomaly pool (headline) | **326,961** | normal **198,810** · ddos **93,648** · portscan **34,503** · **206** `run_id` · **21** `scenario_id` |
| `dataset/fault_stats_grouped_e.csv` | Fault Protocol E (current D2) | **1,982** | delay 570 · bandwidth 553 · loss 529 · normal 330 · **112** `run_id` · **36** `scenario_id` |
| `dataset/fault_stats_grouped.csv` | Fault Protocol D (historical / broken `tc`) | 6,666 | delay 1864 · bandwidth 1857 · loss 1839 · normal 1106 · 324 run · 36 scenario |
| `dataset/fault_stats_grouped_protocol_d.csv` | Archive copy of Protocol D | 6,666 | identical to `fault_stats_grouped.csv` |
| `dataset/train.csv` / `test.csv` | Legacy random-flow split (appendix only) | — | Do not cite Acc ~0.999 |
| `dataset/flow_stats.csv` | Monitor dump | — | Not used. Do not cite. |

326,961 is the number of 5-second OpenFlow snapshots, not independent sessions. Same 2s6h lab, more runs — not CICIDS-scale diversity. Headline anomaly eval: `reports/binary_realtime_loso_summary.csv` (LOSO, 21 scenarios, **RF**). Headline fault D2: `reports/fault_protocol_e_d2_loso.csv` (**RF** Acc 0.923 / F1-macro 0.926, lab only). Do not cite random-split Acc ~0.999. Do not cite Protocol D D2 ~0.38 as current.

## Results to cite

| File | Use |
|------|-----|
| `reports/binary_realtime_loso_summary.csv` | Primary anomaly table (5 models; headline **RF**) |
| `reports/fault_protocol_e_d1_loso.csv` | Fault E D1, 5 models (RF/XGB/SVM + IF/AE; AE Keras 3 CPU) |
| `reports/fault_protocol_e_d1_per_class.csv` | D1 recalls (Normal / Fault) |
| `reports/fault_protocol_e_d2_loso.csv` | Fault E D2 4-class (headline **RF** 0.923 / 0.926; IF/AE = N/A; lab only) |
| `reports/fault_protocol_e_d2_per_class.csv` | E D2 per-class recall (BW/Loss/Delay ≥ 0.82) |
| `reports/fault_protocol_d1_loso.csv` | Protocol D detection (appendix) |
| `reports/fault_protocol_d2_loso.csv` | Protocol D 4-class ~0.38 (failed injection; appendix) |
| `reports/environment_lock.txt` | Package versions |
| `reports/model_comparison.csv` | Appendix (random-flow leakage) |
| `docs/FAULT_DATASET.md` | Fault collection + D vs E |
| `docs/THESIS_EVALUATION_PROTOCOL.md` | Evaluation protocol |

## Layout

```
controller/   os-ken realtime + monitor
topology/     Mininet 2s6h
dataset/      flow_stats_grouped.csv, train/test
src/          eval_binary_realtime_scenario_held_out.py, realtime_protocol.py, train_*
models/       xgboost_model.pkl, scaler.pkl, ...
reports/      locked CSVs + plots
dashboard/    Flask
docs/         evaluation protocol
```

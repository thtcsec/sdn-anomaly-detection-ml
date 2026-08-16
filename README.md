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

| File | Role |
|------|------|
| `dataset/flow_stats_grouped.csv` | Clean independent pool (79,114 poll rows, 32 runs, 19 scenarios) |
| `dataset/train.csv` / `test.csv` | Legacy random-flow split (appendix only) |
| `dataset/flow_stats.csv` | Not used. Monitor dump; do not cite. |

79,114 is the number of 5-second OpenFlow snapshots, not independent sessions.

## Results to cite

| File | Use |
|------|-----|
| `reports/binary_realtime_loso_summary.csv` | Primary 4-model table |
| `reports/environment_lock.txt` | Package versions |
| `reports/model_comparison.csv` | Appendix (random-flow leakage) |
| `HUONG_DAN_CHINH_SUA_KHOA_LUAN_DOCX_VA_SLIDES.md` | Word / slide numbers |
| `HUONG_DAN_QUAY_VIDEO_DEMO.md` | Demo video |

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

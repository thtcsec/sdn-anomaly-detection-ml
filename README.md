# SDN Anomaly Detection using Machine Learning

Mininet **2 switch / 6 host** (`2s6h`) + os-ken OpenFlow 1.3 + machine learning. Realtime controller and Flask dashboard.

| | |
|---|---|
| Trịnh Hoàng Tú | 23DH113972 · lab SDN, thu thập, realtime, dashboard |
| Trần Minh Thiện | 23DH113375 · pipeline ML, đánh giá, Word |
| GVHD | ThS. Cao Tiến Thành · HUFLIT · K29 |

## Environment (locked)

Python **3.11**. Versions in `requirements.txt` and `reports/environment_lock.txt` produced `reports/binary_realtime_loso_summary.csv`.

```
xgboost-cpu 3.2.0     # WSL SOC has no GPU; do not pip install xgboost (CUDA wheel)
scikit-learn 1.7.2
tensorflow 2.21.0     # Autoencoder only; first import is slow (30–180 s)
pandas 2.3.1
numpy 2.2.6
os-ken 4.2.0
eventlet              # os-ken hub (OSKEN_HUB_TYPE=eventlet)
flask 2.3.3
```

Do not install unpinned latest. Do not write XGBoost 2.0.3 / sklearn 1.4.2 in the thesis unless you re-run the table on that stack.

On this WSL (Ubuntu 26.04) `python3` may be 3.14; the lock is **3.11**. Use `python3.11` (deadsnakes). Do not create `.venv` with 3.14 — TensorFlow 2.21 / sklearn 1.7 wheels will not match.

```bash
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

WSL2 + Mininet + OVS + hping3/nmap/iperf are required only for live demo, not for the evaluation command below.

`tensorflow` is required for Autoencoder eval/load. If you skip AE, you can omit TF, but then `models/autoencoder_model.keras` will not load. The other four live artifacts do not need TensorFlow.

## Reproduce the main table

Needs `dataset/flow_stats_grouped.csv` (included in the submission zip).

```bash
python src/eval_binary_realtime_scenario_held_out.py --skip-autoencoder
python src/eval_binary_realtime_scenario_held_out.py
```

Writes `reports/binary_realtime_loso_summary.csv` and `reports/binary_realtime_loso_per_scenario.csv`.

Protocol: binary Normal-vs-Attack, Leave-One-Scenario-Out (hold out one `scenario_id` per fold), first 3 polls per 5-tuple, 8 features (no raw ports), no SMOTE. Headline **Random Forest Acc 0.7724**.

## Demo realtime

Live default / thesis artifact is **Random Forest binary** (`random_forest_binary`): 8 port-agnostic features, labels `NORMAL` / `ANOMALY`. Poll 5 s. Three consecutive **completed polls** with a source-level alert → OpenFlow DROP, `priority=1000`, `hard_timeout=120`, `idle_timeout=0`.

SOC dropdown has five radios plus the live RF-binary artifact: XGBoost, Random Forest (legacy 10-feature multiclass), LinearSVC, Isolation Forest, Autoencoder. Live LinearSVC (`models/svm_model.pkl`) is a **demo baseline on the random-split 10-feature `train.csv` pipeline** — not the 8-feature LOSO headline. Do not cite its deploy accuracy as a thesis result.

On this WSL lab, install **`xgboost-cpu==3.2.0`** (already in `requirements.txt`). The default `xgboost` wheel ships a CUDA `.so` and raises `cudaErrorNoDevice` when unpickling `models/xgboost_model.pkl`. Autoencoder: first TensorFlow import is slow (often 30–180 s of silence); that is not a hang.

### Windows → WSL (usual demo)

```powershell
.\start_demo.ps1
# or start_demo.bat
```

Opens three WSL windows: os-ken controller (`:6633`), Flask SOC (`http://127.0.0.1:5000`), Mininet `topology/custom_topo.py`. Dashboard binds loopback by default.

### Manual (WSL)

```bash
source .venv/bin/activate
python controller/run_realtime.py          # OpenFlow tcp:6633
python dashboard/app.py                    # http://127.0.0.1:5000
sudo /usr/bin/python3 topology/custom_topo.py
```

### PYTHONPATH (collect vs controller)

Mininet collectors that import `mininet` often need the distro packages:

```bash
sudo PYTHONPATH=/usr/lib/python3/dist-packages python3 src/collect_independent_fault_runs.py --protocol e
```

**Do not** export that `PYTHONPATH` for the os-ken controller. Mixing `/usr/lib/python3/dist-packages` into the venv can pull the system `eventlet` / `cryptography` and break the OpenFlow hub. Controller: activate `.venv` only, `OSKEN_HUB_TYPE=eventlet` (set in `controller/run_realtime.py`).

## Data

| File | Role | Rows | Labels / groups |
|------|------|------|-----------------|
| `dataset/flow_stats_grouped.csv` | Anomaly pool (headline) | **326,961** | normal **198,810** · ddos **93,648** · portscan **34,503** · **206** `run_id` · **21** `scenario_id` |
| `dataset/fault_stats_grouped_e.csv` | Fault Protocol E (current D2) | **1,982** | delay 570 · bandwidth 553 · loss 529 · normal 330 · **112** `run_id` · **36** `scenario_id` |
| `dataset/fault_stats_grouped.csv` | Fault Protocol D (historical / broken `tc`) | 6,666 | delay 1864 · bandwidth 1857 · loss 1839 · normal 1106 · 324 run · 36 scenario |
| `dataset/fault_stats_grouped_protocol_d.csv` | Archive copy of Protocol D | 6,666 | identical to `fault_stats_grouped.csv` |
| `dataset/train.csv` / `test.csv` | Legacy random-flow split (appendix only) | — | Do not cite Acc ~0.999 |
| `dataset/flow_stats.csv` | Monitor dump | — | Not used. Do not cite. |

326,961 is the number of 5-second OpenFlow snapshots, not independent sessions. Same 2s6h lab, more runs — not CICIDS-scale diversity. Headline anomaly eval: `reports/binary_realtime_loso_summary.csv` (LOSO, 21 scenarios, **RF Acc 0.7724**). Headline fault D2: `reports/fault_protocol_e_audited_d2_loso.csv` (**RF Acc 0.925 / F1-macro 0.928**, lab only). Do not cite random-split Acc ~0.999. Do not cite Protocol D D2 ~0.38 as current. Do not cite the older 79k / 32-run / 19-scenario pool.

## Results to cite

| File | Use |
|------|-----|
| `reports/binary_realtime_loso_summary.csv` | Primary anomaly table (5 models; headline **RF 0.7724**) |
| `reports/fault_protocol_e_audited_d1_loso.csv` | Fault E D1, 5 models (RF/XGB/SVM + IF/AE) |
| `reports/fault_protocol_e_audited_d1_per_class.csv` | D1 recalls (Normal / Fault) |
| `reports/fault_protocol_e_audited_d2_loso.csv` | Fault E D2 4-class (headline **RF 0.925 / 0.928**; IF/AE = N/A; lab only) |
| `reports/fault_protocol_e_audited_d2_per_class.csv` | E D2 per-class recall |
| `reports/fault_protocol_d1_loso.csv` | Protocol D detection (appendix) |
| `reports/fault_protocol_d2_loso.csv` | Protocol D 4-class ~0.38 (failed injection; appendix) |
| `reports/realtime_binary_artifact_benchmark.csv` | RF-binary batch-1 latency p50/p95/p99 (not 0.33 ms) |
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
models/       random_forest_binary_realtime.pkl (live), xgboost_model.pkl, scaler.pkl, ...
reports/      locked CSVs + plots
dashboard/    Flask SOC (default http://127.0.0.1:5000)
docs/         evaluation protocol
```

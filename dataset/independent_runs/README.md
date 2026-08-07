# Independent Mininet runs

This folder stores **per-run** CSVs and `manifest.csv` from:

```bash
# Terminal 1
python controller/run_controller.py   # or run_realtime.py

# Terminal 2
sudo python3 src/collect_independent_ddos_runs.py --dry-run
sudo python3 src/collect_independent_ddos_runs.py
# optional faster lab flood (still lab-IP only):
sudo python3 src/collect_independent_ddos_runs.py --allow-flood
```

Then:

```bash
python src/ensure_legacy_provenance.py
python src/merge_independent_runs.py
python src/eval_grouped_real_only.py
python src/audit_feature_overlap.py --grouped
```

Notes:
- Does **not** overwrite `dataset/flow_stats.csv`.
- Each file `run_*.csv` is one independent collection run.
- Many flow rows in one run ≠ many experiments.

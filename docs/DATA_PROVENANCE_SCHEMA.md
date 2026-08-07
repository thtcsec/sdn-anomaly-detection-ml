# Data Provenance Schema

## Core ML columns (stable)
Used by training / evaluation models:

`ip_proto, tp_src, tp_dst, packet_count, byte_count, duration_sec, packet_count_per_sec, byte_count_per_sec, packet_size_avg, flow_duration, label`

Existing provenance:

| Column | Meaning |
|--------|---------|
| `is_synthetic` | `0` = lab-collected, `1` = synthetic/bootstrap |
| `source` | e.g. `real_seed_bootstrap`, `handcraft_augment`, `mininet_lab_independent_run` |

## Session / run provenance (new, backward-compatible)

| Column | Meaning |
|--------|---------|
| `run_id` | Unique independent collection run. Historical rows = `unknown` |
| `scenario_id` | Scenario recipe id (protocol/rate/attackers) |
| `capture_session_id` | One Mininet session that may contain multiple runs |
| `topology_id` | Topology fingerprint (default `custom_topo_2s6h_v1`) |
| `traffic_tool` | e.g. `hping3`, `nmap`, `iperf` |
| `attack_protocol` | `tcp_syn` / `udp` / `icmp` / `unknown` |
| `attack_rate` | Interval or `flood` |
| `attacker_count` | Number of attacker hosts (-1 if unknown) |
| `target_host` | Victim IP(s) in lab |
| `collection_timestamp` | Scenario start time |

## Rules (thesis-critical)

1. **Do not invent** `run_id` for legacy rows. Use `unknown` / `legacy_unknown`.
2. **Primary robustness protocol** after enough independent runs: group split by `run_id` on `is_synthetic==0` only (`src/eval_grouped_real_only.py`).
3. **Bootstrap (`is_synthetic==1`) must never appear in the primary test folds.**
4. Optional experiment: SMOTE / bootstrap **train-fold only** via `--with-smote-train`.
5. Legacy `reports/model_comparison.csv` remains an **internal lab benchmark** (random flow split + bootstrap in pool). Do not delete it; do not present it as generalization proof.
6. Many flows inside one DDoS run ≠ many independent experiments. Count **runs/groups**, not only rows.

## Files

| File | Role |
|------|------|
| `dataset/flow_stats.csv` | Original (do not overwrite in new protocol) |
| `dataset/flow_stats_provenance_ready.csv` | Legacy + empty run meta |
| `dataset/independent_runs/*.csv` | Per-run tagged exports |
| `dataset/independent_runs/manifest.csv` | Run inventory |
| `dataset/flow_stats_grouped.csv` | Legacy + independent runs merged |
| `reports/model_comparison.csv` | Legacy benchmark (unchanged) |
| `reports/grouped_real_only_*.csv` | Grouped protocol outputs |

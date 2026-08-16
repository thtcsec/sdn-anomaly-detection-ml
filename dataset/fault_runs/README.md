Fault runs (Mininet s1-s2). Do not mix into independent_runs / flow_stats_grouped.csv.

Collect: python controller/run_fault_monitor.py
        sudo python3 src/collect_independent_fault_runs.py
Merge:  python src/merge_fault_runs.py
See docs/FAULT_DATASET.md

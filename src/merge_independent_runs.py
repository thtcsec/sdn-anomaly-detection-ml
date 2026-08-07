"""
Merge independent run CSVs + legacy provenance-ready rows into a grouped dataset.

Does NOT overwrite:
  - dataset/flow_stats.csv
  - dataset/train.csv
  - dataset/test.csv

Writes:
  dataset/flow_stats_grouped.csv

Chạy:
  python src/ensure_legacy_provenance.py
  python src/merge_independent_runs.py
"""

from __future__ import annotations

import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import LEGACY_DEFAULTS, RUN_META_COLS, SOURCE_INDEPENDENT  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY = os.path.join(BASE_DIR, 'dataset', 'flow_stats_provenance_ready.csv')
RUNS_DIR = os.path.join(BASE_DIR, 'dataset', 'independent_runs')
OUT = os.path.join(BASE_DIR, 'dataset', 'flow_stats_grouped.csv')


def main() -> None:
    if not os.path.exists(LEGACY):
        print('[!] Missing flow_stats_provenance_ready.csv — chạy ensure_legacy_provenance.py trước')
        sys.exit(1)

    frames = [pd.read_csv(LEGACY)]
    print(f'[*] Legacy rows: {len(frames[0])}')

    run_files = []
    if os.path.isdir(RUNS_DIR):
        run_files = sorted(
            f for f in os.listdir(RUNS_DIR)
            if f.startswith('run_') and f.endswith('.csv')
        )

    n_new = 0
    for name in run_files:
        path = os.path.join(RUNS_DIR, name)
        df = pd.read_csv(path)
        if df.empty:
            continue
        # Enforce provenance for independent runs
        df['is_synthetic'] = 0
        df['source'] = SOURCE_INDEPENDENT
        for col, default in LEGACY_DEFAULTS.items():
            if col not in df.columns:
                df[col] = default
        frames.append(df)
        n_new += len(df)
        print(f'  + {name}: {len(df)} rows')

    merged = pd.concat(frames, ignore_index=True)
    # Prefer keeping all columns; fill run meta defaults
    for col, default in LEGACY_DEFAULTS.items():
        if col not in merged.columns:
            merged[col] = default
        else:
            if col == 'attacker_count':
                merged[col] = pd.to_numeric(merged[col], errors='coerce').fillna(-1).astype(int)
            else:
                merged[col] = merged[col].fillna(default)

    tmp = OUT + '.tmp'
    merged.to_csv(tmp, index=False)
    os.replace(tmp, OUT)

    print(f'[✓] Wrote {OUT}')
    print(f'[*] Total rows={len(merged)} | new independent flows={n_new} | run files={len(run_files)}')
    if 'run_id' in merged.columns:
        known = merged[merged['run_id'].astype(str) != 'unknown']
        print(f'[*] Rows with known run_id: {len(known)} | unique runs: {known["run_id"].nunique()}')


if __name__ == '__main__':
    main()

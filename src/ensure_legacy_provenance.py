"""
Ensure legacy flow_stats rows have provenance columns WITHOUT inventing run_id.

Reads:  dataset/flow_stats.csv  (unchanged on disk)
Writes: dataset/flow_stats_provenance_ready.csv

Legacy rules:
  - Existing is_synthetic / source preserved
  - Missing run metadata → unknown / legacy_unknown
  - Never fabricate historical run_id

Chạy: python src/ensure_legacy_provenance.py
"""

from __future__ import annotations

import os
import sys

import pandas as pd

# Allow `python src/ensure_legacy_provenance.py`
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from provenance_schema import (  # noqa: E402
    BASE_COLS,
    LEGACY_DEFAULTS,
    RUN_META_COLS,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(BASE_DIR, 'dataset', 'flow_stats.csv')
OUT = os.path.join(BASE_DIR, 'dataset', 'flow_stats_provenance_ready.csv')


def main() -> None:
    if not os.path.exists(RAW):
        print(f'[!] Missing {RAW}')
        sys.exit(1)

    df = pd.read_csv(RAW)
    print(f'[*] Loaded {len(df)} rows from flow_stats.csv (read-only)')

    if 'is_synthetic' not in df.columns:
        df['is_synthetic'] = 0
    if 'source' not in df.columns:
        df['source'] = ''

    df['is_synthetic'] = df['is_synthetic'].fillna(0).astype(int)
    df['source'] = df['source'].fillna('').astype(str)

    # Do not invent synthetic flags beyond what mark_data_provenance already set.
    for col, default in LEGACY_DEFAULTS.items():
        if col not in df.columns:
            df[col] = default
        else:
            if col == 'attacker_count':
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(-1).astype(int)
            else:
                df[col] = df[col].fillna(default).replace('', default)

    # Mark legacy rows that still lack a real run_id
    mask_unknown = df['run_id'].astype(str).isin(['', 'unknown', 'nan'])
    df.loc[mask_unknown, 'run_id'] = 'unknown'
    df.loc[mask_unknown, 'scenario_id'] = df.loc[mask_unknown, 'scenario_id'].replace(
        {'': 'legacy_unknown'}
    )
    df.loc[mask_unknown & (df['scenario_id'].astype(str).isin(['unknown', 'nan'])), 'scenario_id'] = (
        'legacy_unknown'
    )

    # Preferred column order
    ordered = [c for c in BASE_COLS + RUN_META_COLS if c in df.columns]
    extra = [c for c in df.columns if c not in ordered]
    df = df[ordered + extra]

    tmp = OUT + '.tmp'
    df.to_csv(tmp, index=False)
    os.replace(tmp, OUT)

    print(f'[✓] Wrote {OUT} ({len(df)} rows) — original flow_stats.csv NOT modified')
    print('[*] run_id value counts (top):')
    print(df['run_id'].astype(str).value_counts().head(10).to_string())
    print('[*] is_synthetic x label:')
    print(pd.crosstab(df['label'], df['is_synthetic']).to_string())


if __name__ == '__main__':
    main()

"""
Merge independent run CSVs into the canonical lab training pool.

Default: independent-only (no legacy dump, no random-generated massive files).
Does NOT overwrite dataset/flow_stats.csv.

Writes:
  dataset/flow_stats_grouped.csv

Chạy:
  python src/merge_independent_runs.py
  python src/merge_independent_runs.py --with-legacy   # archival only
"""

from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import LEGACY_DEFAULTS, SOURCE_INDEPENDENT  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY = os.path.join(BASE_DIR, 'dataset', 'flow_stats_provenance_ready.csv')
RUNS_DIR = os.path.join(BASE_DIR, 'dataset', 'independent_runs')
OUT = os.path.join(BASE_DIR, 'dataset', 'flow_stats_grouped.csv')
SKIP_NAME_MARKERS = ('normal_massive',)


def _is_skipped_run(name: str, df: pd.DataFrame) -> bool:
    lower = name.lower()
    if any(m in lower for m in SKIP_NAME_MARKERS):
        return True
    if 'run_id' in df.columns and df['run_id'].astype(str).str.startswith('run_normal_massive_').any():
        return True
    return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        '--with-legacy',
        action='store_true',
        help='Also prepend dirty/unknown flow_stats dump. Do NOT use for controller train.',
    )
    args = ap.parse_args()

    frames: list[pd.DataFrame] = []
    if args.with_legacy:
        if not os.path.exists(LEGACY):
            print('[!] Missing flow_stats_provenance_ready.csv')
            sys.exit(1)
        frames.append(pd.read_csv(LEGACY, low_memory=False))
        print(f'[*] Legacy rows (NOT for controller train): {len(frames[0])}')

    run_files = []
    if os.path.isdir(RUNS_DIR):
        run_files = sorted(
            f for f in os.listdir(RUNS_DIR)
            if f.startswith('run_') and f.endswith('.csv')
        )

    n_new = 0
    skipped = 0
    for name in run_files:
        path = os.path.join(RUNS_DIR, name)
        df = pd.read_csv(path)
        if df.empty:
            continue
        if _is_skipped_run(name, df):
            print(f'  skip {name}: generated/massive, not OpenFlow')
            skipped += 1
            continue
        df['is_synthetic'] = 0
        df['source'] = SOURCE_INDEPENDENT
        for col, default in LEGACY_DEFAULTS.items():
            if col not in df.columns:
                df[col] = default
        frames.append(df)
        n_new += len(df)
        print(f'  + {name}: {len(df)} rows')

    if not frames:
        print('[!] No independent runs to merge')
        sys.exit(1)

    merged = pd.concat(frames, ignore_index=True)
    for col, default in LEGACY_DEFAULTS.items():
        if col not in merged.columns:
            merged[col] = default
        elif col == 'attacker_count':
            merged[col] = pd.to_numeric(merged[col], errors='coerce').fillna(-1).astype(int)
        else:
            merged[col] = merged[col].fillna(default)

    tmp = OUT + '.tmp'
    merged.to_csv(tmp, index=False)
    os.replace(tmp, OUT)

    print(f'[✓] Wrote {OUT}')
    print(f'[*] Total rows={len(merged)} | independent={n_new} | skipped_fake={skipped}')
    if 'label' in merged.columns:
        print(merged['label'].astype(str).str.lower().value_counts().to_string())
    if 'run_id' in merged.columns:
        known = merged[~merged['run_id'].astype(str).isin(['unknown', 'nan', '', 'None'])]
        print(f'[*] known run_id rows={len(known)} | unique runs={known["run_id"].nunique()}')


if __name__ == '__main__':
    main()

"""
Exact feature-overlap audit between train/test feature fingerprints.

Writes reports/feature_overlap_audit.csv
Does NOT delete overlapping rows from any benchmark.

Chạy:
  python src/audit_feature_overlap.py
  python src/audit_feature_overlap.py --grouped
"""

from __future__ import annotations

import argparse
import os
import sys

import pandas as pd
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import FEATURE_COLS  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS = os.path.join(BASE_DIR, 'reports')
OUT = os.path.join(REPORTS, 'feature_overlap_audit.csv')


def fingerprint(df: pd.DataFrame) -> pd.Series:
    cols = [c for c in FEATURE_COLS if c in df.columns]
    return df[cols].astype(str).agg('|'.join, axis=1)


def audit_official_split() -> dict:
    train = pd.read_csv(os.path.join(BASE_DIR, 'dataset', 'train.csv'))
    test = pd.read_csv(os.path.join(BASE_DIR, 'dataset', 'test.csv'))
    # train/test may only have features+label
    tr = set(fingerprint(train))
    te = set(fingerprint(test))
    overlap = tr & te
    return {
        'protocol': 'legacy_official_train_test',
        'fold': -1,
        'n_train': len(train),
        'n_test': len(test),
        'n_overlap_fingerprints': len(overlap),
        'n_test_rows_in_overlap': int(fingerprint(test).isin(overlap).sum()),
        'overlap_rate_of_test': float(fingerprint(test).isin(overlap).mean()),
        'notes': 'Does not remove overlap; informational only',
    }


def audit_grouped(path: str) -> list[dict]:
    if not os.path.exists(path):
        return [{
            'protocol': 'grouped_real_only',
            'fold': -1,
            'n_train': 0,
            'n_test': 0,
            'n_overlap_fingerprints': 0,
            'n_test_rows_in_overlap': 0,
            'overlap_rate_of_test': 0.0,
            'notes': f'Missing {path}',
        }]

    df = pd.read_csv(path)
    real = df[(df.get('is_synthetic', 0).fillna(0).astype(int) == 0)].copy()
    real = real[~real['run_id'].astype(str).isin(['unknown', 'nan', ''])]
    rows = []
    if real.empty or real['run_id'].nunique() < 2:
        rows.append({
            'protocol': 'grouped_real_only',
            'fold': -1,
            'n_train': 0,
            'n_test': 0,
            'n_overlap_fingerprints': 0,
            'n_test_rows_in_overlap': 0,
            'overlap_rate_of_test': 0.0,
            'notes': f'Insufficient known run_id groups (n={real["run_id"].nunique() if len(real) else 0})',
        })
        return rows

    real = real.dropna(subset=FEATURE_COLS + ['label'])
    groups = real['run_id'].astype(str)
    n_splits = min(5, groups.nunique())
    gkf = GroupKFold(n_splits=n_splits)
    X = real[FEATURE_COLS]
    y = real['label']
    for fold, (tr, te) in enumerate(gkf.split(X, y, groups)):
        tr_fp = set(fingerprint(real.iloc[tr]))
        te_fp = fingerprint(real.iloc[te])
        overlap = set(te_fp) & tr_fp
        rows.append({
            'protocol': 'grouped_real_only',
            'fold': fold,
            'n_train': len(tr),
            'n_test': len(te),
            'n_overlap_fingerprints': len(overlap),
            'n_test_rows_in_overlap': int(te_fp.isin(overlap).sum()),
            'overlap_rate_of_test': float(te_fp.isin(overlap).mean()),
            'notes': f'GroupKFold n_splits={n_splits}',
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--grouped', action='store_true')
    args = ap.parse_args()
    os.makedirs(REPORTS, exist_ok=True)

    rows = [audit_official_split()]
    if args.grouped:
        grouped_path = os.path.join(BASE_DIR, 'dataset', 'flow_stats_grouped.csv')
        rows.extend(audit_grouped(grouped_path))

    out_df = pd.DataFrame(rows)
    out_df.to_csv(OUT, index=False)
    print(out_df.to_string(index=False))
    print(f'\n[✓] Wrote {OUT}')


if __name__ == '__main__':
    main()

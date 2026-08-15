"""
Import InSDN (SDN-domain public dataset) as a supplementary benchmark.

The Hugging Face mirror used here is binary (0=Normal, 1=Attack), 343,889 rows.
It is NOT mixed into the Mininet controller train set.

Official InSDN paper also has multiclass (Normal/DoS/DDoS/Probe/...), but the
reachable mirror at the time of import only exposes the binary target column.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from provenance_schema import FEATURE_COLS

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SRC = Path(r'D:\huflit_logs\public_datasets\insdn\Dataset.csv')
DEFAULT_OUT = BASE_DIR / 'dataset' / 'public_benchmark' / 'insdn_binary'


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', default=str(DEFAULT_SRC))
    ap.add_argument('--out-dir', default=str(DEFAULT_OUT))
    ap.add_argument('--test-size', type=float, default=0.2)
    args = ap.parse_args()

    src = Path(args.src)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print('=' * 60)
    print('  IMPORT PUBLIC InSDN (binary SDN benchmark)')
    print('=' * 60)
    print(f'[*] Source: {src}')

    usecols = [
        'Src Port', 'Dst Port', 'Protocol', 'Flow Duration',
        'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
        'Flow Byts/s', 'Flow Pkts/s', 'Pkt Size Avg', 'target',
    ]
    df = pd.read_csv(src, usecols=usecols)
    df = df.replace([np.inf, -np.inf], np.nan)
    out_df = pd.DataFrame({
        'ip_proto': pd.to_numeric(df['Protocol'], errors='coerce'),
        'tp_src': pd.to_numeric(df['Src Port'], errors='coerce'),
        'tp_dst': pd.to_numeric(df['Dst Port'], errors='coerce'),
        'packet_count': (
            pd.to_numeric(df['Tot Fwd Pkts'], errors='coerce').fillna(0)
            + pd.to_numeric(df['Tot Bwd Pkts'], errors='coerce').fillna(0)
        ),
        'byte_count': (
            pd.to_numeric(df['TotLen Fwd Pkts'], errors='coerce').fillna(0)
            + pd.to_numeric(df['TotLen Bwd Pkts'], errors='coerce').fillna(0)
        ),
        'duration_sec': pd.to_numeric(df['Flow Duration'], errors='coerce') / 1_000_000.0,
        'packet_count_per_sec': pd.to_numeric(df['Flow Pkts/s'], errors='coerce'),
        'byte_count_per_sec': pd.to_numeric(df['Flow Byts/s'], errors='coerce'),
        'packet_size_avg': pd.to_numeric(df['Pkt Size Avg'], errors='coerce'),
        'flow_duration': pd.to_numeric(df['Flow Duration'], errors='coerce') / 1_000_000.0,
        'label': df['target'].map({0: 'normal', 1: 'anomaly'}),
        'is_synthetic': 0,
        'source': 'insdn_public_binary',
        'run_id': 'insdn_binary_mirror',
    })
    before = len(out_df)
    out_df = out_df.dropna(subset=FEATURE_COLS + ['label']).copy()
    print(f'[*] Rows {before} -> {len(out_df)} after clean')
    print(out_df['label'].value_counts().to_string())

    y = (out_df['label'] == 'anomaly').astype(int)
    X = out_df[FEATURE_COLS]
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )
    train = pd.DataFrame(X_tr, columns=FEATURE_COLS)
    train['label'] = y_tr.values
    test = pd.DataFrame(X_te, columns=FEATURE_COLS)
    test['label'] = y_te.values

    out_df.to_csv(out / 'flow_stats.csv', index=False)
    train.to_csv(out / 'train.csv', index=False)
    test.to_csv(out / 'test.csv', index=False)
    pd.DataFrame([{
        'dataset': 'insdn_binary',
        'rows': len(out_df),
        'rows_train': len(train),
        'rows_test': len(test),
        'labels': 'normal,anomaly',
        'source': 'insdn_public_binary',
        'note': 'SDN-domain public benchmark only. Binary mirror (0=Normal, 1=Attack). Not used as Mininet controller train set.',
    }]).to_csv(out / 'dataset_summary.csv', index=False)
    print(f'[✓] Saved {out}')


if __name__ == '__main__':
    main()

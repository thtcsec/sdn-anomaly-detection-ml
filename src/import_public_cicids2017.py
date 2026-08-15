"""
Import a focused CICIDS2017 benchmark into this repo's 10-feature schema.

Goal:
  - Keep the legacy Mininet benchmark untouched.
  - Build a separate public benchmark with 3 classes only:
      normal / ddos / portscan
  - Preserve provenance so thesis wording can distinguish data sources.

Inputs (downloaded outside the repo):
  - Monday-WorkingHours.pcap_ISCX.csv.parquet
  - Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet
  - Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet

Outputs (inside repo):
  dataset/public_benchmark/cicids2017_3class/
    - flow_stats.csv
    - train.csv
    - test.csv
    - dataset_summary.csv
    - source_label_summary.csv
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from provenance_schema import FEATURE_COLS, RUN_META_COLS

try:
    from imblearn.over_sampling import SMOTE
except Exception as exc:  # pragma: no cover - import guard
    raise SystemExit(
        'imblearn is required for import_public_cicids2017.py. '
        'Install project dependencies first.'
    ) from exc


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATA_ROOT = Path(r'D:\huflit_logs\public_datasets\cicids2017')
DEFAULT_OUT_DIR = BASE_DIR / 'dataset' / 'public_benchmark' / 'cicids2017_3class'

SOURCE_FILES = {
    'monday': 'Monday-WorkingHours.pcap_ISCX.csv.parquet',
    'portscan': 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet',
    'ddos': 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet',
}

LABEL_MAP = {
    'BENIGN': 'normal',
    'PortScan': 'portscan',
    'DDoS': 'ddos',
}

REQUIRED_PUBLIC_COLS = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Average Packet Size',
    'Label',
]

TCP_FLAG_COLS = [
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'URG Flag Count',
    'ECE Flag Count',
    'CWE Flag Count',
]


def _load_one(path: Path, source_key: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f'Missing source file: {path}')

    df = pd.read_parquet(path)
    missing = [c for c in REQUIRED_PUBLIC_COLS if c not in df.columns]
    if missing:
        raise ValueError(f'{path.name} missing required columns: {missing}')

    selected_cols = [c for c in REQUIRED_PUBLIC_COLS if c in df.columns]
    selected_cols.extend([c for c in TCP_FLAG_COLS if c in df.columns])
    selected_cols = list(dict.fromkeys(selected_cols))
    df = df[selected_cols].copy()
    df['Label'] = df['Label'].astype(str).str.strip()
    df = df[df['Label'].isin(LABEL_MAP)].copy()

    # Normalize infinities that often appear in CICIDS flow-rate columns.
    df = df.replace([np.inf, -np.inf, 'Infinity', 'inf'], np.nan)

    if 'Protocol' in df.columns:
        ip_proto = pd.to_numeric(df['Protocol'], errors='coerce')
    else:
        tcp_flags_present = sum(
            pd.to_numeric(df.get(col, 0), errors='coerce').fillna(0)
            for col in TCP_FLAG_COLS
            if col in df.columns
        )
        # Heuristic fallback for mirrors that dropped the Protocol column.
        ip_proto = np.where(tcp_flags_present > 0, 6, 0)

    if 'Source Port' in df.columns:
        tp_src = pd.to_numeric(df['Source Port'], errors='coerce')
    else:
        # Official mirrors often omit Source Port; keep a sentinel instead of inventing it.
        tp_src = pd.Series(-1, index=df.index, dtype='int64')

    out = pd.DataFrame({
        'ip_proto': ip_proto,
        'tp_src': tp_src,
        'tp_dst': pd.to_numeric(df['Destination Port'], errors='coerce'),
        'packet_count': (
            pd.to_numeric(df['Total Fwd Packets'], errors='coerce').fillna(0)
            + pd.to_numeric(df['Total Backward Packets'], errors='coerce').fillna(0)
        ),
        'byte_count': (
            pd.to_numeric(df['Total Length of Fwd Packets'], errors='coerce').fillna(0)
            + pd.to_numeric(df['Total Length of Bwd Packets'], errors='coerce').fillna(0)
        ),
        # CICIDS Flow Duration is in microseconds; convert to seconds.
        'duration_sec': pd.to_numeric(df['Flow Duration'], errors='coerce') / 1_000_000.0,
        'packet_count_per_sec': pd.to_numeric(df['Flow Packets/s'], errors='coerce'),
        'byte_count_per_sec': pd.to_numeric(df['Flow Bytes/s'], errors='coerce'),
        'packet_size_avg': pd.to_numeric(df['Average Packet Size'], errors='coerce'),
        'flow_duration': pd.to_numeric(df['Flow Duration'], errors='coerce') / 1_000_000.0,
        'label': df['Label'].map(LABEL_MAP),
    })

    source_name = f'cicids2017_{source_key}'
    out['timestamp'] = ''
    out['datapath_id'] = 0
    out['flow_id'] = ''
    out['ip_src'] = ''
    out['ip_dst'] = ''
    out['duration_nsec'] = 0
    out['is_synthetic'] = 0
    out['source'] = 'cicids2017_public'
    out['run_id'] = source_name
    out['scenario_id'] = source_name
    out['capture_session_id'] = path.name
    out['topology_id'] = 'external_cicids2017'
    out['traffic_tool'] = 'cicflowmeter'
    out['attack_protocol'] = 'mixed'
    out['attack_rate'] = 'unknown'
    out['attacker_count'] = -1
    out['target_host'] = 'unknown'
    out['collection_timestamp'] = ''
    out['source_file'] = path.name
    return out


def build_dataset(data_root: Path) -> pd.DataFrame:
    frames = []
    for key, filename in SOURCE_FILES.items():
        frames.append(_load_one(data_root / filename, key))
    df = pd.concat(frames, ignore_index=True)

    before = len(df)
    df = df.dropna(subset=FEATURE_COLS + ['label']).copy()
    after_na = len(df)

    # Public dataset can contain exact duplicates after conversion/mirroring.
    df = df.drop_duplicates(subset=FEATURE_COLS + ['label', 'source_file']).copy()
    after_dedup = len(df)

    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURE_COLS + ['label']).copy()

    print(f'[*] Combined rows before clean: {before}')
    print(f'[*] After dropna on ML columns: {after_na}')
    print(f'[*] After dedup: {after_dedup}')
    print(f'[*] Final rows: {len(df)}')
    print('[*] Label distribution:')
    print(df['label'].value_counts().to_string())
    print('[*] Source/label distribution:')
    print(df.groupby(['source_file', 'label']).size().to_string())
    return df


def split_and_save(df: pd.DataFrame, out_dir: Path, test_size: float, random_state: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    le = LabelEncoder()
    y = le.fit_transform(df['label'])
    X = df[FEATURE_COLS].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    smote = SMOTE(random_state=random_state)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)

    train_df = pd.DataFrame(X_train_res, columns=FEATURE_COLS)
    train_df['label'] = y_train_res
    test_df = pd.DataFrame(X_test, columns=FEATURE_COLS)
    test_df['label'] = y_test
    train_raw_df = pd.DataFrame(X_train, columns=FEATURE_COLS)
    train_raw_df['label'] = y_train
    test_raw_df = pd.DataFrame(X_test, columns=FEATURE_COLS)
    test_raw_df['label'] = y_test

    df.to_csv(out_dir / 'flow_stats.csv', index=False)
    train_df.to_csv(out_dir / 'train.csv', index=False)
    test_df.to_csv(out_dir / 'test.csv', index=False)
    train_raw_df.to_csv(out_dir / 'train_raw.csv', index=False)
    test_raw_df.to_csv(out_dir / 'test_raw.csv', index=False)

    dataset_summary = pd.DataFrame([
        {
            'dataset': 'cicids2017_3class',
            'rows_raw': len(df),
            'rows_train_after_smote': len(train_df),
            'rows_test': len(test_df),
            'test_size': test_size,
            'random_state': random_state,
            'labels': ','.join(le.classes_),
            'label_mapping_json': json.dumps(
                {cls: int(idx) for cls, idx in zip(le.classes_, le.transform(le.classes_))}
            ),
            'source': 'cicids2017_public',
            'is_synthetic': 0,
            'split_protocol': 'stratified_random_flow_split',
            'split_note': 'Public benchmark only; source-held-out CV is not valid because DDOS and PortScan each live in dedicated source files.',
            'missing_public_cols_strategy': 'If Protocol is absent, infer TCP(6) when TCP flag counts > 0 else 0; if Source Port is absent, use sentinel -1.',
        }
    ])
    dataset_summary.to_csv(out_dir / 'dataset_summary.csv', index=False)

    source_label_summary = (
        df.groupby(['source_file', 'label'])
        .size()
        .reset_index(name='rows')
        .sort_values(['source_file', 'label'])
    )
    source_label_summary.to_csv(out_dir / 'source_label_summary.csv', index=False)

    print(f'[✓] Saved canonical benchmark to: {out_dir}')
    print(f'[✓] Saved raw canonical CSV: {out_dir / "flow_stats.csv"}')
    print(
        '[✓] Saved train/test CSVs: '
        f'{out_dir / "train.csv"}, {out_dir / "test.csv"} '
        f'(+ raw pre-SMOTE splits)'
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--data-root', default=str(DEFAULT_DATA_ROOT))
    ap.add_argument('--out-dir', default=str(DEFAULT_OUT_DIR))
    ap.add_argument('--test-size', type=float, default=0.2)
    ap.add_argument('--random-state', type=int, default=42)
    args = ap.parse_args()

    data_root = Path(args.data_root)
    out_dir = Path(args.out_dir)

    print('=' * 60)
    print('  IMPORT PUBLIC CICIDS2017 BENCHMARK')
    print('=' * 60)
    print(f'[*] Data root: {data_root}')
    print(f'[*] Output dir: {out_dir}')

    df = build_dataset(data_root)

    # Ensure provenance columns are present for docs/reporting consistency.
    missing_meta = [c for c in RUN_META_COLS if c not in df.columns]
    if missing_meta:
        raise ValueError(f'Missing run metadata columns after import: {missing_meta}')

    split_and_save(df, out_dir, test_size=args.test_size, random_state=args.random_state)


if __name__ == '__main__':
    main()

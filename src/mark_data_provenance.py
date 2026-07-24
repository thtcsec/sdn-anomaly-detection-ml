"""
Gắn nhãn provenance cho dataset/flow_stats.csv.

Thêm cột is_synthetic:
  - 1: mẫu synthetic (handcraft 2026-05-15 hoặc real_seed_bootstrap)
  - 0: mẫu thu từ lab

Chạy: python src/mark_data_provenance.py
"""

import os
import sys

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_FILE = os.path.join(BASE_DIR, 'dataset', 'flow_stats.csv')

SYNTHETIC_DATE_PREFIX = '2026-05-15'


def _safe_write_csv(df: pd.DataFrame, path: str) -> None:
    tmp = path + '.tmp'
    df.to_csv(tmp, index=False)
    os.replace(tmp, path)


def main():
    if not os.path.exists(CSV_FILE):
        print(f'[!] Missing {CSV_FILE}')
        sys.exit(1)

    df = pd.read_csv(CSV_FILE)
    print(f'[*] Loaded {len(df)} rows')

    if 'is_synthetic' not in df.columns:
        df['is_synthetic'] = 0
    if 'source' not in df.columns:
        df['source'] = ''
    else:
        df['source'] = df['source'].fillna('').astype(str)

    df['is_synthetic'] = 0

    # Handcraft augment cũ
    mask_handcraft = (df['label'].astype(str).str.lower() == 'ddos') & (
        df['timestamp'].astype(str).str.startswith(SYNTHETIC_DATE_PREFIX)
    )
    df.loc[mask_handcraft, 'is_synthetic'] = 1
    empty_hc = mask_handcraft & (
        df['source'].isna() | (df['source'].astype(str).str.strip() == '')
    )
    df.loc[empty_hc, 'source'] = 'handcraft_augment'

    # Bootstrap từ seed real
    if 'source' in df.columns:
        mask_boot = df['source'].astype(str) == 'real_seed_bootstrap'
        df.loc[mask_boot, 'is_synthetic'] = 1

    print('[*] Provenance summary:')
    print(df.groupby(['label', 'is_synthetic']).size().to_string())

    _safe_write_csv(df, CSV_FILE)
    print(f'[✓] Updated {CSV_FILE}')


if __name__ == '__main__':
    main()

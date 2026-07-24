"""
Sinh thêm mẫu DDoS từ seed LAB THẬT (is_synthetic=0), không dùng mẫu hand-craft cũ.

Cách làm:
  - Lấy các dòng ddos real trong flow_stats.csv
  - Bootstrap + nhiễu nhỏ trên đặc trưng liên tục
  - Ghi thêm vào CSV với is_synthetic=1, source=real_seed_bootstrap
  - Timestamp dùng ngày hôm nay (khác 2026-05-15 của augment cũ)

Mục tiêu: tăng coverage DDoS gần phân phối lab thật hơn so với SYN/UDP/ICMP
tự bịa trong augment_ddos_data.py — vẫn phải disclose là semi-synthetic.

Chạy: python src/bootstrap_real_ddos.py [--target 400]
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_FILE = os.path.join(BASE_DIR, 'dataset', 'flow_stats.csv')

FEATURE_NOISE = {
    'packet_count': 0.08,
    'byte_count': 0.08,
    'duration_sec': 0.05,
    'duration_nsec': 0.0,
    'packet_count_per_sec': 0.10,
    'byte_count_per_sec': 0.10,
    'packet_size_avg': 0.05,
    'flow_duration': 0.05,
}

KEEP_AS_IS = {
    'datapath_id', 'ip_src', 'ip_dst', 'ip_proto', 'tp_src', 'tp_dst', 'label',
}


def _safe_write_csv(df: pd.DataFrame, path: str) -> None:
    """Ghi atomic để tránh Errno 22 / file lock nửa chừng."""
    tmp = path + '.tmp'
    df.to_csv(tmp, index=False)
    os.replace(tmp, path)


def bootstrap_rows(real: pd.DataFrame, n: int, rng: np.random.Generator) -> pd.DataFrame:
    if len(real) == 0:
        raise ValueError('Không có ddos real (is_synthetic=0) để bootstrap')

    idxs = rng.integers(0, len(real), size=n)
    rows = real.iloc[idxs].copy().reset_index(drop=True)
    base_time = datetime.now().replace(microsecond=0)

    for i in range(n):
        rows.at[i, 'timestamp'] = (base_time + timedelta(seconds=int(rng.integers(0, 600)))).strftime(
            '%Y-%m-%d %H:%M:%S'
        )
        rows.at[i, 'is_synthetic'] = 1
        if 'source' in rows.columns or True:
            rows.at[i, 'source'] = 'real_seed_bootstrap'

        for col, scale in FEATURE_NOISE.items():
            if col not in rows.columns:
                continue
            val = float(rows.at[i, col])
            if scale <= 0 or val == 0:
                continue
            noise = 1.0 + float(rng.normal(0.0, scale))
            noise = max(0.5, min(1.5, noise))
            new_val = val * noise
            if col in ('packet_count', 'byte_count', 'duration_sec', 'duration_nsec'):
                new_val = max(1, int(round(new_val)))
            rows.at[i, col] = new_val

        # Đồng bộ rate features sau nhiễu
        dur = float(rows.at[i, 'flow_duration'])
        if dur <= 0:
            dur = max(float(rows.at[i, 'duration_sec']), 1.0)
            rows.at[i, 'flow_duration'] = dur
        pkts = float(rows.at[i, 'packet_count'])
        byts = float(rows.at[i, 'byte_count'])
        rows.at[i, 'packet_count_per_sec'] = pkts / dur
        rows.at[i, 'byte_count_per_sec'] = byts / dur
        rows.at[i, 'packet_size_avg'] = byts / pkts if pkts > 0 else 0.0
        rows.at[i, 'flow_id'] = int(rng.integers(10**6, 10**8))

    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=int, default=400,
                        help='Số mẫu bootstrap muốn có (từ seed real)')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--replace-old-handcraft', action='store_true',
                        help='Xóa ddos synthetic timestamp 2026-05-15 (augment cũ)')
    args = parser.parse_args()

    if not os.path.exists(CSV_FILE):
        raise SystemExit(f'[!] Missing {CSV_FILE}')

    df = pd.read_csv(CSV_FILE)
    if 'is_synthetic' not in df.columns:
        df['is_synthetic'] = 0
    if 'source' not in df.columns:
        df['source'] = ''

    # Chuẩn hóa provenance nhanh
    df['is_synthetic'] = df['is_synthetic'].fillna(0).astype(int)
    mask_old = (
        (df['label'].astype(str).str.lower() == 'ddos')
        & (df['timestamp'].astype(str).str.startswith('2026-05-15'))
    )
    df.loc[mask_old, 'is_synthetic'] = 1
    df.loc[mask_old & (df['source'].astype(str).str.len() == 0), 'source'] = 'handcraft_augment'

    if args.replace_old_handcraft:
        before = len(df)
        df = df.loc[~mask_old].copy()
        print(f'[*] Removed {before - len(df)} handcraft synthetic DDoS (2026-05-15)')

    # Xóa bootstrap cũ để idempotent
    boot_mask = df['source'].astype(str) == 'real_seed_bootstrap'
    if boot_mask.any():
        df = df.loc[~boot_mask].copy()
        print(f'[*] Cleared previous real_seed_bootstrap rows')

    real = df[
        (df['label'].astype(str).str.lower() == 'ddos')
        & (df['is_synthetic'] == 0)
    ].copy()
    print(f'[*] Real DDoS seeds: {len(real)}')
    if len(real) == 0:
        raise SystemExit('[!] Không có ddos real — thu lab trước (collect_ddos_extra.py)')

    rng = np.random.default_rng(args.seed)
    new_rows = bootstrap_rows(real, args.target, rng)
    df = pd.concat([df, new_rows], ignore_index=True)

    print('[*] After bootstrap:')
    print(df.groupby(['label', 'is_synthetic']).size().to_string())
    if 'source' in df.columns:
        print('[*] DDoS by source:')
        print(
            df[df['label'].astype(str).str.lower() == 'ddos']
            .groupby(df['source'].replace('', 'lab_or_unknown'))
            .size()
            .to_string()
        )

    _safe_write_csv(df, CSV_FILE)
    print(f'[✓] Updated {CSV_FILE} (+{args.target} real-seed bootstrap DDoS)')


if __name__ == '__main__':
    main()

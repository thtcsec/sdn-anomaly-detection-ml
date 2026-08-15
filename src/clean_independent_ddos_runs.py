"""
Lọc lại các run DDoS độc lập đã thu: chỉ giữ attacker -> target, packet_count > 0.

Không đụng flow_stats.csv. Ghi đè từng run_*.csv DDoS + cập nhật manifest.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
RUNS_DIR = BASE_DIR / 'dataset' / 'independent_runs'
MANIFEST = RUNS_DIR / 'manifest.csv'
ATTACKERS = {'10.0.0.4', '10.0.0.5', '10.0.0.6'}


def main() -> None:
    if not MANIFEST.exists():
        raise SystemExit(f'Missing {MANIFEST}')

    manifest = pd.read_csv(MANIFEST)
    rows = []
    for rec in manifest.to_dict(orient='records'):
        run_id = str(rec['run_id'])
        path = RUNS_DIR / f'{run_id}.csv'
        if not path.exists():
            rows.append(rec)
            continue
        df = pd.read_csv(path)
        before = len(df)
        scenario = str(rec.get('scenario_id', ''))
        if scenario.startswith('ddos_'):
            targets = {p.strip() for p in str(rec.get('target_host', '')).split(';') if p.strip()}
            from collect_independent_ddos_runs import filter_ddos_related
            df = filter_ddos_related(df, targets)
            df['label'] = 'ddos'
            df.to_csv(path, index=False)
            rec['n_flows_exported'] = len(df)
            rec['notes'] = f"{rec.get('notes', '')}; cleaned_attacker_target packet_count>0 ({before}->{len(df)})"
            print(f'[clean] {run_id} {before} -> {len(df)}')
        rows.append(rec)

    pd.DataFrame(rows).to_csv(MANIFEST, index=False)
    print(f'[✓] Updated {MANIFEST}')


if __name__ == '__main__':
    main()

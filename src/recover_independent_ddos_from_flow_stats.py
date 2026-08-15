"""
Recover empty/under-exported independent DDoS runs from flow_stats.csv
using timestamps in run_logs/*.json.

Does not overwrite flow_stats.csv.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect_independent_ddos_runs import filter_ddos_related  # noqa: E402

BASE_DIR = Path(__file__).resolve().parents[1]
FLOW_STATS = BASE_DIR / 'dataset' / 'flow_stats.csv'
RUNS_DIR = BASE_DIR / 'dataset' / 'independent_runs'
LOG_DIR = RUNS_DIR / 'run_logs'
MANIFEST = RUNS_DIR / 'manifest.csv'


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', default='', help='Comma-separated run_id prefix/ids')
    args = ap.parse_args()
    wanted = {x.strip() for x in args.only.split(',') if x.strip()}

    logs = sorted(LOG_DIR.glob('run_*.json'))
    if not logs:
        raise SystemExit('No run logs')

    print(f'[*] Reading {FLOW_STATS}')
    flows = pd.read_csv(FLOW_STATS, low_memory=False)
    flows['timestamp'] = pd.to_datetime(flows['timestamp'], errors='coerce')

    manifest = pd.read_csv(MANIFEST) if MANIFEST.exists() else pd.DataFrame()
    updated = 0
    for log_path in logs:
        meta = json.loads(log_path.read_text(encoding='utf-8'))
        scenario_id = str(meta.get('scenario_id', ''))
        if not scenario_id.startswith('ddos_'):
            continue
        run_id = meta['run_id']
        if wanted and run_id not in wanted and not any(run_id.startswith(w) for w in wanted):
            continue
        start = pd.to_datetime(meta['start_time'])
        end = pd.to_datetime(meta['end_time']) + pd.Timedelta(seconds=15)
        targets = set()
        for _, cmd in meta.get('commands', []):
            for tok in str(cmd).replace('&', '').split():
                if tok.count('.') == 3 and tok[0].isdigit():
                    targets.add(tok)
        part = flows[(flows['timestamp'] >= start) & (flows['timestamp'] <= end)].copy()
        part = filter_ddos_related(part, targets, require_packets=False)
        if part.empty:
            print(f'[skip] {run_id} still empty after recover')
            continue
        part['label'] = 'ddos'
        part['is_synthetic'] = 0
        part['source'] = 'independent_lab'
        part['run_id'] = run_id
        part['scenario_id'] = scenario_id
        out = RUNS_DIR / f'{run_id}.csv'
        part.to_csv(out, index=False)
        if not manifest.empty and 'run_id' in manifest.columns:
            manifest.loc[manifest['run_id'] == run_id, 'n_flows_exported'] = len(part)
        print(f'[recover] {run_id} -> {len(part)} rows | targets={sorted(targets)}')
        updated += 1

    if updated and not manifest.empty:
        manifest.to_csv(MANIFEST, index=False)
    print(f'[✓] Recovered {updated} DDoS runs')


if __name__ == '__main__':
    main()

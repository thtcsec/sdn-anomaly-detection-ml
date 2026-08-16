"""
Biểu đồ trực quan: random-flow (dễ = hay ra 1.0) vs GroupKFold theo run_id.

Không sửa model_comparison.csv. Ghi reports/split_vs_grouped_*.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

BASE = Path(__file__).resolve().parents[1]
REPORTS = BASE / 'reports'


def main() -> None:
    split = pd.read_csv(REPORTS / 'model_comparison.csv')
    grouped = pd.read_csv(REPORTS / 'grouped_real_only_summary.csv')

    rows = []
    for _, r in split.iterrows():
        name = str(r['Model']).replace(' ', '')
        if name == 'XGBoost':
            key = 'XGBoost'
        elif name == 'RandomForest':
            key = 'RandomForest'
        else:
            continue
        rows.append({
            'model': key,
            'protocol': 'Random-flow split (lab dễ tách)',
            'Accuracy': float(r['Accuracy']),
            'F1_macro': float(r['F1_macro']),
        })

    gmap = {
        'XGBoost': 'XGBoost',
        'RandomForest': 'RandomForest',
    }
    for _, r in grouped.iterrows():
        raw = str(r['model']).replace(' ', '')
        if raw not in gmap:
            continue
        rows.append({
            'model': gmap[raw],
            'protocol': 'GroupKFold theo run_id',
            'Accuracy': float(r['accuracy_mean']),
            'F1_macro': float(r['f1_macro_mean']),
        })

    out = pd.DataFrame(rows)
    out.to_csv(REPORTS / 'split_vs_grouped.csv', index=False)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for ax, metric in zip(axes, ['Accuracy', 'F1_macro']):
        pivot = out.pivot(index='model', columns='protocol', values=metric)
        pivot.plot(kind='bar', ax=ax, color=['#7f8c8d', '#c0392b'], rot=0)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel(metric)
        ax.set_title(metric)
        ax.legend(fontsize=8)
        ax.axhline(1.0, color='#bdc3c7', ls='--', lw=0.8)
    fig.suptitle('Lab random-flow dễ ra 1.0 — Grouped-by-run mới là số robustness')
    fig.tight_layout()
    fig.savefig(REPORTS / 'split_vs_grouped.png', dpi=160)
    print('[✓]', REPORTS / 'split_vs_grouped.png')


if __name__ == '__main__':
    main()

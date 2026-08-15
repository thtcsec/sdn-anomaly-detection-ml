"""Binary InSDN public supplementary eval. Does not touch lab models."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from provenance_schema import FEATURE_COLS

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / 'dataset' / 'public_benchmark' / 'insdn_binary'
OUT = BASE / 'reports' / 'public_benchmark' / 'insdn_binary'


def _metrics(y_true, y_pred) -> dict:
    return {
        'accuracy': round(float(accuracy_score(y_true, y_pred)), 4),
        'precision': round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        'recall': round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        'f1': round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    train = pd.read_csv(DATA / 'train.csv')
    test = pd.read_csv(DATA / 'test.csv')
    X_tr, y_tr = train[FEATURE_COLS], train['label'].astype(int)
    X_te, y_te = test[FEATURE_COLS], test['label'].astype(int)
    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    rows = []
    for name, model in [
        ('xgboost', XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            n_jobs=-1, random_state=42, eval_metric='logloss',
        )),
        ('random_forest', RandomForestClassifier(
            n_estimators=200, random_state=42, n_jobs=-1,
        )),
    ]:
        model.fit(X_tr_s, y_tr)
        pred = model.predict(X_te_s)
        rec = {'model': name, **_metrics(y_te, pred)}
        rows.append(rec)
        print(name, rec)

    pd.DataFrame(rows).to_csv(OUT / 'model_comparison.csv', index=False)
    note = {
        'dataset': 'insdn_binary',
        'rows_train': int(len(train)),
        'rows_test': int(len(test)),
        'labels': '0=normal, 1=anomaly',
        'note': 'SDN-domain public supplementary only. Binary mirror. Not controller train.',
        'results': rows,
    }
    (OUT / 'benchmark_note.json').write_text(json.dumps(note, indent=2), encoding='utf-8')
    print(f'[✓] {OUT}')


if __name__ == '__main__':
    main()

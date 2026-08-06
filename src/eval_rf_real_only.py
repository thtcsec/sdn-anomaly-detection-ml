"""
Đánh giá Random Forest trên tập REAL-ONLY (is_synthetic=0).

Mirror của eval_real_only.py (XGBoost) — NO SMOTE.
Tách biệt khỏi test.csv official (lab + bootstrap).

Chạy: python src/eval_rf_real_only.py
Output: reports/random_forest_real_only_metrics.csv
"""

from __future__ import annotations

import os
import sys

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
RAW_CSV = os.path.join(DATASET_DIR, 'flow_stats.csv')
OUT_CSV = os.path.join(REPORTS_DIR, 'random_forest_real_only_metrics.csv')

FEATURE_COLS = [
    'ip_proto', 'tp_src', 'tp_dst', 'packet_count', 'byte_count',
    'duration_sec', 'packet_count_per_sec', 'byte_count_per_sec',
    'packet_size_avg', 'flow_duration',
]


def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    if not os.path.exists(RAW_CSV):
        print(f'[!] Missing {RAW_CSV}')
        sys.exit(1)

    df = pd.read_csv(RAW_CSV)
    if 'is_synthetic' not in df.columns:
        print('[!] Missing is_synthetic — chạy mark_data_provenance.py trước')
        sys.exit(1)

    real = df[df['is_synthetic'].fillna(0).astype(int) == 0].copy()
    print('=' * 60)
    print('  REAL-ONLY RF EVALUATION (is_synthetic=0, NO SMOTE)')
    print('=' * 60)
    print('[*] Real label counts:')
    print(real['label'].value_counts().to_string())

    n_ddos = int((real['label'].astype(str).str.lower() == 'ddos').sum())
    n_normal = int((real['label'].astype(str).str.lower() == 'normal').sum())
    n_portscan = int((real['label'].astype(str).str.lower() == 'portscan').sum())
    print(f'[*] n_real={len(real)}  n_ddos_real={n_ddos}  n_normal_real={n_normal}  n_portscan_real={n_portscan}')

    real = real.dropna(subset=FEATURE_COLS + ['label']).drop_duplicates()
    X = real[FEATURE_COLS]
    y = real['label'].astype(str).str.lower()
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    print(f'[*] Classes: {dict(zip(le.classes_, le.transform(le.classes_)))}')

    counts = pd.Series(y_enc).value_counts()
    if counts.min() < 2:
        print('[!] Một lớp có <2 mẫu real — không đủ để split có ý nghĩa.')
        print('[!] Vẫn train trên toàn bộ real và báo metrics train (cảnh báo overfitting).')
        X_train, y_train = X, y_enc
        X_test, y_test = X, y_enc
        split_note = 'no_holdout_too_few_samples'
    else:
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
            )
            split_note = 'stratified_80_20'
        except ValueError:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_enc, test_size=0.2, random_state=42
            )
            split_note = 'random_80_20_no_stratify'

    print(f'[*] Split={split_note}  train={len(y_train)} test={len(y_test)}')
    print('[*] Test label counts:')
    print(pd.Series(y_test).value_counts().sort_index().to_string())
    print('[*] NO SMOTE on this check.')

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # Same RF hyperparams as train_random_forest.py
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced_subsample',
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_s, y_train)
    y_pred = model.predict(X_test_s)

    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
    f1_w = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec = recall_score(y_test, y_pred, average='macro', zero_division=0)

    print('\n' + classification_report(
        y_test, y_pred, target_names=list(le.classes_), digits=4, zero_division=0
    ))
    print(f'Accuracy={acc:.6f}  Precision_macro={prec:.6f}  Recall_macro={rec:.6f}')
    print(f'F1_macro={f1_macro:.6f}  F1_weighted={f1_w:.6f}')

    out = pd.DataFrame([
        {
            'setting': 'real_only_retrain_rf',
            'n_real_rows': len(real),
            'n_ddos_real': n_ddos,
            'n_normal_real': n_normal,
            'n_portscan_real': n_portscan,
            'split': split_note,
            'smote': False,
            'n_train': len(y_train),
            'n_test': len(y_test),
            'accuracy': acc,
            'precision_macro': prec,
            'recall_macro': rec,
            'f1_macro': f1_macro,
            'f1_weighted': f1_w,
        }
    ])
    out.to_csv(OUT_CSV, index=False)
    print(f'[✓] Saved {OUT_CSV}')


if __name__ == '__main__':
    main()

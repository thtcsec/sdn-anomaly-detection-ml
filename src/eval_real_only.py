"""
Đánh giá XGBoost trên tập REAL-ONLY (is_synthetic=0).

Cho thấy hiệu năng khi loại bỏ mẫu synthetic — số liệu trung thực để
đưa vào hạn chế / thảo luận bảo vệ.

Chạy: python src/eval_real_only.py
Output: reports/real_only_metrics.csv + in console
"""

from __future__ import annotations

import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
RAW_CSV = os.path.join(DATASET_DIR, 'flow_stats.csv')
OUT_CSV = os.path.join(REPORTS_DIR, 'real_only_metrics.csv')

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
    print('  REAL-ONLY EVALUATION (is_synthetic=0)')
    print('=' * 60)
    print('[*] Real label counts:')
    print(real['label'].value_counts().to_string())

    real = real.dropna(subset=FEATURE_COLS + ['label']).drop_duplicates()
    X = real[FEATURE_COLS]
    y = real['label'].astype(str).str.lower()
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    print(f'[*] Classes: {dict(zip(le.classes_, le.transform(le.classes_)))}')

    # Nếu DDoS real quá ít, stratify có thể fail
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

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='mlogloss',
    )
    model.fit(X_train_s, y_train)
    y_pred = model.predict(X_test_s)

    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
    f1_w = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec = recall_score(y_test, y_pred, average='macro', zero_division=0)

    print('\n' + classification_report(
        y_test, y_pred, target_names=list(le.classes_), zero_division=0
    ))
    print(f'Accuracy={acc:.4f}  F1_macro={f1_macro:.4f}  F1_weighted={f1_w:.4f}')
    print(f'Split={split_note}  train={len(y_train)} test={len(y_test)}')

    # So sánh nhanh với model đầy đủ (nếu có) trên real-only features
    full_model_path = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
    full_scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
    full_acc = np.nan
    if os.path.exists(full_model_path) and os.path.exists(full_scaler_path):
        full_model = joblib.load(full_model_path)
        full_scaler = joblib.load(full_scaler_path)
        # Dùng toàn bộ real làm probe (không phải test sạch hoàn toàn)
        X_all_s = full_scaler.transform(X)
        # Label encoder alphabetical khớp train full
        y_full = LabelEncoder().fit_transform(y)
        y_full_pred = full_model.predict(X_all_s)
        full_acc = accuracy_score(y_full, y_full_pred)
        print(f'[*] Full pipeline model accuracy on ALL real rows: {full_acc:.4f}')

    out = pd.DataFrame([
        {
            'setting': 'real_only_retrain',
            'n_real_rows': len(real),
            'n_ddos_real': int((y == 'ddos').sum()),
            'n_normal_real': int((y == 'normal').sum()),
            'n_portscan_real': int((y == 'portscan').sum()),
            'split': split_note,
            'accuracy': acc,
            'precision_macro': prec,
            'recall_macro': rec,
            'f1_macro': f1_macro,
            'f1_weighted': f1_w,
            'full_model_acc_on_real': full_acc,
        }
    ])
    out.to_csv(OUT_CSV, index=False)
    print(f'[✓] Saved {OUT_CSV}')


if __name__ == '__main__':
    main()

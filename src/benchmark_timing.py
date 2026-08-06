"""
Benchmark thời gian train/inference cho các mô hình (phục vụ bảng khóa luận).

Chạy: python src/benchmark_timing.py
Output: reports/model_timing.csv
"""

import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')


def latency_ms(predict_fn, n=1000):
    predict_fn()  # warmup
    t0 = time.perf_counter()
    for _ in range(n):
        predict_fn()
    return (time.perf_counter() - t0) * 1000.0 / n


def main():
    train_df = pd.read_csv(os.path.join(DATASET_DIR, 'train.csv'))
    test_df = pd.read_csv(os.path.join(DATASET_DIR, 'test.csv'))
    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    rows = []

    # --- XGBoost (retrain timed; reuse saved if prefer loaded predict) ---
    scaler = StandardScaler()
    Xtr = scaler.fit_transform(X_train)
    Xte = scaler.transform(X_test)
    xgb = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        use_label_encoder=False, eval_metric='mlogloss',
    )
    t0 = time.perf_counter()
    xgb.fit(Xtr, y_train)
    xgb_train = time.perf_counter() - t0
    sample = Xte[:1]
    xgb_inf = latency_ms(lambda: xgb.predict(sample))
    rows.append({'Model': 'XGBoost', 'Train_Time_sec': xgb_train, 'Inference_ms': xgb_inf})

    # --- Random Forest ---
    rf_path = os.path.join(MODELS_DIR, 'random_forest_model.pkl')
    rf_scaler_path = os.path.join(MODELS_DIR, 'random_forest_scaler.pkl')
    if os.path.exists(rf_path):
        rf = joblib.load(rf_path)
        rf_scaler = joblib.load(rf_scaler_path)
        Xte_rf = rf_scaler.transform(X_test)
        # train time from metrics csv if available
        metrics_path = os.path.join(REPORTS_DIR, 'random_forest_metrics.csv')
        if os.path.exists(metrics_path):
            rf_train = float(pd.read_csv(metrics_path).iloc[0]['Train_Time_sec'])
        else:
            rf_train = float('nan')
        rf_inf = latency_ms(lambda: rf.predict(Xte_rf[:1]))
        rows.append({'Model': 'Random Forest', 'Train_Time_sec': rf_train, 'Inference_ms': rf_inf})

    # --- Isolation Forest (load) ---
    if_path = os.path.join(MODELS_DIR, 'isolation_forest_model.pkl')
    if_scaler_path = os.path.join(MODELS_DIR, 'isolation_forest_scaler.pkl')
    if os.path.exists(if_path):
        iff = joblib.load(if_path)
        if_scaler = joblib.load(if_scaler_path)
        Xte_if = if_scaler.transform(X_test)
        t0 = time.perf_counter()
        # approximate retrain timing for table
        tmp = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
        # train on normal-ish: use all train scaled like existing pipeline
        Xtr_if = if_scaler.transform(X_train)
        tmp.fit(Xtr_if)
        if_train = time.perf_counter() - t0
        if_inf = latency_ms(lambda: iff.predict(Xte_if[:1]))
        rows.append({'Model': 'Isolation Forest', 'Train_Time_sec': if_train, 'Inference_ms': if_inf})

    # --- Autoencoder (load predict only; train time from optional env) ---
    ae_path = os.path.join(MODELS_DIR, 'autoencoder_model.keras')
    ae_scaler_path = os.path.join(MODELS_DIR, 'autoencoder_scaler.pkl')
    if os.path.exists(ae_path):
        try:
            from tensorflow import keras
        except Exception:
            import tf_keras as keras
        ae = keras.models.load_model(ae_path)
        ae_scaler = joblib.load(ae_scaler_path)
        Xte_ae = ae_scaler.transform(X_test)[:1]

        def ae_predict():
            ae.predict(Xte_ae, verbose=0)

        ae_inf = latency_ms(ae_predict, n=100)
        rows.append({'Model': 'Autoencoder', 'Train_Time_sec': float('nan'), 'Inference_ms': ae_inf})

    df = pd.DataFrame(rows)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    out = os.path.join(REPORTS_DIR, 'model_timing.csv')
    df.to_csv(out, index=False)
    print(df.to_string(index=False))
    print(f'\n[✓] Saved: {out}')


if __name__ == '__main__':
    main()

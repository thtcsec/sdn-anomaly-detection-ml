"""
Train and evaluate the public CICIDS2017 3-class benchmark.

This script intentionally does NOT overwrite the legacy lab benchmark outputs.
It writes all artifacts to dataset/models/reports public_benchmark subfolders.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import warnings
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from provenance_schema import FEATURE_COLS


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_BENCHMARK_DIR = BASE_DIR / 'dataset' / 'public_benchmark' / 'cicids2017_3class'
DEFAULT_MODELS_DIR = BASE_DIR / 'models' / 'public_benchmark' / 'cicids2017_3class'
DEFAULT_REPORTS_DIR = BASE_DIR / 'reports' / 'public_benchmark' / 'cicids2017_3class'
LABEL_NAMES = ['ddos', 'normal', 'portscan']
NORMAL_LABEL = 1

np.random.seed(42)


def _ensure_dirs(*paths: Path) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def _load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f'Missing required benchmark file: {path}')
    return pd.read_csv(path)


def load_benchmark(dataset_dir: Path) -> dict[str, pd.DataFrame]:
    return {
        'train': _load_csv(dataset_dir / 'train.csv'),
        'test': _load_csv(dataset_dir / 'test.csv'),
        'train_raw': _load_csv(dataset_dir / 'train_raw.csv'),
        'test_raw': _load_csv(dataset_dir / 'test_raw.csv'),
        'flow_stats': _load_csv(dataset_dir / 'flow_stats.csv'),
        'dataset_summary': _load_csv(dataset_dir / 'dataset_summary.csv'),
    }


def _save_confusion_matrix(
    cm: np.ndarray,
    labels: list[str],
    title: str,
    out_path: Path,
    cmap: str = 'Blues',
) -> None:
    plt.figure(figsize=(7, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap=cmap, xticklabels=labels, yticklabels=labels)
    plt.title(title)
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def _cap_balanced_train(train_df: pd.DataFrame, max_per_class: int | None) -> pd.DataFrame:
    if not max_per_class or max_per_class <= 0:
        return train_df

    parts = []
    for label, part in train_df.groupby('label', sort=True):
        if len(part) > max_per_class:
            part = part.sample(n=max_per_class, random_state=42)
        parts.append(part)
    capped = pd.concat(parts, ignore_index=True)
    return capped.sample(frac=1.0, random_state=42).reset_index(drop=True)


def _cap_normal_train(train_raw_df: pd.DataFrame, max_normal_rows: int | None) -> pd.DataFrame:
    normals = train_raw_df.loc[train_raw_df['label'] == NORMAL_LABEL].copy()
    if max_normal_rows and max_normal_rows > 0 and len(normals) > max_normal_rows:
        normals = normals.sample(n=max_normal_rows, random_state=42)
    return normals.reset_index(drop=True)


def _train_xgb(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    models_dir: Path,
    reports_dir: Path,
    max_per_class: int | None,
):
    train_df = _cap_balanced_train(train_df, max_per_class)
    X_train = train_df[FEATURE_COLS]
    y_train = train_df['label']
    X_test = test_df[FEATURE_COLS]
    y_test = test_df['label']

    scaler = StandardScaler()
    X_train_s = pd.DataFrame(scaler.fit_transform(X_train), columns=FEATURE_COLS)
    X_test_s = pd.DataFrame(scaler.transform(X_test), columns=FEATURE_COLS)

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='mlogloss',
        use_label_encoder=False,
        tree_method='hist',
        n_jobs=0,
    )

    t0 = time.perf_counter()
    model.fit(X_train_s, y_train, verbose=False)
    train_sec = time.perf_counter() - t0

    t1 = time.perf_counter()
    y_pred = model.predict(X_test_s)
    predict_test_sec = time.perf_counter() - t1

    sample = X_test_s.iloc[:1]
    model.predict(sample)
    t2 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        model.predict(sample)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec = recall_score(y_test, y_pred, average='macro', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)

    cm = confusion_matrix(y_test, y_pred)
    _save_confusion_matrix(
        cm,
        LABEL_NAMES,
        'Confusion Matrix - XGBoost (CICIDS2017)',
        reports_dir / 'confusion_matrix_xgboost.png',
    )

    plt.figure(figsize=(10, 6))
    importance = model.feature_importances_
    order = np.argsort(importance)[::-1]
    plt.bar(range(len(importance)), importance[order], align='center')
    plt.xticks(range(len(importance)), [FEATURE_COLS[i] for i in order], rotation=45, ha='right')
    plt.title('Feature Importance - XGBoost (CICIDS2017)')
    plt.tight_layout()
    plt.savefig(reports_dir / 'feature_importance_xgboost.png', dpi=150)
    plt.close()

    joblib.dump(model, models_dir / 'xgboost_model.pkl')
    joblib.dump(scaler, models_dir / 'xgboost_scaler.pkl')

    metrics = {
        'Model': 'XGBoost',
        'Approach': 'Supervised',
        'Classification': 'Multiclass',
        'MetricScope': 'macro_multiclass',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1,
        'Train_Time_sec': train_sec,
        'Predict_Test_sec': predict_test_sec,
        'Inference_ms_per_sample': infer_ms,
    }
    pd.DataFrame([metrics]).to_csv(reports_dir / 'xgboost_metrics.csv', index=False)
    pd.DataFrame(classification_report(
        y_test, y_pred, target_names=LABEL_NAMES, output_dict=True, zero_division=0
    )).transpose().to_csv(reports_dir / 'xgboost_classification_report.csv')
    return metrics


def _train_rf(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    models_dir: Path,
    reports_dir: Path,
    max_per_class: int | None,
):
    train_df = _cap_balanced_train(train_df, max_per_class)
    X_train = train_df[FEATURE_COLS]
    y_train = train_df['label']
    X_test = test_df[FEATURE_COLS]
    y_test = test_df['label']

    scaler = StandardScaler()
    X_train_s = pd.DataFrame(scaler.fit_transform(X_train), columns=FEATURE_COLS)
    X_test_s = pd.DataFrame(scaler.transform(X_test), columns=FEATURE_COLS)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced_subsample',
        random_state=42,
        n_jobs=-1,
    )

    t0 = time.perf_counter()
    model.fit(X_train_s, y_train)
    train_sec = time.perf_counter() - t0

    t1 = time.perf_counter()
    y_pred = model.predict(X_test_s)
    predict_test_sec = time.perf_counter() - t1

    sample = X_test_s.iloc[:1]
    model.predict(sample)
    t2 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        model.predict(sample)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec = recall_score(y_test, y_pred, average='macro', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)

    cm = confusion_matrix(y_test, y_pred)
    _save_confusion_matrix(
        cm,
        LABEL_NAMES,
        'Confusion Matrix - Random Forest (CICIDS2017)',
        reports_dir / 'confusion_matrix_random_forest.png',
    )

    plt.figure(figsize=(10, 6))
    importance = model.feature_importances_
    order = np.argsort(importance)[::-1]
    plt.bar(range(len(importance)), importance[order], align='center')
    plt.xticks(range(len(importance)), [FEATURE_COLS[i] for i in order], rotation=45, ha='right')
    plt.title('Feature Importance - Random Forest (CICIDS2017)')
    plt.tight_layout()
    plt.savefig(reports_dir / 'feature_importance_random_forest.png', dpi=150)
    plt.close()

    joblib.dump(model, models_dir / 'random_forest_model.pkl')
    joblib.dump(scaler, models_dir / 'random_forest_scaler.pkl')

    metrics = {
        'Model': 'Random Forest',
        'Approach': 'Supervised',
        'Classification': 'Multiclass',
        'MetricScope': 'macro_multiclass',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1,
        'Train_Time_sec': train_sec,
        'Predict_Test_sec': predict_test_sec,
        'Inference_ms_per_sample': infer_ms,
    }
    pd.DataFrame([metrics]).to_csv(reports_dir / 'random_forest_metrics.csv', index=False)
    pd.DataFrame(classification_report(
        y_test, y_pred, target_names=LABEL_NAMES, output_dict=True, zero_division=0
    )).transpose().to_csv(reports_dir / 'random_forest_classification_report.csv')
    return metrics


def _train_if(
    train_raw_df: pd.DataFrame,
    test_raw_df: pd.DataFrame,
    models_dir: Path,
    reports_dir: Path,
    max_normal_rows: int | None,
):
    X_train_normal = _cap_normal_train(train_raw_df, max_normal_rows)[FEATURE_COLS]
    X_test = test_raw_df[FEATURE_COLS]
    y_test = test_raw_df['label']

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train_normal)
    X_test_s = scaler.transform(X_test)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_samples='auto',
        random_state=42,
        n_jobs=-1,
    )

    t0 = time.perf_counter()
    model.fit(X_train_s)
    train_sec = time.perf_counter() - t0

    t1 = time.perf_counter()
    y_pred_raw = model.predict(X_test_s)
    predict_test_sec = time.perf_counter() - t1

    sample = X_test_s[:1]
    model.predict(sample)
    t2 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        model.predict(sample)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    y_pred_bin = (y_pred_raw == -1).astype(int)
    y_test_bin = (y_test != NORMAL_LABEL).astype(int)

    acc = accuracy_score(y_test_bin, y_pred_bin)
    prec = precision_score(y_test_bin, y_pred_bin, zero_division=0)
    rec = recall_score(y_test_bin, y_pred_bin, zero_division=0)
    f1 = f1_score(y_test_bin, y_pred_bin, zero_division=0)

    cm = confusion_matrix(y_test_bin, y_pred_bin)
    _save_confusion_matrix(
        cm,
        ['Normal', 'Anomaly'],
        'Confusion Matrix - Isolation Forest (CICIDS2017)',
        reports_dir / 'confusion_matrix_isolation_forest.png',
        cmap='Greens',
    )

    joblib.dump(model, models_dir / 'isolation_forest_model.pkl')
    joblib.dump(scaler, models_dir / 'isolation_forest_scaler.pkl')

    metrics = {
        'Model': 'Isolation Forest',
        'Approach': 'Unsupervised',
        'Classification': 'Binary',
        'MetricScope': 'anomaly_class_binary',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1,
        'Train_Time_sec': train_sec,
        'Predict_Test_sec': predict_test_sec,
        'Inference_ms_per_sample': infer_ms,
    }
    pd.DataFrame([metrics]).to_csv(reports_dir / 'isolation_forest_metrics.csv', index=False)
    return metrics


def _train_ae(
    train_raw_df: pd.DataFrame,
    test_raw_df: pd.DataFrame,
    models_dir: Path,
    reports_dir: Path,
    max_normal_rows: int | None,
):
    try:
        os.environ.setdefault('TF_USE_LEGACY_KERAS', '1')
        import tensorflow as tf
        try:
            from tensorflow import keras
        except Exception:
            import tf_keras as keras  # type: ignore
    except Exception as exc:
        raise SystemExit('TensorFlow/tf_keras is required for Autoencoder benchmark.') from exc

    tf.random.set_seed(42)

    X_train_normal = _cap_normal_train(train_raw_df, max_normal_rows)[FEATURE_COLS]
    X_test = test_raw_df[FEATURE_COLS]
    y_test = test_raw_df['label']

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train_normal)
    X_test_s = scaler.transform(X_test)

    input_dim = X_train_s.shape[1]
    model = keras.Sequential([
        keras.layers.Input(shape=(input_dim,)),
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(6, activation='relu'),
        keras.layers.Dense(4, activation='relu'),
        keras.layers.Dense(6, activation='relu'),
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(input_dim, activation='linear'),
    ])
    model.compile(optimizer='adam', loss='mse')

    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=5,
        restore_best_weights=True,
    )

    t0 = time.perf_counter()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        history = model.fit(
            X_train_s,
            X_train_s,
            epochs=40,
            batch_size=1024,
            validation_split=0.1,
            callbacks=[early_stop],
            verbose=0,
        )
    train_sec = time.perf_counter() - t0

    recon_train = model.predict(X_train_s, verbose=0)
    mse_train = np.mean(np.power(X_train_s - recon_train, 2), axis=1)
    threshold = float(np.percentile(mse_train, 95))

    t1 = time.perf_counter()
    recon_test = model.predict(X_test_s, verbose=0)
    predict_test_sec = time.perf_counter() - t1
    mse_test = np.mean(np.power(X_test_s - recon_test, 2), axis=1)

    sample = X_test_s[:1]
    model.predict(sample, verbose=0)
    t2 = time.perf_counter()
    n_runs = 500
    for _ in range(n_runs):
        model.predict(sample, verbose=0)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    y_test_bin = (y_test != NORMAL_LABEL).astype(int)
    y_pred_bin = (mse_test > threshold).astype(int)

    acc = accuracy_score(y_test_bin, y_pred_bin)
    prec = precision_score(y_test_bin, y_pred_bin, zero_division=0)
    rec = recall_score(y_test_bin, y_pred_bin, zero_division=0)
    f1 = f1_score(y_test_bin, y_pred_bin, zero_division=0)

    cm = confusion_matrix(y_test_bin, y_pred_bin)
    _save_confusion_matrix(
        cm,
        ['Normal', 'Anomaly'],
        'Confusion Matrix - Autoencoder (CICIDS2017)',
        reports_dir / 'confusion_matrix_autoencoder.png',
        cmap='Oranges',
    )

    plt.figure(figsize=(8, 5))
    plt.plot(history.history['loss'], label='Train Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.title('Autoencoder Training Loss (CICIDS2017)')
    plt.xlabel('Epoch')
    plt.ylabel('MSE')
    plt.legend()
    plt.tight_layout()
    plt.savefig(reports_dir / 'autoencoder_loss.png', dpi=150)
    plt.close()

    joblib.dump(scaler, models_dir / 'autoencoder_scaler.pkl')
    joblib.dump({'threshold': threshold}, models_dir / 'autoencoder_threshold.pkl')
    model.save(models_dir / 'autoencoder_model.keras')

    metrics = {
        'Model': 'Autoencoder',
        'Approach': 'Unsupervised',
        'Classification': 'Binary',
        'MetricScope': 'anomaly_class_binary',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1,
        'Train_Time_sec': train_sec,
        'Predict_Test_sec': predict_test_sec,
        'Inference_ms_per_sample': infer_ms,
        'Threshold': threshold,
    }
    pd.DataFrame([metrics]).to_csv(reports_dir / 'autoencoder_metrics.csv', index=False)
    return metrics


def _save_comparison(
    results: list[dict],
    reports_dir: Path,
    dataset_summary: pd.DataFrame,
    max_train_per_class: int | None,
    max_normal_train: int | None,
) -> None:
    comparison = pd.DataFrame(results)
    comparison.to_csv(reports_dir / 'model_comparison.csv', index=False)

    timing = comparison[['Model', 'Train_Time_sec', 'Inference_ms_per_sample']].copy()
    timing.columns = ['Model', 'Train_Time_sec', 'Inference_ms']
    timing.to_csv(reports_dir / 'model_timing.csv', index=False)

    benchmark_note = {
        'dataset': 'cicids2017_3class',
        'source': 'cicids2017_public',
        'rows_flow_stats': int(dataset_summary.loc[0, 'rows_raw']),
        'rows_train_after_smote': int(dataset_summary.loc[0, 'rows_train_after_smote']),
        'rows_test': int(dataset_summary.loc[0, 'rows_test']),
        'split_protocol': str(dataset_summary.loc[0, 'split_protocol']),
        'split_note': str(dataset_summary.loc[0, 'split_note']),
        'missing_public_cols_strategy': str(dataset_summary.loc[0, 'missing_public_cols_strategy']),
        'supervised_train_cap_per_class': max_train_per_class,
        'unsupervised_normal_train_cap': max_normal_train,
    }
    with open(reports_dir / 'benchmark_note.json', 'w', encoding='utf-8') as fh:
        json.dump(benchmark_note, fh, indent=2, ensure_ascii=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset-dir', default=str(DEFAULT_BENCHMARK_DIR))
    ap.add_argument('--models-dir', default=str(DEFAULT_MODELS_DIR))
    ap.add_argument('--reports-dir', default=str(DEFAULT_REPORTS_DIR))
    ap.add_argument(
        '--max-train-per-class',
        type=int,
        default=100_000,
        help='Cap each supervised train class after SMOTE for practical runtime.',
    )
    ap.add_argument(
        '--max-normal-train',
        type=int,
        default=100_000,
        help='Cap normal-only training rows for IF/AE runtime control.',
    )
    args = ap.parse_args()

    dataset_dir = Path(args.dataset_dir)
    models_dir = Path(args.models_dir)
    reports_dir = Path(args.reports_dir)
    _ensure_dirs(models_dir, reports_dir)

    print('=' * 60)
    print('  PUBLIC BENCHMARK - CICIDS2017 3-CLASS')
    print('=' * 60)
    print(f'[*] Dataset dir: {dataset_dir}')
    print(f'[*] Models dir:  {models_dir}')
    print(f'[*] Reports dir: {reports_dir}')

    data = load_benchmark(dataset_dir)
    print(f'[*] train.csv shape: {data["train"].shape}')
    print(f'[*] test.csv shape: {data["test"].shape}')
    print(f'[*] train_raw.csv shape: {data["train_raw"].shape}')
    print(f'[*] test_raw.csv shape: {data["test_raw"].shape}')
    print(f'[*] supervised cap/class: {args.max_train_per_class}')
    print(f'[*] unsupervised normal cap: {args.max_normal_train}')

    results = []
    print('[*] Training XGBoost...')
    results.append(
        _train_xgb(data['train'], data['test'], models_dir, reports_dir, args.max_train_per_class)
    )
    print('[*] Training Random Forest...')
    results.append(
        _train_rf(data['train'], data['test'], models_dir, reports_dir, args.max_train_per_class)
    )
    print('[*] Training Isolation Forest...')
    results.append(
        _train_if(data['train_raw'], data['test_raw'], models_dir, reports_dir, args.max_normal_train)
    )
    print('[*] Training Autoencoder...')
    results.append(
        _train_ae(data['train_raw'], data['test_raw'], models_dir, reports_dir, args.max_normal_train)
    )

    _save_comparison(
        results,
        reports_dir,
        data['dataset_summary'],
        args.max_train_per_class,
        args.max_normal_train,
    )
    print('\n[✓] Public benchmark completed.')
    print(f'[✓] See: {reports_dir / "model_comparison.csv"}')


if __name__ == '__main__':
    main()

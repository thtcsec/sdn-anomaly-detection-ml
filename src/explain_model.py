"""
Giải thích mô hình XGBoost bằng SHAP (Shapley Additive exPlanations).

Input:
  - models/xgboost_model.pkl
  - models/scaler.pkl
  - dataset/test.csv

Output:
  - reports/shap_summary.png
  - reports/shap_bar.png
"""

import os
import sys

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

TEST_CSV = os.path.join(DATASET_DIR, 'test.csv')
MODEL_PATH = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.pkl')

# Giới hạn mẫu để SHAP chạy nhanh nhưng vẫn ổn định
MAX_SAMPLES = 500
RANDOM_STATE = 42
CLASS_NAMES = ['ddos', 'normal', 'portscan']


def load_artifacts():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        print('[!] Model/scaler not found. Run src/train_model.py first.')
        sys.exit(1)
    if not os.path.exists(TEST_CSV):
        print('[!] test.csv not found. Run src/preprocess.py first.')
        sys.exit(1)

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    test_df = pd.read_csv(TEST_CSV)

    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']
    feature_names = list(X_test.columns)

    X_scaled = pd.DataFrame(
        scaler.transform(X_test),
        columns=feature_names,
    )
    return model, X_scaled, y_test, feature_names


def sample_for_shap(X_scaled, y_test):
    n = min(MAX_SAMPLES, len(X_scaled))
    idx = (
        X_scaled.sample(n=n, random_state=RANDOM_STATE).index
        if n < len(X_scaled)
        else X_scaled.index
    )
    return X_scaled.loc[idx], y_test.loc[idx]


def compute_shap(model, X_sample):
    print(f'[*] Computing SHAP values on {len(X_sample)} samples...')
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)
    return explainer, shap_values


def _to_list_of_arrays(shap_values, n_classes):
    """Chuẩn hoá shap_values về list[ndarray] shape (n_samples, n_features)."""
    if isinstance(shap_values, list):
        return shap_values
    arr = np.asarray(shap_values)
    if arr.ndim == 3:
        # (n_samples, n_features, n_classes) hoặc (n_classes, n_samples, n_features)
        if arr.shape[-1] == n_classes:
            return [arr[:, :, i] for i in range(n_classes)]
        if arr.shape[0] == n_classes:
            return [arr[i] for i in range(n_classes)]
    if arr.ndim == 2:
        return [arr]
    raise ValueError(f'Unsupported shap_values shape: {arr.shape}')


def plot_summary(shap_values, X_sample, feature_names, n_classes):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    values = _to_list_of_arrays(shap_values, n_classes)

    # Summary beeswarm dùng mean |SHAP| đa lớp: lấy trung bình tuyệt đối qua các class
    mean_abs = np.mean([np.abs(v) for v in values], axis=0)

    plt.figure(figsize=(10, 7))
    shap.summary_plot(
        mean_abs,
        X_sample.values,
        feature_names=feature_names,
        plot_type='bar',
        show=False,
        max_display=10,
    )
    plt.title('SHAP Mean |value| (avg over classes) - XGBoost')
    plt.tight_layout()
    bar_path = os.path.join(REPORTS_DIR, 'shap_bar.png')
    plt.savefig(bar_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[✓] Saved: {bar_path}')

    # Beeswarm theo class có nhiều mẫu nhất trên test sample (thường portscan),
    # kèm summary đa lớp bằng cách plot class DDoS (class 0) — quan trọng với đề tài.
    for class_idx, class_name in enumerate(CLASS_NAMES[: len(values)]):
        plt.figure(figsize=(10, 7))
        shap.summary_plot(
            values[class_idx],
            X_sample.values,
            feature_names=feature_names,
            show=False,
            max_display=10,
        )
        plt.title(f'SHAP Summary - class "{class_name}"')
        plt.tight_layout()
        out = os.path.join(REPORTS_DIR, f'shap_summary_{class_name}.png')
        plt.savefig(out, dpi=150, bbox_inches='tight')
        plt.close()
        print(f'[✓] Saved: {out}')

    # File chính dùng cho khóa luận: beeswarm của lớp DDoS (class 0)
    plt.figure(figsize=(10, 7))
    shap.summary_plot(
        values[0],
        X_sample.values,
        feature_names=feature_names,
        show=False,
        max_display=10,
    )
    plt.title('SHAP Feature Importance Summary - XGBoost (class: ddos)')
    plt.tight_layout()
    summary_path = os.path.join(REPORTS_DIR, 'shap_summary.png')
    plt.savefig(summary_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[✓] Saved: {summary_path}')

    return values


def print_top_features(values, feature_names):
    mean_abs = np.mean([np.abs(v) for v in values], axis=0)
    importance = mean_abs.mean(axis=0)
    order = np.argsort(importance)[::-1]
    print('\nTop features by mean |SHAP| (avg over classes):')
    for rank, idx in enumerate(order[:10], start=1):
        print(f'  {rank:2d}. {feature_names[idx]:24s}  {importance[idx]:.6f}')


def main():
    print('=' * 60)
    print('  SHAP Explanation - SDN XGBoost')
    print('=' * 60)

    model, X_scaled, y_test, feature_names = load_artifacts()
    X_sample, _ = sample_for_shap(X_scaled, y_test)
    _, shap_values = compute_shap(model, X_sample)
    n_classes = len(CLASS_NAMES)
    values = plot_summary(shap_values, X_sample, feature_names, n_classes)
    print_top_features(values, feature_names)
    print('\n[✓] SHAP explanation complete!')


if __name__ == '__main__':
    main()

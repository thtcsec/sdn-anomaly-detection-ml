"""
Huấn luyện Random Forest (supervised multiclass) để so sánh với XGBoost.

Input:  dataset/train.csv, dataset/test.csv
Output:
  models/random_forest_model.pkl
  models/random_forest_scaler.pkl
  reports/random_forest_metrics.csv
  reports/random_forest_classification_report.csv
  reports/random_forest_confusion_matrix.csv
  reports/confusion_matrix_random_forest.png
  reports/feature_importance_random_forest.png

Chạy: python src/train_random_forest.py

Lưu ý: StandardScaler được áp dụng để đồng nhất preprocessing giữa các
mô hình, mặc dù Random Forest (tree-based) không yêu cầu chuẩn hóa
đặc trưng do dựa trên decision tree splits, không dựa trên khoảng cách.
"""

import os
import sys
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

# Reproducibility
np.random.seed(42)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

TRAIN_CSV = os.path.join(DATASET_DIR, 'train.csv')
TEST_CSV = os.path.join(DATASET_DIR, 'test.csv')
LABEL_NAMES = ['ddos', 'normal', 'portscan']


def load_train_test():
    if not os.path.exists(TRAIN_CSV) or not os.path.exists(TEST_CSV):
        print('[!] Train/Test files not found. Run preprocess.py first.')
        sys.exit(1)

    train_df = pd.read_csv(TRAIN_CSV)
    test_df = pd.read_csv(TEST_CSV)
    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']
    print(f'[*] Train: {X_train.shape}, Test: {X_test.shape}')
    # Chứng minh lý do dùng class_weight='balanced_subsample'
    print(f'[*] Train label distribution:\n{y_train.value_counts()}')
    return X_train, X_test, y_train, y_test


def main():
    print('=' * 60)
    print('  Random Forest Training - SDN Anomaly Detection')
    print('=' * 60)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    X_train, X_test, y_train, y_test = load_train_test()

    # StandardScaler để đồng nhất pipeline với XGBoost (RF không cần scaling)
    scaler = StandardScaler()
    X_train_s = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns)
    X_test_s = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced_subsample',
        random_state=42,
        n_jobs=-1,
        oob_score=True,  # Out-of-Bag score — metric hữu ích cho báo cáo
    )

    # Train + timing
    t0 = time.perf_counter()
    model.fit(X_train_s, y_train)
    train_sec = time.perf_counter() - t0

    print(f'[*] OOB Score: {model.oob_score_:.6f}')

    # Predict batch
    t1 = time.perf_counter()
    y_pred = model.predict(X_test_s)
    predict_batch_sec = time.perf_counter() - t1

    # Inference latency: numpy array để tránh Pandas overhead
    sample_np = X_test_s.iloc[:1].values
    model.predict(sample_np)  # warmup
    t2 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        model.predict(sample_np)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec = recall_score(y_test, y_pred, average='macro', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    # ROC-AUC multiclass (One-vs-Rest)
    y_prob = model.predict_proba(X_test_s)
    auc_macro = roc_auc_score(y_test, y_prob, multi_class='ovr', average='macro')

    print('\n' + '=' * 60)
    print('  RANDOM FOREST RESULTS')
    print('=' * 60)
    print(f'  Accuracy:          {acc:.6f}')
    print(f'  Precision (macro): {prec:.6f}')
    print(f'  Recall (macro):    {rec:.6f}')
    print(f'  F1-Score (macro):  {f1:.6f}')
    print(f'  F1-Score (weighted): {f1_weighted:.6f}')
    print(f'  ROC-AUC (macro):   {auc_macro:.6f}')
    print(f'  OOB Score:         {model.oob_score_:.6f}')
    print(f'  Train time:        {train_sec:.3f}s')
    print(f'  Predict (test):    {predict_batch_sec:.3f}s')
    print(f'  Inference/sample:  {infer_ms:.3f} ms')
    print('=' * 60)
    print('\nClassification Report:')
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES, digits=4))

    # Confusion matrix — PNG + CSV
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=LABEL_NAMES, yticklabels=LABEL_NAMES)
    plt.title('Confusion Matrix - Random Forest')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    cm_png = os.path.join(REPORTS_DIR, 'confusion_matrix_random_forest.png')
    plt.savefig(cm_png, dpi=150)
    plt.close()
    print(f'[✓] Saved: {cm_png}')

    cm_csv = os.path.join(REPORTS_DIR, 'random_forest_confusion_matrix.csv')
    pd.DataFrame(cm, index=LABEL_NAMES, columns=LABEL_NAMES).to_csv(cm_csv)
    print(f'[✓] Saved: {cm_csv}')

    # Feature importance — MDI (Mean Decrease Impurity), top 20
    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1]
    top_n = min(20, len(importance))
    top_indices = indices[:top_n]

    plt.figure(figsize=(10, 6))
    plt.title('Feature Importance (MDI) - Random Forest')
    plt.bar(range(top_n), importance[top_indices], align='center')
    plt.xticks(
        range(top_n),
        [X_train.columns[i] for i in top_indices],
        rotation=45, ha='right',
    )
    plt.xlabel('Features')
    plt.ylabel('Importance (Mean Decrease Impurity)')
    plt.tight_layout()
    fi_path = os.path.join(REPORTS_DIR, 'feature_importance_random_forest.png')
    plt.savefig(fi_path, dpi=150)
    plt.close()
    print(f'[✓] Saved: {fi_path}')

    # Permutation importance (more reliable, less biased than MDI)
    try:
        from sklearn.inspection import permutation_importance
        print('[*] Computing permutation importance (10 repeats)...')
        perm = permutation_importance(
            model, X_test_s, y_test, n_repeats=10, random_state=42, n_jobs=-1
        )
        perm_indices = np.argsort(perm.importances_mean)[::-1][:top_n]
        plt.figure(figsize=(10, 6))
        plt.title('Permutation Importance - Random Forest')
        plt.bar(range(len(perm_indices)), perm.importances_mean[perm_indices], align='center',
                yerr=perm.importances_std[perm_indices])
        plt.xticks(range(len(perm_indices)),
                   [X_train.columns[i] for i in perm_indices], rotation=45, ha='right')
        plt.xlabel('Features')
        plt.ylabel('Mean Accuracy Decrease')
        plt.tight_layout()
        perm_path = os.path.join(REPORTS_DIR, 'permutation_importance_random_forest.png')
        plt.savefig(perm_path, dpi=150)
        plt.close()
        print(f'[✓] Saved: {perm_path}')
    except Exception as e:
        print(f'[!] Permutation importance skipped: {e}')

    # Metrics CSV
    metrics = {
        'Model': 'Random Forest',
        'Approach': 'Supervised',
        'Classification': 'Multiclass',
        'Accuracy': acc,
        'Precision_macro': prec,
        'Recall_macro': rec,
        'F1_macro': f1,
        'F1_weighted': f1_weighted,
        'AUC_macro': auc_macro,
        'OOB_Score': model.oob_score_,
        'Train_Time_sec': train_sec,
        'Predict_Test_sec': predict_batch_sec,
        'Inference_ms_per_sample': infer_ms,
    }
    pd.DataFrame([metrics]).to_csv(
        os.path.join(REPORTS_DIR, 'random_forest_metrics.csv'), index=False
    )
    print(f'[✓] Saved: reports/random_forest_metrics.csv')

    # Per-class report CSV for Word/LaTeX
    report_dict = classification_report(
        y_test, y_pred, target_names=LABEL_NAMES, digits=4, output_dict=True
    )
    rows = []
    for cls in LABEL_NAMES:
        rows.append({
            'Class': cls,
            'Precision': report_dict[cls]['precision'],
            'Recall': report_dict[cls]['recall'],
            'F1-Score': report_dict[cls]['f1-score'],
            'Support': int(report_dict[cls]['support']),
        })
    pd.DataFrame(rows).to_csv(
        os.path.join(REPORTS_DIR, 'random_forest_classification_report.csv'),
        index=False,
    )
    print('[✓] Saved: reports/random_forest_classification_report.csv')

    # Save model + scaler
    joblib.dump(model, os.path.join(MODELS_DIR, 'random_forest_model.pkl'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'random_forest_scaler.pkl'))
    print('[✓] Saved model + scaler')
    print('\n[✓] Random Forest training complete!')


if __name__ == '__main__':
    main()

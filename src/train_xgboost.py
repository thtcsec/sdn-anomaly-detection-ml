"""
Huấn luyện XGBoost Classifier cho phân loại tấn công SDN (multiclass).

Input:  dataset/train.csv, dataset/test.csv
Output:
  models/xgboost_model.pkl
  models/scaler.pkl
  reports/xgboost_metrics.csv
  reports/xgboost_classification_report.csv
  reports/xgboost_confusion_matrix.csv
  reports/confusion_matrix_xgboost.png
  reports/feature_importance_xgboost.png

Chạy: python src/train_xgboost.py
"""

import os
import sys
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
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
from xgboost import XGBClassifier

# Reproducibility
np.random.seed(42)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

TRAIN_CSV = os.path.join(DATASET_DIR, 'train.csv')
TEST_CSV = os.path.join(DATASET_DIR, 'test.csv')
LABEL_NAMES = ['ddos', 'normal', 'portscan']


def load_train_test():
    """Load train và test data."""
    if not os.path.exists(TRAIN_CSV) or not os.path.exists(TEST_CSV):
        print("[!] Train/Test files not found. Run preprocess.py first.")
        sys.exit(1)

    train_df = pd.read_csv(TRAIN_CSV)
    test_df = pd.read_csv(TEST_CSV)

    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    print(f"[*] Train: {X_train.shape}, Test: {X_test.shape}")
    print(f"[*] Train label distribution:\n{y_train.value_counts()}")
    return X_train, X_test, y_train, y_test


def main():
    """Pipeline huấn luyện chính."""
    print("=" * 60)
    print("  XGBoost Training Pipeline - SDN Anomaly Detection")
    print("=" * 60)

    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # 1. Load data
    X_train, X_test, y_train, y_test = load_train_test()

    # 2. Scale features
    # StandardScaler giúp đồng nhất preprocessing pipeline giữa các mô hình,
    # mặc dù XGBoost (tree-based) không yêu cầu chuẩn hóa đặc trưng.
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train), columns=X_train.columns
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test), columns=X_test.columns
    )

    # 3. Train model (với early stopping)
    print("[*] Training XGBoost model...")
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='mlogloss',
        early_stopping_rounds=20,
    )

    t0 = time.perf_counter()
    model.fit(
        X_train_scaled, y_train,
        eval_set=[(X_test_scaled, y_test)],
        verbose=False,
    )
    train_sec = time.perf_counter() - t0
    print(f"[✓] XGBoost training complete! ({train_sec:.3f}s)")
    print(f"[*] Best iteration: {model.best_iteration}")

    # 4. Predict + timing
    t1 = time.perf_counter()
    y_pred = model.predict(X_test_scaled)
    predict_batch_sec = time.perf_counter() - t1

    # Inference latency: numpy array to avoid Pandas overhead
    sample_np = X_test_scaled.iloc[:1].values
    model.predict(sample_np)  # warmup
    t2 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        model.predict(sample_np)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    # 5. Metrics
    acc = accuracy_score(y_test, y_pred)
    prec_macro = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec_macro = recall_score(y_test, y_pred, average='macro', zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    # ROC-AUC multiclass (One-vs-Rest)
    y_prob = model.predict_proba(X_test_scaled)
    auc_macro = roc_auc_score(y_test, y_prob, multi_class='ovr', average='macro')

    print("\n" + "=" * 60)
    print("  XGBOOST RESULTS")
    print("=" * 60)
    print(f"  Accuracy:          {acc:.6f}")
    print(f"  Precision (macro): {prec_macro:.6f}")
    print(f"  Recall (macro):    {rec_macro:.6f}")
    print(f"  F1-Score (macro):  {f1_macro:.6f}")
    print(f"  F1-Score (weighted): {f1_weighted:.6f}")
    print(f"  ROC-AUC (macro):   {auc_macro:.6f}")
    print(f"  Train time:        {train_sec:.3f}s")
    print(f"  Predict (test):    {predict_batch_sec:.3f}s")
    print(f"  Inference/sample:  {infer_ms:.3f} ms")
    print("=" * 60)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES, digits=4))

    # 6. Confusion Matrix — PNG + CSV
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=LABEL_NAMES, yticklabels=LABEL_NAMES)
    plt.title('Confusion Matrix - XGBoost')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    cm_png = os.path.join(REPORTS_DIR, 'confusion_matrix_xgboost.png')
    plt.savefig(cm_png, dpi=150)
    plt.close()
    print(f"[✓] Saved: {cm_png}")

    cm_csv = os.path.join(REPORTS_DIR, 'xgboost_confusion_matrix.csv')
    pd.DataFrame(cm, index=LABEL_NAMES, columns=LABEL_NAMES).to_csv(cm_csv)
    print(f"[✓] Saved: {cm_csv}")

    # 7. Feature Importance (gain-based, more reliable than weight/cover)
    importance = model.feature_importances_  # default importance_type='gain' in sklearn API
    indices = np.argsort(importance)[::-1]
    top_n = min(20, len(importance))
    top_indices = indices[:top_n]

    plt.figure(figsize=(10, 6))
    plt.title('Feature Importance (Gain) - XGBoost')
    plt.bar(range(top_n), importance[top_indices], align='center')
    plt.xticks(range(top_n),
               [X_train.columns[i] for i in top_indices], rotation=45, ha='right')
    plt.xlabel('Features')
    plt.ylabel('Importance (Gain)')
    plt.tight_layout()
    fi_path = os.path.join(REPORTS_DIR, 'feature_importance_xgboost.png')
    plt.savefig(fi_path, dpi=150)
    plt.close()
    print(f"[✓] Saved: {fi_path}")

    # 8. Save metrics CSV
    metrics = {
        'Model': 'XGBoost',
        'Approach': 'Supervised',
        'Classification': 'Multiclass',
        'Accuracy': acc,
        'Precision_macro': prec_macro,
        'Recall_macro': rec_macro,
        'F1_macro': f1_macro,
        'F1_weighted': f1_weighted,
        'AUC_macro': auc_macro,
        'Train_Time_sec': train_sec,
        'Predict_Test_sec': predict_batch_sec,
        'Inference_ms_per_sample': infer_ms,
        'Best_Iteration': model.best_iteration,
    }
    pd.DataFrame([metrics]).to_csv(
        os.path.join(REPORTS_DIR, 'xgboost_metrics.csv'), index=False
    )
    print("[✓] Saved: reports/xgboost_metrics.csv")

    # Per-class report CSV (for Word / LaTeX)
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
        os.path.join(REPORTS_DIR, 'xgboost_classification_report.csv'), index=False
    )
    print("[✓] Saved: reports/xgboost_classification_report.csv")

    # 9. Save model + scaler
    joblib.dump(model, os.path.join(MODELS_DIR, 'xgboost_model.pkl'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler.pkl'))
    print("[✓] Saved: models/xgboost_model.pkl")
    print("[✓] Saved: models/scaler.pkl")

    print("\n[✓] XGBoost training pipeline complete!")


if __name__ == '__main__':
    main()

"""
Train Isolation Forest - mô hình unsupervised thứ 2.
So sánh với Autoencoder để chứng minh vấn đề nằm ở data, không phải thuật toán.

Chạy: python src/train_isolation_forest.py
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc

# Reproducibility
np.random.seed(42)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def main():
    print("=" * 60)
    print("  Isolation Forest Training - SDN Anomaly Detection")
    print("=" * 60)

    # 1. Load data
    train_df = pd.read_csv(os.path.join(DATASET_DIR, 'train.csv'))
    test_df = pd.read_csv(os.path.join(DATASET_DIR, 'test.csv'))

    X_train_all = train_df.drop('label', axis=1)
    y_train_all = train_df['label']
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    # 2. Chỉ train với data NORMAL (label=1 sau LabelEncoder alphabetical: ddos=0, normal=1, portscan=2)
    X_train_normal = X_train_all[y_train_all == 1]
    print(f"[*] Training data (normal only): {len(X_train_normal)} samples")
    print(f"[*] Test data (all): {len(X_test)} samples")

    # 3. Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_normal)
    X_test_scaled = scaler.transform(X_test)

    # 4. Train Isolation Forest
    # contamination = tỷ lệ anomaly dự kiến trong data
    print("[*] Training Isolation Forest...")
    iso_forest = IsolationForest(
        n_estimators=200,
        contamination=0.05,  # 5% anomaly trong training data
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_train_scaled)
    print("[✓] Training complete!")

    # 5. Predict
    # Isolation Forest: 1 = normal, -1 = anomaly
    y_pred_raw = iso_forest.predict(X_test_scaled)
    # Chuyển: -1 → 1 (anomaly), 1 → 0 (normal)
    y_pred_binary = (y_pred_raw == -1).astype(int)

    # Ground truth: normal=1 → 0, còn lại → 1
    y_test_binary = (y_test != 1).astype(int)

    # Anomaly scores (lower = more anomalous)
    anomaly_scores = -iso_forest.decision_function(X_test_scaled)

    # 6. Evaluate
    print("\n" + "=" * 60)
    print("  ISOLATION FOREST EVALUATION (Binary: Normal vs Anomaly)")
    print("=" * 60)
    print(classification_report(y_test_binary, y_pred_binary,
                                target_names=['Normal', 'Anomaly']))

    # 7. ROC Curve
    fpr, tpr, _ = roc_curve(y_test_binary, anomaly_scores)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='green', lw=2,
             label=f'Isolation Forest (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve - Isolation Forest')
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'roc_curve_isolation_forest.png'), dpi=150)
    plt.close()
    print(f"[✓] Saved: reports/roc_curve_isolation_forest.png (AUC={roc_auc:.4f})")

    # 8. Confusion Matrix
    cm = confusion_matrix(y_test_binary, y_pred_binary)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Greens',
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'])
    plt.title('Confusion Matrix - Isolation Forest')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'confusion_matrix_isolation_forest.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/confusion_matrix_isolation_forest.png")

    # 9. Anomaly Score Distribution
    normal_mask = (y_test == 1)
    plt.figure(figsize=(10, 6))
    plt.hist(anomaly_scores[normal_mask], bins=50, alpha=0.7, label='Normal', color='blue')
    plt.hist(anomaly_scores[~normal_mask], bins=50, alpha=0.7, label='Attack', color='red')
    plt.xlabel('Anomaly Score')
    plt.ylabel('Count')
    plt.title('Isolation Forest - Anomaly Score Distribution')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'isolation_forest_score_dist.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/isolation_forest_score_dist.png")

    # 10. Save model
    joblib.dump(iso_forest, os.path.join(MODELS_DIR, 'isolation_forest_model.pkl'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'isolation_forest_scaler.pkl'))
    print("[✓] Saved: models/isolation_forest_model.pkl")

    print(f"\n[✓] Isolation Forest training complete!")
    print(f"[*] AUC Score: {roc_auc:.4f}")


if __name__ == '__main__':
    main()

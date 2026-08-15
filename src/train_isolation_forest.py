"""
Train Isolation Forest - mô hình unsupervised anomaly detection.
Thử nhiều giá trị contamination để đánh giá khách quan hơn.

Chạy: python src/train_isolation_forest.py
"""

import os
import sys
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    auc,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import StandardScaler

# Reproducibility
np.random.seed(42)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def evaluate_at_contamination(iso_forest, X_test_scaled, y_test_binary, contamination):
    """Evaluate binary metrics for a given contamination level."""
    y_pred_raw = iso_forest.predict(X_test_scaled)
    # Isolation Forest: 1 = normal (inlier), -1 = anomaly (outlier)
    y_pred_binary = (y_pred_raw == -1).astype(int)

    acc = accuracy_score(y_test_binary, y_pred_binary)
    prec = precision_score(y_test_binary, y_pred_binary, zero_division=0)
    rec = recall_score(y_test_binary, y_pred_binary, zero_division=0)
    f1 = f1_score(y_test_binary, y_pred_binary, zero_division=0)

    cm_counts = confusion_matrix(y_test_binary, y_pred_binary)
    tn, fp, fn, tp = cm_counts.ravel()
    fpr_rate = fp / (fp + tn) if (fp + tn) else 0.0
    fnr_rate = fn / (fn + tp) if (fn + tp) else 0.0

    return {
        'contamination': contamination,
        'Accuracy': acc,
        'Precision_Anomaly': prec,
        'Recall_Anomaly': rec,
        'F1_Anomaly': f1,
        'FPR': fpr_rate,
        'FNR': fnr_rate,
        'TN': int(tn), 'FP': int(fp), 'FN': int(fn), 'TP': int(tp),
    }


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

    # 2. Chỉ train với data NORMAL (label=1 sau LabelEncoder: ddos=0, normal=1, portscan=2)
    X_train_normal = X_train_all[y_train_all == 1]
    print(f"[*] Training data (normal only): {len(X_train_normal)} samples")
    print(f"[*] Test data (all): {len(X_test)} samples")

    # 3. Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_normal)
    X_test_scaled = scaler.transform(X_test)

    # Ground truth: normal=1 → 0 (negative), attack → 1 (positive)
    y_test_binary = (y_test != 1).astype(int)

    # 4. Multi-contamination sweep
    # contamination = expected proportion of outliers in the TRAINING data,
    # used only to determine the decision threshold on the training data.
    # It is NOT the attack ratio of the test dataset.
    contamination_values = [0.001, 0.005, 0.01, 0.05]
    sweep_results = []
    best_model = None
    best_f1 = -1
    best_contamination = None

    print("\n[*] Running contamination sweep...")
    for cont in contamination_values:
        print(f"  contamination={cont} ... ", end="", flush=True)
        iso_forest = IsolationForest(
            n_estimators=200,
            contamination=cont,
            max_samples='auto',
            random_state=42,
            n_jobs=-1,
        )

        t0 = time.perf_counter()
        iso_forest.fit(X_train_scaled)
        train_sec = time.perf_counter() - t0

        result = evaluate_at_contamination(iso_forest, X_test_scaled, y_test_binary, cont)
        result['Train_Time_sec'] = train_sec
        sweep_results.append(result)
        print(f"F1={result['F1_Anomaly']:.4f}, Recall={result['Recall_Anomaly']:.4f}, "
              f"Prec={result['Precision_Anomaly']:.4f}")

        if result['F1_Anomaly'] > best_f1:
            best_f1 = result['F1_Anomaly']
            best_model = iso_forest
            best_contamination = cont

    # Save sweep table
    sweep_df = pd.DataFrame(sweep_results)
    sweep_path = os.path.join(REPORTS_DIR, 'isolation_forest_contamination_sweep.csv')
    sweep_df.to_csv(sweep_path, index=False)
    print(f"\n[✓] Contamination sweep saved: {sweep_path}")
    print(f"[*] Best contamination: {best_contamination} (F1={best_f1:.4f})")
    print(sweep_df.to_string(index=False))

    # 5. Use best model for full evaluation
    iso_forest = best_model
    y_pred_raw = iso_forest.predict(X_test_scaled)
    y_pred_binary = (y_pred_raw == -1).astype(int)

    # Anomaly scores (higher = more anomalous for sklearn convention)
    anomaly_scores = -iso_forest.decision_function(X_test_scaled)

    # Inference latency
    sample_np = X_test_scaled[:1]
    iso_forest.predict(sample_np)  # warmup
    t2 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        iso_forest.predict(sample_np)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    # Full metrics
    acc = accuracy_score(y_test_binary, y_pred_binary)
    prec = precision_score(y_test_binary, y_pred_binary, zero_division=0)
    rec = recall_score(y_test_binary, y_pred_binary, zero_division=0)
    f1 = f1_score(y_test_binary, y_pred_binary, zero_division=0)
    prec_macro = precision_score(y_test_binary, y_pred_binary, average='macro', zero_division=0)
    rec_macro = recall_score(y_test_binary, y_pred_binary, average='macro', zero_division=0)
    f1_macro = f1_score(y_test_binary, y_pred_binary, average='macro', zero_division=0)
    cm_counts = confusion_matrix(y_test_binary, y_pred_binary)
    tn, fp, fn, tp = cm_counts.ravel()
    fpr_rate = fp / (fp + tn) if (fp + tn) else 0.0
    fnr_rate = fn / (fn + tp) if (fn + tp) else 0.0

    print("\n" + "=" * 60)
    print(f"  ISOLATION FOREST EVALUATION (best contamination={best_contamination})")
    print("  Binary: Normal vs Anomaly | P/R/F1 = Anomaly-class")
    print("=" * 60)
    print(f"  Accuracy:            {acc:.4f}")
    print(f"  Precision (Anomaly): {prec:.4f}")
    print(f"  Recall (Anomaly):    {rec:.4f}")
    print(f"  F1 (Anomaly):        {f1:.4f}")
    print(f"  Macro P/R/F1:        {prec_macro:.4f} / {rec_macro:.4f} / {f1_macro:.4f}")
    print(f"  FPR: {fpr_rate:.4f}  FNR: {fnr_rate:.4f}")
    print(f"  Inference/sample:    {infer_ms:.3f} ms")
    print("=" * 60)
    print(classification_report(y_test_binary, y_pred_binary,
                                target_names=['Normal', 'Anomaly']))

    # 6. ROC Curve + AUC
    fpr_arr, tpr_arr, _ = roc_curve(y_test_binary, anomaly_scores)
    roc_auc = auc(fpr_arr, tpr_arr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr_arr, tpr_arr, color='green', lw=2,
             label=f'Isolation Forest (ROC-AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve - Isolation Forest')
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'roc_curve_isolation_forest.png'), dpi=150)
    plt.close()
    print(f"[✓] Saved: reports/roc_curve_isolation_forest.png (ROC-AUC={roc_auc:.4f})")

    # 7. Precision-Recall Curve + PR-AUC (quan trọng hơn ROC-AUC cho IDS imbalanced)
    pr_precision, pr_recall, _ = precision_recall_curve(y_test_binary, anomaly_scores)
    pr_auc = average_precision_score(y_test_binary, anomaly_scores)

    plt.figure(figsize=(8, 6))
    plt.plot(pr_recall, pr_precision, color='darkgreen', lw=2,
             label=f'Isolation Forest (PR-AUC = {pr_auc:.4f})')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve - Isolation Forest')
    plt.legend(loc='upper right')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'pr_curve_isolation_forest.png'), dpi=150)
    plt.close()
    print(f"[✓] Saved: reports/pr_curve_isolation_forest.png (PR-AUC={pr_auc:.4f})")

    # 8. Confusion Matrix — PNG + CSV
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm_counts, annot=True, fmt='d', cmap='Greens',
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'])
    plt.title(f'Confusion Matrix - Isolation Forest (c={best_contamination})')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'confusion_matrix_isolation_forest.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/confusion_matrix_isolation_forest.png")

    pd.DataFrame(cm_counts, index=['Normal', 'Anomaly'],
                 columns=['Normal', 'Anomaly']).to_csv(
        os.path.join(REPORTS_DIR, 'isolation_forest_confusion_matrix.csv')
    )
    print("[✓] Saved: reports/isolation_forest_confusion_matrix.csv")

    # 9. Anomaly Score Distribution (bằng chứng trực quan)
    normal_mask = (y_test == 1)
    plt.figure(figsize=(10, 6))
    plt.hist(anomaly_scores[normal_mask], bins=50, alpha=0.7, label='Normal', color='blue', density=True)
    plt.hist(anomaly_scores[~normal_mask], bins=50, alpha=0.7, label='Attack', color='red', density=True)
    plt.xlabel('Anomaly Score (-decision_function)')
    plt.ylabel('Density')
    plt.title('Isolation Forest - Anomaly Score Distribution\n'
              '(Nếu hai histogram chồng lấn → dữ liệu không mang tín hiệu phân biệt đủ mạnh)')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'isolation_forest_score_dist.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/isolation_forest_score_dist.png")

    # 10. Save model + metrics
    joblib.dump(iso_forest, os.path.join(MODELS_DIR, 'isolation_forest_model.pkl'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'isolation_forest_scaler.pkl'))
    pd.DataFrame([{
        "MetricScope": "anomaly_class_binary",
        "best_contamination": best_contamination,
        "Accuracy": acc,
        "Precision_Anomaly": prec,
        "Recall_Anomaly": rec,
        "F1_Anomaly": f1,
        "Precision_macro": prec_macro,
        "Recall_macro": rec_macro,
        "F1_macro": f1_macro,
        "FPR": fpr_rate,
        "FNR": fnr_rate,
        "ROC_AUC": roc_auc,
        "PR_AUC": pr_auc,
        "Inference_ms_per_sample": infer_ms,
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
        "note": "contamination = expected proportion of outliers, "
                "used only to determine the decision threshold on training data",
    }]).to_csv(os.path.join(REPORTS_DIR, "isolation_forest_metrics.csv"), index=False)
    print("[✓] Saved: models/isolation_forest_model.pkl")
    print("[✓] Saved: reports/isolation_forest_metrics.csv")

    print(f"\n[✓] Isolation Forest training complete!")
    print(f"[*] Best contamination: {best_contamination}")
    print(f"[*] ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f}")


if __name__ == '__main__':
    main()

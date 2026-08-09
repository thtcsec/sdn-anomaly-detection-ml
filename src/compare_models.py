"""
So sánh tổng hợp hiệu năng tất cả model.
Tạo bảng so sánh + biểu đồ bar chart.

Chạy SAU khi đã train xong tất cả model:
  python src/compare_models.py
"""

import os
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

os.makedirs(REPORTS_DIR, exist_ok=True)


def evaluate_xgboost(X_test, y_test):
    """Evaluate XGBoost (multiclass → binary for comparison)."""
    model_path = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')

    if not os.path.exists(model_path):
        return None

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    X_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)
    y_pred = model.predict(X_scaled)

    # Multiclass metrics
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='macro')
    prec = precision_score(y_test, y_pred, average='macro')
    rec = recall_score(y_test, y_pred, average='macro')

    # Binary for AUC: normal=1 vs rest
    y_binary = (y_test != 1).astype(int)
    y_pred_binary = (y_pred != 1).astype(int)

    return {
        'Model': 'XGBoost',
        'Approach': 'Supervised',
        'Classification': 'Multiclass',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1,
    }


def evaluate_random_forest(X_test, y_test):
    """Evaluate Random Forest (multiclass)."""
    model_path = os.path.join(MODELS_DIR, 'random_forest_model.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'random_forest_scaler.pkl')

    if not os.path.exists(model_path):
        return None

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    X_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)
    y_pred = model.predict(X_scaled)

    return {
        'Model': 'Random Forest',
        'Approach': 'Supervised',
        'Classification': 'Multiclass',
        'Accuracy': accuracy_score(y_test, y_pred),
        'Precision': precision_score(y_test, y_pred, average='macro', zero_division=0),
        'Recall': recall_score(y_test, y_pred, average='macro', zero_division=0),
        'F1-Score': f1_score(y_test, y_pred, average='macro', zero_division=0),
    }


def evaluate_isolation_forest(X_test, y_test):
    """Evaluate Isolation Forest (binary)."""
    model_path = os.path.join(MODELS_DIR, 'isolation_forest_model.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'isolation_forest_scaler.pkl')

    if not os.path.exists(model_path):
        return None

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    X_scaled = scaler.transform(X_test)
    y_pred_raw = model.predict(X_scaled)
    y_pred_binary = (y_pred_raw == -1).astype(int)
    y_test_binary = (y_test != 1).astype(int)

    anomaly_scores = -model.decision_function(X_scaled)

    acc = accuracy_score(y_test_binary, y_pred_binary)
    f1 = f1_score(y_test_binary, y_pred_binary)
    prec = precision_score(y_test_binary, y_pred_binary)
    rec = recall_score(y_test_binary, y_pred_binary)
    try:
        auc_score = roc_auc_score(y_test_binary, anomaly_scores)
    except:
        auc_score = 0

    return {
        'Model': 'Isolation Forest',
        'Approach': 'Unsupervised',
        'Classification': 'Binary (P/R/F1=Anomaly-class)',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1,
    }

def evaluate_autoencoder(X_test, y_test):
    """Evaluate Autoencoder (binary). Threshold MUST come from training, not test."""
    try:
        import os as _os
        _os.environ.setdefault('TF_USE_LEGACY_KERAS', '1')
        from tensorflow import keras
    except Exception:
        try:
            import tf_keras as keras
        except ImportError:
            return None

    model_path = os.path.join(MODELS_DIR, 'autoencoder_model.keras')
    scaler_path = os.path.join(MODELS_DIR, 'autoencoder_scaler.pkl')
    thr_path = os.path.join(MODELS_DIR, 'autoencoder_threshold.pkl')

    if not os.path.exists(model_path):
        return None

    model = keras.models.load_model(model_path)
    scaler = joblib.load(scaler_path)

    X_scaled = scaler.transform(X_test)
    X_pred = model.predict(X_scaled, verbose=0)
    mse = np.mean(np.power(X_scaled - X_pred, 2), axis=1)

    if os.path.exists(thr_path):
        thr_obj = joblib.load(thr_path)
        threshold = float(thr_obj['threshold'] if isinstance(thr_obj, dict) else thr_obj)
        print(f"    [AE] Using saved train threshold={threshold:.6f}")
    else:
        normal_mask = (y_test == 1)
        threshold = float(np.percentile(mse[normal_mask], 95))
        print(
            f"    [AE][WARN] threshold.pkl missing → recomputed on TEST normals "
            f"({threshold:.6f}); run src/sync_ae_threshold_metrics.py"
        )

    y_pred_binary = (mse > threshold).astype(int)
    y_test_binary = (y_test != 1).astype(int)

    # P/R/F1 = Anomaly-class (binary positive), not macro
    acc = accuracy_score(y_test_binary, y_pred_binary)
    f1 = f1_score(y_test_binary, y_pred_binary)
    prec = precision_score(y_test_binary, y_pred_binary, zero_division=0)
    rec = recall_score(y_test_binary, y_pred_binary)

    return {
        'Model': 'Autoencoder',
        'Approach': 'Unsupervised',
        'Classification': 'Binary (P/R/F1=Anomaly-class)',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1,
    }

def main():
    print("=" * 60)
    print("  Model Comparison - SDN Anomaly Detection")
    print("=" * 60)

    # Load test data
    test_df = pd.read_csv(os.path.join(DATASET_DIR, 'test.csv'))
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    # Evaluate all models
    results = []

    print("\n[*] Evaluating XGBoost...")
    r = evaluate_xgboost(X_test, y_test)
    if r:
        results.append(r)
        print(f"    Accuracy={r['Accuracy']:.4f}, F1={r['F1-Score']:.4f}")

    print("[*] Evaluating Random Forest...")
    r = evaluate_random_forest(X_test, y_test)
    if r:
        results.append(r)
        print(f"    Accuracy={r['Accuracy']:.4f}, F1={r['F1-Score']:.4f}")

    print("[*] Evaluating Isolation Forest...")
    r = evaluate_isolation_forest(X_test, y_test)
    if r:
        results.append(r)
        print(f"    Accuracy={r['Accuracy']:.4f}, F1={r['F1-Score']:.4f}")

    print("[*] Evaluating Autoencoder...")
    r = evaluate_autoencoder(X_test, y_test)
    if r:
        results.append(r)
        print(f"    Accuracy={r['Accuracy']:.4f}, F1={r['F1-Score']:.4f}")

    if not results:
        print("[!] No models found. Train models first.")
        return

    # Create comparison table
    df_results = pd.DataFrame(results)
    print("\n" + "=" * 60)
    print("  COMPARISON TABLE")
    print("=" * 60)
    print(df_results.to_string(index=False))

    # Save table
    df_results.to_csv(os.path.join(REPORTS_DIR, 'model_comparison.csv'), index=False)
    print(f"\n[✓] Saved: reports/model_comparison.csv")

    # Bar chart comparison
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    models = df_results['Model'].tolist()

    fig, axes = plt.subplots(1, len(metrics), figsize=(16, 5))

    colors = ['#2196F3', '#9C27B0', '#4CAF50', '#FF9800']

    for i, metric in enumerate(metrics):
        values = df_results[metric].tolist()
        bars = axes[i].bar(models, values, color=colors[:len(models)], edgecolor='black')
        axes[i].set_title(metric, fontsize=13, fontweight='bold')
        axes[i].set_ylim(0, 1.1)
        axes[i].axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)
        for bar, val in zip(bars, values):
            axes[i].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                        f'{val:.3f}', ha='center', fontsize=10, fontweight='bold')

    plt.suptitle('So sánh hiệu năng các mô hình ML - SDN Anomaly Detection',
                 fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'model_comparison_chart.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/model_comparison_chart.png")
    print("=" * 60)


if __name__ == '__main__':
    main()

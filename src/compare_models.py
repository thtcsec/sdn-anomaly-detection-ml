"""
So sánh tổng hợp hiệu năng tất cả model + PCA/t-SNE Visualization.
Tạo bảng so sánh hoàn chỉnh + biểu đồ + PCA scatter plot.

Chạy SAU khi đã train xong tất cả model:
  python src/compare_models.py
"""

import os
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

os.makedirs(REPORTS_DIR, exist_ok=True)

LABEL_NAMES_MAP = {0: 'DDoS', 1: 'Normal', 2: 'PortScan'}
LABEL_COLORS = {0: '#e74c3c', 1: '#2ecc71', 2: '#3498db'}


def evaluate_xgboost(X_test, y_test):
    """Evaluate XGBoost (multiclass)."""
    model_path = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
    scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
    if not os.path.exists(model_path):
        return None

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    X_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)

    t0 = time.perf_counter()
    y_pred = model.predict(X_scaled)
    pred_sec = time.perf_counter() - t0

    # Inference latency
    sample_np = X_scaled.iloc[:1].values
    model.predict(sample_np)
    t1 = time.perf_counter()
    for _ in range(1000):
        model.predict(sample_np)
    infer_ms = (time.perf_counter() - t1) * 1000.0 / 1000

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
    prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec = recall_score(y_test, y_pred, average='macro', zero_division=0)

    try:
        y_prob = model.predict_proba(X_scaled)
        auc_macro = roc_auc_score(y_test, y_prob, multi_class='ovr', average='macro')
    except Exception:
        auc_macro = np.nan

    return {
        'Model': 'XGBoost', 'Approach': 'Supervised', 'Classification': 'Multiclass',
        'Accuracy': acc, 'Precision': prec, 'Recall': rec, 'F1_macro': f1,
        'ROC_AUC': auc_macro, 'PR_AUC': np.nan,
        'Inference_ms': infer_ms,
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

    sample_np = X_scaled.iloc[:1].values
    model.predict(sample_np)
    t1 = time.perf_counter()
    for _ in range(1000):
        model.predict(sample_np)
    infer_ms = (time.perf_counter() - t1) * 1000.0 / 1000

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='macro', zero_division=0)
    prec = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec = recall_score(y_test, y_pred, average='macro', zero_division=0)

    try:
        y_prob = model.predict_proba(X_scaled)
        auc_macro = roc_auc_score(y_test, y_prob, multi_class='ovr', average='macro')
    except Exception:
        auc_macro = np.nan

    return {
        'Model': 'Random Forest', 'Approach': 'Supervised', 'Classification': 'Multiclass',
        'Accuracy': acc, 'Precision': prec, 'Recall': rec, 'F1_macro': f1,
        'ROC_AUC': auc_macro, 'PR_AUC': np.nan,
        'Inference_ms': infer_ms,
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

    sample_np = X_scaled[:1]
    model.predict(sample_np)
    t1 = time.perf_counter()
    for _ in range(1000):
        model.predict(sample_np)
    infer_ms = (time.perf_counter() - t1) * 1000.0 / 1000

    acc = accuracy_score(y_test_binary, y_pred_binary)
    f1 = f1_score(y_test_binary, y_pred_binary, zero_division=0)
    prec = precision_score(y_test_binary, y_pred_binary, zero_division=0)
    rec = recall_score(y_test_binary, y_pred_binary, zero_division=0)

    try:
        roc_auc = roc_auc_score(y_test_binary, anomaly_scores)
    except Exception:
        roc_auc = np.nan
    try:
        pr_auc = average_precision_score(y_test_binary, anomaly_scores)
    except Exception:
        pr_auc = np.nan

    return {
        'Model': 'Isolation Forest', 'Approach': 'Unsupervised',
        'Classification': 'Binary (Anomaly)',
        'Accuracy': acc, 'Precision': prec, 'Recall': rec, 'F1_macro': f1,
        'ROC_AUC': roc_auc, 'PR_AUC': pr_auc,
        'Inference_ms': infer_ms,
    }


def evaluate_autoencoder(X_test, y_test):
    """Evaluate Autoencoder (binary)."""
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

    y_pred_binary = (mse > threshold).astype(int)
    y_test_binary = (y_test != 1).astype(int)

    # Inference latency
    sample_np = X_scaled[:1]
    model.predict(sample_np, verbose=0)
    t1 = time.perf_counter()
    for _ in range(1000):
        model.predict(sample_np, verbose=0)
    infer_ms = (time.perf_counter() - t1) * 1000.0 / 1000

    acc = accuracy_score(y_test_binary, y_pred_binary)
    f1 = f1_score(y_test_binary, y_pred_binary, zero_division=0)
    prec = precision_score(y_test_binary, y_pred_binary, zero_division=0)
    rec = recall_score(y_test_binary, y_pred_binary, zero_division=0)

    try:
        roc_auc = roc_auc_score(y_test_binary, mse)
    except Exception:
        roc_auc = np.nan
    try:
        pr_auc = average_precision_score(y_test_binary, mse)
    except Exception:
        pr_auc = np.nan

    return {
        'Model': 'Autoencoder', 'Approach': 'Unsupervised',
        'Classification': 'Binary (Anomaly)',
        'Accuracy': acc, 'Precision': prec, 'Recall': rec, 'F1_macro': f1,
        'ROC_AUC': roc_auc, 'PR_AUC': pr_auc,
        'Inference_ms': infer_ms,
    }


def plot_pca_visualization(X_test, y_test):
    """PCA 2D visualization — bằng chứng trực quan cho ranh giới phân lớp."""
    print("\n[*] Generating PCA 2D visualization...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_test)

    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)
    explained = pca.explained_variance_ratio_

    plt.figure(figsize=(12, 8))
    for label_id, label_name in LABEL_NAMES_MAP.items():
        mask = (y_test == label_id)
        # Subsample for clarity if too many points
        idx = np.where(mask)[0]
        if len(idx) > 3000:
            idx = np.random.choice(idx, 3000, replace=False)
        plt.scatter(
            X_pca[idx, 0], X_pca[idx, 1],
            c=LABEL_COLORS[label_id], label=label_name,
            alpha=0.3, s=8, edgecolors='none',
        )

    plt.xlabel(f'PC1 ({explained[0]:.1%} variance)')
    plt.ylabel(f'PC2 ({explained[1]:.1%} variance)')
    plt.title('PCA 2D Projection - SDN Flow Feature Space\n'
              '(Nếu các lớp chồng lấn → unsupervised khó phân biệt;\n'
              'nếu tách rõ → supervised có ranh giới rõ ràng)')
    plt.legend(markerscale=5, fontsize=12)
    plt.tight_layout()
    pca_path = os.path.join(REPORTS_DIR, 'pca_2d_visualization.png')
    plt.savefig(pca_path, dpi=150)
    plt.close()
    print(f"[✓] Saved: {pca_path}")
    print(f"    PC1 explains {explained[0]:.1%}, PC2 explains {explained[1]:.1%} of variance")


def plot_tsne_visualization(X_test, y_test, n_samples=5000):
    """t-SNE 2D visualization (subsampled for speed)."""
    print(f"\n[*] Generating t-SNE 2D visualization (subsample={n_samples})...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_test)

    # Subsample
    if len(X_scaled) > n_samples:
        idx = np.random.choice(len(X_scaled), n_samples, replace=False)
        X_sub = X_scaled[idx]
        y_sub = y_test.values[idx] if hasattr(y_test, 'values') else y_test[idx]
    else:
        X_sub = X_scaled
        y_sub = y_test.values if hasattr(y_test, 'values') else y_test

    tsne = TSNE(n_components=2, random_state=42, perplexity=30, max_iter=1000)
    X_tsne = tsne.fit_transform(X_sub)

    plt.figure(figsize=(12, 8))
    for label_id, label_name in LABEL_NAMES_MAP.items():
        mask = (y_sub == label_id)
        plt.scatter(
            X_tsne[mask, 0], X_tsne[mask, 1],
            c=LABEL_COLORS[label_id], label=label_name,
            alpha=0.5, s=10, edgecolors='none',
        )

    plt.xlabel('t-SNE Dimension 1')
    plt.ylabel('t-SNE Dimension 2')
    plt.title('t-SNE 2D Projection - SDN Flow Feature Space')
    plt.legend(markerscale=5, fontsize=12)
    plt.tight_layout()
    tsne_path = os.path.join(REPORTS_DIR, 'tsne_2d_visualization.png')
    try:
        plt.savefig(tsne_path, dpi=150)
    except OSError:
        tsne_path = os.path.join(REPORTS_DIR, 'tsne_2d_visualization_new.png')
        plt.savefig(tsne_path, dpi=150)
    plt.close()
    print(f"[✓] Saved: {tsne_path}")


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
        print(f"    Acc={r['Accuracy']:.4f}, F1={r['F1_macro']:.4f}, AUC={r['ROC_AUC']:.4f}")

    print("[*] Evaluating Random Forest...")
    r = evaluate_random_forest(X_test, y_test)
    if r:
        results.append(r)
        print(f"    Acc={r['Accuracy']:.4f}, F1={r['F1_macro']:.4f}, AUC={r['ROC_AUC']:.4f}")

    print("[*] Evaluating Isolation Forest...")
    r = evaluate_isolation_forest(X_test, y_test)
    if r:
        results.append(r)
        print(f"    Acc={r['Accuracy']:.4f}, F1={r['F1_macro']:.4f}, "
              f"ROC-AUC={r['ROC_AUC']:.4f}, PR-AUC={r['PR_AUC']:.4f}")

    print("[*] Evaluating Autoencoder...")
    r = evaluate_autoencoder(X_test, y_test)
    if r:
        results.append(r)
        print(f"    Acc={r['Accuracy']:.4f}, F1={r['F1_macro']:.4f}, "
              f"ROC-AUC={r['ROC_AUC']:.4f}, PR-AUC={r['PR_AUC']:.4f}")

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

    # Bar chart comparison (5 metrics now)
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1_macro', 'ROC_AUC']
    metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1 (macro)', 'ROC-AUC']
    models = df_results['Model'].tolist()
    colors = ['#2196F3', '#9C27B0', '#4CAF50', '#FF9800']

    fig, axes = plt.subplots(1, len(metrics), figsize=(20, 5))
    for i, (metric, label) in enumerate(zip(metrics, metric_labels)):
        values = df_results[metric].tolist()
        bars = axes[i].bar(models, values, color=colors[:len(models)], edgecolor='black')
        axes[i].set_title(label, fontsize=13, fontweight='bold')
        axes[i].set_ylim(0, 1.15)
        axes[i].axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)
        axes[i].tick_params(axis='x', rotation=30)
        for bar, val in zip(bars, values):
            if not np.isnan(val):
                axes[i].text(
                    bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                    f'{val:.3f}', ha='center', fontsize=9, fontweight='bold',
                )

    plt.suptitle('So sánh hiệu năng các mô hình ML - SDN Anomaly Detection',
                 fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'model_comparison_chart.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/model_comparison_chart.png")

    # PCA + t-SNE Visualization
    plot_pca_visualization(X_test, y_test)
    plot_tsne_visualization(X_test, y_test)

    print("=" * 60)
    print("[✓] Model comparison complete!")


if __name__ == '__main__':
    main()

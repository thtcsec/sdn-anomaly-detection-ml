"""
Train Autoencoder - mô hình unsupervised phát hiện bất thường.
Ý tưởng: train chỉ với data NORMAL thật (không SMOTE), khi gặp attack
thì reconstruction error sẽ cao → phát hiện bất thường.

LƯU Ý: Autoencoder PHẢI train trên data normal GỐC (từ flow_stats.csv),
KHÔNG dùng train.csv đã SMOTE vì SMOTE tạo normal synthetic làm lệch threshold.

Chạy: python src/train_autoencoder.py
"""

import os
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
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
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

import os as _os

_os.environ.setdefault('TF_USE_LEGACY_KERAS', '1')
import tensorflow as tf

try:
    from tensorflow import keras
except Exception:
    import tf_keras as keras  # TF 2.16+ / 2.21 fallback

# Reproducibility
np.random.seed(42)
tf.random.set_seed(42)

# =========================
# PATHS
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# =========================
# FEATURE LIST (FIXED)
# =========================
FEATURES = [
    'ip_proto', 'tp_src', 'tp_dst', 'packet_count', 'byte_count',
    'duration_sec', 'packet_count_per_sec', 'byte_count_per_sec',
    'packet_size_avg', 'flow_duration',
]


def main():
    print("=" * 60)
    print("  AUTOENCODER TRAINING - SDN ANOMALY DETECTION")
    print("=" * 60)

    # ===================================================================
    # Load data GỐC (KHÔNG dùng train.csv đã SMOTE)
    # ===================================================================
    grouped_csv = os.path.join(DATASET_DIR, "flow_stats_grouped.csv")
    raw_csv = grouped_csv if os.path.exists(grouped_csv) else os.path.join(DATASET_DIR, "flow_stats.csv")
    df = pd.read_csv(raw_csv)
    print(f"[*] Loaded {len(df)} records from {os.path.basename(raw_csv)}")

    X = df[FEATURES]
    y_raw = df['label']

    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    print(f"[*] Label mapping: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    # Train/test split (80/20, stratified) — kiểm soát rõ hơn validation
    X_train_all, X_test, y_train_all, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Chỉ lấy NORMAL THẬT để train (label==1)
    X_train_normal = X_train_all[y_train_all == 1]

    # Tách validation riêng từ normal train (tốt hơn validation_split random)
    X_train_n, X_val_n = train_test_split(
        X_train_normal, test_size=0.1, random_state=42
    )
    print(f"[*] Normal training samples: {len(X_train_n)} | Validation: {len(X_val_n)}")
    print(f"[*] Test samples (all labels): {len(X_test)}")

    # =========================
    # SCALING
    # =========================
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_n)
    X_val_scaled = scaler.transform(X_val_n)
    X_test_scaled = scaler.transform(X_test)

    # =========================
    # AUTOENCODER MODEL (10 → 16 → 8 → 4 → 8 → 16 → 10)
    # Wider architecture for better reconstruction capacity
    # =========================
    input_dim = X_train_scaled.shape[1]

    model = keras.Sequential([
        keras.layers.Input(shape=(input_dim,)),
        # Encoder
        keras.layers.Dense(16, activation='relu'),
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(4, activation='relu'),  # Bottleneck
        # Decoder
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(16, activation='relu'),
        keras.layers.Dense(input_dim, activation='linear'),
    ])

    model.compile(optimizer='adam', loss='mse')
    model.summary()

    # =========================
    # TRAINING (with EarlyStopping + explicit validation set)
    # =========================
    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss', patience=10, restore_best_weights=True
    )

    print("\n[*] Training Autoencoder...")
    t0 = time.perf_counter()
    history = model.fit(
        X_train_scaled, X_train_scaled,
        epochs=100,
        batch_size=32,
        validation_data=(X_val_scaled, X_val_scaled),
        callbacks=[early_stop],
        verbose=1,
    )
    train_sec = time.perf_counter() - t0
    print(f"[✓] Training stopped at epoch {len(history.history['loss'])} ({train_sec:.3f}s)")

    # =========================
    # PREDICTION & THRESHOLD
    # =========================
    X_pred_test = model.predict(X_test_scaled, verbose=0)
    mse_test = np.mean(np.power(X_test_scaled - X_pred_test, 2), axis=1)

    # Threshold từ reconstruction error trên tập normal TRAIN (no data leakage)
    X_pred_train = model.predict(X_train_scaled, verbose=0)
    mse_train = np.mean(np.power(X_train_scaled - X_pred_train, 2), axis=1)

    # Multi-threshold sweep
    percentiles = [90, 95, 97, 99]
    y_test_bin = (y_test != 1).astype(int)  # 0=normal, 1=anomaly

    print("\n[*] Threshold percentile sweep:")
    threshold_results = []
    for pct in percentiles:
        thr = np.percentile(mse_train, pct)
        y_p = (mse_test > thr).astype(int)
        t_acc = accuracy_score(y_test_bin, y_p)
        t_prec = precision_score(y_test_bin, y_p, zero_division=0)
        t_rec = recall_score(y_test_bin, y_p, zero_division=0)
        t_f1 = f1_score(y_test_bin, y_p, zero_division=0)
        threshold_results.append({
            'percentile': pct, 'threshold': thr,
            'Accuracy': t_acc, 'Precision': t_prec,
            'Recall': t_rec, 'F1': t_f1,
        })
        print(f"  P{pct}: thr={thr:.6f} → Acc={t_acc:.4f}, P={t_prec:.4f}, R={t_rec:.4f}, F1={t_f1:.4f}")

    thr_sweep_df = pd.DataFrame(threshold_results)
    thr_sweep_df.to_csv(os.path.join(REPORTS_DIR, 'autoencoder_threshold_sweep.csv'), index=False)
    print("[✓] Saved: reports/autoencoder_threshold_sweep.csv")

    # Use 95th percentile as default threshold
    threshold = np.percentile(mse_train, 95)
    print(f"\n[*] Using threshold (95th percentile): {threshold:.6f}")

    y_pred_bin = (mse_test > threshold).astype(int)

    # =========================
    # EVALUATION
    # =========================
    acc = accuracy_score(y_test_bin, y_pred_bin)
    f1 = f1_score(y_test_bin, y_pred_bin)
    prec = precision_score(y_test_bin, y_pred_bin, zero_division=0)
    rec = recall_score(y_test_bin, y_pred_bin)
    f1_macro = f1_score(y_test_bin, y_pred_bin, average='macro')
    prec_macro = precision_score(y_test_bin, y_pred_bin, average='macro', zero_division=0)
    rec_macro = recall_score(y_test_bin, y_pred_bin, average='macro', zero_division=0)
    cm = confusion_matrix(y_test_bin, y_pred_bin)
    tn, fp, fn, tp = cm.ravel()
    fpr_val = fp / (fp + tn) if (fp + tn) else 0.0
    fnr_val = fn / (fn + tp) if (fn + tp) else 0.0

    # Inference latency
    sample_np = X_test_scaled[:1]
    model.predict(sample_np, verbose=0)  # warmup
    t2 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        model.predict(sample_np, verbose=0)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    print("\n" + "=" * 60)
    print("  AUTOENCODER EVALUATION (Binary: Normal vs Anomaly)")
    print("  Precision/Recall/F1 = Anomaly-class (positive=Anomaly)")
    print("=" * 60)
    print(f"  Accuracy:              {acc:.4f}")
    print(f"  Precision (Anomaly):   {prec:.4f}")
    print(f"  Recall (Anomaly):      {rec:.4f}")
    print(f"  F1-Score (Anomaly):    {f1:.4f}")
    print(f"  Macro P/R/F1:          {prec_macro:.4f} / {rec_macro:.4f} / {f1_macro:.4f}")
    print(f"  FPR (Normal→Anomaly):  {fpr_val:.4f}  FNR: {fnr_val:.4f}")
    print(f"  Threshold (95th):      {threshold:.6f}")
    print(f"  Train time:            {train_sec:.3f}s")
    print(f"  Inference/sample:      {infer_ms:.3f} ms")
    print("=" * 60)
    print(classification_report(y_test_bin, y_pred_bin,
                                target_names=['Normal', 'Anomaly']))

    # =========================
    # ROC CURVE + AUC
    # =========================
    fpr_arr, tpr_arr, _ = roc_curve(y_test_bin, mse_test)
    roc_auc = auc(fpr_arr, tpr_arr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr_arr, tpr_arr, color='darkorange', lw=2,
             label=f"Autoencoder (ROC-AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle="--")
    plt.title("ROC Curve - Autoencoder")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "roc_curve_autoencoder.png"), dpi=150)
    plt.close()
    print(f"[✓] Saved: reports/roc_curve_autoencoder.png (ROC-AUC={roc_auc:.4f})")

    # =========================
    # PR CURVE + PR-AUC (quan trọng hơn ROC-AUC cho IDS imbalanced)
    # =========================
    pr_prec_arr, pr_rec_arr, _ = precision_recall_curve(y_test_bin, mse_test)
    pr_auc = average_precision_score(y_test_bin, mse_test)

    plt.figure(figsize=(8, 6))
    plt.plot(pr_rec_arr, pr_prec_arr, color='darkorange', lw=2,
             label=f"Autoencoder (PR-AUC = {pr_auc:.4f})")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve - Autoencoder")
    plt.legend(loc='upper right')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "pr_curve_autoencoder.png"), dpi=150)
    plt.close()
    print(f"[✓] Saved: reports/pr_curve_autoencoder.png (PR-AUC={pr_auc:.4f})")

    # =========================
    # CONFUSION MATRIX — PNG + CSV
    # =========================
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges',
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'])
    plt.title('Confusion Matrix - Autoencoder')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'confusion_matrix_autoencoder.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/confusion_matrix_autoencoder.png")

    pd.DataFrame(cm, index=['Normal', 'Anomaly'],
                 columns=['Normal', 'Anomaly']).to_csv(
        os.path.join(REPORTS_DIR, 'autoencoder_confusion_matrix.csv')
    )
    print("[✓] Saved: reports/autoencoder_confusion_matrix.csv")

    # =========================
    # LOSS PLOT
    # =========================
    plt.figure(figsize=(8, 5))
    plt.plot(history.history['loss'], label='Train Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.title("Training Loss - Autoencoder")
    plt.xlabel("Epoch")
    plt.ylabel("MSE Loss")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "autoencoder_loss.png"), dpi=150)
    plt.close()
    print("[✓] Saved: reports/autoencoder_loss.png")

    # =========================
    # ERROR DISTRIBUTION
    # =========================
    plt.figure(figsize=(10, 6))
    plt.hist(mse_test[y_test_bin == 0], bins=50, alpha=0.7, label="Normal", color='blue', density=True)
    plt.hist(mse_test[y_test_bin == 1], bins=50, alpha=0.7, label="Anomaly", color='red', density=True)
    plt.axvline(threshold, color='black', linestyle='--',
                label=f'Threshold={threshold:.4f}')
    plt.xlabel("Reconstruction Error (MSE)")
    plt.ylabel("Density")
    plt.title("Autoencoder - Reconstruction Error Distribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "autoencoder_error_dist.png"), dpi=150)
    plt.close()
    print("[✓] Saved: reports/autoencoder_error_dist.png")

    # =========================
    # SAVE MODEL + THRESHOLD + METRICS
    # =========================
    model.save(os.path.join(MODELS_DIR, "autoencoder_model.keras"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "autoencoder_scaler.pkl"))
    joblib.dump({
        "threshold": float(threshold),
        "percentile": 95,
        "source": "normal_train_mse",
        "note": "Fit on Normal-train reconstruction MSE only; never recompute on test",
    }, os.path.join(MODELS_DIR, "autoencoder_threshold.pkl"))

    pd.DataFrame([{
        "MetricScope": "anomaly_class_binary",
        "Accuracy": acc,
        "Precision_Anomaly": prec,
        "Recall_Anomaly": rec,
        "F1_Anomaly": f1,
        "Precision_macro": prec_macro,
        "Recall_macro": rec_macro,
        "F1_macro": f1_macro,
        "FPR": fpr_val,
        "FNR": fnr_val,
        "ROC_AUC": roc_auc,
        "PR_AUC": pr_auc,
        "Threshold": float(threshold),
        "Train_Time_sec": train_sec,
        "Inference_ms_per_sample": infer_ms,
        "Architecture": "10→16→8→4→8→16→10",
        "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp),
    }]).to_csv(os.path.join(REPORTS_DIR, "autoencoder_metrics.csv"), index=False)

    print(f"\n[✓] Autoencoder training complete!")
    print(f"[*] ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f}")
    print(f"[*] Accuracy: {acc:.4f} | F1 (Anomaly): {f1:.4f}")


if __name__ == "__main__":
    main()
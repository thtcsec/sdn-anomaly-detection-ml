"""
Train Autoencoder - mô hình unsupervised phát hiện bất thường.
Ý tưởng: train chỉ với data NORMAL thật (không SMOTE), khi gặp attack
thì reconstruction error sẽ cao → phát hiện bất thường.

LƯU Ý: Autoencoder PHẢI train trên data normal GỐC (từ flow_stats.csv),
KHÔNG dùng train.csv đã SMOTE vì SMOTE tạo normal synthetic làm lệch threshold.

Chạy: python src/train_autoencoder.py
"""

import os
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    accuracy_score, f1_score, precision_score, recall_score
)

import tensorflow as tf
from tensorflow import keras

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
    'ip_proto',
    'tp_src',
    'tp_dst',
    'packet_count',
    'byte_count',
    'duration_sec',
    'packet_count_per_sec',
    'byte_count_per_sec',
    'packet_size_avg',
    'flow_duration'
]


# =========================
# MAIN
# =========================
def main():
    print("=" * 60)
    print("  AUTOENCODER TRAINING - SDN ANOMALY DETECTION")
    print("=" * 60)

    # ===================================================================
    # QUAN TRỌNG: Load data GỐC từ flow_stats.csv (KHÔNG dùng train.csv
    # đã SMOTE, vì SMOTE tạo normal synthetic → threshold bị lệch)
    # ===================================================================
    raw_csv = os.path.join(DATASET_DIR, "flow_stats.csv")
    df = pd.read_csv(raw_csv)
    print(f"[*] Loaded {len(df)} records from flow_stats.csv")

    # Extract features
    X = df[FEATURES]
    y_raw = df['label']

    # Encode labels: ddos=0, normal=1, portscan=2
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    print(f"[*] Label mapping: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    # Train/test split (same as preprocess.py: 80/20, stratified)
    from sklearn.model_selection import train_test_split
    X_train_all, X_test, y_train_all, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Chỉ lấy NORMAL THẬT để train (label==1)
    X_train_normal = X_train_all[y_train_all == 1]
    print(f"[*] Normal training samples (real, no SMOTE): {len(X_train_normal)}")
    print(f"[*] Test samples (all labels): {len(X_test)}")

    # =========================
    # SCALING
    # =========================
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_normal)
    X_test_scaled = scaler.transform(X_test)

    # =========================
    # AUTOENCODER MODEL (10 → 8 → 6 → 4 → 6 → 8 → 10)
    # =========================
    input_dim = X_train_scaled.shape[1]

    model = keras.Sequential([
        keras.layers.Input(shape=(input_dim,)),
        # Encoder
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(6, activation='relu'),
        keras.layers.Dense(4, activation='relu'),  # Bottleneck
        # Decoder
        keras.layers.Dense(6, activation='relu'),
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(input_dim, activation='linear')
    ])

    model.compile(optimizer='adam', loss='mse')
    model.summary()

    # =========================
    # TRAINING (with EarlyStopping)
    # =========================
    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )

    print("\n[*] Training Autoencoder...")
    history = model.fit(
        X_train_scaled,
        X_train_scaled,
        epochs=100,
        batch_size=32,
        validation_split=0.1,
        callbacks=[early_stop],
        verbose=1
    )
    print(f"[✓] Training stopped at epoch {len(history.history['loss'])}")

    # =========================
    # PREDICTION & THRESHOLD
    # =========================
    X_pred = model.predict(X_test_scaled, verbose=0)
    mse = np.mean(np.power(X_test_scaled - X_pred, 2), axis=1)

    # Threshold từ reconstruction error trên tập normal TRAIN
    X_train_pred = model.predict(X_train_scaled, verbose=0)
    mse_train = np.mean(np.power(X_train_scaled - X_train_pred, 2), axis=1)
    threshold = np.percentile(mse_train, 95)
    print(f"\n[*] Threshold (95th percentile of normal MSE): {threshold:.6f}")

    # =========================
    # BINARY CLASSIFICATION
    # =========================
    y_test_bin = (y_test != 1).astype(int)   # 0=normal, 1=anomaly
    y_pred_bin = (mse > threshold).astype(int)

    # =========================
    # EVALUATION
    # =========================
    acc = accuracy_score(y_test_bin, y_pred_bin)
    f1 = f1_score(y_test_bin, y_pred_bin)
    prec = precision_score(y_test_bin, y_pred_bin, zero_division=0)
    rec = recall_score(y_test_bin, y_pred_bin)

    print("\n" + "=" * 60)
    print("  AUTOENCODER EVALUATION (Binary: Normal vs Anomaly)")
    print("=" * 60)
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print("=" * 60)
    print(classification_report(y_test_bin, y_pred_bin,
                                target_names=['Normal', 'Anomaly']))

    # =========================
    # ROC CURVE
    # =========================
    fpr, tpr, _ = roc_curve(y_test_bin, mse)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2,
             label=f"Autoencoder (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle="--")
    plt.title("ROC Curve - Autoencoder")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "roc_curve_autoencoder.png"), dpi=150)
    plt.close()
    print(f"[✓] Saved: reports/roc_curve_autoencoder.png (AUC={roc_auc:.4f})")

    # =========================
    # CONFUSION MATRIX
    # =========================
    cm = confusion_matrix(y_test_bin, y_pred_bin)
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
    plt.hist(mse[y_test_bin == 0], bins=50, alpha=0.7, label="Normal", color='blue')
    plt.hist(mse[y_test_bin == 1], bins=50, alpha=0.7, label="Anomaly", color='red')
    plt.axvline(threshold, color='black', linestyle='--',
                label=f'Threshold={threshold:.4f}')
    plt.xlabel("Reconstruction Error (MSE)")
    plt.ylabel("Count")
    plt.title("Autoencoder - Reconstruction Error Distribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "autoencoder_error_dist.png"), dpi=150)
    plt.close()
    print("[✓] Saved: reports/autoencoder_error_dist.png")

    # =========================
    # SAVE MODEL
    # =========================
    model.save(os.path.join(MODELS_DIR, "autoencoder_model.keras"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "autoencoder_scaler.pkl"))

    print(f"\n[✓] Autoencoder training complete!")
    print(f"[*] AUC Score: {roc_auc:.4f}")
    print(f"[*] Accuracy: {acc:.4f}")
    print(f"[*] F1-Score: {f1:.4f}")


if __name__ == "__main__":
    main()
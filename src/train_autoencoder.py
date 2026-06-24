import os
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_curve, auc

import tensorflow as tf
from tensorflow import keras


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
    print("AUTOENCODER TRAINING - SDN ANOMALY DETECTION")
    print("=" * 60)

    # Load data
    train_df = pd.read_csv(os.path.join(DATASET_DIR, "train.csv"))
    test_df = pd.read_csv(os.path.join(DATASET_DIR, "test.csv"))

    X_train = train_df[FEATURES]
    y_train = train_df["label"]

    X_test = test_df[FEATURES]
    y_test = test_df["label"]

    # =========================
    # NORMAL ONLY TRAINING
    # =========================
    X_train_normal = X_train[y_train == 1]

    print(f"[*] Normal training samples: {len(X_train_normal)}")

    # =========================
    # SCALING
    # =========================
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_normal)
    X_test_scaled = scaler.transform(X_test)

    # =========================
    # AUTOENCODER MODEL
    # =========================
    input_dim = X_train_scaled.shape[1]

    model = keras.Sequential([
        keras.layers.Input(shape=(input_dim,)),

        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dropout(0.1),

        keras.layers.Dense(6, activation='relu'),
        keras.layers.Dropout(0.1),

        keras.layers.Dense(4, activation='relu'),

        keras.layers.Dense(6, activation='relu'),
        keras.layers.Dense(8, activation='relu'),

        keras.layers.Dense(input_dim, activation='linear')
    ])

    model.compile(optimizer='adam', loss='mse')

    # =========================
    # TRAINING
    # =========================
    history = model.fit(
        X_train_scaled,
        X_train_scaled,
        epochs=50,
        batch_size=32,
        validation_split=0.1,
        verbose=1
    )

    # =========================
    # PREDICTION
    # =========================
    X_pred = model.predict(X_test_scaled, verbose=0)
    mse = np.mean(np.power(X_test_scaled - X_pred, 2), axis=1)

    # threshold from normal train error
    X_train_pred = model.predict(X_train_scaled, verbose=0)
    mse_train = np.mean(np.power(X_train_scaled - X_train_pred, 2), axis=1)

    threshold = np.percentile(mse_train, 95)

    print("\n[*] Threshold (95 percentile):", threshold)

    # =========================
    # BINARY LABEL
    # =========================
    y_test_bin = (y_test != 1).astype(int)
    y_pred_bin = (mse > threshold).astype(int)

    # =========================
    # REPORT
    # =========================
    print("\n" + "=" * 60)
    print("AUTOENCODER EVALUATION")
    print("=" * 60)
    print(classification_report(y_test_bin, y_pred_bin))

    # =========================
    # ROC CURVE
    # =========================
    fpr, tpr, _ = roc_curve(y_test_bin, mse)
    roc_auc = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--")
    plt.title("ROC Curve - Autoencoder")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend()

    plt.savefig(os.path.join(REPORTS_DIR, "roc_curve_autoencoder.png"))
    plt.close()

    # =========================
    # LOSS PLOT
    # =========================
    plt.figure()
    plt.plot(history.history['loss'], label='train')
    plt.plot(history.history['val_loss'], label='val')
    plt.title("Training Loss - Autoencoder")
    plt.legend()

    plt.savefig(os.path.join(REPORTS_DIR, "autoencoder_loss.png"))
    plt.close()

    # =========================
    # SAVE ERROR DISTRIBUTION
    # =========================
    plt.figure()
    plt.hist(mse[y_test_bin == 0], bins=50, alpha=0.6, label="Normal")
    plt.hist(mse[y_test_bin == 1], bins=50, alpha=0.6, label="Anomaly")
    plt.legend()
    plt.title("Reconstruction Error Distribution")

    plt.savefig(os.path.join(REPORTS_DIR, "autoencoder_error_dist.png"))
    plt.close()

    # =========================
    # SAVE MODEL
    # =========================
    model.save(os.path.join(MODELS_DIR, "autoencoder_model.keras"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "autoencoder_scaler.pkl"))

    print("\n[✓] Model saved successfully")
    print("[✓] Training complete!")


if __name__ == "__main__":
    main()
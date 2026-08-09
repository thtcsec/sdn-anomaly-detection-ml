"""
Đồng bộ threshold AE + metrics AE/IF với model đã train (không cần retrain).

- Tái tạo đúng split AE (flow_stats, 80/20, seed=42)
- Threshold = 95th percentile MSE trên Normal-TRAIN
- Lưu models/autoencoder_threshold.pkl
- Lưu reports/autoencoder_metrics.csv (anomaly-class + macro + FPR/FNR)
- Lưu reports/isolation_forest_metrics.csv từ test.csv
- Cập nhật hàng Autoencoder trong reports/model_comparison.csv theo metrics AE

Chạy: python src/sync_ae_threshold_metrics.py
"""

from __future__ import annotations

import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
    auc,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

FEATURES = [
    "ip_proto",
    "tp_src",
    "tp_dst",
    "packet_count",
    "byte_count",
    "duration_sec",
    "packet_count_per_sec",
    "byte_count_per_sec",
    "packet_size_avg",
    "flow_duration",
]


def _load_keras():
    os.environ.setdefault("TF_USE_LEGACY_KERAS", "1")
    try:
        from tensorflow import keras
        return keras
    except Exception:
        import tf_keras as keras
        return keras


def sync_autoencoder():
    keras = _load_keras()
    model = keras.models.load_model(os.path.join(MODELS_DIR, "autoencoder_model.keras"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "autoencoder_scaler.pkl"))

    df = pd.read_csv(os.path.join(DATASET_DIR, "flow_stats.csv"))
    X = df[FEATURES]
    y = LabelEncoder().fit_transform(df["label"])
    X_train_all, X_test, y_train_all, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train_normal = X_train_all[y_train_all == 1]

    X_tr = scaler.transform(X_train_normal)
    X_te = scaler.transform(X_test)
    mse_train = np.mean(np.power(X_tr - model.predict(X_tr, verbose=0), 2), axis=1)
    threshold = float(np.percentile(mse_train, 95))

    mse = np.mean(np.power(X_te - model.predict(X_te, verbose=0), 2), axis=1)
    y_true = (y_test != 1).astype(int)
    y_pred = (mse > threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    prec_m = precision_score(y_true, y_pred, average="macro", zero_division=0)
    rec_m = recall_score(y_true, y_pred, average="macro")
    f1_m = f1_score(y_true, y_pred, average="macro")
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    fpr_c, tpr_c, _ = roc_curve(y_true, mse)
    roc_auc = auc(fpr_c, tpr_c)

    joblib.dump(
        {
            "threshold": threshold,
            "percentile": 95,
            "source": "normal_train_mse",
            "note": "synced from existing model; matches autoencoder_error_dist.png",
        },
        os.path.join(MODELS_DIR, "autoencoder_threshold.pkl"),
    )
    metrics = {
        "MetricScope": "anomaly_class_binary",
        "Accuracy": acc,
        "Precision_Anomaly": prec,
        "Recall_Anomaly": rec,
        "F1_Anomaly": f1,
        "Precision_macro": prec_m,
        "Recall_macro": rec_m,
        "F1_macro": f1_m,
        "FPR": fpr,
        "FNR": fnr,
        "AUC": roc_auc,
        "Threshold": threshold,
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
    }
    pd.DataFrame([metrics]).to_csv(
        os.path.join(REPORTS_DIR, "autoencoder_metrics.csv"), index=False
    )
    print("[AE] threshold=", threshold)
    print("[AE] Acc/P/R/F1 (Anomaly)=", round(acc, 6), round(prec, 6), round(rec, 6), round(f1, 6))
    print("[AE] CM TN/FP/FN/TP=", tn, fp, fn, tp)
    return metrics


def sync_isolation_forest():
    model = joblib.load(os.path.join(MODELS_DIR, "isolation_forest_model.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR, "isolation_forest_scaler.pkl"))
    test_df = pd.read_csv(os.path.join(DATASET_DIR, "test.csv"))
    X_test = test_df.drop("label", axis=1)
    y_test = test_df["label"]
    X_scaled = scaler.transform(X_test)
    y_pred = (model.predict(X_scaled) == -1).astype(int)
    y_true = (y_test != 1).astype(int)
    scores = -model.decision_function(X_scaled)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    metrics = {
        "MetricScope": "anomaly_class_binary",
        "Accuracy": accuracy_score(y_true, y_pred),
        "Precision_Anomaly": precision_score(y_true, y_pred, zero_division=0),
        "Recall_Anomaly": recall_score(y_true, y_pred),
        "F1_Anomaly": f1_score(y_true, y_pred),
        "Precision_macro": precision_score(y_true, y_pred, average="macro", zero_division=0),
        "Recall_macro": recall_score(y_true, y_pred, average="macro"),
        "F1_macro": f1_score(y_true, y_pred, average="macro"),
        "FPR": fp / (fp + tn) if (fp + tn) else 0.0,
        "FNR": fn / (fn + tp) if (fn + tp) else 0.0,
        "AUC": roc_auc_score(y_true, scores),
        "contamination": 0.05,
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
        "score_note": "plot uses -decision_function (sklearn), not Liu s(x) in 0..1",
    }
    pd.DataFrame([metrics]).to_csv(
        os.path.join(REPORTS_DIR, "isolation_forest_metrics.csv"), index=False
    )
    print("[IF] Acc/P/R/F1 (Anomaly)=",
          round(metrics["Accuracy"], 6),
          round(metrics["Precision_Anomaly"], 6),
          round(metrics["Recall_Anomaly"], 6),
          round(metrics["F1_Anomaly"], 6))
    print("[IF] FPR/FNR=", round(metrics["FPR"], 6), round(metrics["FNR"], 6))
    print("[IF] CM TN/FP/FN/TP=", tn, fp, fn, tp)
    return metrics


def patch_model_comparison(ae: dict, iso: dict):
    path = os.path.join(REPORTS_DIR, "model_comparison.csv")
    df = pd.read_csv(path)
    # Keep XGB/RF macro; AE/IF = anomaly-class numbers matching CM
    for model, m in (("Autoencoder", ae), ("Isolation Forest", iso)):
        mask = df["Model"] == model
        if not mask.any():
            continue
        df.loc[mask, "Accuracy"] = m["Accuracy"]
        df.loc[mask, "Precision"] = m["Precision_Anomaly"]
        df.loc[mask, "Recall"] = m["Recall_Anomaly"]
        df.loc[mask, "F1-Score"] = m["F1_Anomaly"]
        if "Classification" in df.columns:
            df.loc[mask, "Classification"] = "Binary (P/R/F1=Anomaly-class)"
    df.to_csv(path, index=False)
    note = os.path.join(REPORTS_DIR, "METRICS_SCOPE_NOTE.txt")
    with open(note, "w", encoding="utf-8") as f:
        f.write(
            "XGBoost / Random Forest: Accuracy + Precision/Recall/F1 = MACRO (multiclass).\n"
            "Autoencoder / Isolation Forest: Accuracy = binary overall; "
            "Precision/Recall/F1 = Anomaly-class (positive=Anomaly), NOT macro.\n"
            "AE Threshold = 95th percentile of Normal-TRAIN reconstruction MSE "
            f"(saved in models/autoencoder_threshold.pkl).\n"
            f"AE Threshold value: {ae['Threshold']:.6f}\n"
            "Do NOT recompute AE threshold on test normals.\n"
        )
    print("[✓] Updated", path)
    print("[✓] Wrote", note)


def main():
    ae = sync_autoencoder()
    iso = sync_isolation_forest()
    patch_model_comparison(ae, iso)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        raise

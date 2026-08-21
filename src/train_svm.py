"""
Train LinearSVC for the live demo (5th supervised model).

Same deploy pipeline as RF/XGB: dataset/train.csv + test.csv, 10 FEATURE_COLS
including tp_src/tp_dst, 3-class labels 0/1/2 (ddos/normal/portscan).
LinearSVC (liblinear, dual=False) — no TensorFlow, fast to unpickle on eventlet.

This pickle is for the SOC dropdown. Thesis LOSO numbers use a separate
8-feature no-port binary protocol; do not mix those Acc figures with this demo.

Chạy: python src/train_svm.py
"""

from __future__ import annotations

import os
import sys
import time

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

TRAIN_CSV = os.path.join(DATASET_DIR, "train.csv")
TEST_CSV = os.path.join(DATASET_DIR, "test.csv")
LABEL_NAMES = ["ddos", "normal", "portscan"]

FEATURE_COLS = [
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


def load_train_test():
    if not os.path.exists(TRAIN_CSV) or not os.path.exists(TEST_CSV):
        print("[!] Train/Test files not found. Run preprocess.py first.")
        sys.exit(1)

    train_df = pd.read_csv(TRAIN_CSV)
    test_df = pd.read_csv(TEST_CSV)
    missing = [c for c in FEATURE_COLS + ["label"] if c not in train_df.columns]
    if missing:
        print(f"[!] train.csv missing columns: {missing}")
        sys.exit(1)

    X_train = train_df[FEATURE_COLS]
    y_train = train_df["label"].astype(int)
    X_test = test_df[FEATURE_COLS]
    y_test = test_df["label"].astype(int)
    print(f"[*] Train: {X_train.shape}, Test: {X_test.shape}")
    print(f"[*] Train label distribution:\n{y_train.value_counts().sort_index()}")
    return X_train, X_test, y_train, y_test


def main():
    print("=" * 60)
    print("  LinearSVC (SVM) Training - SDN Anomaly Detection")
    print("=" * 60)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    X_train, X_test, y_train, y_test = load_train_test()

    scaler = StandardScaler()
    X_train_s = pd.DataFrame(scaler.fit_transform(X_train), columns=FEATURE_COLS)
    X_test_s = pd.DataFrame(scaler.transform(X_test), columns=FEATURE_COLS)

    # dual=False: n_samples >> n_features; no RBF (too slow to unpickle/predict in demo).
    model = LinearSVC(
        C=1.0,
        dual=False,
        max_iter=4000,
        class_weight="balanced",
        random_state=42,
    )

    t0 = time.perf_counter()
    model.fit(X_train_s, y_train)
    train_sec = time.perf_counter() - t0
    print(f"[✓] LinearSVC training complete! ({train_sec:.3f}s)")
    print(f"[*] classes_={list(model.classes_)}")

    t1 = time.perf_counter()
    y_pred = model.predict(X_test_s)
    predict_batch_sec = time.perf_counter() - t1

    sample_df = X_test_s.iloc[:1]
    model.predict(sample_df)
    t2 = time.perf_counter()
    n_runs = 1000
    for _ in range(n_runs):
        model.predict(sample_df)
    infer_ms = (time.perf_counter() - t2) * 1000.0 / n_runs

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
    rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print("\n" + "=" * 60)
    print("  LINEARSVC RESULTS (deploy pickle — not LOSO table)")
    print("=" * 60)
    print(f"  Accuracy:          {acc:.6f}")
    print(f"  Precision (macro): {prec:.6f}")
    print(f"  Recall (macro):    {rec:.6f}")
    print(f"  F1-Score (macro):  {f1:.6f}")
    print(f"  F1-Score (weighted): {f1_weighted:.6f}")
    print(f"  Train time:        {train_sec:.3f}s")
    print(f"  Predict (test):    {predict_batch_sec:.3f}s")
    print(f"  Inference/sample:  {infer_ms:.3f} ms")
    print("=" * 60)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES, digits=4))

    metrics = {
        "Model": "LinearSVC",
        "Approach": "Supervised",
        "Classification": "Multiclass",
        "Accuracy": acc,
        "Precision_macro": prec,
        "Recall_macro": rec,
        "F1_macro": f1,
        "F1_weighted": f1_weighted,
        "Train_Time_sec": train_sec,
        "Predict_Test_sec": predict_batch_sec,
        "Inference_ms_per_sample": infer_ms,
        "n_features": len(FEATURE_COLS),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "note": "deploy pickle; random-split train.csv; not thesis LOSO",
    }
    pd.DataFrame([metrics]).to_csv(
        os.path.join(REPORTS_DIR, "svm_metrics.csv"), index=False
    )
    print("[✓] Saved: reports/svm_metrics.csv")

    report_dict = classification_report(
        y_test, y_pred, target_names=LABEL_NAMES, digits=4, output_dict=True
    )
    rows = []
    for cls in LABEL_NAMES:
        rows.append({
            "Class": cls,
            "Precision": report_dict[cls]["precision"],
            "Recall": report_dict[cls]["recall"],
            "F1-Score": report_dict[cls]["f1-score"],
            "Support": int(report_dict[cls]["support"]),
        })
    pd.DataFrame(rows).to_csv(
        os.path.join(REPORTS_DIR, "svm_classification_report.csv"),
        index=False,
    )
    print("[✓] Saved: reports/svm_classification_report.csv")

    joblib.dump(model, os.path.join(MODELS_DIR, "svm_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "svm_scaler.pkl"))
    print("[✓] Saved: models/svm_model.pkl")
    print("[✓] Saved: models/svm_scaler.pkl")
    print("\n[✓] LinearSVC training complete!")


if __name__ == "__main__":
    main()

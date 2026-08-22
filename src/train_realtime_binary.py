"""Train the final 8-feature binary artifact used by the realtime controller.

Hyperparameters and preprocessing match the primary LOSO Random Forest
benchmark. LOSO metrics remain in ``reports/binary_realtime_loso_*.csv``;
this script fits the frozen deployment configuration on all clean runs only
after model selection. It never reports resubstitution accuracy.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from model_catalog import PORT_AGNOSTIC_FEATURE_COLS, model_task
from realtime_protocol import BASE_DIR, early_poll_snapshots, load_clean_independent


MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
MODEL_NAME = "random_forest_binary"


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    data_path = os.path.join(BASE_DIR, "dataset", "flow_stats_grouped.csv")
    polls = load_clean_independent(data_path)
    df = early_poll_snapshots(polls, max_polls=3)
    X = df[PORT_AGNOSTIC_FEATURE_COLS]
    y = (df["label"].to_numpy() != "normal").astype(int)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    started = time.perf_counter()
    model.fit(X_scaled, y)
    train_seconds = time.perf_counter() - started
    training_hyperparameters = model.get_params()
    # Parallel tree dispatch dominates batch-size-1 latency. Keep training
    # parallel, but persist single-thread inference for the controller.
    model.n_jobs = 1

    model_path = os.path.join(MODELS_DIR, "random_forest_binary_realtime.pkl")
    scaler_path = os.path.join(MODELS_DIR, "random_forest_binary_realtime_scaler.pkl")
    manifest_path = os.path.join(MODELS_DIR, "random_forest_binary_realtime_manifest.json")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    # Exact artifact path: scaler + predict, batch size 1, with warm-up.
    rng = np.random.default_rng(42)
    sample_idx = rng.choice(len(X), size=min(1000, len(X)), replace=False)
    for idx in sample_idx[:20]:
        model.predict(scaler.transform(X.iloc[[int(idx)]]))
    latency_ms = []
    for idx in sample_idx:
        t0 = time.perf_counter_ns()
        model.predict(scaler.transform(X.iloc[[int(idx)]]))
        latency_ms.append((time.perf_counter_ns() - t0) / 1_000_000.0)

    manifest = {
        "artifact_name": MODEL_NAME,
        "task": model_task(MODEL_NAME),
        "labels": {"0": "NORMAL", "1": "ANOMALY"},
        "feature_columns": PORT_AGNOSTIC_FEATURE_COLS,
        "n_features": len(PORT_AGNOSTIC_FEATURE_COLS),
        "training_protocol": "all clean independent runs after frozen LOSO model selection; first 3 tuple polls; no raw ports; no SMOTE",
        "evaluation_reports": [
            "reports/binary_realtime_loso_summary.csv",
            "reports/binary_realtime_loso_per_scenario.csv",
        ],
        "dataset": os.path.relpath(data_path, BASE_DIR).replace("\\", "/"),
        "dataset_sha256": _sha256(data_path),
        "n_training_snapshots": int(len(df)),
        "n_runs": int(df["run_id"].nunique()),
        "n_scenarios": int(df["scenario_id"].nunique()),
        "class_counts": {
            "normal": int((y == 0).sum()),
            "attack": int((y == 1).sum()),
        },
        "training_hyperparameters": training_hyperparameters,
        "inference_n_jobs": 1,
        "train_seconds": float(train_seconds),
        "batch1_latency_ms": {
            "n": int(len(latency_ms)),
            "p50": float(np.percentile(latency_ms, 50)),
            "p95": float(np.percentile(latency_ms, 95)),
            "p99": float(np.percentile(latency_ms, 99)),
            "scope": "scaler.transform + model.predict; excludes FlowStats polling and feature extraction",
        },
        "runtime": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
    pd.DataFrame([{
        "artifact": MODEL_NAME,
        "n_training_snapshots": len(df),
        "train_seconds": train_seconds,
        "latency_batch1_p50_ms": np.percentile(latency_ms, 50),
        "latency_batch1_p95_ms": np.percentile(latency_ms, 95),
        "latency_batch1_p99_ms": np.percentile(latency_ms, 99),
        "accuracy_note": "Not reported on fit data; use binary_realtime_loso_summary.csv",
    }]).to_csv(os.path.join(REPORTS_DIR, "realtime_binary_artifact_benchmark.csv"), index=False)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

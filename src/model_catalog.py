"""Realtime model artifacts — no fake fallbacks.

XGBoost / Random Forest: 10-feature multiclass (ddos/normal/portscan).
Isolation Forest / Autoencoder: binary Normal vs Anomaly. They cannot
emit DDoS vs Portscan; do not invent those labels.
"""

from __future__ import annotations

import os

ALLOWED_MODELS = (
    "xgboost",
    "random_forest",
    "isolation_forest",
    "autoencoder",
)

MULTICLASS_MODELS = ("xgboost", "random_forest")
BINARY_MODELS = ("isolation_forest", "autoencoder")

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


def artifact_paths(models_dir: str, name: str) -> dict[str, str]:
    name = str(name).lower()
    if name == "xgboost":
        return {
            "model": os.path.join(models_dir, "xgboost_model.pkl"),
            "scaler": os.path.join(models_dir, "scaler.pkl"),
        }
    if name == "random_forest":
        return {
            "model": os.path.join(models_dir, "random_forest_model.pkl"),
            "scaler": os.path.join(models_dir, "random_forest_scaler.pkl"),
        }
    if name == "isolation_forest":
        return {
            "model": os.path.join(models_dir, "isolation_forest_model.pkl"),
            "scaler": os.path.join(models_dir, "isolation_forest_scaler.pkl"),
        }
    if name == "autoencoder":
        return {
            "model": os.path.join(models_dir, "autoencoder_model.keras"),
            "scaler": os.path.join(models_dir, "autoencoder_scaler.pkl"),
            "threshold": os.path.join(models_dir, "autoencoder_threshold.pkl"),
        }
    return {}


def missing_artifacts(models_dir: str, name: str) -> list[str]:
    return [p for p in artifact_paths(models_dir, name).values() if not os.path.isfile(p)]


def inventory(models_dir: str) -> dict[str, dict]:
    out = {}
    for name in ALLOWED_MODELS:
        miss = missing_artifacts(models_dir, name)
        out[name] = {
            "available": not miss,
            "task": "multiclass" if name in MULTICLASS_MODELS else "binary_anomaly",
            "missing": [os.path.basename(p) for p in miss],
        }
    return out


def train_hint(name: str) -> str:
    scripts = {
        "xgboost": "python src/train_xgboost.py",
        "random_forest": "python src/train_random_forest.py",
        "isolation_forest": "python src/train_isolation_forest.py",
        "autoencoder": "python src/train_autoencoder.py",
    }
    return scripts.get(name, "")

"""Realtime artifact catalog with an explicit task and feature schema.

The thesis deployment artifact is ``random_forest_binary``: binary
Normal-vs-Attack, eight port-agnostic features. Older 10-feature multiclass
artifacts remain available for reproducibility and are labelled as legacy.
"""

from __future__ import annotations

import os

# WSL/SOC has no NVIDIA GPU. Must be set before libxgboost.so loads.
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")

ALLOWED_MODELS = (
    "random_forest_binary",
    "xgboost",
    "random_forest",
    "svm",
    "isolation_forest",
    "autoencoder",
)

MULTICLASS_MODELS = ("xgboost", "random_forest", "svm")
BINARY_MODELS = ("random_forest_binary", "isolation_forest", "autoencoder")

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

PORT_AGNOSTIC_FEATURE_COLS = [
    col for col in FEATURE_COLS if col not in ("tp_src", "tp_dst")
]


def feature_columns(name: str) -> list[str]:
    """Return the exact ordered schema used by one artifact."""
    if str(name).lower() == "random_forest_binary":
        return list(PORT_AGNOSTIC_FEATURE_COLS)
    return list(FEATURE_COLS)


def model_task(name: str) -> str:
    name = str(name).lower()
    if name == "random_forest_binary":
        return "binary_anomaly_port_agnostic"
    if name in MULTICLASS_MODELS:
        return "legacy_multiclass_with_raw_ports"
    return "binary_anomaly_with_raw_ports"


def artifact_paths(models_dir: str, name: str) -> dict[str, str]:
    name = str(name).lower()
    if name == "random_forest_binary":
        return {
            "model": os.path.join(models_dir, "random_forest_binary_realtime.pkl"),
            "scaler": os.path.join(models_dir, "random_forest_binary_realtime_scaler.pkl"),
            "manifest": os.path.join(models_dir, "random_forest_binary_realtime_manifest.json"),
        }
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
    if name == "svm":
        return {
            "model": os.path.join(models_dir, "svm_model.pkl"),
            "scaler": os.path.join(models_dir, "svm_scaler.pkl"),
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
            "task": model_task(name),
            "features": feature_columns(name),
            "n_features": len(feature_columns(name)),
            "missing": [os.path.basename(p) for p in miss],
        }
    return out


def train_hint(name: str) -> str:
    scripts = {
        "random_forest_binary": "python src/train_realtime_binary.py",
        "xgboost": "python src/train_xgboost.py",
        "random_forest": "python src/train_random_forest.py",
        "svm": "python src/train_svm.py",
        "isolation_forest": "python src/train_isolation_forest.py",
        "autoencoder": "python src/train_autoencoder.py",
    }
    return scripts.get(name, "")


def force_xgboost_cpu(model) -> None:
    """Keep predict on CPU after unpickle. No-op if the API is missing."""
    booster = model
    getter = getattr(model, "get_booster", None)
    if callable(getter):
        try:
            booster = getter()
        except Exception:
            booster = model
    setter = getattr(booster, "set_param", None)
    if callable(setter):
        try:
            setter({"device": "cpu"})
            return
        except Exception:
            pass
        try:
            setter({"predictor": "cpu_predictor"})
        except Exception:
            pass
    params = getattr(model, "set_params", None)
    if callable(params):
        try:
            params(device="cpu")
        except Exception:
            pass

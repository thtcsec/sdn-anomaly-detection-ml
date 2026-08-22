"""
Protocol D/E evaluation on the fault dataset (poll snapshots).

Does not touch the anomaly 326k pool.
Ground-truth columns are never used as features.

  D1 — Normal vs Fault (detection). Five models: RF, XGB, SVM, IsolationForest, Autoencoder.
        IF/AE train on Normal-only of each LOSO train fold (scaler fit on that subset).
        AE threshold = 95th percentile of train-normal reconstruction MSE (same as anomaly LOSO).
  D2 — 4-class family (normal / bandwidth / loss / delay). RF, XGB, SVM only.
        IF/AE = N/A: unsupervised models cannot assign 4 family labels without a supervised head.
  Rule-based baseline on the same telemetry (RTT / loss / throughput)

  python src/eval_fault_loso.py --data dataset/fault_stats_grouped.csv --prefix fault_protocol_d
  python src/eval_fault_loso.py --data dataset/fault_stats_grouped_e.csv --prefix fault_protocol_e
"""

from __future__ import annotations

import argparse
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import SVC

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import FAULT_FORBIDDEN_FEATURES, FAULT_MODEL_FEATURES  # noqa: E402

# Keras is preferred (thesis models/). sklearn MLP is the CPU fallback if TF is absent.
_AE_BACKEND: str | None = None
_AE_BACKEND_NOTE = ""
_AE_KERAS = None

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DEFAULT = os.path.join(BASE_DIR, "dataset", "fault_stats_grouped.csv")
OUT_DIR = os.path.join(BASE_DIR, "reports")
FAMILIES = ("normal", "bandwidth", "loss", "delay")


def _load(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Missing {path}. Collect then merge:\n"
            "  python controller/run_fault_monitor.py\n"
            "  sudo python3 src/collect_independent_fault_runs.py --protocol e\n"
            "  python src/merge_fault_runs.py --protocol e"
        )
    df = pd.read_csv(path)
    leaked = [c for c in FAULT_FORBIDDEN_FEATURES if c in FAULT_MODEL_FEATURES]
    if leaked:
        raise RuntimeError(f"schema leak: {leaked}")
    return df


def _steady_state(df: pd.DataFrame) -> pd.DataFrame:
    """Drop start/end polls of each run (empty flow tables after killall)."""
    if "run_id" not in df.columns:
        return df
    work = df.copy()
    if "timestamp" in work.columns:
        work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce")
        work = work.sort_values(["run_id", "timestamp"])

    def trim(g: pd.DataFrame) -> pd.DataFrame:
        n = len(g)
        if n <= 4:
            return g.iloc[1:-1] if n > 2 else g
        return g.iloc[2:-2]

    parts = []
    for rid, g in work.groupby("run_id"):
        t = trim(g).copy()
        t["run_id"] = rid
        parts.append(t)
    if not parts:
        return df.iloc[0:0].copy()
    trimmed = pd.concat(parts, ignore_index=True)
    if "n_flows" in trimmed.columns:
        trimmed = trimmed[trimmed["n_flows"].fillna(0).astype(float) > 0]
    return trimmed.reset_index(drop=True)


def _xy(df: pd.DataFrame, y: pd.Series):
    cols = [c for c in FAULT_MODEL_FEATURES if c in df.columns]
    leaked = set(cols) & set(FAULT_FORBIDDEN_FEATURES)
    if leaked:
        raise RuntimeError(f"refusing leak features: {leaked}")
    X = df[cols].apply(pd.to_numeric, errors="coerce")
    groups = df["scenario_id"].astype(str)
    return X, y.astype(str), groups, cols


def _impute_fold(
    X_train: pd.DataFrame, X_test: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Fit missing-value statistics on the train fold only.

    ``keep_empty_features`` preserves the declared schema even when a probe
    column (for example jitter) is entirely absent in one training fold.
    """
    imputer = SimpleImputer(
        strategy="median", keep_empty_features=True, fill_value=0.0,
    )
    train_arr = imputer.fit_transform(X_train)
    test_arr = imputer.transform(X_test)
    return (
        pd.DataFrame(train_arr, columns=X_train.columns, index=X_train.index),
        pd.DataFrame(test_arr, columns=X_test.columns, index=X_test.index),
    )


def _rule_thresholds(X: pd.DataFrame, y: pd.Series) -> dict[str, float]:
    """Calibrate on Normal rows of the *train* fold only."""
    nmask = y.astype(str) == "normal"
    if int(nmask.sum()) < 3:
        nmask = pd.Series(True, index=y.index)

    def col(name, fill):
        if name not in X.columns:
            return pd.Series([fill])
        return pd.to_numeric(X.loc[nmask, name], errors="coerce")

    loss = col("probe_loss_pct", 0.0)
    uloss = col("udp_lost_pct", 0.0)
    rtt = col("rtt_mean_ms", 1.0)
    thr = col("throughput_mbps", 10.0)
    return {
        "loss": float(max(2.0, np.nanpercentile(loss.fillna(0.0), 95))),
        "uloss": float(max(3.0, np.nanpercentile(uloss.fillna(0.0), 95))),
        "rtt": float(max(20.0, np.nanpercentile(rtt.fillna(0.0), 95) * 2.0)),
        "thr": float(max(0.5, np.nanpercentile(thr.fillna(np.nan), 25) * 0.5)) if thr.notna().any() else 1.0,
    }


def _rule_predict_4(X: pd.DataFrame, thr: dict[str, float]) -> np.ndarray:
    loss = pd.to_numeric(X.get("probe_loss_pct", 0), errors="coerce").fillna(0.0).to_numpy()
    uloss = pd.to_numeric(X.get("udp_lost_pct", 0), errors="coerce").fillna(0.0).to_numpy()
    rtt = pd.to_numeric(X.get("rtt_mean_ms", 0), errors="coerce").fillna(0.0).to_numpy()
    tput = pd.to_numeric(X.get("throughput_mbps", np.nan), errors="coerce").to_numpy()
    pred = np.full(len(X), "normal", dtype=object)
    pred[np.nan_to_num(tput, nan=np.inf) <= thr["thr"]] = "bandwidth"
    pred[rtt >= thr["rtt"]] = "delay"
    pred[(loss >= thr["loss"]) | (uloss >= thr.get("uloss", 3.0))] = "loss"
    return pred


def _rule_predict_bin(X: pd.DataFrame, thr: dict[str, float]) -> np.ndarray:
    four = _rule_predict_4(X, thr)
    return np.where(four == "normal", "normal", "fault")


def _loso_ml(name: str, factory, X, y, groups) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    enc = LabelEncoder()
    y_enc = enc.fit_transform(y)
    logo = LeaveOneGroupOut()
    rows = []
    yt_all, yp_all = [], []
    for train_idx, test_idx in logo.split(X, y_enc, groups):
        sc = groups.iloc[test_idx].iloc[0]
        X_train, X_test = _impute_fold(X.iloc[train_idx], X.iloc[test_idx])
        scaler = StandardScaler()
        Xtr = scaler.fit_transform(X_train)
        Xte = scaler.transform(X_test)
        clf = factory()
        clf.fit(Xtr, y_enc[train_idx])
        pred = clf.predict(Xte)
        yt, yp = y_enc[test_idx], pred
        yt_all.append(yt)
        yp_all.append(yp)
        rows.append({
            "model": name,
            "held_out_scenario": sc,
            "n_test": int(len(test_idx)),
            "accuracy": float(accuracy_score(yt, yp)),
            "f1_macro": float(f1_score(yt, yp, average="macro", zero_division=0)),
        })
    yt_cat = np.concatenate(yt_all)
    yp_cat = np.concatenate(yp_all)
    rows.append({
        "model": name,
        "held_out_scenario": "_pooled",
        "n_test": int(len(yt_cat)),
        "accuracy": float(accuracy_score(yt_cat, yp_cat)),
        "f1_macro": float(f1_score(yt_cat, yp_cat, average="macro", zero_division=0)),
    })
    return pd.DataFrame(rows), enc.inverse_transform(yt_cat), enc.inverse_transform(yp_cat)


def _loso_rule(task: str, X, y, groups) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    logo = LeaveOneGroupOut()
    dummy = np.zeros(len(y))
    rows = []
    yt_all, yp_all = [], []
    y = y.astype(str)
    for train_idx, test_idx in logo.split(dummy, dummy, groups):
        sc = groups.iloc[test_idx].iloc[0]
        y_train = y.iloc[train_idx]
        thr = _rule_thresholds(X.iloc[train_idx], y_train)
        Xte = X.iloc[test_idx]
        if task == "d1":
            pred = _rule_predict_bin(Xte, thr)
        else:
            pred = _rule_predict_4(Xte, thr)
        yt = y.iloc[test_idx].to_numpy()
        yt_all.append(yt)
        yp_all.append(pred)
        rows.append({
            "model": "rule_based",
            "held_out_scenario": sc,
            "n_test": int(len(test_idx)),
            "accuracy": float(accuracy_score(yt, pred)),
            "f1_macro": float(f1_score(yt, pred, average="macro", zero_division=0)),
        })
    yt_cat = np.concatenate(yt_all)
    yp_cat = np.concatenate(yp_all)
    rows.append({
        "model": "rule_based",
        "held_out_scenario": "_pooled",
        "n_test": int(len(yt_cat)),
        "accuracy": float(accuracy_score(yt_cat, yp_cat)),
        "f1_macro": float(f1_score(yt_cat, yp_cat, average="macro", zero_division=0)),
    })
    return pd.DataFrame(rows), yt_cat, yp_cat


def _resolve_ae_backend() -> str:
    """Prefer Keras/TF (thesis AE). Fall back to sklearn MLP. Never fake 4-class."""
    global _AE_BACKEND, _AE_BACKEND_NOTE, _AE_KERAS
    if _AE_BACKEND is not None:
        return _AE_BACKEND
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
    os.environ.setdefault("TF_NUM_INTRAOP_THREADS", "2")
    os.environ.setdefault("TF_NUM_INTEROP_THREADS", "1")
    os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")
    # TF 2.21 + Keras 3: TF_USE_LEGACY_KERAS=1 breaks `from tensorflow import keras`
    # unless tf_keras is installed. Do not set it.
    os.environ.pop("TF_USE_LEGACY_KERAS", None)
    print("  [autoencoder] importing keras (WSL/CPU; first import can take minutes)...", flush=True)
    try:
        from tensorflow import keras as tf_keras  # type: ignore
        _AE_KERAS = tf_keras
        _AE_BACKEND = "keras"
        _AE_BACKEND_NOTE = "keras/tensorflow CPU (Keras 3)"
        print(f"  [autoencoder] backend={_AE_BACKEND_NOTE}", flush=True)
        return _AE_BACKEND
    except Exception as exc:
        print(f"  [autoencoder] tensorflow.keras failed: {type(exc).__name__}: {exc}", flush=True)
    try:
        import tf_keras as tf_keras  # type: ignore
        _AE_KERAS = tf_keras
        _AE_BACKEND = "keras"
        _AE_BACKEND_NOTE = "tf_keras CPU"
        return _AE_BACKEND
    except ImportError:
        pass
    _AE_BACKEND = "sklearn"
    _AE_BACKEND_NOTE = "sklearn MLPRegressor (TensorFlow missing in this env)"
    return _AE_BACKEND


def _train_normal(X_train: pd.DataFrame, y_train: pd.Series) -> pd.DataFrame:
    """Normal-only rows of the train fold. Never mix fault into unsupervised fit."""
    Xn = X_train.loc[y_train.astype(str) == "normal"]
    if len(Xn) == 0:
        raise RuntimeError("train fold has no Normal rows for unsupervised fit")
    return Xn


def _impute_normal_only_fold(
    X_train: pd.DataFrame, y_train: pd.Series, X_test: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Fit one-class preprocessing on train-normal rows only."""
    Xn_raw = _train_normal(X_train, y_train)
    imputer = SimpleImputer(
        strategy="median", keep_empty_features=True, fill_value=0.0,
    )
    normal_arr = imputer.fit_transform(Xn_raw)
    test_arr = imputer.transform(X_test)
    return (
        pd.DataFrame(normal_arr, columns=X_train.columns, index=Xn_raw.index),
        pd.DataFrame(test_arr, columns=X_test.columns, index=X_test.index),
    )


def _if_predict_fold(X_train: pd.DataFrame, y_train: pd.Series, X_test: pd.DataFrame) -> np.ndarray:
    """IsolationForest on Normal-only; contamination=0.05 matches anomaly LOSO."""
    Xn, X_test = _impute_normal_only_fold(X_train, y_train, X_test)
    scaler = StandardScaler()
    clf = IsolationForest(
        n_estimators=200, contamination=0.05, random_state=42, n_jobs=1,
    )
    clf.fit(scaler.fit_transform(Xn))
    pred = clf.predict(scaler.transform(X_test))
    return np.where(pred == -1, "fault", "normal")


def _ae_reconstruct(Xn: np.ndarray, Xt: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    backend = _resolve_ae_backend()
    n_in = int(Xn.shape[1])
    if backend == "keras":
        keras = _AE_KERAS
        try:
            keras.backend.clear_session()
        except Exception:
            pass
        if hasattr(keras, "utils") and hasattr(keras.utils, "set_random_seed"):
            keras.utils.set_random_seed(42)
        model = keras.Sequential([
            keras.layers.Input(shape=(n_in,)),
            keras.layers.Dense(16, activation="relu"),
            keras.layers.Dense(8, activation="relu"),
            keras.layers.Dense(4, activation="relu"),
            keras.layers.Dense(8, activation="relu"),
            keras.layers.Dense(16, activation="relu"),
            keras.layers.Dense(n_in, activation="linear"),
        ])
        model.compile(optimizer="adam", loss="mse")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model.fit(Xn, Xn, epochs=20, batch_size=32, verbose=0)
        try:
            recon_tr = model.predict(Xn, verbose=0)
            recon_te = model.predict(Xt, verbose=0)
        except TypeError:
            recon_tr = model.predict(Xn)
            recon_te = model.predict(Xt)
        return recon_tr, recon_te

    from sklearn.neural_network import MLPRegressor
    ae = MLPRegressor(
        hidden_layer_sizes=(16, 8, 4, 8, 16),
        activation="relu",
        solver="adam",
        max_iter=300,
        random_state=42,
        early_stopping=len(Xn) >= 30,
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ae.fit(Xn, Xn)
    return ae.predict(Xn), ae.predict(Xt)


def _ae_predict_fold(X_train: pd.DataFrame, y_train: pd.Series, X_test: pd.DataFrame) -> np.ndarray:
    """Autoencoder on Normal-only; threshold = 95th percentile of train-normal MSE."""
    Xn, X_test = _impute_normal_only_fold(X_train, y_train, X_test)
    scaler = StandardScaler()
    Xn_s = scaler.fit_transform(Xn)
    Xt_s = scaler.transform(X_test)
    recon_tr, recon_te = _ae_reconstruct(Xn_s, Xt_s)
    train_mse = np.mean((Xn_s - recon_tr) ** 2, axis=1)
    test_mse = np.mean((Xt_s - recon_te) ** 2, axis=1)
    thr = float(np.percentile(train_mse, 95))
    return np.where(test_mse > thr, "fault", "normal")


def _loso_unsupervised(name: str, predict_fold, X, y, groups) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    logo = LeaveOneGroupOut()
    dummy = np.zeros(len(y))
    rows = []
    yt_all, yp_all = [], []
    y = y.astype(str)
    for train_idx, test_idx in logo.split(dummy, dummy, groups):
        sc = groups.iloc[test_idx].iloc[0]
        if name == "autoencoder":
            print(f"    ae fold held_out={sc} n_test={len(test_idx)}", flush=True)
        pred = predict_fold(X.iloc[train_idx], y.iloc[train_idx], X.iloc[test_idx])
        yt = y.iloc[test_idx].to_numpy()
        yt_all.append(yt)
        yp_all.append(pred)
        rows.append({
            "model": name,
            "held_out_scenario": sc,
            "n_test": int(len(test_idx)),
            "accuracy": float(accuracy_score(yt, pred)),
            "f1_macro": float(f1_score(yt, pred, average="macro", zero_division=0)),
        })
    yt_cat = np.concatenate(yt_all)
    yp_cat = np.concatenate(yp_all)
    rows.append({
        "model": name,
        "held_out_scenario": "_pooled",
        "n_test": int(len(yt_cat)),
        "accuracy": float(accuracy_score(yt_cat, yp_cat)),
        "f1_macro": float(f1_score(yt_cat, yp_cat, average="macro", zero_division=0)),
    })
    return pd.DataFrame(rows), yt_cat, yp_cat


def _per_class(yt, yp, labels) -> pd.DataFrame:
    p, r, f, s = precision_recall_fscore_support(yt, yp, labels=labels, zero_division=0)
    return pd.DataFrame({
        "label": list(labels),
        "precision": p,
        "recall": r,
        "f1": f,
        "support": s,
    })


def _confusion(yt, yp, labels) -> pd.DataFrame:
    cm = confusion_matrix(yt, yp, labels=labels)
    return pd.DataFrame(cm, index=labels, columns=labels)


def _write(df: pd.DataFrame, name: str) -> str:
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    df.to_csv(path, index=not isinstance(df.index, pd.RangeIndex) and df.index.name is not None)
    if name.endswith("confusion.csv"):
        df.to_csv(path)
    return path


def _scenario_dispersion(summary: pd.DataFrame, n_boot: int = 2500) -> pd.DataFrame:
    """Scenario-macro spread and cluster bootstrap CI (scenario is the cluster)."""
    work = summary[summary["held_out_scenario"] != "_pooled"].copy()
    work = work.dropna(subset=["accuracy", "f1_macro"])
    rows = []
    for offset, (model, group) in enumerate(work.groupby("model", sort=True)):
        values = group[["accuracy", "f1_macro"]].to_numpy(dtype=float)
        rng = np.random.default_rng(4200 + offset)
        boot_idx = rng.integers(0, len(values), size=(n_boot, len(values)))
        boot_means = values[boot_idx].mean(axis=1)
        rows.append({
            "model": model,
            "n_scenarios": int(len(values)),
            "accuracy_scenario_mean": float(values[:, 0].mean()),
            "accuracy_scenario_std": float(values[:, 0].std(ddof=0)),
            "accuracy_scenario_min": float(values[:, 0].min()),
            "accuracy_scenario_median": float(np.median(values[:, 0])),
            "accuracy_cluster_bootstrap_ci95_low": float(np.quantile(boot_means[:, 0], 0.025)),
            "accuracy_cluster_bootstrap_ci95_high": float(np.quantile(boot_means[:, 0], 0.975)),
            "f1_scenario_mean": float(values[:, 1].mean()),
            "f1_scenario_std": float(values[:, 1].std(ddof=0)),
            "f1_scenario_min": float(values[:, 1].min()),
            "f1_scenario_median": float(np.median(values[:, 1])),
            "f1_cluster_bootstrap_ci95_low": float(np.quantile(boot_means[:, 1], 0.025)),
            "f1_cluster_bootstrap_ci95_high": float(np.quantile(boot_means[:, 1], 0.975)),
            "bootstrap_unit": "held_out_scenario",
            "n_bootstrap": int(n_boot),
        })
    return pd.DataFrame(rows)


def _factories(n_class: int):
    out = [
        ("random_forest", lambda: RandomForestClassifier(n_estimators=200, random_state=42)),
        (
            "svm",
            lambda: SVC(kernel="rbf", C=1.0, gamma="scale", class_weight="balanced"),
        ),
    ]
    if XGBClassifier is None:
        return out
    kwargs = dict(n_estimators=200, max_depth=4, learning_rate=0.1, n_jobs=2, random_state=42)
    if n_class > 2:
        kwargs["eval_metric"] = "mlogloss"
    else:
        kwargs["eval_metric"] = "logloss"
    out.append(("xgboost", lambda: XGBClassifier(**kwargs)))
    return out


def _run_task(tag: str, X, y, groups, labels, prefix: str, supervised_only: bool = False) -> None:
    print(f"\n=== Protocol {tag.upper()} | classes={list(labels)} | n={len(y)} ===")
    frames = []
    pooled = {}
    for name, factory in _factories(len(labels)):
        tbl, yt, yp = _loso_ml(name, factory, X, y, groups)
        frames.append(tbl)
        pooled[name] = (yt, yp)
        row = tbl[tbl["held_out_scenario"] == "_pooled"].iloc[0]
        print(f"  {name:15s}  Acc={row.accuracy:.4f}  F1-macro={row.f1_macro:.4f}")
    if tag == "d1" and not supervised_only:
        tbl, yt, yp = _loso_unsupervised(
            "isolation_forest", _if_predict_fold, X, y, groups,
        )
        frames.append(tbl)
        pooled["isolation_forest"] = (yt, yp)
        row = tbl[tbl["held_out_scenario"] == "_pooled"].iloc[0]
        print(f"  {'isolation_forest':15s}  Acc={row.accuracy:.4f}  F1-macro={row.f1_macro:.4f}")
        try:
            backend = _resolve_ae_backend()
            print(f"  [autoencoder] backend={backend} ({_AE_BACKEND_NOTE})")
            tbl, yt, yp = _loso_unsupervised(
                "autoencoder", _ae_predict_fold, X, y, groups,
            )
            frames.append(tbl)
            pooled["autoencoder"] = (yt, yp)
            row = tbl[tbl["held_out_scenario"] == "_pooled"].iloc[0]
            print(f"  {'autoencoder':15s}  Acc={row.accuracy:.4f}  F1-macro={row.f1_macro:.4f}")
        except Exception as exc:
            print(f"  {'autoencoder':15s}  SKIP — {type(exc).__name__}: {exc}")
    task = "d1" if tag == "d1" else "d2"
    tbl, yt, yp = _loso_rule(task, X, y, groups)
    frames.append(tbl)
    pooled["rule_based"] = (yt, yp)
    row = tbl[tbl["held_out_scenario"] == "_pooled"].iloc[0]
    print(f"  {'rule_based':15s}  Acc={row.accuracy:.4f}  F1-macro={row.f1_macro:.4f}")
    if tag == "d2":
        na = pd.DataFrame([
            {
                "model": m,
                "held_out_scenario": "_pooled",
                "n_test": 0,
                "accuracy": np.nan,
                "f1_macro": np.nan,
                "note": "N/A — unsupervised answers D1 only; cannot assign 4-class labels",
            }
            for m in ("isolation_forest", "autoencoder")
        ])
        frames.append(na)
        print("  isolation_forest / autoencoder  N/A — unsupervised D1 only, not 4-class")

    summary = pd.concat(frames, ignore_index=True)
    _write(summary, f"{prefix}_{tag}_loso.csv")
    _write(
        _scenario_dispersion(summary),
        f"{prefix}_{tag}_scenario_dispersion.csv",
    )
    if tag == "d2":
        _write(summary, f"{prefix}_loso_summary.csv")

    class_rows = []
    for name, (yt, yp) in pooled.items():
        pc = _per_class(yt, yp, labels)
        pc.insert(0, "model", name)
        class_rows.append(pc)
        cm = _confusion(yt, yp, labels)
        cm.index.name = "true"
        path = os.path.join(OUT_DIR, f"{prefix}_{tag}_{name}_confusion.csv")
        cm.to_csv(path)
        print(f"  confusion {name} -> {path}")
        print(classification_report(yt, yp, labels=labels, zero_division=0))
    _write(pd.concat(class_rows, ignore_index=True), f"{prefix}_{tag}_per_class.csv")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA_DEFAULT)
    ap.add_argument(
        "--prefix",
        default="",
        help="Report filename prefix (default: fault_protocol_e if csv has protocol=e else fault_protocol_d)",
    )
    ap.add_argument(
        "--skip-d2",
        action="store_true",
        help="Only regenerate D1 (keeps existing D2 CSVs). Default runs both.",
    )
    ap.add_argument(
        "--supervised-only",
        action="store_true",
        help="Run RF/SVM/XGB and rule baseline; skip IF/AE during fast audited reruns.",
    )
    args = ap.parse_args()

    raw = _load(args.data)
    df = _steady_state(raw)
    proto_vals = (
        sorted(df["protocol"].astype(str).str.lower().unique())
        if "protocol" in df.columns
        else []
    )
    prefix = args.prefix
    if not prefix:
        if proto_vals == ["e"]:
            prefix = "fault_protocol_e"
        elif proto_vals == ["d"]:
            prefix = "fault_protocol_d"
        else:
            prefix = "fault_protocol"
    print(
        f"[*] raw snapshots={len(raw)}  steady={len(df)}  "
        f"runs={df['run_id'].nunique()}  scenarios={df['scenario_id'].nunique()}  "
        f"protocol={proto_vals}  prefix={prefix}"
    )
    print("[*] families:\n", df["fault_family"].value_counts().to_string())
    if df["scenario_id"].nunique() < 4:
        print("[!] need ≥4 scenarios before LOSO is meaningful")
        sys.exit(1)

    X4, y4, groups, cols = _xy(df, df["fault_family"])
    print(f"[*] features ({len(cols)}): {cols}")

    y1 = y4.where(y4 == "normal", "fault")
    _run_task(
        "d1", X4, y1, groups, ("normal", "fault"), prefix,
        supervised_only=args.supervised_only,
    )
    if not args.skip_d2:
        _run_task(
            "d2", X4, y4, groups, FAMILIES, prefix,
            supervised_only=args.supervised_only,
        )
    print("[!] Results are observations on this Mininet fault testbed only.")
    print("[!] Unsupervised IF/AE answer D1 (binary) only; D2 4-class stays N/A.")
    print("[!] Do not claim 4-class type classification unless D2 F1-macro ≥ 0.70 "
          "and Bandwidth/Loss/Delay recall are all ≥ 0.50.")


if __name__ == "__main__":
    main()

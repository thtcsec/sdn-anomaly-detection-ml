"""
Protocol D evaluation on the fault dataset (poll snapshots).

Does not touch the anomaly 79.114 pool.
Ground-truth columns are never used as features.

  D1 — Normal vs Fault (detection)
  D2 — 4-class family (normal / bandwidth / loss / delay)
  Rule-based baseline on the same telemetry (RTT / loss / throughput)

  python src/eval_fault_loso.py
"""

from __future__ import annotations

import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.preprocessing import LabelEncoder, StandardScaler

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import FAULT_FORBIDDEN_FEATURES, FAULT_MODEL_FEATURES  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE_DIR, "dataset", "fault_stats_grouped.csv")
OUT_DIR = os.path.join(BASE_DIR, "reports")
FAMILIES = ("normal", "bandwidth", "loss", "delay")


def _load() -> pd.DataFrame:
    if not os.path.exists(DATA):
        raise FileNotFoundError(
            f"Missing {DATA}. Collect then merge:\n"
            "  python controller/run_fault_monitor.py\n"
            "  sudo python3 src/collect_independent_fault_runs.py --protocol d\n"
            "  python src/merge_fault_runs.py"
        )
    df = pd.read_csv(DATA)
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
    X = X.fillna(X.median(numeric_only=True)).fillna(0.0)
    groups = df["scenario_id"].astype(str)
    return X, y.astype(str), groups, cols


def _rule_thresholds(X: pd.DataFrame, y: pd.Series) -> dict[str, float]:
    """Calibrate on Normal rows of the *train* fold only."""
    nmask = y.astype(str) == "normal"
    if int(nmask.sum()) < 3:
        nmask = pd.Series(True, index=y.index)
    loss = pd.to_numeric(X.loc[nmask, "probe_loss_pct"], errors="coerce") if "probe_loss_pct" in X else pd.Series([0.0])
    rtt = pd.to_numeric(X.loc[nmask, "rtt_mean_ms"], errors="coerce") if "rtt_mean_ms" in X else pd.Series([1.0])
    thr = pd.to_numeric(X.loc[nmask, "throughput_mbps"], errors="coerce") if "throughput_mbps" in X else pd.Series([10.0])
    return {
        "loss": float(max(2.0, np.nanpercentile(loss.fillna(0.0), 95))),
        "rtt": float(max(15.0, np.nanpercentile(rtt.fillna(0.0), 95) * 2.0)),
        "thr": float(max(0.5, np.nanpercentile(thr.fillna(np.nan), 25) * 0.5)) if thr.notna().any() else 1.0,
    }


def _rule_predict_4(X: pd.DataFrame, thr: dict[str, float]) -> np.ndarray:
    loss = pd.to_numeric(X.get("probe_loss_pct", 0), errors="coerce").fillna(0.0).to_numpy()
    rtt = pd.to_numeric(X.get("rtt_mean_ms", 0), errors="coerce").fillna(0.0).to_numpy()
    tput = pd.to_numeric(X.get("throughput_mbps", np.nan), errors="coerce").to_numpy()
    pred = np.full(len(X), "normal", dtype=object)
    pred[np.nan_to_num(tput, nan=np.inf) <= thr["thr"]] = "bandwidth"
    pred[rtt >= thr["rtt"]] = "delay"
    pred[loss >= thr["loss"]] = "loss"
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
        scaler = StandardScaler()
        Xtr = scaler.fit_transform(X.iloc[train_idx])
        Xte = scaler.transform(X.iloc[test_idx])
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


def _factories(n_class: int):
    out = [
        ("random_forest", lambda: RandomForestClassifier(n_estimators=200, random_state=42)),
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


def _run_task(tag: str, X, y, groups, labels) -> None:
    print(f"\n=== Protocol {tag.upper()} | classes={list(labels)} | n={len(y)} ===")
    frames = []
    pooled = {}
    for name, factory in _factories(len(labels)):
        tbl, yt, yp = _loso_ml(name, factory, X, y, groups)
        frames.append(tbl)
        pooled[name] = (yt, yp)
        row = tbl[tbl["held_out_scenario"] == "_pooled"].iloc[0]
        print(f"  {name:15s}  Acc={row.accuracy:.4f}  F1-macro={row.f1_macro:.4f}")
    task = "d1" if tag == "d1" else "d2"
    tbl, yt, yp = _loso_rule(task, X, y, groups)
    frames.append(tbl)
    pooled["rule_based"] = (yt, yp)
    row = tbl[tbl["held_out_scenario"] == "_pooled"].iloc[0]
    print(f"  {'rule_based':15s}  Acc={row.accuracy:.4f}  F1-macro={row.f1_macro:.4f}")

    summary = pd.concat(frames, ignore_index=True)
    _write(summary, f"fault_protocol_{tag}_loso.csv")
    if tag == "d2":
        _write(summary, "fault_loso_summary.csv")

    class_rows = []
    for name, (yt, yp) in pooled.items():
        pc = _per_class(yt, yp, labels)
        pc.insert(0, "model", name)
        class_rows.append(pc)
        cm = _confusion(yt, yp, labels)
        cm.index.name = "true"
        path = os.path.join(OUT_DIR, f"fault_protocol_{tag}_{name}_confusion.csv")
        cm.to_csv(path)
        print(f"  confusion {name} -> {path}")
        print(classification_report(yt, yp, labels=labels, zero_division=0))
    _write(pd.concat(class_rows, ignore_index=True), f"fault_protocol_{tag}_per_class.csv")


def main() -> None:
    raw = _load()
    df = _steady_state(raw)
    print(
        f"[*] raw snapshots={len(raw)}  steady={len(df)}  "
        f"runs={df['run_id'].nunique()}  scenarios={df['scenario_id'].nunique()}"
    )
    print("[*] families:\n", df["fault_family"].value_counts().to_string())
    if df["scenario_id"].nunique() < 4:
        print("[!] need ≥4 scenarios before LOSO is meaningful")
        sys.exit(1)

    X4, y4, groups, cols = _xy(df, df["fault_family"])
    print(f"[*] features ({len(cols)}): {cols}")

    y1 = y4.where(y4 == "normal", "fault")
    _run_task("d1", X4, y1, groups, ("normal", "fault"))
    _run_task("d2", X4, y4, groups, FAMILIES)
    print("[!] Results are observations on this Mininet fault testbed only.")
    print("[!] 4-class Acc near 0.25 is not a deployable classifier — D1 is the detection question.")


if __name__ == "__main__":
    main()

"""
Leave-One-Scenario-Out on the fault dataset (poll snapshots).

Does not touch the anomaly 79.114 pool.
Ground-truth columns are never used as features.

  python src/eval_fault_loso.py
"""

from __future__ import annotations

import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
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


def _load() -> pd.DataFrame:
    if not os.path.exists(DATA):
        raise FileNotFoundError(
            f"Missing {DATA}. Collect then merge:\n"
            "  python controller/run_fault_monitor.py\n"
            "  sudo python3 src/collect_independent_fault_runs.py\n"
            "  python src/merge_fault_runs.py"
        )
    df = pd.read_csv(DATA)
    leaked = [c for c in FAULT_FORBIDDEN_FEATURES if c in FAULT_MODEL_FEATURES]
    if leaked:
        raise RuntimeError(f"schema leak: {leaked}")
    return df


def _xy(df: pd.DataFrame, ycol: str):
    cols = [c for c in FAULT_MODEL_FEATURES if c in df.columns]
    X = df[cols].apply(pd.to_numeric, errors="coerce")
    X = X.fillna(X.median(numeric_only=True)).fillna(0.0)
    y = df[ycol].astype(str)
    groups = df["scenario_id"].astype(str)
    return X, y, groups, cols


def _loso(name: str, model_factory, X, y, groups) -> pd.DataFrame:
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
        clf = model_factory()
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
    yt_all = np.concatenate(yt_all)
    yp_all = np.concatenate(yp_all)
    rows.append({
        "model": name,
        "held_out_scenario": "_pooled",
        "n_test": int(len(yt_all)),
        "accuracy": float(accuracy_score(yt_all, yp_all)),
        "f1_macro": float(f1_score(yt_all, yp_all, average="macro", zero_division=0)),
    })
    return pd.DataFrame(rows)


def main() -> None:
    df = _load()
    n_run = df["run_id"].nunique()
    n_sc = df["scenario_id"].nunique()
    print(f"[*] fault snapshots={len(df)} runs={n_run} scenarios={n_sc}")
    print("[*] labels:\n", df["fault_family"].value_counts().to_string())
    if n_sc < 4:
        print("[!] need ≥4 scenarios before LOSO is meaningful")
        sys.exit(1)

    X, y, groups, cols = _xy(df, "fault_family")
    used_forbidden = set(cols) & set(FAULT_FORBIDDEN_FEATURES)
    if used_forbidden:
        raise RuntimeError(f"refusing leak features: {used_forbidden}")
    print(f"[*] features ({len(cols)}): {cols}")

    frames = [
        _loso("random_forest", lambda: RandomForestClassifier(n_estimators=200, random_state=42), X, y, groups),
    ]
    if XGBClassifier is not None:
        frames.append(_loso(
            "xgboost",
            lambda: XGBClassifier(
                n_estimators=200, max_depth=4, learning_rate=0.1,
                eval_metric="mlogloss", n_jobs=2, random_state=42,
            ),
            X, y, groups,
        ))
    out = pd.concat(frames, ignore_index=True)
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, "fault_loso_summary.csv")
    out.to_csv(path, index=False)
    print(out.to_string(index=False))
    print(f"[✓] {path}")
    print("[!] Results are observations on this Mininet fault testbed only.")


if __name__ == "__main__":
    main()

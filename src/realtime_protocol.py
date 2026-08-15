"""Shared, leakage-resistant data preparation for the realtime research protocol.

This module deliberately uses only clean, independently labelled Mininet runs.
It never creates rows, resamples rows, or changes labels.
"""

from __future__ import annotations

import os

import pandas as pd

try:  # Supports both ``python src/...`` and ``import src...``.
    from .provenance_schema import FEATURE_COLS
except ImportError:
    from provenance_schema import FEATURE_COLS

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUPED_CSV = os.path.join(BASE_DIR, "dataset", "flow_stats_grouped.csv")

# Raw source/destination ports are intentionally excluded from the deployment
# candidate.  Port diversity belongs in a future, explicitly validated window
# feature pipeline; raw port values are scenario identifiers in this lab.
REALTIME_FEATURE_COLS = [c for c in FEATURE_COLS if c not in ("tp_src", "tp_dst")]

TUPLE_COLS = [
    "run_id",
    "datapath_id",
    "ip_src",
    "ip_dst",
    "ip_proto",
    "tp_src",
    "tp_dst",
]


def load_clean_independent(path: str = GROUPED_CSV) -> pd.DataFrame:
    """Return only real rows with known run and scenario provenance."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing clean grouped pool: {path}")

    df = pd.read_csv(path, low_memory=False)
    required = FEATURE_COLS + ["label", "run_id", "scenario_id", "timestamp"]
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"Grouped pool is missing required columns: {missing}")

    out = df[df["is_synthetic"].fillna(0).astype(int) == 0].copy()
    invalid = {"unknown", "nan", "", "None", "legacy_unknown"}
    out = out[~out["run_id"].astype(str).isin(invalid)]
    out = out[~out["scenario_id"].astype(str).isin(invalid)]
    out = out.dropna(subset=required)
    out["label"] = out["label"].astype(str).str.lower()
    out["scenario_id"] = out["scenario_id"].astype(str)
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce")
    out = out.dropna(subset=["timestamp"])
    return out


def early_poll_snapshots(df: pd.DataFrame, max_polls: int = 3) -> pd.DataFrame:
    """Keep only observations available during the first ``max_polls`` polls.

    The controller sees a flow at poll time, not at its final lifetime state.
    Grouping includes ``run_id`` so identically named flows from different runs
    never collapse into a single sample.
    """
    if max_polls < 1:
        raise ValueError("max_polls must be >= 1")
    missing = [col for col in TUPLE_COLS if col not in df.columns]
    if missing:
        raise ValueError(f"Cannot identify OpenFlow tuple; missing {missing}")

    out = df.sort_values(["run_id", "timestamp"], kind="stable").copy()
    out["poll_index"] = out.groupby(TUPLE_COLS, dropna=False).cumcount()
    out = out[out["poll_index"] < max_polls].copy()
    start = out.groupby("run_id")["timestamp"].transform("min")
    out["seconds_from_run_start"] = (out["timestamp"] - start).dt.total_seconds()
    return out.reset_index(drop=True)

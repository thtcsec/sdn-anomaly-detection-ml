"""Shared data prep for the realtime scenario-held-out protocol.

Uses only clean independent Mininet runs. Does not create, resample, or
relabel rows.
"""

from __future__ import annotations

import os

import pandas as pd

try:
    from .provenance_schema import FEATURE_COLS
except ImportError:
    from provenance_schema import FEATURE_COLS

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUPED_CSV = os.path.join(BASE_DIR, "dataset", "flow_stats_grouped.csv")

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
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Missing clean grouped pool: {path}. "
            "Need dataset/flow_stats_grouped.csv from the submission zip."
        )

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

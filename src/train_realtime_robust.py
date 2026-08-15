"""Train a separately named, port-free realtime candidate on the clean pool.

This produces a candidate artifact only.  It does not overwrite the deployed
legacy XGBoost model and does not claim an in-sample accuracy as generalization.
Use ``eval_realtime_scenario_held_out.py`` for the generalization result.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from realtime_protocol import (  # noqa: E402
    BASE_DIR,
    REALTIME_FEATURE_COLS,
    early_poll_snapshots,
    load_clean_independent,
)

MODELS = os.path.join(BASE_DIR, "models")
REPORTS = os.path.join(BASE_DIR, "reports")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None)
    ap.add_argument("--max-polls", type=int, default=3)
    args = ap.parse_args()

    from xgboost import XGBClassifier

    os.makedirs(MODELS, exist_ok=True)
    os.makedirs(REPORTS, exist_ok=True)
    polls = load_clean_independent(args.data) if args.data else load_clean_independent()
    df = early_poll_snapshots(polls, max_polls=args.max_polls)
    encoder = LabelEncoder()
    y = encoder.fit_transform(df["label"])
    x = df[REALTIME_FEATURE_COLS]

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x)
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="mlogloss",
        n_jobs=-1,
    )
    # No SMOTE: class handling remains visible in scenario-held-out evaluation.
    model.fit(x_scaled, y)

    model_path = os.path.join(MODELS, "xgboost_realtime_robust.pkl")
    scaler_path = os.path.join(MODELS, "xgboost_realtime_robust_scaler.pkl")
    meta_path = os.path.join(MODELS, "xgboost_realtime_robust_metadata.json")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    metadata = {
        "purpose": "candidate_only; activate explicitly in controller_config.json",
        "source": "clean independent Mininet runs only",
        "n_clean_poll_rows": int(len(polls)),
        "n_training_early_snapshots": int(len(df)),
        "n_scenarios": int(df["scenario_id"].nunique()),
        "max_polls_per_5tuple": args.max_polls,
        "feature_columns": REALTIME_FEATURE_COLS,
        "label_classes": encoder.classes_.tolist(),
        "smote": False,
        "evaluation": "reports/realtime_scenario_held_out_summary.csv",
        "warning": "Do not report training accuracy; use scenario-held-out episode metrics.",
    }
    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)
    pd.DataFrame([metadata]).to_json(
        os.path.join(REPORTS, "realtime_robust_training_manifest.json"),
        orient="records", indent=2,
    )
    print(f"[✓] Candidate model: {model_path}")
    print(f"[✓] Candidate scaler: {scaler_path}")
    print(f"[✓] Metadata: {meta_path}")
    print("[*] Existing controller model was not overwritten.")


if __name__ == "__main__":
    main()

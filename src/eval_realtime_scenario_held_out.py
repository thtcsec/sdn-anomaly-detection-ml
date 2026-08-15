"""Evaluate the deployment candidate without flow/time/scenario leakage.

The unit of the primary result is a *run episode*, not a poll row.  For every
outer fold all repeats of one ``scenario_id`` are held out.  A model receives
only the first N polls of each flow and an attack is detected only after the
same source is anomalous for N consecutive controller polling rounds.

No synthetic rows, SMOTE, public datasets, or controller model files are used.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from realtime_protocol import (  # noqa: E402
    BASE_DIR,
    REALTIME_FEATURE_COLS,
    early_poll_snapshots,
    load_clean_independent,
)

REPORTS = os.path.join(BASE_DIR, "reports")


def new_rf() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )


def new_xgb():
    from xgboost import XGBClassifier

    return XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="mlogloss",
        n_jobs=-1,
    )


def fit_predict(factory, x_train, y_train, x_test):
    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)
    model = factory()
    model.fit(x_train_scaled, y_train)
    return model.predict(x_test_scaled)


def episode_outcomes(test: pd.DataFrame, labels: np.ndarray, normal_id: int,
                     consecutive_polls: int) -> pd.DataFrame:
    """Simulate source-level consecutive-poll alerting for held-out runs."""
    scored = test[["run_id", "scenario_id", "label", "timestamp", "ip_src"]].copy()
    scored["prediction"] = labels
    rows = []
    for run_id, run in scored.groupby("run_id", sort=False):
        run = run.sort_values("timestamp", kind="stable")
        run_start = run["timestamp"].min()
        alert_at = None
        # Aggregate all flow classifications for a source in one stats reply.
        # This is the semantics implemented by the revised controller.
        for (timestamp, src), tick in run.groupby(["timestamp", "ip_src"], sort=True):
            attack_labels = [p for p in tick["prediction"] if p != normal_id]
            if attack_labels:
                # Mode is deterministic on ties because Counter preserves input order.
                predicted = Counter(attack_labels).most_common(1)[0][0]
                key = src
                # Per-source state is stored in the local evaluation run below.
            else:
                predicted = normal_id
            rows.append({
                "run_id": run_id,
                "scenario_id": tick["scenario_id"].iat[0],
                "label": tick["label"].iat[0],
                "timestamp": timestamp,
                "ip_src": src,
                "source_prediction": predicted,
                "run_start": run_start,
            })

    ticks = pd.DataFrame(rows)
    outcomes = []
    for run_id, run_ticks in ticks.groupby("run_id", sort=False):
        streaks: dict[str, int] = {}
        alert_time = None
        for tick in run_ticks.sort_values(["timestamp", "ip_src"], kind="stable").itertuples(index=False):
            if tick.source_prediction == normal_id:
                streaks[tick.ip_src] = 0
            else:
                streaks[tick.ip_src] = streaks.get(tick.ip_src, 0) + 1
                if streaks[tick.ip_src] >= consecutive_polls and alert_time is None:
                    alert_time = tick.timestamp
        label = run_ticks["label"].iat[0]
        is_attack = label != "normal"
        outcomes.append({
            "run_id": run_id,
            "scenario_id": run_ticks["scenario_id"].iat[0],
            "label": label,
            "episode_alert": alert_time is not None,
            "detected_attack": bool(is_attack and alert_time is not None),
            "false_alert": bool((not is_attack) and alert_time is not None),
            "time_to_alert_sec": (
                (alert_time - run_ticks["run_start"].iat[0]).total_seconds()
                if alert_time is not None else np.nan
            ),
        })
    return pd.DataFrame(outcomes)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None)
    ap.add_argument("--max-polls", type=int, default=3)
    ap.add_argument("--consecutive-polls", type=int, default=3)
    args = ap.parse_args()
    if args.consecutive_polls < 1:
        raise SystemExit("--consecutive-polls must be >= 1")

    os.makedirs(REPORTS, exist_ok=True)
    polls = load_clean_independent(args.data) if args.data else load_clean_independent()
    df = early_poll_snapshots(polls, max_polls=args.max_polls)
    labels = LabelEncoder()
    y = labels.fit_transform(df["label"])
    if "normal" not in labels.classes_:
        raise SystemExit("Clean pool has no normal class")
    normal_id = int(labels.transform(["normal"])[0])
    groups = df["scenario_id"].to_numpy()
    x = df[REALTIME_FEATURE_COLS].to_numpy(dtype=float)

    print(f"[*] Clean poll rows={len(polls)}; early snapshots={len(df)}")
    print(f"[*] scenarios={df['scenario_id'].nunique()}; features={REALTIME_FEATURE_COLS}")
    print("[*] No SMOTE; raw source/destination ports excluded.")

    factories = {"RandomForest": new_rf}
    try:
        from xgboost import XGBClassifier  # noqa: F401
        factories["XGBoost"] = new_xgb
    except ImportError:
        print("[!] xgboost unavailable; evaluating RandomForest only")

    fold_rows = []
    snapshot_rows = []
    logo = LeaveOneGroupOut()
    for fold, (train_idx, test_idx) in enumerate(logo.split(x, y, groups)):
        scenario = str(groups[test_idx][0])
        held_label = df.iloc[test_idx]["label"].mode().iat[0]
        for model_name, factory in factories.items():
            pred = fit_predict(factory, x[train_idx], y[train_idx], x[test_idx])
            test = df.iloc[test_idx].copy()
            episodes = episode_outcomes(
                test, pred, normal_id, args.consecutive_polls
            )
            attack_episodes = episodes[episodes["label"] != "normal"]
            normal_episodes = episodes[episodes["label"] == "normal"]
            fold_rows.append({
                "protocol": "leave_one_scenario_out_realtime",
                "model": model_name,
                "fold": fold,
                "heldout_scenario": scenario,
                "heldout_label": held_label,
                "n_test_snapshots": int(len(test)),
                "n_test_runs": int(test["run_id"].nunique()),
                "snapshot_accuracy": accuracy_score(y[test_idx], pred),
                "snapshot_f1_macro": f1_score(
                    y[test_idx], pred, labels=range(len(labels.classes_)),
                    average="macro", zero_division=0,
                ),
                "episode_detection_rate": (
                    float(attack_episodes["detected_attack"].mean())
                    if not attack_episodes.empty else np.nan
                ),
                "normal_false_alert_rate": (
                    float(normal_episodes["false_alert"].mean())
                    if not normal_episodes.empty else np.nan
                ),
                "median_time_to_alert_sec": (
                    float(attack_episodes["time_to_alert_sec"].median())
                    if attack_episodes["time_to_alert_sec"].notna().any() else np.nan
                ),
            })
            snapshot_rows.append(pd.DataFrame({
                "model": model_name,
                "fold": fold,
                "heldout_scenario": scenario,
                "heldout_label": held_label,
                "actual": labels.inverse_transform(y[test_idx]),
                "predicted": labels.inverse_transform(pred),
            }))

    folds = pd.DataFrame(fold_rows)
    summary_rows = []
    for (model, held_label), group in folds.groupby(["model", "heldout_label"], dropna=False):
        metric = "normal_false_alert_rate" if held_label == "normal" else "episode_detection_rate"
        values = group[metric].dropna()
        summary_rows.append({
            "model": model,
            "heldout_label": held_label,
            "metric": metric,
            "n_scenarios": int(len(group)),
            "mean": values.mean(),
            "median": values.median(),
            "min": values.min(),
            "max": values.max(),
            "note": "scenario-weighted; no resampling or synthetic rows",
        })
    summary = pd.DataFrame(summary_rows)
    snapshots = pd.concat(snapshot_rows, ignore_index=True)

    folds.to_csv(os.path.join(REPORTS, "realtime_scenario_held_out_folds.csv"), index=False)
    summary.to_csv(os.path.join(REPORTS, "realtime_scenario_held_out_summary.csv"), index=False)
    snapshots.to_csv(os.path.join(REPORTS, "realtime_scenario_held_out_snapshots.csv"), index=False)
    pd.DataFrame([{
        "status": "ok",
        "protocol": "LOSO by scenario_id; early flow observations only",
        "n_clean_poll_rows": len(polls),
        "n_early_snapshots": len(df),
        "n_scenarios": df["scenario_id"].nunique(),
        "max_polls_per_5tuple": args.max_polls,
        "consecutive_source_polls_for_alert": args.consecutive_polls,
        "feature_set": ",".join(REALTIME_FEATURE_COLS),
        "smote": False,
        "controller_model_changed": False,
    }]).to_csv(os.path.join(REPORTS, "realtime_scenario_held_out_STATUS.csv"), index=False)

    print("\n" + summary.to_string(index=False))
    print("[✓] Wrote realtime scenario-held-out reports; no controller model was changed.")


if __name__ == "__main__":
    main()

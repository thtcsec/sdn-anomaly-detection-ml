"""Fair four-model binary benchmark on the clean realtime protocol.

All models solve the same task: Normal (0) versus Attack (1).  It uses the
same scenario-held-out outer split, early observations, and port-free features
for every model.  No row generation, SMOTE, or public dataset is involved.
"""

from __future__ import annotations

import argparse
import os
import sys
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from realtime_protocol import (  # noqa: E402
    BASE_DIR,
    REALTIME_FEATURE_COLS,
    early_poll_snapshots,
    load_clean_independent,
)

REPORTS = os.path.join(BASE_DIR, "reports")


def _cap_train(x_train, y_train, cap: int):
    if cap <= 0 or len(y_train) <= cap:
        return x_train, y_train
    rs = np.random.RandomState(42)
    idx = []
    for label in np.unique(y_train):
        lab = np.where(y_train == label)[0]
        n = max(1, int(round(cap * len(lab) / len(y_train))))
        n = min(n, len(lab))
        idx.append(rs.choice(lab, size=n, replace=False))
    take = np.concatenate(idx)
    return x_train[take], y_train[take]


def _supervised_predictions(factory, x_train, y_train, x_test, train_cap: int = 0):
    x_train, y_train = _cap_train(x_train, y_train, train_cap)
    scaler = StandardScaler()
    model = factory()
    model.fit(scaler.fit_transform(x_train), y_train)
    return model.predict(scaler.transform(x_test))


def _if_predictions(x_train, y_train, x_test):
    normal_train = x_train[y_train == 0]
    scaler = StandardScaler()
    model = IsolationForest(
        n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1,
    )
    model.fit(scaler.fit_transform(normal_train))
    return (model.predict(scaler.transform(x_test)) == -1).astype(int)


def _ae_predictions(x_train, y_train, x_test):
    try:
        from tensorflow import keras
    except Exception:
        try:
            import tf_keras as keras
        except ImportError as exc:
            raise RuntimeError("TensorFlow is required for Autoencoder evaluation") from exc

    keras.utils.set_random_seed(42)
    normal_train = x_train[y_train == 0]
    scaler = StandardScaler()
    x_normal = scaler.fit_transform(normal_train)
    x_test_scaled = scaler.transform(x_test)
    width = x_normal.shape[1]
    model = keras.Sequential([
        keras.layers.Input(shape=(width,)),
        keras.layers.Dense(8, activation="relu"),
        keras.layers.Dense(4, activation="relu"),
        keras.layers.Dense(8, activation="relu"),
        keras.layers.Dense(width, activation="linear"),
    ])
    model.compile(optimizer="adam", loss="mse")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model.fit(x_normal, x_normal, epochs=20, batch_size=32, verbose=0)
    train_mse = np.mean((x_normal - model.predict(x_normal, verbose=0)) ** 2, axis=1)
    test_mse = np.mean((x_test_scaled - model.predict(x_test_scaled, verbose=0)) ** 2, axis=1)
    return (test_mse > np.percentile(train_mse, 95)).astype(int)


def _metrics(y_true, y_pred) -> dict[str, float]:
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision_anomaly": precision_score(y_true, y_pred, zero_division=0),
        "recall_anomaly": recall_score(y_true, y_pred, zero_division=0),
        "f1_anomaly": f1_score(y_true, y_pred, zero_division=0),
        "false_positive_rate_normal": float((y_pred[y_true == 0] == 1).mean())
        if (y_true == 0).any() else np.nan,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None)
    ap.add_argument("--max-polls", type=int, default=3)
    ap.add_argument("--skip-autoencoder", action="store_true")
    ap.add_argument(
        "--models",
        default="",
        help="Comma list: RandomForest,XGBoost,LinearSVC,IsolationForest,Autoencoder. "
             "Empty = all (except LinearSVC-only merge when --append-models).",
    )
    ap.add_argument(
        "--append-models",
        action="store_true",
        help="Run selected models and merge into existing binary_realtime_loso_*.csv",
    )
    ap.add_argument(
        "--svm-train-cap",
        type=int,
        default=40000,
        help="Max train rows for LinearSVC (0 = no cap). Scenario hold-out is kept intact.",
    )
    args = ap.parse_args()

    os.makedirs(REPORTS, exist_ok=True)
    polls = load_clean_independent(args.data) if args.data else load_clean_independent()
    df = early_poll_snapshots(polls, max_polls=args.max_polls)
    y = (df["label"].to_numpy() != "normal").astype(int)
    x = df[REALTIME_FEATURE_COLS].to_numpy(dtype=float)
    groups = df["scenario_id"].to_numpy()

    models = {
        "RandomForest": lambda: RandomForestClassifier(
            n_estimators=200, max_depth=12, min_samples_leaf=2,
            class_weight="balanced_subsample", random_state=42, n_jobs=-1,
        ),
        "LinearSVC": lambda: LinearSVC(
            C=1.0, dual=False, max_iter=4000, class_weight="balanced", random_state=42,
        ),
    }
    try:
        from xgboost import XGBClassifier  # noqa: F401
        models["XGBoost"] = lambda: XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8, random_state=42,
            eval_metric="logloss", n_jobs=-1,
        )
    except ImportError:
        print("[!] xgboost unavailable; skip XGBoost")

    wanted = {m.strip() for m in args.models.split(",") if m.strip()}
    if not wanted:
        wanted = set(models) | {"IsolationForest"}
        if not args.skip_autoencoder:
            wanted.add("Autoencoder")
        if args.append_models:
            wanted = {"LinearSVC"}

    prediction_functions = {}
    for name, factory in models.items():
        if name not in wanted:
            continue
        cap = args.svm_train_cap if name == "LinearSVC" else 0
        prediction_functions[name] = (
            lambda train_x, train_y, test_x, f=factory, c=cap: _supervised_predictions(
                f, train_x, train_y, test_x, train_cap=c
            )
        )
    if "IsolationForest" in wanted:
        prediction_functions["IsolationForest"] = _if_predictions
    if "Autoencoder" in wanted and not args.skip_autoencoder:
        prediction_functions["Autoencoder"] = _ae_predictions

    print(f"[*] Clean rows={len(polls)} | early snapshots={len(df)} | scenarios={df['scenario_id'].nunique()}")
    print(f"[*] Task=binary Normal-vs-Attack | features={REALTIME_FEATURE_COLS} | SMOTE=False")
    print(f"[*] models={list(prediction_functions)}")

    folds: list[dict] = []
    pooled: list[pd.DataFrame] = []
    logo = LeaveOneGroupOut()
    for fold, (tr, te) in enumerate(logo.split(x, y, groups)):
        scenario = str(groups[te][0])
        scenario_label = str(df.iloc[te]["label"].mode().iat[0])
        for model_name, predict in prediction_functions.items():
            pred = predict(x[tr], y[tr], x[te])
            folds.append({
                "protocol": "LOSO_scenario_early_binary_no_ports_no_smote",
                "model": model_name,
                "fold": fold,
                "heldout_scenario": scenario,
                "heldout_label": scenario_label,
                "n_test_snapshots": int(len(te)),
                **_metrics(y[te], pred),
            })
            pooled.append(pd.DataFrame({
                "model": model_name,
                "fold": fold,
                "heldout_scenario": scenario,
                "actual_binary": y[te],
                "predicted_binary": pred,
            }))
        print(f"[✓] fold={fold:02d} scenario={scenario}")

    fold_df = pd.DataFrame(folds)
    pooled_df = pd.concat(pooled, ignore_index=True)
    fold_path = os.path.join(REPORTS, "binary_realtime_loso_per_scenario.csv")
    sum_path = os.path.join(REPORTS, "binary_realtime_loso_summary.csv")
    if args.append_models and os.path.isfile(fold_path):
        old = pd.read_csv(fold_path)
        drop = set(fold_df["model"].unique())
        old = old[~old["model"].isin(drop)]
        fold_df = pd.concat([old, fold_df], ignore_index=True)

    summary_rows = []
    for model, group in fold_df.groupby("model"):
        p = pooled_df[pooled_df["model"] == model]
        if p.empty and args.append_models and os.path.isfile(sum_path):
            continue
        if p.empty:
            continue
        pooled_metrics = _metrics(p["actual_binary"].to_numpy(), p["predicted_binary"].to_numpy())
        attack = group[group["heldout_label"] != "normal"]
        normal = group[group["heldout_label"] == "normal"]
        summary_rows.append({
            "model": model,
            "pooled_snapshot_accuracy": pooled_metrics["accuracy"],
            "pooled_f1_anomaly": pooled_metrics["f1_anomaly"],
            "pooled_precision_anomaly": pooled_metrics["precision_anomaly"],
            "pooled_recall_anomaly": pooled_metrics["recall_anomaly"],
            "attack_scenario_recall_mean": attack["recall_anomaly"].mean() if len(attack) else np.nan,
            "attack_scenario_recall_min": attack["recall_anomaly"].min() if len(attack) else np.nan,
            "normal_scenario_fpr_mean": normal["false_positive_rate_normal"].mean() if len(normal) else np.nan,
            "normal_scenario_fpr_max": normal["false_positive_rate_normal"].max() if len(normal) else np.nan,
            "n_scenarios": int(group["heldout_scenario"].nunique()),
            "note": "Same binary task, scenario-held-out, early polls, no raw ports, no SMOTE. LinearSVC is a 5th supervised baseline.",
        })
    summary_df = pd.DataFrame(summary_rows).sort_values("model")
    if args.append_models and os.path.isfile(sum_path) and not summary_df.empty:
        old_sum = pd.read_csv(sum_path)
        drop = set(summary_df["model"].unique())
        old_sum = old_sum[~old_sum["model"].isin(drop)]
        summary_df = pd.concat([old_sum, summary_df], ignore_index=True).sort_values("model")

    fold_df.to_csv(fold_path, index=False)
    summary_df.to_csv(sum_path, index=False)
    print("\n" + summary_df.to_string(index=False))


if __name__ == "__main__":
    main()

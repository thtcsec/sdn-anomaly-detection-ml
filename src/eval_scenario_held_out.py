"""
Protocol D — Leave-One-Scenario-Out on the clean independent pool.

This is the generalization headline. It does NOT overwrite:
  reports/model_comparison.csv
  reports/grouped_real_only_*.csv

Rules:
  - Only is_synthetic==0 and known run_id
  - One eval sample = last OpenFlow poll of each 5-tuple per run
    (not every 5s snapshot of the same flow)
  - Split by scenario_id: every repeat of the same scenario stays on one side
  - Baseline features drop raw tp_src / tp_dst
  - Optional diagnostic keeps raw ports; optional window behavior features
  - Headline = recall of the held-out scenario label, plus min–max
  - IF/AE are binary ablation only (anomaly P/R/F1, never *_macro)

Chạy:
  python src/eval_scenario_held_out.py
  python src/eval_scenario_held_out.py --feature-set all
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
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import FEATURE_COLS  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUPED_CSV = os.path.join(BASE_DIR, 'dataset', 'flow_stats_grouped.csv')
REPORTS = os.path.join(BASE_DIR, 'reports')

TUPLE_COLS = ['run_id', 'datapath_id', 'ip_src', 'ip_dst', 'ip_proto', 'tp_src', 'tp_dst']
BEHAVIOR_COLS = ['win_unique_dst_ports', 'win_unique_dst_ips', 'win_flow_count']
NO_PORT_COLS = [c for c in FEATURE_COLS if c not in ('tp_src', 'tp_dst')]

FEATURE_SETS = {
    'with_raw_ports': FEATURE_COLS,
    'no_raw_ports': NO_PORT_COLS,
    'behavior_window': NO_PORT_COLS + BEHAVIOR_COLS,
}


def load_clean(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(f'Missing {path}. Run merge_independent_runs.py first.')
    df = pd.read_csv(path, low_memory=False)
    real = df[df['is_synthetic'].fillna(0).astype(int) == 0].copy()
    real = real[~real['run_id'].astype(str).isin(['unknown', 'nan', '', 'None'])]
    real = real.dropna(subset=FEATURE_COLS + ['label', 'scenario_id'])
    real['label'] = real['label'].astype(str).str.lower()
    real['scenario_id'] = real['scenario_id'].astype(str)
    real = real[~real['scenario_id'].isin(['unknown', 'nan', '', 'None', 'legacy_unknown'])]
    return real


def attach_window_behavior(df: pd.DataFrame) -> pd.DataFrame:
    keys = ['run_id', 'timestamp', 'ip_src']
    win = (
        df.groupby(keys, dropna=False)
        .agg(
            win_unique_dst_ports=('tp_dst', 'nunique'),
            win_unique_dst_ips=('ip_dst', 'nunique'),
            win_flow_count=('flow_id', 'count'),
        )
        .reset_index()
    )
    return df.merge(win, on=keys, how='left')


def last_poll_per_tuple(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out['timestamp'] = pd.to_datetime(out['timestamp'], errors='coerce')
    out = out.sort_values('timestamp')
    present = [c for c in TUPLE_COLS if c in out.columns]
    return out.groupby(present, as_index=False, dropna=False).tail(1).reset_index(drop=True)


def _fit_predict(model, X_tr, y_tr, X_te):
    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)
    model.fit(X_tr_s, y_tr)
    return model.predict(X_te_s)


def _new_rf():
    return RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_leaf=2,
        class_weight='balanced_subsample', random_state=42, n_jobs=-1,
    )


def _new_xgb():
    from xgboost import XGBClassifier
    return XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        eval_metric='mlogloss',
    )


def _eval_if(X_tr, y_tr, X_te, y_te, normal_idx: int):
    X_norm = X_tr[y_tr == normal_idx]
    if len(X_norm) < 5:
        return None
    scaler = StandardScaler()
    clf = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    clf.fit(scaler.fit_transform(X_norm))
    pred = clf.predict(scaler.transform(X_te))
    y_true = (y_te != normal_idx).astype(int)
    y_pred = (pred == -1).astype(int)
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision_anomaly': precision_score(y_true, y_pred, zero_division=0),
        'recall_anomaly': recall_score(y_true, y_pred, zero_division=0),
        'f1_anomaly': f1_score(y_true, y_pred, zero_division=0),
        'support': int(len(y_te)),
    }


def _eval_ae(X_tr, y_tr, X_te, y_te, normal_idx: int):
    try:
        from tensorflow import keras
    except Exception:
        try:
            import tf_keras as keras
        except ImportError:
            return None
    X_norm = X_tr[y_tr == normal_idx]
    if len(X_norm) < 10:
        return None
    scaler = StandardScaler()
    Xn = scaler.fit_transform(X_norm)
    Xt = scaler.transform(X_te)
    inp = Xn.shape[1]
    model = keras.Sequential([
        keras.layers.Input(shape=(inp,)),
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(4, activation='relu'),
        keras.layers.Dense(8, activation='relu'),
        keras.layers.Dense(inp, activation='linear'),
    ])
    model.compile(optimizer='adam', loss='mse')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        model.fit(Xn, Xn, epochs=20, batch_size=32, verbose=0)
    thr = np.percentile(np.mean((Xn - model.predict(Xn, verbose=0)) ** 2, axis=1), 95)
    y_true = (y_te != normal_idx).astype(int)
    y_pred = (np.mean((Xt - model.predict(Xt, verbose=0)) ** 2, axis=1) > thr).astype(int)
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision_anomaly': precision_score(y_true, y_pred, zero_division=0),
        'recall_anomaly': recall_score(y_true, y_pred, zero_division=0),
        'f1_anomaly': f1_score(y_true, y_pred, zero_division=0),
        'support': int(len(y_te)),
    }


def run_loso(df: pd.DataFrame, feature_cols: list[str], feature_set: str,
             with_unsupervised: bool) -> pd.DataFrame:
    le = LabelEncoder()
    y_all = le.fit_transform(df['label'])
    X_all = df[feature_cols].to_numpy(dtype=float)
    groups = df['scenario_id'].astype(str).to_numpy()
    all_ids = list(range(len(le.classes_)))
    class_to_id = {name: i for i, name in enumerate(le.classes_)}

    models = {'RandomForest': _new_rf}
    try:
        from xgboost import XGBClassifier  # noqa: F401
        models['XGBoost'] = _new_xgb
    except ImportError:
        print('[!] xgboost not installed — skip XGBoost')

    logo = LeaveOneGroupOut()
    rows = []
    for fold, (tr, te) in enumerate(logo.split(X_all, y_all, groups)):
        scenario = str(groups[te][0])
        held_label = str(df.iloc[te]['label'].mode().iat[0])
        n_test_labels = int(df.iloc[te]['label'].nunique())
        n_runs = int(df.iloc[te]['run_id'].nunique())
        print(f'  [{feature_set}] fold {fold:02d} {scenario} | label={held_label} '
              f'| tuples={len(te)} | runs={n_runs}')

        for name, factory in models.items():
            y_pred = _fit_predict(factory(), X_all[tr], y_all[tr], X_all[te])
            y_te = y_all[te]
            held_id = class_to_id[held_label]
            held_mask = y_te == held_id
            held_recall = (
                recall_score((y_te == held_id).astype(int), (y_pred == held_id).astype(int),
                             zero_division=0)
                if held_mask.any() else np.nan
            )
            per_cls = {}
            for cls_name, cls_id in zip(le.classes_, all_ids):
                mask = y_te == cls_id
                per_cls[f'support_{cls_name}'] = int(mask.sum())
                per_cls[f'recall_{cls_name}'] = (
                    recall_score((y_te == cls_id).astype(int), (y_pred == cls_id).astype(int),
                                 zero_division=0)
                    if mask.any() else np.nan
                )
            rows.append({
                'protocol': 'leave_one_scenario_out',
                'feature_set': feature_set,
                'model': name,
                'fold': fold,
                'heldout_scenario': scenario,
                'heldout_label': held_label,
                'n_test_tuples': int(len(te)),
                'n_test_runs': n_runs,
                'n_test_labels': n_test_labels,
                'accuracy': accuracy_score(y_te, y_pred),
                'f1_macro': f1_score(y_te, y_pred, labels=all_ids, average='macro',
                                     zero_division=0),
                'recall_heldout_label': held_recall,
                **per_cls,
            })

        if with_unsupervised and 'normal' in class_to_id:
            nid = class_to_id['normal']
            if_m = _eval_if(X_all[tr], y_all[tr], X_all[te], y_all[te], nid)
            if if_m:
                rows.append({
                    'protocol': 'leave_one_scenario_out',
                    'feature_set': feature_set,
                    'model': 'IsolationForest',
                    'fold': fold,
                    'heldout_scenario': scenario,
                    'heldout_label': held_label,
                    'n_test_tuples': int(len(te)),
                    'n_test_runs': n_runs,
                    'n_test_labels': n_test_labels,
                    'role': 'binary_anomaly_ablation',
                    **if_m,
                })
            ae_m = _eval_ae(X_all[tr], y_all[tr], X_all[te], y_all[te], nid)
            if ae_m:
                rows.append({
                    'protocol': 'leave_one_scenario_out',
                    'feature_set': feature_set,
                    'model': 'Autoencoder',
                    'fold': fold,
                    'heldout_scenario': scenario,
                    'heldout_label': held_label,
                    'n_test_tuples': int(len(te)),
                    'n_test_runs': n_runs,
                    'n_test_labels': n_test_labels,
                    'role': 'binary_anomaly_ablation',
                    **ae_m,
                })
    return pd.DataFrame(rows)


def summarize(fold_df: pd.DataFrame) -> pd.DataFrame:
    sup = fold_df[fold_df['model'].isin(['RandomForest', 'XGBoost'])].copy()
    if sup.empty:
        return pd.DataFrame()
    rows = []
    for (fs, model), g in sup.groupby(['feature_set', 'model']):
        rec = g['recall_heldout_label']
        f1 = g['f1_macro']
        rows.append({
            'feature_set': fs,
            'model': model,
            'n_scenarios': int(len(g)),
            'recall_heldout_mean': rec.mean(),
            'recall_heldout_std': rec.std(ddof=1) if len(g) > 1 else 0.0,
            'recall_heldout_min': rec.min(),
            'recall_heldout_max': rec.max(),
            'f1_macro_mean': f1.mean(),
            'f1_macro_std': f1.std(ddof=1) if len(g) > 1 else 0.0,
            'f1_macro_min': f1.min(),
            'f1_macro_max': f1.max(),
            'accuracy_mean': g['accuracy'].mean(),
            'note': 'headline=recall_heldout min-max; f1_macro noisy on single-class holdouts',
        })
        for lab, lg in g.groupby('heldout_label'):
            rows.append({
                'feature_set': fs,
                'model': model,
                'n_scenarios': int(len(lg)),
                'heldout_label': lab,
                'recall_heldout_mean': lg['recall_heldout_label'].mean(),
                'recall_heldout_std': lg['recall_heldout_label'].std(ddof=1) if len(lg) > 1 else 0.0,
                'recall_heldout_min': lg['recall_heldout_label'].min(),
                'recall_heldout_max': lg['recall_heldout_label'].max(),
                'f1_macro_mean': lg['f1_macro'].mean(),
                'note': f'per-label holdout ({lab})',
            })
    return pd.DataFrame(rows)


def inventory(polls: pd.DataFrame, tuples: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for sid, g in polls.groupby('scenario_id'):
        t = tuples[tuples['scenario_id'] == sid]
        rows.append({
            'scenario_id': sid,
            'label': g['label'].mode().iat[0],
            'n_runs': int(g['run_id'].nunique()),
            'n_poll_rows': int(len(g)),
            'n_unique_5tuples': int(len(t)),
            'poll_to_tuple_ratio': (len(g) / len(t)) if len(t) else np.nan,
        })
    return pd.DataFrame(rows).sort_values(['label', 'scenario_id'])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=GROUPED_CSV)
    ap.add_argument(
        '--feature-set',
        default='primary',
        choices=['primary', 'all', 'with_raw_ports', 'no_raw_ports', 'behavior_window'],
        help='primary = no_raw_ports + with_raw_ports diagnostic',
    )
    ap.add_argument('--with-unsupervised', action='store_true',
                    help='IF/AE binary ablation (slow for AE)')
    args = ap.parse_args()
    os.makedirs(REPORTS, exist_ok=True)

    print('=' * 64)
    print('  PROTOCOL D — Leave-One-Scenario-Out')
    print('  Does NOT modify model_comparison.csv or grouped_real_only_*')
    print('=' * 64)

    polls = load_clean(args.data)
    polls = attach_window_behavior(polls)
    tuples = last_poll_per_tuple(polls)
    print(f'[*] poll rows={len(polls)} | unique 5-tuples (last poll)={len(tuples)}')
    print(f'[*] scenarios={tuples["scenario_id"].nunique()} | runs={tuples["run_id"].nunique()}')
    print(tuples.groupby(['label', 'scenario_id']).size().to_string())

    inv = inventory(polls, tuples)
    inv_path = os.path.join(REPORTS, 'scenario_inventory.csv')
    inv.to_csv(inv_path, index=False)

    if args.feature_set == 'primary':
        sets = ['with_raw_ports', 'no_raw_ports']
    elif args.feature_set == 'all':
        sets = list(FEATURE_SETS)
    else:
        sets = [args.feature_set]

    frames = []
    for name in sets:
        cols = FEATURE_SETS[name]
        missing = [c for c in cols if c not in tuples.columns]
        if missing:
            raise SystemExit(f'Feature set {name} missing columns: {missing}')
        print(f'\n=== feature_set={name} | cols={cols} ===')
        frames.append(run_loso(tuples, cols, name, args.with_unsupervised))

    fold_df = pd.concat(frames, ignore_index=True)
    fold_path = os.path.join(REPORTS, 'scenario_held_out_per_scenario.csv')
    fold_df.to_csv(fold_path, index=False)

    summary = summarize(fold_df)
    sum_path = os.path.join(REPORTS, 'scenario_held_out_summary.csv')
    summary.to_csv(sum_path, index=False)

    pd.DataFrame([{
        'status': 'ok',
        'protocol': 'leave_one_scenario_out',
        'n_poll_rows': len(polls),
        'n_eval_tuples': len(tuples),
        'n_scenarios': int(tuples['scenario_id'].nunique()),
        'n_runs': int(tuples['run_id'].nunique()),
        'primary_feature_set': 'no_raw_ports',
        'headline_metric': 'recall_heldout_label mean / min / max',
        'legacy_random_split': 'reports/model_comparison.csv (appendix only)',
        'grouped_by_run': 'reports/grouped_real_only_summary.csv (intermediate; scenario overlap)',
        'primary_reports': 'scenario_held_out_summary.csv + scenario_held_out_per_scenario.csv',
        'do_not_cite_as_generalization': 'random Acc 0.9999 ; grouped-by-run Acc ~0.98',
    }]).to_csv(os.path.join(REPORTS, 'scenario_held_out_STATUS.csv'), index=False)

    print('\n' + '=' * 64)
    print(summary.to_string(index=False))
    print(f'\n[✓] {inv_path}')
    print(f'[✓] {fold_path}')
    print(f'[✓] {sum_path}')
    print('[*] Controller models were NOT retrained')


if __name__ == '__main__':
    main()

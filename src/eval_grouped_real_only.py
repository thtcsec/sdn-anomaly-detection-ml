"""
Grouped real-only evaluation (scenario-/run-isolated).

Rules:
  - Test folds: is_synthetic==0 AND run_id known (not unknown/legacy)
  - Split by GroupKFold / LeaveOneGroupOut on run_id (NOT flow-level StratifiedKFold)
  - Scaler (+ optional SMOTE) fit on TRAIN fold only
  - Test fold never gets SMOTE/bootstrap
  - Does NOT overwrite reports/model_comparison.csv (legacy benchmark)

Fails clearly if insufficient independent runs/groups.

Chạy:
  python src/ensure_legacy_provenance.py
  python src/merge_independent_runs.py
  python src/eval_grouped_real_only.py
  python src/eval_grouped_real_only.py --with-smote-train
  python src/audit_feature_overlap.py --grouped
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
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupKFold, LeaveOneGroupOut
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import FEATURE_COLS  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUPED_CSV = os.path.join(BASE_DIR, 'dataset', 'flow_stats_grouped.csv')
REPORTS = os.path.join(BASE_DIR, 'reports')
MIN_GROUPS = 3
MIN_LABELS = 2


def _require_imblearn():
    from imblearn.over_sampling import SMOTE
    return SMOTE


def load_grouped_real(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f'Missing {path}. Run ensure_legacy_provenance.py then merge_independent_runs.py'
        )
    df = pd.read_csv(path)
    if 'is_synthetic' not in df.columns or 'run_id' not in df.columns:
        raise ValueError('Grouped CSV missing is_synthetic/run_id columns')

    real = df[df['is_synthetic'].fillna(0).astype(int) == 0].copy()
    # Exclude legacy/unknown from grouped protocol
    real = real[~real['run_id'].astype(str).isin(['unknown', 'nan', '', 'None'])]
    real = real.dropna(subset=FEATURE_COLS + ['label'])
    real['label'] = real['label'].astype(str).str.lower()
    return real


def _choose_splitter(n_groups: int, min_groups: int = MIN_GROUPS):
    if n_groups < min_groups:
        return None, (
            f'Insufficient independent run_id groups for grouped eval: '
            f'have {n_groups}, need >= {min_groups}. '
            f'Collect more independent Mininet runs before claiming grouped metrics.'
        )
    if n_groups <= 5:
        return LeaveOneGroupOut(), 'LeaveOneGroupOut'
    return GroupKFold(n_splits=5), 'GroupKFold(n_splits=5)'


def _fit_predict_supervised(model, X_tr, y_tr, X_te, use_smote: bool):
    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)
    if use_smote:
        SMOTE = _require_imblearn()
        # SMOTE needs k_neighbors < minority count
        counts = pd.Series(y_tr).value_counts()
        k = max(1, min(5, int(counts.min()) - 1))
        if counts.min() < 2:
            pass
        else:
            try:
                X_tr_s, y_tr = SMOTE(random_state=42, k_neighbors=k).fit_resample(X_tr_s, y_tr)
            except ValueError:
                pass
    model.fit(X_tr_s, y_tr)
    return model.predict(X_te_s)


def _eval_if(X_tr, y_tr, X_te, y_te, le: LabelEncoder):
    """Isolation Forest binary: normal vs anomaly (ddos+portscan)."""
    classes = list(le.classes_)
    if 'normal' not in classes:
        return None
    normal_idx = list(le.transform(['normal']))[0]
    X_norm = X_tr[y_tr == normal_idx]
    if len(X_norm) < 5:
        return None
    scaler = StandardScaler()
    Xn = scaler.fit_transform(X_norm)
    Xt = scaler.transform(X_te)
    clf = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    clf.fit(Xn)
    pred_raw = clf.predict(Xt)
    # -1 anomaly -> 1, 1 normal -> 0 for binary anomaly label
    y_true_bin = (y_te != normal_idx).astype(int)
    y_pred_bin = (pred_raw == -1).astype(int)
    return {
        'accuracy': accuracy_score(y_true_bin, y_pred_bin),
        'precision_macro': precision_score(y_true_bin, y_pred_bin, zero_division=0),
        'recall_macro': recall_score(y_true_bin, y_pred_bin, zero_division=0),
        'f1_macro': f1_score(y_true_bin, y_pred_bin, zero_division=0),
        'ddos_recall': float('nan'),  # binary protocol
        'support': len(y_te),
    }


def _try_autoencoder(X_tr, y_tr, X_te, y_te, le: LabelEncoder):
    try:
        from tensorflow import keras
    except Exception:
        try:
            import tf_keras as keras
        except ImportError:
            return None
    classes = list(le.classes_)
    if 'normal' not in classes:
        return None
    normal_idx = list(le.transform(['normal']))[0]
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
        model.fit(Xn, Xn, epochs=30, batch_size=32, verbose=0)
    recon = model.predict(Xn, verbose=0)
    thr = np.percentile(np.mean((Xn - recon) ** 2, axis=1), 95)
    pred_mse = np.mean((Xt - model.predict(Xt, verbose=0)) ** 2, axis=1)
    y_true_bin = (y_te != normal_idx).astype(int)
    y_pred_bin = (pred_mse > thr).astype(int)
    return {
        'accuracy': accuracy_score(y_true_bin, y_pred_bin),
        'precision_macro': precision_score(y_true_bin, y_pred_bin, zero_division=0),
        'recall_macro': recall_score(y_true_bin, y_pred_bin, zero_division=0),
        'f1_macro': f1_score(y_true_bin, y_pred_bin, zero_division=0),
        'ddos_recall': float('nan'),
        'support': len(y_te),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=GROUPED_CSV)
    ap.add_argument('--with-smote-train', action='store_true',
                    help='Optional experiment: SMOTE inside train fold only')
    ap.add_argument('--min-groups', type=int, default=MIN_GROUPS)
    args = ap.parse_args()
    os.makedirs(REPORTS, exist_ok=True)

    print('=' * 60)
    print('  GROUPED REAL-ONLY EVALUATION (run-isolated)')
    print('  Legacy model_comparison.csv is NOT modified')
    print('=' * 60)

    try:
        real = load_grouped_real(args.data)
    except Exception as exc:
        print(f'[FAIL] {exc}')
        sys.exit(2)

    n_groups = real['run_id'].nunique()
    labels = sorted(real['label'].unique())
    print(f'[*] Rows={len(real)} | known run_id groups={n_groups} | labels={labels}')
    print(real.groupby(['run_id', 'label']).size().to_string())

    if len(labels) < MIN_LABELS:
        print(
            f'[FAIL] Need >= {MIN_LABELS} classes in known-run real data; have {labels}. '
            'Independent DDoS-only runs are not enough — also collect normal/portscan runs '
            'with run_id, or include multi-label sessions.'
        )
        # Still write a status file so thesis can say protocol ready but data insufficient
        pd.DataFrame([{
            'status': 'insufficient_labels',
            'n_groups': n_groups,
            'labels': ','.join(labels),
            'n_rows': len(real),
        }]).to_csv(os.path.join(REPORTS, 'grouped_real_only_STATUS.csv'), index=False)
        sys.exit(3)

    splitter, split_name = _choose_splitter(n_groups, min_groups=args.min_groups)
    if splitter is None:
        print(f'[FAIL] {split_name}')
        pd.DataFrame([{
            'status': 'insufficient_groups',
            'n_groups': n_groups,
            'min_groups_required': args.min_groups,
            'hint': 'Run sudo python3 src/collect_independent_ddos_runs.py for more independent runs',
        }]).to_csv(os.path.join(REPORTS, 'grouped_real_only_STATUS.csv'), index=False)
        sys.exit(3)

    print(f'[*] Splitter: {split_name}')

    le = LabelEncoder()
    y_all = le.fit_transform(real['label'])
    X_all = real[FEATURE_COLS].to_numpy()
    groups = real['run_id'].astype(str).to_numpy()

    models = {
        'RandomForest': RandomForestClassifier(
            n_estimators=200, max_depth=12, min_samples_leaf=2,
            class_weight='balanced_subsample', random_state=42, n_jobs=-1,
        ),
    }
    try:
        from xgboost import XGBClassifier
        models['XGBoost'] = XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8, random_state=42,
            eval_metric='mlogloss',
        )
    except ImportError:
        print('[!] xgboost not installed — skip XGBoost')

    fold_rows = []
    y_true_all = []
    y_pred_rf_all = []

    splits = list(splitter.split(X_all, y_all, groups))
    for fold, (tr, te) in enumerate(splits):
        X_tr, X_te = X_all[tr], X_all[te]
        y_tr, y_te = y_all[tr], y_all[te]
        g_te = sorted(set(groups[te]))
        print(f'\n--- Fold {fold} | test groups={g_te} | n_test={len(te)} ---')

        # Supervised models
        for name, proto in models.items():
            # fresh clone via re-init params
            if name == 'RandomForest':
                clf = RandomForestClassifier(
                    n_estimators=200, max_depth=12, min_samples_leaf=2,
                    class_weight='balanced_subsample', random_state=42, n_jobs=-1,
                )
            else:
                from xgboost import XGBClassifier
                clf = XGBClassifier(
                    n_estimators=200, max_depth=6, learning_rate=0.1,
                    subsample=0.8, colsample_bytree=0.8, random_state=42,
                    eval_metric='mlogloss',
                )
            y_pred = _fit_predict_supervised(clf, X_tr, y_tr, X_te, args.with_smote_train)
            if name == 'RandomForest':
                y_true_all.extend(y_te.tolist())
                y_pred_rf_all.extend(y_pred.tolist())

            # per-class F1 / ddos recall
            report = {}
            for cls_name, cls_id in zip(le.classes_, range(len(le.classes_))):
                mask = y_te == cls_id
                if mask.sum() == 0:
                    report[f'f1_{cls_name}'] = np.nan
                    report[f'support_{cls_name}'] = 0
                    report[f'recall_{cls_name}'] = np.nan
                else:
                    report[f'f1_{cls_name}'] = f1_score(
                        (y_te == cls_id).astype(int), (y_pred == cls_id).astype(int),
                        zero_division=0,
                    )
                    report[f'support_{cls_name}'] = int(mask.sum())
                    report[f'recall_{cls_name}'] = recall_score(
                        (y_te == cls_id).astype(int), (y_pred == cls_id).astype(int),
                        zero_division=0,
                    )

            fold_rows.append({
                'model': name,
                'fold': fold,
                'splitter': split_name,
                'smote_train': args.with_smote_train,
                'test_groups': ';'.join(g_te),
                'accuracy': accuracy_score(y_te, y_pred),
                'precision_macro': precision_score(y_te, y_pred, average='macro', zero_division=0),
                'recall_macro': recall_score(y_te, y_pred, average='macro', zero_division=0),
                'f1_macro': f1_score(y_te, y_pred, average='macro', zero_division=0),
                'ddos_recall': report.get('recall_ddos', np.nan),
                **report,
            })

        if_metrics = _eval_if(X_tr, y_tr, X_te, y_te, le)
        if if_metrics:
            fold_rows.append({
                'model': 'IsolationForest',
                'fold': fold,
                'splitter': split_name,
                'smote_train': False,
                'test_groups': ';'.join(g_te),
                **if_metrics,
            })

        ae_metrics = _try_autoencoder(X_tr, y_tr, X_te, y_te, le)
        if ae_metrics:
            fold_rows.append({
                'model': 'Autoencoder',
                'fold': fold,
                'splitter': split_name,
                'smote_train': False,
                'test_groups': ';'.join(g_te),
                **ae_metrics,
            })

    fold_df = pd.DataFrame(fold_rows)
    fold_path = os.path.join(REPORTS, 'grouped_real_only_per_fold.csv')
    fold_df.to_csv(fold_path, index=False)

    summary = (
        fold_df.groupby('model')[['accuracy', 'precision_macro', 'recall_macro', 'f1_macro', 'ddos_recall']]
        .agg(['mean', 'std', 'count'])
    )
    # flatten columns
    summary.columns = ['_'.join(c).strip('_') for c in summary.columns.to_flat_index()]
    summary = summary.reset_index()
    sum_path = os.path.join(REPORTS, 'grouped_real_only_summary.csv')
    summary.to_csv(sum_path, index=False)

    if y_true_all:
        cm = confusion_matrix(y_true_all, y_pred_rf_all)
        cm_df = pd.DataFrame(cm, index=le.classes_, columns=le.classes_)
        cm_df.to_csv(os.path.join(REPORTS, 'grouped_real_only_rf_confusion.csv'))

    pd.DataFrame([{
        'status': 'ok',
        'n_groups': n_groups,
        'n_rows': len(real),
        'splitter': split_name,
        'smote_train': args.with_smote_train,
        'legacy_benchmark': 'reports/model_comparison.csv (UNCHANGED)',
        'primary_conclusion': 'grouped_real_only_summary.csv',
    }]).to_csv(os.path.join(REPORTS, 'grouped_real_only_STATUS.csv'), index=False)

    print('\n' + '=' * 60)
    print(summary.to_string(index=False))
    print(f'\n[✓] {fold_path}')
    print(f'[✓] {sum_path}')
    print('[*] Legacy reports/model_comparison.csv was NOT modified')


if __name__ == '__main__':
    main()

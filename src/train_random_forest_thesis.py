"""
Random Forest — giao thức đánh giá cho luận văn (honest protocol).

DATASET / SPLITS
----------------
1) Full (official): train.csv / test.csv từ preprocess.py
   - Pool lab + bootstrap DDoS; SMOTE chỉ trên train.
   - Hyperparams giống train_random_forest.py.
   - Kỳ vọng Acc≈1.0 trên lab dễ tách — GIỮ trong model_comparison.csv.

2) Real-only holdout: is_synthetic==0, stratified 80/20, rs=42, NO SMOTE.
   - n_ddos_real=6 → test thường chỉ ~1 DDoS; Acc=1.0 là kết quả lab hợp lệ,
     không chứng minh generalization production.

3) PRIMARY (robustness, metrics không toàn 1.0): Real-only StratifiedKFold
   K=min(5, n_ddos_real). Báo Acc/F1 mean±std + per-fold.
   Macro-F1 dao động vì lớp DDoS cực nhỏ — đây là hạn chế dữ liệu, không phải
   "phá model".

4) OPTIONAL (domain-shift): train real-only, test = real holdout + bootstrap DDoS.
   Đo khả năng nhận diện mẫu bootstrap khi chỉ học từ DDoS lab thật.

KHÔNG thay đổi hàng RF official trong model_comparison.csv nếu Acc full vẫn 1.0.

Chạy: python src/train_random_forest_thesis.py
"""
from __future__ import annotations

import os
import sys
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

TRAIN_CSV = os.path.join(DATASET_DIR, "train.csv")
TEST_CSV = os.path.join(DATASET_DIR, "test.csv")
RAW_CSV = os.path.join(DATASET_DIR, "flow_stats.csv")

FEATURE_COLS = [
    "ip_proto",
    "tp_src",
    "tp_dst",
    "packet_count",
    "byte_count",
    "duration_sec",
    "packet_count_per_sec",
    "byte_count_per_sec",
    "packet_size_avg",
    "flow_duration",
]
LABEL_NAMES = ["ddos", "normal", "portscan"]


def make_rf() -> RandomForestClassifier:
    """Same hyperparams as train_random_forest.py (official)."""
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )


def score_pack(y_true, y_pred):
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(
            precision_score(y_true, y_pred, average="macro", zero_division=0)
        ),
        "recall_macro": float(
            recall_score(y_true, y_pred, average="macro", zero_division=0)
        ),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(
            f1_score(y_true, y_pred, average="weighted", zero_division=0)
        ),
    }


def save_cm(y_true, y_pred, labels, title, path):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels
    )
    plt.title(title)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[OK] Saved {path}")


def save_fi(model, feature_names, title, path):
    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1]
    plt.figure(figsize=(10, 6))
    plt.title(title)
    plt.bar(range(len(importance)), importance[indices], align="center")
    plt.xticks(
        range(len(importance)),
        [feature_names[i] for i in indices],
        rotation=45,
        ha="right",
    )
    plt.xlabel("Features")
    plt.ylabel("Importance")
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[OK] Saved {path}")
    fi_df = pd.DataFrame(
        {
            "feature": [feature_names[i] for i in indices],
            "importance": importance[indices],
        }
    )
    return fi_df


def load_real_only():
    if not os.path.exists(RAW_CSV):
        print(f"[!] Missing {RAW_CSV}")
        sys.exit(1)
    df = pd.read_csv(RAW_CSV)
    if "is_synthetic" not in df.columns:
        print("[!] Missing is_synthetic — chạy mark_data_provenance.py trước")
        sys.exit(1)
    df = df.drop_duplicates().dropna(subset=FEATURE_COLS + ["label"])
    real = df[df["is_synthetic"].fillna(0).astype(int) == 0].copy()
    syn = df[df["is_synthetic"].fillna(0).astype(int) == 1].copy()
    X_real = real[FEATURE_COLS]
    y_str = real["label"].astype(str).str.lower()
    le = LabelEncoder()
    # Fit on all three class names for stable mapping
    le.fit(LABEL_NAMES)
    y_real = le.transform(y_str)
    return df, real, syn, X_real, y_real, le


def run_full_official():
    print("\n" + "=" * 60)
    print("  [1] FULL official: train.csv / test.csv (SMOTE train)")
    print("=" * 60)
    train = pd.read_csv(TRAIN_CSV)
    test = pd.read_csv(TEST_CSV)
    X_train = train.drop("label", axis=1)
    y_train = train["label"]
    X_test = test.drop("label", axis=1)
    y_test = test["label"]
    print(f"[*] Train={X_train.shape} Test={X_test.shape}")
    print("[*] Test support:", y_test.value_counts().sort_index().to_dict())

    scaler = StandardScaler()
    X_train_s = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns)
    X_test_s = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)

    model = make_rf()
    t0 = time.perf_counter()
    model.fit(X_train_s, y_train)
    train_sec = time.perf_counter() - t0
    y_pred = model.predict(X_test_s)
    m = score_pack(y_test, y_pred)
    print(
        f"Acc={m['accuracy']:.6f}  P={m['precision_macro']:.6f}  "
        f"R={m['recall_macro']:.6f}  F1={m['f1_macro']:.6f}"
    )
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES, digits=4))

    # Refresh official artifacts (same as train_random_forest.py outputs)
    save_cm(
        y_test,
        y_pred,
        LABEL_NAMES,
        "Confusion Matrix - Random Forest (Full / official)",
        os.path.join(REPORTS_DIR, "confusion_matrix_random_forest.png"),
    )
    fi_df = save_fi(
        model,
        list(X_train.columns),
        "Feature Importance - Random Forest (Full)",
        os.path.join(REPORTS_DIR, "feature_importance_random_forest.png"),
    )
    fi_df.to_csv(
        os.path.join(REPORTS_DIR, "random_forest_feature_importance.csv"), index=False
    )

    metrics_df = pd.DataFrame(
        [
            {
                "Model": "Random Forest",
                "Approach": "Supervised",
                "Classification": "Multiclass",
                "Accuracy": m["accuracy"],
                "Precision": m["precision_macro"],
                "Recall": m["recall_macro"],
                "F1-Score": m["f1_macro"],
                "Train_Time_sec": train_sec,
            }
        ]
    )
    metrics_df.to_csv(
        os.path.join(REPORTS_DIR, "random_forest_metrics.csv"), index=False
    )

    report_dict = classification_report(
        y_test, y_pred, target_names=LABEL_NAMES, digits=4, output_dict=True
    )
    rows = []
    for cls in LABEL_NAMES:
        rows.append(
            {
                "Class": cls,
                "Precision": report_dict[cls]["precision"],
                "Recall": report_dict[cls]["recall"],
                "F1-Score": report_dict[cls]["f1-score"],
                "Support": int(report_dict[cls]["support"]),
            }
        )
    pd.DataFrame(rows).to_csv(
        os.path.join(REPORTS_DIR, "random_forest_classification_report.csv"),
        index=False,
    )

    joblib.dump(model, os.path.join(MODELS_DIR, "random_forest_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "random_forest_scaler.pkl"))
    return m


def run_real_only_holdout(X_real, y_real, le):
    print("\n" + "=" * 60)
    print("  [2] REAL-ONLY holdout 80/20 (NO SMOTE)")
    print("=" * 60)
    n_ddos = int((y_real == le.transform(["ddos"])[0]).sum())
    n_normal = int((y_real == le.transform(["normal"])[0]).sum())
    n_portscan = int((y_real == le.transform(["portscan"])[0]).sum())
    print(f"[*] n_real={len(y_real)} ddos={n_ddos} normal={n_normal} portscan={n_portscan}")

    X_train, X_test, y_train, y_test = train_test_split(
        X_real, y_real, test_size=0.2, random_state=42, stratify=y_real
    )
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    model = make_rf()
    model.fit(X_train_s, y_train)
    y_pred = model.predict(X_test_s)
    m = score_pack(y_test, y_pred)
    print(
        f"Acc={m['accuracy']:.6f}  P={m['precision_macro']:.6f}  "
        f"R={m['recall_macro']:.6f}  F1={m['f1_macro']:.6f}"
    )
    print(
        classification_report(
            y_test, y_pred, target_names=list(le.classes_), digits=4, zero_division=0
        )
    )

    save_cm(
        y_test,
        y_pred,
        list(le.classes_),
        "Confusion Matrix - RF Real-only 80/20",
        os.path.join(REPORTS_DIR, "confusion_matrix_random_forest_real_only.png"),
    )
    fi_df = save_fi(
        model,
        FEATURE_COLS,
        "Feature Importance - RF Real-only",
        os.path.join(REPORTS_DIR, "feature_importance_random_forest_real_only.png"),
    )
    fi_df.to_csv(
        os.path.join(REPORTS_DIR, "random_forest_real_only_feature_importance.csv"),
        index=False,
    )

    out = pd.DataFrame(
        [
            {
                "setting": "real_only_retrain_rf",
                "n_real_rows": len(y_real),
                "n_ddos_real": n_ddos,
                "n_normal_real": n_normal,
                "n_portscan_real": n_portscan,
                "split": "stratified_80_20",
                "smote": False,
                "n_train": len(y_train),
                "n_test": len(y_test),
                "accuracy": m["accuracy"],
                "precision_macro": m["precision_macro"],
                "recall_macro": m["recall_macro"],
                "f1_macro": m["f1_macro"],
                "f1_weighted": m["f1_weighted"],
            }
        ]
    )
    out.to_csv(
        os.path.join(REPORTS_DIR, "random_forest_real_only_metrics.csv"), index=False
    )
    print("[OK] Saved reports/random_forest_real_only_metrics.csv")
    return m, n_ddos, n_normal, n_portscan


def run_real_only_cv(X_real, y_real, le):
    print("\n" + "=" * 60)
    print("  [3] PRIMARY: REAL-ONLY StratifiedKFold (honest variance)")
    print("=" * 60)
    min_class = int(pd.Series(y_real).value_counts().min())
    k = min(5, min_class)
    if k < 2:
        print("[!] Không đủ mẫu minority cho CV có nghĩa.")
        return None
    print(f"[*] K={k} (min class count={min_class}, n_ddos_real={min_class if min_class<=6 else 'n/a'})")

    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    fold_rows = []
    ddos_id = int(le.transform(["ddos"])[0])

    for i, (tr, te) in enumerate(skf.split(X_real, y_real), 1):
        scaler = StandardScaler()
        X_tr = scaler.fit_transform(X_real.iloc[tr])
        X_te = scaler.transform(X_real.iloc[te])
        model = make_rf()
        model.fit(X_tr, y_real[tr])
        y_pred = model.predict(X_te)
        m = score_pack(y_real[te], y_pred)
        n_ddos_te = int((y_real[te] == ddos_id).sum())
        n_ddos_correct = int(
            ((y_real[te] == ddos_id) & (y_pred == ddos_id)).sum()
        )
        print(
            f"  Fold {i}: Acc={m['accuracy']:.6f} P={m['precision_macro']:.6f} "
            f"R={m['recall_macro']:.6f} F1={m['f1_macro']:.6f} "
            f"ddos_test={n_ddos_te} ddos_correct={n_ddos_correct}"
        )
        fold_rows.append(
            {
                "Fold": i,
                "Accuracy": m["accuracy"],
                "Precision_macro": m["precision_macro"],
                "Recall_macro": m["recall_macro"],
                "F1_macro": m["f1_macro"],
                "F1_weighted": m["f1_weighted"],
                "n_test": len(te),
                "n_ddos_in_test": n_ddos_te,
                "n_ddos_correct": n_ddos_correct,
            }
        )

    folds = pd.DataFrame(fold_rows)
    summary = {
        "protocol": "real_only_stratified_kfold",
        "k": k,
        "n_real": len(y_real),
        "n_ddos_real": int((y_real == ddos_id).sum()),
        "smote": False,
        "hyperparams": "same_as_train_random_forest.py",
        "accuracy_mean": float(folds["Accuracy"].mean()),
        "accuracy_std": float(folds["Accuracy"].std(ddof=0)),
        "precision_macro_mean": float(folds["Precision_macro"].mean()),
        "precision_macro_std": float(folds["Precision_macro"].std(ddof=0)),
        "recall_macro_mean": float(folds["Recall_macro"].mean()),
        "recall_macro_std": float(folds["Recall_macro"].std(ddof=0)),
        "f1_macro_mean": float(folds["F1_macro"].mean()),
        "f1_macro_std": float(folds["F1_macro"].std(ddof=0)),
    }
    print(
        f"  MEAN+/-STD Acc={summary['accuracy_mean']:.6f}+/-{summary['accuracy_std']:.6f}  "
        f"F1={summary['f1_macro_mean']:.6f}+/-{summary['f1_macro_std']:.6f}"
    )

    folds.to_csv(os.path.join(REPORTS_DIR, "random_forest_cv_folds.csv"), index=False)
    pd.DataFrame([summary]).to_csv(
        os.path.join(REPORTS_DIR, "random_forest_cv_results.csv"), index=False
    )
    print("[OK] Saved reports/random_forest_cv_folds.csv")
    print("[OK] Saved reports/random_forest_cv_results.csv")

    # Also write a combined thesis metrics table
    return summary, folds


def run_domain_shift(df, X_real, y_real, le):
    print("\n" + "=" * 60)
    print("  [4] OPTIONAL domain-shift: train real / test + bootstrap DDoS")
    print("=" * 60)
    syn_mask = df["is_synthetic"].fillna(0).astype(int) == 1
    ddos_mask = df["label"].astype(str).str.lower() == "ddos"
    boot = df[syn_mask & ddos_mask]
    if len(boot) == 0:
        print("[!] No bootstrap DDoS — skip F")
        return None

    X_train, X_hold, y_train, y_hold = train_test_split(
        X_real, y_real, test_size=0.2, random_state=42, stratify=y_real
    )
    X_boot = boot[FEATURE_COLS]
    y_boot = le.transform(boot["label"].astype(str).str.lower())
    X_test = pd.concat([X_hold, X_boot], axis=0)
    y_test = np.concatenate([y_hold, y_boot])

    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_train)
    X_te_s = scaler.transform(X_test)
    model = make_rf()
    model.fit(X_tr_s, y_train)
    y_pred = model.predict(X_te_s)
    m = score_pack(y_test, y_pred)
    print(
        f"Acc={m['accuracy']:.6f}  P={m['precision_macro']:.6f}  "
        f"R={m['recall_macro']:.6f}  F1={m['f1_macro']:.6f}"
    )
    print(
        classification_report(
            y_test, y_pred, target_names=list(le.classes_), digits=4, zero_division=0
        )
    )

    # Bootstrap-only accuracy
    y_pred_boot = model.predict(scaler.transform(X_boot))
    boot_acc = float(accuracy_score(y_boot, y_pred_boot))
    hold_m = score_pack(y_hold, model.predict(scaler.transform(X_hold)))

    save_cm(
        y_test,
        y_pred,
        list(le.classes_),
        "Confusion Matrix - RF Domain-shift (real train / +bootstrap test)",
        os.path.join(REPORTS_DIR, "confusion_matrix_random_forest_domain_shift.png"),
    )

    out = pd.DataFrame(
        [
            {
                "setting": "domain_shift_real_train_boot_test",
                "n_train_real": len(y_train),
                "n_test_real_holdout": len(y_hold),
                "n_test_bootstrap_ddos": len(y_boot),
                "n_test_total": len(y_test),
                "accuracy": m["accuracy"],
                "precision_macro": m["precision_macro"],
                "recall_macro": m["recall_macro"],
                "f1_macro": m["f1_macro"],
                "real_holdout_accuracy": hold_m["accuracy"],
                "bootstrap_ddos_accuracy": boot_acc,
            }
        ]
    )
    out.to_csv(
        os.path.join(REPORTS_DIR, "random_forest_domain_shift_metrics.csv"), index=False
    )
    print("[OK] Saved reports/random_forest_domain_shift_metrics.csv")
    return m, boot_acc, hold_m


def write_protocol_note(full_m, real_m, cv_summary, folds, domain):
    path = os.path.join(REPORTS_DIR, "rf_protocol_note.txt")
    lines = []
    lines.append("RF PROTOCOL NOTE — dùng cho bảng luận văn")
    lines.append("=" * 60)
    lines.append("")
    lines.append("QUYẾT ĐỊNH (primary protocol)")
    lines.append("-----------------------------")
    lines.append(
        "Báo cáo SONG SONG: (A) Full official + Real-only 80/20, và "
        "(B) Real-only StratifiedKFold K=5 làm kiểm chứng độ vững."
    )
    lines.append("")
    lines.append("Lý do:")
    lines.append(
        "- A/B/D/E (holdout đơn) đều cho Acc/F1 = 1.0000 trên lab dễ tách — "
        "hợp lệ nhưng dễ bị hiểu nhầm là 'hoàn hảo'."
    )
    lines.append(
        "- Constrained RF (max_depth=8, min_samples_leaf=5) VẪN Acc=1.0 → "
        "KHÔNG dùng siêu tham số chặt hơn chỉ để 'hạ số'."
    )
    lines.append(
        "- Real-only CV K=5 cho F1_macro mean±std < 1.0 một cách trung thực, "
        "vì n_ddos_real=6: một fold sai 1 mẫu DDoS làm macro-F1 tụt mạnh."
    )
    lines.append("")
    lines.append("SỐ LIỆU CHÍNH (sao chép vào Word)")
    lines.append("---------------------------------")
    lines.append(
        f"Full (official test.csv): Acc={full_m['accuracy']:.4f}  "
        f"P={full_m['precision_macro']:.4f}  R={full_m['recall_macro']:.4f}  "
        f"F1={full_m['f1_macro']:.4f}"
    )
    lines.append(
        f"Real-only 80/20 (NO SMOTE): Acc={real_m['accuracy']:.4f}  "
        f"P={real_m['precision_macro']:.4f}  R={real_m['recall_macro']:.4f}  "
        f"F1={real_m['f1_macro']:.4f}"
    )
    if cv_summary is not None:
        lines.append(
            f"Real-only StratifiedKFold K={cv_summary['k']}: "
            f"Acc={cv_summary['accuracy_mean']:.4f}±{cv_summary['accuracy_std']:.4f}  "
            f"F1_macro={cv_summary['f1_macro_mean']:.4f}±{cv_summary['f1_macro_std']:.4f}"
        )
        lines.append("Per-fold F1_macro: " + ", ".join(
            f"{v:.4f}" for v in folds["F1_macro"].tolist()
        ))
    if domain is not None:
        m, boot_acc, hold_m = domain
        lines.append(
            f"Domain-shift (optional): Acc={m['accuracy']:.4f}  "
            f"F1={m['f1_macro']:.4f}  "
            f"(bootstrap DDoS Acc={boot_acc:.4f}; real holdout Acc={hold_m['accuracy']:.4f})"
        )
    lines.append("")
    lines.append("CÁCH VIẾT TRONG LUẬN VĂN (tiếng Việt)")
    lines.append("------------------------------------")
    lines.append(
        "\"Trên tập kiểm thử chính thức (lab + bootstrap, SMOTE chỉ ở train), "
        "Random Forest đạt Accuracy = 1,0000 — cao nhất trên tập thực nghiệm hiện tại. "
        "Kết quả này phản ánh tính dễ tách của traffic trong môi trường lab, "
        "không được diễn giải là hiệu năng tuyệt đối trên mạng thực.\""
    )
    lines.append("")
    lines.append(
        "\"Khi đánh giá chỉ trên mẫu thực (is_synthetic=0; n_ddos_real=6) bằng "
        "Stratified 5-fold CV, Accuracy trung bình ≈ 0,9997±0,0004 nhưng "
        "F1-macro ≈ 0,8994±0,1343 — phương sai lớn vì lớp DDoS thực quá ít; "
        "một fold sai duy nhất một mẫu DDoS làm giảm mạnh macro-F1.\""
    )
    lines.append("")
    lines.append("model_comparison.csv: GIỮ hàng RF Acc=1.0 (official full).")
    lines.append("Bảng bổ sung: reports/random_forest_cv_results.csv + full_vs_real_only.")
    lines.append("")
    lines.append("Tái tạo:")
    lines.append("  python src/train_random_forest_thesis.py")
    lines.append("  python src/build_full_vs_real_only.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[OK] Saved {path}")


def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)
    print("=" * 60)
    print("  RF THESIS PROTOCOL (honest evaluation)")
    print("=" * 60)

    if not os.path.exists(TRAIN_CSV) or not os.path.exists(TEST_CSV):
        print("[!] Missing train/test — chạy preprocess.py trước")
        sys.exit(1)

    full_m = run_full_official()
    df, real, syn, X_real, y_real, le = load_real_only()
    real_m, n_ddos, n_normal, n_portscan = run_real_only_holdout(X_real, y_real, le)
    cv_out = run_real_only_cv(X_real, y_real, le)
    if cv_out is None:
        cv_summary, folds = None, None
    else:
        cv_summary, folds = cv_out
    domain = run_domain_shift(df, X_real, y_real, le)

    # Thesis summary table
    rows = [
        {
            "Protocol": "A_full_official",
            "Accuracy": full_m["accuracy"],
            "Precision_macro": full_m["precision_macro"],
            "Recall_macro": full_m["recall_macro"],
            "F1_macro": full_m["f1_macro"],
            "Notes": "train.csv/test.csv; SMOTE train only",
        },
        {
            "Protocol": "B_real_only_80_20",
            "Accuracy": real_m["accuracy"],
            "Precision_macro": real_m["precision_macro"],
            "Recall_macro": real_m["recall_macro"],
            "F1_macro": real_m["f1_macro"],
            "Notes": f"is_synthetic==0; n_ddos_real={n_ddos}; NO SMOTE",
        },
    ]
    if cv_summary is not None:
        rows.append(
            {
                "Protocol": "C_real_only_cv_mean",
                "Accuracy": cv_summary["accuracy_mean"],
                "Precision_macro": cv_summary["precision_macro_mean"],
                "Recall_macro": cv_summary["recall_macro_mean"],
                "F1_macro": cv_summary["f1_macro_mean"],
                "Notes": (
                    f"StratifiedKFold K={cv_summary['k']}; "
                    f"Acc_std={cv_summary['accuracy_std']:.6f}; "
                    f"F1_std={cv_summary['f1_macro_std']:.6f}"
                ),
            }
        )
    if domain is not None:
        m, boot_acc, hold_m = domain
        rows.append(
            {
                "Protocol": "F_domain_shift",
                "Accuracy": m["accuracy"],
                "Precision_macro": m["precision_macro"],
                "Recall_macro": m["recall_macro"],
                "F1_macro": m["f1_macro"],
                "Notes": (
                    f"train real-only; test=real_holdout+bootstrap; "
                    f"boot_ddos_acc={boot_acc:.4f}"
                ),
            }
        )
    summary_path = os.path.join(REPORTS_DIR, "random_forest_thesis_protocols.csv")
    pd.DataFrame(rows).to_csv(summary_path, index=False)
    print(f"[OK] Saved {summary_path}")

    write_protocol_note(full_m, real_m, cv_summary, folds, domain)

    # Do NOT rewrite model_comparison Acc if still 1.0 — leave compare_models as source of truth
    print("\n[*] model_comparison.csv: không ghi đè (giữ RF Acc=1.0 official).")
    print("[*] Chạy build_full_vs_real_only.py để cập nhật bảng Full vs Real-only.")
    print("\n[OK] Thesis RF protocol complete.")


if __name__ == "__main__":
    main()

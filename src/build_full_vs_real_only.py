"""
Build reports/full_vs_real_only_comparison.csv from existing metric CSVs.

Sources (no retrain unless those files are missing — run eval scripts separately):
  - reports/model_comparison.csv          (XGBoost + RF full / official test)
  - reports/real_only_metrics.csv         (XGBoost real-only)
  - reports/random_forest_metrics.csv     (RF full detail; optional fallback)
  - reports/random_forest_real_only_metrics.csv

Run: python src/build_full_vs_real_only.py
"""
from __future__ import annotations

import os
import sys

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS = os.path.join(BASE_DIR, "reports")
OUT_CSV = os.path.join(REPORTS, "full_vs_real_only_comparison.csv")
OUT_README = os.path.join(REPORTS, "FULL_VS_REAL_ONLY_README.txt")

MODEL_CMP = os.path.join(REPORTS, "model_comparison.csv")
XGB_REAL = os.path.join(REPORTS, "real_only_metrics.csv")
RF_FULL = os.path.join(REPORTS, "random_forest_metrics.csv")
RF_REAL = os.path.join(REPORTS, "random_forest_real_only_metrics.csv")

README_TEXT = """FULL vs REAL-ONLY — cách đọc bảng so sánh
=============================================

Full (official test.csv từ preprocess)
--------------------------------------
- Tập test sau pipeline preprocess: gồm traffic lab + DDoS bootstrap
  trong pool dữ liệu (đánh dấu provenance qua is_synthetic).
- SMOTE chỉ áp dụng trên tập train, KHÔNG áp dụng trên test.
- Metrics lấy từ reports/model_comparison.csv (và random_forest_metrics.csv).

Real-only (is_synthetic == 0)
-----------------------------
- Chỉ giữ mẫu thực (is_synthetic==0); loại synthetic / bootstrap khỏi đánh giá này.
- DDoS real trong pool hiện tại: 6 mẫu (rất ít).
- Split stratified 80/20 (random_state=42) → tập test real-only RF có thể chỉ còn
  ~1 mẫu DDoS; Accuracy=1.0 trên holdout nhỏ là KẾT QUẢ LAB HỢP LỆ nhưng
  KHÔNG được diễn giải như bằng chứng tổng quát hóa production.
- XGBoost real-only: reports/real_only_metrics.csv (eval_real_only.py)
- RF real-only: reports/random_forest_real_only_metrics.csv (eval_rf_real_only.py), NO SMOTE.

Cách viết trong luận văn (khuyến nghị)
--------------------------------------
- Acc=1.0 của RF trên tập thực nghiệm hiện tại: viết \"cao nhất trên tập thực nghiệm
  hiện tại\" — KHÔNG viết \"tốt nhất tuyệt đối\" / \"tối ưu mọi điều kiện\".
- RF Acc=1.0 vs XGBoost Acc≈0.9991 trên Full KHÔNG chứng minh RF vượt trội cho
  production: chênh lệch rất nhỏ; hệ realtime ưu tiên XGBoost vì latency suy luận.
- Luôn nêu hạn chế: bootstrap DDoS, số DDoS real ít, real-only test nhỏ.

Tái tạo bảng
------------
  python src/build_full_vs_real_only.py
Nếu thiếu real-only CSV:
  python src/eval_real_only.py
  python src/eval_rf_real_only.py
"""


def _require(path: str) -> None:
    if not os.path.exists(path):
        print(f"[!] Missing {path}")
        sys.exit(1)


def main() -> None:
    os.makedirs(REPORTS, exist_ok=True)
    for p in (MODEL_CMP, XGB_REAL, RF_REAL):
        _require(p)

    cmp_df = pd.read_csv(MODEL_CMP)
    xgb_full = cmp_df.loc[cmp_df["Model"].astype(str).str.strip() == "XGBoost"].iloc[0]
    rf_full_row = cmp_df.loc[cmp_df["Model"].astype(str).str.strip() == "Random Forest"]
    if len(rf_full_row) == 0 and os.path.exists(RF_FULL):
        rf_full = pd.read_csv(RF_FULL).iloc[0]
        rf_note = "from random_forest_metrics.csv (model_comparison missing RF)"
    else:
        rf_full = rf_full_row.iloc[0]
        rf_note = "official test.csv (lab+bootstrap pool); SMOTE train only"

    xgb_real = pd.read_csv(XGB_REAL).iloc[0]
    rf_real = pd.read_csv(RF_REAL).iloc[0]

    n_ddos = int(rf_real.get("n_ddos_real", xgb_real.get("n_ddos_real", 6)))
    n_test = rf_real.get("n_test", "")
    rows = [
        {
            "Model": "XGBoost",
            "Setting": "full",
            "Accuracy": float(xgb_full["Accuracy"]),
            "Precision_macro": float(xgb_full["Precision"]),
            "Recall_macro": float(xgb_full["Recall"]),
            "F1_macro": float(xgb_full["F1-Score"]),
            "Notes": "official test.csv (lab+bootstrap pool); SMOTE train only",
        },
        {
            "Model": "XGBoost",
            "Setting": "real_only",
            "Accuracy": float(xgb_real["accuracy"]),
            "Precision_macro": float(xgb_real["precision_macro"]),
            "Recall_macro": float(xgb_real["recall_macro"]),
            "F1_macro": float(xgb_real["f1_macro"]),
            "Notes": (
                f"is_synthetic==0; n_ddos_real={int(xgb_real['n_ddos_real'])}; "
                f"split={xgb_real['split']}; retrain no synthetic"
            ),
        },
        {
            "Model": "Random Forest",
            "Setting": "full",
            "Accuracy": float(rf_full["Accuracy"]),
            "Precision_macro": float(rf_full["Precision"]),
            "Recall_macro": float(rf_full["Recall"]),
            "F1_macro": float(rf_full["F1-Score"]),
            "Notes": rf_note,
        },
        {
            "Model": "Random Forest",
            "Setting": "real_only",
            "Accuracy": float(rf_real["accuracy"]),
            "Precision_macro": float(rf_real["precision_macro"]),
            "Recall_macro": float(rf_real["recall_macro"]),
            "F1_macro": float(rf_real["f1_macro"]),
            "Notes": (
                f"is_synthetic==0; n_ddos_real={n_ddos}; n_test={n_test}; "
                f"NO SMOTE; ~1 DDoS in stratified holdout possible; Acc=1.0 lab-only"
            ),
        },
    ]

    out = pd.DataFrame(
        rows,
        columns=[
            "Model",
            "Setting",
            "Accuracy",
            "Precision_macro",
            "Recall_macro",
            "F1_macro",
            "Notes",
        ],
    )
    out.to_csv(OUT_CSV, index=False)
    with open(OUT_README, "w", encoding="utf-8") as f:
        f.write(README_TEXT)
    print(out.to_string(index=False))
    print(f"[OK] Wrote {OUT_CSV}")
    print(f"[OK] Wrote {OUT_README}")


if __name__ == "__main__":
    main()

"""Ve lai bieu do khoa luan tu CSV da khoa. Khong bia so."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.titlesize": 12,
    "axes.labelsize": 10,
    "figure.dpi": 140,
})


def _save(fig, name: str) -> Path:
    path = REPORTS / name
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("[ok]", path)
    return path


def fig_loso() -> None:
    df = pd.read_csv(REPORTS / "binary_realtime_loso_summary.csv")
    order = ["XGBoost", "RandomForest", "Autoencoder", "IsolationForest"]
    labels = ["XGBoost", "Random Forest", "Autoencoder", "Isolation Forest"]
    df = df.set_index("model").loc[order]
    metrics = [
        ("pooled_f1_anomaly", "F1 lớp Attack"),
        ("attack_scenario_recall_mean", "Mean Attack Recall"),
        ("normal_scenario_fpr_mean", "Mean Normal FPR"),
    ]
    x = np.arange(len(order))
    width = 0.24
    fig, ax = plt.subplots(figsize=(9.2, 4.8))
    colors = ["#3d348b", "#7678ed", "#9aa0a6"]
    for i, (col, lab) in enumerate(metrics):
        ax.bar(x + (i - 1) * width, df[col].to_numpy(), width, label=lab, color=colors[i])
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Giá trị")
    ax.set_title("Leave-One-Scenario-Out, nhị phân Normal–Attack, 8 đặc trưng")
    ax.legend(frameon=False, loc="upper right")
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    _save(fig, "binary_realtime_loso_comparison.png")


def fig_split_vs_grouped() -> None:
    df = pd.read_csv(REPORTS / "split_vs_grouped.csv")
    models = ["RandomForest", "XGBoost"]
    model_lab = {"RandomForest": "Random Forest", "XGBoost": "XGBoost"}
    proto_lab = {
        "Random-flow split (lab dễ tách)": "Random-flow 80/20",
        "GroupKFold theo run_id": "GroupKFold theo run_id",
    }
    fig, axes = plt.subplots(1, 2, figsize=(9.4, 4.6), sharey=True)
    handles = []
    for ax, metric in zip(axes, ["Accuracy", "F1_macro"]):
        x = np.arange(len(models))
        width = 0.35
        for i, proto in enumerate(df["protocol"].unique()):
            vals = [
                float(df[(df["model"] == m) & (df["protocol"] == proto)][metric].iloc[0])
                for m in models
            ]
            bars = ax.bar(x + (i - 0.5) * width, vals, width, label=proto_lab.get(proto, proto))
            if ax is axes[0]:
                handles.append(bars)
            for xi, v in zip(x + (i - 0.5) * width, vals):
                ax.text(xi, min(v + 0.004, 1.018), f"{v:.3f}", ha="center", va="bottom", fontsize=8)
        ax.set_xticks(x, [model_lab[m] for m in models])
        ax.set_ylim(0.90, 1.035)
        ax.set_title(metric if metric == "Accuracy" else "F1-macro")
        ax.grid(axis="y", linestyle="--", alpha=0.35)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    fig.legend(
        handles,
        [proto_lab.get(p, p) for p in df["protocol"].unique()],
        loc="upper center",
        ncol=2,
        frameon=False,
        bbox_to_anchor=(0.5, 1.08),
    )
    fig.suptitle("Đối chiếu random-flow và GroupKFold theo run_id (không thay thế LOSO)", y=1.14)
    fig.tight_layout()
    _save(fig, "split_vs_grouped.png")


def fig_attack_recall() -> None:
    df = pd.read_csv(REPORTS / "binary_realtime_loso_per_scenario.csv")
    atk = df[df["heldout_label"] != "normal"].copy()
    keep = atk[atk["model"].isin(["XGBoost", "RandomForest"])]
    scenarios = sorted(keep["heldout_scenario"].unique())
    fig, ax = plt.subplots(figsize=(10.2, 5.2))
    x = np.arange(len(scenarios))
    width = 0.38
    for i, (model, color) in enumerate([("XGBoost", "#3d348b"), ("RandomForest", "#7678ed")]):
        sub = keep[keep["model"] == model].set_index("heldout_scenario").loc[scenarios]
        ax.bar(x + (i - 0.5) * width, sub["recall_anomaly"].to_numpy(), width, label=model, color=color)
    ax.axhline(0.1342, color="#c1121f", linestyle="--", linewidth=1, label="Min Recall XGBoost = 0,1342")
    short = [s.replace("portscan_", "ps_").replace("ddos_", "dd_") for s in scenarios]
    ax.set_xticks(x, short, rotation=55, ha="right", fontsize=7.5)
    ax.set_ylabel("Recall trên scenario Attack")
    ax.set_ylim(0, 1.08)
    ax.set_title("LOSO: Recall theo từng attack scenario (XGBoost và Random Forest)")
    ax.legend(frameon=False, fontsize=8)
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    _save(fig, "loso_attack_recall_per_scenario.png")


if __name__ == "__main__":
    fig_loso()
    fig_split_vs_grouped()
    fig_attack_recall()

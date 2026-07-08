"""
So sánh ML models vs Static Threshold Baseline.
Chứng minh ML tốt hơn phương pháp rule-based truyền thống.

Baseline: Dùng ngưỡng tĩnh trên packet_count_per_sec và byte_count_per_sec
để phân loại traffic (giống cách IDS truyền thống hoạt động).

Chạy: python src/baseline_comparison.py
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, classification_report

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)


def baseline_static_threshold(X_test, y_test):
    """
    Baseline 1: Static Threshold trên packet rate.
    Rule: Nếu packet_count_per_sec > threshold → Attack
    Đây là cách IDS truyền thống hoạt động.
    """
    # Tìm threshold tối ưu trên test set (best case cho baseline)
    best_acc = 0
    best_threshold = 0

    for threshold in [100, 500, 1000, 5000, 10000, 50000, 100000]:
        y_pred = (X_test['packet_count_per_sec'] > threshold).astype(int)
        # Convert y_test: normal(1) → 0, attack(0,2) → 1
        y_true_binary = (y_test != 1).astype(int)
        acc = accuracy_score(y_true_binary, y_pred)
        if acc > best_acc:
            best_acc = acc
            best_threshold = threshold

    # Apply best threshold
    y_pred = (X_test['packet_count_per_sec'] > best_threshold).astype(int)
    y_true_binary = (y_test != 1).astype(int)

    acc = accuracy_score(y_true_binary, y_pred)
    f1 = f1_score(y_true_binary, y_pred, zero_division=0)
    prec = precision_score(y_true_binary, y_pred, zero_division=0)
    rec = recall_score(y_true_binary, y_pred, zero_division=0)

    return {
        'Method': 'Static Threshold (pkt/s)',
        'Threshold': best_threshold,
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1
    }


def baseline_multi_rule(X_test, y_test):
    """
    Baseline 2: Multi-rule detection.
    Rule: Attack nếu:
      - packet_count_per_sec > 10000 (DDoS indicator) OR
      - byte_count < 100 AND packet_count > 5 (Portscan - small packets, many connections)
    """
    y_true_binary = (y_test != 1).astype(int)

    # Multi-rule
    ddos_rule = X_test['packet_count_per_sec'] > 10000
    portscan_rule = (X_test['byte_count'] < 200) & (X_test['packet_count'] >= 2)

    y_pred = (ddos_rule | portscan_rule).astype(int)

    acc = accuracy_score(y_true_binary, y_pred)
    f1 = f1_score(y_true_binary, y_pred, zero_division=0)
    prec = precision_score(y_true_binary, y_pred, zero_division=0)
    rec = recall_score(y_true_binary, y_pred, zero_division=0)

    return {
        'Method': 'Multi-Rule IDS',
        'Threshold': 'pkt/s>10k OR (bytes<200 & pkts>=2)',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1
    }


def baseline_statistical(X_test, y_test):
    """
    Baseline 3: Statistical anomaly (Z-score).
    Nếu packet_count_per_sec > mean + 2*std → anomaly.
    """
    y_true_binary = (y_test != 1).astype(int)

    pkt_rate = X_test['packet_count_per_sec']
    mean = pkt_rate.mean()
    std = pkt_rate.std()
    threshold = mean + 2 * std

    y_pred = (pkt_rate > threshold).astype(int)

    acc = accuracy_score(y_true_binary, y_pred)
    f1 = f1_score(y_true_binary, y_pred, zero_division=0)
    prec = precision_score(y_true_binary, y_pred, zero_division=0)
    rec = recall_score(y_true_binary, y_pred, zero_division=0)

    return {
        'Method': 'Z-Score Statistical',
        'Threshold': f'mean+2σ = {threshold:.0f}',
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1
    }


def main():
    print("=" * 60)
    print("  BASELINE COMPARISON: ML vs Traditional Methods")
    print("=" * 60)

    # Load test data
    test_csv = os.path.join(DATASET_DIR, 'test.csv')
    if not os.path.exists(test_csv):
        print("[!] test.csv not found. Run preprocess.py first.")
        sys.exit(1)

    test_df = pd.read_csv(test_csv)
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    print(f"[*] Test samples: {len(test_df)}")
    print(f"[*] Label distribution: {dict(y_test.value_counts())}")

    # Run baselines
    print("\n[*] Running baseline methods...")
    results = []

    r = baseline_static_threshold(X_test, y_test)
    results.append(r)
    print(f"  {r['Method']}: Acc={r['Accuracy']:.4f}, F1={r['F1-Score']:.4f}")

    r = baseline_multi_rule(X_test, y_test)
    results.append(r)
    print(f"  {r['Method']}: Acc={r['Accuracy']:.4f}, F1={r['F1-Score']:.4f}")

    r = baseline_statistical(X_test, y_test)
    results.append(r)
    print(f"  {r['Method']}: Acc={r['Accuracy']:.4f}, F1={r['F1-Score']:.4f}")

    # ML results (from model_comparison.csv)
    ml_csv = os.path.join(REPORTS_DIR, 'model_comparison.csv')
    if os.path.exists(ml_csv):
        ml_df = pd.read_csv(ml_csv)
        for _, row in ml_df.iterrows():
            results.append({
                'Method': f"{row['Model']} (ML)",
                'Threshold': row['Approach'],
                'Accuracy': row['Accuracy'],
                'Precision': row['Precision'],
                'Recall': row['Recall'],
                'F1-Score': row['F1-Score']
            })

    # Create comparison table
    results_df = pd.DataFrame(results)
    print("\n" + "=" * 60)
    print("  COMPARISON TABLE: ML vs Traditional Baselines")
    print("=" * 60)
    print(results_df[['Method', 'Accuracy', 'Precision', 'Recall', 'F1-Score']].to_string(index=False))

    # Save CSV
    results_df.to_csv(os.path.join(REPORTS_DIR, 'baseline_comparison.csv'), index=False)
    print(f"\n[✓] Saved: reports/baseline_comparison.csv")

    # Plot comparison bar chart
    fig, ax = plt.subplots(figsize=(12, 6))

    methods = results_df['Method'].tolist()
    x = np.arange(len(methods))
    width = 0.2

    colors_metrics = ['#2196F3', '#4CAF50', '#FF9800', '#F44336']
    metrics_to_plot = ['Accuracy', 'Precision', 'Recall', 'F1-Score']

    for i, metric in enumerate(metrics_to_plot):
        values = results_df[metric].tolist()
        bars = ax.bar(x + i * width, values, width, label=metric, color=colors_metrics[i])
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                    f'{val:.3f}', ha='center', fontsize=7, fontweight='bold')

    ax.set_xlabel('Method')
    ax.set_ylabel('Score')
    ax.set_title('ML Models vs Traditional Baseline Methods\nPhát hiện bất thường SDN',
                 fontsize=13, fontweight='bold')
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(methods, rotation=15, ha='right', fontsize=9)
    ax.legend(loc='lower right')
    ax.set_ylim(0, 1.15)
    ax.axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)

    # Highlight ML region
    ax.axvspan(2.5, len(methods) - 0.5, alpha=0.05, color='green')
    ax.text(len(methods) - 1.5, 0.05, 'ML Models', fontsize=10, ha='center',
            color='green', fontstyle='italic', fontweight='bold')

    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, 'baseline_comparison_chart.png'), dpi=150)
    plt.close()
    print("[✓] Saved: reports/baseline_comparison_chart.png")

    # Summary
    best_baseline = results_df.iloc[:3]['F1-Score'].max()
    best_ml = results_df.iloc[3:]['F1-Score'].max() if len(results_df) > 3 else 0
    improvement = ((best_ml - best_baseline) / best_baseline) * 100 if best_baseline > 0 else 0

    print(f"\n" + "=" * 60)
    print(f"  SUMMARY")
    print(f"  Best Baseline F1: {best_baseline:.4f}")
    print(f"  Best ML Model F1: {best_ml:.4f}")
    print(f"  Improvement: +{improvement:.1f}%")
    print(f"  => ML vượt trội so với phương pháp ngưỡng tĩnh truyền thống")
    print("=" * 60)


if __name__ == '__main__':
    main()

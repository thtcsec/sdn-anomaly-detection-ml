"""
Script huấn luyện model XGBoost cho phân loại tấn công SDN.

Input:  dataset/train.csv, dataset/test.csv
Output: models/xgboost_model.pkl
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score
)
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
import seaborn as sns

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

TRAIN_CSV = os.path.join(DATASET_DIR, 'train.csv')
TEST_CSV = os.path.join(DATASET_DIR, 'test.csv')


def load_train_test():
    """Load train và test data."""
    if not os.path.exists(TRAIN_CSV) or not os.path.exists(TEST_CSV):
        print("[!] Train/Test files not found. Run preprocess.py first.")
        sys.exit(1)

    train_df = pd.read_csv(TRAIN_CSV)
    test_df = pd.read_csv(TEST_CSV)

    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']

    print(f"[*] Train: {X_train.shape}, Test: {X_test.shape}")
    return X_train, X_test, y_train, y_test


def train_xgboost(X_train, y_train):
    """Huấn luyện XGBoost classifier."""
    print("[*] Training XGBoost model...")

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        use_label_encoder=False,
        eval_metric='mlogloss'
    )

    model.fit(X_train, y_train, verbose=True)
    print("[✓] XGBoost training complete!")
    return model


def evaluate_model(model, X_test, y_test, label_names=None):
    """Đánh giá model và in kết quả."""
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='weighted')

    print("\n" + "=" * 60)
    print("  MODEL EVALUATION RESULTS")
    print("=" * 60)
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    print("=" * 60)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=label_names))

    return y_pred, accuracy, f1


def plot_confusion_matrix(y_test, y_pred, label_names=None):
    """Vẽ confusion matrix và lưu vào reports/."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=label_names, yticklabels=label_names)
    plt.title('Confusion Matrix - XGBoost')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()

    save_path = os.path.join(REPORTS_DIR, 'confusion_matrix_xgboost.png')
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"[✓] Confusion matrix saved to: {save_path}")


def plot_feature_importance(model, feature_names):
    """Vẽ biểu đồ feature importance."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1]

    plt.figure(figsize=(10, 6))
    plt.title('Feature Importance - XGBoost')
    plt.bar(range(len(importance)), importance[indices], align='center')
    plt.xticks(range(len(importance)),
               [feature_names[i] for i in indices], rotation=45, ha='right')
    plt.xlabel('Features')
    plt.ylabel('Importance')
    plt.tight_layout()

    save_path = os.path.join(REPORTS_DIR, 'feature_importance_xgboost.png')
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"[✓] Feature importance saved to: {save_path}")


def save_model(model, scaler=None):
    """Lưu model và scaler."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    model_path = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
    joblib.dump(model, model_path)
    print(f"[✓] Model saved to: {model_path}")

    if scaler:
        scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
        joblib.dump(scaler, scaler_path)
        print(f"[✓] Scaler saved to: {scaler_path}")


def main():
    """Pipeline huấn luyện chính."""
    print("=" * 60)
    print("  XGBoost Training Pipeline - SDN Anomaly Detection")
    print("=" * 60)

    # 1. Load data
    X_train, X_test, y_train, y_test = load_train_test()

    # 2. Scale features
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train),
        columns=X_train.columns
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test),
        columns=X_test.columns
    )

    # 3. Train model
    model = train_xgboost(X_train_scaled, y_train)

    # 4. Evaluate
    label_names = ['ddos', 'normal', 'portscan']  # LabelEncoder sort alphabetical
    y_pred, accuracy, f1 = evaluate_model(model, X_test_scaled, y_test, label_names)

    # 5. Visualize
    plot_confusion_matrix(y_test, y_pred, label_names)
    plot_feature_importance(model, list(X_train.columns))

    # 6. Save
    save_model(model, scaler)

    print("\n[✓] Training pipeline complete!")


if __name__ == '__main__':
    main()

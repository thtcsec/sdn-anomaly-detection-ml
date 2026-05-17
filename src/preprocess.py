"""
Script tiền xử lý dữ liệu flow stats cho ML training.

Input:  dataset/flow_stats.csv (raw data từ controller)
Output: dataset/processed_data.csv (clean data sẵn sàng cho training)
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
RAW_CSV = os.path.join(DATASET_DIR, 'flow_stats.csv')
PROCESSED_CSV = os.path.join(DATASET_DIR, 'processed_data.csv')
TRAIN_CSV = os.path.join(DATASET_DIR, 'train.csv')
TEST_CSV = os.path.join(DATASET_DIR, 'test.csv')


def load_data(filepath=RAW_CSV):
    """Load raw CSV data."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    df = pd.read_csv(filepath)
    print(f"[*] Loaded {len(df)} records from {filepath}")
    print(f"[*] Columns: {list(df.columns)}")
    print(f"[*] Label distribution:\n{df['label'].value_counts()}")
    return df


def clean_data(df):
    """Làm sạch dữ liệu: xóa duplicates, handle missing values."""
    initial_len = len(df)

    # Xóa duplicates
    df = df.drop_duplicates()
    print(f"[*] Removed {initial_len - len(df)} duplicate rows")

    # Xóa rows có missing values
    df = df.dropna()
    print(f"[*] After cleaning: {len(df)} records")

    return df


def extract_features(df):
    """
    Trích xuất và chọn features cho ML model.
    Loại bỏ các cột không cần thiết (timestamp, IP addresses dạng string).
    """
    # Features số học dùng cho training
    feature_cols = [
        'ip_proto',
        'tp_src',
        'tp_dst',
        'packet_count',
        'byte_count',
        'duration_sec',
        'packet_count_per_sec',
        'byte_count_per_sec',
        'packet_size_avg',
        'flow_duration'
    ]

    # Kiểm tra các cột có tồn tại
    missing_cols = [col for col in feature_cols if col not in df.columns]
    if missing_cols:
        print(f"[!] Missing columns: {missing_cols}")
        print(f"[!] Available columns: {list(df.columns)}")
        sys.exit(1)

    # Tạo DataFrame với features đã chọn
    X = df[feature_cols].copy()
    y = df['label'].copy()

    print(f"[*] Selected {len(feature_cols)} features")
    print(f"[*] Features: {feature_cols}")

    return X, y


def encode_labels(y):
    """Encode labels thành số."""
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    print(f"[*] Label mapping: {dict(zip(le.classes_, le.transform(le.classes_)))}")
    return y_encoded, le


def scale_features(X_train, X_test):
    """Chuẩn hóa features bằng StandardScaler."""
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    return X_train_scaled, X_test_scaled, scaler


def preprocess_pipeline():
    """Pipeline tiền xử lý hoàn chỉnh."""
    print("=" * 60)
    print("  SDN Flow Data Preprocessing Pipeline")
    print("=" * 60)

    # 1. Load data
    df = load_data()

    # 2. Clean data
    df = clean_data(df)

    # 3. Extract features
    X, y = extract_features(df)

    # 4. Encode labels
    y_encoded, label_encoder = encode_labels(y)

    # 5. Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    print(f"[*] Train size: {len(X_train)}, Test size: {len(X_test)}")

    # 6. Save processed data
    train_df = pd.DataFrame(X_train, columns=X.columns)
    train_df['label'] = y_train
    train_df.to_csv(TRAIN_CSV, index=False)

    test_df = pd.DataFrame(X_test, columns=X.columns)
    test_df['label'] = y_test
    test_df.to_csv(TEST_CSV, index=False)

    # Save full processed data
    processed_df = pd.DataFrame(X, columns=X.columns)
    processed_df['label'] = y_encoded
    processed_df.to_csv(PROCESSED_CSV, index=False)

    print(f"\n[✓] Saved processed data to: {PROCESSED_CSV}")
    print(f"[✓] Saved train data to: {TRAIN_CSV}")
    print(f"[✓] Saved test data to: {TEST_CSV}")
    print("=" * 60)

    return X_train, X_test, y_train, y_test, label_encoder


if __name__ == '__main__':
    preprocess_pipeline()

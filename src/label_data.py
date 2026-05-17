"""
Script gán label cho flow_stats.csv dựa trên label_log.csv.

Controller ghi tất cả flow với label='normal' mặc định.
Script này đọc label_log (timestamp ranges) và update label
cho các rows nằm trong khoảng thời gian tấn công.

Chạy SAU khi collect_data.py hoàn thành:
  python src/label_data.py
"""

import os
import sys
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
CSV_FILE = os.path.join(DATASET_DIR, 'flow_stats.csv')
LABEL_LOG = os.path.join(DATASET_DIR, 'label_log.csv')


def main():
    print("=" * 60)
    print("  Label Assignment - SDN Flow Data")
    print("=" * 60)

    if not os.path.exists(CSV_FILE):
        print(f"[!] File not found: {CSV_FILE}")
        sys.exit(1)

    # Đọc CSV, tự thêm header nếu file không có
    COLUMNS = [
        'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'ip_dst',
        'ip_proto', 'tp_src', 'tp_dst', 'packet_count', 'byte_count',
        'duration_sec', 'duration_nsec', 'packet_count_per_sec',
        'byte_count_per_sec', 'packet_size_avg', 'flow_duration', 'label'
    ]

    # Check if first line is header or data
    with open(CSV_FILE, 'r') as f:
        first_line = f.readline().strip()

    if first_line.startswith('timestamp') or first_line.startswith('timestamp,'):
        df = pd.read_csv(CSV_FILE)
    else:
        df = pd.read_csv(CSV_FILE, header=None, names=COLUMNS)

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    print(f"[*] Loaded {len(df)} flow records")

    if not os.path.exists(LABEL_LOG):
        print(f"[!] Label log not found: {LABEL_LOG}")
        print("[!] Chạy 'sudo python3 src/collect_data.py' trước!")
        sys.exit(1)

    labels = pd.read_csv(LABEL_LOG)
    labels['start_time'] = pd.to_datetime(labels['start_time'])
    labels['end_time'] = pd.to_datetime(labels['end_time'])
    print(f"[*] Loaded {len(labels)} label entries")

    # Mặc định giữ label='normal'
    df['label'] = 'normal'

    for _, row in labels.iterrows():
        mask = (df['timestamp'] >= row['start_time']) & (df['timestamp'] <= row['end_time'])
        count = mask.sum()
        df.loc[mask, 'label'] = row['label']
        print(f"  [{row['label']}] {row['start_time']} -> {row['end_time']}: {count} rows")

    print(f"\n[*] Label distribution:")
    print(df['label'].value_counts().to_string())

    # Lưu file
    df.to_csv(CSV_FILE, index=False)
    print(f"\n[✓] Updated: {CSV_FILE}")
    print("=" * 60)


if __name__ == '__main__':
    main()

"""
Sinh thêm dữ liệu DDoS synthetic để cân bằng dataset.

Lý do: Dataset hiện tại chỉ có 6 mẫu DDoS (do thời gian lab hạn chế),
trong khi có 10565 portscan và 312 normal. Cần bổ sung để SMOTE
và model training hiệu quả hơn.

Phương pháp: Dựa trên đặc trưng thực tế của DDoS flow đã thu thập
(high packet_count, high byte_count_per_sec, high packet_count_per_sec),
sinh thêm các mẫu với variation hợp lý mô phỏng:
  - SYN Flood (TCP, port 80/443/8080)
  - UDP Flood (UDP, port 53/123/161)
  - ICMP Flood (ICMP, no port)

Chạy: python src/augment_ddos_data.py
"""

import os
import sys
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

np.random.seed(42)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
CSV_FILE = os.path.join(DATASET_DIR, 'flow_stats.csv')

# Số mẫu DDoS cần sinh thêm
NUM_SYN_FLOOD = 200   # TCP SYN Flood
NUM_UDP_FLOOD = 150   # UDP Flood
NUM_ICMP_FLOOD = 150  # ICMP Flood

# IP ranges
ATTACKER_IPS = ['10.0.0.4', '10.0.0.5', '10.0.0.6']
VICTIM_IPS = ['10.0.0.1', '10.0.0.2', '10.0.0.3']


def generate_syn_flood(n=NUM_SYN_FLOOD):
    """Sinh mẫu SYN Flood: TCP, high packet rate, target port 80/443."""
    records = []
    base_time = datetime(2026, 5, 15, 14, 0, 0)

    for i in range(n):
        ts = base_time + timedelta(seconds=np.random.randint(0, 300))
        attacker = np.random.choice(ATTACKER_IPS)
        victim = np.random.choice(VICTIM_IPS)
        tp_src = np.random.randint(1024, 65535)
        tp_dst = np.random.choice([80, 443, 8080, 8443])

        # DDoS characteristics: very high packet count, short packets
        packet_count = np.random.randint(50000, 8000000)
        byte_count = packet_count * np.random.randint(40, 66)  # SYN packets ~40-66 bytes
        duration_sec = np.random.randint(5, 90)
        duration_nsec = np.random.randint(0, 999999999)
        flow_duration = duration_sec + duration_nsec / 1e9
        pkt_per_sec = packet_count / flow_duration if flow_duration > 0 else 0
        byte_per_sec = byte_count / flow_duration if flow_duration > 0 else 0
        pkt_size_avg = byte_count / packet_count if packet_count > 0 else 0

        flow_id = hash((attacker, victim, 6, tp_src, tp_dst)) % (10**8)

        records.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'datapath_id': np.random.choice([1, 2]),
            'flow_id': flow_id,
            'ip_src': attacker,
            'ip_dst': victim,
            'ip_proto': 6,  # TCP
            'tp_src': tp_src,
            'tp_dst': tp_dst,
            'packet_count': packet_count,
            'byte_count': byte_count,
            'duration_sec': duration_sec,
            'duration_nsec': duration_nsec,
            'packet_count_per_sec': pkt_per_sec,
            'byte_count_per_sec': byte_per_sec,
            'packet_size_avg': pkt_size_avg,
            'flow_duration': flow_duration,
            'label': 'ddos'
        })

    return records


def generate_udp_flood(n=NUM_UDP_FLOOD):
    """Sinh mẫu UDP Flood: UDP, high bandwidth, target port 53/123."""
    records = []
    base_time = datetime(2026, 5, 15, 14, 5, 0)

    for i in range(n):
        ts = base_time + timedelta(seconds=np.random.randint(0, 300))
        attacker = np.random.choice(ATTACKER_IPS)
        victim = np.random.choice(VICTIM_IPS)
        tp_src = np.random.randint(1024, 65535)
        tp_dst = np.random.choice([53, 123, 161, 500, 1900])

        # UDP flood: large packets, very high byte rate
        packet_count = np.random.randint(100000, 7000000)
        byte_count = packet_count * np.random.randint(512, 1500)  # UDP can be larger
        duration_sec = np.random.randint(5, 90)
        duration_nsec = np.random.randint(0, 999999999)
        flow_duration = duration_sec + duration_nsec / 1e9
        pkt_per_sec = packet_count / flow_duration if flow_duration > 0 else 0
        byte_per_sec = byte_count / flow_duration if flow_duration > 0 else 0
        pkt_size_avg = byte_count / packet_count if packet_count > 0 else 0

        flow_id = hash((attacker, victim, 17, tp_src, tp_dst)) % (10**8)

        records.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'datapath_id': np.random.choice([1, 2]),
            'flow_id': flow_id,
            'ip_src': attacker,
            'ip_dst': victim,
            'ip_proto': 17,  # UDP
            'tp_src': tp_src,
            'tp_dst': tp_dst,
            'packet_count': packet_count,
            'byte_count': byte_count,
            'duration_sec': duration_sec,
            'duration_nsec': duration_nsec,
            'packet_count_per_sec': pkt_per_sec,
            'byte_count_per_sec': byte_per_sec,
            'packet_size_avg': pkt_size_avg,
            'flow_duration': flow_duration,
            'label': 'ddos'
        })

    return records


def generate_icmp_flood(n=NUM_ICMP_FLOOD):
    """Sinh mẫu ICMP Flood: ICMP, no port, high packet rate."""
    records = []
    base_time = datetime(2026, 5, 15, 14, 10, 0)

    for i in range(n):
        ts = base_time + timedelta(seconds=np.random.randint(0, 300))
        attacker = np.random.choice(ATTACKER_IPS)
        victim = np.random.choice(VICTIM_IPS)

        # ICMP flood: fixed size packets, very high rate
        packet_count = np.random.randint(200000, 9000000)
        byte_count = packet_count * np.random.randint(64, 128)  # ICMP echo ~64-128 bytes
        duration_sec = np.random.randint(5, 90)
        duration_nsec = np.random.randint(0, 999999999)
        flow_duration = duration_sec + duration_nsec / 1e9
        pkt_per_sec = packet_count / flow_duration if flow_duration > 0 else 0
        byte_per_sec = byte_count / flow_duration if flow_duration > 0 else 0
        pkt_size_avg = byte_count / packet_count if packet_count > 0 else 0

        flow_id = hash((attacker, victim, 1, 0, 0)) % (10**8)

        records.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'datapath_id': np.random.choice([1, 2]),
            'flow_id': flow_id,
            'ip_src': attacker,
            'ip_dst': victim,
            'ip_proto': 1,  # ICMP
            'tp_src': 0,
            'tp_dst': 0,
            'packet_count': packet_count,
            'byte_count': byte_count,
            'duration_sec': duration_sec,
            'duration_nsec': duration_nsec,
            'packet_count_per_sec': pkt_per_sec,
            'byte_count_per_sec': byte_per_sec,
            'packet_size_avg': pkt_size_avg,
            'flow_duration': flow_duration,
            'label': 'ddos'
        })

    return records


def main():
    print("=" * 60)
    print("  DDoS Data Augmentation - SDN Anomaly Detection")
    print("=" * 60)

    if not os.path.exists(CSV_FILE):
        print(f"[!] File not found: {CSV_FILE}")
        sys.exit(1)

    # Load existing data
    df = pd.read_csv(CSV_FILE)
    print(f"[*] Existing dataset: {len(df)} records")
    print(f"[*] Current label distribution:")
    print(df['label'].value_counts().to_string())
    print()

    # Generate synthetic DDoS data
    print("[*] Generating SYN Flood samples...")
    syn_records = generate_syn_flood()
    print(f"    Generated: {len(syn_records)} samples")

    print("[*] Generating UDP Flood samples...")
    udp_records = generate_udp_flood()
    print(f"    Generated: {len(udp_records)} samples")

    print("[*] Generating ICMP Flood samples...")
    icmp_records = generate_icmp_flood()
    print(f"    Generated: {len(icmp_records)} samples")

    # Combine
    all_new = syn_records + udp_records + icmp_records
    df_new = pd.DataFrame(all_new)
    print(f"\n[*] Total new DDoS samples: {len(df_new)}")

    # Append to existing dataset
    df_combined = pd.concat([df, df_new], ignore_index=True)
    df_combined.to_csv(CSV_FILE, index=False)

    print(f"\n[*] Updated dataset: {len(df_combined)} records")
    print(f"[*] New label distribution:")
    print(df_combined['label'].value_counts().to_string())
    print()
    print(f"[✓] Saved to: {CSV_FILE}")
    print("=" * 60)
    print("[*] Next step: python src/label_data.py (skip nếu đã có label)")
    print("[*] Then: python src/preprocess.py")
    print("[*] Then: python src/train_model.py")
    print("=" * 60)


if __name__ == '__main__':
    main()

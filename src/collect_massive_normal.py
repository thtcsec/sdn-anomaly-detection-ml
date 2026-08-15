"""
Thu thập phiên lab độc lập quy mô lớn cho lưu lượng NORMAL.
Ghi trực tiếp ra dataset/independent_runs/ và merge vào dataset chính.
"""

import os
import sys
import time
import uuid
import pandas as pd
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'src'))

from provenance_schema import (
    ALLOWED_LAB_IPV4,
    SOURCE_INDEPENDENT,
    TOPOLOGY_DEFAULT,
    FEATURE_COLS
)
from generate_diverse_normal import generate_massive_normal

DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
FLOW_STATS = os.path.join(DATASET_DIR, 'flow_stats.csv')
RUNS_DIR = os.path.join(DATASET_DIR, 'independent_runs')
MANIFEST = os.path.join(RUNS_DIR, 'manifest.csv')
LABEL_FILE = os.path.join(DATASET_DIR, 'current_label.txt')

def collect_massive_normal_runs(num_runs=3):
    os.makedirs(RUNS_DIR, exist_ok=True)
    with open(LABEL_FILE, 'w') as f:
        f.write('normal')

    total_collected = 0

    for r in range(1, num_runs + 1):
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        session_id = f"session_normal_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n==================================================")
        print(f"[*] Bắt đầu thu thập NORMAL Run #{r}/{num_runs}: {run_id}")
        print(f"==================================================")

        # Generate traffic
        generate_massive_normal(num_flows=5000, duration_sec=20)
        end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Export window from flow_stats if exists, or synthesize high-fidelity flow records
        n_flows = 0
        if os.path.exists(FLOW_STATS):
            try:
                df = pd.read_csv(FLOW_STATS)
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                part = df[(df['timestamp'] >= pd.to_datetime(start_time)) & (df['timestamp'] <= pd.to_datetime(end_time))].copy()
                if not part.empty:
                    part['label'] = 'normal'
                    part['is_synthetic'] = 0
                    part['source'] = SOURCE_INDEPENDENT
                    part['run_id'] = run_id
                    part['scenario_id'] = f'normal_massive_mesh_run_{r}'
                    part['capture_session_id'] = session_id
                    part['topology_id'] = TOPOLOGY_DEFAULT
                    out_path = os.path.join(RUNS_DIR, f"{run_id}.csv")
                    part.to_csv(out_path, index=False)
                    n_flows = len(part)
                    print(f"[✓] Đã xuất {n_flows} flow records vào {out_path}")
            except Exception as e:
                print(f"[!] Export window error: {e}")

        # Update manifest
        manifest_row = {
            'run_id': run_id,
            'scenario_id': f'normal_massive_mesh_run_{r}',
            'capture_session_id': session_id,
            'topology_id': TOPOLOGY_DEFAULT,
            'traffic_tool': 'python_mesh_sockets',
            'attack_protocol': 'none',
            'attack_rate': 'n/a',
            'attacker_count': 0,
            'target_host': 'all_hosts',
            'start_time': start_time,
            'end_time': end_time,
            'duration_sec': 20,
            'commands': '[["all", "generate_massive_normal"]]',
            'n_flows_exported': n_flows,
            'notes': 'massive_normal_mesh_lab_run; label=normal'
        }
        
        mf_df = pd.DataFrame([manifest_row])
        if os.path.exists(MANIFEST):
            mf_df.to_csv(MANIFEST, mode='a', header=False, index=False)
        else:
            mf_df.to_csv(MANIFEST, index=False)

        total_collected += n_flows
        time.sleep(2)

    print(f"\n[✓] TỔNG CỘNG THU THẬP THÀNH CÔNG: {total_collected} NORMAL FLOWS MỚI!")

if __name__ == '__main__':
    collect_massive_normal_runs(num_runs=3)

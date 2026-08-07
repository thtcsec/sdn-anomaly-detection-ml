"""
Thu thập phiên lab độc lập cho NORMAL / PORTSCAN (bổ sung DDoS runs).

Grouped evaluation cần >=2 nhãn với run_id thật.
Script này tạo các run độc lập cho normal và portscan — chỉ host 10.0.0.0/24.

T1: controller
T2: sudo python3 src/collect_independent_support_runs.py [--dry-run]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import uuid
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab_safety import assert_lab_targets, assert_no_default_route_hint  # noqa: E402
from provenance_schema import ALLOWED_LAB_IPV4, SOURCE_INDEPENDENT, TOPOLOGY_DEFAULT  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
FLOW_STATS = os.path.join(DATASET_DIR, 'flow_stats.csv')
RUNS_DIR = os.path.join(DATASET_DIR, 'independent_runs')
MANIFEST = os.path.join(RUNS_DIR, 'manifest.csv')
LOG_DIR = os.path.join(RUNS_DIR, 'run_logs')


def _now() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def scenarios():
    return [
        {
            'scenario_id': 'normal_ping_iperf_light',
            'label': 'normal',
            'attack_protocol': 'none',
            'attack_rate': 'n/a',
            'attacker_count': 0,
            'target_host': '10.0.0.4',
            'duration_sec': 30,
            'commands': [
                ('h1', 'timeout 30 ping -i 0.5 10.0.0.4 &'),
                ('h2', 'timeout 30 ping -i 0.8 10.0.0.5 &'),
                ('h2', 'iperf -s -p 5001 &'),
                ('h1', 'timeout 25 iperf -c 10.0.0.2 -p 5001 -t 20 &'),
            ],
            'kill': 'ping;iperf',
        },
        {
            'scenario_id': 'portscan_nmap_h4_h1',
            'label': 'portscan',
            'attack_protocol': 'tcp_syn_scan',
            'attack_rate': 'max-rate=200',
            'attacker_count': 1,
            'target_host': '10.0.0.1',
            'duration_sec': 35,
            'commands': [
                ('h4', 'timeout 35 nmap -sS -p 1-512 --max-rate 200 10.0.0.1 &'),
            ],
            'kill': 'nmap',
        },
        {
            'scenario_id': 'portscan_nmap_h5_h2',
            'label': 'portscan',
            'attack_protocol': 'tcp_syn_scan',
            'attack_rate': 'max-rate=150',
            'attacker_count': 1,
            'target_host': '10.0.0.2',
            'duration_sec': 30,
            'commands': [
                ('h5', 'timeout 30 nmap -sS -p 1-256 --max-rate 150 10.0.0.2 &'),
            ],
            'kill': 'nmap',
        },
    ]


def export_window(run_id, sc, session_id, start, end) -> int:
    import pandas as pd
    if not os.path.exists(FLOW_STATS):
        return 0
    df = pd.read_csv(FLOW_STATS)
    if df.empty:
        return 0
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    part = df[(df['timestamp'] >= pd.to_datetime(start)) & (df['timestamp'] <= pd.to_datetime(end))].copy()
    part['label'] = sc['label']
    part['is_synthetic'] = 0
    part['source'] = SOURCE_INDEPENDENT
    part['run_id'] = run_id
    part['scenario_id'] = sc['scenario_id']
    part['capture_session_id'] = session_id
    part['topology_id'] = TOPOLOGY_DEFAULT
    part['traffic_tool'] = 'iperf/ping' if sc['label'] == 'normal' else 'nmap'
    part['attack_protocol'] = sc['attack_protocol']
    part['attack_rate'] = sc['attack_rate']
    part['attacker_count'] = sc['attacker_count']
    part['target_host'] = sc['target_host']
    part['collection_timestamp'] = start
    part.to_csv(os.path.join(RUNS_DIR, f'{run_id}.csv'), index=False)
    return len(part)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    os.makedirs(RUNS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(MANIFEST):
        with open(MANIFEST, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([
                'run_id', 'scenario_id', 'capture_session_id', 'topology_id',
                'traffic_tool', 'attack_protocol', 'attack_rate', 'attacker_count',
                'target_host', 'start_time', 'end_time', 'duration_sec',
                'commands', 'n_flows_exported', 'notes',
            ])

    scs = scenarios()
    for sc in scs:
        assert_lab_targets([sc['target_host']], context=sc['scenario_id'])
        for _, cmd in sc['commands']:
            assert_no_default_route_hint(cmd)

    if args.dry_run:
        for sc in scs:
            print(sc['scenario_id'], sc['commands'])
        print('[✓] dry-run OK', sorted(ALLOWED_LAB_IPV4))
        return

    if os.geteuid() != 0:
        print('[!] sudo required')
        sys.exit(1)

    from mininet.log import setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController
    from mininet.topo import Topo

    class LabTopo(Topo):
        def build(self):
            s1 = self.addSwitch('s1', protocols='OpenFlow13')
            s2 = self.addSwitch('s2', protocols='OpenFlow13')
            hs = [self.addHost(f'h{i}', ip=f'10.0.0.{i}/24', mac=f'00:00:00:00:00:0{i}') for i in range(1, 7)]
            self.addLink(hs[0], s1); self.addLink(hs[1], s1); self.addLink(hs[2], s1)
            self.addLink(hs[3], s2); self.addLink(hs[4], s2); self.addLink(hs[5], s2)
            self.addLink(s1, s2)

    setLogLevel('info')
    session = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    net = Mininet(topo=LabTopo(), controller=None, switch=OVSKernelSwitch)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    time.sleep(5)
    net.pingAll()
    time.sleep(2)
    hosts = {f'h{i}': net.get(f'h{i}') for i in range(1, 7)}

    for sc in scs:
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        start = _now()
        for hname, cmd in sc['commands']:
            hosts[hname].cmd(cmd)
        time.sleep(sc['duration_sec'] + 3)
        for h in hosts.values():
            for proc in sc['kill'].split(';'):
                h.cmd(f'killall {proc} 2>/dev/null')
        time.sleep(8)
        end = _now()
        n = export_window(run_id, sc, session, start, end)
        with open(os.path.join(LOG_DIR, f'{run_id}.json'), 'w', encoding='utf-8') as f:
            json.dump({'run_id': run_id, 'scenario': sc, 'start': start, 'end': end, 'n': n}, f, indent=2)
        with open(MANIFEST, 'a', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([
                run_id, sc['scenario_id'], session, TOPOLOGY_DEFAULT,
                'ping/iperf/nmap', sc['attack_protocol'], sc['attack_rate'], sc['attacker_count'],
                sc['target_host'], start, end, sc['duration_sec'],
                json.dumps(sc['commands']), n, f"label={sc['label']}",
            ])
        print(f'[✓] {sc["scenario_id"]} -> {n} flows')
        time.sleep(4)

    net.stop()
    print('[✓] support runs done')


if __name__ == '__main__':
    main()

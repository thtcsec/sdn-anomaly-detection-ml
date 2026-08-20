"""
Thu Normal lab độc lập — traffic THẬT qua Mininet/OpenFlow.

Nhiều cổng/dịch vụ để OVS tạo nhiều flow entry (không random CSV).
Chỉ host 10.0.0.1–10.0.0.6. Không ghi đè flow_stats.csv làm nhãn chính.

T1: python controller/run_controller.py
T2: sudo PYTHONPATH=/usr/lib/python3/dist-packages python src/collect_independent_normal_runs.py
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
LABEL_FILE = os.path.join(DATASET_DIR, 'current_label.txt')


def _now() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _scenarios() -> list[dict]:
    # Mỗi run ~50s, mesh + iperf + HTTP nhiều cổng.
    http_ports = ' '.join(str(p) for p in range(8000, 8040))
    return [
        {
            'scenario_id': 'normal_mesh_ping_iperf_http_a',
            'duration_sec': 50,
            'target_host': '10.0.0.1;10.0.0.2;10.0.0.3',
            'commands': [
                ('h1', f'for p in {http_ports}; do python3 -m http.server $p >/dev/null 2>&1 & done'),
                ('h2', 'iperf -s -p 5001 >/dev/null 2>&1 &'),
                ('h3', 'iperf -s -p 5002 >/dev/null 2>&1 &'),
                ('h4', 'timeout 45 ping -i 0.2 10.0.0.1 >/dev/null 2>&1 &'),
                ('h5', 'timeout 45 ping -i 0.3 10.0.0.2 >/dev/null 2>&1 &'),
                ('h6', 'timeout 45 ping -i 0.4 10.0.0.3 >/dev/null 2>&1 &'),
                ('h4', 'timeout 40 iperf -c 10.0.0.2 -p 5001 -t 35 >/dev/null 2>&1 &'),
                ('h5', 'timeout 40 iperf -c 10.0.0.3 -p 5002 -t 35 >/dev/null 2>&1 &'),
                ('h6', f'for p in {http_ports}; do timeout 1 wget -q -O /dev/null http://10.0.0.1:$p/ || true; done &'),
                ('h5', f'for p in {http_ports}; do timeout 1 wget -q -O /dev/null http://10.0.0.1:$p/ || true; done &'),
            ],
        },
        {
            'scenario_id': 'normal_mesh_ping_iperf_http_b',
            'duration_sec': 50,
            'target_host': '10.0.0.2;10.0.0.3;10.0.0.4',
            'commands': [
                ('h2', f'for p in {http_ports}; do python3 -m http.server $p >/dev/null 2>&1 & done'),
                ('h1', 'iperf -s -p 5003 >/dev/null 2>&1 &'),
                ('h3', 'timeout 45 ping -i 0.25 10.0.0.4 >/dev/null 2>&1 &'),
                ('h4', 'timeout 45 ping -i 0.35 10.0.0.2 >/dev/null 2>&1 &'),
                ('h6', 'timeout 40 iperf -c 10.0.0.1 -p 5003 -t 35 >/dev/null 2>&1 &'),
                ('h5', f'for p in {http_ports}; do timeout 1 wget -q -O /dev/null http://10.0.0.2:$p/ || true; done &'),
                ('h1', f'for p in {http_ports}; do timeout 1 wget -q -O /dev/null http://10.0.0.2:$p/ || true; done &'),
            ],
        },
        {
            'scenario_id': 'normal_mesh_udp_tcp_c',
            'duration_sec': 45,
            'target_host': '10.0.0.1;10.0.0.5',
            'commands': [
                ('h1', 'iperf -s -u -p 5004 >/dev/null 2>&1 &'),
                ('h5', 'python3 -m http.server 8080 >/dev/null 2>&1 &'),
                ('h5', 'python3 -m http.server 8443 >/dev/null 2>&1 &'),
                ('h2', 'timeout 40 ping -i 0.2 10.0.0.5 >/dev/null 2>&1 &'),
                ('h3', 'timeout 40 ping -i 0.3 10.0.0.1 >/dev/null 2>&1 &'),
                ('h4', 'timeout 35 iperf -u -c 10.0.0.1 -p 5004 -t 30 -b 2M >/dev/null 2>&1 &'),
                ('h6', 'timeout 35 wget -q -O /dev/null http://10.0.0.5:8080/ || true &'),
                ('h3', 'timeout 35 wget -q -O /dev/null http://10.0.0.5:8443/ || true &'),
                ('h4', 'for p in 8080 8443 80 443 22; do timeout 1 wget -q -O /dev/null http://10.0.0.5:$p/ || true; done &'),
            ],
        },
    ]


def _export(run_id: str, sc: dict, session_id: str, start: str, end: str) -> int:
    import pandas as pd

    if not os.path.exists(FLOW_STATS):
        return 0
    df = pd.read_csv(FLOW_STATS, low_memory=False)
    if df.empty:
        return 0
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    part = df[(df['timestamp'] >= pd.to_datetime(start)) & (df['timestamp'] <= pd.to_datetime(end))].copy()
    if part.empty:
        return 0
    lab = {f'10.0.0.{i}' for i in range(1, 7)}
    if 'ip_src' in part.columns and 'ip_dst' in part.columns:
        part = part[part['ip_src'].astype(str).isin(lab) & part['ip_dst'].astype(str).isin(lab)].copy()
    part['label'] = 'normal'
    part['is_synthetic'] = 0
    part['source'] = SOURCE_INDEPENDENT
    part['run_id'] = run_id
    part['scenario_id'] = sc['scenario_id']
    part['capture_session_id'] = session_id
    part['topology_id'] = TOPOLOGY_DEFAULT
    part['traffic_tool'] = 'ping/iperf/http'
    part['attack_protocol'] = 'none'
    part['attack_rate'] = 'n/a'
    part['attacker_count'] = 0
    part['target_host'] = sc['target_host']
    part['collection_timestamp'] = start
    out = os.path.join(RUNS_DIR, f'{run_id}.csv')
    part.to_csv(out, index=False)
    return len(part)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--repeat', type=int, default=2, help='Repeat the 3-scenario block')
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

    scs = _scenarios() * max(1, args.repeat)
    for sc in scs:
        assert_lab_targets([p for p in sc['target_host'].split(';') if p], context=sc['scenario_id'])
        for _, cmd in sc['commands']:
            assert_no_default_route_hint(cmd)

    if os.geteuid() != 0:
        print('[!] sudo required')
        sys.exit(1)

    with open(LABEL_FILE, 'w', encoding='utf-8') as f:
        f.write('normal')

    from mininet.log import setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController
    from mininet.topo import Topo

    class LabTopo(Topo):
        def build(self):
            s1 = self.addSwitch('s1', protocols='OpenFlow13')
            s2 = self.addSwitch('s2', protocols='OpenFlow13')
            hs = [
                self.addHost(f'h{i}', ip=f'10.0.0.{i}/24', mac=f'00:00:00:00:00:0{i}')
                for i in range(1, 7)
            ]
            self.addLink(hs[0], s1)
            self.addLink(hs[1], s1)
            self.addLink(hs[2], s1)
            self.addLink(hs[3], s2)
            self.addLink(hs[4], s2)
            self.addLink(hs[5], s2)
            self.addLink(s1, s2)

    setLogLevel('info')
    session = f"session_normal_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    net = Mininet(topo=LabTopo(), controller=None, switch=OVSKernelSwitch)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    time.sleep(5)
    try:
        net.pingAll()
    except Exception as exc:
        print(f'[!] pingAll: {exc}')
    time.sleep(3)
    hosts = {f'h{i}': net.get(f'h{i}') for i in range(1, 7)}

    print('=' * 60)
    print(f'  Independent REAL Normal collection | {len(scs)} runs')
    print(f'  Allowed: {sorted(ALLOWED_LAB_IPV4)}')
    print('=' * 60)

    for sc in scs:
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        start = _now()
        print(f"\n[*] {sc['scenario_id']} | {run_id}")
        for hname, cmd in sc['commands']:
            print(f'    {hname}$ {cmd[:90]}')
            hosts[hname].cmd(cmd)
        time.sleep(int(sc['duration_sec']) + 3)
        for h in hosts.values():
            h.cmd('killall ping iperf wget python3 2>/dev/null')
        time.sleep(8)
        end = _now()
        n = _export(run_id, sc, session, start, end)
        with open(os.path.join(LOG_DIR, f'{run_id}.json'), 'w', encoding='utf-8') as f:
            json.dump({'run_id': run_id, 'scenario_id': sc['scenario_id'], 'start': start, 'end': end, 'n': n}, f, indent=2)
        with open(MANIFEST, 'a', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([
                run_id, sc['scenario_id'], session, TOPOLOGY_DEFAULT,
                'ping/iperf/http', 'none', 'n/a', 0, sc['target_host'],
                start, end, sc['duration_sec'], json.dumps(sc['commands']), n,
                'independent_lab_run; label=normal; real OpenFlow',
            ])
        print(f'[✓] exported {n} flows')
        time.sleep(4)

    net.stop()
    print('[✓] Normal collection finished')


if __name__ == '__main__':
    main()

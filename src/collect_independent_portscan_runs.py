"""
Thu Portscan lab độc lập — nmap THẬT qua OpenFlow, đa dạng run.

Mỗi scenario khác attacker / target / dải cổng / tốc độ.
Lọc attacker→target trong cửa sổ thời gian (kể cả packet_count=0).
Không ghi đè flow_stats.csv làm nhãn chính.

T1: python controller/run_controller.py
T2: sudo PYTHONPATH=/usr/lib/python3/dist-packages python src/collect_independent_portscan_runs.py
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
HOST_IP = {f'h{i}': f'10.0.0.{i}' for i in range(1, 7)}


def _now() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _scenarios() -> list[dict]:
    return [
        {
            'scenario_id': 'portscan_syn_h4_h1_p1_128_r80',
            'attack_protocol': 'tcp_syn_scan',
            'attack_rate': 'max-rate=80',
            'attacker_count': 1,
            'target_host': '10.0.0.1',
            'duration_sec': 28,
            'commands': [('h4', 'timeout 28 nmap -sS -p 1-128 --max-rate 80 10.0.0.1 &')],
        },
        {
            'scenario_id': 'portscan_syn_h5_h2_top20_r40',
            'attack_protocol': 'tcp_syn_scan',
            'attack_rate': 'max-rate=40',
            'attacker_count': 1,
            'target_host': '10.0.0.2',
            'duration_sec': 25,
            'commands': [('h5', 'timeout 25 nmap -sS -p 22,53,80,443,445,3306,3389,5001,8000,8080,8443 --max-rate 40 10.0.0.2 &')],
        },
        {
            'scenario_id': 'portscan_connect_h6_h3_p20_120_r60',
            'attack_protocol': 'tcp_connect_scan',
            'attack_rate': 'max-rate=60',
            'attacker_count': 1,
            'target_host': '10.0.0.3',
            'duration_sec': 30,
            'commands': [('h6', 'timeout 30 nmap -sT -p 20-120 --max-rate 60 10.0.0.3 &')],
        },
        {
            'scenario_id': 'portscan_syn_h4_h2_p8000_8120_r100',
            'attack_protocol': 'tcp_syn_scan',
            'attack_rate': 'max-rate=100',
            'attacker_count': 1,
            'target_host': '10.0.0.2',
            'duration_sec': 28,
            'commands': [('h4', 'timeout 28 nmap -sS -p 8000-8120 --max-rate 100 10.0.0.2 &')],
        },
        {
            'scenario_id': 'portscan_syn_h5h6_h1h3_p1_64_r50',
            'attack_protocol': 'tcp_syn_scan',
            'attack_rate': 'max-rate=50',
            'attacker_count': 2,
            'target_host': '10.0.0.1;10.0.0.3',
            'duration_sec': 32,
            'commands': [
                ('h5', 'timeout 32 nmap -sS -p 1-64 --max-rate 50 10.0.0.1 &'),
                ('h6', 'timeout 32 nmap -sS -p 1-64 --max-rate 50 10.0.0.3 &'),
            ],
        },
        {
            'scenario_id': 'portscan_udp_h4_h1_dns_ntp_r20',
            'attack_protocol': 'udp_scan',
            'attack_rate': 'max-rate=20',
            'attacker_count': 1,
            'target_host': '10.0.0.1',
            'duration_sec': 30,
            'commands': [('h4', 'timeout 30 nmap -sU -p 53,123,161,5004 --max-rate 20 10.0.0.1 &')],
        },
        {
            'scenario_id': 'portscan_syn_h6_h1_p200_320_r70',
            'attack_protocol': 'tcp_syn_scan',
            'attack_rate': 'max-rate=70',
            'attacker_count': 1,
            'target_host': '10.0.0.1',
            'duration_sec': 28,
            'commands': [('h6', 'timeout 28 nmap -sS -p 200-320 --max-rate 70 10.0.0.1 &')],
        },
        {
            'scenario_id': 'portscan_syn_h5_h3_p1_96_r90',
            'attack_protocol': 'tcp_syn_scan',
            'attack_rate': 'max-rate=90',
            'attacker_count': 1,
            'target_host': '10.0.0.3',
            'duration_sec': 26,
            'commands': [('h5', 'timeout 26 nmap -sS -p 1-96 --max-rate 90 10.0.0.3 &')],
        },
    ]


def _attackers(sc: dict) -> set[str]:
    return {HOST_IP[h] for h, _ in sc['commands'] if h in HOST_IP}


def _targets(sc: dict) -> set[str]:
    return {p.strip() for p in str(sc['target_host']).split(';') if p.strip()}


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
    atk, tgt = _attackers(sc), _targets(sc)
    if 'ip_src' in part.columns and 'ip_dst' in part.columns:
        part = part[part['ip_src'].astype(str).isin(atk) & part['ip_dst'].astype(str).isin(tgt)].copy()
    if 'tp_src' in part.columns and 'tp_dst' in part.columns:
        l4 = (
            (pd.to_numeric(part['tp_src'], errors='coerce').fillna(0) != 0)
            | (pd.to_numeric(part['tp_dst'], errors='coerce').fillna(0) != 0)
        )
        part = part[l4].copy()
    part['label'] = 'portscan'
    part['is_synthetic'] = 0
    part['source'] = SOURCE_INDEPENDENT
    part['run_id'] = run_id
    part['scenario_id'] = sc['scenario_id']
    part['capture_session_id'] = session_id
    part['topology_id'] = TOPOLOGY_DEFAULT
    part['traffic_tool'] = 'nmap'
    part['attack_protocol'] = sc['attack_protocol']
    part['attack_rate'] = sc['attack_rate']
    part['attacker_count'] = sc['attacker_count']
    part['target_host'] = sc['target_host']
    part['collection_timestamp'] = start
    part.to_csv(os.path.join(RUNS_DIR, f'{run_id}.csv'), index=False)
    return len(part)


def main() -> None:
    argparse.ArgumentParser().parse_args()
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

    scs = _scenarios()
    for sc in scs:
        assert_lab_targets(sorted(_targets(sc)), context=sc['scenario_id'])
        for _, cmd in sc['commands']:
            assert_no_default_route_hint(cmd)

    if os.geteuid() != 0:
        print('[!] sudo required')
        sys.exit(1)

    with open(LABEL_FILE, 'w', encoding='utf-8') as f:
        f.write('portscan')

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
    session = f"session_ps_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
    print(f'  Independent REAL Portscan | {len(scs)} runs')
    print(f'  Allowed: {sorted(ALLOWED_LAB_IPV4)}')
    print('=' * 60)

    for sc in scs:
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        start = _now()
        print(f"\n[*] {sc['scenario_id']} | {run_id}")
        for hname, cmd in sc['commands']:
            print(f'    {hname}$ {cmd}')
            hosts[hname].cmd(cmd)
        time.sleep(int(sc['duration_sec']) + 3)
        for h in hosts.values():
            h.cmd('killall nmap 2>/dev/null')
        time.sleep(8)
        end = _now()
        n = _export(run_id, sc, session, start, end)
        with open(os.path.join(LOG_DIR, f'{run_id}.json'), 'w', encoding='utf-8') as f:
            json.dump({'run_id': run_id, 'scenario_id': sc['scenario_id'], 'start': start, 'end': end, 'n': n}, f, indent=2)
        with open(MANIFEST, 'a', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([
                run_id, sc['scenario_id'], session, TOPOLOGY_DEFAULT,
                'nmap', sc['attack_protocol'], sc['attack_rate'], sc['attacker_count'],
                sc['target_host'], start, end, sc['duration_sec'],
                json.dumps(sc['commands']), n,
                'independent_lab_run; label=portscan; real OpenFlow',
            ])
        print(f'[✓] exported {n} flows')
        time.sleep(4)

    net.stop()
    print('[✓] Portscan collection finished')


if __name__ == '__main__':
    main()

"""
Thu thập DDoS lab độc lập theo scenario/run — CHỈ trong Mininet 10.0.0.0/24.

An toàn:
  - Mọi target phải thuộc ALLOWED_LAB_IPV4
  - timeout hữu hạn + killall cleanup
  - rate-limited mặc định (không --flood trừ --allow-flood)
  - Không ghi đè dataset/flow_stats.csv
  - Mỗi run lưu riêng + manifest

Yêu cầu:
  T1: controller đang chạy (python controller/run_controller.py hoặc run_realtime.py)
  T2: sudo python3 src/collect_independent_ddos_runs.py [--dry-run] [--allow-flood]

Output:
  dataset/independent_runs/manifest.csv
  dataset/independent_runs/{run_id}.csv   (flows tagged, sau khi snapshot từ flow_stats)
  dataset/independent_runs/run_logs/{run_id}.json
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
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lab_safety import assert_lab_targets, assert_no_default_route_hint  # noqa: E402
from provenance_schema import (  # noqa: E402
    ALLOWED_LAB_IPV4,
    SOURCE_INDEPENDENT,
    TOPOLOGY_DEFAULT,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
FLOW_STATS = os.path.join(DATASET_DIR, 'flow_stats.csv')
RUNS_DIR = os.path.join(DATASET_DIR, 'independent_runs')
MANIFEST = os.path.join(RUNS_DIR, 'manifest.csv')
LOG_DIR = os.path.join(RUNS_DIR, 'run_logs')

# Default rate-limited interval for hping3 (-i). Smaller = faster.
# u1000 ≈ 1000 microseconds between packets (~1000 pps theoretical upper bound).
DEFAULT_INTERVAL = 'u2000'


def _now() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _scenarios(allow_flood: bool) -> list[dict[str, Any]]:
    """Independent scenarios — different protocol / attackers / targets / rate."""
    flood = '--flood' if allow_flood else f'-i {DEFAULT_INTERVAL}'
    slow = '-i u5000'
    return [
        {
            'scenario_id': 'ddos_syn_single_h4_h1',
            'attack_protocol': 'tcp_syn',
            'attack_rate': 'flood' if allow_flood else DEFAULT_INTERVAL,
            'attacker_count': 1,
            'target_host': '10.0.0.1',
            'duration_sec': 25,
            'commands': [
                ('h4', f'timeout 25 hping3 -S {flood} -p 80 10.0.0.1 &'),
            ],
            'kill': 'hping3',
        },
        {
            'scenario_id': 'ddos_syn_multi_h4h5_h1h2',
            'attack_protocol': 'tcp_syn',
            'attack_rate': 'flood' if allow_flood else DEFAULT_INTERVAL,
            'attacker_count': 2,
            'target_host': '10.0.0.1;10.0.0.2',
            'duration_sec': 25,
            'commands': [
                ('h4', f'timeout 25 hping3 -S {flood} -p 80 10.0.0.1 &'),
                ('h5', f'timeout 25 hping3 -S {flood} -p 443 10.0.0.2 &'),
            ],
            'kill': 'hping3',
        },
        {
            'scenario_id': 'ddos_udp_h5_h1',
            'attack_protocol': 'udp',
            'attack_rate': 'flood' if allow_flood else DEFAULT_INTERVAL,
            'attacker_count': 1,
            'target_host': '10.0.0.1',
            'duration_sec': 25,
            'commands': [
                ('h5', f'timeout 25 hping3 --udp {flood} -p 53 10.0.0.1 &'),
            ],
            'kill': 'hping3',
        },
        {
            'scenario_id': 'ddos_icmp_multi_h4h6_h1h3',
            'attack_protocol': 'icmp',
            'attack_rate': 'flood' if allow_flood else DEFAULT_INTERVAL,
            'attacker_count': 2,
            'target_host': '10.0.0.1;10.0.0.3',
            'duration_sec': 20,
            'commands': [
                ('h4', f'timeout 20 hping3 --icmp {flood} 10.0.0.1 &'),
                ('h6', f'timeout 20 hping3 --icmp {flood} 10.0.0.3 &'),
            ],
            'kill': 'hping3',
        },
        {
            'scenario_id': 'ddos_syn_slow_h4_h2',
            'attack_protocol': 'tcp_syn',
            'attack_rate': 'u5000',
            'attacker_count': 1,
            'target_host': '10.0.0.2',
            'duration_sec': 30,
            'commands': [
                ('h4', f'timeout 30 hping3 -S {slow} -p 8080 10.0.0.2 &'),
            ],
            'kill': 'hping3',
        },
        {
            'scenario_id': 'ddos_udp_multi_h5h6_h2h3',
            'attack_protocol': 'udp',
            'attack_rate': 'flood' if allow_flood else DEFAULT_INTERVAL,
            'attacker_count': 2,
            'target_host': '10.0.0.2;10.0.0.3',
            'duration_sec': 25,
            'commands': [
                ('h5', f'timeout 25 hping3 --udp {flood} -p 53 10.0.0.2 &'),
                ('h6', f'timeout 25 hping3 --udp {flood} -p 123 10.0.0.3 &'),
            ],
            'kill': 'hping3',
        },
        {
            'scenario_id': 'ddos_syn_multiport_h4_h1',
            'attack_protocol': 'tcp_syn',
            'attack_rate': 'flood' if allow_flood else DEFAULT_INTERVAL,
            'attacker_count': 1,
            'target_host': '10.0.0.1',
            'duration_sec': 30,
            'commands': [
                ('h4', f'timeout 30 hping3 -S {flood} -p ++80 10.0.0.1 &'),
            ],
            'kill': 'hping3',
        },
        {
            'scenario_id': 'ddos_udp_multiport_h5_h2',
            'attack_protocol': 'udp',
            'attack_rate': 'flood' if allow_flood else DEFAULT_INTERVAL,
            'attacker_count': 1,
            'target_host': '10.0.0.2',
            'duration_sec': 30,
            'commands': [
                ('h5', f'timeout 30 hping3 --udp {flood} -p ++53 10.0.0.2 &'),
            ],
            'kill': 'hping3',
        },
        {
            'scenario_id': 'ddos_syn_multiport_multi_h4h6_h1h3',
            'attack_protocol': 'tcp_syn',
            'attack_rate': 'flood' if allow_flood else DEFAULT_INTERVAL,
            'attacker_count': 2,
            'target_host': '10.0.0.1;10.0.0.3',
            'duration_sec': 30,
            'commands': [
                ('h4', f'timeout 30 hping3 -S {flood} -p ++80 10.0.0.1 &'),
                ('h6', f'timeout 30 hping3 -S {flood} -p ++443 10.0.0.3 &'),
            ],
            'kill': 'hping3',
        },
    ]


ATTACKERS = {'10.0.0.4', '10.0.0.5', '10.0.0.6'}


def filter_ddos_related(part, targets: set[str], require_packets: bool = False):
    """Keep L4 flows between attackers and scenario targets, either direction.

    Multiport hping3 creates one 5-tuple per packet, so OpenFlow often records
    packet_count=0 (the only packet was handled as packet-in). Do not drop
    those unless leftover-scan cleaning is explicitly requested.
    """
    import pandas as pd

    if part is None or part.empty:
        return part
    if 'ip_src' in part.columns and 'ip_dst' in part.columns:
        src = part['ip_src'].astype(str)
        dst = part['ip_dst'].astype(str)
        related = (
            (src.isin(ATTACKERS) & dst.isin(targets))
            | (src.isin(targets) & dst.isin(ATTACKERS))
        )
        part = part[related].copy()
    if 'tp_src' in part.columns and 'tp_dst' in part.columns:
        l4 = (
            (pd.to_numeric(part['tp_src'], errors='coerce').fillna(0) != 0)
            | (pd.to_numeric(part['tp_dst'], errors='coerce').fillna(0) != 0)
        )
        part = part[l4].copy()
    if require_packets and 'packet_count' in part.columns:
        part = part[pd.to_numeric(part['packet_count'], errors='coerce').fillna(0) > 0].copy()
    return part


def _extract_targets(scenario: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    for part in str(scenario['target_host']).split(';'):
        part = part.strip()
        if part:
            targets.append(part)
    for _, cmd in scenario['commands']:
        # last token often IP
        toks = cmd.replace('&', '').split()
        for t in toks:
            if t.count('.') == 3 and t[0].isdigit():
                targets.append(t)
    return sorted(set(targets))


def _init_dirs() -> None:
    os.makedirs(RUNS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(MANIFEST):
        with open(MANIFEST, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow([
                'run_id', 'scenario_id', 'capture_session_id', 'topology_id',
                'traffic_tool', 'attack_protocol', 'attack_rate', 'attacker_count',
                'target_host', 'start_time', 'end_time', 'duration_sec',
                'commands', 'n_flows_exported', 'notes',
            ])


def _count_flow_rows() -> int:
    if not os.path.exists(FLOW_STATS):
        return 0
    with open(FLOW_STATS, 'r', encoding='utf-8', errors='ignore') as f:
        return max(0, sum(1 for _ in f) - 1)


def _export_window_to_run_csv(
    run_id: str,
    scenario: dict[str, Any],
    capture_session_id: str,
    start: str,
    end: str,
) -> int:
    """Tag flows whose timestamp falls in [start, end] into an independent run file."""
    import pandas as pd

    if not os.path.exists(FLOW_STATS):
        print('[!] flow_stats.csv missing — controller may not be writing stats')
        return 0

    df = pd.read_csv(FLOW_STATS)
    if df.empty:
        return 0

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    t0 = pd.to_datetime(start)
    t1 = pd.to_datetime(end)
    mask = (df['timestamp'] >= t0) & (df['timestamp'] <= t1)
    part = df.loc[mask].copy()
    if part.empty:
        # fallback: take newest rows since start of scenario if clock skew
        part = df.tail(0).copy()

    # Giữ flow L4 liên quan attacker <-> target.
    # Learning-switch có thể ghi chiều ngược (RST victim -> attacker);
    # rule ARP không có eth_type từng nuốt SYN nên chiều xuôi có thể trống.
    part = filter_ddos_related(part, set(_extract_targets(scenario)))

    # Label as ddos for this collection script (DDoS-focused)
    part['label'] = 'ddos'
    part['is_synthetic'] = 0
    part['source'] = SOURCE_INDEPENDENT
    part['run_id'] = run_id
    part['scenario_id'] = scenario['scenario_id']
    part['capture_session_id'] = capture_session_id
    part['topology_id'] = TOPOLOGY_DEFAULT
    part['traffic_tool'] = 'hping3'
    part['attack_protocol'] = scenario['attack_protocol']
    part['attack_rate'] = scenario['attack_rate']
    part['attacker_count'] = int(scenario['attacker_count'])
    part['target_host'] = scenario['target_host']
    part['collection_timestamp'] = start

    out = os.path.join(RUNS_DIR, f'{run_id}.csv')
    part.to_csv(out, index=False)
    return len(part)


def run_collection(dry_run: bool, allow_flood: bool, only: str | None) -> None:
    _init_dirs()
    scenarios = _scenarios(allow_flood=allow_flood)
    if only:
        wanted = [x.strip() for x in only.split(',') if x.strip()]
        scenarios = [s for s in scenarios if s['scenario_id'] in wanted]
        missing = [x for x in wanted if x not in {s['scenario_id'] for s in scenarios}]
        if missing:
            raise SystemExit(f'Unknown scenario_id={missing}')

    # Validate all targets up front
    for sc in scenarios:
        assert_lab_targets(_extract_targets(sc), context=sc['scenario_id'])
        for _, cmd in sc['commands']:
            assert_no_default_route_hint(cmd)

    print('=' * 60)
    print('  Independent Mininet DDoS collection')
    print(f'  Allowed lab IPs: {sorted(ALLOWED_LAB_IPV4)}')
    print(f'  Scenarios: {len(scenarios)} | flood={allow_flood} | dry_run={dry_run}')
    print('  Does NOT overwrite dataset/flow_stats.csv')
    print('=' * 60)

    if dry_run:
        for sc in scenarios:
            print(f"\n[DRY] {sc['scenario_id']}")
            for host, cmd in sc['commands']:
                print(f'  {host}: {cmd}')
        print('\n[✓] Dry-run OK — no traffic sent')
        return

    if os.geteuid() != 0:
        print('[!] Cần sudo: sudo python3 src/collect_independent_ddos_runs.py')
        sys.exit(1)

    from mininet.log import setLogLevel, info
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController
    from mininet.topo import Topo

    class LabTopo(Topo):
        def build(self):
            s1 = self.addSwitch('s1', protocols='OpenFlow13')
            s2 = self.addSwitch('s2', protocols='OpenFlow13')
            hosts = []
            for i in range(1, 7):
                hosts.append(
                    self.addHost(
                        f'h{i}',
                        ip=f'10.0.0.{i}/24',
                        mac=f'00:00:00:00:00:0{i}',
                    )
                )
            self.addLink(hosts[0], s1)
            self.addLink(hosts[1], s1)
            self.addLink(hosts[2], s1)
            self.addLink(hosts[3], s2)
            self.addLink(hosts[4], s2)
            self.addLink(hosts[5], s2)
            self.addLink(s1, s2)

    setLogLevel('info')
    capture_session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    net = Mininet(topo=LabTopo(), controller=None, switch=OVSKernelSwitch)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    info('*** Waiting for controller...\n')
    time.sleep(5)
    try:
        net.pingAll()
    except Exception as exc:
        print(f'[!] pingAll warning: {exc}')
    time.sleep(3)

    hosts = {f'h{i}': net.get(f'h{i}') for i in range(1, 7)}

    for sc in scenarios:
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        assert_lab_targets(_extract_targets(sc), context=sc['scenario_id'])

        print(f"\n[*] START {sc['scenario_id']} | {run_id}")
        start = _now()
        before_rows = _count_flow_rows()

        for host_name, cmd in sc['commands']:
            assert_no_default_route_hint(cmd)
            print(f'    {host_name}$ {cmd}')
            hosts[host_name].cmd(cmd)

        time.sleep(int(sc['duration_sec']) + 3)

        # Cleanup
        for h in hosts.values():
            h.cmd(f"killall {sc['kill']} 2>/dev/null")
        time.sleep(2)

        # Allow controller to flush a couple monitor intervals BEFORE closing
        # the export window — otherwise new rows fall after `end`.
        time.sleep(8)
        end = _now()
        n_flows = _export_window_to_run_csv(
            run_id, sc, capture_session_id, start, end
        )
        after_rows = _count_flow_rows()

        meta = {
            'run_id': run_id,
            'scenario_id': sc['scenario_id'],
            'capture_session_id': capture_session_id,
            'topology_id': TOPOLOGY_DEFAULT,
            'start_time': start,
            'end_time': end,
            'commands': sc['commands'],
            'n_flows_exported': n_flows,
            'flow_stats_rows_before': before_rows,
            'flow_stats_rows_after': after_rows,
            'allow_flood': allow_flood,
        }
        with open(os.path.join(LOG_DIR, f'{run_id}.json'), 'w', encoding='utf-8') as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

        with open(MANIFEST, 'a', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([
                run_id, sc['scenario_id'], capture_session_id, TOPOLOGY_DEFAULT,
                'hping3', sc['attack_protocol'], sc['attack_rate'], sc['attacker_count'],
                sc['target_host'], start, end, sc['duration_sec'],
                json.dumps(sc['commands']), n_flows,
                'independent_lab_run; not bootstrap',
            ])

        print(f'[✓] Exported {n_flows} flows → independent_runs/{run_id}.csv')
        time.sleep(5)

    net.stop()
    print('\n[✓] Collection finished')
    print(f'[*] Manifest: {MANIFEST}')
    print('[*] Next: python src/merge_independent_runs.py')
    print('[*] Then:  python src/eval_grouped_real_only.py')


def main() -> None:
    ap = argparse.ArgumentParser(description='Safe independent Mininet DDoS collection')
    ap.add_argument('--dry-run', action='store_true', help='Validate scenarios only')
    ap.add_argument(
        '--allow-flood',
        action='store_true',
        help='Use hping3 --flood (still lab-IP only, finite timeout). Default is rate-limited.',
    )
    ap.add_argument('--only', type=str, default=None, help='Run a single scenario_id')
    args = ap.parse_args()
    run_collection(dry_run=args.dry_run, allow_flood=args.allow_flood, only=args.only)


if __name__ == '__main__':
    main()

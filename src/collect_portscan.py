"""
Thu thập data portscan riêng (bổ sung cho dataset).
Chạy: sudo python3 src/collect_portscan.py

Đảm bảo controller đang chạy ở terminal khác.
"""

import os
import sys
import time
import csv
from datetime import datetime

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
LABEL_LOG = os.path.join(DATASET_DIR, 'label_log.csv')


class SimpleTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        # Victims
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        # Attackers
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        h5 = self.addHost('h5', ip='10.0.0.5/24')
        h6 = self.addHost('h6', ip='10.0.0.6/24')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)
        self.addLink(s1, s2)


def main():
    setLogLevel('info')

    if os.geteuid() != 0:
        print("[!] Cần sudo: sudo python3 src/collect_portscan.py")
        sys.exit(1)

    print("=" * 60)
    print("  Collecting PORT SCAN data")
    print("=" * 60)

    net = Mininet(topo=SimpleTopo(), controller=None, switch=OVSKernelSwitch)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()

    info('*** Waiting for controller...\n')
    time.sleep(5)
    net.pingAll()
    time.sleep(5)

    h1, h2, h3, h4, h5, h6 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6')

    # Round 1: 45s portscan
    info('*** Port Scan Round 1 (45s)\n')
    start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    h4.cmd('timeout 45 nmap -sS -p 1-1024 --max-rate 200 10.0.0.1 &')
    h5.cmd('timeout 45 nmap -sS -p 1-500 --max-rate 150 10.0.0.2 &')
    h6.cmd('timeout 45 nmap -sS -p 22,80,443,8080,3306,5432,6379,8443 10.0.0.1 10.0.0.2 10.0.0.3 &')
    time.sleep(50)
    end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LABEL_LOG, 'a', newline='') as f:
        csv.writer(f).writerow([start, end, 'portscan'])
    info(f'*** Round 1 done: {start} -> {end}\n')

    # Cooldown
    for h in [h4, h5, h6]:
        h.cmd('killall nmap 2>/dev/null')
    time.sleep(10)

    # Round 2: 45s portscan (different patterns)
    info('*** Port Scan Round 2 (45s)\n')
    start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    h4.cmd('timeout 45 nmap -sS -p 1-2000 --max-rate 300 10.0.0.2 &')
    h5.cmd('timeout 45 nmap -sS -p 1-1024 --max-rate 250 10.0.0.3 &')
    h6.cmd('timeout 45 nmap -sS --top-ports 100 10.0.0.0/24 &')
    time.sleep(50)
    end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LABEL_LOG, 'a', newline='') as f:
        csv.writer(f).writerow([start, end, 'portscan'])
    info(f'*** Round 2 done: {start} -> {end}\n')

    # Cooldown
    for h in [h4, h5, h6]:
        h.cmd('killall nmap 2>/dev/null')
    time.sleep(10)

    # Round 3: 45s portscan
    info('*** Port Scan Round 3 (45s)\n')
    start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    h4.cmd('timeout 45 nmap -sS -p 1-500 --max-rate 400 10.0.0.1 &')
    h5.cmd('timeout 45 nmap -sU -p 53,67,68,123,161,500 10.0.0.1 10.0.0.2 &')
    h6.cmd('timeout 45 nmap -sS -p 1-1024 --max-rate 200 10.0.0.3 &')
    time.sleep(50)
    end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LABEL_LOG, 'a', newline='') as f:
        csv.writer(f).writerow([start, end, 'portscan'])
    info(f'*** Round 3 done: {start} -> {end}\n')

    for h in [h4, h5, h6]:
        h.cmd('killall nmap 2>/dev/null')

    net.stop()

    print("\n" + "=" * 60)
    print("[✓] Port scan collection done!")
    print("[*] Chạy: source .venv/bin/activate && python src/label_data.py")
    print("=" * 60)


if __name__ == '__main__':
    main()

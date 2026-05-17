"""
Script tự động thu thập data với đầy đủ 3 loại traffic.
Script này THAY THẾ topology/custom_topo.py — nó tự tạo topology,
chạy traffic, và ghi label log.

Cách dùng:
  1. Terminal 1: source .venv/bin/activate && python controller/run_controller.py
  2. Terminal 2: sudo python3 src/collect_data.py

Script sẽ tự:
  - Tạo Mininet topology
  - Chạy normal traffic → ghi label
  - Chạy DDoS attack → ghi label
  - Chạy port scan → ghi label
  - Lặp lại 3 rounds
"""

import os
import sys
import time
import csv
from datetime import datetime

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.log import setLogLevel, info


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
LABEL_LOG = os.path.join(DATASET_DIR, 'label_log.csv')

# Số rounds thu thập
NUM_ROUNDS = 3

# Thời gian mỗi loại traffic (giây)
NORMAL_DURATION = 60
DDOS_DURATION = 45
PORTSCAN_DURATION = 30
COOLDOWN = 10


class SDNAnomalyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')

        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        h6 = self.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)
        self.addLink(s1, s2)


def init_label_log():
    """Khởi tạo file label log."""
    os.makedirs(DATASET_DIR, exist_ok=True)
    with open(LABEL_LOG, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['start_time', 'end_time', 'label'])


def log_label(label, start_time, end_time):
    """Ghi 1 entry vào label log."""
    with open(LABEL_LOG, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([start_time, end_time, label])


def generate_normal(net, duration=NORMAL_DURATION):
    """Tạo traffic bình thường: ping + iperf."""
    h1, h2, h3, h4, h5, h6 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6')

    info(f'*** Generating NORMAL traffic ({duration}s)\n')
    start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Ping liên tục giữa các host
    h1.cmd(f'ping -i 0.5 -c {duration * 2} 10.0.0.4 &')
    h2.cmd(f'ping -i 0.8 -c {int(duration / 0.8)} 10.0.0.5 &')
    h3.cmd(f'ping -i 1.0 -c {duration} 10.0.0.6 &')

    # iperf TCP normal
    h2.cmd('iperf -s -p 5001 &')
    time.sleep(1)
    h1.cmd(f'iperf -c 10.0.0.2 -p 5001 -t {duration - 5} &')

    # iperf UDP normal (low bandwidth)
    h5.cmd('iperf -s -u -p 5002 &')
    time.sleep(1)
    h4.cmd(f'iperf -c 10.0.0.5 -u -p 5002 -b 1M -t {duration - 5} &')

    time.sleep(duration)

    # Kill background processes
    for h in [h1, h2, h3, h4, h5, h6]:
        h.cmd('kill %ping 2>/dev/null; kill %iperf 2>/dev/null')
    time.sleep(2)

    end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_label('normal', start, end)
    info(f'*** Normal done: {start} -> {end}\n')


def generate_ddos(net, duration=DDOS_DURATION):
    """Tạo DDoS: SYN flood, UDP flood, ICMP flood."""
    h1, h2, h3, h4, h5, h6 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6')

    info(f'*** Generating DDoS ATTACK ({duration}s)\n')
    start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # SYN Flood: h4 → h1
    h4.cmd(f'timeout {duration} hping3 -S --flood -p 80 10.0.0.1 &')
    # UDP Flood: h5 → h2
    h5.cmd(f'timeout {duration} hping3 --udp --flood -p 53 10.0.0.2 &')
    # ICMP Flood: h6 → h3
    h6.cmd(f'timeout {duration} hping3 --icmp --flood 10.0.0.3 &')

    time.sleep(duration + 2)

    # Cleanup
    for h in [h4, h5, h6]:
        h.cmd('killall hping3 2>/dev/null')
    time.sleep(2)

    end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_label('ddos', start, end)
    info(f'*** DDoS done: {start} -> {end}\n')


def generate_portscan(net, duration=PORTSCAN_DURATION):
    """Tạo Port Scan: nmap từ attacker hosts."""
    h1, h2, h3, h4, h5, h6 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6')

    info(f'*** Generating PORT SCAN ({duration}s)\n')
    start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # SYN scan h4 → h1
    h4.cmd(f'timeout {duration} nmap -sS -p 1-1024 --max-rate 200 10.0.0.1 &')
    # SYN scan h5 → h2
    h5.cmd(f'timeout {duration} nmap -sS -p 1-500 --max-rate 150 10.0.0.2 &')
    # Scan subnet h6
    h6.cmd(f'timeout {duration} nmap -sS -p 22,80,443,8080,3306 10.0.0.0/24 &')

    time.sleep(duration + 2)

    # Cleanup
    for h in [h4, h5, h6]:
        h.cmd('killall nmap 2>/dev/null')
    time.sleep(2)

    end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_label('portscan', start, end)
    info(f'*** Port scan done: {start} -> {end}\n')


def main():
    setLogLevel('info')

    print("=" * 60)
    print("  SDN Traffic Data Collection")
    print("  Đảm bảo controller đang chạy ở terminal khác!")
    print("=" * 60)

    if os.geteuid() != 0:
        print("[!] Cần chạy với sudo: sudo python3 src/collect_data.py")
        sys.exit(1)

    # Init
    init_label_log()

    # Tạo topology
    info('*** Creating network\n')
    topo = SDNAnomalyTopo()
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=False
    )
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()

    # Đợi controller kết nối
    info('*** Waiting for controller connection...\n')
    time.sleep(5)

    # Test connectivity
    info('*** Testing connectivity\n')
    net.pingAll()
    time.sleep(5)

    # Thu thập data
    for i in range(NUM_ROUNDS):
        print(f"\n{'='*60}")
        print(f"  ROUND {i+1}/{NUM_ROUNDS}")
        print(f"{'='*60}")

        generate_normal(net)
        info(f'*** Cooldown {COOLDOWN}s\n')
        time.sleep(COOLDOWN)

        generate_ddos(net)
        info(f'*** Cooldown {COOLDOWN}s\n')
        time.sleep(COOLDOWN)

        generate_portscan(net)
        info(f'*** Cooldown {COOLDOWN}s\n')
        time.sleep(COOLDOWN)

    # Dừng mạng
    info('*** Stopping network\n')
    net.stop()

    print("\n" + "=" * 60)
    print("[✓] Data collection complete!")
    print(f"[✓] Label log: {LABEL_LOG}")
    print("[*] Chạy: source .venv/bin/activate && python src/label_data.py")
    print("=" * 60)


if __name__ == '__main__':
    main()

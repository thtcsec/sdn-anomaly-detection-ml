"""
Script giả lập traffic bình thường và tấn công trong Mininet.
Chạy trong Mininet CLI hoặc gọi từ bên ngoài.

Sử dụng:
  - Normal traffic: python3 src/generate_traffic.py normal
  - DDoS attack:    python3 src/generate_traffic.py ddos
  - Port scan:      python3 src/generate_traffic.py portscan
"""

import sys
import os
import time
import subprocess
import random


def generate_normal_traffic():
    """
    Giả lập traffic bình thường: ping, iperf, HTTP requests.
    Chạy trên các host trong Mininet.
    """
    print("[*] Generating NORMAL traffic...")
    print("[*] Sử dụng trong Mininet CLI:")
    print()
    print("    # Ping bình thường giữa các host")
    print("    h1 ping -c 10 h2")
    print("    h2 ping -c 10 h3")
    print()
    print("    # iperf TCP bình thường (bandwidth test)")
    print("    h2 iperf -s &")
    print("    h1 iperf -c 10.0.0.2 -t 30")
    print()
    print("    # HTTP traffic giả lập")
    print("    h3 python3 -m http.server 80 &")
    print("    h1 curl http://10.0.0.3/")
    print()
    print("[*] Lưu ý: Đảm bảo controller đang chạy và ghi label='normal' trong CSV")


def generate_ddos_traffic():
    """
    Giả lập DDoS attack: flood packets từ nhiều source.
    """
    print("[*] Generating DDoS ATTACK traffic...")
    print("[*] Sử dụng trong Mininet CLI:")
    print()
    print("    # SYN Flood từ h4 (attacker) tới h1 (victim)")
    print("    h4 hping3 -S --flood -V -p 80 10.0.0.1 &")
    print()
    print("    # UDP Flood")
    print("    h5 hping3 --udp --flood -p 53 10.0.0.1 &")
    print()
    print("    # ICMP Flood (Ping of Death)")
    print("    h6 hping3 --icmp --flood 10.0.0.1 &")
    print()
    print("    # Hoặc dùng nhiều attacker cùng lúc:")
    print("    h4 hping3 -S --flood -p 80 10.0.0.1 &")
    print("    h5 hping3 -S --flood -p 80 10.0.0.2 &")
    print("    h6 hping3 --udp --flood -p 53 10.0.0.3 &")
    print()
    print("[*] QUAN TRỌNG: Sau khi chạy attack, đổi label trong monitor.py thành 'ddos'")
    print("[*] Hoặc post-process CSV file để gán label cho khoảng thời gian tấn công")


def generate_portscan_traffic():
    """
    Giả lập Port Scanning attack.
    """
    print("[*] Generating PORT SCAN traffic...")
    print("[*] Sử dụng trong Mininet CLI:")
    print()
    print("    # Nmap SYN scan từ h4 tới h1")
    print("    h4 nmap -sS -p 1-1024 10.0.0.1")
    print()
    print("    # Nmap full scan")
    print("    h4 nmap -sV -p- 10.0.0.1")
    print()
    print("    # Scan toàn bộ subnet")
    print("    h4 nmap -sS 10.0.0.0/24")
    print()
    print("[*] QUAN TRỌNG: Gán label='portscan' cho dữ liệu thu được trong khoảng này")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 src/generate_traffic.py [normal|ddos|portscan]")
        print()
        print("Script này in ra các lệnh cần chạy trong Mininet CLI.")
        print("Copy và paste vào Mininet CLI để thực thi.")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == 'normal':
        generate_normal_traffic()
    elif mode == 'ddos':
        generate_ddos_traffic()
    elif mode == 'portscan':
        generate_portscan_traffic()
    else:
        print(f"[!] Unknown mode: {mode}")
        print("Available modes: normal, ddos, portscan")
        sys.exit(1)


if __name__ == '__main__':
    main()

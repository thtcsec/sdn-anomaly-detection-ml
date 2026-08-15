"""
Script điều khiển sinh traffic thực nghiệm (Normal, DDoS, Portscan) trong Mininet.
Có thể gọi trực tiếp từ terminal hoặc qua Dashboard API.
"""

import sys
import os
import subprocess
import time
import argparse

def get_mininet_host_pids():
    """Lấy PID của các mininet host processes từ ps."""
    pids = {}
    try:
        out = subprocess.check_output(['ps', '-ef'], text=True)
        for line in out.splitlines():
            if 'mininet:h' in line:
                parts = line.split()
                pid = parts[1]
                for h in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
                    if f'mininet:{h}' in line:
                        pids[h] = pid
    except Exception as e:
        print(f"[!] Error getting host pids: {e}", file=sys.stderr)
    return pids

def run_in_host(pid, cmd, bg=True):
    """Chạy command bên trong host namespace qua mnexec."""
    if not pid:
        return False
    full_cmd = f"mnexec -a {pid} {cmd}"
    if bg:
        full_cmd += " &"
    subprocess.Popen(full_cmd, shell=True)
    return True

def trigger_normal(duration=10):
    pids = get_mininet_host_pids()
    if not pids:
        print("[!] Không tìm thấy Mininet topology đang chạy.")
        return False
    
    h1_pid = pids.get('h1')
    h2_pid = pids.get('h2')
    h3_pid = pids.get('h3')

    print(f"[*] Bắt đầu sinh Normal Traffic ({duration}s)...")
    if h2_pid:
        run_in_host(h2_pid, "iperf -s -p 5001", bg=True)
    if h3_pid:
        run_in_host(h3_pid, "python3 -m http.server 8000", bg=True)
    
    time.sleep(0.5)
    if h1_pid:
        # ping liên tục và curl nhẹ
        run_in_host(h1_pid, f"ping -c {duration * 2} -i 0.5 10.0.0.2", bg=True)
        run_in_host(h1_pid, f"iperf -c 10.0.0.2 -p 5001 -t {duration}", bg=True)
    
    return True

def trigger_ddos(target_ip='10.0.0.1', duration=8):
    pids = get_mininet_host_pids()
    if not pids:
        print("[!] Không tìm thấy Mininet topology đang chạy.")
        return False
    
    h4_pid = pids.get('h4')
    h5_pid = pids.get('h5')

    print(f"[*] Bắt đầu sinh DDoS SYN/UDP Flood tới {target_ip} ({duration}s)...")
    if h4_pid:
        # SYN flood
        run_in_host(h4_pid, f"timeout {duration} hping3 -S --flood -V -p 80 {target_ip}", bg=True)
    if h5_pid:
        # UDP flood
        run_in_host(h5_pid, f"timeout {duration} hping3 --udp --flood -p 53 {target_ip}", bg=True)
    
    return True

def trigger_portscan(target_ip='10.0.0.1', duration=10):
    pids = get_mininet_host_pids()
    if not pids:
        print("[!] Không tìm thấy Mininet topology đang chạy.")
        return False
    
    h6_pid = pids.get('h6')
    print(f"[*] Bắt đầu sinh Portscan tới {target_ip} ({duration}s)...")
    if h6_pid:
        run_in_host(h6_pid, f"timeout {duration} nmap -sS -T4 -p 1-1000 {target_ip}", bg=True)
    
    return True

def stop_all_traffic():
    print("[*] Dừng tất cả traffic simulation...")
    try:
        subprocess.run(["killall", "-9", "hping3", "nmap", "iperf"], capture_output=True)
    except Exception:
        pass
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mininet Traffic Generator")
    parser.add_argument('--type', choices=['normal', 'ddos', 'portscan', 'stop'], default='normal')
    parser.add_argument('--duration', type=int, default=8)
    parser.add_argument('--target', type=str, default='10.0.0.1')
    args = parser.parse_args()

    if args.type == 'normal':
        trigger_normal(args.duration)
    elif args.type == 'ddos':
        trigger_ddos(args.target, args.duration)
    elif args.type == 'portscan':
        trigger_portscan(args.target, args.duration)
    elif args.type == 'stop':
        stop_all_traffic()

"""SOC / Mininet traffic trigger (normal, ddos, portscan, stop). Keep — dashboard /api/simulate."""

import sys
import os
import subprocess
import time
import argparse
import ipaddress

ALLOWED_TARGETS = {ipaddress.ip_address(f"10.0.0.{host}") for host in range(1, 7)}

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

def validate_target(value):
    """Accept only the six hosts in the fixed Mininet thesis topology."""
    try:
        parsed = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("target must be an IPv4 address") from exc
    if parsed not in ALLOWED_TARGETS:
        raise argparse.ArgumentTypeError("target must be one of 10.0.0.1 through 10.0.0.6")
    return str(parsed)


def run_in_host(pid, argv, bg=True):
    """Chạy command bên trong host namespace qua mnexec."""
    if not pid:
        return False
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("argv must be a non-empty list")
    full_cmd = ["mnexec", "-a", str(int(pid)), *[str(arg) for arg in argv]]
    if bg:
        subprocess.Popen(full_cmd, start_new_session=True)
    else:
        subprocess.run(full_cmd, check=False)
    return True

def trigger_normal(duration=10):
    pids = get_mininet_host_pids()
    if not pids:
        print("[!] Không tìm thấy Mininet topology đang chạy.")
        return False
    
    h1_pid = pids.get('h1')
    h2_pid = pids.get('h2')

    print(f"[*] Bắt đầu sinh Normal Traffic ({duration}s)...")
    if h2_pid:
        run_in_host(h2_pid, ["timeout", str(duration + 3), "iperf", "-s", "-p", "5001"], bg=True)

    time.sleep(0.5)
    if h1_pid:
        run_in_host(h1_pid, ["ping", "-c", str(max(4, duration)), "-i", "0.4", "10.0.0.2"], bg=True)
        run_in_host(h1_pid, ["iperf", "-c", "10.0.0.2", "-p", "5001", "-t", str(duration)], bg=True)
    
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
        run_in_host(h4_pid, ["timeout", str(duration), "hping3", "-S", "--flood", "-V", "-p", "80", target_ip], bg=True)
    if h5_pid:
        # UDP flood
        run_in_host(h5_pid, ["timeout", str(duration), "hping3", "--udp", "--flood", "-p", "53", target_ip], bg=True)
    
    return True

def trigger_portscan(target_ip='10.0.0.1', duration=10):
    pids = get_mininet_host_pids()
    if not pids:
        print("[!] Không tìm thấy Mininet topology đang chạy.")
        return False
    
    h6_pid = pids.get('h6')
    print(f"[*] Bắt đầu sinh Portscan tới {target_ip} ({duration}s)...")
    if h6_pid:
        run_in_host(h6_pid, ["timeout", str(duration), "nmap", "-sS", "-T4", "-p", "1-1000", target_ip], bg=True)
    
    return True

def stop_all_traffic():
    print("[*] Dừng tất cả traffic simulation...")
    names = ["hping3", "nmap", "iperf", "iperf3", "ping"]
    for name in names:
        try:
            subprocess.run(["killall", "-9", name], capture_output=True)
        except Exception:
            pass
    try:
        subprocess.run(["pkill", "-9", "-f", "http.server"], capture_output=True)
    except Exception:
        pass
    for pid in get_mininet_host_pids().values():
        try:
            subprocess.run(
                ["mnexec", "-a", str(pid), "killall", "-9",
                 "hping3", "nmap", "iperf", "iperf3", "ping"],
                capture_output=True,
            )
        except Exception:
            pass
    print("[✓] Đã gửi SIGKILL tới ping/iperf/hping3/nmap trong host Mininet.")
    print("[*] Đồ thị SOC dùng packet tăng thêm mỗi poll — hết gói thì p/s về 0, "
          "không phải tổng lifetime của flow còn trong OVS.")
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mininet Traffic Generator")
    parser.add_argument('--type', choices=['normal', 'ddos', 'portscan', 'stop'], default='normal')
    parser.add_argument('--duration', type=lambda value: max(1, min(60, int(value))), default=8)
    parser.add_argument('--target', type=validate_target, default='10.0.0.1')
    args = parser.parse_args()

    if args.type == 'normal':
        trigger_normal(args.duration)
    elif args.type == 'ddos':
        trigger_ddos(args.target, args.duration)
    elif args.type == 'portscan':
        trigger_portscan(args.target, args.duration)
    elif args.type == 'stop':
        stop_all_traffic()

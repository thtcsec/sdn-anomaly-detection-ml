"""SOC / Mininet traffic trigger (normal, ddos, portscan, stop). Keep — dashboard /api/simulate."""

import sys
import os
import subprocess
import time
import argparse
import ipaddress

ALLOWED_TARGETS = {ipaddress.ip_address(f"10.0.0.{host}") for host in range(1, 7)}
HOST_NAMES = ('h1', 'h2', 'h3', 'h4', 'h5', 'h6')
KILL_NAMES = ('hping3', 'nmap', 'iperf', 'iperf3', 'ping')
# Never put these in an argv we exec — dash `sh -c` treats them as redirects/tokens.
_UNSAFE_ARGV_CHARS = set('<>()|&;`$')


def _argv_safe(argv):
    """Reject shell metacharacters so nothing is ever `sh -c '... < ...'`."""
    cleaned = [str(arg) for arg in argv]
    if not cleaned:
        raise ValueError("argv must be non-empty")
    for arg in cleaned:
        if _UNSAFE_ARGV_CHARS.intersection(arg):
            raise ValueError(f"refusing argv with shell metacharacters: {cleaned!r}")
    return cleaned


def _run_argv(argv, timeout=5):
    """POSIX exec, no shell, no redirects, no heredoc."""
    return subprocess.run(
        _argv_safe(argv),
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def get_mininet_host_pids():
    """PIDs of Mininet host bash shells (`mininet:hN`), skipping nested children."""
    pids = {}
    rows = []
    try:
        out = subprocess.check_output(['ps', '-eo', 'pid,ppid,args'], text=True)
    except Exception as e:
        print(f"[!] Error getting host pids: {e}", file=sys.stderr)
        return pids
    for line in out.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid_s, ppid_s, args = parts
        if not pid_s.isdigit() or not ppid_s.isdigit():
            continue
        if 'bash' not in args or 'mininet:h' not in args:
            continue
        for host in HOST_NAMES:
            if f'mininet:{host}' in args:
                rows.append((host, int(pid_s), int(ppid_s)))
                break
    host_pids = {pid for _, pid, _ in rows}
    for host, pid, ppid in rows:
        if ppid in host_pids:
            continue
        pids[host] = str(pid)
    if not pids:
        for host, pid, _ppid in rows:
            pids.setdefault(host, str(pid))
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
    full_cmd = _argv_safe(["mnexec", "-a", str(int(pid)), *argv])
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

def trigger_ddos(target_ip='10.0.0.1', duration=25, include_h5_udp=False):
    """Default thesis/video path: h4 SYN flood → h1 only (enough for 3×5s polls).

    Optional ``include_h5_udp`` keeps the old dual-attacker UDP path off the
    dashboard button.
    """
    pids = get_mininet_host_pids()
    if not pids:
        print("[!] Không tìm thấy Mininet topology đang chạy.")
        return False

    h4_pid = pids.get('h4')

    print(f"[*] Bắt đầu sinh DDoS SYN flood h4 → {target_ip} ({duration}s)...")
    if h4_pid:
        run_in_host(h4_pid, ["timeout", str(duration), "hping3", "-S", "--flood", "-V", "-p", "80", target_ip], bg=True)
    if include_h5_udp:
        h5_pid = pids.get('h5')
        if h5_pid:
            print(f"[*] Optional: UDP flood h5 → {target_ip} ({duration}s)...")
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
    """Kill hping3/iperf/nmap/ping in h1–h6. One killall name per exec (POSIX)."""
    print("[*] Dừng tất cả traffic simulation...")
    for name in KILL_NAMES:
        try:
            _run_argv(["killall", "-9", name])
        except Exception:
            pass
    for pid in get_mininet_host_pids().values():
        try:
            ipid = str(int(pid))
        except (TypeError, ValueError):
            continue
        for name in KILL_NAMES:
            try:
                _run_argv(["mnexec", "-a", ipid, "killall", "-9", name])
            except Exception:
                pass
    print("[✓] Đã gửi SIGKILL tới ping/iperf/hping3/nmap trong host Mininet.")
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mininet Traffic Generator")
    parser.add_argument('--type', choices=['normal', 'ddos', 'portscan', 'stop'], default='normal')
    parser.add_argument('--duration', type=lambda value: max(1, min(60, int(value))), default=None)
    parser.add_argument('--target', type=validate_target, default='10.0.0.1')
    parser.add_argument(
        '--include-h5-udp',
        action='store_true',
        help='Optional second attacker: h5 UDP flood (default is h4 SYN → h1 only)',
    )
    args = parser.parse_args()
    if args.duration is None:
        duration = 25 if args.type == 'ddos' else 10
    else:
        duration = args.duration

    if args.type == 'normal':
        trigger_normal(duration)
    elif args.type == 'ddos':
        trigger_ddos(args.target, duration, include_h5_udp=args.include_h5_udp)
    elif args.type == 'portscan':
        trigger_portscan(args.target, duration)
    elif args.type == 'stop':
        stop_all_traffic()

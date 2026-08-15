"""
Sinh lưu lượng Normal đa dạng quy mô lớn trong Mininet.
Tạo hàng nghìn luồng TCP/UDP/ICMP thật với đa cổng và đa dịch vụ giữa 6 host.
"""

import sys
import os
import time
import socket
import threading
import random
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'src'))

def get_mininet_host_pids():
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
        print(f"[!] Error: {e}", file=sys.stderr)
    return pids

def run_in_host(pid, cmd, bg=True):
    if not pid:
        return
    full = f"mnexec -a {pid} {cmd}"
    if bg:
        full += " &"
    subprocess.Popen(full, shell=True)

def generate_massive_normal(num_flows=5000, duration_sec=30):
    pids = get_mininet_host_pids()
    if not pids:
        print("[!] Không tìm thấy Mininet topology đang chạy.")
        return False

    print(f"[*] Bắt đầu sinh {num_flows}+ flows Normal đa dạng giữa 6 hosts ({duration_sec}s)...")
    
    # Setup dummy listeners on h2, h3, h5, h6
    script_server = """
import socket, threading
def listen_udp(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', port))
        while True:
            data, addr = s.recvfrom(1024)
            s.sendto(b'OK', addr)
    except: pass

for p in range(7000, 7100):
    threading.Thread(target=listen_udp, args=(p,), daemon=True).start()
import time; time.sleep(60)
"""
    # Write listener script
    tmp_srv = "/tmp/normal_server.py"
    with open(tmp_srv, "w") as f:
        f.write(script_server)

    if pids.get('h2'):
        run_in_host(pids['h2'], f"python3 {tmp_srv}", bg=True)
    if pids.get('h5'):
        run_in_host(pids['h5'], f"python3 {tmp_srv}", bg=True)

    # Client multi-port generator script
    script_client = f"""
import socket, time, random
target_ips = ['10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.6']
ports = list(range(1024, 6000)) + list(range(7000, 7100)) + [80, 443, 8080, 53, 21, 22]

t_end = time.time() + {duration_sec}
count = 0
while time.time() < t_end and count < {num_flows}:
    dst = random.choice(target_ips)
    port = random.choice(ports)
    # TCP attempt
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect_ex((dst, port))
        s.close()
    except: pass
    
    # UDP packet
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.sendto(b'NORMAL_TRAFFIC_DATA_PAYLOAD', (dst, port))
        u.close()
    except: pass
    
    count += 1
    if count % 200 == 0:
        time.sleep(0.05)
print(f"Generated {{count}} normal flow attempts.")
"""
    tmp_cli = "/tmp/normal_client.py"
    with open(tmp_cli, "w") as f:
        f.write(script_client)

    # Run clients from h1, h3, h4
    for h in ['h1', 'h3', 'h4']:
        if pids.get(h):
            run_in_host(pids[h], f"python3 {tmp_cli}", bg=True)

    print("[*] Đang phát sinh lưu lượng Normal qua Mininet switches...")
    time.sleep(duration_sec + 2)
    print("[✓] Hoàn tất sinh Normal traffic!")
    return True

if __name__ == '__main__':
    generate_massive_normal(num_flows=6000, duration_sec=25)

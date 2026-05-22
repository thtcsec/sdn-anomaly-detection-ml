import os
import time
import subprocess
import signal
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
LABEL_FILE = os.path.join(DATASET_DIR, 'current_label.txt')

def set_label(label):
    with open(LABEL_FILE, 'w') as f:
        f.write(label)
    print(f"[*] Set current label to: {label}")

def run_auto_traffic():
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.log import setLogLevel, info
    sys.path.insert(0, os.path.join(BASE_DIR, 'topology'))
    from custom_topo import SDNAnomalyTopo
    
    setLogLevel('info')
    topo = SDNAnomalyTopo()
    net = Mininet(topo=topo, controller=None, switch=OVSKernelSwitch, autoSetMacs=False)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    
    print("[*] Waiting for switches to connect to controller...")
    time.sleep(5)
    net.pingAll()
    time.sleep(2)
    
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    h4, h5, h6 = net.get('h4', 'h5', 'h6')
    
    # 1. Normal traffic
    set_label('normal')
    print("[*] Generating Normal Traffic for 60 seconds...")
    h2.cmd('iperf -s &')
    h1.cmd('iperf -c 10.0.0.2 -t 60 &')
    h3.cmd('python3 -m http.server 80 &')
    for _ in range(12):
        h1.cmd('curl -s http://10.0.0.3/ > /dev/null')
        time.sleep(5)
    h2.cmd('kill %iperf')
    h3.cmd('kill %python3')
    
    # 2. DDoS attack
    set_label('ddos')
    print("[*] Generating DDoS Traffic for 30 seconds...")
    h4.cmd('hping3 -S --flood -V -p 80 10.0.0.1 &')
    h5.cmd('hping3 --udp --flood -p 53 10.0.0.1 &')
    time.sleep(30)
    h4.cmd('killall hping3')
    h5.cmd('killall hping3')
    
    # 3. Portscan
    set_label('portscan')
    print("[*] Generating Portscan Traffic for 30 seconds...")
    h6.cmd('nmap -sS -p- 10.0.0.1 &')
    time.sleep(30)
    h6.cmd('killall nmap')
    
    net.stop()
    print("[*] Traffic generation complete.")

if __name__ == '__main__':
    run_auto_traffic()

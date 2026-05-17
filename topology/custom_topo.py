"""
Custom Mininet Topology cho khóa luận SDN Anomaly Detection.

Topology: 2 switches, 6 hosts
  - Switch s1: h1, h2, h3 (mạng nội bộ - normal traffic)
  - Switch s2: h4, h5, h6 (mạng ngoài - có thể giả lập attacker)
  - s1 <-> s2 kết nối với nhau

Chạy: sudo python3 topology/custom_topo.py
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class SDNAnomalyTopo(Topo):
    """Topology cho thí nghiệm phát hiện bất thường SDN."""

    def build(self):
        info('*** Tạo switches\n')
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')

        info('*** Tạo hosts\n')
        # Mạng nội bộ (normal users)
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')

        # Mạng ngoài (attacker có thể ở đây)
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        h6 = self.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')

        info('*** Tạo links\n')
        # Kết nối hosts vào switches
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)

        # Kết nối 2 switches
        self.addLink(s1, s2)


def run_topology():
    """Khởi chạy topology với Remote Controller (os-ken)."""
    setLogLevel('info')

    topo = SDNAnomalyTopo()
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=False
    )

    # Kết nối tới os-ken controller chạy ở localhost:6633
    info('*** Kết nối tới os-ken controller\n')
    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    info('*** Khởi động mạng\n')
    net.start()

    info('*** Kiểm tra kết nối\n')
    net.pingAll()

    info('*** Mở Mininet CLI\n')
    CLI(net)

    info('*** Dừng mạng\n')
    net.stop()


if __name__ == '__main__':
    run_topology()

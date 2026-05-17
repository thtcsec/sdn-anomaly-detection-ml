"""
SDN Flow Monitor - Thu thập flow statistics từ OpenFlow switches.
Sử dụng os-ken (fork chính thức của Ryu) làm SDN controller.

Chạy: python controller/run_controller.py
"""

import os
import csv
import time
from datetime import datetime

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp
from os_ken.lib import hub


# Đường dẫn lưu dataset
DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dataset')
CSV_FILE = os.path.join(DATASET_DIR, 'flow_stats.csv')

# Chu kỳ thu thập (giây)
MONITOR_INTERVAL = 5

# Header cho CSV
CSV_HEADER = [
    'timestamp',
    'datapath_id',
    'flow_id',
    'ip_src',
    'ip_dst',
    'ip_proto',
    'tp_src',
    'tp_dst',
    'packet_count',
    'byte_count',
    'duration_sec',
    'duration_nsec',
    'packet_count_per_sec',
    'byte_count_per_sec',
    'packet_size_avg',
    'flow_duration',
    'label'
]


class FlowMonitor(app_manager.OSKenApp):
    """
    Controller app thu thập flow statistics từ các switch.
    Dữ liệu được ghi ra file CSV để phục vụ training ML model.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self._init_csv()

    def _init_csv(self):
        """Khởi tạo file CSV với header nếu chưa tồn tại."""
        os.makedirs(DATASET_DIR, exist_ok=True)
        if not os.path.exists(CSV_FILE):
            with open(CSV_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)
            self.logger.info("Created CSV file: %s", CSV_FILE)

    def _monitor(self):
        """Thread gửi request flow stats định kỳ."""
        while True:
            for dp_id, dp in self.datapaths.items():
                self._request_stats(dp)
            hub.sleep(MONITOR_INTERVAL)

    def _request_stats(self, datapath):
        """Gửi FlowStatsRequest tới switch."""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Xử lý khi switch kết nối - cài đặt table-miss flow entry."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Cài đặt table-miss flow entry: gửi packet tới controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

        # Đăng ký datapath để monitor
        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch connected: dpid=%s", datapath.id)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=60):
        """Thêm flow entry vào switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timeout,
                                    instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Xử lý packet-in: học MAC, cài flow entry match IP (L3)."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Bỏ qua LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Cài flow entry match IP layer (L3) nếu biết output port
        if out_port != ofproto.OFPP_FLOOD:
            # Kiểm tra xem có phải IP packet không
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                # Match theo IP src/dst + protocol để flow stats có thông tin IP
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)

                if tcp_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto,
                        tcp_src=tcp_pkt.src_port,
                        tcp_dst=tcp_pkt.dst_port
                    )
                elif udp_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto,
                        udp_src=udp_pkt.src_port,
                        udp_dst=udp_pkt.dst_port
                    )
                else:
                    # ICMP hoặc protocol khác
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto
                    )
            else:
                # Non-IP packet (ARP, etc.) - match L2
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self._add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Xử lý flow stats reply - trích xuất features và ghi CSV."""
        body = ev.msg.body
        datapath = ev.msg.datapath
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        rows = []
        for stat in body:
            # Chỉ thu thập flow có thông tin IP (bỏ qua table-miss và ARP flows)
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match:
                continue

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match.get('ip_proto', 0)
            tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
            tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))

            # Tính flow_id duy nhất
            flow_id = hash((ip_src, ip_dst, ip_proto, tp_src, tp_dst)) % (10**8)

            # Tính các features
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            pkt_per_sec = stat.packet_count / duration if duration > 0 else 0
            byte_per_sec = stat.byte_count / duration if duration > 0 else 0
            pkt_size_avg = stat.byte_count / stat.packet_count if stat.packet_count > 0 else 0

            row = [
                timestamp,
                datapath.id,
                flow_id,
                ip_src,
                ip_dst,
                ip_proto,
                tp_src,
                tp_dst,
                stat.packet_count,
                stat.byte_count,
                stat.duration_sec,
                stat.duration_nsec,
                round(pkt_per_sec, 4),
                round(byte_per_sec, 4),
                round(pkt_size_avg, 4),
                round(duration, 4),
                'normal'  # Label mặc định, đổi khi giả lập tấn công
            ]
            rows.append(row)

        # Ghi vào CSV
        if rows:
            with open(CSV_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            self.logger.info("Recorded %d flows from dpid=%s", len(rows), datapath.id)

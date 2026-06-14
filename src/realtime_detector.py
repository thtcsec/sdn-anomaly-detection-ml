"""
Real-time Anomaly Detection Controller.
Tích hợp XGBoost model vào os-ken controller để detect attack real-time.
Được đặt trong thư mục src.
"""

import os
import joblib
import pandas as pd
from datetime import datetime

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from os_ken.lib import hub

# Đường dẫn lưu dataset & models
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'xgboost_model.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'models', 'scaler.pkl')

MONITOR_INTERVAL = 5
# Đảm bảo LABEL_MAP đúng với label encoder (0: DDOS, 1: NORMAL, 2: PORTSCAN)
LABEL_MAP = {0: 'DDOS', 1: 'NORMAL', 2: 'PORTSCAN'}


class RealtimeDetector(app_manager.OSKenApp):
    """Controller với khả năng phát hiện tấn công real-time."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RealtimeDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # Load model
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.logger.info("\033[92m[✓] Tải thành công mô hình XGBoost để Real-time Inference.\033[0m")
        else:
            self.model = None
            self.scaler = None
            self.logger.warning("[!] Không tìm thấy mô hình. Chạy train_model.py trước.")

    def _monitor(self):
        """Thread gửi request flow stats định kỳ mỗi 5 giây."""
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

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch connected: dpid=%s", datapath.id)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=60):
        """Thêm flow entry vào switch với idle_timeout."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timeout, instructions=inst)
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
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)
                if tcp_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto,
                        tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
                elif udp_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto,
                        udp_src=udp_pkt.src_port, udp_dst=udp_pkt.dst_port)
                else:
                    match = parser.OFPMatch(
                        in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto)
            else:
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
        """Thu thập flow stats và predict real-time."""
        if self.model is None or self.scaler is None:
            return

        body = ev.msg.body
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for stat in body:
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match:
                continue

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match.get('ip_proto', 0)
            tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
            tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))

            duration = stat.duration_sec + stat.duration_nsec / 1e9
            pkt_per_sec = stat.packet_count / duration if duration > 0 else 0
            byte_per_sec = stat.byte_count / duration if duration > 0 else 0
            pkt_size_avg = stat.byte_count / stat.packet_count if stat.packet_count > 0 else 0

            # Tạo dictionary features theo định dạng và tên cột chính xác của model training
            features = {
                'ip_proto': ip_proto,
                'tp_src': tp_src,
                'tp_dst': tp_dst,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec,
                'packet_count_per_sec': pkt_per_sec,
                'byte_count_per_sec': byte_per_sec,
                'packet_size_avg': pkt_size_avg,
                'flow_duration': duration
            }

            # Chuyển đổi thành DataFrame để tránh cảnh báo UserWarning về feature names
            df_features = pd.DataFrame([features])
            features_scaled = pd.DataFrame(
                self.scaler.transform(df_features),
                columns=df_features.columns
            )

            prediction = self.model.predict(features_scaled)[0]
            label = LABEL_MAP.get(prediction, 'UNKNOWN')

            # Alert cảnh báo có màu đỏ nếu phát hiện tấn công (DDOS hoặc PORTSCAN)
            if label in ['DDOS', 'PORTSCAN']:
                self.logger.warning(
                    "\033[91m⚠️  ALERT [%s] PHÁT HIỆN TẤN CÔNG %s TỪ %s ĐẾN %s ! (proto=%d, pkts/s=%.1f)\033[0m",
                    timestamp, label, ip_src, ip_dst, ip_proto, pkt_per_sec
                )

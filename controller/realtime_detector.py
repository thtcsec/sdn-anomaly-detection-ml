"""
Real-time Anomaly Detection Controller with Auto-Mitigation.
Tích hợp XGBoost model vào os-ken controller để detect attack real-time.
Khi phát hiện tấn công → tự động cài đặt DROP rule chặn IP nguồn tấn công.

Chạy: python controller/run_realtime.py
"""

import os
import numpy as np
import joblib
from datetime import datetime
from collections import defaultdict

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from os_ken.lib import hub


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'xgboost_model.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'models', 'scaler.pkl')

MONITOR_INTERVAL = 5
LABEL_MAP = {0: 'DDOS', 1: 'NORMAL', 2: 'PORTSCAN'}

# === AUTO-MITIGATION CONFIG ===
MITIGATION_ENABLED = True          # Bật/tắt auto-block
ALERT_THRESHOLD = 3                # Số lần detect liên tiếp trước khi block
BLOCK_TIMEOUT = 120                # Thời gian block IP (giây), sau đó tự mở
BLOCK_PRIORITY = 100               # Priority cao để override flow rules khác


class RealtimeDetector(app_manager.OSKenApp):
    """Controller với khả năng phát hiện tấn công real-time."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RealtimeDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # Mitigation state
        self.alert_counter = defaultdict(int)  # IP → số lần bị detect
        self.blocked_ips = set()               # Danh sách IP đã bị block

        # Load model
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.logger.info("\033[92m[✓] Loaded XGBoost model successfully\033[0m")
            self.logger.info("\033[92m[✓] Auto-Mitigation: %s (threshold=%d, timeout=%ds)\033[0m",
                            "ENABLED" if MITIGATION_ENABLED else "DISABLED",
                            ALERT_THRESHOLD, BLOCK_TIMEOUT)
        else:
            self.model = None
            self.scaler = None
            self.logger.warning("[!] Model not found! Run train_model.py first.")

    def _monitor(self):
        while True:
            for dp_id, dp in self.datapaths.items():
                self._request_stats(dp)
            hub.sleep(MONITOR_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch connected: dpid=%s", datapath.id)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=60, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=60, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

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
        if self.model is None:
            return

        body = ev.msg.body
        datapath = ev.msg.datapath
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for stat in body:
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match:
                continue

            ip_proto = stat.match.get('ip_proto', 0)
            tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
            tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))

            duration = stat.duration_sec + stat.duration_nsec / 1e9
            pkt_per_sec = stat.packet_count / duration if duration > 0 else 0
            byte_per_sec = stat.byte_count / duration if duration > 0 else 0
            pkt_size_avg = stat.byte_count / stat.packet_count if stat.packet_count > 0 else 0

            # Feature vector (10 features, same order as training)
            features = np.array([[
                ip_proto, tp_src, tp_dst,
                stat.packet_count, stat.byte_count, stat.duration_sec,
                pkt_per_sec, byte_per_sec, pkt_size_avg, duration
            ]])

            # Scale + Predict
            features_scaled = self.scaler.transform(features)
            prediction = self.model.predict(features_scaled)[0]
            label = LABEL_MAP.get(prediction, 'UNKNOWN')

            # Alert nếu phát hiện tấn công
            if label != 'NORMAL':
                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match['ipv4_dst']

                self.logger.warning(
                    "\033[91m⚠️  ALERT [%s] %s -> %s | proto=%d | "
                    "pkts/s=%.1f | bytes/s=%.1f | prediction=%s\033[0m",
                    timestamp, ip_src, ip_dst,
                    ip_proto, pkt_per_sec, byte_per_sec, label
                )

                # === AUTO-MITIGATION ===
                if MITIGATION_ENABLED and ip_src not in self.blocked_ips:
                    self.alert_counter[ip_src] += 1

                    if self.alert_counter[ip_src] >= ALERT_THRESHOLD:
                        self._block_attacker(datapath, ip_src, label)

    def _block_attacker(self, datapath, attacker_ip, attack_type):
        """
        Cài đặt DROP rule trên TẤT CẢ switches để chặn traffic từ attacker IP.
        Rule có hard_timeout → tự động gỡ sau BLOCK_TIMEOUT giây.
        """
        if attacker_ip in self.blocked_ips:
            return

        self.blocked_ips.add(attacker_ip)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Match tất cả traffic từ attacker IP
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=attacker_ip
        )

        # Actions rỗng = DROP (không forward gói tin đi đâu cả)
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Cài đặt DROP rule trên TẤT CẢ switches đã kết nối
        for dp_id, dp in self.datapaths.items():
            dp_parser = dp.ofproto_parser
            dp_ofproto = dp.ofproto

            dp_match = dp_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=attacker_ip
            )
            dp_inst = [dp_parser.OFPInstructionActions(
                dp_ofproto.OFPIT_APPLY_ACTIONS, [])]

            mod = dp_parser.OFPFlowMod(
                datapath=dp,
                priority=BLOCK_PRIORITY,
                match=dp_match,
                instructions=dp_inst,
                hard_timeout=BLOCK_TIMEOUT,  # Tự gỡ sau N giây
                idle_timeout=0,
                flags=dp_ofproto.OFPFF_SEND_FLOW_REM  # Notify khi rule bị xóa
            )
            dp.send_msg(mod)

        self.logger.error(
            "\033[91;1m🚫 BLOCKED [%s] Attacker IP %s on ALL switches | "
            "Attack: %s | Duration: %ds | Alerts: %d\033[0m",
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            attacker_ip, attack_type, BLOCK_TIMEOUT,
            self.alert_counter[attacker_ip]
        )

        # Reset counter sau khi block
        self.alert_counter[attacker_ip] = 0

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """Xử lý khi DROP rule hết timeout → unblock IP."""
        msg = ev.msg
        match = msg.match

        if 'ipv4_src' in match and msg.priority == BLOCK_PRIORITY:
            unblocked_ip = match['ipv4_src']
            if unblocked_ip in self.blocked_ips:
                self.blocked_ips.discard(unblocked_ip)
                self.logger.info(
                    "\033[93m🔓 UNBLOCKED [%s] IP %s - block timeout expired (%ds)\033[0m",
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    unblocked_ip, BLOCK_TIMEOUT
                )

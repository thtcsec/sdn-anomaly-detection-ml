"""
Real-time Anomaly Detection Controller with Auto-Mitigation.
Tích hợp XGBoost model vào os-ken controller để detect attack real-time.
Khi phát hiện tấn công → tự động cài đặt DROP rule chặn IP nguồn tấn công.

Chạy: python controller/run_realtime.py
"""

import os
import time
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from collections import Counter, defaultdict

LEGACY_FEATURE_COLS = [
    'ip_proto', 'tp_src', 'tp_dst',
    'packet_count', 'byte_count', 'duration_sec',
    'packet_count_per_sec', 'byte_count_per_sec',
    'packet_size_avg', 'flow_duration',
]

# Candidate protocol D intentionally excludes raw port values.  It is loaded
# only when explicitly selected in controller_config.json; the legacy model is
# unchanged by this code path.
ROBUST_FEATURE_COLS = [
    'ip_proto',
    'packet_count', 'byte_count', 'duration_sec',
    'packet_count_per_sec', 'byte_count_per_sec',
    'packet_size_avg', 'flow_duration',
]

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from os_ken.lib import hub


import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'xgboost_model.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'models', 'scaler.pkl')
ALERT_LOG = os.path.join(BASE_DIR, 'dataset', 'alerts.json')
LIVE_STATS_LOG = os.path.join(BASE_DIR, 'dataset', 'live_stats.json')
CONFIG_PATH = os.path.join(BASE_DIR, 'dataset', 'controller_config.json')

MAX_ALERTS = 500
MAX_RECENT_FLOWS = 50
BLOCK_PRIORITY = 100
LABEL_MAP = {0: 'DDOS', 1: 'NORMAL', 2: 'PORTSCAN'}

DEFAULT_CONFIG = {
    'polling_interval': 5.0,
    'alert_threshold': 3,
    'block_timeout': 120,
    'mitigation_enabled': True,
    'selected_model': 'xgboost'
}


class RealtimeDetector(app_manager.OSKenApp):
    """Controller với khả năng phát hiện tấn công real-time."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RealtimeDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        # Mitigation & Dynamic Config State
        self.monitor_interval = 5.0
        self.alert_threshold = 3
        self.block_timeout = 120
        self.mitigation_enabled = True
        self.selected_model_name = 'xgboost'

        self.alert_counter = defaultdict(int)  # IP → số lần bị detect
        self.blocked_ips = set()               # Danh sách IP đã bị block
        self.flows_analyzed = 0
        self.normal_count = 0
        self.ddos_count = 0
        self.portscan_count = 0
        self.recent_flows = []
        self.last_inference_latency_ms = 0.32

        # Initial config & model load
        self.model = None
        self.scaler = None
        self.feature_cols = LEGACY_FEATURE_COLS
        self._reload_config(initial=True)

        self.monitor_thread = hub.spawn(self._monitor)

        # Reset alert log & live stats khi start controller
        os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
        with open(ALERT_LOG, 'w', encoding='utf-8') as f:
            json.dump([], f)
        self._save_live_stats()

    def _reload_config(self, initial=False):
        """Đọc dynamic config từ dataset/controller_config.json nếu có."""
        cfg = dict(DEFAULT_CONFIG)
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                    if isinstance(saved, dict):
                        cfg.update(saved)
            except Exception:
                pass
        else:
            try:
                os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
                with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                    json.dump(cfg, f, indent=2)
            except Exception:
                pass

        self.monitor_interval = max(1.0, min(30.0, float(cfg.get('polling_interval', 5.0))))
        self.alert_threshold = max(1, min(20, int(cfg.get('alert_threshold', 3))))
        self.block_timeout = max(10, min(1200, int(cfg.get('block_timeout', 120))))
        self.mitigation_enabled = bool(cfg.get('mitigation_enabled', True))

        target_model = str(cfg.get('selected_model', 'xgboost')).lower()
        if initial or target_model != self.selected_model_name or self.model is None:
            self._switch_model(target_model)

    def _switch_model(self, model_name):
        """Nạp model ML tương ứng (XGBoost hoặc Random Forest)."""
        if model_name == 'random_forest':
            m_path = os.path.join(BASE_DIR, 'models', 'random_forest_model.pkl')
            s_path = os.path.join(BASE_DIR, 'models', 'random_forest_scaler.pkl')
            feature_cols = LEGACY_FEATURE_COLS
        elif model_name == 'xgboost_robust':
            m_path = os.path.join(BASE_DIR, 'models', 'xgboost_realtime_robust.pkl')
            s_path = os.path.join(BASE_DIR, 'models', 'xgboost_realtime_robust_scaler.pkl')
            feature_cols = ROBUST_FEATURE_COLS
        else:
            model_name = 'xgboost'
            m_path = os.path.join(BASE_DIR, 'models', 'xgboost_model.pkl')
            s_path = os.path.join(BASE_DIR, 'models', 'scaler.pkl')
            feature_cols = LEGACY_FEATURE_COLS

        if os.path.exists(m_path) and os.path.exists(s_path):
            try:
                self.model = joblib.load(m_path)
                self.scaler = joblib.load(s_path)
                self.selected_model_name = model_name
                self.feature_cols = feature_cols
                self.logger.info("\033[92m[✓] Active ML Model: %s\033[0m", model_name.upper())
                self.logger.info("\033[92m[✓] Auto-Mitigation: %s (threshold=%d, timeout=%ds, poll=%.1fs)\033[0m",
                                "ENABLED" if self.mitigation_enabled else "DISABLED",
                                self.alert_threshold, self.block_timeout, self.monitor_interval)
            except Exception as e:
                self.logger.error("[!] Failed to load model %s: %s", model_name, e)
        else:
            self.logger.warning("[!] Model file not found: %s", m_path)

    def _monitor(self):
        while True:
            self._reload_config()
            for dp_id, dp in self.datapaths.items():
                self._request_stats(dp)
            hub.sleep(self.monitor_interval)

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
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_dst=dst,
                    eth_src=src,
                )

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
        updated_any = False
        # A polling reply is the decision round.  We aggregate per source so
        # "3 consecutive alerts" means three polling rounds, not three flow
        # entries from the same stats reply.
        source_poll = defaultdict(list)

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

            feature_values = {
                'ip_proto': ip_proto,
                'tp_src': tp_src,
                'tp_dst': tp_dst,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec,
                'packet_count_per_sec': pkt_per_sec,
                'byte_count_per_sec': byte_per_sec,
                'packet_size_avg': pkt_size_avg,
                'flow_duration': duration,
            }
            # Keep names and ordering from the fitted candidate/legacy scaler.
            features = pd.DataFrame([[feature_values[c] for c in self.feature_cols]],
                                    columns=self.feature_cols)

            t0 = time.perf_counter()
            features_scaled = self.scaler.transform(features)
            prediction = self.model.predict(features_scaled)[0]
            inf_time = (time.perf_counter() - t0) * 1000.0  # in ms
            self.last_inference_latency_ms = round(inf_time, 3)

            label = LABEL_MAP.get(prediction, 'UNKNOWN')
            self.flows_analyzed += 1
            updated_any = True

            if label == 'NORMAL':
                self.normal_count += 1
            elif label == 'DDOS':
                self.ddos_count += 1
            elif label == 'PORTSCAN':
                self.portscan_count += 1

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            is_blocked = (ip_src in self.blocked_ips)
            source_poll[ip_src].append({
                'label': label,
                'datapath': datapath,
                'ip_dst': ip_dst,
                'tp_dst': int(tp_dst),
                'ip_proto': int(ip_proto),
                'packet_count_per_sec': float(pkt_per_sec),
                'byte_count_per_sec': float(byte_per_sec),
                'blocked': is_blocked,
            })

            # Record recent flow (kể cả Normal)
            flow_entry = {
                'timestamp': timestamp,
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'tp_src': int(tp_src),
                'tp_dst': int(tp_dst),
                'ip_proto': int(ip_proto),
                'packet_count': int(stat.packet_count),
                'packet_count_per_sec': round(float(pkt_per_sec), 1),
                'byte_count_per_sec': round(float(byte_per_sec), 1),
                'prediction': label,
                'blocked': is_blocked,
                'latency_ms': self.last_inference_latency_ms
            }
            self.recent_flows.append(flow_entry)
            if len(self.recent_flows) > MAX_RECENT_FLOWS:
                self.recent_flows = self.recent_flows[-MAX_RECENT_FLOWS:]

        # Apply mitigation once per source for this complete polling reply.
        for ip_src, evidence in source_poll.items():
            attacks = [item for item in evidence if item['label'] != 'NORMAL']
            if not attacks:
                self.alert_counter[ip_src] = 0
                continue
            selected = Counter(item['label'] for item in attacks).most_common(1)[0][0]
            representative = attacks[0]
            self.logger.warning(
                "\033[91m⚠️  ALERT [%s] %s -> %s | proto=%d | "
                "pkts/s=%.1f | bytes/s=%.1f | prediction=%s (source poll)\033[0m",
                timestamp, ip_src, representative['ip_dst'], representative['ip_proto'],
                representative['packet_count_per_sec'], representative['byte_count_per_sec'], selected,
            )
            blocked_now = False
            if self.mitigation_enabled and ip_src not in self.blocked_ips:
                self.alert_counter[ip_src] += 1
                if self.alert_counter[ip_src] >= self.alert_threshold:
                    self._block_attacker(representative['datapath'], ip_src, selected)
                    blocked_now = True
            self._append_alert({
                'timestamp': timestamp,
                'ip_src': ip_src,
                'ip_dst': representative['ip_dst'],
                'tp_dst': representative['tp_dst'],
                'ip_proto': representative['ip_proto'],
                'packet_count_per_sec': representative['packet_count_per_sec'],
                'byte_count_per_sec': representative['byte_count_per_sec'],
                'prediction': selected,
                'blocked': blocked_now or representative['blocked'],
                'flows_analyzed': self.flows_analyzed,
                'latency_ms': self.last_inference_latency_ms,
                'source_poll_flows': len(evidence),
            })

        if updated_any:
            self._save_live_stats()

    def _save_live_stats(self):
        """Lưu telemetry & live stats ra dataset/live_stats.json cho Dashboard."""
        try:
            payload = {
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'flows_analyzed': self.flows_analyzed,
                'normal_count': self.normal_count,
                'ddos_count': self.ddos_count,
                'portscan_count': self.portscan_count,
                'blocked_ips': sorted(list(self.blocked_ips)),
                'active_switches': list(self.datapaths.keys()),
                'last_latency_ms': self.last_inference_latency_ms,
                'recent_flows': self.recent_flows[-30:],
                'config': {
                    'polling_interval': self.monitor_interval,
                    'alert_threshold': self.alert_threshold,
                    'block_timeout': self.block_timeout,
                    'mitigation_enabled': self.mitigation_enabled,
                    'selected_model': self.selected_model_name
                }
            }
            tmp = LIVE_STATS_LOG + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp, LIVE_STATS_LOG)
        except Exception as exc:
            self.logger.error("[!] Failed to write live stats: %s", exc)

    def _append_alert(self, alert):
        """Ghi alert ra dataset/alerts.json (atomic) để Web Dashboard đọc."""
        try:
            alerts = []
            if os.path.exists(ALERT_LOG):
                with open(ALERT_LOG, 'r', encoding='utf-8') as f:
                    alerts = json.load(f)
                    if not isinstance(alerts, list):
                        alerts = []
            alerts.append(alert)
            if len(alerts) > MAX_ALERTS:
                alerts = alerts[-MAX_ALERTS:]
            tmp_path = ALERT_LOG + '.tmp'
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, ALERT_LOG)
        except (OSError, json.JSONDecodeError) as exc:
            self.logger.error("[!] Failed to write alert log: %s", exc)

    def _block_attacker(self, datapath, attacker_ip, attack_type):
        """
        Cài đặt DROP rule trên TẤT CẢ switches để chặn traffic từ attacker IP.
        Rule có hard_timeout → tự động gỡ sau self.block_timeout giây.
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
                hard_timeout=self.block_timeout,  # Tự gỡ sau N giây
                idle_timeout=0,
                flags=dp_ofproto.OFPFF_SEND_FLOW_REM  # Notify khi rule bị xóa
            )
            dp.send_msg(mod)

        self.logger.error(
            "\033[91;1m🚫 BLOCKED [%s] Attacker IP %s on ALL switches | "
            "Attack: %s | Duration: %ds | Alerts: %d\033[0m",
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            attacker_ip, attack_type, self.block_timeout,
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
                    unblocked_ip, self.block_timeout
                )


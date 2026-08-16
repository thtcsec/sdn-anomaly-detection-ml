"""
os-ken app for the FAULT dataset only.

Polls Flow Statistics + Port Statistics every 5s, writes delta/window
features to dataset/fault_live/. Does NOT touch dataset/flow_stats.csv
(the anomaly DDoS/Portscan/Normal pool).

Chạy: python controller/run_fault_monitor.py
"""

from __future__ import annotations

import csv
import os
import time
from datetime import datetime

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, ether_types, ipv4, packet, tcp, udp
from os_ken.ofproto import ofproto_v1_3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE_DIR = os.path.join(BASE_DIR, "dataset", "fault_live")
FLOW_CSV = os.path.join(LIVE_DIR, "flow_polls.csv")
PORT_CSV = os.path.join(LIVE_DIR, "port_polls.csv")
MONITOR_INTERVAL = 5.0

FLOW_HEADER = [
    "timestamp",
    "datapath_id",
    "ip_src",
    "ip_dst",
    "ip_proto",
    "tp_src",
    "tp_dst",
    "packet_count",
    "byte_count",
    "duration_sec",
    "packet_size_avg",
    "delta_packet",
    "delta_byte",
    "packet_rate_window",
    "byte_rate_window",
    "dt_sec",
    "has_delta",
]

PORT_HEADER = [
    "timestamp",
    "datapath_id",
    "port_no",
    "rx_packets",
    "tx_packets",
    "rx_bytes",
    "tx_bytes",
    "rx_dropped",
    "tx_dropped",
    "rx_errors",
    "tx_errors",
    "delta_rx_packets",
    "delta_tx_packets",
    "delta_rx_bytes",
    "delta_tx_bytes",
    "delta_rx_dropped",
    "delta_tx_dropped",
    "delta_rx_errors",
    "delta_tx_errors",
    "rx_bps",
    "tx_bps",
    "drop_rate",
    "dt_sec",
    "has_delta",
]


def _init_csv(path, header):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)


class FaultMonitor(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.prev_flow = {}
        self.prev_port = {}
        _init_csv(FLOW_CSV, FLOW_HEADER)
        _init_csv(PORT_CSV, PORT_HEADER)
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("[fault] writing %s and %s", FLOW_CSV, PORT_CSV)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                ofproto = dp.ofproto
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
                dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofproto.OFPP_ANY))
            hub.sleep(MONITOR_INTERVAL)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=20):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            idle_timeout=idle_timeout,
            instructions=inst,
        )
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions, idle_timeout=0)
        self.datapaths[datapath.id] = datapath
        self.logger.info("[fault] switch dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
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
                        tcp_dst=tcp_pkt.dst_port,
                    )
                elif udp_pkt:
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto,
                        udp_src=udp_pkt.src_port,
                        udp_dst=udp_pkt.dst_port,
                    )
                else:
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst,
                        ip_proto=ip_pkt.proto,
                    )
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_dst=eth.dst,
                    eth_src=eth.src,
                )
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            self._add_flow(datapath, 1, match, actions)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(
            parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
        )

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        now = time.time()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dpid = ev.msg.datapath.id
        rows = []
        for stat in ev.msg.body:
            if "ipv4_src" not in stat.match or "ipv4_dst" not in stat.match:
                continue
            ip_src = stat.match["ipv4_src"]
            ip_dst = stat.match["ipv4_dst"]
            ip_proto = int(stat.match.get("ip_proto", 0) or 0)
            tp_src = int(stat.match.get("tcp_src", stat.match.get("udp_src", 0)) or 0)
            tp_dst = int(stat.match.get("tcp_dst", stat.match.get("udp_dst", 0)) or 0)
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            pkt = int(stat.packet_count)
            byt = int(stat.byte_count)
            size_avg = byt / pkt if pkt else 0.0
            key = (dpid, ip_src, ip_dst, ip_proto, tp_src, tp_dst)
            prev = self.prev_flow.get(key)
            has_delta = 0
            d_pkt = d_byt = dt = rate_p = rate_b = 0.0
            if prev is not None:
                dt = max(now - prev["t"], 1e-6)
                d_pkt = pkt - prev["pkt"]
                d_byt = byt - prev["byt"]
                if d_pkt < 0 or d_byt < 0:
                    d_pkt = d_byt = 0.0
                else:
                    has_delta = 1
                    rate_p = d_pkt / dt
                    rate_b = d_byt / dt
            self.prev_flow[key] = {"t": now, "pkt": pkt, "byt": byt}
            rows.append([
                ts, dpid, ip_src, ip_dst, ip_proto, tp_src, tp_dst,
                pkt, byt, round(duration, 4), round(size_avg, 4),
                round(d_pkt, 4), round(d_byt, 4), round(rate_p, 4), round(rate_b, 4),
                round(dt, 4), has_delta,
            ])
        if rows:
            with open(FLOW_CSV, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)
            self.logger.info("[fault] flows=%d dpid=%s", len(rows), dpid)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        now = time.time()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dpid = ev.msg.datapath.id
        ofproto = ev.msg.datapath.ofproto
        rows = []
        for stat in ev.msg.body:
            port_no = int(stat.port_no)
            if port_no == ofproto.OFPP_LOCAL or port_no > 0xFFFFFF00:
                continue
            key = (dpid, port_no)
            prev = self.prev_port.get(key)
            rx_p, tx_p = int(stat.rx_packets), int(stat.tx_packets)
            rx_b, tx_b = int(stat.rx_bytes), int(stat.tx_bytes)
            rx_d, tx_d = int(stat.rx_dropped), int(stat.tx_dropped)
            rx_e, tx_e = int(stat.rx_errors), int(stat.tx_errors)
            has_delta = 0
            dt = 0.0
            rx_bps = tx_bps = drop_rate = 0.0
            d_rx_p = d_tx_p = d_rx_b = d_tx_b = 0
            d_rx_d = d_tx_d = d_rx_e = d_tx_e = 0
            if prev is not None:
                dt = max(now - prev["t"], 1e-6)
                d_rx_p = max(rx_p - prev["rx_p"], 0)
                d_tx_p = max(tx_p - prev["tx_p"], 0)
                d_rx_b = max(rx_b - prev["rx_b"], 0)
                d_tx_b = max(tx_b - prev["tx_b"], 0)
                d_rx_d = max(rx_d - prev["rx_d"], 0)
                d_tx_d = max(tx_d - prev["tx_d"], 0)
                d_rx_e = max(rx_e - prev["rx_e"], 0)
                d_tx_e = max(tx_e - prev["tx_e"], 0)
                has_delta = 1
                rx_bps = (8.0 * d_rx_b) / dt
                tx_bps = (8.0 * d_tx_b) / dt
                pkts = d_rx_p + d_tx_p
                drop_rate = (d_rx_d + d_tx_d) / pkts if pkts else 0.0
            self.prev_port[key] = {
                "t": now, "rx_p": rx_p, "tx_p": tx_p, "rx_b": rx_b, "tx_b": tx_b,
                "rx_d": rx_d, "tx_d": tx_d, "rx_e": rx_e, "tx_e": tx_e,
            }
            rows.append([
                ts, dpid, port_no,
                rx_p, tx_p, rx_b, tx_b, rx_d, tx_d, rx_e, tx_e,
                d_rx_p, d_tx_p, d_rx_b, d_tx_b, d_rx_d, d_tx_d, d_rx_e, d_tx_e,
                round(rx_bps, 4), round(tx_bps, 4), round(drop_rate, 6),
                round(dt, 4), has_delta,
            ])
        if rows:
            with open(PORT_CSV, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerows(rows)

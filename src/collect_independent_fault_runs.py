"""
Thu Fault Dataset trên CÙNG topology 2s6h — không đụng pool anomaly 326k.

Inject tc trên link s1↔s2 (explicit ``tc`` netem/HTB, not Intf.config).
Ground truth (fault_label, configured_*) ghi metadata, không phải feature.

T1: python controller/run_fault_monitor.py
T2: sudo PYTHONPATH=/usr/lib/python3/dist-packages python3 src/collect_independent_fault_runs.py

  --protocol legacy   12 scenario × 3 run (bộ 392 snapshot cũ)
  --protocol d        Protocol D (historical): mild overlapping severities; D2 Acc ~0.38
  --protocol e        Protocol E (headline D2): separable BW/loss/delay + mixed TCP/UDP
                      + probes that actually cross s1↔s2
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fault_link import (  # noqa: E402
    apply_core_fault,
    clear_core_qos,
    core_link,
    core_port_meta,
)
from lab_safety import assert_lab_targets, assert_no_default_route_hint  # noqa: E402
from provenance_schema import (  # noqa: E402
    ALLOWED_LAB_IPV4,
    FAULT_AFFECTED_LINK,
    FAULT_TOPOLOGY_ID,
    SOURCE_FAULT,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE_DIR = os.path.join(BASE_DIR, "dataset", "fault_live")
FLOW_LIVE = os.path.join(LIVE_DIR, "flow_polls.csv")
PORT_LIVE = os.path.join(LIVE_DIR, "port_polls.csv")
RUNS_DIR = os.path.join(BASE_DIR, "dataset", "fault_runs")
MANIFEST = os.path.join(RUNS_DIR, "manifest.csv")
LOG_DIR = os.path.join(RUNS_DIR, "run_logs")

def _hcmd(host, cmd: str) -> str:
    """Mininet Node.cmd is not thread-safe."""
    with _CMD_LOCK:
        return host.cmd(cmd)


_CMD_LOCK = threading.Lock()
LAN = {f"10.0.0.{i}" for i in range(1, 7)}
S1_NET = {f"10.0.0.{i}" for i in range(1, 4)}
S2_NET = {f"10.0.0.{i}" for i in range(4, 7)}

MANIFEST_HEADER = [
    "run_id", "scenario_id", "fault_label", "fault_family", "fault_severity",
    "affected_link", "configured_bw", "configured_loss", "configured_delay",
    "s1_core_port", "s2_core_port", "repeat_idx",
    "start_time", "end_time", "duration_sec",
    "n_flow_rows", "n_port_rows", "n_probe_rows", "notes",
]


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


TRAFFIC_PAIRS = (
    ("h1", "10.0.0.4"),
    ("h2", "10.0.0.5"),
    ("h3", "10.0.0.6"),
)


def _scenarios_legacy(duration_sec: int) -> list[dict[str, Any]]:
    """Original 12 scenarios (392-snapshot collection)."""
    base = dict(duration_sec=duration_sec, affected_link=FAULT_AFFECTED_LINK)
    specs = [
        ("N1", "normal", "normal", "ping_http", None, None, None, "ping_http"),
        ("N2", "normal", "normal", "iperf_tcp", None, None, None, "iperf_tcp"),
        ("N3", "normal", "normal", "mixed", None, None, None, "mixed"),
        ("B1", "bandwidth", "bandwidth", "50Mbit", 50.0, None, None, "mixed"),
        ("B2", "bandwidth", "bandwidth", "20Mbit", 20.0, None, None, "mixed"),
        ("B3", "bandwidth", "bandwidth", "10Mbit", 10.0, None, None, "mixed"),
        ("L1", "loss", "loss", "1pct", None, 1.0, None, "mixed"),
        ("L2", "loss", "loss", "5pct", None, 5.0, None, "mixed"),
        ("L3", "loss", "loss", "10pct", None, 10.0, None, "mixed"),
        ("D1", "delay", "delay", "20ms", None, None, "20ms", "mixed"),
        ("D2", "delay", "delay", "50ms", None, None, "50ms", "mixed"),
        ("D3", "delay", "delay", "100ms", None, None, "100ms", "mixed"),
    ]
    out = []
    for sid, label, family, severity, bw, loss, delay, traffic in specs:
        out.append({
            **base,
            "scenario_id": sid,
            "fault_label": label,
            "fault_family": family,
            "fault_severity": severity,
            "configured_bw": bw,
            "configured_loss": loss,
            "configured_delay": delay,
            "traffic": traffic,
        })
    return out


def _scenarios_protocol_d(duration_sec: int) -> list[dict[str, Any]]:
    """Diversity over severity × workload, same 2s6h topology.

    Goal: model cannot memorize one tc setting as one scenario_id.
    """
    base = dict(duration_sec=duration_sec, affected_link=FAULT_AFFECTED_LINK)
    out: list[dict[str, Any]] = []

    for sid, severity, traffic in (
        ("N_ping", "ping", "ping"),
        ("N_http", "http", "http"),
        ("N_tcp", "iperf_tcp", "iperf_tcp"),
        ("N_udp", "iperf_udp", "iperf_udp"),
        ("N_low", "mixed_low", "mixed_low"),
        ("N_high", "mixed_high", "mixed_high"),
    ):
        out.append({
            **base, "scenario_id": sid, "fault_label": "normal",
            "fault_family": "normal", "fault_severity": severity,
            "configured_bw": None, "configured_loss": None, "configured_delay": None,
            "traffic": traffic,
        })

    for bw in (1.0, 2.0, 5.0, 10.0, 20.0):
        tag = str(int(bw))
        for suffix, traffic in (("t", "iperf_tcp"), ("m", "mixed")):
            out.append({
                **base, "scenario_id": f"B_{tag}M_{suffix}",
                "fault_label": "bandwidth", "fault_family": "bandwidth",
                "fault_severity": f"{tag}Mbit",
                "configured_bw": bw, "configured_loss": None, "configured_delay": None,
                "traffic": traffic,
            })

    for loss in (1.0, 3.0, 5.0, 10.0, 20.0):
        tag = str(int(loss))
        for suffix, traffic in (("t", "iperf_tcp"), ("m", "mixed")):
            out.append({
                **base, "scenario_id": f"L_{tag}pct_{suffix}",
                "fault_label": "loss", "fault_family": "loss",
                "fault_severity": f"{tag}pct",
                "configured_bw": None, "configured_loss": loss, "configured_delay": None,
                "traffic": traffic,
            })

    for delay_ms in (10, 25, 50, 100, 200):
        for suffix, traffic in (("t", "iperf_tcp"), ("m", "mixed")):
            out.append({
                **base, "scenario_id": f"D_{delay_ms}ms_{suffix}",
                "fault_label": "delay", "fault_family": "delay",
                "fault_severity": f"{delay_ms}ms",
                "configured_bw": None, "configured_loss": None,
                "configured_delay": f"{delay_ms}ms",
                "traffic": traffic,
            })
    return out


def _scenarios_protocol_e(duration_sec: int) -> list[dict[str, Any]]:
    """Separable 4-class grid (still 36 scenario_id). Same 2s6h topology.

    Protocol D failed because (1) tc never attached to OVS ports and (2) mild
    1% / 10ms / 20Mbps settings plus same-switch probes look identical.

    Protocol E keeps 4 labels (normal / bandwidth / loss / delay):
      BW   1–5 Mbit/s   — rate ceiling, ping still low-loss / low-RTT
      Loss 5–20 %       — random drops, RTT not inflated to delay-class
      Delay 50–200 ms   — RTT jump, loss stays near 0
    Workloads always include TCP+UDP on the fault pairs (``tu`` / ``mixed``).
    Scenario ids are E_* so merge can keep Protocol D dirs on disk untouched.
    """
    base = dict(duration_sec=duration_sec, affected_link=FAULT_AFFECTED_LINK)
    out: list[dict[str, Any]] = []

    for sid, severity, traffic in (
        ("EN_ping", "ping", "ping"),
        ("EN_http", "http", "http"),
        ("EN_tcp", "iperf_tcp", "iperf_tcp"),
        ("EN_udp", "iperf_udp", "iperf_udp"),
        ("EN_low", "mixed_low", "mixed_low"),
        ("EN_high", "mixed_high", "mixed_high"),
    ):
        out.append({
            **base, "scenario_id": sid, "fault_label": "normal",
            "fault_family": "normal", "fault_severity": severity,
            "configured_bw": None, "configured_loss": None, "configured_delay": None,
            "traffic": traffic,
        })

    for bw in (1.0, 2.0, 3.0, 4.0, 5.0):
        tag = str(int(bw))
        for suffix, traffic in (("tu", "tu"), ("m", "mixed")):
            out.append({
                **base, "scenario_id": f"EB_{tag}M_{suffix}",
                "fault_label": "bandwidth", "fault_family": "bandwidth",
                "fault_severity": f"{tag}Mbit",
                "configured_bw": bw, "configured_loss": None, "configured_delay": None,
                "traffic": traffic,
            })

    for loss in (5.0, 8.0, 12.0, 16.0, 20.0):
        tag = str(int(loss))
        for suffix, traffic in (("tu", "tu"), ("m", "mixed")):
            out.append({
                **base, "scenario_id": f"EL_{tag}pct_{suffix}",
                "fault_label": "loss", "fault_family": "loss",
                "fault_severity": f"{tag}pct",
                "configured_bw": None, "configured_loss": loss, "configured_delay": None,
                "traffic": traffic,
            })

    for delay_ms in (50, 80, 120, 160, 200):
        for suffix, traffic in (("tu", "tu"), ("m", "mixed")):
            out.append({
                **base, "scenario_id": f"ED_{delay_ms}ms_{suffix}",
                "fault_label": "delay", "fault_family": "delay",
                "fault_severity": f"{delay_ms}ms",
                "configured_bw": None, "configured_loss": None,
                "configured_delay": f"{delay_ms}ms",
                "traffic": traffic,
            })
    return out


def _scenarios(duration_sec: int, protocol: str) -> list[dict[str, Any]]:
    if protocol == "legacy":
        return _scenarios_legacy(duration_sec)
    if protocol == "d":
        return _scenarios_protocol_d(duration_sec)
    if protocol == "e":
        return _scenarios_protocol_e(duration_sec)
    raise ValueError(f"unknown protocol {protocol}")


def _window(path: str, start: str, end: str):
    import pandas as pd

    if not os.path.exists(path):
        return pd.DataFrame()
    df = pd.read_csv(path, low_memory=False)
    if df.empty or "timestamp" not in df.columns:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    t0, t1 = pd.to_datetime(start), pd.to_datetime(end)
    return df[(df["timestamp"] >= t0) & (df["timestamp"] <= t1)].copy()


def _parse_ping(text: str) -> dict[str, Optional[float]]:
    loss = None
    rtt = (None, None, None)
    m_loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", text)
    if m_loss:
        loss = float(m_loss.group(1))
    m_rtt = re.search(
        r"rtt min/avg/max(?:/mdev)? = ([\d.]+)/([\d.]+)/([\d.]+)",
        text,
    )
    if m_rtt:
        rtt = (float(m_rtt.group(1)), float(m_rtt.group(2)), float(m_rtt.group(3)))
    return {
        "rtt_min_ms": rtt[0],
        "rtt_mean_ms": rtt[1],
        "rtt_max_ms": rtt[2],
        "probe_loss_pct": loss,
    }


def _parse_iperf_csv(text: str) -> tuple[Optional[float], Optional[float], Optional[float]]:
    """iperf 2 `-y C`: last data row.

    TCP: field 8 = bps. UDP also has jitter (9), lost (10), total (11), %loss (12).
    """
    throughput = None
    jitter = None
    lost_pct = None
    for line in text.strip().splitlines():
        parts = line.split(",")
        if len(parts) < 9:
            continue
        try:
            bps = float(parts[8])
            throughput = bps / 1e6
        except ValueError:
            continue
        if len(parts) >= 11:
            try:
                jitter = float(parts[9])
            except ValueError:
                pass
        if len(parts) >= 13:
            try:
                lost_pct = float(str(parts[12]).replace("%", ""))
            except ValueError:
                lost_pct = None
        if lost_pct is None and len(parts) >= 12:
            try:
                lost, total = float(parts[10]), float(parts[11])
                if total > 0:
                    lost_pct = 100.0 * lost / total
            except ValueError:
                pass
    return throughput, jitter, lost_pct


def _start_servers(hosts: dict) -> None:
    """iperf/HTTP on every host so probes h6→h1 actually cross s1↔s2."""
    for hname in ("h1", "h2", "h3", "h4", "h5", "h6"):
        _hcmd(hosts[hname], "iperf -s -p 5001 >/dev/null 2>&1 &")
        _hcmd(hosts[hname], "iperf -s -u -p 5002 >/dev/null 2>&1 &")
        _hcmd(hosts[hname], "python3 -m http.server 8080 >/dev/null 2>&1 &")
    time.sleep(1)


def _pair(repeat_idx: int) -> tuple[str, str]:
    return TRAFFIC_PAIRS[int(repeat_idx) % len(TRAFFIC_PAIRS)]


def _tcp_port(dst_ip: str) -> int:
    return 5001


def _udp_port(dst_ip: str) -> int:
    return 5002


def _traffic(hosts: dict, kind: str, duration: int, repeat_idx: int = 0) -> None:
    t = max(8, duration - 8)
    src, dst = _pair(repeat_idx)
    assert_lab_targets([dst], context="fault-traffic")
    p_tcp, p_udp = _tcp_port(dst), _udp_port(dst)
    cmds: list[tuple[str, str]] = []

    if kind in ("ping", "ping_http", "mixed", "mixed_low", "mixed_high"):
        cmds.append((src, f"timeout {t} ping -i 0.2 {dst} >/dev/null 2>&1 &"))
    if kind in ("http", "ping_http", "mixed", "mixed_low", "mixed_high"):
        cmds.append((
            src,
            f"timeout {t} bash -c 'while true; do "
            f"wget -q -O /dev/null http://{dst}:8080/ || true; sleep 0.5; done' >/dev/null 2>&1 &",
        ))
    if kind in ("iperf_tcp", "mixed", "mixed_high", "tu"):
        cmds.append((src, f"timeout {t} iperf -c {dst} -p {p_tcp} -t {t} >/dev/null 2>&1 &"))
    if kind == "mixed_low":
        cmds.append((src, f"timeout {t} iperf -c {dst} -p {p_tcp} -t {t} -b 2M >/dev/null 2>&1 &"))
    if kind in ("iperf_udp", "mixed", "mixed_high", "tu"):
        udp_bw = "8M" if kind in ("mixed_high", "tu") else "2M"
        cmds.append((src, f"timeout {t} iperf -u -c {dst} -p {p_udp} -t {t} -b {udp_bw} >/dev/null 2>&1 &"))
    if kind == "iperf_tcp" and src == "h1":
        # second TCP flow on a different pair so bandwidth faults still show under load
        cmds.append(("h2", f"timeout {t} iperf -c 10.0.0.5 -p 5001 -t {t} >/dev/null 2>&1 &"))

    for hname, cmd in cmds:
        assert_no_default_route_hint(cmd)
        _hcmd(hosts[hname], cmd)


def _probe_loop(hosts: dict, samples: list, stop: threading.Event) -> None:
    """Probe h6→h1 so ICMP/iperf CROSS the impaired s1↔s2 link.

    Protocol D probed h6→h4 (both on s2): RTT~0.03ms and ~40Gbps for every class.
    """
    dst = "10.0.0.1"
    assert_lab_targets([dst], context="fault-probe")
    while not stop.is_set():
        ts = _now()
        ping_out = _hcmd(hosts["h6"], f"ping -c 8 -W 2 {dst}")
        parsed = _parse_ping(ping_out)
        iperf_out = _hcmd(hosts["h6"], f"iperf -c {dst} -p 5001 -t 2 -y C 2>/dev/null")
        udp_out = _hcmd(hosts["h6"], f"iperf -u -c {dst} -p 5002 -t 2 -b 2M -y C 2>/dev/null")
        thr, _, _ = _parse_iperf_csv(iperf_out)
        _, jitter, udp_lost = _parse_iperf_csv(udp_out)
        samples.append({
            "timestamp": ts,
            **parsed,
            "throughput_mbps": thr,
            "jitter_ms": jitter,
            "udp_lost_pct": udp_lost,
        })
        stop.wait(5.0)


def _write_run(run_dir: str, start: str, end: str, probes: list, meta: dict) -> tuple[int, int, int]:
    os.makedirs(run_dir, exist_ok=True)
    flows = _window(FLOW_LIVE, start, end)
    ports = _window(PORT_LIVE, start, end)
    if not flows.empty and "ip_src" in flows.columns:
        flows = flows[flows["ip_src"].astype(str).isin(LAN) & flows["ip_dst"].astype(str).isin(LAN)]
    flows_path = os.path.join(run_dir, "flows.csv")
    ports_path = os.path.join(run_dir, "ports.csv")
    probes_path = os.path.join(run_dir, "probes.csv")
    n_f = n_p = 0
    if not flows.empty:
        flows.to_csv(flows_path, index=False)
        n_f = len(flows)
    else:
        open(flows_path, "w", encoding="utf-8").close()
    if not ports.empty:
        ports.to_csv(ports_path, index=False)
        n_p = len(ports)
    else:
        open(ports_path, "w", encoding="utf-8").close()
    import pandas as pd
    pdf = pd.DataFrame(probes)
    if not pdf.empty:
        pdf.to_csv(probes_path, index=False)
    else:
        open(probes_path, "w", encoding="utf-8").close()
    with open(os.path.join(run_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    return n_f, n_p, len(probes)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=3, help="Independent runs per scenario")
    ap.add_argument("--duration", type=int, default=0, help="Seconds per run (0 = protocol default)")
    ap.add_argument("--protocol", choices=("legacy", "d", "e"), default="e")
    ap.add_argument("--only", default="", help="Comma scenario ids, e.g. N1,B1,L2")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    os.makedirs(RUNS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(MANIFEST):
        with open(MANIFEST, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(MANIFEST_HEADER)

    duration = args.duration or (45 if args.protocol == "legacy" else 75 if args.protocol == "e" else 90)
    scs = _scenarios(duration, args.protocol)
    if args.only:
        wanted = {x.strip() for x in args.only.split(",") if x.strip()}
        scs = [s for s in scs if s["scenario_id"] in wanted]
        if not scs:
            raise SystemExit(f"unknown --only {wanted}")

    plan = [(sc, r) for sc in scs for r in range(args.repeat)]
    print("=" * 60)
    print("  Fault collection | same topo 2s6h | inject s1-s2")
    print(f"  protocol={args.protocol} duration={duration}s")
    print(f"  {len(scs)} scenario × {args.repeat} run = {len(plan)} runs")
    print("  Does NOT write dataset/flow_stats.csv")
    print("  Ground truth is metadata, not features")
    print("=" * 60)
    if args.dry_run:
        for sc, r in plan:
            print(f"  {sc['scenario_id']} r{r} label={sc['fault_label']} "
                  f"traffic={sc['traffic']} pair={_pair(r)[0]}->{_pair(r)[1]} "
                  f"bw={sc['configured_bw']} loss={sc['configured_loss']} delay={sc['configured_delay']}")
        return

    if os.geteuid() != 0:
        print("[!] sudo required")
        sys.exit(1)
    for _ in range(30):
        if os.path.exists(FLOW_LIVE):
            break
        time.sleep(1)
    else:
        print("[!] Start T1 first: python controller/run_fault_monitor.py")
        print(f"    waiting for {FLOW_LIVE}")
        sys.exit(1)

    from mininet.link import TCLink
    from mininet.log import setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController

    sys.path.insert(0, BASE_DIR)
    from topology.custom_topo import SDNAnomalyTopo

    setLogLevel("info")
    net = Mininet(
        topo=SDNAnomalyTopo(),
        controller=None,
        switch=OVSKernelSwitch,
        link=TCLink,
    )
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    net.start()
    time.sleep(5)
    try:
        net.pingAll()
    except Exception as exc:
        print(f"[!] pingAll: {exc}")
    link = core_link(net)
    ports = core_port_meta(link)
    hosts = {f"h{i}": net.get(f"h{i}") for i in range(1, 7)}
    _start_servers(hosts)

    try:
        for sc, repeat_idx in plan:
            qdisc = apply_core_fault(
                link,
                bw_mbit=sc["configured_bw"],
                delay=sc["configured_delay"],
                loss_pct=sc["configured_loss"],
            )
            print(f"    qdisc {qdisc}")
            time.sleep(2)
            run_id = f"fault_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
            start = _now()
            print(f"\n[*] {sc['scenario_id']} r{repeat_idx} | {run_id} | {sc['fault_label']}")
            probes: list[dict] = []
            stop = threading.Event()
            _traffic(hosts, sc["traffic"], sc["duration_sec"], repeat_idx)
            th = threading.Thread(target=_probe_loop, args=(hosts, probes, stop), daemon=True)
            th.start()
            time.sleep(int(sc["duration_sec"]))
            stop.set()
            th.join(timeout=12)
            for h in hosts.values():
                try:
                    _hcmd(h, "killall ping iperf wget 2>/dev/null")
                except Exception:
                    pass
            time.sleep(8)
            end = _now()
            clear_core_qos(link)
            src_h, dst_ip = _pair(repeat_idx)
            meta = {
                "run_id": run_id,
                "scenario_id": sc["scenario_id"],
                "fault_label": sc["fault_label"],
                "fault_family": sc["fault_family"],
                "fault_severity": sc["fault_severity"],
                "affected_link": sc["affected_link"],
                "configured_bw": sc["configured_bw"],
                "configured_loss": sc["configured_loss"],
                "configured_delay": sc["configured_delay"],
                "source": SOURCE_FAULT,
                "topology_id": FAULT_TOPOLOGY_ID,
                "protocol": args.protocol,
                "start_time": start,
                "end_time": end,
                "duration_sec": sc["duration_sec"],
                "repeat_idx": repeat_idx,
                "traffic": sc["traffic"],
                "traffic_pair": f"{src_h}->{dst_ip}",
                **ports,
                "qdisc": qdisc,
                "notes": "gt metadata; do not use configured_* or ids as features",
            }
            run_dir = os.path.join(RUNS_DIR, run_id)
            n_f, n_p, n_pr = _write_run(run_dir, start, end, probes, meta)
            with open(os.path.join(LOG_DIR, f"{run_id}.json"), "w", encoding="utf-8") as f:
                json.dump({**meta, "n_flow_rows": n_f, "n_port_rows": n_p, "n_probe_rows": n_pr}, f, indent=2)
            with open(MANIFEST, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    run_id, sc["scenario_id"], sc["fault_label"], sc["fault_family"],
                    sc["fault_severity"], sc["affected_link"],
                    sc["configured_bw"] if sc["configured_bw"] is not None else "",
                    sc["configured_loss"] if sc["configured_loss"] is not None else "",
                    sc["configured_delay"] or "",
                    ports.get("s1_core_port", ""), ports.get("s2_core_port", ""),
                    repeat_idx, start, end, sc["duration_sec"],
                    n_f, n_p, n_pr,
                    "independent_fault_run; same topo as anomaly set",
                ])
            print(f"[✓] flows={n_f} ports={n_p} probes={n_pr}")
            time.sleep(4)
            _start_servers(hosts)
    finally:
        try:
            clear_core_qos(link)
        except Exception:
            pass
        try:
            net.stop()
        except Exception as exc:
            print(f"[!] net.stop: {exc}")
            os.system("mn -c >/dev/null 2>&1")
    print("[✓] Fault collection finished — merge: python src/merge_fault_runs.py")


if __name__ == "__main__":
    main()

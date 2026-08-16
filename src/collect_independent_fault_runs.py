"""
Thu Fault Dataset trên CÙNG topology 2s6h — không đụng pool anomaly 79.114.

Inject tc trên link s1↔s2. Ground truth (fault_label, configured_*) ghi metadata,
không phải feature.

T1: python controller/run_fault_monitor.py
T2: sudo PYTHONPATH=/usr/lib/python3/dist-packages python3 src/collect_independent_fault_runs.py

Mặc định: 12 scenario × 3 run = 36 run. Không ghi dataset/flow_stats.csv.
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
from fault_link import apply_core_fault, clear_core_qos, core_link, core_port_meta  # noqa: E402
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


def _scenarios(duration_sec: int) -> list[dict[str, Any]]:
    """12 scenarios. configured_* are ground truth, never model features."""
    base = dict(duration_sec=duration_sec, affected_link=FAULT_AFFECTED_LINK)
    specs = [
        ("N1", "normal", "normal", "ping_http", None, None, None),
        ("N2", "normal", "normal", "iperf_tcp", None, None, None),
        ("N3", "normal", "normal", "mixed", None, None, None),
        ("B1", "bandwidth", "bandwidth", "50Mbit", 50.0, None, None),
        ("B2", "bandwidth", "bandwidth", "20Mbit", 20.0, None, None),
        ("B3", "bandwidth", "bandwidth", "10Mbit", 10.0, None, None),
        ("L1", "loss", "loss", "1pct", None, 1.0, None),
        ("L2", "loss", "loss", "5pct", None, 5.0, None),
        ("L3", "loss", "loss", "10pct", None, 10.0, None),
        ("D1", "delay", "delay", "20ms", None, None, "20ms"),
        ("D2", "delay", "delay", "50ms", None, None, "50ms"),
        ("D3", "delay", "delay", "100ms", None, None, "100ms"),
    ]
    out = []
    for sid, label, family, severity, bw, loss, delay in specs:
        traffic = "mixed"
        if sid == "N1":
            traffic = "ping_http"
        elif sid == "N2":
            traffic = "iperf_tcp"
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


def _parse_iperf_csv(text: str) -> tuple[Optional[float], Optional[float]]:
    """iperf 2 `-y C`: last data row, bps in field 9 (0-based 8). UDP jitter field 10."""
    throughput = None
    jitter = None
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
    return throughput, jitter


def _start_servers(hosts: dict) -> None:
    hosts["h4"].cmd("iperf -s >/dev/null 2>&1 &")
    hosts["h4"].cmd("iperf -s -u -p 5002 >/dev/null 2>&1 &")
    hosts["h4"].cmd("python3 -m http.server 8080 >/dev/null 2>&1 &")
    hosts["h5"].cmd("iperf -s -p 5003 >/dev/null 2>&1 &")
    time.sleep(1)


def _traffic(hosts: dict, kind: str, duration: int) -> None:
    t = max(5, duration - 5)
    assert_lab_targets(["10.0.0.4", "10.0.0.5"], context="fault-traffic")
    cmds = []
    if kind in ("ping_http", "mixed"):
        cmds += [
            ("h1", f"timeout {t} ping -i 0.2 10.0.0.4 >/dev/null 2>&1 &"),
            ("h2", f"timeout {t} ping -i 0.3 10.0.0.5 >/dev/null 2>&1 &"),
            ("h3", (
                f"timeout {t} bash -c 'while true; do "
                "wget -q -O /dev/null http://10.0.0.4:8080/ || true; sleep 0.5; done' >/dev/null 2>&1 &"
            )),
        ]
    if kind in ("iperf_tcp", "mixed"):
        cmds += [
            ("h1", f"timeout {t} iperf -c 10.0.0.4 -t {t} >/dev/null 2>&1 &"),
            ("h2", f"timeout {t} iperf -c 10.0.0.5 -p 5003 -t {t} >/dev/null 2>&1 &"),
        ]
    if kind == "mixed":
        cmds.append(
            ("h3", f"timeout {t} iperf -u -c 10.0.0.4 -p 5002 -t {t} -b 2M >/dev/null 2>&1 &"),
        )
    for hname, cmd in cmds:
        assert_no_default_route_hint(cmd)
        hosts[hname].cmd(cmd)


def _probe_loop(hosts: dict, samples: list, stop: threading.Event) -> None:
    while not stop.is_set():
        ts = _now()
        ping_out = hosts["h1"].cmd("ping -c 4 -W 1 10.0.0.4")
        parsed = _parse_ping(ping_out)
        iperf_out = hosts["h6"].cmd("iperf -c 10.0.0.4 -t 2 -y C 2>/dev/null")
        udp_out = hosts["h6"].cmd("iperf -u -c 10.0.0.4 -p 5002 -t 2 -b 1M -y C 2>/dev/null")
        thr, _ = _parse_iperf_csv(iperf_out)
        _, jitter = _parse_iperf_csv(udp_out)
        samples.append({
            "timestamp": ts,
            **parsed,
            "throughput_mbps": thr,
            "jitter_ms": jitter,
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
    ap.add_argument("--duration", type=int, default=45)
    ap.add_argument("--only", default="", help="Comma scenario ids, e.g. N1,B1,L2")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    os.makedirs(RUNS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(MANIFEST):
        with open(MANIFEST, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(MANIFEST_HEADER)

    scs = _scenarios(args.duration)
    if args.only:
        wanted = {x.strip() for x in args.only.split(",") if x.strip()}
        scs = [s for s in scs if s["scenario_id"] in wanted]
        if not scs:
            raise SystemExit(f"unknown --only {wanted}")

    plan = [(sc, r) for sc in scs for r in range(args.repeat)]
    print("=" * 60)
    print("  Fault collection | same topo 2s6h | inject s1-s2")
    print(f"  {len(scs)} scenario × {args.repeat} run = {len(plan)} runs")
    print("  Does NOT write dataset/flow_stats.csv")
    print("  Ground truth is metadata, not features")
    print("=" * 60)
    if args.dry_run:
        for sc, r in plan:
            print(f"  {sc['scenario_id']} r{r} label={sc['fault_label']} "
                  f"bw={sc['configured_bw']} loss={sc['configured_loss']} delay={sc['configured_delay']}")
        return

    if os.geteuid() != 0:
        print("[!] sudo required")
        sys.exit(1)
    if not os.path.exists(FLOW_LIVE):
        print("[!] Start T1 first: python controller/run_fault_monitor.py")
        sys.exit(1)

    from mininet.log import setLogLevel
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController

    sys.path.insert(0, BASE_DIR)
    from topology.custom_topo import SDNAnomalyTopo

    setLogLevel("info")
    net = Mininet(topo=SDNAnomalyTopo(), controller=None, switch=OVSKernelSwitch)
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
            apply_core_fault(
                link,
                bw_mbit=sc["configured_bw"],
                delay=sc["configured_delay"],
                loss_pct=sc["configured_loss"],
            )
            time.sleep(2)
            run_id = f"fault_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
            start = _now()
            print(f"\n[*] {sc['scenario_id']} r{repeat_idx} | {run_id} | {sc['fault_label']}")
            probes: list[dict] = []
            stop = threading.Event()
            th = threading.Thread(target=_probe_loop, args=(hosts, probes, stop), daemon=True)
            th.start()
            _traffic(hosts, sc["traffic"], sc["duration_sec"])
            time.sleep(int(sc["duration_sec"]))
            stop.set()
            th.join(timeout=8)
            for h in hosts.values():
                h.cmd("killall ping iperf wget 2>/dev/null")
            time.sleep(8)
            end = _now()
            clear_core_qos(link)
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
                "start_time": start,
                "end_time": end,
                "duration_sec": sc["duration_sec"],
                "repeat_idx": repeat_idx,
                "traffic": sc["traffic"],
                **ports,
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
        net.stop()
    print("[✓] Fault collection finished — merge: python src/merge_fault_runs.py")


if __name__ == "__main__":
    main()

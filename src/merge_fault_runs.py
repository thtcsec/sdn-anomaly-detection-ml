"""
Gộp fault_runs thành snapshot theo poll 5s.

Output (chọn protocol, không trộn D với E trong bảng headline):
  python src/merge_fault_runs.py --protocol d --out dataset/fault_stats_grouped.csv
  python src/merge_fault_runs.py --protocol e --out dataset/fault_stats_grouped_e.csv

Cột ground-truth / identity KHÔNG dùng train:
  run_id, scenario_id, fault_label, fault_family, fault_severity,
  affected_link, configured_bw, configured_loss, configured_delay, protocol

Không ghi đè flow_stats_grouped.csv (anomaly).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import FAULT_MODEL_FEATURES  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS_DIR = os.path.join(BASE_DIR, "dataset", "fault_runs")
OUT_DEFAULT = os.path.join(BASE_DIR, "dataset", "fault_stats_grouped.csv")
S1 = {f"10.0.0.{i}" for i in range(1, 4)}
S2 = {f"10.0.0.{i}" for i in range(4, 7)}
IP_TCP, IP_UDP = 6, 17


def _cross(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or "ip_src" not in df.columns:
        return df
    src, dst = df["ip_src"].astype(str), df["ip_dst"].astype(str)
    mask = ((src.isin(S1) & dst.isin(S2)) | (src.isin(S2) & dst.isin(S1)))
    return df.loc[mask].copy()


def _nearest(left: pd.DataFrame, right: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    if left.empty:
        return left
    if right.empty:
        for c in cols:
            if c not in left.columns:
                left[c] = pd.NA
        return left
    l = left.sort_values("timestamp")
    r = right.sort_values("timestamp")
    return pd.merge_asof(l, r, on="timestamp", direction="nearest", tolerance=pd.Timedelta("4s"))


def _core_ports(ports: pd.DataFrame, meta: dict) -> pd.DataFrame:
    if ports.empty:
        return ports
    s1p = meta.get("s1_core_port")
    s2p = meta.get("s2_core_port")
    if s1p is None or s2p is None:
        return ports
    return ports[ports["port_no"].astype(int).isin({int(s1p), int(s2p)})].copy()


def _proto_rates(flows: pd.DataFrame, proto: int, prefix: str) -> pd.DataFrame:
    if flows.empty or "ip_proto" not in flows.columns:
        return pd.DataFrame(columns=["timestamp"])
    sub = flows[pd.to_numeric(flows["ip_proto"], errors="coerce").fillna(0).astype(int) == proto]
    if sub.empty:
        return pd.DataFrame(columns=["timestamp"])
    return sub.groupby("timestamp", as_index=False).agg(
        **{
            f"{prefix}_delta_packet_sum": ("delta_packet", "sum"),
            f"{prefix}_byte_rate_window_sum": ("byte_rate_window", "sum"),
            f"n_{prefix}_flows": ("ip_src", "count"),
        }
    )


def merge_one(run_dir: str) -> pd.DataFrame:
    meta_path = os.path.join(run_dir, "meta.json")
    if not os.path.isfile(meta_path):
        return pd.DataFrame()
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    flows_path = os.path.join(run_dir, "flows.csv")
    ports_path = os.path.join(run_dir, "ports.csv")
    probes_path = os.path.join(run_dir, "probes.csv")
    flows = pd.read_csv(flows_path) if os.path.isfile(flows_path) and os.path.getsize(flows_path) else pd.DataFrame()
    ports = pd.read_csv(ports_path) if os.path.isfile(ports_path) and os.path.getsize(ports_path) else pd.DataFrame()
    probes = pd.read_csv(probes_path) if os.path.isfile(probes_path) and os.path.getsize(probes_path) else pd.DataFrame()

    for df in (flows, ports, probes):
        if not df.empty and "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if not probes.empty:
        probes = probes.dropna(subset=["timestamp"]).sort_values("timestamp")
        probes = probes.drop_duplicates("timestamp", keep="last")

    if not flows.empty and "has_delta" in flows.columns:
        flows = flows[flows["has_delta"].fillna(0).astype(int) == 1]
    flows = _cross(flows)
    if flows.empty:
        base = probes.copy() if not probes.empty else pd.DataFrame()
        if base.empty:
            return pd.DataFrame()
        agg = base.copy()
        for c in (
            "packet_count_sum", "byte_count_sum", "delta_packet_sum", "delta_byte_sum",
            "packet_rate_window_sum", "byte_rate_window_sum", "packet_size_avg_mean",
            "duration_sec_mean", "n_flows", "n_tcp_flows", "n_udp_flows",
            "tcp_delta_packet_sum", "udp_delta_packet_sum",
            "tcp_byte_rate_window_sum", "udp_byte_rate_window_sum", "tcp_share",
        ):
            agg[c] = 0
    else:
        g = flows.groupby("timestamp", as_index=False).agg(
            packet_count_sum=("packet_count", "sum"),
            byte_count_sum=("byte_count", "sum"),
            delta_packet_sum=("delta_packet", "sum"),
            delta_byte_sum=("delta_byte", "sum"),
            packet_rate_window_sum=("packet_rate_window", "sum"),
            byte_rate_window_sum=("byte_rate_window", "sum"),
            packet_size_avg_mean=("packet_size_avg", "mean"),
            duration_sec_mean=("duration_sec", "mean") if "duration_sec" in flows.columns else ("packet_count", "count"),
            n_flows=("ip_src", "count"),
        )
        if "duration_sec" not in flows.columns:
            g["duration_sec_mean"] = 0
        tcp = _proto_rates(flows, IP_TCP, "tcp")
        udp = _proto_rates(flows, IP_UDP, "udp")
        agg = g
        if not tcp.empty:
            agg = _nearest(agg, tcp, list(tcp.columns))
        if not udp.empty:
            agg = _nearest(agg, udp, list(udp.columns))
        for c in (
            "tcp_delta_packet_sum", "udp_delta_packet_sum",
            "tcp_byte_rate_window_sum", "udp_byte_rate_window_sum",
            "n_tcp_flows", "n_udp_flows",
        ):
            if c not in agg.columns:
                agg[c] = 0
            else:
                agg[c] = pd.to_numeric(agg[c], errors="coerce").fillna(0)
        tot = agg["tcp_delta_packet_sum"] + agg["udp_delta_packet_sum"]
        agg["tcp_share"] = (agg["tcp_delta_packet_sum"] / tot.replace(0, pd.NA)).fillna(0.0)

    core = _core_ports(ports, meta)
    if not core.empty and "has_delta" in core.columns:
        core = core[core["has_delta"].fillna(0).astype(int) == 1]
    port_cols = [
        "rx_bps_core", "tx_bps_core", "core_bps",
        "delta_rx_dropped_core", "delta_tx_dropped_core",
        "drop_rate_core", "delta_rx_errors_core", "delta_tx_errors_core",
    ]
    if not core.empty:
        port_g = core.groupby("timestamp", as_index=False).agg(
            rx_bps_core=("rx_bps", "sum"),
            tx_bps_core=("tx_bps", "sum"),
            delta_rx_dropped_core=("delta_rx_dropped", "sum"),
            delta_tx_dropped_core=("delta_tx_dropped", "sum"),
            drop_rate_core=("drop_rate", "mean"),
            delta_rx_errors_core=("delta_rx_errors", "sum"),
            delta_tx_errors_core=("delta_tx_errors", "sum"),
        )
        port_g["core_bps"] = (
            pd.to_numeric(port_g["rx_bps_core"], errors="coerce").fillna(0)
            + pd.to_numeric(port_g["tx_bps_core"], errors="coerce").fillna(0)
        )
        agg = _nearest(agg, port_g, list(port_g.columns))
    else:
        for c in port_cols:
            agg[c] = pd.NA

    probe_cols = [
        "rtt_mean_ms", "rtt_min_ms", "rtt_max_ms", "probe_loss_pct",
        "throughput_mbps", "jitter_ms", "udp_lost_pct",
    ]
    if not probes.empty:
        keep = ["timestamp"] + [c for c in probe_cols if c in probes.columns]
        agg = _nearest(agg, probes[keep], probe_cols)
    else:
        for c in probe_cols:
            if c not in agg.columns:
                agg[c] = pd.NA
    if "udp_lost_pct" not in agg.columns:
        agg["udp_lost_pct"] = pd.NA

    agg["run_id"] = meta["run_id"]
    agg["scenario_id"] = meta["scenario_id"]
    agg["fault_label"] = meta["fault_label"]
    agg["fault_family"] = meta["fault_family"]
    agg["fault_severity"] = meta["fault_severity"]
    agg["affected_link"] = meta.get("affected_link", "s1-s2")
    agg["configured_bw"] = meta.get("configured_bw")
    agg["configured_loss"] = meta.get("configured_loss")
    agg["configured_delay"] = meta.get("configured_delay")
    agg["traffic"] = meta.get("traffic", "")
    agg["traffic_pair"] = meta.get("traffic_pair", "")
    agg["protocol"] = meta.get("protocol", "")
    agg["source"] = meta.get("source", "mininet_lab_fault_run")
    agg["is_synthetic"] = 0
    return agg


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--protocol",
        default="",
        help="Only merge runs whose meta.protocol matches (d or e). Empty = all.",
    )
    ap.add_argument("--out", default="", help="Output CSV (default depends on --protocol)")
    args = ap.parse_args()
    protocol = (args.protocol or "").strip().lower()
    if args.out:
        out_path = args.out
    elif protocol == "e":
        out_path = os.path.join(BASE_DIR, "dataset", "fault_stats_grouped_e.csv")
    else:
        out_path = OUT_DEFAULT

    if not os.path.isdir(RUNS_DIR):
        print(f"[!] missing {RUNS_DIR}")
        sys.exit(1)
    frames = []
    skipped = 0
    for name in sorted(os.listdir(RUNS_DIR)):
        path = os.path.join(RUNS_DIR, name)
        if not os.path.isdir(path) or not name.startswith("fault_"):
            continue
        meta_path = os.path.join(path, "meta.json")
        if protocol and os.path.isfile(meta_path):
            with open(meta_path, encoding="utf-8") as f:
                meta = json.load(f)
            if str(meta.get("protocol", "")).lower() != protocol:
                skipped += 1
                continue
        part = merge_one(path)
        if not part.empty:
            frames.append(part)
            print(f"  {name}: {len(part)} polls")
    if not frames:
        print("[!] no fault runs to merge")
        sys.exit(1)
    out = pd.concat(frames, ignore_index=True)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    out.to_csv(out_path, index=False)
    print(
        f"[✓] {out_path} rows={len(out)} runs={out['run_id'].nunique()} "
        f"scenarios={out['scenario_id'].nunique()} skipped_other_protocol={skipped}"
    )
    missing = [c for c in FAULT_MODEL_FEATURES if c not in out.columns]
    if missing:
        print(f"[!] missing model columns: {missing}")


if __name__ == "__main__":
    main()

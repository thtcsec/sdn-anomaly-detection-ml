"""
Gộp fault_runs thành snapshot theo poll 5s.

Output:
  dataset/fault_stats_grouped.csv

Cột ground-truth / identity KHÔNG dùng train:
  run_id, scenario_id, fault_label, fault_family, fault_severity,
  affected_link, configured_bw, configured_loss, configured_delay

Không ghi đè flow_stats_grouped.csv (anomaly).
"""

from __future__ import annotations

import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provenance_schema import FAULT_MODEL_FEATURES  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS_DIR = os.path.join(BASE_DIR, "dataset", "fault_runs")
OUT = os.path.join(BASE_DIR, "dataset", "fault_stats_grouped.csv")
S1 = {f"10.0.0.{i}" for i in range(1, 4)}
S2 = {f"10.0.0.{i}" for i in range(4, 7)}


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
    # Keep rows whose port_no matches either core port (both switches).
    return ports[ports["port_no"].astype(int).isin({int(s1p), int(s2p)})].copy()


def merge_one(run_dir: str) -> pd.DataFrame:
    meta_path = os.path.join(run_dir, "meta.json")
    if not os.path.isfile(meta_path):
        return pd.DataFrame()
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    flows = pd.read_csv(os.path.join(run_dir, "flows.csv")) if os.path.getsize(os.path.join(run_dir, "flows.csv")) else pd.DataFrame()
    ports = pd.read_csv(os.path.join(run_dir, "ports.csv")) if os.path.getsize(os.path.join(run_dir, "ports.csv")) else pd.DataFrame()
    probes_path = os.path.join(run_dir, "probes.csv")
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
        # still emit probe/port-only snapshots if we have probes
        base = probes.copy() if not probes.empty else pd.DataFrame()
        if base.empty:
            return pd.DataFrame()
        agg = base.copy()
        agg["packet_count_sum"] = 0
        agg["byte_count_sum"] = 0
        agg["delta_packet_sum"] = 0
        agg["delta_byte_sum"] = 0
        agg["packet_rate_window_sum"] = 0
        agg["byte_rate_window_sum"] = 0
        agg["packet_size_avg_mean"] = 0
        agg["n_flows"] = 0
    else:
        g = flows.groupby("timestamp", as_index=False).agg(
            packet_count_sum=("packet_count", "sum"),
            byte_count_sum=("byte_count", "sum"),
            delta_packet_sum=("delta_packet", "sum"),
            delta_byte_sum=("delta_byte", "sum"),
            packet_rate_window_sum=("packet_rate_window", "sum"),
            byte_rate_window_sum=("byte_rate_window", "sum"),
            packet_size_avg_mean=("packet_size_avg", "mean"),
            n_flows=("ip_src", "count"),
        )
        agg = g

    core = _core_ports(ports, meta)
    if not core.empty and "has_delta" in core.columns:
        core = core[core["has_delta"].fillna(0).astype(int) == 1]
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
        agg = _nearest(agg, port_g, list(port_g.columns))
    else:
        for c in [
            "rx_bps_core", "tx_bps_core", "delta_rx_dropped_core", "delta_tx_dropped_core",
            "drop_rate_core", "delta_rx_errors_core", "delta_tx_errors_core",
        ]:
            agg[c] = pd.NA

    probe_cols = ["rtt_mean_ms", "rtt_min_ms", "rtt_max_ms", "probe_loss_pct", "throughput_mbps", "jitter_ms"]
    if not probes.empty:
        keep = ["timestamp"] + [c for c in probe_cols if c in probes.columns]
        agg = _nearest(agg, probes[keep], probe_cols)
    else:
        for c in probe_cols:
            if c not in agg.columns:
                agg[c] = pd.NA

    agg["run_id"] = meta["run_id"]
    agg["scenario_id"] = meta["scenario_id"]
    agg["fault_label"] = meta["fault_label"]
    agg["fault_family"] = meta["fault_family"]
    agg["fault_severity"] = meta["fault_severity"]
    agg["affected_link"] = meta.get("affected_link", "s1-s2")
    agg["configured_bw"] = meta.get("configured_bw")
    agg["configured_loss"] = meta.get("configured_loss")
    agg["configured_delay"] = meta.get("configured_delay")
    agg["source"] = meta.get("source", "mininet_lab_fault_run")
    agg["is_synthetic"] = 0
    return agg


def main() -> None:
    if not os.path.isdir(RUNS_DIR):
        print(f"[!] missing {RUNS_DIR}")
        sys.exit(1)
    frames = []
    for name in sorted(os.listdir(RUNS_DIR)):
        path = os.path.join(RUNS_DIR, name)
        if not os.path.isdir(path) or not name.startswith("fault_"):
            continue
        part = merge_one(path)
        if not part.empty:
            frames.append(part)
            print(f"  {name}: {len(part)} polls")
    if not frames:
        print("[!] no fault runs to merge")
        sys.exit(1)
    out = pd.concat(frames, ignore_index=True)
    out.to_csv(OUT, index=False)
    print(f"[✓] {OUT} rows={len(out)} runs={out['run_id'].nunique()} scenarios={out['scenario_id'].nunique()}")
    missing = [c for c in FAULT_MODEL_FEATURES if c not in out.columns]
    if missing:
        print(f"[!] missing model columns: {missing}")


if __name__ == "__main__":
    main()

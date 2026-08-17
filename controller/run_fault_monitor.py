"""Launcher: fault telemetry controller (FlowStats + PortStats).

Does not load XGBoost. Does not write dataset/flow_stats.csv.

Chạy: python controller/run_fault_monitor.py
"""

import logging
import os
import sys

os.environ.setdefault("OSKEN_HUB_TYPE", "eventlet")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from os_ken.base.app_manager import AppManager
from controller.openflow_bind import terminate_stale_controllers


def main():
    terminate_stale_controllers(6633)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    print("=" * 60)
    print("  Fault monitor (os-ken) — PortStats + FlowStats delta")
    print("  OpenFlow tcp:6633")
    print("  CSV: dataset/fault_live/  (NOT flow_stats.csv)")
    print("  T2: sudo python3 src/collect_independent_fault_runs.py")
    print("=" * 60)
    sys.stdout.flush()
    AppManager.run_apps(["controller.fault_monitor"])


if __name__ == "__main__":
    main()

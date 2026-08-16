"""
Launcher cho Real-time Anomaly Detection Controller.
Chạy: python controller/run_realtime.py

os-ken mặc định khá im lặng khi chờ switch connect — không phải bị treo.
"""

import logging
import sys
import os

# os-ken 4.2 default hub=native: AppManager.run_apps() gọi t.kill() rồi chết.
os.environ.setdefault("OSKEN_HUB_TYPE", "eventlet")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from os_ken.base.app_manager import AppManager


def main():
    # Bật log INFO để thấy "Loaded model" / "Switch connected"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    )
    logging.getLogger('os_ken').setLevel(logging.INFO)
    logging.getLogger('controller').setLevel(logging.INFO)

    print("=" * 60)
    print("  Realtime SDN Detector (os-ken)")
    print("  Listening OpenFlow on tcp:6633")
    print("  App: controller.realtime_detector")
    print("  Đang chờ Mininet connect... (không phải bị treo)")
    print("  Terminal 2: sudo python3 topology/custom_topo.py")
    print("=" * 60)
    sys.stdout.flush()

    AppManager.run_apps(['controller.realtime_detector'])


if __name__ == '__main__':
    main()

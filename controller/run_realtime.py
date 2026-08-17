"""
Launcher cho Real-time Anomaly Detection Controller.
Chạy: python controller/run_realtime.py

os-ken mặc định khá im lặng khi chờ switch connect — không phải bị treo.
"""

import atexit
import logging
import sys
import os

# os-ken 4.2 default hub=native: AppManager.run_apps() gọi t.kill() rồi chết.
os.environ.setdefault("OSKEN_HUB_TYPE", "eventlet")
# Quiet TensorFlow until Autoencoder actually loads. Demo has no GPU.
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
os.environ.setdefault("TF_USE_LEGACY_KERAS", "1")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from os_ken.base.app_manager import AppManager
from controller.openflow_bind import (
    clear_pid_file,
    terminate_stale_controllers,
    write_pid_file,
)


def main():
    terminate_stale_controllers(6633)
    write_pid_file()
    atexit.register(clear_pid_file)
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

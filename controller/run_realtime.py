"""
Launcher cho Real-time Anomaly Detection Controller.
Chạy: python controller/run_realtime.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from os_ken.base.app_manager import AppManager


def main():
    AppManager.run_apps(['controller.realtime_detector'])


if __name__ == '__main__':
    main()

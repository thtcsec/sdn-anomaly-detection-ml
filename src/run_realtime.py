"""
Launcher cho Real-time Anomaly Detection Controller trong thư mục src.
Chạy: python src/run_realtime.py
"""

import sys
import os

# Thêm project root vào sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from os_ken.base.app_manager import AppManager


def main():
    # Load realtime_detector app từ thư mục src
    AppManager.run_apps(['src.realtime_detector'])


if __name__ == '__main__':
    main()

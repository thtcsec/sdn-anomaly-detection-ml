"""
Launcher script cho os-ken controller.
Thay thế lệnh 'osken-manager' (không có trong os-ken 4.x).

Chạy: python controller/run_controller.py
"""

import sys
import os

# Thêm project root vào path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from os_ken.base.app_manager import AppManager


def main():
    # Load monitor app
    app_lists = ['controller.monitor']
    AppManager.run_apps(app_lists)


if __name__ == '__main__':
    main()

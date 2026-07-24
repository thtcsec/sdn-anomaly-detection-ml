"""
DEPRECATED launcher — chuyển sang controller/run_realtime.py.

Bản src/realtime_detector.py cũ không có auto-block / alerts.json.
Chạy nhầm sẽ làm demo bảo vệ fail.
"""

import os
import runpy
import sys
import warnings

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANONICAL = os.path.join(BASE_DIR, 'controller', 'run_realtime.py')


def main():
    warnings.warn(
        'src/run_realtime.py đã deprecated. Đang chuyển sang controller/run_realtime.py',
        DeprecationWarning,
        stacklevel=2,
    )
    print('[!] DEPRECATED: dùng python controller/run_realtime.py')
    print('[*] Redirecting to controller/run_realtime.py ...')
    if not os.path.exists(CANONICAL):
        print(f'[!] Missing {CANONICAL}')
        sys.exit(1)
    # Đảm bảo import controller.* hoạt động
    if BASE_DIR not in sys.path:
        sys.path.insert(0, BASE_DIR)
    runpy.run_path(CANONICAL, run_name='__main__')


if __name__ == '__main__':
    main()

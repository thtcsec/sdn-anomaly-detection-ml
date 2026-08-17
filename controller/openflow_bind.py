"""Single OpenFlow listener on tcp/6633 + PID file for the dashboard."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PID_FILE = BASE_DIR / "dataset" / "controller.pid"

_OURS = ("run_realtime.py", "run_fault_monitor.py", "fault_monitor")


def _cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\0", b" ").decode("utf-8", "replace")


def _pids_listening(port: int) -> list[int]:
    try:
        out = subprocess.check_output(
            ["ss", "-lntp"], text=True, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.SubprocessError):
        return []
    found: list[int] = []
    needle = f":{port}"
    for line in out.splitlines():
        if needle not in line or "LISTEN" not in line:
            continue
        marker = "pid="
        start = 0
        while True:
            i = line.find(marker, start)
            if i < 0:
                break
            j = i + len(marker)
            k = j
            while k < len(line) and line[k].isdigit():
                k += 1
            if k > j:
                found.append(int(line[j:k]))
            start = k
    return sorted(set(found))


def _port_has_listener(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.4)
    try:
        sock.connect(("127.0.0.1", port))
        return True
    except (ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()


def terminate_stale_controllers(port: int = 6633, self_pid: int | None = None) -> None:
    """Kill leftover realtime/fault controllers holding 6633 (not this process)."""
    self_pid = os.getpid() if self_pid is None else self_pid
    victims: list[int] = []
    for pid in _pids_listening(port):
        if pid == self_pid:
            continue
        cmd = _cmdline(pid)
        if any(token in cmd for token in _OURS):
            victims.append(pid)
    if not victims and _port_has_listener(port):
        print(
            f"[!] Cổng tcp:{port} đang LISTEN bởi process không phải "
            "run_realtime/run_fault_monitor. Không kill. Dừng process đó rồi chạy lại.",
            file=sys.stderr,
        )
        sys.exit(1)
    for pid in victims:
        print(f"[*] Dừng controller cũ pid={pid} ({_cmdline(pid)[:80]})", flush=True)
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            continue
    deadline = time.time() + 4
    while time.time() < deadline:
        alive = [p for p in victims if Path(f"/proc/{p}").exists()]
        if not alive:
            break
        time.sleep(0.2)
    for pid in victims:
        if Path(f"/proc/{pid}").exists():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    time.sleep(0.3)
    if _port_has_listener(port):
        still = _pids_listening(port)
        print(
            f"[!] Cổng tcp:{port} vẫn bận sau khi reclaim (pids={still}).",
            file=sys.stderr,
        )
        sys.exit(1)


def write_pid_file() -> None:
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")


def clear_pid_file() -> None:
    try:
        if PID_FILE.exists() and PID_FILE.read_text(encoding="utf-8").strip() == str(os.getpid()):
            PID_FILE.unlink()
    except OSError:
        pass


def pid_file_alive() -> bool:
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    if not Path(f"/proc/{pid}").exists():
        return False
    return any(token in _cmdline(pid) for token in _OURS)


def any_realtime_controller_running() -> bool:
    """True if a run_realtime.py process exists (WSL /proc)."""
    proc = Path("/proc")
    if not proc.is_dir():
        return pid_file_alive()
    try:
        entries = list(proc.iterdir())
    except OSError:
        return False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        cmd = _cmdline(int(entry.name))
        if "controller/run_realtime.py" in cmd or "controller.realtime_detector" in cmd:
            return True
    return False

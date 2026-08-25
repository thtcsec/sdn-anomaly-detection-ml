"""Demo DDoS trigger: h4 SYN → h1 for 25s by default. No Mininet."""

from __future__ import annotations

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import trigger_traffic as tt  # noqa: E402


def test_trigger_ddos_default_h4_syn_only_duration_25(monkeypatch):
    calls = []

    monkeypatch.setattr(tt, "get_mininet_host_pids", lambda: {"h4": "104", "h5": "105"})
    monkeypatch.setattr(
        tt,
        "run_in_host",
        lambda pid, argv, bg=True: calls.append((pid, list(argv))) or True,
    )

    assert tt.trigger_ddos("10.0.0.1") is True
    assert len(calls) == 1
    pid, argv = calls[0]
    assert pid == "104"
    assert argv[:2] == ["timeout", "25"]
    assert "hping3" in argv and "-S" in argv and "--flood" in argv
    assert argv[-1] == "10.0.0.1"
    assert "--udp" not in argv


def test_trigger_ddos_optional_h5_udp(monkeypatch):
    calls = []
    monkeypatch.setattr(tt, "get_mininet_host_pids", lambda: {"h4": "104", "h5": "105"})
    monkeypatch.setattr(
        tt,
        "run_in_host",
        lambda pid, argv, bg=True: calls.append((pid, list(argv))) or True,
    )

    assert tt.trigger_ddos("10.0.0.1", duration=25, include_h5_udp=True) is True
    assert [pid for pid, _ in calls] == ["104", "105"]
    assert "-S" in calls[0][1]
    assert "--udp" in calls[1][1]

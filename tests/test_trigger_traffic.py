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


def test_stop_all_traffic_posix_killall_no_shell_metacharacters(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))

        class Result:
            returncode = 0
            stdout = b""
            stderr = b""

        return Result()

    monkeypatch.setattr(tt.subprocess, "run", fake_run)
    monkeypatch.setattr(tt, "get_mininet_host_pids", lambda: {"h1": "101", "h4": "104"})

    assert tt.stop_all_traffic() is True
    assert calls
    for argv in calls:
        assert all(isinstance(arg, str) for arg in argv)
        joined = " ".join(argv)
        assert "<" not in joined
        assert ">" not in joined
        assert "<<" not in joined
        assert "$(" not in joined
        assert "<(" not in joined
        assert argv[0] in {"killall", "mnexec"}
        if argv[0] == "killall":
            assert argv == ["killall", "-9", argv[2]]
            assert argv[2] in tt.KILL_NAMES
        else:
            assert argv[:4] == ["mnexec", "-a", argv[2], "killall"]
            assert argv[2].isdigit()
            assert argv[4] == "-9"
            assert argv[5] in tt.KILL_NAMES
            assert len(argv) == 6


def test_argv_safe_rejects_redirect_token():
    try:
        tt._argv_safe(["sh", "-c", "killall < /dev/null"])
    except ValueError as exc:
        assert "metacharacters" in str(exc)
    else:
        raise AssertionError("expected ValueError")


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

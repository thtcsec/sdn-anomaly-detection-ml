"""SOC unit tests: no Mininet, no OpenFlow bind on :6633, no TensorFlow load."""

from __future__ import annotations

import os
import sys

# Must be set before any xgboost unpickle in other modules.
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


@pytest.fixture
def dashboard_module():
    from dashboard import app as dashboard_app

    return dashboard_app


@pytest.fixture
def client(dashboard_module, tmp_path, monkeypatch):
    """Flask client with live_stats / alerts / config pointed at missing tmp files."""
    monkeypatch.setattr(dashboard_module, "LIVE_STATS_LOG", str(tmp_path / "live_stats.json"))
    monkeypatch.setattr(dashboard_module, "ALERT_LOG", str(tmp_path / "alerts.json"))
    monkeypatch.setattr(dashboard_module, "CONFIG_PATH", str(tmp_path / "controller_config.json"))
    dashboard_module.app.config["TESTING"] = True
    return dashboard_module.app.test_client()

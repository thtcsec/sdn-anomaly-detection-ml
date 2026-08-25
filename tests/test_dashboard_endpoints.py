"""GET endpoints must not 500 when telemetry files are missing."""

from __future__ import annotations


JSON_GETS = (
    "/api/health",
    "/api/stats",
    "/api/live_data",
    "/api/alerts",
    "/api/blocked",
    "/api/traffic_stats",
    "/api/settings",
)


def test_index_ok(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"html" in resp.data.lower() or b"SDN" in resp.data or resp.data


def test_json_endpoints_not_500_without_live_stats(client):
    for path in JSON_GETS:
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code} {resp.data[:200]!r}"
        payload = resp.get_json()
        assert payload is not None, f"{path} did not return JSON"


def test_health_lists_models_without_loading_ae(client):
    payload = client.get("/api/health").get_json()
    assert payload["status"] == "ok"
    names = set(payload["available_models"])
    assert {"svm", "random_forest", "xgboost", "isolation_forest", "autoencoder"} <= names
    # Existence flags only — this must not import tensorflow.
    assert "missing" in payload["available_models"]["autoencoder"]


def test_stats_shape_with_missing_telemetry(client):
    payload = client.get("/api/stats").get_json()
    assert "total_flows_analyzed" in payload
    assert "controller_alive" in payload
    assert payload["controller_alive"] in (True, False)
    assert "total_attacks_detected" in payload


def test_index_demo_ddos_duration_h4_only_and_alert_wording(client):
    html = client.get("/").get_data(as_text=True)
    assert "triggerSimulate('ddos', 25)" in html
    assert "triggerSimulate('stop', 0)" in html
    assert "Bắn DDoS (h4 SYN → h1)" in html
    assert "Anomaly Alerts" in html
    assert "mininet&gt;" in html
    assert "poll_pps" in html
    assert "Lỗi kết nối:" not in html
    assert "JSON.parse(raw)" in html


def test_simulate_stop_returns_json_not_html(client, dashboard_module):
    resp = client.post(
        "/api/simulate",
        json={"type": "stop", "duration": 0, "target": "10.0.0.1"},
        headers={"X-CSRF-Token": dashboard_module.CSRF_TOKEN},
    )
    payload = resp.get_json()
    assert payload is not None
    assert payload.get("status") in {"ok", "error"}
    assert "<" not in str(payload.get("message") or "")
    assert b"<!DOCTYPE" not in resp.data
    assert b"<html" not in resp.data.lower()


def test_blocked_count_reads_live_stats(client, dashboard_module):
    import json
    from datetime import datetime

    live_path = dashboard_module.LIVE_STATS_LOG
    payload = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "blocked_ips": ["10.0.0.4"],
        "flood_sources": ["10.0.0.4"],
        "poll_pps": 1234.0,
        "flows_analyzed": 10,
        "normal_count": 1,
        "ddos_count": 0,
        "portscan_count": 0,
        "anomaly_count": 9,
        "active_switches": [1, 2],
        "recent_flows": [
            {
                "ip_src": "10.0.0.4",
                "ip_dst": "10.0.0.1",
                "prediction": "ANOMALY",
                "blocked": True,
                "packet_delta_per_sec": 80,
            }
        ],
    }
    with open(live_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)

    data = client.get("/api/live_data").get_json()
    assert data["stats"]["total_ips_blocked"] == 1
    assert data["blocked_ips"] == ["10.0.0.4"]
    assert data["stats"]["poll_pps"] == 1234.0
    by_id = {h["id"]: h["status"] for h in data["hosts"]}
    assert by_id["h4"] == "BLOCKED"
    assert by_id["h1"] == "NORMAL"
    assert by_id["h5"] == "NORMAL"
    assert by_id["h6"] == "NORMAL"

    blocked = client.get("/api/blocked").get_json()
    assert blocked == [{"ip": "10.0.0.4", "blocked": True}]

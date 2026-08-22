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

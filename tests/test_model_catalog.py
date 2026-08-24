"""Catalog + 8-col feature builder. Does not load pickle / keras artifacts."""

from __future__ import annotations

import pandas as pd

from model_catalog import (
    ALLOWED_MODELS,
    BINARY_MODELS,
    DEFAULT_LIVE_MODEL,
    FEATURE_COLS,
    PORT_AGNOSTIC_FEATURE_COLS,
    SAFE_FALLBACK_MODEL,
    artifact_paths,
    build_flow_features,
    feature_columns,
    inventory,
    model_task,
    ordered_feature_row,
    resolve_live_model,
    train_hint,
)


def test_catalog_lists_expected_models():
    names = set(ALLOWED_MODELS)
    assert {
        "svm",
        "random_forest",
        "random_forest_binary",
        "xgboost",
        "isolation_forest",
        "autoencoder",
    } <= names
    inv = inventory("/nonexistent/models-dir")
    assert set(inv) == names
    for name, meta in inv.items():
        assert meta["n_features"] == len(feature_columns(name))
        assert meta["available"] is False
        assert meta["missing"]


def test_binary_schema_is_eight_cols_without_raw_ports():
    cols = feature_columns("random_forest_binary")
    assert cols == PORT_AGNOSTIC_FEATURE_COLS
    assert len(cols) == 8
    assert "tp_src" not in cols
    assert "tp_dst" not in cols
    assert model_task("random_forest_binary") == "binary_anomaly_port_agnostic"


def test_legacy_models_keep_ten_col_schema():
    for name in ("svm", "xgboost", "random_forest", "isolation_forest", "autoencoder"):
        cols = feature_columns(name)
        assert cols == FEATURE_COLS
        assert len(cols) == 10
        assert "tp_src" in cols


def test_dummy_flow_row_does_not_crash():
    values = build_flow_features(
        ip_proto=6,
        tp_src=443,
        tp_dst=80,
        packet_count=100,
        byte_count=8000,
        duration_sec=5,
        duration_nsec=0,
    )
    row8 = ordered_feature_row(values, "random_forest_binary")
    assert len(row8) == 8
    df = pd.DataFrame([row8], columns=feature_columns("random_forest_binary"))
    assert df.shape == (1, 8)
    row10 = ordered_feature_row(values, "svm")
    assert len(row10) == 10
    assert values["packet_count_per_sec"] == 20.0
    assert values["byte_count_per_sec"] == 1600.0


def test_zero_duration_and_empty_flow_are_safe():
    values = build_flow_features(
        packet_count=0, byte_count=0, duration_sec=0, duration_nsec=0,
    )
    assert values["packet_count_per_sec"] == 0.0
    assert values["byte_count_per_sec"] == 0.0
    assert values["packet_size_avg"] == 0.0
    assert values["flow_duration"] == 0.0
    ordered_feature_row(values, "random_forest_binary")
    ordered_feature_row(values, "xgboost")


def test_train_hints_and_ae_path_do_not_import_tf():
    assert "train_svm.py" in train_hint("svm")
    assert "train_xgboost.py" in train_hint("xgboost")
    ae = artifact_paths("/tmp/models", "autoencoder")
    assert ae["model"].endswith("autoencoder_model.keras")
    assert set(BINARY_MODELS) == {"random_forest_binary", "isolation_forest", "autoencoder"}


def _touch_artifacts(models_dir, name: str) -> None:
    from pathlib import Path

    root = Path(models_dir)
    root.mkdir(parents=True, exist_ok=True)
    for path in artifact_paths(str(root), name).values():
        Path(path).write_bytes(b"x")


def test_committed_controller_config_defaults_to_rf_binary():
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "dataset" / "controller_config.json"
    cfg = json.loads(path.read_text(encoding="utf-8"))
    assert cfg["selected_model"] == "random_forest_binary"


def test_resolve_live_model_keeps_rf_when_present(tmp_path):
    _touch_artifacts(tmp_path, "random_forest_binary")
    name, warn = resolve_live_model(str(tmp_path), "random_forest_binary")
    assert name == "random_forest_binary"
    assert warn is None


def test_resolve_live_model_falls_back_to_svm_not_xgboost(tmp_path):
    _touch_artifacts(tmp_path, "svm")
    _touch_artifacts(tmp_path, "xgboost")
    name, warn = resolve_live_model(str(tmp_path), "random_forest_binary")
    assert name == "svm"
    assert warn
    assert "xgboost" in warn.lower() or "CUDA" in warn or "cuda" in warn
    assert "RF pickle" in warn or "thieu RF" in warn


def test_resolve_live_model_keeps_explicit_xgboost_if_present(tmp_path):
    _touch_artifacts(tmp_path, "xgboost")
    name, warn = resolve_live_model(str(tmp_path), "xgboost")
    assert name == "xgboost"
    assert warn is None

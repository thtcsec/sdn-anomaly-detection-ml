"""Catalog + 8-col feature builder. Does not load pickle / keras artifacts."""

from __future__ import annotations

import pandas as pd

from model_catalog import (
    ALLOWED_MODELS,
    BINARY_MODELS,
    FEATURE_COLS,
    PORT_AGNOSTIC_FEATURE_COLS,
    artifact_paths,
    build_flow_features,
    feature_columns,
    inventory,
    model_task,
    ordered_feature_row,
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

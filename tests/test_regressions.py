from __future__ import annotations

import os
import sys
import unittest

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "src"))
sys.path.insert(0, os.path.join(BASE_DIR, "scripts"))
sys.path.insert(0, BASE_DIR)

from eval_fault_loso import _impute_fold, _impute_normal_only_fold
from mitigation_policy import update_consecutive_poll_streaks
from model_catalog import feature_columns, model_task
from trigger_traffic import validate_target
from dashboard import app as dashboard_app


class RegressionTests(unittest.TestCase):
    def test_fault_imputer_uses_train_fold_only(self):
        train = pd.DataFrame({"probe": [1.0, 3.0]})
        test = pd.DataFrame({"probe": [None]})
        _, transformed = _impute_fold(train, test)
        self.assertEqual(float(transformed.iloc[0, 0]), 2.0)

    def test_one_class_imputer_uses_train_normal_only(self):
        train = pd.DataFrame({"probe": [1.0, 3.0, 100.0]})
        labels = pd.Series(["normal", "normal", "fault"])
        test = pd.DataFrame({"probe": [None]})
        normal, transformed = _impute_normal_only_fold(train, labels, test)
        self.assertEqual(normal["probe"].tolist(), [1.0, 3.0])
        self.assertEqual(float(transformed.iloc[0, 0]), 2.0)

    def test_realtime_binary_schema_has_no_raw_ports(self):
        cols = feature_columns("random_forest_binary")
        self.assertEqual(len(cols), 8)
        self.assertNotIn("tp_src", cols)
        self.assertNotIn("tp_dst", cols)
        self.assertEqual(model_task("random_forest_binary"), "binary_anomaly_port_agnostic")

    def test_many_flows_increment_only_once_per_poll(self):
        streaks = {"10.0.0.4": 1}
        incremented = update_consecutive_poll_streaks(
            streaks,
            {"10.0.0.4", "10.0.0.4"},
            {"10.0.0.4"},
            set(),
        )
        self.assertEqual(streaks["10.0.0.4"], 2)
        self.assertEqual(incremented, ["10.0.0.4"])

    def test_benign_poll_resets_streak(self):
        streaks = {"10.0.0.4": 2}
        update_consecutive_poll_streaks(streaks, set(), {"10.0.0.4"}, set())
        self.assertEqual(streaks["10.0.0.4"], 0)

    def test_target_allowlist(self):
        self.assertEqual(validate_target("10.0.0.6"), "10.0.0.6")
        with self.assertRaises(Exception):
            validate_target("8.8.8.8")

    def test_dashboard_rejects_post_without_csrf(self):
        client = dashboard_app.app.test_client()
        response = client.post("/api/simulate", json={"type": "normal"})
        self.assertEqual(response.status_code, 403)

    def test_dashboard_rejects_non_lab_target(self):
        client = dashboard_app.app.test_client()
        response = client.post(
            "/api/simulate",
            json={"type": "ddos", "target": "8.8.8.8"},
            headers={"X-CSRF-Token": dashboard_app.CSRF_TOKEN},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

"""Tests for GET /api/metrics."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.conftest import MODEL_AVAILABLE

pytestmark = pytest.mark.skipif(not MODEL_AVAILABLE, reason="No model artifacts")


class TestMetricsEndpoint:
    """Verify the metrics endpoint returns valid evaluation data."""

    def test_metrics_status_code(self, client: TestClient) -> None:
        response = client.get("/api/metrics")
        assert response.status_code == 200

    def test_metrics_response_keys(self, client: TestClient) -> None:
        data = client.get("/api/metrics").json()
        expected_keys = {"accuracy", "classification_report"}
        assert set(data.keys()) == expected_keys

    def test_accuracy_range(self, client: TestClient) -> None:
        data = client.get("/api/metrics").json()
        acc = data["accuracy"]
        assert isinstance(acc, float)
        assert 0.0 <= acc <= 1.0

    def test_accuracy_is_reasonable(self, client: TestClient) -> None:
        """A trained XGBoost model should exceed 50% on multiclass classification."""
        data = client.get("/api/metrics").json()
        assert data["accuracy"] > 0.5

    def test_classification_report_is_dict(self, client: TestClient) -> None:
        data = client.get("/api/metrics").json()
        report = data["classification_report"]
        assert isinstance(report, dict)

    def test_classification_report_contains_accuracy(self, client: TestClient) -> None:
        data = client.get("/api/metrics").json()
        report = data["classification_report"]
        assert "accuracy" in report

    def test_classification_report_precision_recall_f1(
        self, client: TestClient
    ) -> None:
        """Each per-class entry should have precision, recall, and f1-score."""
        data = client.get("/api/metrics").json()
        report = data["classification_report"]
        per_class_keys = {"precision", "recall", "f1-score", "support"}
        for key, val in report.items():
            if isinstance(val, dict) and key not in ("macro avg", "weighted avg"):
                assert per_class_keys.issubset(
                    set(val.keys())
                ), f"Class '{key}' is missing expected keys"

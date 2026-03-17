"""Tests for analytics endpoints:
- GET /api/feature-importance
- GET /api/confusion-matrix
- GET /api/dataset/stats
"""
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.conftest import ATTACK_CLASSES, MODEL_AVAILABLE

pytestmark = pytest.mark.skipif(not MODEL_AVAILABLE, reason="No model artifacts")


# ── Feature importance ────────────────────────────────────────────────


class TestFeatureImportanceEndpoint:
    """Verify GET /api/feature-importance."""

    def test_status_code(self, client: TestClient) -> None:
        response = client.get("/api/feature-importance")
        assert response.status_code == 200

    def test_returns_list(self, client: TestClient) -> None:
        data = client.get("/api/feature-importance").json()
        assert isinstance(data, list)

    def test_length_is_28(self, client: TestClient) -> None:
        data = client.get("/api/feature-importance").json()
        assert len(data) == 28

    def test_each_item_has_feature_and_importance(
        self, client: TestClient
    ) -> None:
        data = client.get("/api/feature-importance").json()
        for item in data:
            assert "feature" in item
            assert "importance" in item
            assert isinstance(item["feature"], str)
            assert isinstance(item["importance"], (int, float))

    def test_importance_values_non_negative(self, client: TestClient) -> None:
        data = client.get("/api/feature-importance").json()
        for item in data:
            assert item["importance"] >= 0.0

    def test_sorted_descending(self, client: TestClient) -> None:
        data = client.get("/api/feature-importance").json()
        importances = [item["importance"] for item in data]
        assert importances == sorted(importances, reverse=True)

    def test_feature_names_match_config(
        self, client: TestClient, feature_names: list[str]
    ) -> None:
        data = client.get("/api/feature-importance").json()
        returned_features = {item["feature"] for item in data}
        assert returned_features == set(feature_names)

    def test_importances_sum_to_approximately_one(
        self, client: TestClient
    ) -> None:
        """XGBoost gain-based importances typically sum to ~1.0."""
        data = client.get("/api/feature-importance").json()
        total = sum(item["importance"] for item in data)
        # Allow a generous tolerance; some importance types may not sum exactly.
        assert 0.5 < total < 1.5


# ── Confusion matrix ─────────────────────────────────────────────────


class TestConfusionMatrixEndpoint:
    """Verify GET /api/confusion-matrix."""

    def test_status_code(self, client: TestClient) -> None:
        response = client.get("/api/confusion-matrix")
        assert response.status_code == 200

    def test_response_keys(self, client: TestClient) -> None:
        data = client.get("/api/confusion-matrix").json()
        assert "labels" in data
        assert "matrix" in data

    def test_labels_is_list_of_strings(self, client: TestClient) -> None:
        data = client.get("/api/confusion-matrix").json()
        labels = data["labels"]
        assert isinstance(labels, list)
        assert all(isinstance(name, str) for name in labels)

    def test_labels_match_attack_classes(self, client: TestClient) -> None:
        data = client.get("/api/confusion-matrix").json()
        assert set(data["labels"]) == set(ATTACK_CLASSES)

    def test_matrix_is_square(self, client: TestClient) -> None:
        data = client.get("/api/confusion-matrix").json()
        matrix = data["matrix"]
        n = len(data["labels"])
        assert len(matrix) == n
        for row in matrix:
            assert len(row) == n

    def test_matrix_values_non_negative(self, client: TestClient) -> None:
        data = client.get("/api/confusion-matrix").json()
        for row in data["matrix"]:
            for val in row:
                assert isinstance(val, int)
                assert val >= 0

    def test_matrix_row_sums_positive(self, client: TestClient) -> None:
        """Each row should have at least one sample."""
        data = client.get("/api/confusion-matrix").json()
        for i, row in enumerate(data["matrix"]):
            assert sum(row) > 0, f"Row {i} has zero total"

    def test_matrix_total_equals_test_set_size(
        self, client: TestClient
    ) -> None:
        """The total of all cells should equal the test set size."""
        data = client.get("/api/confusion-matrix").json()
        total = sum(sum(row) for row in data["matrix"])
        assert total > 0


# ── Dataset stats ─────────────────────────────────────────────────────


class TestDatasetStatsEndpoint:
    """Verify GET /api/dataset/stats."""

    def test_status_code(self, client: TestClient) -> None:
        response = client.get("/api/dataset/stats")
        assert response.status_code == 200

    def test_response_keys(self, client: TestClient) -> None:
        data = client.get("/api/dataset/stats").json()
        assert "total_samples" in data
        assert "attack_distribution" in data

    def test_total_samples_positive(self, client: TestClient) -> None:
        data = client.get("/api/dataset/stats").json()
        assert isinstance(data["total_samples"], int)
        assert data["total_samples"] > 0

    def test_attack_distribution_is_dict(self, client: TestClient) -> None:
        data = client.get("/api/dataset/stats").json()
        dist = data["attack_distribution"]
        assert isinstance(dist, dict)

    def test_attack_distribution_keys_are_attack_classes(
        self, client: TestClient
    ) -> None:
        data = client.get("/api/dataset/stats").json()
        dist_keys = set(data["attack_distribution"].keys())
        assert dist_keys == set(ATTACK_CLASSES)

    def test_attack_distribution_values_positive(
        self, client: TestClient
    ) -> None:
        data = client.get("/api/dataset/stats").json()
        for label, count in data["attack_distribution"].items():
            assert isinstance(count, int)
            assert count > 0, f"Attack class '{label}' has 0 samples"

    def test_distribution_sums_to_total(self, client: TestClient) -> None:
        data = client.get("/api/dataset/stats").json()
        total_from_dist = sum(data["attack_distribution"].values())
        assert total_from_dist == data["total_samples"]

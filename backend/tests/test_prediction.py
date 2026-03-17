"""Tests for prediction endpoints:
- POST /api/predict
- POST /api/predict/batch
"""
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from tests.conftest import ATTACK_CLASSES, MODEL_AVAILABLE

pytestmark = pytest.mark.skipif(not MODEL_AVAILABLE, reason="No model artifacts")


# ── Single prediction ─────────────────────────────────────────────────


class TestPredictEndpoint:
    """Verify POST /api/predict."""

    def test_status_code(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        response = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        )
        assert response.status_code == 200

    def test_response_keys(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        expected = {"predicted_class", "confidence", "is_attack", "probabilities"}
        assert set(data.keys()) == expected

    def test_predicted_class_is_known(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        assert data["predicted_class"] in ATTACK_CLASSES

    def test_confidence_range(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        assert 0.0 <= data["confidence"] <= 1.0

    def test_is_attack_bool(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        assert isinstance(data["is_attack"], bool)

    def test_is_attack_consistent_with_class(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        if data["predicted_class"] == "normal":
            assert data["is_attack"] is False
        else:
            assert data["is_attack"] is True

    def test_probabilities_keys_match_classes(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        assert set(data["probabilities"].keys()) == set(ATTACK_CLASSES)

    def test_probabilities_sum_to_one(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        total = sum(data["probabilities"].values())
        assert abs(total - 1.0) < 0.01

    def test_probabilities_non_negative(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        for cls, prob in data["probabilities"].items():
            assert prob >= 0.0, f"Probability for '{cls}' is negative"

    def test_highest_probability_matches_predicted_class(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        best_class = max(data["probabilities"], key=data["probabilities"].get)
        assert best_class == data["predicted_class"]

    def test_confidence_matches_max_probability(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict", json={"features": all_zero_features}, headers=auth_headers
        ).json()
        max_prob = max(data["probabilities"].values())
        assert abs(data["confidence"] - max_prob) < 1e-4

    def test_partial_features_filled_with_defaults(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """Sending only a subset of features should still work;
        missing features default to 0.0 in the ModelManager."""
        response = client.post(
            "/api/predict",
            json={"features": {"duration": 100.0, "src_bytes": 500.0}},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["predicted_class"] in ATTACK_CLASSES

    def test_empty_features_dict(self, client: TestClient, auth_headers: dict[str, str]) -> None:
        """An empty feature dict should still produce a prediction (all zeros)."""
        response = client.post("/api/predict", json={"features": {}}, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["predicted_class"] in ATTACK_CLASSES

    def test_missing_features_key_returns_422(self, client: TestClient, auth_headers: dict[str, str]) -> None:
        """Omitting the required 'features' key should return 422."""
        response = client.post("/api/predict", json={}, headers=auth_headers)
        assert response.status_code == 422

    def test_invalid_body_returns_422(self, client: TestClient, auth_headers: dict[str, str]) -> None:
        """Non-JSON body or wrong types should return 422."""
        response = client.post(
            "/api/predict", json={"features": "not_a_dict"}, headers=auth_headers
        )
        assert response.status_code == 422

    def test_predict_with_nonzero_features(
        self, client: TestClient, feature_names: list[str], auth_headers: dict[str, str]
    ) -> None:
        """A sample with non-trivial feature values should classify correctly."""
        features = {name: float(i) for i, name in enumerate(feature_names)}
        response = client.post("/api/predict", json={"features": features}, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["predicted_class"] in ATTACK_CLASSES
        assert 0.0 <= data["confidence"] <= 1.0

    def test_predict_without_api_key_returns_401(
        self, client: TestClient, all_zero_features: dict[str, float]
    ) -> None:
        """POST /api/predict without API key should return 422 (missing header)."""
        response = client.post("/api/predict", json={"features": all_zero_features})
        assert response.status_code == 422


# ── Batch prediction ─────────────────────────────────────────────────


class TestBatchPredictEndpoint:
    """Verify POST /api/predict/batch."""

    def test_batch_status_code(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        response = client.post(
            "/api/predict/batch", json={"samples": [all_zero_features]}, headers=auth_headers
        )
        assert response.status_code == 200

    def test_batch_returns_list(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict/batch", json={"samples": [all_zero_features]}, headers=auth_headers
        ).json()
        assert isinstance(data, list)

    def test_batch_single_sample(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        """A batch with exactly one sample should return a list of length 1."""
        data = client.post(
            "/api/predict/batch", json={"samples": [all_zero_features]}, headers=auth_headers
        ).json()
        assert len(data) == 1

    def test_batch_multiple_samples(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        """Sending multiple samples should return results for each."""
        samples = [all_zero_features, all_zero_features, all_zero_features]
        data = client.post(
            "/api/predict/batch", json={"samples": samples}, headers=auth_headers
        ).json()
        assert len(data) == 3

    def test_batch_each_item_schema(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        data = client.post(
            "/api/predict/batch",
            json={"samples": [all_zero_features, all_zero_features]},
            headers=auth_headers,
        ).json()
        for item in data:
            assert "predicted_class" in item
            assert "confidence" in item
            assert "is_attack" in item
            assert "probabilities" in item
            assert item["predicted_class"] in ATTACK_CLASSES
            assert 0.0 <= item["confidence"] <= 1.0
            assert isinstance(item["is_attack"], bool)

    def test_batch_identical_samples_produce_identical_results(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        """Same input should produce the same output."""
        data = client.post(
            "/api/predict/batch",
            json={"samples": [all_zero_features, all_zero_features]},
            headers=auth_headers,
        ).json()
        assert data[0] == data[1]

    def test_batch_different_samples(
        self, client: TestClient, feature_names: list[str], auth_headers: dict[str, str]
    ) -> None:
        """Different inputs may produce different outputs."""
        sample_a = {name: 0.0 for name in feature_names}
        sample_b = {name: 999.0 for name in feature_names}
        data = client.post(
            "/api/predict/batch", json={"samples": [sample_a, sample_b]}, headers=auth_headers
        ).json()
        assert len(data) == 2
        for item in data:
            assert item["predicted_class"] in ATTACK_CLASSES

    def test_batch_empty_samples_returns_422(self, client: TestClient, auth_headers: dict[str, str]) -> None:
        """An empty samples list should be rejected (min_length=1)."""
        response = client.post("/api/predict/batch", json={"samples": []}, headers=auth_headers)
        assert response.status_code == 422

    def test_batch_missing_samples_key_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        response = client.post("/api/predict/batch", json={}, headers=auth_headers)
        assert response.status_code == 422

    def test_batch_five_samples(
        self, client: TestClient, all_zero_features: dict[str, float], auth_headers: dict[str, str]
    ) -> None:
        samples = [all_zero_features] * 5
        data = client.post(
            "/api/predict/batch", json={"samples": samples}, headers=auth_headers
        ).json()
        assert len(data) == 5
        for item in data:
            assert set(item.keys()) == {
                "predicted_class",
                "confidence",
                "is_attack",
                "probabilities",
            }

    def test_batch_without_api_key_returns_422(
        self, client: TestClient, all_zero_features: dict[str, float]
    ) -> None:
        """POST /api/predict/batch without API key should return 422."""
        response = client.post(
            "/api/predict/batch", json={"samples": [all_zero_features]}
        )
        assert response.status_code == 422

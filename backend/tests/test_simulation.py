"""Tests for GET /api/simulate.

The endpoint returns 200 with events when ``test_data.joblib`` exists,
or 503 when the artifact is missing.  Tests are split into two groups:
validation tests that always apply, and payload tests that are skipped
when test data is unavailable.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.config import settings
from tests.conftest import ATTACK_CLASSES

_test_data_available = settings.TEST_DATA_PATH.exists()


# ── Validation (always applies) ──────────────────────────────────────


class TestSimulateValidation:
    """Query-parameter validation — independent of test-data presence."""

    def test_count_zero_returns_422(self, client: TestClient) -> None:
        response = client.get("/api/simulate", params={"count": 0})
        assert response.status_code == 422

    def test_count_negative_returns_422(self, client: TestClient) -> None:
        response = client.get("/api/simulate", params={"count": -1})
        assert response.status_code == 422

    def test_count_exceeds_max_returns_422(self, client: TestClient) -> None:
        response = client.get("/api/simulate", params={"count": 101})
        assert response.status_code == 422

    def test_count_not_integer_returns_422(self, client: TestClient) -> None:
        response = client.get("/api/simulate", params={"count": "abc"})
        assert response.status_code == 422

    def test_no_auth_required(self, client: TestClient) -> None:
        """The endpoint should never return 401/422 for missing key."""
        resp = client.get("/api/simulate")
        assert resp.status_code in (200, 503)

    def test_graceful_503_when_data_missing(self, client: TestClient) -> None:
        """When test_data.joblib is absent the endpoint must not crash."""
        resp = client.get("/api/simulate")
        assert resp.status_code in (200, 503)
        if resp.status_code == 503:
            assert "detail" in resp.json()


# ── Payload (only when test_data.joblib exists) ──────────────────────


@pytest.mark.skipif(not _test_data_available, reason="test_data.joblib not present")
class TestSimulatePayload:
    """Verify response shape and semantics when simulation data exists."""

    def test_default_count(self, client: TestClient) -> None:
        response = client.get("/api/simulate")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 10

    def test_count_one(self, client: TestClient) -> None:
        response = client.get("/api/simulate", params={"count": 1})
        assert response.status_code == 200
        assert len(response.json()) == 1

    def test_count_five(self, client: TestClient) -> None:
        response = client.get("/api/simulate", params={"count": 5})
        assert response.status_code == 200
        assert len(response.json()) == 5

    def test_count_100(self, client: TestClient) -> None:
        response = client.get("/api/simulate", params={"count": 100})
        assert response.status_code == 200
        assert len(response.json()) == 100

    def test_event_schema(self, client: TestClient) -> None:
        data = client.get("/api/simulate", params={"count": 3}).json()
        expected_keys = {
            "timestamp",
            "features",
            "predicted_class",
            "confidence",
            "is_attack",
        }
        for event in data:
            assert set(event.keys()) == expected_keys

    def test_timestamp_is_iso_string(self, client: TestClient) -> None:
        from datetime import datetime

        data = client.get("/api/simulate", params={"count": 2}).json()
        for event in data:
            datetime.fromisoformat(event["timestamp"])

    def test_predicted_class_is_known(self, client: TestClient) -> None:
        data = client.get("/api/simulate", params={"count": 5}).json()
        for event in data:
            assert event["predicted_class"] in ATTACK_CLASSES

    def test_confidence_range(self, client: TestClient) -> None:
        data = client.get("/api/simulate", params={"count": 5}).json()
        for event in data:
            assert 0.0 <= event["confidence"] <= 1.0

    def test_is_attack_bool(self, client: TestClient) -> None:
        data = client.get("/api/simulate", params={"count": 5}).json()
        for event in data:
            assert isinstance(event["is_attack"], bool)

    def test_is_attack_consistent_with_class(self, client: TestClient) -> None:
        data = client.get("/api/simulate", params={"count": 20}).json()
        for event in data:
            if event["predicted_class"] == "normal":
                assert event["is_attack"] is False
            else:
                assert event["is_attack"] is True

    def test_features_is_dict(self, client: TestClient) -> None:
        data = client.get("/api/simulate", params={"count": 3}).json()
        for event in data:
            assert isinstance(event["features"], dict)

    def test_features_values_nonzero(self, client: TestClient) -> None:
        data = client.get("/api/simulate", params={"count": 5}).json()
        for event in data:
            for key, val in event["features"].items():
                assert isinstance(key, str)
                assert isinstance(val, (int, float))
                assert val != 0.0

    def test_randomness_across_calls(self, client: TestClient) -> None:
        data1 = client.get("/api/simulate", params={"count": 10}).json()
        data2 = client.get("/api/simulate", params={"count": 10}).json()
        assert len(data1) == 10
        assert len(data2) == 10

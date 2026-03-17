"""Tests for GET /api/feature-names."""

from __future__ import annotations

from starlette.testclient import TestClient

# Canonical list — the 28 observable features
EXPECTED_FEATURE_NAMES: list[str] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


class TestFeatureNamesEndpoint:
    """Verify GET /api/feature-names returns the exact canonical 28 names."""

    def test_status_code(self, client: TestClient) -> None:
        response = client.get("/api/feature-names")
        assert response.status_code == 200

    def test_returns_list(self, client: TestClient) -> None:
        data = client.get("/api/feature-names").json()
        assert isinstance(data, list)

    def test_exactly_28_names(self, client: TestClient) -> None:
        data = client.get("/api/feature-names").json()
        assert len(data) == 28

    def test_all_strings(self, client: TestClient) -> None:
        data = client.get("/api/feature-names").json()
        for name in data:
            assert isinstance(name, str)

    def test_exact_names_and_order(self, client: TestClient) -> None:
        """The endpoint must return exactly the canonical list in order."""
        data = client.get("/api/feature-names").json()
        assert data == EXPECTED_FEATURE_NAMES

    def test_no_duplicates(self, client: TestClient) -> None:
        data = client.get("/api/feature-names").json()
        assert len(data) == len(set(data))

    def test_matches_config_settings(
        self, client: TestClient, feature_names: list[str]
    ) -> None:
        """The endpoint output must match settings.FEATURE_NAMES exactly."""
        data = client.get("/api/feature-names").json()
        assert data == feature_names

    def test_content_type(self, client: TestClient) -> None:
        response = client.get("/api/feature-names")
        assert response.headers["content-type"] == "application/json"

    def test_first_feature_is_duration(self, client: TestClient) -> None:
        data = client.get("/api/feature-names").json()
        assert data[0] == "duration"

    def test_last_feature_is_dst_host_srv_rerror_rate(
        self, client: TestClient
    ) -> None:
        data = client.get("/api/feature-names").json()
        assert data[-1] == "dst_host_srv_rerror_rate"

    def test_no_host_level_features(self, client: TestClient) -> None:
        """Host-level features must NOT be in the observable feature set."""
        data = client.get("/api/feature-names").json()
        host_level = {
            "hot", "num_failed_logins", "logged_in", "num_compromised",
            "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds",
            "is_host_login", "is_guest_login",
        }
        assert host_level.isdisjoint(set(data))

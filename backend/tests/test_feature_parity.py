"""
Phase 2 parity tests — verify that FeatureExtractor output matches
the live system's expected feature set, and that the full
extract → predict pipeline works end-to-end (when model artifacts exist).
"""

from __future__ import annotations

import time

import pytest

from app.capture import FeatureExtractor, Flow
from app.config import settings


def _make_flow(**overrides) -> Flow:
    defaults = dict(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        proto=6,
        start_time=time.time() - 5,
        last_time=time.time(),
        src_bytes=1024,
        dst_bytes=2048,
        src_packets=10,
        dst_packets=15,
        tcp_flags=[2, 18, 16, 1],
    )
    defaults.update(overrides)
    return Flow(**defaults)


class TestFeatureParity:
    """The extractor must produce exactly the features the live system expects."""

    def test_extractor_keys_equal_feature_names(self) -> None:
        ext = FeatureExtractor()
        features = ext.extract(_make_flow())
        assert set(features.keys()) == set(settings.FEATURE_NAMES)

    def test_extractor_length_equals_feature_names(self) -> None:
        ext = FeatureExtractor()
        features = ext.extract(_make_flow())
        assert len(features) == len(settings.FEATURE_NAMES)

    def test_no_unobservable_features_in_output(self) -> None:
        unobservable = {
            "hot", "num_failed_logins", "logged_in", "num_compromised",
            "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds",
            "is_host_login", "is_guest_login",
        }
        ext = FeatureExtractor()
        features = ext.extract(_make_flow())
        assert unobservable.isdisjoint(set(features.keys()))

    def test_schema_version_is_set(self) -> None:
        assert settings.FEATURE_SCHEMA_VERSION == "v2-observable-28"

    def test_feature_names_count_is_28(self) -> None:
        assert len(settings.FEATURE_NAMES) == 28


_model_available = settings.MULTI_MODEL_PATH.exists()


@pytest.mark.skipif(not _model_available, reason="No model artifacts")
class TestExtractorToModelIntegration:
    """End-to-end: extract → predict (requires model artifacts on disk)."""

    @pytest.fixture(scope="class")
    def manager(self):
        from app.model import ModelManager
        mgr = ModelManager()
        mgr.load()
        return mgr

    def test_extract_then_predict_succeeds(self, manager) -> None:
        ext = FeatureExtractor()
        features = ext.extract(_make_flow())
        result = manager.predict(features)
        assert "predicted_class" in result
        assert "confidence" in result

    def test_extract_predict_confidence_valid(self, manager) -> None:
        ext = FeatureExtractor()
        features = ext.extract(_make_flow())
        result = manager.predict(features)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_extract_predict_probabilities_sum_to_one(self, manager) -> None:
        ext = FeatureExtractor()
        features = ext.extract(_make_flow())
        result = manager.predict(features)
        total = sum(result["probabilities"].values())
        assert abs(total - 1.0) < 0.01

    def test_model_feature_names_match_extractor(self, manager) -> None:
        assert manager.feature_names == settings.FEATURE_NAMES

    def test_extract_predict_different_flows(self, manager) -> None:
        ext = FeatureExtractor()
        flows = [
            _make_flow(proto=6, dst_port=80),
            _make_flow(proto=17, dst_port=53, tcp_flags=[]),
            _make_flow(proto=6, dst_port=22),
        ]
        for flow in flows:
            features = ext.extract(flow)
            result = manager.predict(features)
            assert result["predicted_class"] is not None

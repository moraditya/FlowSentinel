"""
Tests for the live packet capture engine.

Verifies Flow, FlowAggregator, FeatureExtractor, and CaptureEngine
without requiring real network interfaces or scapy hardware access.
"""

from __future__ import annotations

import time

import numpy as np

from app.capture import (
    FLAG_MAP,
    CaptureEngine,
    FeatureExtractor,
    Flow,
    FlowAggregator,
)
from app.config import settings

# ── helpers ──────────────────────────────────────────────────────────

def _make_flow(**kwargs) -> Flow:
    """Create a ``Flow`` with sensible defaults, overridable via kwargs."""
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
        tcp_flags=[2, 18, 16, 1],  # SYN, SYN-ACK, ACK, FIN
        wrong_fragments=0,
        urgent_count=0,
    )
    defaults.update(kwargs)
    return Flow(**defaults)


# ══════════════════════════════════════════════════════════════════════
# FlowAggregator
# ══════════════════════════════════════════════════════════════════════

class TestFlowAggregator:
    def test_flush_all_empty(self):
        agg = FlowAggregator()
        assert agg.flush_all() == []

    def test_flush_expired_no_flows(self):
        agg = FlowAggregator()
        assert agg.flush_expired() == []

    def test_flush_all_returns_active_flows(self):
        agg = FlowAggregator()
        # Manually insert a flow
        key = ("10.0.0.1", "192.168.1.1", 80, 12345, 6)
        flow = _make_flow()
        agg._flows[key] = flow
        flushed = agg.flush_all()
        assert len(flushed) == 1
        assert agg.flush_all() == []  # cleared

# ══════════════════════════════════════════════════════════════════════
# FeatureExtractor
# ══════════════════════════════════════════════════════════════════════

class TestFeatureExtractor:
    def test_extract_returns_28_features(self):
        ext = FeatureExtractor()
        flow = _make_flow()
        features = ext.extract(flow)
        assert len(features) == 28
        assert set(features.keys()) == set(settings.FEATURE_NAMES)

    def test_no_host_level_features(self):
        """Host-level features should not be present in extracted output."""
        ext = FeatureExtractor()
        flow = _make_flow()
        features = ext.extract(flow)
        host_level = {
            "hot", "num_failed_logins", "logged_in", "num_compromised",
            "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds",
            "is_host_login", "is_guest_login",
        }
        assert host_level.isdisjoint(set(features.keys()))

    def test_duration_positive(self):
        ext = FeatureExtractor()
        flow = _make_flow()
        features = ext.extract(flow)
        assert features["duration"] >= 0

    def test_protocol_type_tcp(self):
        ext = FeatureExtractor()
        flow = _make_flow(proto=6)
        features = ext.extract(flow)
        assert features["protocol_type"] == 0  # TCP encoding

    def test_protocol_type_udp(self):
        ext = FeatureExtractor()
        flow = _make_flow(proto=17, tcp_flags=[])
        features = ext.extract(flow)
        assert features["protocol_type"] == 1  # UDP encoding

    def test_service_http(self):
        ext = FeatureExtractor()
        flow = _make_flow(dst_port=80)
        features = ext.extract(flow)
        assert features["service"] == 1  # HTTP encoding

    def test_service_ssh(self):
        ext = FeatureExtractor()
        flow = _make_flow(dst_port=22)
        features = ext.extract(flow)
        assert features["service"] == 3  # SSH encoding

    def test_service_unknown_port(self):
        ext = FeatureExtractor()
        flow = _make_flow(dst_port=9999)
        features = ext.extract(flow)
        assert features["service"] == 0  # unknown

    def test_src_dst_bytes(self):
        ext = FeatureExtractor()
        flow = _make_flow(src_bytes=500, dst_bytes=1000)
        features = ext.extract(flow)
        assert features["src_bytes"] == 500
        assert features["dst_bytes"] == 1000

    def test_land_same_ip_port(self):
        ext = FeatureExtractor()
        flow = _make_flow(
            src_ip="10.0.0.1", dst_ip="10.0.0.1",
            src_port=80, dst_port=80,
        )
        features = ext.extract(flow)
        assert features["land"] == 1

    def test_land_different(self):
        ext = FeatureExtractor()
        flow = _make_flow()
        features = ext.extract(flow)
        assert features["land"] == 0

    def test_wrong_fragment(self):
        ext = FeatureExtractor()
        flow = _make_flow(wrong_fragments=3)
        features = ext.extract(flow)
        assert features["wrong_fragment"] == 3

    def test_urgent(self):
        ext = FeatureExtractor()
        flow = _make_flow(urgent_count=2)
        features = ext.extract(flow)
        assert features["urgent"] == 2

    def test_flag_sf_normal_connection(self):
        ext = FeatureExtractor()
        # SYN(2), SYN-ACK(18), ACK(16), FIN(1)
        flow = _make_flow(tcp_flags=[2, 18, 16, 1])
        features = ext.extract(flow)
        assert features["flag"] == FLAG_MAP["SF"]

    def test_flag_s0_syn_only(self):
        ext = FeatureExtractor()
        flow = _make_flow(tcp_flags=[2])  # SYN only
        features = ext.extract(flow)
        assert features["flag"] == FLAG_MAP["S0"]

    def test_normalize_with_scaler(self):
        ext = FeatureExtractor()
        features_list = []
        for i in range(10):
            flow = _make_flow(src_bytes=i * 100, dst_bytes=i * 200)
            features_list.append(ext.extract(flow))

        matrix = np.array(
            [[f[name] for name in settings.FEATURE_NAMES] for f in features_list]
        )
        ext.fit_scaler(matrix)

        normalized = ext.normalize(features_list[5])
        assert isinstance(normalized, dict)
        assert len(normalized) == 28

    def test_normalize_without_scaler(self):
        ext = FeatureExtractor()
        flow = _make_flow()
        features = ext.extract(flow)
        normalized = ext.normalize(features)
        assert normalized == features

    def test_set_scaler(self):
        from sklearn.preprocessing import MinMaxScaler

        ext = FeatureExtractor()
        scaler = MinMaxScaler()
        ext.set_scaler(scaler)
        assert ext._scaler is scaler


# ══════════════════════════════════════════════════════════════════════
# CaptureEngine
# ══════════════════════════════════════════════════════════════════════

class TestCaptureEngine:
    def test_initial_state(self):
        engine = CaptureEngine()
        assert not engine.is_capturing
        status = engine.status
        assert status["is_capturing"] is False
        assert status["packets_captured"] == 0

    def test_status_keys(self):
        engine = CaptureEngine()
        status = engine.status
        expected_keys = {
            "is_capturing", "interface", "packets_captured",
            "flows_analyzed", "threats_detected", "uptime_seconds",
            "error",
        }
        assert set(status.keys()) == expected_keys

    def test_uptime_zero_when_not_started(self):
        engine = CaptureEngine()
        assert engine.status["uptime_seconds"] == 0.0

    def test_stop_without_start(self):
        engine = CaptureEngine()
        # Should not raise
        engine.stop()
        assert not engine.is_capturing

    def test_start_sets_running(self):
        """Verify start() flips state (without actually sniffing)."""
        engine = CaptureEngine()
        # Monkey-patch the thread so it does nothing
        engine._capture_loop = lambda *a: None  # type: ignore[assignment]
        engine.start(interface="lo0")
        assert engine.is_capturing
        assert engine.status["interface"] == "lo0"
        engine._running = False  # clean up

    def test_double_start_is_noop(self):
        engine = CaptureEngine()
        engine._running = True
        engine.start()  # should return immediately
        assert engine._thread is None  # no new thread created

    def test_stop_start_cycle_resets_state(self):
        """stop() then start() should produce clean state."""
        engine = CaptureEngine()
        engine._capture_loop = lambda *a: None  # type: ignore[assignment]
        engine.start(interface="lo0")
        assert engine.is_capturing
        engine._running = False
        engine.stop()
        assert not engine.is_capturing
        # Second start should work cleanly
        engine._capture_loop = lambda *a: None  # type: ignore[assignment]
        engine.start(interface="eth0")
        assert engine.is_capturing
        assert engine.status["interface"] == "eth0"
        assert engine.status["packets_captured"] == 0
        engine._running = False

    def test_stop_sets_stop_event(self):
        """stop() should signal the stop event for the sniff loop."""
        engine = CaptureEngine()
        assert not engine._stop_event.is_set()
        engine.stop()
        assert engine._stop_event.is_set()

    def test_start_clears_stop_event(self):
        """start() should clear the stop event."""
        engine = CaptureEngine()
        engine._stop_event.set()
        engine._capture_loop = lambda *a: None  # type: ignore[assignment]
        engine.start(interface="lo0")
        assert not engine._stop_event.is_set()
        engine._running = False

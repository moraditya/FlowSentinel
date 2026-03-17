"""
Live packet capture engine — sniff, aggregate flows, extract features.

Provides the real-time pipeline:

    scapy sniff → FlowAggregator → FeatureExtractor → AnomalyDetector → ModelManager

All heavy work runs in a daemon thread so the async API loop stays free.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np
from sklearn.preprocessing import MinMaxScaler

from app.config import settings

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
# Flow dataclass
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Flow:
    """Represents an aggregated network flow (one 5-tuple conversation)."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int  # 6=TCP, 17=UDP, 1=ICMP
    start_time: float  # time.time()
    last_time: float
    src_bytes: int = 0
    dst_bytes: int = 0
    src_packets: int = 0
    dst_packets: int = 0
    tcp_flags: list[int] = field(default_factory=list)  # collected TCP flags
    wrong_fragments: int = 0
    urgent_count: int = 0


# ══════════════════════════════════════════════════════════════════════
# FlowAggregator
# ══════════════════════════════════════════════════════════════════════

class FlowAggregator:
    """Collect packets into bidirectional flows keyed on a 5-tuple."""

    def __init__(
        self,
        idle_timeout: float = 5.0,
        active_timeout: float = 30.0,
    ) -> None:
        self._flows: dict[tuple, Flow] = {}
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout

    # ── helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> tuple:
        """Canonical 5-tuple key (sorted so both directions hit the same flow)."""
        forward = (src_ip, dst_ip, src_port, dst_port, proto)
        reverse = (dst_ip, src_ip, dst_port, src_port, proto)
        return min(forward, reverse)

    # ── public API ────────────────────────────────────────────────────

    def add_packet(self, packet, timestamp: float | None = None) -> Flow | None:
        """Process a scapy packet and maybe return a completed ``Flow``.

        Parameters
        ----------
        packet : scapy packet
        timestamp : float, optional
            Override for the current time (used by PCAP replay to honour
            original capture timestamps).  Defaults to ``time.time()``.
        """
        from scapy.all import IP, TCP, UDP

        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        pkt_len = len(ip_layer)

        src_port = 0
        dst_port = 0
        tcp_flag_val: int | None = None

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flag_val = int(tcp_layer.flags)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport

        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        now = timestamp if timestamp is not None else time.time()

        if key in self._flows:
            flow = self._flows[key]

            # Check timeouts before updating
            idle_expired = (now - flow.last_time) > self.idle_timeout
            active_expired = (now - flow.start_time) > self.active_timeout

            if idle_expired or active_expired:
                completed = flow
                del self._flows[key]
                self.add_packet(packet)
                return completed

            # Update existing flow
            flow.last_time = now
            if src_ip == flow.src_ip:
                flow.src_bytes += pkt_len
                flow.src_packets += 1
            else:
                flow.dst_bytes += pkt_len
                flow.dst_packets += 1

            if tcp_flag_val is not None:
                flow.tcp_flags.append(tcp_flag_val)

            # Wrong fragment detection (IP fragment offset > 0 but MF not set)
            if ip_layer.frag > 0 and not (ip_layer.flags & 0x1):
                flow.wrong_fragments += 1

            # Urgent pointer
            if packet.haslayer(TCP) and packet[TCP].urgptr > 0:
                flow.urgent_count += 1

            return None

        # New flow
        flow = Flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            start_time=now,
            last_time=now,
            src_bytes=pkt_len,
            dst_bytes=0,
            src_packets=1,
            dst_packets=0,
            tcp_flags=[tcp_flag_val] if tcp_flag_val is not None else [],
            wrong_fragments=1 if (ip_layer.frag > 0 and not (ip_layer.flags & 0x1)) else 0,
            urgent_count=(1 if (packet.haslayer(TCP) and packet[TCP].urgptr > 0) else 0),
        )
        self._flows[key] = flow
        return None

    def flush_expired(self, now: float | None = None) -> list[Flow]:
        """Return all flows whose idle or active timeout has passed."""
        now = now if now is not None else time.time()
        expired: list[Flow] = []
        keys_to_remove: list[tuple] = []

        for key, flow in self._flows.items():
            idle_expired = (now - flow.last_time) > self.idle_timeout
            active_expired = (now - flow.start_time) > self.active_timeout
            if idle_expired or active_expired:
                expired.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._flows[key]

        return expired

    def flush_all(self) -> list[Flow]:
        """Return every active flow (used during shutdown)."""
        flows = list(self._flows.values())
        self._flows.clear()
        return flows


# ══════════════════════════════════════════════════════════════════════
# Feature extraction
# ══════════════════════════════════════════════════════════════════════

# Port → numeric service encoding
SERVICE_MAP: dict[int, int] = {
    80: 1, 443: 1,      # http / https
    21: 2, 20: 2,        # ftp-data / ftp
    22: 3,               # ssh
    23: 4,               # telnet
    25: 5,               # smtp
    53: 6,               # dns
    110: 7,              # pop3
    143: 8,              # imap
    993: 8,              # imaps
    995: 7,              # pop3s
    3306: 9,             # mysql
    5432: 9,             # postgresql
    8080: 1,             # http-alt
}

# TCP flag patterns → numeric flag encoding
FLAG_MAP: dict[str, int] = {
    "SF": 0,     # normal establishment + close
    "S0": 1,     # SYN sent, no reply
    "REJ": 2,    # connection rejected (RST)
    "RSTR": 3,   # reset from server
    "S1": 4,     # SYN-ACK seen, no final ACK
    "S2": 5,     # established, FIN from source only
    "S3": 6,     # established, FIN from dest only
    "OTH": 7,    # other
}

# Individual TCP flag bits
_SYN = 0x02
_ACK = 0x10
_FIN = 0x01
_RST = 0x04
_SYN_ACK = _SYN | _ACK  # 0x12

# Protocol → numeric encoding
PROTOCOL_MAP: dict[int, int] = {
    6: 0,    # TCP
    17: 1,   # UDP
    1: 2,    # ICMP
}


class FeatureExtractor:
    """Convert a ``Flow`` into the 28 observable feature vector."""

    def __init__(self) -> None:
        # Rolling buffer of recent connections for time-window stats.
        # Each entry: (timestamp, dst_ip, dst_port, proto,
        #              had_syn_error, had_rej_error, src_port, src_ip)
        self._recent_connections: deque = deque(maxlen=500)
        self._scaler: MinMaxScaler | None = None

    # ── public API ────────────────────────────────────────────────────

    def extract(self, flow: Flow) -> dict[str, float]:
        """Convert *flow* into a dict of the 28 observable feature values."""
        duration = max(0.0, flow.last_time - flow.start_time)
        protocol_type = float(PROTOCOL_MAP.get(flow.proto, 0))
        service = float(SERVICE_MAP.get(flow.dst_port, 0))

        flag_str = self._infer_flag(flow)
        flag = float(FLAG_MAP.get(flag_str, FLAG_MAP["OTH"]))

        land = 1.0 if (flow.src_ip == flow.dst_ip and flow.src_port == flow.dst_port) else 0.0

        # Determine error flags for time-window bookkeeping
        had_syn_error = flag_str in ("S0", "S1")
        had_rej_error = flag_str in ("REJ", "RSTR")

        # Time-window features
        tw = self._compute_time_window_stats(flow, had_syn_error, had_rej_error)

        # Register this connection *after* computing window stats so it
        # does not count itself in the window.
        self._recent_connections.append((
            flow.start_time,
            flow.dst_ip,
            flow.dst_port,
            flow.proto,
            had_syn_error,
            had_rej_error,
            flow.src_port,
            flow.src_ip,
        ))

        features: dict[str, float] = {
            # ── basic (9) ────────────────────────────────────────────
            "duration": duration,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": float(flow.src_bytes),
            "dst_bytes": float(flow.dst_bytes),
            "land": land,
            "wrong_fragment": float(flow.wrong_fragments),
            "urgent": float(flow.urgent_count),
        }

        # ── time-window features (19) ────────────────────────────────
        features.update(tw)

        # Sanity: ensure every canonical name is present
        for name in settings.FEATURE_NAMES:
            features.setdefault(name, 0.0)

        return features

    # ── flag inference ────────────────────────────────────────────────

    def _infer_flag(self, flow: Flow) -> str:
        """Infer the connection flag string from collected TCP flags."""
        if flow.proto != 6:
            # Non-TCP: use SF for completed UDP/ICMP, OTH otherwise
            if flow.src_packets > 0 and flow.dst_packets > 0:
                return "SF"
            return "OTH"

        flags = flow.tcp_flags
        if not flags:
            return "OTH"

        has_syn = any(f & _SYN and not (f & _ACK) for f in flags)
        has_syn_ack = any(f & _SYN_ACK == _SYN_ACK for f in flags)
        has_fin = any(f & _FIN for f in flags)
        has_rst = any(f & _RST for f in flags)
        has_ack = any(f & _ACK and not (f & _SYN) for f in flags)

        if has_syn and has_syn_ack and has_fin:
            return "SF"  # normal connection
        if has_syn and has_syn_ack and has_rst:
            return "RSTR"  # reset from server after establishment
        if has_syn and not has_syn_ack and not has_rst:
            return "S0"  # SYN only, no reply
        if has_syn and has_syn_ack and not has_ack:
            return "S1"  # SYN-ACK seen, no final ACK
        if has_rst and not has_syn_ack:
            return "REJ"  # immediate rejection
        if has_syn and has_ack and has_fin and not has_rst:
            # FIN only from source
            return "S2"
        return "OTH"

    # ── time-window statistics ────────────────────────────────────────

    def _compute_time_window_stats(
        self,
        flow: Flow,
        had_syn_error: bool,
        had_rej_error: bool,
    ) -> dict[str, float]:
        """Compute features 23-41 from the recent-connections buffer."""
        now = flow.start_time
        dst_ip = flow.dst_ip
        dst_port = flow.dst_port
        src_port = flow.src_port

        # ── 2-second window ──────────────────────────────────────────
        two_sec_window = [
            c for c in self._recent_connections if (now - c[0]) <= 2.0
        ]

        same_dst = [c for c in two_sec_window if c[1] == dst_ip]
        same_srv = [c for c in two_sec_window if c[2] == dst_port]

        count = float(len(same_dst))
        srv_count = float(len(same_srv))

        def _safe_rate(subset: list, total: float) -> float:
            if total == 0:
                return 0.0
            return len(subset) / total

        serror_rate = _safe_rate([c for c in same_dst if c[4]], count)
        srv_serror_rate = _safe_rate([c for c in same_srv if c[4]], srv_count)
        rerror_rate = _safe_rate([c for c in same_dst if c[5]], count)
        srv_rerror_rate = _safe_rate([c for c in same_srv if c[5]], srv_count)

        same_srv_in_dst = [c for c in same_dst if c[2] == dst_port]
        same_srv_rate = _safe_rate(same_srv_in_dst, count)
        diff_srv_rate = (1.0 - same_srv_rate) if count > 0 else 0.0

        diff_host_in_srv = [c for c in same_srv if c[1] != dst_ip]
        srv_diff_host_rate = _safe_rate(diff_host_in_srv, srv_count)

        # ── 100-connection host window ───────────────────────────────
        # Last 100 entries with the same dst_ip
        host_window = [c for c in self._recent_connections if c[1] == dst_ip]
        host_window = host_window[-100:] if len(host_window) > 100 else host_window

        dst_host_count = float(len(host_window))

        host_same_srv = [c for c in host_window if c[2] == dst_port]
        dst_host_srv_count = float(len(host_same_srv))

        dst_host_same_srv_rate = (
            dst_host_srv_count / dst_host_count if dst_host_count > 0 else 0.0
        )
        dst_host_diff_srv_rate = (
            (1.0 - dst_host_same_srv_rate) if dst_host_count > 0 else 0.0
        )

        host_same_src_port = [c for c in host_window if c[6] == src_port]
        dst_host_same_src_port_rate = (
            len(host_same_src_port) / dst_host_count if dst_host_count > 0 else 0.0
        )

        # Fraction of connections in srv window that go to a different host
        srv_window = [c for c in self._recent_connections if c[2] == dst_port]
        srv_window = srv_window[-100:] if len(srv_window) > 100 else srv_window
        srv_diff_host = [c for c in srv_window if c[1] != dst_ip]
        dst_host_srv_diff_host_rate = (
            len(srv_diff_host) / len(srv_window) if len(srv_window) > 0 else 0.0
        )

        dst_host_serror_rate = _safe_rate(
            [c for c in host_window if c[4]], dst_host_count
        )
        dst_host_srv_serror_rate = _safe_rate(
            [c for c in host_same_srv if c[4]], dst_host_srv_count
        )
        dst_host_rerror_rate = _safe_rate(
            [c for c in host_window if c[5]], dst_host_count
        )
        dst_host_srv_rerror_rate = _safe_rate(
            [c for c in host_same_srv if c[5]], dst_host_srv_count
        )

        return {
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "srv_serror_rate": srv_serror_rate,
            "rerror_rate": rerror_rate,
            "srv_rerror_rate": srv_rerror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
            "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
            "dst_host_serror_rate": dst_host_serror_rate,
            "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
            "dst_host_rerror_rate": dst_host_rerror_rate,
            "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
        }

    # ── scaling ──────────────────────────────────────────────────────

    def fit_scaler(self, feature_matrix: np.ndarray) -> None:
        """Fit a ``MinMaxScaler`` on a baseline feature matrix."""
        self._scaler = MinMaxScaler()
        self._scaler.fit(feature_matrix)

    def set_scaler(self, scaler: MinMaxScaler) -> None:
        """Set an externally fitted scaler."""
        self._scaler = scaler

    def normalize(self, features: dict[str, float]) -> dict[str, float]:
        """Apply the fitted scaler. If no scaler, return *features* as-is."""
        if self._scaler is None:
            return features

        vec = np.array(
            [features[name] for name in settings.FEATURE_NAMES], dtype=np.float64
        ).reshape(1, -1)
        scaled = self._scaler.transform(vec).flatten()
        return {
            name: float(scaled[i]) for i, name in enumerate(settings.FEATURE_NAMES)
        }


# ══════════════════════════════════════════════════════════════════════
# CaptureEngine
# ══════════════════════════════════════════════════════════════════════

class CaptureEngine:
    """Orchestrates live packet capture, flow aggregation, and classification.

    Runs scapy's ``sniff()`` in a daemon thread, feeding completed flows
    through the feature extractor, anomaly detector, and attack
    classifier.

    Thread safety: a ``threading.Lock`` protects all mutable state that is
    read by the async API thread and written by the daemon capture thread.
    """

    _MAX_SCORE_HISTORY: int = 10_000

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._running: bool = False
        self._aggregator: FlowAggregator = FlowAggregator()
        self._extractor: FeatureExtractor = FeatureExtractor()
        self._interface: str | None = None
        self._start_time: float | None = None
        self._stats: dict[str, int] = {"packets": 0, "flows": 0, "threats": 0}
        self._error: str | None = None
        self._anomaly_scores: deque[float] = deque(maxlen=self._MAX_SCORE_HISTORY)
        self._anomaly_count: int = 0
        self._classifications: dict[str, int] = {}

        # Event callback — set externally (e.g. broadcaster.publish)
        self._on_event: Callable[[dict], None] | None = None

        # Optional per-flow timing callback for replay instrumentation.
        # Signature: callback(stage_timings: dict[str, float])
        self._timing_hook: Callable[[dict[str, float]], None] | None = None
        self._ingest_timing: dict[str, float] | None = None

        self._model_manager = None  # set externally (ModelManager)
        self._anomaly_detector = None  # set externally (AnomalyDetector)

    # ── properties ────────────────────────────────────────────────────

    @property
    def is_capturing(self) -> bool:
        return self._running

    @property
    def status(self) -> dict:
        with self._lock:
            return {
                "is_capturing": self._running,
                "interface": self._interface,
                "packets_captured": self._stats["packets"],
                "flows_analyzed": self._stats["flows"],
                "threats_detected": self._stats["threats"],
                "uptime_seconds": (
                    time.time() - self._start_time
                    if self._start_time and self._running
                    else 0.0
                ),
                "error": self._error,
            }

    @property
    def detection_stats(self) -> dict:
        """Live Isolation Forest detection metrics."""
        with self._lock:
            scores = list(self._anomaly_scores)
            anomaly_count = self._anomaly_count
            threats = self._stats["threats"]
            classifications = dict(self._classifications)

        total = len(scores)
        if total == 0:
            return {
                "total_flows_scored": 0,
                "anomalies_detected": 0,
                "anomaly_rate": 0.0,
                "threats_classified": threats,
                "score_distribution": [],
                "classifications": {},
                "mean_score": 0.0,
                "min_score": 0.0,
                "max_score": 0.0,
            }

        hist_min = min(scores)
        hist_max = max(scores)
        n_bins = 10
        if hist_max == hist_min:
            distribution = [{"range_start": hist_min, "range_end": hist_max, "count": total}]
        else:
            bin_width = (hist_max - hist_min) / n_bins
            distribution = []
            for i in range(n_bins):
                lo = hist_min + i * bin_width
                hi = lo + bin_width
                count = sum(1 for s in scores if lo <= s < hi or (i == n_bins - 1 and s == hi))
                distribution.append({
                    "range_start": round(lo, 4),
                    "range_end": round(hi, 4),
                    "count": count,
                })

        return {
            "total_flows_scored": total,
            "anomalies_detected": anomaly_count,
            "anomaly_rate": round(anomaly_count / total, 4) if total > 0 else 0.0,
            "threats_classified": threats,
            "score_distribution": distribution,
            "classifications": classifications,
            "mean_score": round(sum(scores) / total, 4),
            "min_score": round(min(scores), 4),
            "max_score": round(max(scores), 4),
        }

    @property
    def anomaly_scores(self) -> list[float]:
        """Thread-safe copy of anomaly scores for external use (e.g. CSV export)."""
        with self._lock:
            return list(self._anomaly_scores)

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self, interface: str = "en0", bpf_filter: str = "") -> None:
        """Start capture in a background daemon thread."""
        if self._running:
            return

        # Reset all mutable state for a clean start
        self._stop_event.clear()
        with self._lock:
            self._running = True
            self._error = None
            self._interface = interface
            self._start_time = time.time()
            self._stats = {"packets": 0, "flows": 0, "threats": 0}
            self._anomaly_scores = deque(maxlen=self._MAX_SCORE_HISTORY)
            self._anomaly_count = 0
            self._classifications = {}

        # Fresh aggregator and extractor so no stale state leaks
        self._aggregator = FlowAggregator()
        self._extractor = FeatureExtractor()

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, bpf_filter),
            daemon=True,
        )
        self._thread.start()
        logger.info("Capture started on %s", interface)

    def stop(self) -> None:
        """Signal the capture thread to stop and flush remaining flows."""
        self._stop_event.set()
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        # Flush remaining flows (with a timeout guard)
        try:
            remaining = self._aggregator.flush_all()
        except Exception:
            remaining = []
            logger.warning("flush_all() failed during stop")
        for flow in remaining:
            self._process_flow(flow)
        logger.info("Capture stopped")

    # ── internal loop ────────────────────────────────────────────────

    def _capture_loop(self, interface: str, bpf_filter: str) -> None:
        """Scapy ``sniff()`` loop — runs in the background thread.

        Uses short 1-second ``timeout`` sniff bursts so the thread checks
        ``_stop_event`` at least once per second, ensuring ``stop()``
        terminates deterministically even on quiet interfaces.
        """
        from scapy.all import sniff

        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=interface,
                    prn=self._packet_handler,
                    filter=bpf_filter or None,
                    store=False,
                    timeout=1,
                )
        except PermissionError:
            msg = (
                "Permission denied — packet capture requires root. "
                "Restart the backend with: sudo uvicorn app.main:app --host 0.0.0.0 --port 8000"
            )
            with self._lock:
                self._error = msg
                self._running = False
            logger.error("Capture failed: %s", msg)
        except Exception as exc:
            with self._lock:
                self._error = str(exc)
                self._running = False
            logger.exception("Capture loop crashed")

    def ingest_packet(self, packet, timestamp: float | None = None) -> None:
        """Shared ingestion seam used by both live capture and PCAP replay.

        Increments packet count, feeds the packet to the aggregator, and
        processes any completed or expired flows.  When ``_timing_hook``
        is set, parse and aggregation latency is measured here and
        attached to the stage timings reported by ``_process_flow``.
        """
        timed = self._timing_hook is not None
        if timed:
            t_parse_start = time.perf_counter()

        with self._lock:
            self._stats["packets"] += 1

        completed = self._aggregator.add_packet(packet, timestamp=timestamp)

        if timed:
            t_aggregated = time.perf_counter()
            self._ingest_timing = {
                "parse_ms": (t_aggregated - t_parse_start) * 1000,
            }
        else:
            self._ingest_timing = None

        if completed:
            self._process_flow(completed)
        for flow in self._aggregator.flush_expired(now=timestamp):
            self._process_flow(flow)

    def _packet_handler(self, packet) -> None:
        """Called per-packet by scapy's ``sniff``.  Delegates to ``ingest_packet``."""
        self.ingest_packet(packet)

    def _process_flow(self, flow: Flow) -> None:
        """Extract features, run anomaly detection, classify if anomalous."""
        timed = self._timing_hook is not None
        if timed:
            t_start = time.perf_counter()

        with self._lock:
            self._stats["flows"] += 1

        # ── Feature extraction ────────────────────────────────────────
        features = self._extractor.extract(flow)
        if timed:
            t_features = time.perf_counter()

        # Defaults
        anomaly_score = 0.0
        is_anomaly = False
        predicted_class = "normal"
        confidence = 1.0
        is_attack = False

        # Feed samples during baseline collection
        if self._anomaly_detector and self._anomaly_detector.status == "collecting":
            self._anomaly_detector.add_baseline_sample(features)

        # ── Anomaly scoring ───────────────────────────────────────────
        if self._anomaly_detector and self._anomaly_detector.status == "ready":
            anomaly_score = self._anomaly_detector.score(features)
            is_anomaly = self._anomaly_detector.is_anomaly(features)

            with self._lock:
                self._anomaly_scores.append(anomaly_score)
                if is_anomaly:
                    self._anomaly_count += 1
        if timed:
            t_score = time.perf_counter()

        # ── Classification ────────────────────────────────────────────
        if is_anomaly and self._model_manager and self._model_manager.is_loaded:
            result = self._model_manager.predict(features)
            predicted_class = result["predicted_class"]
            confidence = result["confidence"]
            is_attack = result["is_attack"]
            with self._lock:
                if is_attack:
                    self._stats["threats"] += 1
                self._classifications[predicted_class] = (
                    self._classifications.get(predicted_class, 0) + 1
                )
        if timed:
            t_classify = time.perf_counter()

        # ── Event publish ─────────────────────────────────────────────
        event = {
            "source": "live",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(flow.proto, "OTHER"),
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly,
            "predicted_class": predicted_class if is_anomaly else None,
            "confidence": confidence if is_anomaly else None,
            "is_attack": is_attack,
            "features": {
                k: round(v, 6) for k, v in features.items()
            },
        }

        if self._on_event:
            try:
                self._on_event(event)
            except Exception:
                pass
        if timed:
            t_publish = time.perf_counter()

        # ── Report stage timings ──────────────────────────────────────
        if timed:
            stage = {
                "parse_ms": 0.0,
                "features_ms": (t_features - t_start) * 1000,
                "score_ms": (t_score - t_features) * 1000,
                "classify_ms": (t_classify - t_score) * 1000,
                "publish_ms": (t_publish - t_classify) * 1000,
                "total_ms": (t_publish - t_start) * 1000,
            }
            # Merge parse/aggregation timing from ingest_packet
            if self._ingest_timing:
                stage["parse_ms"] = self._ingest_timing["parse_ms"]
            self._timing_hook(stage)

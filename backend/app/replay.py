"""
PCAP replay engine — deterministic demo without root or live traffic.

Reads packets from ``.pcap`` files and feeds them through the existing
``CaptureEngine.ingest_packet`` seam so the full pipeline (flow
aggregation → feature extraction → anomaly scoring → classification →
WebSocket broadcast) fires exactly as it would for live traffic.

Replay keeps its own stats separate from live capture stats.
Replay baseline bootstrap does NOT persist to disk (preserves the
user's real baseline).
"""

from __future__ import annotations

import logging
import statistics
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Status model
_IDLE = "idle"
_BOOTSTRAPPING = "bootstrapping_baseline"
_REPLAYING = "replaying"
_COMPLETED = "completed"
_ERROR = "error"

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo"

SCENARIOS: dict[str, list[str]] = {
    "benign": ["benign.pcap"],
    "port_scan": ["port_scan.pcap"],
    "brute_force": ["brute_force.pcap"],
    "mixed": ["benign.pcap", "port_scan.pcap", "brute_force.pcap"],
}


class ReplayEngine:
    """Replay PCAP files through the live capture pipeline.

    Keeps its own packet/flow/latency stats — does not pollute the
    live ``CaptureEngine`` stats.
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._status: str = _IDLE
        self._error: str | None = None
        self._scenario: str | None = None
        self._speed: float = 1.0

        # Replay-specific stats (separate from live capture)
        self._lock = threading.Lock()
        self._packets_replayed: int = 0
        self._flows_processed: int = 0
        self._start_time: float | None = None
        self._end_time: float | None = None
        self._latencies: list[float] = []
        # Per-stage timing from _process_flow
        self._stage_timings: list[dict[str, float]] = []

        # Replay-specific baseline summary (survives detector restore)
        self._baseline_summary: dict[str, dict[str, float]] = {}

        # Set externally during wiring
        self._capture_engine: Any = None
        self._anomaly_detector: Any = None

    # ── Properties ────────────────────────────────────────────────────

    @property
    def is_replaying(self) -> bool:
        return self._status in (_BOOTSTRAPPING, _REPLAYING)

    @property
    def status(self) -> dict[str, Any]:
        with self._lock:
            if self._start_time:
                if self.is_replaying:
                    elapsed = time.time() - self._start_time
                elif self._end_time:
                    elapsed = self._end_time - self._start_time
                else:
                    elapsed = 0.0
            else:
                elapsed = 0.0
            lats = list(self._latencies)
            stages = list(self._stage_timings)
            pkts = self._packets_replayed
            flows = self._flows_processed

        # Aggregate packet-level latency
        latency_stats: dict[str, float] = {}
        if lats:
            lats_sorted = sorted(lats)
            n = len(lats_sorted)
            latency_stats = {
                "mean_ms": round(statistics.mean(lats_sorted) * 1000, 3),
                "p50_ms": round(lats_sorted[n // 2] * 1000, 3),
                "p95_ms": round(lats_sorted[int(n * 0.95)] * 1000, 3),
                "p99_ms": round(lats_sorted[int(n * 0.99)] * 1000, 3),
            }

        # Per-stage breakdown (from _process_flow timing hook)
        stage_breakdown: dict[str, dict[str, float]] = {}
        if stages:
            for key in ("parse_ms", "features_ms", "score_ms", "classify_ms", "publish_ms", "total_ms"):
                vals = sorted(s[key] for s in stages)
                n = len(vals)
                stage_breakdown[key] = {
                    "mean": round(statistics.mean(vals), 4),
                    "p50": round(vals[n // 2], 4),
                    "p95": round(vals[int(n * 0.95)], 4),
                    "p99": round(vals[int(n * 0.99)], 4),
                }

        return {
            "state": self._status,
            "scenario": self._scenario,
            "speed": self._speed,
            "packets_replayed": pkts,
            "flows_processed": flows,
            "elapsed_seconds": round(elapsed, 2),
            "throughput_fps": round(flows / elapsed, 2) if elapsed > 0.1 else 0.0,
            "latency": latency_stats,
            "stage_timing": stage_breakdown,
            "error": self._error,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────

    def start(
        self,
        scenario: str,
        speed: float = 1.0,
    ) -> None:
        """Start replaying a scenario in a background thread."""
        if self.is_replaying:
            raise RuntimeError("Replay already in progress")

        if self._capture_engine and self._capture_engine.is_capturing:
            raise RuntimeError("Live capture is active — stop it before replaying")

        if scenario not in SCENARIOS:
            raise ValueError(
                f"Unknown scenario '{scenario}'. Available: {sorted(SCENARIOS)}"
            )

        pcap_files = [DEMO_DIR / name for name in SCENARIOS[scenario]]
        missing = [p for p in pcap_files if not p.exists()]
        if missing:
            raise FileNotFoundError(
                f"Missing PCAP files: {[str(m) for m in missing]}"
            )

        self._stop_event.clear()
        self._scenario = scenario
        self._speed = speed
        self._error = None
        # Set status BEFORE spawning the thread so the API never returns
        # idle after a successful start.
        is_mixed = scenario == "mixed"
        self._status = _BOOTSTRAPPING if is_mixed else _REPLAYING

        with self._lock:
            self._packets_replayed = 0
            self._flows_processed = 0
            self._latencies = []
            self._stage_timings = []
            self._start_time = time.time()
            self._end_time = None

        self._thread = threading.Thread(
            target=self._replay_loop,
            args=(scenario, pcap_files, speed),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the replay thread, clean up, and reset to idle."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

        # Clean up anomaly detector if stuck in collecting from bootstrap
        detector = self._anomaly_detector
        if detector and detector.status == "collecting":
            detector.cancel_collection()

        # Always reset to idle (including from completed/error state)
        self._status = _IDLE

        with self._lock:
            if self._start_time and not self._end_time:
                self._end_time = time.time()

    # ── Internal ──────────────────────────────────────────────────────

    def _replay_loop(
        self,
        scenario: str,
        pcap_files: list[Path],
        speed: float,
    ) -> None:
        """Background thread: read PCAPs and feed packets to the pipeline."""
        from app.capture import FeatureExtractor, FlowAggregator

        engine = self._capture_engine
        detector = self._anomaly_detector
        if engine is None:
            self._status = _ERROR
            self._error = "CaptureEngine not wired"
            return

        from collections import deque

        # ── Snapshot ALL shared state so replay is fully isolated ─────
        saved_aggregator = engine._aggregator
        saved_extractor = engine._extractor
        saved_timing_hook = engine._timing_hook
        saved_on_event = engine._on_event
        saved_stats = None
        saved_anomaly_scores = None
        saved_anomaly_count = None
        saved_classifications = None

        # Detector state (model, scaler, status, buffer, timing)
        saved_detector_model = None
        saved_detector_scaler = None
        saved_detector_status = None
        saved_detector_samples = None
        saved_detector_buffer = None
        saved_detector_started_at = None
        saved_detector_duration = None

        saved_detector_means = None
        saved_detector_stds = None

        if detector:
            saved_detector_model = detector._model
            saved_detector_scaler = detector._scaler
            saved_detector_status = detector._status
            saved_detector_samples = detector._samples_collected
            saved_detector_buffer = list(detector._collection_buffer)
            saved_detector_started_at = detector._started_at
            saved_detector_duration = detector._duration_seconds
            saved_detector_means = detector._feature_means
            saved_detector_stds = detector._feature_stds

        try:
            is_mixed = scenario == "mixed"
            baseline_file = pcap_files[0] if is_mixed else None
            attack_files = pcap_files[1:] if is_mixed else pcap_files

            # Swap in replay-private aggregator/extractor + timing hook
            engine._aggregator = FlowAggregator()
            engine._extractor = FeatureExtractor()
            engine._timing_hook = self._record_stage_timing

            # Wrap event callback to tag events with source=replay
            if saved_on_event:
                def _replay_event_wrapper(evt: dict) -> None:
                    evt["source"] = "replay"
                    saved_on_event(evt)
                engine._on_event = _replay_event_wrapper

            # Save and reset engine stats + detection analytics
            with engine._lock:
                saved_stats = dict(engine._stats)
                saved_anomaly_scores = engine._anomaly_scores
                saved_anomaly_count = engine._anomaly_count
                saved_classifications = dict(engine._classifications)
                engine._stats = {"packets": 0, "flows": 0, "threats": 0}
                engine._anomaly_scores = deque(maxlen=engine._MAX_SCORE_HISTORY)
                engine._anomaly_count = 0
                engine._classifications = {}

            # ── Phase 1: bootstrap baseline (mixed scenario) ──────────
            if is_mixed and baseline_file and detector:
                logger.info("Replay: bootstrapping baseline from %s", baseline_file.name)

                detector.start_collection(duration_seconds=9999)
                self._replay_pcap(baseline_file, engine, speed)

                if self._stop_event.is_set():
                    detector.cancel_collection()
                    return

                for flow in engine._aggregator.flush_all():
                    engine._process_flow(flow)

                if detector.samples_collected > 0:
                    self._finish_demo_baseline(detector, engine)
                else:
                    logger.warning("Replay: no samples collected during baseline")
                    detector.cancel_collection()

            # ── Phase 2: replay attack traffic ────────────────────────
            self._status = _REPLAYING

            if not is_mixed and detector and detector.status != "ready":
                self._status = _ERROR
                self._error = "Baseline not trained. Use --scenario mixed or train baseline first."
                return

            engine._aggregator = FlowAggregator()

            for pcap_path in attack_files:
                if self._stop_event.is_set():
                    break
                logger.info("Replay: playing %s", pcap_path.name)
                self._replay_pcap(pcap_path, engine, speed)

            for flow in engine._aggregator.flush_all():
                engine._process_flow(flow)

            if not self._stop_event.is_set():
                self._status = _COMPLETED
                with self._lock:
                    self._end_time = time.time()
                logger.info("Replay: completed. %s", self._summary_line())

        except Exception as exc:
            self._status = _ERROR
            self._error = str(exc)
            with self._lock:
                self._end_time = time.time()
            logger.exception("Replay failed")

        finally:
            # ── Restore ALL shared state ─────────────────────────────
            engine._aggregator = saved_aggregator
            engine._extractor = saved_extractor
            engine._timing_hook = saved_timing_hook
            engine._on_event = saved_on_event
            if saved_stats is not None:
                with engine._lock:
                    engine._stats = saved_stats
                    engine._anomaly_scores = saved_anomaly_scores
                    engine._anomaly_count = saved_anomaly_count
                    engine._classifications = saved_classifications

            if detector and saved_detector_status is not None:
                detector._model = saved_detector_model
                detector._scaler = saved_detector_scaler
                detector._status = saved_detector_status
                detector._samples_collected = saved_detector_samples
                detector._collection_buffer = saved_detector_buffer
                detector._started_at = saved_detector_started_at
                detector._duration_seconds = saved_detector_duration
                detector._feature_means = saved_detector_means
                detector._feature_stds = saved_detector_stds

    def _finish_demo_baseline(self, detector: Any, engine: Any) -> None:
        """Train the demo baseline in-memory without persisting to disk."""
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import MinMaxScaler

        if not detector._collection_buffer:
            return

        X = np.vstack(detector._collection_buffer)

        # Compute per-feature stats
        means = np.mean(X, axis=0)
        stds = np.std(X, axis=0)
        detector._feature_means = means
        detector._feature_stds = stds

        # Stash on the replay engine so it survives detector restore
        from app.config import settings
        self._baseline_summary = {
            name: {"mean": round(float(means[i]), 6), "std": round(float(stds[i]), 6)}
            for i, name in enumerate(settings.FEATURE_NAMES)
        }

        detector._scaler = MinMaxScaler()
        detector._scaler.fit(X)

        detector._model = IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
        detector._model.fit(X)
        detector._status = "ready"
        detector._started_at = None
        detector._duration_seconds = 0

        if detector._scaler is not None:
            engine._extractor.set_scaler(detector._scaler)

        logger.info(
            "Replay: demo baseline trained on %d samples (in-memory only, not saved)",
            len(detector._collection_buffer),
        )

    def _record_stage_timing(self, timings: dict[str, float]) -> None:
        """Timing hook called by CaptureEngine._process_flow for each flow."""
        with self._lock:
            self._stage_timings.append(timings)

    def _replay_pcap(self, path: Path, engine: Any, speed: float) -> None:
        """Replay a single PCAP file with timestamp-aware pacing."""
        from scapy.all import rdpcap

        packets = rdpcap(str(path))
        if not packets:
            return

        prev_ts: float | None = None

        for pkt in packets:
            if self._stop_event.is_set():
                break

            pkt_ts = float(pkt.time)

            # Pacing: sleep based on inter-packet gap scaled by speed
            if prev_ts is not None and speed > 0:
                gap = pkt_ts - prev_ts
                if gap > 0 and speed != float("inf"):
                    time.sleep(gap / speed)
            prev_ts = pkt_ts

            # Feed through shared ingestion seam with original timestamp
            t0 = time.perf_counter()
            engine.ingest_packet(pkt, timestamp=pkt_ts)
            elapsed = time.perf_counter() - t0

            with self._lock:
                self._packets_replayed += 1
                self._latencies.append(elapsed)
                # Track flows from engine stats (will be restored in finally)
                self._flows_processed = engine._stats.get("flows", 0)

    def _summary_line(self) -> str:
        s = self.status
        lat = s.get("latency", {})
        return (
            f"packets={s['packets_replayed']} "
            f"flows={s['flows_processed']} "
            f"throughput={s['throughput_fps']}fps "
            f"p50={lat.get('p50_ms', '?')}ms "
            f"p95={lat.get('p95_ms', '?')}ms"
        )

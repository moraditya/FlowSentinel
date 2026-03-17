"""
FastAPI application — Network Intrusion Detection System.

Exposes prediction, analytics, capture, baseline, and simulation
endpoints.  The primary detection system is an Isolation Forest
anomaly detector trained on the user's own baseline traffic.
Anomalous flows are optionally classified by a multiclass XGBoost
model trained on labeled attack data.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from app.anomaly import AnomalyDetector
from app.auth import verify_api_key
from app.broadcast import BroadcastManager
from app.capture import CaptureEngine
from app.config import settings
from app.model import ModelManager
from app.replay import ReplayEngine
from app.schemas import (
    BaselineCollectRequest,
    BaselineStatusResponse,
    BatchPredictionRequest,
    CaptureStartRequest,
    CaptureStatusResponse,
    ConfusionMatrixResponse,
    DatasetStatsResponse,
    FeatureImportanceItem,
    HealthResponse,
    MetricsResponse,
    PredictionRequest,
    PredictionResponse,
    SimulationEvent,
)

# ── Logging ──────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

# ── Singleton instances ──────────────────────────────────────────────

manager = ModelManager()
capture_engine = CaptureEngine()
anomaly_detector = AnomalyDetector()
broadcaster = BroadcastManager()
replay_engine = ReplayEngine()

# Handle to the current auto-finish background task so we can cancel it.
_baseline_task: asyncio.Task | None = None

# ── Lifespan (startup / shutdown) ────────────────────────────────────


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Load or train models and restore baseline on startup."""
    # Production mode validation — fail fast on insecure config
    settings.validate_production()
    logger.info("Starting in %s mode", settings.NIDS_MODE)

    # Supplementary XGBoost classifier (optional — live IF works without it)
    try:
        manager.load()
        logger.info("Pre-trained classifier loaded successfully")
    except FileNotFoundError:
        logger.warning(
            "No classifier artifacts found — supplementary classification disabled. "
            "The live Isolation Forest anomaly detector works independently."
        )
    except ValueError as exc:
        logger.warning("Classifier schema mismatch: %s — classification disabled", exc)

    # Wire up capture engine dependencies
    capture_engine._model_manager = manager
    capture_engine._anomaly_detector = anomaly_detector

    # Wire up replay engine
    replay_engine._capture_engine = capture_engine
    replay_engine._anomaly_detector = anomaly_detector

    # Thread-safe event bridge: the capture thread calls publish which
    # uses loop.call_soon_threadsafe to enqueue into the async queue.
    loop = asyncio.get_running_loop()
    capture_engine._on_event = lambda evt: broadcaster.publish(evt, loop)

    # Start the WebSocket broadcast task
    asyncio.create_task(broadcaster.run())

    # Restore baseline anomaly model if saved
    if anomaly_detector.load():
        logger.info("Baseline anomaly model restored from disk")

    yield  # application runs here

    # Shutdown
    if capture_engine.is_capturing:
        capture_engine.stop()
    if replay_engine.is_replaying:
        replay_engine.stop()
    _cancel_baseline_task()
    logger.info("Application shutting down")


def _cancel_baseline_task() -> None:
    """Cancel any pending auto-finish baseline task."""
    global _baseline_task
    if _baseline_task is not None and not _baseline_task.done():
        _baseline_task.cancel()
    _baseline_task = None


# ── App factory ──────────────────────────────────────────────────────

app = FastAPI(
    title="Network Intrusion Detection System",
    description=(
        "Real-time network anomaly detection platform.  An Isolation Forest "
        "trained on user baseline traffic flags unusual flows; a supplementary "
        "XGBoost multiclass classifier labels flagged anomalies with attack types."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ───────────────────────────────────────────────────────────


@app.get("/api/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """Lightweight liveness / readiness probe."""
    return HealthResponse(
        status="healthy" if manager.is_loaded else "degraded",
        model_loaded=manager.is_loaded,
        model_type="xgboost",
        mode=settings.NIDS_MODE,
    )


# ── Metrics & analytics ─────────────────────────────────────────────


@app.get("/api/metrics", response_model=MetricsResponse, tags=["Analytics"])
async def get_metrics() -> MetricsResponse:
    """Return accuracy and classification report for the multiclass model."""
    try:
        data = manager.get_metrics()
        return MetricsResponse(**data)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get(
    "/api/feature-importance",
    response_model=list[FeatureImportanceItem],
    tags=["Analytics"],
)
async def get_feature_importance() -> list[FeatureImportanceItem]:
    """Feature importance scores sorted in descending order."""
    try:
        items = manager.get_feature_importance()
        return [FeatureImportanceItem(**item) for item in items]
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get(
    "/api/confusion-matrix",
    response_model=ConfusionMatrixResponse,
    tags=["Analytics"],
)
async def get_confusion_matrix() -> ConfusionMatrixResponse:
    """Multiclass confusion matrix with class labels."""
    try:
        data = manager.get_confusion_matrix()
        return ConfusionMatrixResponse(**data)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get(
    "/api/dataset/stats",
    response_model=DatasetStatsResponse,
    tags=["Analytics"],
)
async def get_dataset_stats() -> DatasetStatsResponse:
    """Attack-type distribution and total sample count."""
    try:
        data = manager.get_dataset_stats()
        return DatasetStatsResponse(**data)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ── Prediction (protected) ──────────────────────────────────────────


@app.post(
    "/api/predict",
    response_model=PredictionResponse,
    tags=["Prediction"],
    dependencies=[Depends(verify_api_key)],
)
async def predict(request: PredictionRequest) -> PredictionResponse:
    """Classify a single network-traffic sample."""
    try:
        result = manager.predict(request.features)
        return PredictionResponse(**result)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Prediction failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post(
    "/api/predict/batch",
    response_model=list[PredictionResponse],
    tags=["Prediction"],
    dependencies=[Depends(verify_api_key)],
)
async def predict_batch(
    request: BatchPredictionRequest,
) -> list[PredictionResponse]:
    """Classify a batch of network-traffic samples."""
    try:
        results: list[PredictionResponse] = []
        for sample in request.samples:
            result = manager.predict(sample)
            results.append(PredictionResponse(**result))
        return results
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Batch prediction failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ── Simulation ───────────────────────────────────────────────────────


@app.get(
    "/api/simulate",
    response_model=list[SimulationEvent],
    tags=["Simulation"],
)
async def simulate(
    count: int = Query(default=10, ge=1, le=100, description="Number of events"),
) -> list[SimulationEvent]:
    """Generate simulated intrusion-detection events from the test set."""
    try:
        events = manager.simulate_batch(n=count)
        return [SimulationEvent(**e) for e in events]
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ── Feature names ────────────────────────────────────────────────────


@app.get(
    "/api/feature-names",
    response_model=list[str],
    tags=["Schema"],
)
async def get_feature_names() -> list[str]:
    """Return the canonical list of 28 observable feature names."""
    return settings.FEATURE_NAMES


# ── Evaluation Results ───────────────────────────────────────────────


@app.get("/api/evaluation", tags=["Evaluation"])
async def get_evaluation_results() -> dict:
    """Return cached evaluation results from the last run."""
    eval_path = settings.MODELS_DIR / "evaluation.json"
    if not eval_path.exists():
        raise HTTPException(
            status_code=404,
            detail="No evaluation results. Run: python run_evaluation.py",
        )
    with open(eval_path) as f:
        return json.load(f)


# ══════════════════════════════════════════════════════════════════════
# Live Capture, Baseline, WebSocket
# ══════════════════════════════════════════════════════════════════════


# ── Capture ──────────────────────────────────────────────────────────


@app.post(
    "/api/capture/start",
    response_model=CaptureStatusResponse,
    tags=["Capture"],
    dependencies=[Depends(verify_api_key)],
)
async def start_capture(request: CaptureStartRequest) -> CaptureStatusResponse:
    """Start live packet capture on the specified interface."""
    if replay_engine.is_replaying:
        raise HTTPException(
            status_code=400,
            detail="PCAP replay is active — stop it before starting live capture",
        )

    interface = request.interface or settings.CAPTURE_INTERFACE

    # Preflight: test sniff access before spawning the thread
    try:
        from scapy.all import sniff
        sniff(iface=interface, count=0, timeout=0.1, store=False)
    except PermissionError:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Permission denied on interface '{interface}'. "
                "Packet capture requires root or CAP_NET_RAW+CAP_NET_ADMIN. "
                "Run with: sudo uvicorn app.main:app --host 0.0.0.0 --port 8000"
            ),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot access interface '{interface}': {exc}",
        )

    capture_engine.start(interface=interface, bpf_filter=request.bpf_filter)
    return CaptureStatusResponse(**capture_engine.status)


@app.post(
    "/api/capture/stop",
    response_model=CaptureStatusResponse,
    tags=["Capture"],
    dependencies=[Depends(verify_api_key)],
)
async def stop_capture() -> CaptureStatusResponse:
    """Stop live packet capture and cancel any in-progress baseline."""
    _cancel_baseline_task()
    anomaly_detector.cancel_collection()
    capture_engine.stop()
    return CaptureStatusResponse(**capture_engine.status)


@app.get(
    "/api/capture/status",
    response_model=CaptureStatusResponse,
    tags=["Capture"],
)
async def get_capture_status() -> CaptureStatusResponse:
    """Get current capture engine status."""
    return CaptureStatusResponse(**capture_engine.status)


# ── Detection Stats ──────────────────────────────────────────────────


@app.get("/api/detection/stats", tags=["Detection"])
async def get_detection_stats() -> dict:
    """Live Isolation Forest detection metrics."""
    return capture_engine.detection_stats


# ── Report Export ────────────────────────────────────────────────────


@app.get("/api/report/csv", tags=["Report"])
async def export_report_csv() -> StreamingResponse:
    """Export detection metrics and flow log as a downloadable CSV report."""
    stats = capture_engine.detection_stats
    cap = capture_engine.status
    baseline = {
        "status": anomaly_detector.status,
        "samples": anomaly_detector.samples_collected,
    }

    buf = io.StringIO()
    writer = csv.writer(buf)

    # Section 1: Summary
    writer.writerow(["NIDS Detection Report"])
    writer.writerow(["Generated", datetime.now(timezone.utc).isoformat()])
    writer.writerow([])

    writer.writerow(["== Capture Summary =="])
    writer.writerow(["Interface", cap.get("interface", "N/A")])
    writer.writerow(["Packets Captured", cap.get("packets_captured", 0)])
    writer.writerow(["Flows Analyzed", cap.get("flows_analyzed", 0)])
    writer.writerow(["Threats Detected", cap.get("threats_detected", 0)])
    writer.writerow([])

    writer.writerow(["== Baseline =="])
    writer.writerow(["Status", baseline["status"]])
    writer.writerow(["Samples Collected", baseline["samples"]])
    writer.writerow([])

    # Section 2: Detection Metrics
    writer.writerow(["== Isolation Forest Metrics =="])
    writer.writerow(["Total Flows Scored", stats["total_flows_scored"]])
    writer.writerow(["Anomalies Detected", stats["anomalies_detected"]])
    writer.writerow(["Anomaly Rate", f"{stats['anomaly_rate']:.4f}"])
    writer.writerow(["Threats Classified", stats["threats_classified"]])
    writer.writerow(["Mean Score", f"{stats['mean_score']:.4f}"])
    writer.writerow(["Min Score", f"{stats['min_score']:.4f}"])
    writer.writerow(["Max Score", f"{stats['max_score']:.4f}"])
    writer.writerow([])

    # Section 3: Score Distribution
    if stats["score_distribution"]:
        writer.writerow(["== Score Distribution =="])
        writer.writerow(["Range Start", "Range End", "Count"])
        for bucket in stats["score_distribution"]:
            writer.writerow([
                f"{bucket['range_start']:.4f}",
                f"{bucket['range_end']:.4f}",
                bucket["count"],
            ])
        writer.writerow([])

    # Section 4: Classification Breakdown
    if stats["classifications"]:
        writer.writerow(["== Classification Breakdown =="])
        writer.writerow(["Class", "Count", "Percentage"])
        total_anomalies = stats["anomalies_detected"] or 1
        for cls, count in sorted(
            stats["classifications"].items(), key=lambda x: x[1], reverse=True
        ):
            writer.writerow([cls, count, f"{count / total_anomalies * 100:.1f}%"])
        writer.writerow([])

    # Section 5: Recent flow events from the queue history
    scores = capture_engine.anomaly_scores
    if scores:
        writer.writerow(["== Anomaly Scores (all scored flows) =="])
        writer.writerow(["Flow Index", "Anomaly Score", "Is Anomaly"])
        for i, score in enumerate(scores):
            writer.writerow([i + 1, f"{score:.6f}", "Yes" if score < 0 else "No"])

    buf.seek(0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"nids_report_{timestamp}.csv"

    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Baseline ─────────────────────────────────────────────────────────


@app.post(
    "/api/baseline/collect",
    response_model=BaselineStatusResponse,
    tags=["Baseline"],
    dependencies=[Depends(verify_api_key)],
)
async def collect_baseline(request: BaselineCollectRequest) -> BaselineStatusResponse:
    """Start baseline traffic collection for the given duration.

    The backend owns the timer: after ``duration_seconds`` elapses the
    Isolation Forest is automatically trained.  The frontend should poll
    ``GET /api/baseline/status`` for progress.
    """
    if not capture_engine.is_capturing:
        raise HTTPException(
            status_code=400,
            detail="Capture must be running before collecting baseline",
        )

    # Cancel any previous in-flight baseline before starting a new one
    _cancel_baseline_task()
    anomaly_detector.cancel_collection()

    anomaly_detector.start_collection(duration_seconds=request.duration_seconds)

    # Spawn a background task that waits for the duration then finishes
    global _baseline_task
    _baseline_task = asyncio.create_task(
        _baseline_auto_finish(request.duration_seconds)
    )

    return BaselineStatusResponse(
        status="collecting",
        samples_collected=0,
        seconds_remaining=request.duration_seconds,
        duration_seconds=request.duration_seconds,
        message="Collection started — flows are being recorded",
    )


async def _baseline_auto_finish(duration: int) -> None:
    """Background coroutine: wait *duration* seconds, then train the baseline model."""
    try:
        await asyncio.sleep(duration)
    except asyncio.CancelledError:
        return

    if anomaly_detector.status != "collecting":
        return  # collection was cancelled or already finished

    if anomaly_detector.samples_collected == 0:
        anomaly_detector._status = "not_collected"
        anomaly_detector._started_at = None
        anomaly_detector._duration_seconds = 0
        logger.warning("Baseline collection ended with zero samples")
        return

    try:
        anomaly_detector.finish_collection()
        if anomaly_detector._scaler is not None:
            capture_engine._extractor.set_scaler(anomaly_detector._scaler)
        logger.info(
            "Baseline auto-trained on %d samples", anomaly_detector.samples_collected
        )
    except Exception:
        anomaly_detector._status = "not_collected"
        anomaly_detector._started_at = None
        anomaly_detector._duration_seconds = 0
        logger.exception("Auto-finish baseline training failed")


@app.post(
    "/api/baseline/finish",
    response_model=BaselineStatusResponse,
    tags=["Baseline"],
    dependencies=[Depends(verify_api_key)],
)
async def finish_baseline() -> BaselineStatusResponse:
    """Manually train the Isolation Forest on collected samples."""
    if anomaly_detector.status != "collecting":
        raise HTTPException(status_code=400, detail="No collection in progress")

    # Cancel the auto-finish task since we're finishing manually
    _cancel_baseline_task()

    if anomaly_detector.samples_collected == 0:
        anomaly_detector._status = "not_collected"
        anomaly_detector._started_at = None
        anomaly_detector._duration_seconds = 0
        raise HTTPException(
            status_code=400,
            detail="No flows captured during baseline. Try a longer duration.",
        )

    try:
        anomaly_detector.finish_collection()
        if anomaly_detector._scaler is not None:
            capture_engine._extractor.set_scaler(anomaly_detector._scaler)
        logger.info(
            "Baseline trained on %d samples", anomaly_detector.samples_collected
        )
        return BaselineStatusResponse(
            status="ready",
            samples_collected=anomaly_detector.samples_collected,
            message=f"Isolation Forest trained on {anomaly_detector.samples_collected} samples",
        )
    except Exception as exc:
        anomaly_detector._status = "not_collected"
        anomaly_detector._started_at = None
        anomaly_detector._duration_seconds = 0
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get(
    "/api/baseline/status",
    response_model=BaselineStatusResponse,
    tags=["Baseline"],
)
async def get_baseline_status() -> BaselineStatusResponse:
    """Get the anomaly detector baseline status with time-remaining info."""
    messages = {
        "not_collected": "No baseline collected yet",
        "collecting": "Collection in progress...",
        "ready": "Baseline ready — anomaly detection active",
    }

    seconds_remaining = 0
    duration = anomaly_detector.duration_seconds
    if anomaly_detector.status == "collecting" and anomaly_detector.started_at:
        elapsed = time.time() - anomaly_detector.started_at
        seconds_remaining = max(0, duration - int(elapsed))

    return BaselineStatusResponse(
        status=anomaly_detector.status,
        samples_collected=anomaly_detector.samples_collected,
        seconds_remaining=seconds_remaining,
        duration_seconds=duration,
        message=messages.get(anomaly_detector.status, ""),
    )


@app.get("/api/baseline/summary", tags=["Baseline"])
async def get_baseline_summary() -> dict:
    """Per-feature baseline mean and std for deviation analysis."""
    summary = anomaly_detector.get_feature_summary()
    if not summary:
        raise HTTPException(
            status_code=404,
            detail="No baseline summary available. Train a baseline first.",
        )
    return summary


# ── WebSocket live feed (broadcast to all clients) ───────────────────

@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket) -> None:
    """Accept a WebSocket client and keep it alive until disconnect."""
    await ws.accept()
    broadcaster.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        broadcaster.disconnect(ws)


# ══════════════════════════════════════════════════════════════════════
# PCAP Replay
# ══════════════════════════════════════════════════════════════════════


@app.post(
    "/api/replay/start",
    tags=["Replay"],
    dependencies=[Depends(verify_api_key)],
)
async def start_replay(
    scenario: str = Query(default="mixed", description="Demo scenario name"),
    speed: float = Query(default=2.0, ge=0.1, le=100.0, description="Replay speed multiplier"),
) -> dict:
    """Start replaying a PCAP scenario through the live pipeline."""
    try:
        replay_engine.start(scenario=scenario, speed=speed)
        return replay_engine.status
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post(
    "/api/replay/stop",
    tags=["Replay"],
    dependencies=[Depends(verify_api_key)],
)
async def stop_replay() -> dict:
    """Stop the current replay."""
    replay_engine.stop()
    return replay_engine.status


@app.get("/api/replay/status", tags=["Replay"])
async def get_replay_status() -> dict:
    """Get current replay state, stats, and latency metrics."""
    return replay_engine.status


@app.get("/api/replay/baseline-summary", tags=["Replay"])
async def get_replay_baseline_summary() -> dict:
    """Per-feature baseline summary from the most recent replay bootstrap."""
    if not replay_engine._baseline_summary:
        raise HTTPException(
            status_code=404,
            detail="No replay baseline available. Run a mixed replay first.",
        )
    return replay_engine._baseline_summary

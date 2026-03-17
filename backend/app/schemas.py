"""
Pydantic models for request / response validation.

Every payload that enters or leaves the API is validated here,
giving us automatic OpenAPI documentation and runtime safety.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.config import settings

# ── Requests ─────────────────────────────────────────────────────────

class PredictionRequest(BaseModel):
    """Single-sample prediction request.

    Keys must match the 28 observable feature names; values are floats.
    """

    features: dict[str, float] = Field(
        ...,
        description="Mapping of feature_name → float value (28 observable features)",
        json_schema_extra={
            "example": {name: 0.0 for name in settings.FEATURE_NAMES},
        },
    )


class BatchPredictionRequest(BaseModel):
    """Batch prediction request — a list of feature dictionaries."""

    samples: list[dict[str, float]] = Field(
        ...,
        min_length=1,
        description="List of feature dictionaries, each with 28 observable features",
    )


# ── Responses ────────────────────────────────────────────────────────

class PredictionResponse(BaseModel):
    """Result of a single prediction."""

    predicted_class: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    is_attack: bool
    probabilities: dict[str, float]


class MetricsResponse(BaseModel):
    """Training / evaluation metrics for the multiclass classifier."""

    accuracy: float
    classification_report: dict


class ConfusionMatrixResponse(BaseModel):
    """Confusion matrix with human-readable labels."""

    labels: list[str]
    matrix: list[list[int]]


class FeatureImportanceItem(BaseModel):
    """A single feature and its importance score."""

    feature: str
    importance: float


class DatasetStatsResponse(BaseModel):
    """High-level statistics about the training dataset."""

    total_samples: int
    attack_distribution: dict[str, int]


class SimulationEvent(BaseModel):
    """One event in a live-simulation batch."""

    timestamp: str
    features: dict[str, float]
    predicted_class: str
    confidence: float
    is_attack: bool


class HealthResponse(BaseModel):
    """Health-check payload."""

    status: str
    model_loaded: bool
    model_type: str
    mode: str


# ── Capture & Live Detection ────────────────────────────────────────


class CaptureStartRequest(BaseModel):
    """Request to start live packet capture."""

    interface: str = Field(default="", description="Network interface (empty = use config default)")
    bpf_filter: str = Field(default="", description="Optional BPF filter expression")


class CaptureStatusResponse(BaseModel):
    """Current state of the capture engine."""

    is_capturing: bool
    interface: str | None = None
    packets_captured: int = 0
    flows_analyzed: int = 0
    threats_detected: int = 0
    uptime_seconds: float = 0.0
    error: str | None = None


class BaselineCollectRequest(BaseModel):
    """Request to collect baseline traffic for anomaly detection."""

    duration_seconds: int = Field(
        default=60, ge=10, le=1800, description="Seconds of baseline traffic to collect"
    )


class BaselineStatusResponse(BaseModel):
    """Status of the anomaly detection baseline."""

    status: str  # "not_collected" | "collecting" | "ready"
    samples_collected: int = 0
    seconds_remaining: int = 0
    duration_seconds: int = 0
    message: str = ""


class LiveFlowEvent(BaseModel):
    """A single live-detected network flow event."""

    source: str = "live"  # "live" or "replay"
    timestamp: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    predicted_class: str | None = None
    confidence: float | None = None
    is_attack: bool = False
    features: dict[str, float] = Field(default_factory=dict)



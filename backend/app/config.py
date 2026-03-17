"""
Application configuration.

Centralizes all runtime settings, file paths, and tunable parameters
so that nothing is hard-coded across modules.

NOTE: FEATURE_NAMES defines the live system's feature contract (28
observable features from packet headers).  Evaluation datasets have
their own native feature spaces — do not conflate the two.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

_DEFAULT_KEY = "dev-key-change-me"
_MODE = os.environ.get("NIDS_MODE", "demo")


def _default_cors() -> str:
    if _MODE == "production":
        return ""
    return "http://localhost:3000,http://localhost:3001"


def _default_interface() -> str:
    iface = os.environ.get("NIDS_CAPTURE_INTERFACE")
    if iface:
        return iface
    if _MODE == "production":
        return "eth0"
    return "lo0" if platform.system() == "Darwin" else "lo"


class Settings:
    """Immutable application settings resolved once at import time."""

    # ── Mode ─────────────────────────────────────────────────────────
    NIDS_MODE: str = _MODE

    # ── Directories ──────────────────────────────────────────────────
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    MODELS_DIR: Path = BASE_DIR / "models"

    # ── Serialised artefact paths ────────────────────────────────────
    MULTI_MODEL_PATH: Path = MODELS_DIR / "multi_model.joblib"
    LABEL_ENCODER_PATH: Path = MODELS_DIR / "label_encoder.joblib"
    METADATA_PATH: Path = MODELS_DIR / "metadata.joblib"
    TEST_DATA_PATH: Path = MODELS_DIR / "test_data.joblib"

    # ── API key ─────────────────────────────────────────────────────
    NIDS_API_KEY: str = os.environ.get("NIDS_API_KEY", _DEFAULT_KEY)

    # ── CORS ─────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = os.environ.get(
        "CORS_ORIGINS", _default_cors()
    ).split(",")

    # ── Capture interface ────────────────────────────────────────────
    CAPTURE_INTERFACE: str = _default_interface()

    # ── Training hyper-parameters ────────────────────────────────────
    TEST_SIZE: float = 0.2
    RANDOM_STATE: int = 42
    XGB_N_ESTIMATORS: int = 200
    XGB_MAX_DEPTH: int = 6
    XGB_LEARNING_RATE: float = 0.1

    # ── Live feature schema ──────────────────────────────────────────

    FEATURE_SCHEMA_VERSION: str = "v2-observable-28"

    FEATURE_NAMES: list[str] = [
        # basic (9)
        "duration", "protocol_type", "service", "flag",
        "src_bytes", "dst_bytes", "land", "wrong_fragment",
        "urgent",
        # time-window (19)
        "count", "srv_count", "serror_rate",
        "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
        "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
        "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    ]

    # ── Production validation ────────────────────────────────────────

    def validate_production(self) -> None:
        """Raise if production mode has insecure defaults."""
        if self.NIDS_MODE != "production":
            return

        if self.NIDS_API_KEY == _DEFAULT_KEY or not self.NIDS_API_KEY:
            raise RuntimeError(
                "NIDS_MODE=production requires a real NIDS_API_KEY. "
                "Set it via environment variable."
            )

        if "*" in self.CORS_ORIGINS or "" in self.CORS_ORIGINS:
            raise RuntimeError(
                "NIDS_MODE=production requires explicit CORS_ORIGINS. "
                "Wildcard or empty origins are not allowed."
            )


settings = Settings()

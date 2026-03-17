"""
Shared pytest fixtures for the NIDS backend test suite.

The ``client`` fixture creates a ``TestClient`` that triggers the app's
lifespan.  The supplementary XGBoost classifier is optional — tests that
need it are skipped when model artifacts are absent.
"""

from __future__ import annotations

import os

import pytest
from starlette.testclient import TestClient

# Set the API key before any app code is imported so that the auth
# dependency accepts our test key.
os.environ["NIDS_API_KEY"] = "test-key"

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402

# Whether the supplementary classifier artifacts exist on disk
MODEL_AVAILABLE: bool = settings.MULTI_MODEL_PATH.exists()

# Attack classes — only meaningful when a model trained on labeled data
# is available.  Empty otherwise.
ATTACK_CLASSES: list[str] = []


@pytest.fixture(scope="session")
def client() -> TestClient:
    """Provide a ``TestClient`` whose lifespan loads models if available."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def auth_headers() -> dict[str, str]:
    """Standard auth headers for protected endpoints."""
    return {"X-Api-Key": "test-key"}


@pytest.fixture(scope="session")
def all_zero_features() -> dict[str, float]:
    """A feature dict with every canonical feature set to 0.0."""
    return {name: 0.0 for name in settings.FEATURE_NAMES}


@pytest.fixture(scope="session")
def feature_names() -> list[str]:
    """The canonical 28 feature names from settings."""
    return list(settings.FEATURE_NAMES)

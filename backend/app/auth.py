"""
API key authentication for FastAPI.

Provides a dependency that validates the ``X-Api-Key`` header against
the ``NIDS_API_KEY`` environment variable (or a default dev key).
"""

from __future__ import annotations

from fastapi import Header, HTTPException

from app.config import settings


def verify_api_key(x_api_key: str = Header(...)) -> str:
    """Validate the request's API key.

    Parameters
    ----------
    x_api_key:
        Value of the ``X-Api-Key`` header injected by FastAPI.

    Returns
    -------
    str
        The validated API key.

    Raises
    ------
    HTTPException
        401 if the key is missing or does not match the expected value.
    """
    if x_api_key != settings.NIDS_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key

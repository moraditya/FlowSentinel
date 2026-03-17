"""
WebSocket broadcast manager — fan-out events to all connected clients.

The capture thread publishes events via ``publish(event, loop)`` which uses
``loop.call_soon_threadsafe`` to safely enqueue into the async queue from
a non-async thread.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class BroadcastManager:
    """Thread-safe fan-out broadcaster for WebSocket clients."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    # ── client lifecycle ─────────────────────────────────────────────

    def connect(self, ws: WebSocket) -> None:
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    # ── publishing ───────────────────────────────────────────────────

    def publish(self, event: dict, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Enqueue an event from any thread.

        When called from the capture thread, *loop* must be the main
        event loop so we can use ``call_soon_threadsafe``.
        """
        if loop is not None:
            loop.call_soon_threadsafe(self._enqueue, event)
        else:
            # Called from the async thread (e.g. tests)
            self._enqueue(event)

    def _enqueue(self, event: dict) -> None:
        """Put event onto the queue; drop silently if full."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    # ── broadcast loop ───────────────────────────────────────────────

    async def run(self) -> None:
        """Long-running coroutine: read queue, send to all clients."""
        while True:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=5.0)
                msg = json.dumps(event)
            except asyncio.TimeoutError:
                msg = json.dumps({"type": "heartbeat"})

            dead: list[WebSocket] = []
            for ws in list(self._clients):
                try:
                    await ws.send_text(msg)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._clients.discard(ws)

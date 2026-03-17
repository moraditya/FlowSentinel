#!/usr/bin/env python3
"""
CLI wrapper for the PCAP replay API.

Usage:
    python replay.py --scenario mixed --speed 2
    python replay.py --scenario port_scan --speed 10
    python replay.py --stop
    python replay.py --status

Requires the backend to be running (calls /api/replay/* endpoints).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

DEFAULT_BASE = "http://localhost:8000"
DEFAULT_API_KEY = "dev-key-change-me"


def _api(method: str, path: str, base: str, api_key: str, data: dict | None = None) -> dict:
    url = f"{base}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Api-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail", str(exc))
        except Exception:
            detail = str(exc)
        print(f"Error: {detail}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError:
        print("Error: Cannot reach backend. Is it running?", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="NIDS PCAP Replay CLI")
    parser.add_argument(
        "--scenario", "-s",
        choices=["benign", "port_scan", "brute_force", "mixed"],
        default="mixed",
        help="Demo scenario to replay (default: mixed)",
    )
    parser.add_argument(
        "--speed", type=float, default=2.0,
        help="Replay speed multiplier (default: 2.0)",
    )
    parser.add_argument(
        "--stop", action="store_true",
        help="Stop the current replay",
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Print replay status and exit",
    )
    parser.add_argument(
        "--base-url", default=DEFAULT_BASE,
        help=f"Backend URL (default: {DEFAULT_BASE})",
    )
    parser.add_argument(
        "--api-key", default=DEFAULT_API_KEY,
        help="API key for protected endpoints",
    )
    args = parser.parse_args()

    if args.status:
        status = _api("GET", "/api/replay/status", args.base_url, args.api_key)
        print(json.dumps(status, indent=2))
        return

    if args.stop:
        status = _api("POST", "/api/replay/stop", args.base_url, args.api_key)
        print(f"Replay stopped. State: {status['state']}")
        return

    # Start replay
    print(f"Starting replay: scenario={args.scenario} speed={args.speed}x")
    status = _api(
        "POST",
        f"/api/replay/start?scenario={args.scenario}&speed={args.speed}",
        args.base_url,
        args.api_key,
    )
    print(f"State: {status['state']}")

    # Poll until completed
    try:
        while True:
            time.sleep(2)
            status = _api("GET", "/api/replay/status", args.base_url, args.api_key)
            state = status["state"]
            pkts = status["packets_replayed"]
            flows = status["flows_processed"]
            fps = status["throughput_fps"]
            lat = status.get("latency", {})
            p50 = lat.get("p50_ms", "?")

            print(
                f"\r  [{state}] packets={pkts} flows={flows} "
                f"throughput={fps}fps p50={p50}ms",
                end="", flush=True,
            )

            if state in ("completed", "error", "idle"):
                print()
                break

    except KeyboardInterrupt:
        print("\nStopping...")
        _api("POST", "/api/replay/stop", args.base_url, args.api_key)

    # Final summary
    status = _api("GET", "/api/replay/status", args.base_url, args.api_key)
    print(f"\nFinal state: {status['state']}")
    print(f"Packets: {status['packets_replayed']}")
    print(f"Flows: {status['flows_processed']}")
    print(f"Elapsed: {status['elapsed_seconds']}s")
    if status.get("latency"):
        lat = status["latency"]
        print(f"Packet latency: mean={lat.get('mean_ms', '?')}ms "
              f"p50={lat.get('p50_ms', '?')}ms "
              f"p95={lat.get('p95_ms', '?')}ms "
              f"p99={lat.get('p99_ms', '?')}ms")
    stages = status.get("stage_timing", {})
    if stages:
        print("Per-stage breakdown (p50):")
        for stage, vals in stages.items():
            print(f"  {stage}: mean={vals['mean']:.3f}ms p50={vals['p50']:.3f}ms p95={vals['p95']:.3f}ms")
    if status.get("error"):
        print(f"Error: {status['error']}")


if __name__ == "__main__":
    main()

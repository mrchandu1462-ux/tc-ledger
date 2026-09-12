#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
TC Live Technocore Indexer Local HTTP Adapter Server

Provides a strictly READ-ONLY local JSON API for TC Verify / TC-Ledger Explorer
to query live Technocore activity indexer results.

Security Controls:
- Strictly READ-ONLY: rejects all non-GET/OPTIONS requests (405).
- Restrictive CORS: no unrestricted wildcard CORS; only trusted local/deployed origins.
- Clamped request parameters (max_rooms 1..50, window 0.1..168.0 hours).
- Strict room name validation: ^[A-Za-z0-9_-]{1,64}$, no path traversal (.., /, \\).
- Bounded LRU/TTL result cache (maximum 100 entries, 30s TTL).
- Multi-threaded: ThreadingHTTPServer prevents request head-of-line blocking.
- SSRF prevention: restricts outbound calls to intended Technocore host.

Usage:
  python tools/tc_indexer_server.py [--port 8088] [--host 127.0.0.1]
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.tc_live_indexer import (
    DEFAULT_TECHNOCORE_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_WINDOW_HOURS,
    format_json_report,
    run_indexer,
)

CACHE_TTL_SECONDS = 30.0
MAX_CACHE_SIZE = 100
_RESULT_CACHE: dict[str, tuple[float, str]] = {}

CLAMPED_MIN_ROOMS = 1
CLAMPED_MAX_ROOMS = 50
CLAMPED_MIN_WINDOW = 0.1
CLAMPED_MAX_WINDOW = 168.0  # 7 days max

ROOM_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

DEFAULT_ALLOWED_ORIGIN_PATTERNS = [
    re.compile(r"^https?://localhost(:[0-9]+)?$"),
    re.compile(r"^https?://127\.0\.0\.1(:[0-9]+)?$"),
    re.compile(r"^https://mrchandu1462-ux\.github\.io$"),
]


def prune_cache(now: float) -> None:
    """Prune expired cache entries and enforce max size limit."""
    global _RESULT_CACHE
    # Remove expired entries
    _RESULT_CACHE = {
        k: v for k, v in _RESULT_CACHE.items() if now - v[0] < CACHE_TTL_SECONDS
    }
    # If still above capacity, remove oldest
    if len(_RESULT_CACHE) >= MAX_CACHE_SIZE:
        sorted_keys = sorted(_RESULT_CACHE.keys(), key=lambda k: _RESULT_CACHE[k][0])
        for k in sorted_keys[: len(_RESULT_CACHE) - MAX_CACHE_SIZE + 1]:
            del _RESULT_CACHE[k]


def is_allowed_origin(origin: str, allowed_patterns: list[re.Pattern] | None = None) -> bool:
    """Validate whether an Origin header matches allowed origin patterns."""
    if not origin:
        return False
    patterns = allowed_patterns or DEFAULT_ALLOWED_ORIGIN_PATTERNS
    return any(p.match(origin.strip()) for p in patterns)


class IndexerRequestHandler(BaseHTTPRequestHandler):
    server_version = "TcIndexerServer/0.2"

    def get_cors_origin(self) -> str | None:
        origin = self.headers.get("Origin")
        if origin and is_allowed_origin(origin):
            return origin
        return None

    def send_cors_headers(self):
        matched = self.get_cors_origin()
        if matched:
            self.send_header("Access-Control-Allow-Origin", matched)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_cors_headers()
        self.end_headers()

    def do_POST(self):
        self.send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Method Not Allowed: Indexer is strictly read-only"})

    def do_PUT(self):
        self.send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Method Not Allowed: Indexer is strictly read-only"})

    def do_DELETE(self):
        self.send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Method Not Allowed: Indexer is strictly read-only"})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "ok", "service": "tc-live-indexer"})
            return

        if path == "/api/index":
            dids = qs.get("did")
            if not dids or not dids[0].strip():
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Missing required query parameter: did"}
                )
                return

            target_did = dids[0].strip()

            raw_rooms = qs.get("rooms", [])
            explicit_rooms = None
            if raw_rooms:
                room_candidates = [r.lstrip("#").strip() for r in raw_rooms[0].split(",") if r.strip()]
                if len(room_candidates) > CLAMPED_MAX_ROOMS:
                    self.send_json(
                        HTTPStatus.BAD_REQUEST,
                        {"error": f"Too many explicit rooms requested (max {CLAMPED_MAX_ROOMS})"}
                    )
                    return
                for r in room_candidates:
                    if not ROOM_NAME_RE.match(r) or ".." in r or "/" in r or "\\" in r:
                        self.send_json(
                            HTTPStatus.BAD_REQUEST,
                            {"error": f"Invalid room name: '{r}'. Room names must match ^[A-Za-z0-9_-]{{1,64}}$ without path traversal."}
                        )
                        return
                explicit_rooms = room_candidates if room_candidates else None

            # Parameter limit clamping & validation
            raw_max_rooms = qs.get("max_rooms", ["15"])[0]
            try:
                max_rooms = int(raw_max_rooms)
            except ValueError:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Invalid max_rooms parameter: '{raw_max_rooms}' must be an integer"}
                )
                return

            if max_rooms < CLAMPED_MIN_ROOMS or max_rooms > CLAMPED_MAX_ROOMS:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"max_rooms out of allowed range [{CLAMPED_MIN_ROOMS}..{CLAMPED_MAX_ROOMS}]"}
                )
                return

            raw_window = qs.get("window", [str(DEFAULT_WINDOW_HOURS)])[0]
            try:
                window_hours = float(raw_window)
            except ValueError:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Invalid window parameter: '{raw_window}' must be a float"}
                )
                return

            if window_hours < CLAMPED_MIN_WINDOW or window_hours > CLAMPED_MAX_WINDOW:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"window out of allowed range [{CLAMPED_MIN_WINDOW}..{CLAMPED_MAX_WINDOW}] hours"}
                )
                return

            now = time.time()
            prune_cache(now)

            cache_key = f"{target_did}|{','.join(explicit_rooms or [])}|{max_rooms}|{window_hours}"

            if cache_key in _RESULT_CACHE:
                cached_time, cached_json = _RESULT_CACHE[cache_key]
                if now - cached_time < CACHE_TTL_SECONDS:
                    self.send_json_raw(HTTPStatus.OK, cached_json)
                    return

            try:
                result = run_indexer(
                    target_did=target_did,
                    base_url=DEFAULT_TECHNOCORE_URL,
                    explicit_rooms=explicit_rooms,
                    max_rooms=max_rooms,
                    window_hours=window_hours,
                    timeout=DEFAULT_TIMEOUT,
                )
                json_str = format_json_report(result)
                _RESULT_CACHE[cache_key] = (now, json_str)
                self.send_json_raw(HTTPStatus.OK, json_str)
            except ValueError as exc:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Invalid DID: {exc}"}
                )
            except Exception as exc:
                self.send_json(
                    HTTPStatus.BAD_GATEWAY,
                    {"error": f"Indexer error: {exc}"}
                )
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})

    def send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json_raw(self, status: int, json_str: str):
        body = json_str.encode("utf-8")
        self.send_response(status)
        self.send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Keep test runs clean
        pass


def run_server(host: str = "127.0.0.1", port: int = 8088):
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, IndexerRequestHandler)
    print(f"TC Live Indexer Server listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="TC Live Indexer Local HTTP Adapter")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8088, help="Port (default: 8088)")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()

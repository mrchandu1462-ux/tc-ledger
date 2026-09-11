#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
TC Live Technocore Indexer Local HTTP Adapter Server

Provides a strictly READ-ONLY local JSON API for TC-Ledger Explorer
to query live Technocore activity indexer results without CORS restrictions.

Usage:
  python tools/tc_indexer_server.py [--port 8088] [--host 127.0.0.1]
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
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
_RESULT_CACHE: dict[str, tuple[float, str]] = {}


class IndexerRequestHandler(BaseHTTPRequestHandler):
    server_version = "TcIndexerServer/0.1"

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_cors_headers()
        self.end_headers()

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
            explicit_rooms = [r.strip() for r in raw_rooms[0].split(",") if r.strip()] if raw_rooms else None

            try:
                max_rooms = int(qs.get("max_rooms", ["15"])[0])
            except ValueError:
                max_rooms = 15

            try:
                window_hours = float(qs.get("window", [str(DEFAULT_WINDOW_HOURS)])[0])
            except ValueError:
                window_hours = DEFAULT_WINDOW_HOURS

            cache_key = f"{target_did}|{','.join(explicit_rooms or [])}|{max_rooms}|{window_hours}"
            now = time.time()

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

    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")

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
    httpd = HTTPServer(server_address, IndexerRequestHandler)
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

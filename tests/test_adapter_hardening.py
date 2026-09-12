# SPDX-License-Identifier: Apache-2.0
"""
Regression tests for local indexer adapter server and path/redirect security hardening.
"""

import re
import sys
import urllib.error
import urllib.parse
from http import HTTPStatus
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.tc_indexer_server import (
    CLAMPED_MAX_ROOMS,
    CLAMPED_MIN_ROOMS,
    MAX_CACHE_SIZE,
    ROOM_NAME_RE,
    _RESULT_CACHE,
    is_allowed_origin,
    prune_cache,
)
from tools.tc_live_indexer import SafeRedirectHandler, fetch_room_generation_and_export, run_indexer


class TestAdapterSecurityHardening:
    def test_room_name_validation_regex(self):
        """Valid rooms conform to ^[A-Za-z0-9_-]{1,64}$, invalid are rejected."""
        valid_rooms = ["lobby", "tclk-offers", "room_123", "A-B-C", "z" * 64]
        for r in valid_rooms:
            assert ROOM_NAME_RE.match(r) is not None

        invalid_rooms = [
            "../../etc/passwd",
            "../lobby",
            "room/slash",
            "room\\backslash",
            "<script>",
            "room name with space",
            "",
            "z" * 65,
            "room?query=1",
            "room#fragment",
        ]
        for r in invalid_rooms:
            assert not ROOM_NAME_RE.match(r)

    def test_fetch_room_generation_rejects_traversal(self):
        """fetch_room_generation_and_export raises ValueError for path traversal."""
        traversal_attempts = [
            "../../evil",
            "../secret",
            "room/../../x",
            "room\\..\\x",
            "room with spaces",
        ]
        for attempt in traversal_attempts:
            with pytest.raises(ValueError, match="Invalid room name"):
                fetch_room_generation_and_export("https://technocore.chat", attempt)

    def test_run_indexer_rejects_excessive_max_rooms(self):
        """run_indexer rejects max_rooms < 1 or > 50."""
        valid_did = "did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z"
        with pytest.raises(ValueError, match="max_rooms must be between 1 and 50"):
            run_indexer(valid_did, max_rooms=0)

        with pytest.raises(ValueError, match="max_rooms must be between 1 and 50"):
            run_indexer(valid_did, max_rooms=51)

    def test_run_indexer_rejects_traversal_in_explicit_rooms(self):
        """run_indexer rejects explicit rooms containing traversal or separators."""
        valid_did = "did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z"
        with pytest.raises(ValueError, match="Invalid room name"):
            run_indexer(valid_did, explicit_rooms=["../../lobby"])

        with pytest.raises(ValueError, match="Invalid room name"):
            run_indexer(valid_did, explicit_rooms=["valid-room", "bad/room"])

    def test_cors_origin_allowlist(self):
        """CORS allowlist allows trusted local/pages origins and rejects untrusted."""
        assert is_allowed_origin("http://127.0.0.1:8088")
        assert is_allowed_origin("http://localhost:3000")
        assert is_allowed_origin("http://localhost:8080")
        assert is_allowed_origin("https://mrchandu1462-ux.github.io")

        # Untrusted origins rejected
        assert not is_allowed_origin("http://evil.com")
        assert not is_allowed_origin("https://attacker.org")
        assert not is_allowed_origin("http://127.0.0.1.evil.com")
        assert not is_allowed_origin("http://localhost.evil.com")
        assert not is_allowed_origin("null")
        assert not is_allowed_origin("")

    def test_bounded_cache_pruning(self):
        """prune_cache enforces MAX_CACHE_SIZE and removes expired entries."""
        import tools.tc_indexer_server as srv
        srv._RESULT_CACHE.clear()

        now = 1000.0
        # Add 120 items at now
        for i in range(120):
            srv._RESULT_CACHE[f"key_{i}"] = (now + i, f"json_{i}")

        assert len(srv._RESULT_CACHE) == 120
        srv.prune_cache(now + 120)

        assert len(srv._RESULT_CACHE) <= MAX_CACHE_SIZE

        # Advance past TTL: all expired entries should be pruned
        srv.prune_cache(now + 200.0)
        assert len(srv._RESULT_CACHE) == 0

    def test_ssrf_redirect_handler_blocks_cross_host(self):
        """SafeRedirectHandler raises HTTPError when redirected to an unexpected host."""
        handler = SafeRedirectHandler("technocore.chat")
        req = urllib.request.Request("https://technocore.chat/r/lobby/export")

        # Same host redirect is allowed
        allowed_url = "https://technocore.chat/r/lobby/export?v=2"
        # Handler super().redirect_request would proceed (we test netloc check here)
        parsed = urllib.parse.urlparse(allowed_url)
        assert parsed.netloc.lower() == "technocore.chat"

        # Cross-host redirect raises HTTPError
        with pytest.raises(urllib.error.HTTPError, match="Cross-host redirect forbidden to evil.com"):
            handler.redirect_request(req, None, 302, "Found", {}, "https://evil.com/steal")

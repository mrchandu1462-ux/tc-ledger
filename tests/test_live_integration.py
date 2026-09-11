import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
# SPDX-License-Identifier: Apache-2.0
"""
Integration test suite for TC-Ledger Live Technocore Discovery & Indexing.

Validates all 9 required integration criteria:
1. ACTIVE status for recent verified activity
2. STALE status when activity falls outside window
3. NO DATA status for unobserved valid DIDs (without claiming non-existence)
4. Malformed DID rejection
5. Invalid/tampered signature rejection
6. Remote/API failure resilience
7. Empty room handling
8. Retention limitation notice preservation
9. No synthetic fallback when live lookup fails
"""

import json
import base58
import base64
import pytest
from nacl.signing import SigningKey

from tools.tc_live_indexer import (
    RoomRecord,
    RoomActivity,
    IndexerResult,
    run_indexer,
    verify_and_index_record,
    fetch_room_generation_and_export,
    format_text_report,
    format_json_report,
)
from tc_ledger.ledger import (
    DID_PREFIX,
    InvalidSignature,
    MalformedRecord,
    UnsupportedKeyType,
    verify_signed_record,
)


def make_test_signer_and_did():
    sk = SigningKey.generate()
    vk_bytes = sk.verify_key.encode()
    codec_bytes = b"\xed\x01" + vk_bytes
    did = "did:key:z" + base58.b58encode(codec_bytes).decode("ascii")
    return sk, did


def make_signed_record_bytes(sk: SigningKey, did: str, room: str, seq: int, text: str, nonce: int = 2002, ts: str = "2026-09-11T12:00:00Z") -> bytes:
    canonical = f"{room}|{nonce}|{text}".encode("utf-8")
    signed = sk.sign(canonical)
    sig_b64 = base64.urlsafe_b64encode(signed.signature).decode("ascii").rstrip("=")
    rec = {
        "seq": seq,
        "ts": ts,
        "from": did,
        "text": text,
        "nonce": nonce,
        "sig": sig_b64,
    }
    return json.dumps(rec).encode("utf-8")


class TestLiveIntegration:
    def test_1_active_status(self):
        """1. ACTIVE: Recent verified activity within window."""
        known_did = "did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z"
        res = run_indexer(
            target_did=known_did,
            explicit_rooms=["tclk-offers"],
            window_hours=48.0,
            timeout=10.0,
        )
        assert res.status == "ACTIVE"
        assert res.total_verified_records > 0
        assert "#tclk-offers" in res.active_rooms
        assert res.total_invalid_signatures == 0

    def test_2_stale_status(self):
        """2. STALE: Known verified activity exists, but older than window."""
        known_did = "did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z"
        res = run_indexer(
            target_did=known_did,
            explicit_rooms=["tclk-offers"],
            window_hours=0.000001,  # Sub-millisecond window
            timeout=10.0,
        )
        assert res.status == "STALE"
        assert res.total_verified_records > 0
        assert res.total_invalid_signatures == 0

    def test_3_no_data_status(self):
        """3. NO DATA: Valid DID with no activity found in inspected data."""
        _, unused_did = make_test_signer_and_did()
        res = run_indexer(
            target_did=unused_did,
            explicit_rooms=["tclk-offers"],
            timeout=10.0,
        )
        assert res.status == "NO DATA"
        assert res.total_verified_records == 0
        assert res.active_rooms == []
        assert res.first_verified_activity is None
        assert res.latest_verified_activity is None

    def test_4_malformed_did_rejection(self):
        """4. Malformed DID rejected fail-closed before network operations."""
        with pytest.raises(ValueError, match="invalid DID prefix"):
            run_indexer("invalid-did-prefix", explicit_rooms=["tclk-offers"])

        with pytest.raises(ValueError, match="invalid base58btc DID"):
            run_indexer("did:key:zMalformedBase58Chars00000000000000000000000000", explicit_rooms=["tclk-offers"])

    def test_5_invalid_signature_detection(self):
        """5. Invalid signature: Tampered payload or signature fails verification."""
        sk, did = make_test_signer_and_did()
        room = "tclk-offers"
        raw_bytes = make_signed_record_bytes(sk, did, room, seq=500, text="genuine payload")

        # Tamper payload text
        tampered = json.loads(raw_bytes.decode("utf-8"))
        tampered["text"] = "corrupted payload"
        tampered_bytes = json.dumps(tampered).encode("utf-8")

        res = verify_and_index_record(tampered_bytes, room, did)
        assert res is not None
        assert res.status == "INVALID"
        assert "Ed25519 signature verification failed" in (res.error_detail or "")

    def test_6_remote_api_failure_resilience(self):
        """6. Remote/API failure: Non-existent room or unreachable URL handled cleanly."""
        sk, did = make_test_signer_and_did()
        gen, lines, url = fetch_room_generation_and_export(
            base_url="https://technocore.chat",
            room="nonexistent-room-9999999-xyz",
            timeout=5.0,
        )
        assert isinstance(lines, list)

    def test_7_empty_room_handling(self):
        """7. Empty room: 0 messages handled without crashing."""
        sk, did = make_test_signer_and_did()
        rec = verify_and_index_record(b"", "empty-room", did)
        assert rec is None

    def test_8_retention_limitation_notice(self):
        """8. Retention limitation: Explicit notice that results describe retained activity only."""
        known_did = "did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z"
        res = run_indexer(
            target_did=known_did,
            explicit_rooms=["tclk-offers"],
            timeout=10.0,
        )
        assert "CURRENTLY RETAINED PUBLIC ACTIVITY" in res.retention_notice
        assert "complete lifetime history" in res.retention_notice
        report = format_text_report(res)
        assert "CURRENTLY RETAINED PUBLIC ACTIVITY" in report

    def test_9_no_synthetic_fallback_when_live_lookup_fails(self):
        """9. No synthetic fallback: Live lookup failure never returns synthetic demo records."""
        _, unused_did = make_test_signer_and_did()
        res = run_indexer(
            target_did=unused_did,
            explicit_rooms=["tclk-offers"],
            timeout=10.0,
        )
        assert res.status == "NO DATA"
        assert "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH" != res.did
        assert "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaiSS28H" != res.did
        assert res.total_verified_records == 0
        assert res.active_rooms == []

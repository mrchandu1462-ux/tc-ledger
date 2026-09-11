# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
# SPDX-License-Identifier: Apache-2.0
"""
Tests for TC Live Technocore Indexer (Proof-of-Concept)

Verifies:
1. Live/known DID verification against retained activity
2. Random/nonexistent valid DID (NO DATA)
3. Malformed DID rejection
4. Activity window status semantics (ACTIVE vs STALE)
5. Tampered/invalid signature detection (INVALID)
6. Raw export and generation metadata preservation
7. Resilience to untrusted message content
"""

import json
import pytest
from nacl.signing import SigningKey
import base58
import base64

from tools.tc_live_indexer import (
    RoomRecord,
    RoomActivity,
    IndexerResult,
    run_indexer,
    verify_and_index_record,
    parse_iso_timestamp,
    format_text_report,
    format_json_report,
)
from tc_ledger.ledger import export_leaf_hash


def generate_test_did_and_signer():
    """Helper to generate a valid Ed25519 SigningKey and corresponding did:key."""
    sk = SigningKey.generate()
    vk_bytes = sk.verify_key.encode()
    codec_bytes = b"\xed\x01" + vk_bytes
    did = "did:key:z" + base58.b58encode(codec_bytes).decode("ascii")
    return sk, did


def make_signed_line(sk: SigningKey, did: str, room: str, seq: int, text: str, nonce: int = 1001, ts: str = "2026-09-11T12:00:00Z") -> bytes:
    """Create a canonically signed JSONL export line matching Technocore specs."""
    canonical = f"{room}|{nonce}|{text}".encode("utf-8")
    signed = sk.sign(canonical)
    raw_sig = signed.signature
    sig_b64 = base64.urlsafe_b64encode(raw_sig).decode("ascii").rstrip("=")
    rec = {
        "seq": seq,
        "ts": ts,
        "from": did,
        "text": text,
        "nonce": nonce,
        "sig": sig_b64,
    }
    return json.dumps(rec).encode("utf-8")


class TestTcLiveIndexer:
    def test_known_live_did_activity(self):
        """1. Verify known DID in currently retained public Technocore activity."""
        known_did = "did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z"
        result = run_indexer(
            target_did=known_did,
            explicit_rooms=["tclk-offers"],
            timeout=10.0,
        )
        assert result.did == known_did
        assert result.total_verified_records > 0
        assert result.status in ("ACTIVE", "STALE")
        assert "#tclk-offers" in result.active_rooms
        assert result.total_invalid_signatures == 0
        assert result.room_details["tclk-offers"].generation == 1
        assert result.first_verified_activity is not None
        assert result.latest_verified_activity is not None

    def test_nonexistent_valid_did(self):
        """2. Verify validly formatted but nonexistent DID returns NO DATA."""
        _, unused_did = generate_test_did_and_signer()
        result = run_indexer(
            target_did=unused_did,
            explicit_rooms=["tclk-offers"],
            timeout=10.0,
        )
        assert result.did == unused_did
        assert result.status == "NO DATA"
        assert result.total_verified_records == 0
        assert result.total_invalid_signatures == 0
        assert result.active_rooms == []
        assert result.first_verified_activity is None
        assert result.latest_verified_activity is None

    def test_malformed_did_rejection(self):
        """3. Verify malformed DIDs are rejected with ValueError."""
        with pytest.raises(ValueError, match="invalid DID prefix"):
            run_indexer("not-a-did", explicit_rooms=["tclk-offers"])

        with pytest.raises(ValueError, match="invalid base58btc DID"):
            run_indexer("did:key:z6MkInvalidChars000000000000000000000000000000000000", explicit_rooms=["tclk-offers"])

        with pytest.raises(ValueError):
            run_indexer("did:key:zTooShort", explicit_rooms=["tclk-offers"])

    def test_stale_activity_window_semantics(self):
        """4. Verify status transitions to STALE when records fall outside activity window."""
        known_did = "did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z"
        # Using a microsecond window ensures even immediate activity is considered STALE
        result = run_indexer(
            target_did=known_did,
            explicit_rooms=["tclk-offers"],
            window_hours=0.00001,
            timeout=10.0,
        )
        assert result.total_verified_records > 0
        assert result.status == "STALE"
        assert result.total_invalid_signatures == 0

    def test_tampered_signature_detection(self):
        """5. Verify tampered payload is detected and classified as INVALID."""
        sk, did = generate_test_did_and_signer()
        room = "lobby"
        valid_line = make_signed_line(sk, did, room, seq=100, text="valid original message")

        # Verify valid line passes
        rec_valid = verify_and_index_record(valid_line, room, did)
        assert rec_valid is not None
        assert rec_valid.status == "VALID"

        # Tamper message text without altering signature
        tampered_rec = json.loads(valid_line.decode("utf-8"))
        tampered_rec["text"] = "tampered malicious message"
        tampered_line = json.dumps(tampered_rec).encode("utf-8")

        rec_tampered = verify_and_index_record(tampered_line, room, did)
        assert rec_tampered is not None
        assert rec_tampered.status == "INVALID"
        assert "Ed25519 signature verification failed" in (rec_tampered.error_detail or "")

    def test_tampered_signature_bytes(self):
        """Verify tampered signature bytes fail verification."""
        sk, did = generate_test_did_and_signer()
        room = "lobby"
        valid_line = make_signed_line(sk, did, room, seq=101, text="test")
        rec = json.loads(valid_line.decode("utf-8"))
        # Invert characters in valid base64url sig
        rec["sig"] = "A" + rec["sig"][1:]
        tampered_line = json.dumps(rec).encode("utf-8")

        res = verify_and_index_record(tampered_line, room, did)
        assert res is not None
        assert res.status == "INVALID"

    def test_untrusted_content_handling(self):
        """6. Untrusted data safety: HTML, shell escapes, URLs must not affect verification."""
        sk, did = generate_test_did_and_signer()
        room = "test-room"
        payload = "<script>alert('xss')</script> rm -rf / ; https://attacker.example.com"
        line = make_signed_line(sk, did, room, seq=102, text=payload)

        res = verify_and_index_record(line, room, did)
        assert res is not None
        assert res.status == "VALID"
        assert res.text == payload

    def test_raw_export_leaf_hash_preservation(self):
        """7. Verify raw export line bytes are preserved exactly for RFC 6962 leaf hashing."""
        sk, did = generate_test_did_and_signer()
        room = "test-room"
        raw_line = make_signed_line(sk, did, room, seq=103, text="preserve exact bytes")
        res = verify_and_index_record(raw_line, room, did)
        assert res is not None
        assert res.raw_line_bytes == raw_line
        # RFC 6962 leaf hash: sha256(0x00 || raw_line)
        h = export_leaf_hash(res.raw_line_bytes)
        assert len(h) == 32
        assert len(h.hex()) == 64

    def test_text_report_formatting(self):
        """Verify format_text_report produces exact expected sections."""
        res = IndexerResult(
            did="did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z",
            status="ACTIVE",
            rooms_scanned=["tclk-offers"],
            active_rooms=["#tclk-offers"],
            total_verified_records=5,
            total_invalid_signatures=0,
            total_unsigned_records=0,
            total_malformed_records=0,
            first_verified_activity="2026-09-11T13:00:00Z",
            latest_verified_activity="2026-09-11T13:30:00Z",
            room_details={
                "tclk-offers": RoomActivity(
                    room="tclk-offers",
                    generation=1,
                    verified_count=5,
                    latest_seq=2890000,
                    latest_ts="2026-09-11T13:30:00Z",
                )
            },
            retention_notice="CURRENTLY RETAINED PUBLIC ACTIVITY",
            endpoints_queried=["https://technocore.chat/rooms"],
            activity_window_hours=24.0,
            scanned_at_utc="2026-09-11T13:31:00Z",
        )
        report = format_text_report(res)
        assert "STATUS\nACTIVE" in report
        assert "ROOMS\n#tclk-offers" in report
        assert "VERIFIED RECORDS\n5" in report
        assert "INVALID SIGNATURES\n0" in report
        assert "FIRST VERIFIED ACTIVITY\n2026-09-11T13:00:00Z" in report
        assert "LATEST VERIFIED ACTIVITY\n2026-09-11T13:30:00Z" in report
        assert "generation: 1" in report
        assert "CURRENTLY RETAINED PUBLIC ACTIVITY" in report

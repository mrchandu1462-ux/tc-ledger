"""Security regression and hardening tests for TC-Ledger v0.3.1.

Covers findings from the independent Gemini + Surf security audit:
- F-1: New tree size authentication & verification semantics
- F-2: Room and generation trust-anchor binding limitations
- F-3: Strict canonical base64url signature decoding
- F-4: Nonce representation (int vs string) in signatures vs JCS vs raw export bytes
- F-5: Pipe delimiter collision in room identifiers
- C7 Adversarial test suite:
  1. incorrect new_tree_size
  2. room mutation
  3. generation mutation
  4. proof mutation
  5. old root mutation
  6. new root mutation
  7. truncated proof
  8. extra proof nodes
  9. non-power-of-two trees
  10. retention/eviction causing non-prefix exports
"""

import base64
import json
import tempfile
from pathlib import Path

import pytest

from tc_ledger.ledger import (
    verify_signed_record,
    evidence_commitment,
    build_consistency_proof_artifact,
    verify_consistency_proof_artifact,
    verify_consistency_proof,
    export_merkle_root,
    consistency_proof,
    MalformedRecord,
)

# Reference valid record from examples/synthetic_export.jsonl (line 1)
VALID_RECORD = {
    "seq": 1,
    "ts": "2026-09-01T12:01:00.000000Z",
    "from": "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX",
    "text": "Alice initialized session in room",
    "nonce": 1001,
    "sig": "J5PBn8HbOgv5A-rn-oNaz5rhb-PtmT3MgNq1cpsfRKNusy23gzsjh5D2r3xKSoNyeVblw6bAAQnxyANP25rQBA",
}
ROOM = "demo-room"


# ---------------------------------------------------------------------------
# F-3: Strict Base64URL Signature Decoding
# ---------------------------------------------------------------------------

def test_strict_base64_valid_signature():
    res = verify_signed_record(VALID_RECORD, ROOM)
    assert res.status == "VALID"


def test_strict_base64_appended_characters_rejected():
    # Appended exclamation marks
    bad_rec = dict(VALID_RECORD, sig=VALID_RECORD["sig"] + "!!!")
    with pytest.raises(MalformedRecord, match="sig must be valid 86-character base64url"):
        verify_signed_record(bad_rec, ROOM)


def test_strict_base64_invalid_alphabet_rejected():
    # Character '@' is not in base64url alphabet
    bad_sig = VALID_RECORD["sig"][:-1] + "@"
    bad_rec = dict(VALID_RECORD, sig=bad_sig)
    with pytest.raises(MalformedRecord, match="sig must be valid 86-character base64url"):
        verify_signed_record(bad_rec, ROOM)


def test_strict_base64_malformed_padding_rejected():
    # Single '=' padding or 3 '=' padding is invalid for 64-byte payload
    bad_rec_1 = dict(VALID_RECORD, sig=VALID_RECORD["sig"] + "=")
    bad_rec_3 = dict(VALID_RECORD, sig=VALID_RECORD["sig"] + "===")
    with pytest.raises(MalformedRecord, match="sig must be valid 86-character base64url"):
        verify_signed_record(bad_rec_1, ROOM)
    with pytest.raises(MalformedRecord, match="sig must be valid 86-character base64url"):
        verify_signed_record(bad_rec_3, ROOM)


def test_strict_base64_altered_malleable_encoding_rejected():
    # The last character of an 86-char base64url string has 4 unused bits.
    # Changing unused bits produces malleable non-canonical base64 that decodes to the same bytes.
    # Strict canonical verification must reject non-zero unused bits.
    assert VALID_RECORD["sig"].endswith("A")  # 'A' has 000000 (unused bits 0)
    malleable_sig = VALID_RECORD["sig"][:-1] + "B"  # 'B' has unused bits 000001
    bad_rec = dict(VALID_RECORD, sig=malleable_sig)
    with pytest.raises(MalformedRecord, match="signature base64url encoding is non-canonical"):
        verify_signed_record(bad_rec, ROOM)


def test_strict_base64_wrong_decoded_length_rejected():
    # Signature that decodes to 63 bytes or 65 bytes
    raw_63 = b"\x00" * 63
    sig_63 = base64.urlsafe_b64encode(raw_63).decode("ascii").rstrip("=")
    bad_rec_63 = dict(VALID_RECORD, sig=sig_63)
    with pytest.raises(MalformedRecord, match="sig must be valid 86-character base64url"):
        verify_signed_record(bad_rec_63, ROOM)


# ---------------------------------------------------------------------------
# F-4: Nonce Representation (int vs string)
# ---------------------------------------------------------------------------

def test_nonce_int_vs_string_signature_equivalence():
    # Technocore signature payload is room|nonce|text
    # Both int 1001 and str "1001" produce identical canonical bytes "demo-room|1001|Alice..."
    rec_int = dict(VALID_RECORD, nonce=1001)
    rec_str = dict(VALID_RECORD, nonce="1001")

    assert verify_signed_record(rec_int, ROOM).status == "VALID"
    assert verify_signed_record(rec_str, ROOM).status == "VALID"


def test_nonce_int_vs_string_commitment_differentiation():
    # RFC 8785 (JCS) preserves JSON data types.
    # Therefore, integer nonce 1001 produces distinct commitment from string nonce "1001".
    rec_int = dict(VALID_RECORD, nonce=1001)
    rec_str = dict(VALID_RECORD, nonce="1001")

    id_int = evidence_commitment(rec_int, ROOM)
    id_str = evidence_commitment(rec_str, ROOM)

    assert id_int != id_str
    assert id_int.startswith("tc-ledger:v1:")
    assert id_str.startswith("tc-ledger:v1:")


# ---------------------------------------------------------------------------
# F-5: Pipe Delimiter in Room Identifiers
# ---------------------------------------------------------------------------

def test_pipe_delimiter_in_room_rejected():
    # If room identifier contained '|', room="a|b", nonce=1, text="c" would collide with
    # room="a", nonce=1, text="b|1|c" (or room="a", nonce="b|1", text="c").
    # TC-Ledger strictly rejects '|' in room identifiers.
    with pytest.raises(MalformedRecord, match="room identifier must not contain delimiter '\\|'"):
        verify_signed_record(VALID_RECORD, "bad|room")

    with pytest.raises(MalformedRecord, match="room identifier must not contain delimiter '\\|'"):
        evidence_commitment(VALID_RECORD, "bad|room")

    with tempfile.TemporaryDirectory() as tmp_dir:
        p1 = Path(tmp_dir) / "gen1.jsonl"
        p2 = Path(tmp_dir) / "gen2.jsonl"
        p1.write_bytes(b'{"seq":1}\n')
        p2.write_bytes(b'{"seq":1}\n{"seq":2}\n')
        with pytest.raises(MalformedRecord, match="room identifier must not contain delimiter '\\|'"):
            build_consistency_proof_artifact(str(p1), str(p2), "bad|room", 1, 2)


# ---------------------------------------------------------------------------
# F-1 & F-2: New Tree Size Authentication & Trust-Anchor Verification
# ---------------------------------------------------------------------------

def test_new_tree_size_expected_bounds_enforced():
    old_lines = [b'{"seq":1}\n', b'{"seq":2}\n']
    new_lines = old_lines + [b'{"seq":3}\n', b'{"seq":4}\n']

    with tempfile.TemporaryDirectory() as tmp_dir:
        p1 = Path(tmp_dir) / "gen1.jsonl"
        p2 = Path(tmp_dir) / "gen2.jsonl"
        p1.write_bytes(b"".join(old_lines))
        p2.write_bytes(b"".join(new_lines))

        art = build_consistency_proof_artifact(str(p1), str(p2), "r1", 1, 2)
        assert art["old_tree_size"] == 2
        assert art["new_tree_size"] == 4

        # Verification succeeds when expected sizes match
        res_ok = verify_consistency_proof_artifact(
            art,
            expected_room="r1",
            expected_old_generation=1,
            expected_new_generation=2,
            expected_old_tree_size=2,
            expected_new_tree_size=4,
        )
        assert res_ok["valid"] is True
        assert res_ok["tree_sizes_authenticated"] is True

        # When caller does NOT specify expected sizes, tree_sizes_authenticated is False
        res_no_sizes = verify_consistency_proof_artifact(art)
        assert res_no_sizes["valid"] is True
        assert res_no_sizes["tree_sizes_authenticated"] is False

        # Caller specifies expected_new_tree_size = 5 (mismatch) -> REJECTED
        res_bad_new_size = verify_consistency_proof_artifact(art, expected_new_tree_size=5)
        assert res_bad_new_size["valid"] is False
        assert "new_tree_size mismatch" in res_bad_new_size["error"]

        # Caller specifies expected_old_tree_size = 3 (mismatch) -> REJECTED
        res_bad_old_size = verify_consistency_proof_artifact(art, expected_old_tree_size=3)
        assert res_bad_old_size["valid"] is False
        assert "old_tree_size mismatch" in res_bad_old_size["error"]


def test_tampered_artifact_tree_size_rejection():
    # Attacker tampers with new_tree_size in artifact JSON from 4 to 5 (incompatible size)
    old_lines = [b'{"seq":1}\n', b'{"seq":2}\n']
    new_lines = old_lines + [b'{"seq":3}\n', b'{"seq":4}\n']

    with tempfile.TemporaryDirectory() as tmp_dir:
        p1 = Path(tmp_dir) / "gen1.jsonl"
        p2 = Path(tmp_dir) / "gen2.jsonl"
        p1.write_bytes(b"".join(old_lines))
        p2.write_bytes(b"".join(new_lines))

        art = build_consistency_proof_artifact(str(p1), str(p2), "r1", 1, 2)
        tampered_art_5 = dict(art, new_tree_size=5)

        # Mathematical consistency verification fails
        res = verify_consistency_proof_artifact(tampered_art_5)
        assert res["valid"] is False
        assert "cryptographic consistency proof verification failed" in res["error"]

        # If attacker tampers new_tree_size to 3, verifier with expected_new_tree_size=4 catches it
        tampered_art_3 = dict(art, new_tree_size=3)
        res_anchored = verify_consistency_proof_artifact(tampered_art_3, expected_new_tree_size=4)
        assert res_anchored["valid"] is False
        assert "new_tree_size mismatch" in res_anchored["error"]


# ---------------------------------------------------------------------------
# TASK 8: Comprehensive C7 Adversarial & Conformance Matrix
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_artifact():
    old_lines = [f'{{"seq":{i}}}\n'.encode() for i in range(1, 5)]  # size 4
    new_lines = old_lines + [f'{{"seq":{i}}}\n'.encode() for i in range(5, 9)]  # size 8

    with tempfile.TemporaryDirectory() as tmp_dir:
        p1 = Path(tmp_dir) / "gen1.jsonl"
        p2 = Path(tmp_dir) / "gen2.jsonl"
        p1.write_bytes(b"".join(old_lines))
        p2.write_bytes(b"".join(new_lines))
        art = build_consistency_proof_artifact(str(p1), str(p2), "room-a", 1, 2)
    return art


def test_c7_room_mutation_rejected(sample_artifact):
    # Mutating room in artifact must be rejected when expected_room is provided
    mutated = dict(sample_artifact, room="evil-room")
    res = verify_consistency_proof_artifact(mutated, expected_room="room-a")
    assert res["valid"] is False
    assert "room mismatch" in res["error"]


def test_c7_generation_mutation_rejected(sample_artifact):
    # Mutating generations must be rejected when expected generations are provided
    mutated_old = dict(sample_artifact, old_generation=0)
    res_old = verify_consistency_proof_artifact(mutated_old, expected_old_generation=1)
    assert res_old["valid"] is False
    assert "old generation mismatch" in res_old["error"]

    mutated_new = dict(sample_artifact, new_generation=99)
    res_new = verify_consistency_proof_artifact(mutated_new, expected_new_generation=2)
    assert res_new["valid"] is False
    assert "new generation mismatch" in res_new["error"]


def test_c7_proof_mutation_rejected(sample_artifact):
    # Flipping bits in a proof node must cause verification failure
    mutated_proof = list(sample_artifact["proof"])
    # Flip first character of first proof node
    first_node = mutated_proof[0]
    flipped_char = "0" if first_node[0] != "0" else "1"
    mutated_proof[0] = flipped_char + first_node[1:]
    mutated = dict(sample_artifact, proof=mutated_proof)

    res = verify_consistency_proof_artifact(mutated)
    assert res["valid"] is False
    assert "cryptographic consistency proof verification failed" in res["error"]


def test_c7_old_root_mutation_rejected(sample_artifact):
    # Mutating old_root must be rejected both cryptographically and against anchor
    mutated = dict(sample_artifact, old_root="00" * 32)
    res = verify_consistency_proof_artifact(mutated)
    assert res["valid"] is False
    assert "cryptographic consistency proof verification failed" in res["error"]

    res_anchor = verify_consistency_proof_artifact(mutated, expected_old_root=sample_artifact["old_root"])
    assert res_anchor["valid"] is False
    assert "old root mismatch" in res_anchor["error"]


def test_c7_new_root_mutation_rejected(sample_artifact):
    # Mutating new_root must be rejected both cryptographically and against anchor
    mutated = dict(sample_artifact, new_root="00" * 32)
    res = verify_consistency_proof_artifact(mutated)
    assert res["valid"] is False
    assert "cryptographic consistency proof verification failed" in res["error"]

    res_anchor = verify_consistency_proof_artifact(mutated, expected_new_root=sample_artifact["new_root"])
    assert res_anchor["valid"] is False
    assert "new root mismatch" in res_anchor["error"]


def test_c7_truncated_proof_rejected(sample_artifact):
    # Removing a node from proof must cause failure
    if len(sample_artifact["proof"]) > 1:
        truncated_proof = sample_artifact["proof"][:-1]
    else:
        truncated_proof = []
    mutated = dict(sample_artifact, proof=truncated_proof)

    res = verify_consistency_proof_artifact(mutated)
    assert res["valid"] is False


def test_c7_extra_proof_nodes_rejected(sample_artifact):
    # Appending an extra hash to proof must cause failure
    mutated_proof = list(sample_artifact["proof"]) + ["aa" * 32]
    mutated = dict(sample_artifact, proof=mutated_proof)

    res = verify_consistency_proof_artifact(mutated)
    assert res["valid"] is False


@pytest.mark.parametrize("m,n", [(3, 5), (5, 8), (7, 11), (6, 9), (9, 13)])
def test_c7_non_power_of_two_trees(m, n):
    # Verification across various non-power-of-two tree sizes
    leaves = [f'{{"seq":{i}}}\n'.encode() for i in range(1, n + 1)]
    old_root = export_merkle_root(leaves[:m])
    new_root = export_merkle_root(leaves[:n])

    proof = consistency_proof(m, leaves[:n])
    assert verify_consistency_proof(m, n, old_root, new_root, proof) is True

    # Negative check: tampering old_root fails
    bad_old = bytes([b ^ 0x01 for b in old_root])
    assert verify_consistency_proof(m, n, bad_old, new_root, proof) is False


def test_c7_evicted_history_fails_consistency_proof():
    # Generation 1 committed lines [1, 2, 3]
    gen1_lines = [b'{"seq":1}\n', b'{"seq":2}\n', b'{"seq":3}\n']
    old_root = export_merkle_root(gen1_lines)

    # Server evicts record 1 due to retention limits.
    # Generation 2 export has only lines [2, 3, 4, 5] (NOT an append-only extension of gen1)
    gen2_evicted_lines = [b'{"seq":2}\n', b'{"seq":3}\n', b'{"seq":4}\n', b'{"seq":5}\n']
    new_root = export_merkle_root(gen2_evicted_lines)

    # Attempting to verify consistency proof between gen1 old_root and gen2 against gen2 fails
    proof = consistency_proof(len(gen1_lines), gen2_evicted_lines)
    assert verify_consistency_proof(len(gen1_lines), len(gen2_evicted_lines), old_root, new_root, proof) is False

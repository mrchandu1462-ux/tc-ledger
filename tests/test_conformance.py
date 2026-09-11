import base58
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import nacl.signing
import pytest

from tc_ledger.ledger import (
    verify_signed_record,
    evidence_commitment,
    leaf_hash,
    node_hash,
    export_leaf_hash,
    export_merkle_root,
    export_merkle_proof,
    verify_export_merkle_proof,
    expected_proof_directions,
    build_commitment_artifact,
    verify_commitment_artifact,
    build_inclusion_proof_artifact,
    verify_inclusion_proof_artifact,
    verify_export_inclusion_proof,
    verify_consistency_proof,
    consistency_proof,
    export_merkle_root,
    classify_export_lines,
    InvalidSignature,
    MalformedRecord,
    UnsupportedKeyType,
    VerificationResult,
)

ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE_FILE = ROOT / "vectors" / "conformance.json"


@pytest.fixture(scope="module")
def conformance_data():
    return json.loads(CONFORMANCE_FILE.read_text(encoding="utf-8"))


# -----------------------------------------------------------------------------
# C0: Signed Technocore Export Verification
# -----------------------------------------------------------------------------

def test_c0_valid_signed_record(conformance_data):
    c0 = conformance_data["C0_export_verification"]
    room = c0["room"]
    valid_rec = c0["valid_record"]

    res = verify_signed_record(valid_rec, room)
    assert res.status == "VALID"
    assert res.seq == valid_rec["seq"]


def test_c0_invalid_signature(conformance_data):
    c0 = conformance_data["C0_export_verification"]
    room = c0["room"]
    invalid_rec = c0["invalid_sig_record"]

    with pytest.raises(InvalidSignature):
        verify_signed_record(invalid_rec, room)


def test_c0_unsigned_record(conformance_data):
    c0 = conformance_data["C0_export_verification"]
    room = c0["room"]
    unsigned_rec = c0["unsigned_record"]

    res = verify_signed_record(unsigned_rec, room)
    assert res.status == "UNSIGNED"
    assert res.seq == unsigned_rec["seq"]


def test_c0_malformed_records(conformance_data):
    c0 = conformance_data["C0_export_verification"]
    room = c0["room"]
    for malformed in c0["malformed_records"]:
        with pytest.raises(MalformedRecord):
            verify_signed_record(malformed, room)


def test_c0_unsupported_key_type(conformance_data):
    c0 = conformance_data["C0_export_verification"]
    room = c0["room"]
    with pytest.raises(UnsupportedKeyType):
        verify_signed_record(c0["unsupported_key_record"], room)


# -----------------------------------------------------------------------------
# C1: Deterministic JCS Evidence Commitment
# -----------------------------------------------------------------------------

def test_c1_evidence_commitment_matches_vector(conformance_data):
    c1 = conformance_data["C1_evidence_commitment"]
    payload = c1["payload"]
    room = payload["room"]

    rec = {
        "seq": payload["seq"],
        "ts": payload["ts"],
        "from": payload["from"],
        "text": payload["text"],
        "nonce": payload["nonce"],
        "sig": payload["sig"],
    }
    evidence_id = evidence_commitment(rec, room)
    assert evidence_id == c1["evidence_id"]


def test_c1_evidence_commitment_whitespace_and_type_sensitivity(conformance_data):
    c1 = conformance_data["C1_evidence_commitment"]
    payload = c1["payload"]
    room = payload["room"]

    rec_normal = dict(payload)
    rec_trailing_space = dict(payload, text=payload["text"] + " ")
    rec_string_nonce = dict(payload, nonce=str(payload["nonce"]))

    id_normal = evidence_commitment(rec_normal, room)
    id_space = evidence_commitment(rec_trailing_space, room)
    id_str_nonce = evidence_commitment(rec_string_nonce, room)

    assert id_normal != id_space
    assert id_normal != id_str_nonce
    assert id_str_nonce == f"tc-ledger:v1:{c1['string_nonce_sha256']}"


# -----------------------------------------------------------------------------
# C2: Merkle Primitives & Odd-Node Promotion
# -----------------------------------------------------------------------------

def test_c2_merkle_leaf_and_node_prefixes(conformance_data):
    c2 = conformance_data["C2_merkle_primitives"]
    leaf_a_in_str = c2["leaf_A"]["input_utf8"]
    leaf_a_in = leaf_a_in_str.encode("utf-8")
    expected_leaf_a = c2["leaf_A"]["hash"]

    # Leaf prefix 0x00
    assert leaf_hash(leaf_a_in_str).hex() == expected_leaf_a
    assert export_leaf_hash(leaf_a_in).hex() == expected_leaf_a

    # Node prefix 0x01
    leaf_b_in_str = c2["leaf_B"]["input_utf8"]
    hash_a = leaf_hash(leaf_a_in_str)
    hash_b = leaf_hash(leaf_b_in_str)
    expected_node = hashlib.sha256(b"\x01" + hash_a + hash_b).hexdigest()
    assert node_hash(hash_a, hash_b).hex() == expected_node


def test_c2_odd_node_promotion_3_leaves(conformance_data):
    c2 = conformance_data["C2_merkle_primitives"]
    odd_vector = c2["odd_node_promotion_3"]
    lines = [item.encode("utf-8") for item in odd_vector["leaves"]]

    root = export_merkle_root(lines).hex()
    assert root == odd_vector["root"]


# -----------------------------------------------------------------------------
# C3: Merkle Conformance Vectors (Various Tree Geometries)
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("n", [0, 1, 2, 3, 4, 5, 7, 8])
def test_c3_merkle_tree_geometries(n):
    lines = [f"line_{i}\n".encode("utf-8") for i in range(n)]
    root = export_merkle_root(lines)
    assert len(root) == 32

    if n == 0:
        assert root == hashlib.sha256(b"").digest()
    elif n == 1:
        assert root == export_leaf_hash(lines[0])
    else:
        # Check proof for every leaf in tree
        for i in range(n):
            proof = export_merkle_proof(lines, i)
            dirs = expected_proof_directions(n, i)
            assert len(proof) == len(dirs)
            assert verify_export_merkle_proof(lines[i], proof, root)


# -----------------------------------------------------------------------------
# C4: Export Commitment (Exact Bytes, Line Endings, Generation Anchor)
# -----------------------------------------------------------------------------

def test_c4_export_commitment_exact_bytes_and_anomalies():
    room = "conformance-room"
    raw_lines = [
        b'{"seq":1,"ts":"2026-09-01T12:00:00Z","from":"did:key:z1","text":"ok"}\n',
        b"\n",  # Blank line (not an anomaly)
        b"MALFORMED_JSON_LINE\n",  # Malformed anomaly
        b'{"seq":2,"ts":"2026-09-01T12:01:00Z","from":"did:key:z1","text":"ok2"}\n',
    ]
    counts, anomalies = classify_export_lines(raw_lines, room)
    assert anomalies == [2]
    assert counts["MALFORMED"] == 1
    assert counts["UNSIGNED"] == 2

    # Unterminated final line test
    unterminated_lines = [
        b'{"seq":1,"ts":"2026-09-01T12:00:00Z","from":"did:key:z1","text":"ok"}\n',
        b'{"seq":2,"ts":"2026-09-01T12:01:00Z","from":"did:key:z1","text":"ok2"}',  # No trailing newline
    ]
    u_counts, u_anomalies = classify_export_lines(unterminated_lines, room)
    art = build_commitment_artifact(unterminated_lines, room, u_counts, u_anomalies, export_generation=10)
    assert art["export_generation"] == 10
    assert art["byte_count"] == sum(len(line) for line in unterminated_lines)
    assert art["file_sha256"] == hashlib.sha256(b"".join(unterminated_lines)).hexdigest()
    assert art["export_root"] == export_merkle_root(unterminated_lines).hex()

    assert verify_commitment_artifact(unterminated_lines, art, expected_generation=10, expected_room=room)
    assert not verify_commitment_artifact(unterminated_lines, art, expected_generation=11)


# -----------------------------------------------------------------------------
# C5: Inclusion Proof (Positive & Negative Cases)
# -----------------------------------------------------------------------------

def test_c5_inclusion_proof_positive_and_negative_cases():
    room = "conformance-room"
    raw_lines = [
        b'{"seq":1,"text":"first"}\n',
        b'{"seq":2,"text":"second"}\n',
        b'{"seq":3,"text":"third"}\n',
        b'{"seq":4,"text":"fourth"}\n',
        b'{"seq":5,"text":"fifth"}\n',
    ]
    gen = 3
    root = export_merkle_root(raw_lines)

    # Valid proof for leaf 2
    artifact = build_inclusion_proof_artifact(raw_lines, room, 2, export_generation=gen)
    assert artifact["tree_size"] == 5
    assert artifact["leaf_index"] == 2
    assert artifact["export_generation"] == gen

    assert verify_export_inclusion_proof(
        raw_lines[2],
        artifact,
        expected_root=root,
        expected_room=room,
        expected_generation=gen,
    )

    # Negative 1: Wrong record bytes
    assert not verify_export_inclusion_proof(
        b"wrong bytes\n",
        artifact,
        expected_root=root,
        expected_room=room,
        expected_generation=gen,
    )

    # Negative 2: Wrong root
    assert not verify_export_inclusion_proof(
        raw_lines[2],
        artifact,
        expected_root="00" * 32,
        expected_room=room,
        expected_generation=gen,
    )

    # Negative 3: Wrong generation
    assert not verify_export_inclusion_proof(
        raw_lines[2],
        artifact,
        expected_root=root,
        expected_room=room,
        expected_generation=gen + 1,
    )

    # Negative 4: Wrong room
    assert not verify_export_inclusion_proof(
        raw_lines[2],
        artifact,
        expected_root=root,
        expected_room="other-room",
        expected_generation=gen,
    )

    # Negative 5: Corrupted audit path sibling
    corrupted_artifact = dict(artifact)
    corrupted_path = [dict(step) for step in artifact["audit_path"]]
    corrupted_path[0]["sibling_hash"] = "ff" * 32
    corrupted_artifact["audit_path"] = corrupted_path
    assert not verify_export_inclusion_proof(
        raw_lines[2],
        corrupted_artifact,
        expected_root=root,
        expected_room=room,
        expected_generation=gen,
    )

    # Negative 6: Corrupted audit path position
    corrupted_artifact2 = dict(artifact)
    corrupted_path2 = [dict(step) for step in artifact["audit_path"]]
    corrupted_path2[0]["position"] = "right" if corrupted_path2[0]["position"] == "left" else "left"
    corrupted_artifact2["audit_path"] = corrupted_path2
    assert not verify_export_inclusion_proof(
        raw_lines[2],
        corrupted_artifact2,
        expected_root=root,
        expected_room=room,
        expected_generation=gen,
    )


# -----------------------------------------------------------------------------
# Phase 9: Live Technocore Protocol Boundary Cases
# -----------------------------------------------------------------------------

def test_phase9_live_technocore_nonce_boundaries():
    seed = hashlib.sha256(b"seed-phase9-nonce").digest()
    sk = nacl.signing.SigningKey(seed)
    vk = sk.verify_key
    pub_bytes = vk.encode()
    did = "did:key:z" + base58.b58encode(b"\xed\x01" + pub_bytes).decode("ascii")
    room = "boundary-room"

    # 1. Valid 1-digit nonce
    msg_1 = f"{room}|7|short_nonce".encode("utf-8")
    sig_1 = base64.urlsafe_b64encode(sk.sign(msg_1).signature).decode("ascii").rstrip("=")
    rec_1 = {"seq": 1, "ts": "2026-09-01T12:00:00Z", "from": did, "text": "short_nonce", "nonce": 7, "sig": sig_1}
    assert verify_signed_record(rec_1, room).status == "VALID"

    # 2. Valid 19-digit nonce (max supported decimal digits)
    nonce_19 = 9999999999999999999
    msg_19 = f"{room}|{nonce_19}|max_nonce".encode("utf-8")
    sig_19 = base64.urlsafe_b64encode(sk.sign(msg_19).signature).decode("ascii").rstrip("=")
    rec_19 = {"seq": 2, "ts": "2026-09-01T12:01:00Z", "from": did, "text": "max_nonce", "nonce": nonce_19, "sig": sig_19}
    assert verify_signed_record(rec_19, room).status == "VALID"

    # 3. Invalid 20-digit nonce (> 19 digits)
    nonce_20 = 10000000000000000000
    rec_20 = {"seq": 3, "ts": "2026-09-01T12:02:00Z", "from": did, "text": "too_big", "nonce": nonce_20, "sig": sig_19}
    with pytest.raises(MalformedRecord):
        verify_signed_record(rec_20, room)


def test_phase9_live_technocore_message_size_4096_characters():
    seed = hashlib.sha256(b"seed-phase9-4096").digest()
    sk = nacl.signing.SigningKey(seed)
    vk = sk.verify_key
    pub_bytes = vk.encode()
    did = "did:key:z" + base58.b58encode(b"\xed\x01" + pub_bytes).decode("ascii")
    room = "boundary-room"

    # Message at decoder 4096 boundary
    large_text = "A" * 4096
    nonce = 123456789
    msg = f"{room}|{nonce}|{large_text}".encode("utf-8")
    sig = base64.urlsafe_b64encode(sk.sign(msg).signature).decode("ascii").rstrip("=")
    rec = {"seq": 100, "ts": "2026-09-01T12:00:00Z", "from": did, "text": large_text, "nonce": nonce, "sig": sig}

    res = verify_signed_record(rec, room)
    assert res.status == "VALID"


def test_phase9_retained_export_sparse_sequence_window():
    # Retained exports from rolling buffers have sequence gaps from swept/cleaned history
    room = "boundary-room"
    sparse_export = [
        b'{"seq":5120,"ts":"2026-09-01T12:00:00Z","from":"did:key:z1","text":"checkpoint 1"}\n',
        b'{"seq":10240,"ts":"2026-09-01T12:10:00Z","from":"did:key:z1","text":"checkpoint 2"}\n',
        b'{"seq":163840,"ts":"2026-09-01T12:20:00Z","from":"did:key:z1","text":"checkpoint 3"}\n',
    ]
    counts, anomalies = classify_export_lines(sparse_export, room)
    assert len(anomalies) == 0
    art = build_commitment_artifact(sparse_export, room, counts, anomalies, export_generation=42)
    assert art["line_count"] == 3
    assert art["export_generation"] == 42
    assert verify_commitment_artifact(sparse_export, art, expected_generation=42, expected_room=room)


# -----------------------------------------------------------------------------
# C7: Cross-Generation Merkle Consistency Proofs
# -----------------------------------------------------------------------------

def test_c7_conformance_vectors(conformance_data):
    c7 = conformance_data["C7_consistency_proof_cases"]
    cases = c7["cases"]
    assert len(cases) > 0

    for case in cases:
        old_size = case["old_tree_size"]
        new_size = case["new_tree_size"]
        old_root = case["old_root"]
        new_root = case["new_root"]
        proof = case["proof"]
        expected_valid = case["expected_valid"]

        res = verify_consistency_proof(
            old_size=old_size,
            new_size=new_size,
            old_root=old_root,
            new_root=new_root,
            proof=proof,
        )
        assert res is expected_valid, f"Failed for case {case['id']}"


def test_c7_conformance_positive_vectors_regenerated(conformance_data):
    c7 = conformance_data["C7_consistency_proof_cases"]
    leaf_fixtures = [l.encode("utf-8") for l in c7["leaf_fixtures"]]

    for case in c7["cases"]:
        if not case["expected_valid"]:
            continue

        m = case["old_tree_size"]
        n = case["new_tree_size"]
        gen_proof = consistency_proof(m, leaf_fixtures[:n])
        gen_proof_hex = [p.hex() for p in gen_proof]

        assert gen_proof_hex == case["proof"], f"Regenerated proof mismatch for case {case['id']}"
        assert export_merkle_root(leaf_fixtures[:m]).hex() == case["old_root"]
        assert export_merkle_root(leaf_fixtures[:n]).hex() == case["new_root"]

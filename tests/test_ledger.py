import base64
import json

import base58
import pytest
from nacl.signing import SigningKey

from tc_ledger.ledger import (
    InvalidSignature,
    MalformedRecord,
    UnsupportedKeyType,
    verify_signed_record,
    verify_export,
    evidence_commitment,
    leaf_hash,
    merkle_root,
    merkle_proof,
    verify_merkle_proof,
)


def make_did(signing_key: SigningKey) -> str:
    public_key = bytes(signing_key.verify_key)
    payload = b"\xed\x01" + public_key
    return "did:key:z" + base58.b58encode(payload).decode()


def make_record(room="kibble", nonce=12345, text="hello"):
    signing_key = SigningKey.generate()
    did = make_did(signing_key)

    message = f"{room}|{nonce}|{text}".encode("utf-8")
    signature = signing_key.sign(message).signature
    sig = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return {
        "seq": 1,
        "ts": "2026-09-01T00:00:00Z",
        "from": did,
        "text": text,
        "nonce": nonce,
        "sig": sig,
    }


def test_valid_signed_record():
    record = make_record()
    result = verify_signed_record(record, "kibble")
    assert result.status == "VALID"


def test_tampered_text_is_invalid():
    record = make_record()
    record["text"] = "tampered"

    with pytest.raises(InvalidSignature):
        verify_signed_record(record, "kibble")


def test_wrong_room_is_invalid():
    record = make_record(room="kibble")

    with pytest.raises(InvalidSignature):
        verify_signed_record(record, "lobby")


def test_unsigned_record():
    record = make_record()
    del record["sig"]
    del record["nonce"]

    result = verify_signed_record(record, "kibble")
    assert result.status == "UNSIGNED"


def test_missing_required_field_is_malformed():
    record = make_record()
    del record["text"]

    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")


def test_unsupported_multicodec():
    record = make_record()

    decoded = base58.b58decode(record["from"][9:])
    fake_payload = b"\x80\x01" + decoded[2:]
    record["from"] = "did:key:z" + base58.b58encode(fake_payload).decode()

    with pytest.raises(UnsupportedKeyType):
        verify_signed_record(record, "kibble")


def test_correct_multicodec_wrong_key_length():
    record = make_record()

    decoded = base58.b58decode(record["from"][9:])
    truncated_payload = b"\xed\x01" + decoded[2:-1]
    record["from"] = "did:key:z" + base58.b58encode(truncated_payload).decode()

    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")


def test_invalid_signature_length():
    record = make_record()
    record["sig"] = "AAAA"

    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")


def test_empty_export(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")

    counts = verify_export(str(path), "kibble")

    assert counts == {
        "VALID": 0,
        "INVALID": 0,
        "UNSIGNED": 0,
        "MALFORMED": 0,
        "UNSUPPORTED_KEY": 0,
    }


def test_truncated_json_line(tmp_path):
    path = tmp_path / "truncated.jsonl"
    path.write_text(
        '{"seq":1,"ts":"2026-09-01T00:00:00Z","from":"did:key:z',
        encoding="utf-8",
    )

    counts = verify_export(str(path), "kibble")

    assert counts["MALFORMED"] == 1
    assert counts["VALID"] == 0


def test_export_counts(tmp_path):
    valid = make_record()
    unsigned = make_record()
    del unsigned["sig"]
    del unsigned["nonce"]

    path = tmp_path / "sample.jsonl"
    path.write_text(
        json.dumps(valid) + "\n" + json.dumps(unsigned) + "\n",
        encoding="utf-8",
    )

    counts = verify_export(str(path), "kibble")

    assert counts["VALID"] == 1
    assert counts["UNSIGNED"] == 1
    assert counts["INVALID"] == 0
    assert counts["MALFORMED"] == 0
    assert counts["UNSUPPORTED_KEY"] == 0


def test_evidence_commitment_matches_v1_vector():
    record = {
        "seq": 123456,
        "ts": "2026-09-01T00:00:00Z",
        "from": "did:key:z6MkTestVector",
        "text": "tc-ledger v1 test",
        "nonce": 17002,
        "sig": "TEST_SIGNATURE_64_BYTES_PLACEHOLDER",
    }

    assert evidence_commitment(record, "kibble") == (
        "tc-ledger:v1:"
        "892e8c6b6cd74e6bee0b60ab5ed0e1d546f1640195c7f0604687218bdfc6c677"
    )

MERKLE_TEST_IDS = [
    "tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000001",
    "tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000002",
    "tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000003",
    "tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000004",
    "tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000005",
]


def test_merkle_empty_root():
    assert merkle_root([]).hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_merkle_single_leaf_root_equals_leaf():
    evidence_id = "tc-ledger:v1:single"

    assert merkle_root([evidence_id]) == leaf_hash(evidence_id)


def test_merkle_five_leaf_root_matches_v1_vector():
    assert merkle_root(MERKLE_TEST_IDS).hex() == (
        "47e08ddf4237cb6466253e1cbad77d3aa6607e815436085fcb36c9799e52739d"
    )


def test_merkle_seven_leaf_root_matches_reproduced_vector():
    evidence_ids = [
        f"tc-ledger:v1:{i:064d}"
        for i in range(1, 8)
    ]

    assert merkle_root(evidence_ids).hex() == (
        "2f6d403229481753bd718e317a6652fb31372dd0e16df7cb2db4403642f35664"
    )

def test_merkle_leaf_five_proof_matches_v1_vector():
    evidence_ids = [
        f"tc-ledger:v1:{i:064d}"
        for i in range(1, 6)
    ]

    proof = merkle_proof(evidence_ids, 4)

    assert len(proof) == 1
    assert proof[0][0].hex() == (
        "be6a2436be3e7269e50d8ecea3b21ff98d87ab432c92f25fc21cf1bb15a91c8e"
    )
    assert proof[0][1] == "left"

    assert verify_merkle_proof(
        evidence_ids[4],
        proof,
        merkle_root(evidence_ids),
    )


def test_merkle_leaf_one_three_step_proof_matches_v1_vector():
    evidence_ids = [
        f"tc-ledger:v1:{i:064d}"
        for i in range(1, 6)
    ]

    proof = merkle_proof(evidence_ids, 0)

    assert len(proof) == 3

    assert proof[0][0].hex() == (
        "dea3c2984c88f1fb936c44d8fdb7e7b8ddcfb43fa8c9c55c7b51702e8e5042c4"
    )
    assert proof[0][1] == "right"

    assert proof[1][0].hex() == (
        "94ff3c158e2f0c09f0f8e48ebae11ef4aa2f7f894acdaa5c25311fd065b8a030"
    )
    assert proof[1][1] == "right"

    assert proof[2][0].hex() == (
        "91d067d984e8177fe64ac7db2aa071f56246a2e95f4339214c79d655ad8ff8dc"
    )
    assert proof[2][1] == "right"

    assert verify_merkle_proof(
        evidence_ids[0],
        proof,
        merkle_root(evidence_ids),
    )


def test_merkle_seven_leaf_last_node_proof_verifies():
    evidence_ids = [
        f"tc-ledger:v1:{i:064d}"
        for i in range(1, 8)
    ]

    proof = merkle_proof(evidence_ids, 6)

    assert len(proof) == 2
    assert proof[0][0].hex() == (
        "5f3ccba5ef159588f89527559c6b6b1c645123c4ec2eac261b4e40743650572e"
    )
    assert proof[0][1] == "left"

    assert proof[1][0].hex() == (
        "be6a2436be3e7269e50d8ecea3b21ff98d87ab432c92f25fc21cf1bb15a91c8e"
    )
    assert proof[1][1] == "left"

    assert verify_merkle_proof(
        evidence_ids[6],
        proof,
        merkle_root(evidence_ids),
    )


def test_merkle_tampered_proof_is_rejected():
    evidence_ids = [
        f"tc-ledger:v1:{i:064d}"
        for i in range(1, 6)
    ]

    proof = merkle_proof(evidence_ids, 0)
    sibling, position = proof[0]

    tampered_proof = list(proof)
    tampered_proof[0] = (
        bytes([sibling[0] ^ 1]) + sibling[1:],
        position,
    )

    assert verify_merkle_proof(
        evidence_ids[0],
        proof,
        merkle_root(evidence_ids),
    )

    assert not verify_merkle_proof(
        evidence_ids[0],
        tampered_proof,
        merkle_root(evidence_ids),
    )

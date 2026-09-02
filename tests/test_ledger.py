import base64
import json
import sys

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
    export_leaf_hash,
    export_merkle_root,
    map_evidence_to_export,
    find_duplicate_evidence_ids,
    EvidenceLeafMapping,
    ExportEvidenceIndex,
    merkle_proof,
    verify_merkle_proof,
    main,
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


def test_commit_cli_clean_export(tmp_path, capsys):
    valid = make_record()
    unsigned = make_record()
    del unsigned["sig"]
    del unsigned["nonce"]

    path = tmp_path / "sample.jsonl"
    path.write_text(
        json.dumps(valid) + "\n" + json.dumps(unsigned) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = ["tc-ledger", "commit", "--room", "kibble", str(path)]
    try:
        exit_code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Room: kibble" in captured.out
    assert "Export lines: 2" in captured.out
    assert "Valid signatures: 1" in captured.out
    assert "Unsigned records: 1" in captured.out
    assert "Evidence mappings: 1" in captured.out
    assert "Duplicate evidence IDs: 0" in captured.out


def test_commit_cli_tampered_export(tmp_path, capsys):
    valid = make_record()

    tampered = dict(valid)
    tampered["text"] = "tampered"

    path = tmp_path / "tampered.jsonl"
    path.write_text(
        json.dumps(tampered) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = ["tc-ledger", "commit", "--room", "kibble", str(path)]
    try:
        exit_code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Room: kibble" in captured.out
    assert "Export lines: 1" in captured.out
    assert "Invalid signatures: 1" in captured.out
    assert "Evidence mappings: 0" in captured.out
    assert "INVALID line 1" in captured.err

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

EXPORT_RAW_LINES = [
    b'{"seq":1,"text":"alpha"}' + bytes([10]),
    b'{"seq":2,"text":"beta"}' + bytes([10]),
    bytes([10]),
    b'{"seq":3,"text":',
]


def test_export_leaf_hash_matches_raw_byte_vector():
    expected = [
        "abdc89455a812d5e701133e2b0e61f0c0978dd358021e0c75d18037b93f922b5",
        "22187d1fdaa8ec03cbf0cbfe727b98698dbe586ed8c6de135ab9e49cbe1ec3a7",
        "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e",
        "38c3cb8ccae67d1a734a9bb5fd87959781a3c01badf69f2befd6534b78360fb8",
    ]

    actual = [
        export_leaf_hash(raw_line).hex()
        for raw_line in EXPORT_RAW_LINES
    ]

    assert actual == expected


def test_export_merkle_root_matches_raw_byte_vector():
    assert export_merkle_root(EXPORT_RAW_LINES).hex() == (
        "d3fda195c2bec1d0882440c4fa72777d71d4e6079463852f2fb44ecabacc281b"
    )


def test_export_empty_root_matches_sha256_empty():
    assert export_merkle_root([]).hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_export_single_line_root_equals_leaf():
    raw_line = b'{"seq":1,"text":"single"}' + bytes([10])

    assert export_merkle_root([raw_line]) == export_leaf_hash(raw_line)

def make_deterministic_mapping_records():
    import base64
    import base58
    from nacl.signing import SigningKey

    def make_did(signing_key):
        public_key = bytes(signing_key.verify_key)
        payload = b"\xed\x01" + public_key
        return "did:key:z" + base58.b58encode(payload).decode()

    def make_record(seed, seq, nonce, text):
        signing_key = SigningKey(seed=bytes(seed))
        did = make_did(signing_key)

        message = f"kibble|{nonce}|{text}".encode("utf-8")
        signature = signing_key.sign(message).signature
        sig = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return {
            "seq": seq,
            "ts": "2026-09-01T00:00:00Z",
            "from": did,
            "text": text,
            "nonce": nonce,
            "sig": sig,
        }

    valid_1 = make_record(range(0, 32), 1, 10001, "alpha")
    valid_2 = make_record(range(32, 64), 2, 10002, "beta")

    unsigned = make_record(range(64, 96), 5, 10005, "unsigned")
    del unsigned["sig"]
    del unsigned["nonce"]

    malformed = b'{"seq":4,"text":'

    invalid = make_record(range(96, 128), 6, 10006, "tampered")
    invalid["text"] = "tampered-after-signing"

    records = [
        valid_1,
        valid_2,
        None,
        malformed,
        unsigned,
        invalid,
    ]

    raw_lines = []

    for item in records:
        if isinstance(item, bytes):
            raw_lines.append(item)
        elif item is None:
            raw_lines.append(bytes([10]))
        else:
            raw_lines.append(
                json.dumps(
                    item,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8") + bytes([10])
            )

    return records, raw_lines


def test_map_evidence_to_export_matches_deterministic_vector():
    records, raw_lines = make_deterministic_mapping_records()

    index = map_evidence_to_export(raw_lines, "kibble")

    assert index.export_root.hex() == (
        "f43ea7c83535b25d01b218be956e0768d5015179dddb681569d0dc4929de40d5"
    )

    assert index.export_root == export_merkle_root(raw_lines)

    assert index.mappings == [
        EvidenceLeafMapping(
            evidence_id=(
                "tc-ledger:v1:"
                "91e246308a156e69afcd0837bb8d403e96f5ca0a3f0c6576e2243acc77ec3617"
            ),
            export_leaf_index=0,
        ),
        EvidenceLeafMapping(
            evidence_id=(
                "tc-ledger:v1:"
                "9b70bb047371584384fc49b61c6206f9316520cebae3a741e279f330f55e73f9"
            ),
            export_leaf_index=1,
        ),
    ]


def test_map_evidence_to_export_excludes_non_valid_lines():
    records, raw_lines = make_deterministic_mapping_records()

    index = map_evidence_to_export(raw_lines, "kibble")

    mapped_indices = [
        mapping.export_leaf_index
        for mapping in index.mappings
    ]

    assert mapped_indices == [0, 1]

    assert all(
        index not in mapped_indices
        for index in [2, 3, 4, 5]
    )


def test_map_evidence_to_export_empty_export():
    index = map_evidence_to_export([], "kibble")

    assert index.export_root.hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert index.mappings == []


def test_find_duplicate_evidence_ids_preserves_duplicates():
    duplicate_id = "tc-ledger:v1:duplicate"

    index = ExportEvidenceIndex(
        export_root=bytes(32),
        mappings=[
            EvidenceLeafMapping(duplicate_id, 0),
            EvidenceLeafMapping("tc-ledger:v1:other", 1),
            EvidenceLeafMapping(duplicate_id, 2),
            EvidenceLeafMapping(duplicate_id, 3),
        ],
    )

    assert find_duplicate_evidence_ids(index) == [duplicate_id]


def test_valid_mapping_indices_are_zero_based():
    _, raw_lines = make_deterministic_mapping_records()

    index = map_evidence_to_export(raw_lines, "kibble")

    assert [m.export_leaf_index for m in index.mappings] == [0, 1]
    assert [m.export_leaf_index + 1 for m in index.mappings] == [1, 2]

def test_mapping_excludes_malformed_line():
    _, raw_lines = make_deterministic_mapping_records()

    index = map_evidence_to_export(raw_lines, "kibble")

    assert all(
        mapping.export_leaf_index != 3
        for mapping in index.mappings
    )


def test_mapping_excludes_unsigned_line():
    _, raw_lines = make_deterministic_mapping_records()

    index = map_evidence_to_export(raw_lines, "kibble")

    assert all(
        mapping.export_leaf_index != 4
        for mapping in index.mappings
    )


def test_mapping_excludes_invalid_signature_line():
    _, raw_lines = make_deterministic_mapping_records()

    index = map_evidence_to_export(raw_lines, "kibble")

    assert all(
        mapping.export_leaf_index != 5
        for mapping in index.mappings
    )


def test_mapping_excludes_unsupported_key_line():
    records, raw_lines = make_deterministic_mapping_records()

    record = records[0].copy()

    decoded = base58.b58decode(record["from"][9:])
    fake_payload = b"\x80\x01" + decoded[2:]
    record["from"] = (
        "did:key:z" + base58.b58encode(fake_payload).decode()
    )

    raw_lines[0] = (
        json.dumps(
            record,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8") + bytes([10])
    )

    index = map_evidence_to_export(raw_lines, "kibble")

    assert all(
        mapping.export_leaf_index != 0
        for mapping in index.mappings
    )

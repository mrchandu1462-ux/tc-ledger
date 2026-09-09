import base64
import json
import sys
import hashlib

import base58
import pytest
from nacl.signing import SigningKey

from tc_ledger.ledger import (
    InvalidSignature,
    MalformedRecord,
    UnsupportedKeyType,
    verify_signed_record,
    verify_export,
    build_commitment_artifact,
    classify_export_lines,
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
    build_inclusion_proof_artifact,
    verify_export_inclusion_proof,
    verify_inclusion_proof_artifact,
    export_merkle_proof,
    verify_export_merkle_proof,
    expected_proof_directions,
    write_inclusion_proof_artifact,
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


def test_classify_export_lines_returns_anomaly_indices(tmp_path):
    valid = make_record()
    unsigned = make_record()
    del unsigned["sig"]
    del unsigned["nonce"]

    malformed = '{"seq":1,"ts":"broken"'

    path = tmp_path / "classify.jsonl"
    path.write_text(
        json.dumps(valid) + "\n"
        + json.dumps(unsigned) + "\n"
        + malformed + "\n",
        encoding="utf-8",
    )

    raw_lines = path.read_bytes().splitlines(keepends=True)
    counts, anomaly_indices = classify_export_lines(raw_lines, "kibble")

    assert counts["VALID"] == 1
    assert counts["UNSIGNED"] == 1
    assert counts["MALFORMED"] == 1
    assert counts["INVALID"] == 0
    assert counts["UNSUPPORTED_KEY"] == 0
    assert anomaly_indices == [2]


def test_build_commitment_artifact_contains_c4_metadata():
    raw_lines = [
        b'{"first":1}\n',
        b'{"second":2}\n',
    ]

    counts = {
        "VALID": 1,
        "INVALID": 0,
        "UNSIGNED": 1,
        "MALFORMED": 0,
        "UNSUPPORTED_KEY": 0,
    }
    anomaly_indices = [1]

    artifact = build_commitment_artifact(
        raw_lines,
        "kibble",
        counts,
        anomaly_indices,
    )

    assert artifact["version"] == 1
    assert artifact["profile"] == "tc-ledger/1"
    assert artifact["room"] == "kibble"
    assert artifact["line_count"] == 2
    assert artifact["byte_count"] == sum(len(line) for line in raw_lines)
    assert artifact["file_sha256"] == hashlib.sha256(
        b"".join(raw_lines)
    ).hexdigest()
    assert artifact["export_root"] == export_merkle_root(raw_lines).hex()
    assert artifact["verification"] == counts
    assert artifact["anomaly_indices"] == [1]


def test_build_commitment_artifact_preserves_exact_bytes():
    raw_lines = [
        b'{"text":"one"}\r\n',
        b'{"text":"two"}\n',
    ]

    counts = {
        "VALID": 2,
        "INVALID": 0,
        "UNSIGNED": 0,
        "MALFORMED": 0,
        "UNSUPPORTED_KEY": 0,
    }

    artifact = build_commitment_artifact(
        raw_lines,
        "kibble",
        counts,
        [],
    )

    expected = hashlib.sha256(
        b'{"text":"one"}\r\n{"text":"two"}\n'
    ).hexdigest()

    assert artifact["line_count"] == 2
    assert artifact["byte_count"] == 31
    assert artifact["file_sha256"] == expected

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

def test_export_line_terminator_changes_root():
    content = b'{"seq":1,"text":"same"}'

    lf_root = export_merkle_root([content + b"\n"])
    crlf_root = export_merkle_root([content + b"\r\n"])

    assert lf_root != crlf_root

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

def _rfc6962_reference_root(evidence_ids):
    """Independent RFC 6962 recursive reference construction."""
    if not evidence_ids:
        return hashlib.sha256(b"").digest()

    leaves = [
        hashlib.sha256(b"\x00" + evidence_id.encode("utf-8")).digest()
        for evidence_id in evidence_ids
    ]

    def build(items):
        if len(items) == 1:
            return items[0]

        split = 1 << (len(items).bit_length() - 1)
        if split == len(items):
            split >>= 1

        return hashlib.sha256(
            b"\x01" + build(items[:split]) + build(items[split:])
        ).digest()

    return build(leaves)


def _rfc6962_reference_proof(evidence_ids, index):
    """Independent RFC 6962 recursive proof construction."""
    def subtree_root(start, end):
        return _rfc6962_reference_root(evidence_ids[start:end])

    def build(start, end):
        if end - start == 1:
            return subtree_root(start, end), []

        split = 1 << ((end - start).bit_length() - 1)
        if split == end - start:
            split >>= 1

        middle = start + split

        if index < middle:
            root, path = build(start, middle)
            sibling = subtree_root(middle, end)
            return root, path + [(sibling, "right")]

        root, path = build(middle, end)
        sibling = subtree_root(start, middle)
        return root, path + [(sibling, "left")]

    _, proof = build(0, len(evidence_ids))
    return proof

def test_merkle_rfc6962_reference_roots_n_0_through_64():
    for size in range(65):
        evidence_ids = [
            f"tc-ledger:v1:{i:064d}"
            for i in range(size)
        ]

        assert merkle_root(evidence_ids) == _rfc6962_reference_root(
            evidence_ids
        )


def test_merkle_rfc6962_reference_proofs_n_1_through_64():
    for size in range(1, 65):
        evidence_ids = [
            f"tc-ledger:v1:{i:064d}"
            for i in range(size)
        ]

        expected_root = _rfc6962_reference_root(evidence_ids)

        for index in range(size):
            actual = merkle_proof(evidence_ids, index)
            expected = _rfc6962_reference_proof(evidence_ids, index)

            assert actual == expected
            assert verify_merkle_proof(
                evidence_ids[index],
                actual,
                expected_root,
            )

def test_export_byte_model_preserves_final_unterminated_line():
    content = b'{"seq":1,"text":"final"}'

    assert export_merkle_root([content]) == export_leaf_hash(content)


def test_export_byte_model_treats_blank_line_as_zero_length_leaf():
    blank = b"\n"

    assert export_merkle_root([blank]) == export_leaf_hash(blank)


def test_export_byte_model_distinguishes_lf_crlf_and_literal_cr():
    content = b'{"seq":1,"text":"same"}'

    lf = export_leaf_hash(content + b"\n")
    crlf = export_leaf_hash(content + b"\r\n")
    cr = export_leaf_hash(content + b"\r")

    assert lf != crlf
    assert lf != cr
    assert cr != crlf


def test_export_byte_model_hashes_raw_bytes_without_utf8_decoding():
    raw_line = b"\xff\xfe\x00\x80\n"

    assert export_merkle_root([raw_line]) == export_leaf_hash(raw_line)


def test_export_byte_model_double_newline_creates_two_leaves():
    first = b'{"seq":1}\n'
    second = b"\n"

    root = export_merkle_root([first, second])

    assert root != export_leaf_hash(first)
    assert root != export_leaf_hash(second)


def test_export_byte_model_empty_file_has_sha256_empty_root():
    assert export_merkle_root([]) == hashlib.sha256(b"").digest()

# ---------------------------------------------------------------------------
# C5: Export Verification & Merkle Inclusion Proofs
# ---------------------------------------------------------------------------

def test_nonce_zero_padded_string():
    record = make_record(room="kibble", nonce="0000000042", text="zero-padded")
    result = verify_signed_record(record, "kibble")
    assert result.status == "VALID"


def test_nonce_zero_padded_string_tamper_to_int():
    record = make_record(room="kibble", nonce="0000000042", text="zero-padded")
    record["nonce"] = 42
    with pytest.raises(InvalidSignature):
        verify_signed_record(record, "kibble")


def test_nonce_zero_padded_string_tamper_value():
    record = make_record(room="kibble", nonce="0000000042", text="zero-padded")
    record["nonce"] = "0000000043"
    with pytest.raises(InvalidSignature):
        verify_signed_record(record, "kibble")


def test_nonce_boolean_rejected():
    record = make_record()
    record["nonce"] = True
    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")

    record["nonce"] = False
    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")


def test_nonce_invalid_string():
    record = make_record()
    record["nonce"] = "not_a_number"
    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")

    record["nonce"] = "-1"
    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")


def test_nonce_oversized():
    record = make_record()
    record["nonce"] = 10**20
    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")

    record["nonce"] = "1" * 20
    with pytest.raises(MalformedRecord):
        verify_signed_record(record, "kibble")


@pytest.mark.parametrize("tree_size", [1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32])
def test_inclusion_proof_every_leaf_position(tree_size):
    raw_lines = [f'{{"seq":{i},"text":"line_{i}"}}\n'.encode("utf-8") for i in range(tree_size)]
    room = "testroom"
    expected_root = export_merkle_root(raw_lines)

    for leaf_index in range(tree_size):
        artifact = build_inclusion_proof_artifact(
            raw_lines,
            room=room,
            index=leaf_index,
            export_generation=0,
        )

        assert artifact["version"] == 1
        assert artifact["profile"] == "tc-ledger/1"
        assert artifact["room"] == room
        assert artifact["export_generation"] == 0
        assert artifact["leaf_index"] == leaf_index
        assert artifact["tree_size"] == tree_size
        assert artifact["leaf_hash"] == export_leaf_hash(raw_lines[leaf_index]).hex()
        assert artifact["export_root"] == expected_root.hex()

        # Independent verification (no full export)
        assert verify_export_inclusion_proof(
            raw_lines[leaf_index],
            artifact,
            expected_root=expected_root,
            expected_generation=0,
            expected_room=room,
        )

        # Full export verification
        assert verify_inclusion_proof_artifact(
            artifact,
            raw_lines,
            expected_generation=0,
            expected_room=room,
        )


def test_empty_export_cannot_produce_inclusion_proof():
    with pytest.raises(IndexError):
        build_inclusion_proof_artifact([], "room", 0)

    # Empty export root is valid canonical root, but tree_size 0 artifact must fail verification
    fake_empty_artifact = {
        "version": 1,
        "profile": "tc-ledger/1",
        "room": "room",
        "export_generation": 0,
        "leaf_index": 0,
        "tree_size": 0,
        "leaf_hash": hashlib.sha256(b"").hexdigest(),
        "export_root": hashlib.sha256(b"").hexdigest(),
        "audit_path": [],
    }
    assert not verify_export_inclusion_proof(b"", fake_empty_artifact)
    assert not verify_inclusion_proof_artifact(fake_empty_artifact, [])


def test_single_record_export_inclusion_proof():
    raw_line = b'{"seq":1,"text":"single"}\n'
    raw_lines = [raw_line]
    room = "kibble"

    artifact = build_inclusion_proof_artifact(raw_lines, room, 0, export_generation=42)

    assert artifact["tree_size"] == 1
    assert artifact["leaf_index"] == 0
    assert artifact["audit_path"] == []
    assert artifact["leaf_hash"] == export_leaf_hash(raw_line).hex()
    assert artifact["export_root"] == export_leaf_hash(raw_line).hex()
    assert artifact["export_generation"] == 42

    assert verify_export_inclusion_proof(
        raw_line,
        artifact,
        expected_root=export_leaf_hash(raw_line),
        expected_generation=42,
    )
    assert verify_inclusion_proof_artifact(artifact, raw_lines, expected_generation=42)


def test_tampered_record_bytes_fails_verification():
    raw_lines = [f'{{"seq":{i}}}\n'.encode("utf-8") for i in range(5)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 2)

    # Tamper the record bytes
    tampered_bytes = b'{"seq":999}\n'
    assert not verify_export_inclusion_proof(tampered_bytes, artifact)


def test_tampered_leaf_hash_fails_verification():
    raw_lines = [f'{{"seq":{i}}}\n'.encode("utf-8") for i in range(5)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 2)

    # Alter leaf_hash in artifact
    artifact["leaf_hash"] = "00" * 32
    assert not verify_export_inclusion_proof(raw_lines[2], artifact)
    assert not verify_inclusion_proof_artifact(artifact, raw_lines)


def test_tampered_sibling_hash_fails_verification():
    raw_lines = [f'{{"seq":{i}}}\n'.encode("utf-8") for i in range(6)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 0)

    # Alter one sibling hash in audit path
    assert len(artifact["audit_path"]) > 0
    artifact["audit_path"][0]["sibling_hash"] = "ff" * 32
    assert not verify_export_inclusion_proof(raw_lines[0], artifact)
    assert not verify_inclusion_proof_artifact(artifact, raw_lines)


def test_tampered_leaf_index_fails_verification():
    raw_lines = [f'{{"seq":{i}}}\n'.encode("utf-8") for i in range(6)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 0)

    # Change leaf_index to 1 (audit path structure will mismatch expected directions)
    artifact["leaf_index"] = 1
    assert not verify_export_inclusion_proof(raw_lines[0], artifact)
    assert not verify_inclusion_proof_artifact(artifact, raw_lines)

    # Out of bounds index
    artifact["leaf_index"] = 99
    assert not verify_export_inclusion_proof(raw_lines[0], artifact)
    assert not verify_inclusion_proof_artifact(artifact, raw_lines)

    artifact["leaf_index"] = -1
    assert not verify_export_inclusion_proof(raw_lines[0], artifact)
    assert not verify_inclusion_proof_artifact(artifact, raw_lines)


def test_tampered_tree_size_fails_verification():
    raw_lines = [f'{"seq":{i}}\n'.encode("utf-8") for i in range(6)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 0)

    # Incompatible shape (size 4 has 2 levels, size 6 has 3 levels)
    bad_shape = json.loads(json.dumps(artifact))
    bad_shape["tree_size"] = 4
    assert not verify_export_inclusion_proof(raw_lines[0], bad_shape)
    assert not verify_inclusion_proof_artifact(bad_shape, raw_lines)

    # Incompatible shape (size 8 has 3 levels but index 5 has different directions)
    art5 = build_inclusion_proof_artifact(raw_lines, "kibble", 5)
    bad_shape5 = json.loads(json.dumps(art5))
    bad_shape5["tree_size"] = 8
    assert not verify_export_inclusion_proof(raw_lines[5], bad_shape5)
    assert not verify_inclusion_proof_artifact(bad_shape5, raw_lines)

    # Against full export, tree_size != len(raw_lines) fails
    bad_size = json.loads(json.dumps(artifact))
    bad_size["tree_size"] = 5
    assert not verify_inclusion_proof_artifact(bad_size, raw_lines)

    # Against expected root of a 5-element tree, root mismatch fails
    root_5 = export_merkle_root(raw_lines[:5])
    assert not verify_export_inclusion_proof(raw_lines[0], bad_size, expected_root=root_5)


def test_tampered_export_root_fails_verification():
    raw_lines = [f'{{"seq":{i}}}\n'.encode("utf-8") for i in range(4)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 1)

    artifact["export_root"] = "ee" * 32
    assert not verify_export_inclusion_proof(raw_lines[1], artifact)
    assert not verify_inclusion_proof_artifact(artifact, raw_lines)


def test_export_generation_enforcement_and_mismatch():
    raw_lines = [f'{{"seq":{i}}}\n'.encode("utf-8") for i in range(4)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 1, export_generation=0)

    # Expected generation 0 matches
    assert verify_export_inclusion_proof(raw_lines[1], artifact, expected_generation=0)
    assert verify_inclusion_proof_artifact(artifact, raw_lines, expected_generation=0)

    # Expected generation 1 fails
    assert not verify_export_inclusion_proof(raw_lines[1], artifact, expected_generation=1)
    assert not verify_inclusion_proof_artifact(artifact, raw_lines, expected_generation=1)

    # Tampering generation inside artifact
    artifact["export_generation"] = 1
    assert not verify_export_inclusion_proof(raw_lines[1], artifact, expected_generation=0)


def test_retention_and_generation_rotation_scenario():
    # Generation 0: room has records 0, 1, 2, 3
    gen0_lines = [f'{{"seq":{i},"text":"msg_{i}"}}\n'.encode("utf-8") for i in range(4)]
    proof_gen0 = build_inclusion_proof_artifact(gen0_lines, "kibble", 2, export_generation=0)
    gen0_root = export_merkle_root(gen0_lines)

    assert verify_export_inclusion_proof(gen0_lines[2], proof_gen0, expected_root=gen0_root, expected_generation=0)

    # Retention occurs: records 0 and 1 are pruned; records 2, 3 remain, record 4 added.
    # Room generation advances from 0 to 1.
    gen1_lines = [
        b'{"seq":2,"text":"msg_2"}\n',
        b'{"seq":3,"text":"msg_3"}\n',
        b'{"seq":4,"text":"msg_4"}\n',
    ]
    gen1_root = export_merkle_root(gen1_lines)

    # Verification of gen0 proof against gen1 state MUST fail
    assert not verify_export_inclusion_proof(gen0_lines[2], proof_gen0, expected_root=gen1_root, expected_generation=1)
    assert not verify_inclusion_proof_artifact(proof_gen0, gen1_lines, expected_generation=1)

    # Generating fresh proof in gen1 for record 2 (now leaf_index 0 in tree_size 3) succeeds
    proof_gen1 = build_inclusion_proof_artifact(gen1_lines, "kibble", 0, export_generation=1)
    assert verify_export_inclusion_proof(gen1_lines[0], proof_gen1, expected_root=gen1_root, expected_generation=1)


def test_audit_path_tampering():
    raw_lines = [f'{{"seq":{i}}}\n'.encode("utf-8") for i in range(7)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 3)

    # 1. Truncated proof (remove last step)
    truncated = json.loads(json.dumps(artifact))
    truncated["audit_path"].pop()
    assert not verify_export_inclusion_proof(raw_lines[3], truncated)

    # 2. Extra proof step (append dummy node)
    extra = json.loads(json.dumps(artifact))
    extra["audit_path"].append({"position": "right", "sibling_hash": "aa" * 32})
    assert not verify_export_inclusion_proof(raw_lines[3], extra)

    # 3. Inverted position direction ("left" -> "right" or vice versa)
    inverted = json.loads(json.dumps(artifact))
    pos = inverted["audit_path"][0]["position"]
    inverted["audit_path"][0]["position"] = "left" if pos == "right" else "right"
    assert not verify_export_inclusion_proof(raw_lines[3], inverted)


def test_malformed_artifact_inputs():
    raw_line = b'{"seq":1}\n'
    valid_artifact = build_inclusion_proof_artifact([raw_line], "kibble", 0)

    # Not a dict
    assert not verify_export_inclusion_proof(raw_line, "not-a-dict")  # type: ignore

    # Wrong version or profile
    bad_ver = json.loads(json.dumps(valid_artifact))
    bad_ver["version"] = 2
    assert not verify_export_inclusion_proof(raw_line, bad_ver)

    bad_profile = json.loads(json.dumps(valid_artifact))
    bad_profile["profile"] = "tc-ledger/99"
    assert not verify_export_inclusion_proof(raw_line, bad_profile)

    # Bad hash length or non-hex
    bad_hash = json.loads(json.dumps(valid_artifact))
    bad_hash["leaf_hash"] = "not-hex-chars"
    assert not verify_export_inclusion_proof(raw_line, bad_hash)

    bad_len = json.loads(json.dumps(valid_artifact))
    bad_len["leaf_hash"] = "aa" * 31
    assert not verify_export_inclusion_proof(raw_line, bad_len)

    # Bad audit_path items
    raw_lines = [b'{"seq":1}\n', b'{"seq":2}\n']
    multi_artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 0)

    bad_item = json.loads(json.dumps(multi_artifact))
    bad_item["audit_path"][0] = "not-a-dict"
    assert not verify_export_inclusion_proof(raw_lines[0], bad_item)

    bad_pos = json.loads(json.dumps(multi_artifact))
    bad_pos["audit_path"][0]["position"] = "diagonal"
    assert not verify_export_inclusion_proof(raw_lines[0], bad_pos)


def test_serialization_round_trip(tmp_path):
    raw_lines = [f'{{"seq":{i},"data":"payload_{i}"}}\n'.encode("utf-8") for i in range(5)]
    artifact = build_inclusion_proof_artifact(raw_lines, "kibble", 2, export_generation=3)

    out_file = tmp_path / "proof.json"
    write_inclusion_proof_artifact(str(out_file), artifact)

    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded == artifact

    assert verify_export_inclusion_proof(
        raw_lines[2],
        loaded,
        expected_root=export_merkle_root(raw_lines),
        expected_generation=3,
        expected_room="kibble",
    )


def test_signed_record_end_to_end_lifecycle():
    # 1. Sign record with zero-padded nonce
    signing_key = SigningKey.generate()
    did = make_did(signing_key)
    room = "lobby"
    nonce = "0000000042"
    text = "C5 inclusion proof lifecycle"

    message = f"{room}|{nonce}|{text}".encode("utf-8")
    sig = base64.urlsafe_b64encode(signing_key.sign(message).signature).decode().rstrip("=")

    record = {
        "seq": 101,
        "ts": "2026-09-09T12:00:00Z",
        "from": did,
        "text": text,
        "nonce": nonce,
        "sig": sig,
    }

    # 2. Exact export line
    raw_line = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    raw_lines = [
        b'{"seq":100,"text":"preceding"}\n',
        raw_line,
        b'{"seq":102,"text":"following"}\n',
    ]

    # 3. Signature verification
    verification = verify_signed_record(record, room)
    assert verification.status == "VALID"

    # 4. Evidence commitment
    ev_id = evidence_commitment(record, room)
    assert ev_id.startswith("tc-ledger:v1:")

    # 5. Merkle leaf and inclusion proof
    leaf_idx = 1
    artifact = build_inclusion_proof_artifact(raw_lines, room, leaf_idx, export_generation=0)

    # 6. Independent proof verification (only raw_line + artifact + expected root)
    root = export_merkle_root(raw_lines)
    assert verify_export_inclusion_proof(raw_line, artifact, expected_root=root, expected_generation=0)

    # 7. Full export verification
    assert verify_inclusion_proof_artifact(artifact, raw_lines, expected_generation=0)


def test_cli_prove_and_verify_proof(tmp_path, capsys):
    raw_lines = [
        b'{"seq":1,"text":"first"}\n',
        b'{"seq":2,"text":"second"}\n',
        b'{"seq":3,"text":"third"}\n',
    ]
    export_path = tmp_path / "test_export.jsonl"
    export_path.write_bytes(b"".join(raw_lines))

    proof_path = tmp_path / "proof_out.json"

    # 1. Run prove via CLI
    old_argv = sys.argv
    sys.argv = [
        "tc-ledger", "prove",
        str(export_path),
        "--room", "lobby",
        "--leaf-index", "1",
        "--generation", "5",
        "--output", str(proof_path),
    ]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    assert code == 0
    assert proof_path.is_file()

    # 2. Run verify-proof via CLI with --export
    sys.argv = [
        "tc-ledger", "verify-proof",
        str(proof_path),
        "--export", str(export_path),
        "--expected-generation", "5",
    ]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    assert code == 0
    assert "VERIFY-PROOF: VALID" in captured.out

    # 3. Run verify-proof via CLI with --record (independent mode)
    record_path = tmp_path / "record.jsonl"
    record_path.write_bytes(raw_lines[1])

    expected_root_hex = export_merkle_root(raw_lines).hex()
    sys.argv = [
        "tc-ledger", "verify-proof",
        str(proof_path),
        "--record", str(record_path),
        "--expected-root", expected_root_hex,
        "--expected-generation", "5",
    ]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    assert code == 0
    assert "VERIFY-PROOF: VALID" in captured.out

    # 4. Run verify-proof with tampered record -> exit code 1
    tampered_record_path = tmp_path / "tampered_record.jsonl"
    tampered_record_path.write_bytes(b'{"seq":2,"text":"tampered"}\n')

    sys.argv = [
        "tc-ledger", "verify-proof",
        str(proof_path),
        "--record", str(tampered_record_path),
    ]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    assert code == 1
    assert "VERIFY-PROOF: INVALID" in captured.err


def test_randomized_merkle_inclusion_proofs():
    import random
    rng = random.Random(42)

    for tree_size in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 17, 23, 32]:
        raw_lines = [
            f'{{"idx":{i},"rand":"{rng.getrandbits(64):x}"}}\n'.encode("utf-8")
            for i in range(tree_size)
        ]
        root = export_merkle_root(raw_lines)

        for leaf_idx in range(tree_size):
            artifact = build_inclusion_proof_artifact(raw_lines, "rnd", leaf_idx, export_generation=0)

            # Valid proof succeeds
            assert verify_export_inclusion_proof(raw_lines[leaf_idx], artifact, expected_root=root)

            # Record tamper fails
            tampered = raw_lines[leaf_idx] + b"x"
            assert not verify_export_inclusion_proof(tampered, artifact, expected_root=root)

            # Sibling tamper fails if audit_path is not empty
            if artifact["audit_path"]:
                tampered_artifact = json.loads(json.dumps(artifact))
                tampered_artifact["audit_path"][0]["sibling_hash"] = "00" * 32
                assert not verify_export_inclusion_proof(raw_lines[leaf_idx], tampered_artifact, expected_root=root)


# =====================================================================
# C5 Adversarial Regression Test Suite
# =====================================================================

def test_adversarial_merkle_proof_integrity():
    """Permanent regression test for Merkle inclusion proof integrity and malleability."""
    raw_lines = [f'{{"idx":{i},"msg":"line_{i}"}}\n'.encode("utf-8") for i in range(7)]
    root = export_merkle_root(raw_lines)
    artifact = build_inclusion_proof_artifact(raw_lines, "lobby", 3, export_generation=1)

    assert verify_export_inclusion_proof(raw_lines[3], artifact, expected_root=root)

    # 1. Sibling mutation across all audit path levels
    for i in range(len(artifact["audit_path"])):
        tampered = json.loads(json.dumps(artifact))
        orig_hash = tampered["audit_path"][i]["sibling_hash"]
        mutated_hash = ("00" if orig_hash[:2] != "00" else "ff") + orig_hash[2:]
        tampered["audit_path"][i]["sibling_hash"] = mutated_hash
        assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # 2. Direction mutation (left <-> right)
    for i in range(len(artifact["audit_path"])):
        tampered = json.loads(json.dumps(artifact))
        cur_pos = tampered["audit_path"][i]["position"]
        tampered["audit_path"][i]["position"] = "right" if cur_pos == "left" else "left"
        assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # 3. Path truncation (dropping sibling)
    tampered = json.loads(json.dumps(artifact))
    tampered["audit_path"].pop()
    assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # 4. Path extension (appending dummy sibling)
    tampered = json.loads(json.dumps(artifact))
    tampered["audit_path"].append({"position": "right", "sibling_hash": "00" * 32})
    assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # 5. Leaf-index mutation
    tampered = json.loads(json.dumps(artifact))
    tampered["leaf_index"] = 2
    assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # Out-of-bounds leaf index
    tampered["leaf_index"] = 7
    assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)
    tampered["leaf_index"] = -1
    assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # 6. Tree-size mutation
    # Standalone verification:
    # Sizes <= 3 violate leaf_index < tree_size bounds
    for bad_size in [0, 1, 2, 3]:
        tampered = json.loads(json.dumps(artifact))
        tampered["tree_size"] = bad_size
        assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # Size 4 has expected direction length 2 (mismatches audit_path length 3)
    tampered = json.loads(json.dumps(artifact))
    tampered["tree_size"] = 4
    assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # Sizes >= 9 have expected direction length 4 (mismatches audit_path length 3)
    for bad_size in [9, 10, 16]:
        tampered = json.loads(json.dumps(artifact))
        tampered["tree_size"] = bad_size
        assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # Against complete export lines, any tree_size != len(lines) is strictly rejected
    for bad_size in [4, 5, 6, 8, 9]:
        tampered = json.loads(json.dumps(artifact))
        tampered["tree_size"] = bad_size
        assert not verify_inclusion_proof_artifact(tampered, raw_lines)

    # 7. Export-root mutation
    tampered = json.loads(json.dumps(artifact))
    tampered["export_root"] = "ff" * 32
    assert not verify_export_inclusion_proof(raw_lines[3], tampered)
    assert not verify_export_inclusion_proof(raw_lines[3], tampered, expected_root=root)

    # 8. Malformed hashes
    tampered = json.loads(json.dumps(artifact))
    tampered["leaf_hash"] = "not-a-valid-hex-digest"
    assert not verify_export_inclusion_proof(raw_lines[3], tampered)

    tampered = json.loads(json.dumps(artifact))
    tampered["export_root"] = "00" * 31  # 31 bytes
    assert not verify_export_inclusion_proof(raw_lines[3], tampered)

    # 9. Malformed artifact structure
    for bad_art in [
        None,
        "not-a-dict",
        [],
        {**artifact, "version": 2},
        {**artifact, "profile": "unsupported/1"},
        {**artifact, "tree_size": "7"},
        {**artifact, "leaf_index": "3"},
        {**artifact, "audit_path": "not-a-list"},
    ]:
        assert not verify_export_inclusion_proof(raw_lines[3], bad_art)


def test_adversarial_raw_byte_commitment():
    """Permanent regression test for raw physical byte commitment without canonicalization."""
    base_lf = b'{"seq":1,"text":"data"}\n'
    base_crlf = b'{"seq":1,"text":"data"}\r\n'
    base_unterminated = b'{"seq":1,"text":"data"}'
    base_whitespace = b'{ "seq": 1, "text": "data" }\n'
    base_keyorder = b'{"text":"data","seq":1}\n'
    base_escaped = b'{"seq":1,"text":"d\\u0061ta"}\n'
    base_nfc = '{"seq":1,"text":"café"}\n'.encode("utf-8")
    import unicodedata
    base_nfd = unicodedata.normalize("NFD", '{"seq":1,"text":"café"}\n').encode("utf-8")
    arbitrary_bytes = b"\x00\xff\xfe\x01binary_payload\n"
    blank_line = b"\n"

    all_cases = [
        base_lf,
        base_crlf,
        base_unterminated,
        base_whitespace,
        base_keyorder,
        base_escaped,
        base_nfc,
        base_nfd,
        arbitrary_bytes,
        blank_line,
    ]

    # All leaf hashes must be unique
    leaf_hashes = [export_leaf_hash(b) for b in all_cases]
    assert len(set(leaf_hashes)) == len(all_cases), "Collision in raw-byte leaf hashes!"

    # Proof built for LF line must not verify for any physical variation
    lines = [b'{"seq":0}\n', base_lf, b'{"seq":2}\n']
    proof = build_inclusion_proof_artifact(lines, "kibble", 1, export_generation=0)

    assert verify_export_inclusion_proof(base_lf, proof)
    for variant in [base_crlf, base_unterminated, base_whitespace, base_keyorder, base_escaped, blank_line]:
        assert not verify_export_inclusion_proof(variant, proof)


def test_adversarial_signed_writes_and_nonce_boundaries():
    """Permanent regression test for signed writes and nonce representation boundaries."""
    signing_key = SigningKey.generate()
    did = make_did(signing_key)
    room = "kibble"
    text = "nonce_boundary_test"

    valid_nonces = [
        42,
        "42",
        "0000000042",
        "042",
        "00042",
        0,
        "0",
        "0000000000000000000",
    ]

    for nonce in valid_nonces:
        msg = f"{room}|{nonce}|{text}".encode("utf-8")
        sig = base64.urlsafe_b64encode(signing_key.sign(msg).signature).decode().rstrip("=")
        rec = {
            "seq": 1,
            "ts": "2026-09-09T12:00:00Z",
            "from": did,
            "text": text,
            "nonce": nonce,
            "sig": sig,
        }
        res = verify_signed_record(rec, room)
        assert res.status == "VALID"

        raw = json.dumps(rec, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        proof = build_inclusion_proof_artifact([raw], room, 0, export_generation=1)
        assert verify_export_inclusion_proof(raw, proof, expected_room=room, expected_generation=1)

    # Invalid nonces rejected with MalformedRecord
    invalid_nonces = [
        True,
        False,
        -1,
        10**20,
        "1" * 20,
        "+42",
        " 42",
        "42 ",
        "4 2",
        "42\n",
        "",
        "00x42",
        "-42",
        "+042",
    ]
    for bad_nonce in invalid_nonces:
        bad_rec = {
            "seq": 1,
            "ts": "2026-09-09T12:00:00Z",
            "from": did,
            "text": text,
            "nonce": bad_nonce,
            "sig": "AAAA",
        }
        with pytest.raises(MalformedRecord):
            verify_signed_record(bad_rec, room)

    # Specific test for "0000000042": mutation must fail signature
    target_nonce = "0000000042"
    target_msg = f"{room}|{target_nonce}|{text}".encode("utf-8")
    target_sig = base64.urlsafe_b64encode(signing_key.sign(target_msg).signature).decode().rstrip("=")
    target_rec = {
        "seq": 1,
        "ts": "2026-09-09T12:00:00Z",
        "from": did,
        "text": text,
        "nonce": target_nonce,
        "sig": target_sig,
    }
    assert verify_signed_record(target_rec, room).status == "VALID"

    for tampered_nonce in [42, "0000000043", "000000042", "00000000042"]:
        t_rec = {**target_rec, "nonce": tampered_nonce}
        with pytest.raises(InvalidSignature):
            verify_signed_record(t_rec, room)


def test_adversarial_retention_generation_and_room_reuse():
    """Permanent regression test for retention, generation rotation, and room reuse."""
    raw_a = b'{"seq":1,"text":"msgA"}\n'
    raw_b = b'{"seq":2,"text":"msgB"}\n'
    raw_c = b'{"seq":3,"text":"msgC"}\n'
    raw_d = b'{"seq":4,"text":"msgD"}\n'

    gen0_export = [raw_a, raw_b, raw_c, raw_d]
    gen0_root = export_merkle_root(gen0_export)
    proof_b = build_inclusion_proof_artifact(gen0_export, "kibble", 1, export_generation=0)

    # 1. Standalone vs expected root
    assert verify_export_inclusion_proof(raw_b, proof_b)
    assert verify_export_inclusion_proof(raw_b, proof_b, expected_root=gen0_root, expected_generation=0)

    # 2. Retention simulation: [raw_c, raw_d, raw_e]
    raw_e = b'{"seq":5,"text":"msgE"}\n'
    gen1_export = [raw_c, raw_d, raw_e]
    gen1_root = export_merkle_root(gen1_export)

    assert not verify_export_inclusion_proof(raw_b, proof_b, expected_root=gen1_root)
    assert not verify_inclusion_proof_artifact(proof_b, gen1_export)

    # 3. Metadata tampering (generation & room)
    tampered_gen = json.loads(json.dumps(proof_b))
    tampered_gen["export_generation"] = 1
    assert verify_export_inclusion_proof(raw_b, tampered_gen)  # Standalone unanchored
    assert not verify_export_inclusion_proof(raw_b, tampered_gen, expected_generation=0)
    assert not verify_export_inclusion_proof(raw_b, tampered_gen, expected_root=gen1_root, expected_generation=1)

    tampered_room = json.loads(json.dumps(proof_b))
    tampered_room["room"] = "attacker-room"
    assert verify_export_inclusion_proof(raw_b, tampered_room)  # Standalone unanchored
    assert not verify_export_inclusion_proof(raw_b, tampered_room, expected_room="kibble")

    # 4. Room reuse / reset
    reset_export = [raw_e]
    reset_root = export_merkle_root(reset_export)
    assert not verify_export_inclusion_proof(raw_b, proof_b, expected_root=reset_root, expected_generation=0)

    # 5. Same raw record reappearing in later generation
    gen2_export = [raw_e, raw_b]
    gen2_root = export_merkle_root(gen2_export)
    proof_b_gen2 = build_inclusion_proof_artifact(gen2_export, "kibble", 1, export_generation=2)

    assert proof_b["leaf_hash"] == proof_b_gen2["leaf_hash"]
    assert gen0_root != gen2_root
    assert not verify_export_inclusion_proof(raw_b, proof_b, expected_root=gen2_root)
    assert verify_export_inclusion_proof(raw_b, proof_b_gen2, expected_root=gen2_root, expected_generation=2)


def test_adversarial_cli_suite(tmp_path, capsys):
    """Permanent regression test for CLI argument validation, trust anchors, and error handling."""
    raw_lines = [
        b'{"seq":0,"text":"zero"}\n',
        b'{"seq":1,"text":"one"}\r\n',
        b'{"seq":2,"text":"two"}',
    ]
    export_file = tmp_path / "export.jsonl"
    export_file.write_bytes(b"".join(raw_lines))

    record_file = tmp_path / "rec1.bin"
    record_file.write_bytes(raw_lines[1])

    proof_file = tmp_path / "proof1.json"

    # 1. Prove round-trip
    old_argv = sys.argv
    try:
        sys.argv = [
            "tc-ledger", "prove",
            str(export_file),
            "--room", "lobby",
            "--leaf-index", "1",
            "--generation", "3",
            "--output", str(proof_file),
        ]
        assert main() == 0
        assert proof_file.is_file()

        # 2. Verify-proof standalone
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(proof_file),
            "--record", str(record_file),
        ]
        assert main() == 0
        captured = capsys.readouterr()
        assert "VERIFY-PROOF: VALID" in captured.out

        # 3. Expected anchors matching
        correct_root = export_merkle_root(raw_lines).hex()
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(proof_file),
            "--record", str(record_file),
            "--expected-root", correct_root,
            "--expected-generation", "3",
            "--expected-room", "lobby",
        ]
        assert main() == 0
        captured = capsys.readouterr()
        assert "VERIFY-PROOF: VALID" in captured.out

        # 4. Expected-room mismatch -> INVALID (exit 1)
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(proof_file),
            "--record", str(record_file),
            "--expected-room", "wrong-room",
        ]
        assert main() == 1
        captured = capsys.readouterr()
        assert "VERIFY-PROOF: INVALID" in captured.err

        # 5. Tampered artifact room with expected-room -> INVALID (exit 1)
        tampered_proof_file = tmp_path / "tampered_room.json"
        art = json.loads(proof_file.read_text(encoding="utf-8"))
        art["room"] = "attacker-room"
        tampered_proof_file.write_text(json.dumps(art), encoding="utf-8")

        sys.argv = [
            "tc-ledger", "verify-proof",
            str(tampered_proof_file),
            "--record", str(record_file),
            "--expected-room", "lobby",
        ]
        assert main() == 1
        captured = capsys.readouterr()
        assert "VERIFY-PROOF: INVALID" in captured.err

        # Tampered artifact room without expected-room -> VALID (exit 0, standalone)
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(tampered_proof_file),
            "--record", str(record_file),
        ]
        assert main() == 0
        captured = capsys.readouterr()
        assert "VERIFY-PROOF: VALID" in captured.out

        # 6. Expected-generation mismatch -> INVALID (exit 1)
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(proof_file),
            "--record", str(record_file),
            "--expected-generation", "99",
        ]
        assert main() == 1

        # 7. Expected-root mismatch -> INVALID (exit 1)
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(proof_file),
            "--record", str(record_file),
            "--expected-root", "00" * 32,
        ]
        assert main() == 1

        # 8. Missing both --record and --export -> exit 2
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(proof_file),
        ]
        assert main() == 2

        # 9. Nonexistent files -> exit 3
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(tmp_path / "nonexistent.json"),
            "--record", str(record_file),
        ]
        assert main() == 3

        # 10. Malformed JSON -> exit 3
        bad_json_file = tmp_path / "bad.json"
        bad_json_file.write_text("{bad json", encoding="utf-8")
        sys.argv = [
            "tc-ledger", "verify-proof",
            str(bad_json_file),
            "--record", str(record_file),
        ]
        assert main() == 3

    finally:
        sys.argv = old_argv

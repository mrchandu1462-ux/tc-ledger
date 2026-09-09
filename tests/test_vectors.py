import base64
import hashlib
import json
from pathlib import Path

from tc_ledger.ledger import export_merkle_proof, verify_export_merkle_proof


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors" / "vectors.json"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def reference_root(lines: list[bytes]) -> bytes:
    if not lines:
        return hashlib.sha256(b"").digest()

    level = [leaf_hash(line) for line in lines]

    while len(level) > 1:
        next_level = []

        for i in range(0, len(level), 2):
            if i + 1 >= len(level):
                next_level.append(level[i])
            else:
                next_level.append(node_hash(level[i], level[i + 1]))

        level = next_level

    return level[0]


def reference_levels(lines: list[bytes]) -> list[list[bytes]]:
    if not lines:
        return []

    level = [leaf_hash(line) for line in lines]
    levels = []

    while len(level) > 1:
        next_level = []

        for i in range(0, len(level), 2):
            if i + 1 >= len(level):
                next_level.append(level[i])
            else:
                next_level.append(node_hash(level[i], level[i + 1]))

        levels.append(next_level)
        level = next_level

    return levels


def test_every_frozen_merkle_vector():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))

    for vector in data["merkle"]["trivial"]:
        lines = [base64.b64decode(value) for value in vector["leaves_b64"]]

        assert [leaf_hash(line).hex() for line in lines] == vector["leaf_hashes"]
        assert reference_root(lines).hex() == vector["root"]


def test_byte_model_fixtures():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))

    for vector in data["byte_model"]:
        data_bytes = base64.b64decode(vector["data_b64"])
        lines = [] if not data_bytes else [data_bytes]

        assert [
            base64.b64encode(x).decode("ascii") for x in lines
        ] == vector["leaves_b64"]

        assert [leaf_hash(x).hex() for x in lines] == vector["leaf_hashes"]
        assert reference_root(lines).hex() == vector["root"]


def test_synthetic_export_leaf_hashes_and_root():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    vector = data["synthetic_export"]

    lines = [
        base64.b64decode(item["bytes_b64"])
        for item in vector["lines"]
    ]

    assert [len(line) for line in lines] == [
        item["byte_length"] for item in vector["lines"]
    ]

    assert [leaf_hash(line).hex() for line in lines] == [
        item["leaf_hash"] for item in vector["lines"]
    ]

    assert reference_root(lines).hex() == vector["root"]


def test_synthetic_export_intermediate_levels():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    vector = data["synthetic_export"]

    lines = [
        base64.b64decode(item["bytes_b64"])
        for item in vector["lines"]
    ]

    actual = [
        [value.hex() for value in level]
        for level in reference_levels(lines)
    ]

    assert actual == vector["intermediate_levels"]


def test_synthetic_export_proof():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    vector = data["synthetic_export"]

    lines = [
        base64.b64decode(item["bytes_b64"])
        for item in vector["lines"]
    ]

    proof_vector = vector["proof"]
    index = proof_vector["leaf_index"]

    proof = export_merkle_proof(lines, index)

    assert [
        sibling.hex()
        for sibling, _position in proof
    ] == proof_vector["audit_path"]

    expected_root = bytes.fromhex(vector["root"])

    assert verify_export_merkle_proof(
        lines[index],
        proof,
        expected_root,
    )


def test_synthetic_evidence_ids_are_frozen():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    vector = data["synthetic_export"]

    assert vector["evidence_ids"] == {
        "0": "tc-ledger:v1:91e246308a156e69afcd0837bb8d403e96f5ca0a3f0c6576e2243acc77ec3617",
        "1": "tc-ledger:v1:9b70bb047371584384fc49b61c6206f9316520cebae3a741e279f330f55e73f9",
    }
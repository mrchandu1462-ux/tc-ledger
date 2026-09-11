"""Tests for C7 Merkle Cross-Generation Consistency Proofs (RFC 6962 §2.1.2)."""

import hashlib
import json
import random
import tempfile
from pathlib import Path

import pytest

from tc_ledger.ledger import (
    consistency_proof,
    verify_consistency_proof,
    build_consistency_proof_artifact,
    verify_consistency_proof_artifact,
    write_consistency_proof_artifact,
    export_merkle_root,
    export_leaf_hash,
    node_hash,
)


# ---------------------------------------------------------------------------
# Independent Reference Implementation for Cross-Implementation Sanity
# ---------------------------------------------------------------------------

def _ref_mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    left = _ref_mth(leaves[:k])
    right = _ref_mth(leaves[k:])
    return hashlib.sha256(b"\x01" + left + right).digest()


def _ref_subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [_ref_mth(leaves)]
    k = 1 << ((n - 1).bit_length() - 1)
    if m <= k:
        return _ref_subproof(m, leaves[:k], b) + [_ref_mth(leaves[k:])]
    else:
        return _ref_subproof(m - k, leaves[k:], False) + [_ref_mth(leaves[:k])]


def _ref_consistency_proof(m: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if m == 0 or m == n:
        return []
    k = 1 << ((n - 1).bit_length() - 1)
    if m <= k:
        return _ref_subproof(m, leaves[:k], True) + [_ref_mth(leaves[k:])]
    else:
        return _ref_subproof(m - k, leaves[k:], False) + [_ref_mth(leaves[:k])]


def _ref_verify_consistency(
    m: int, n: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    if m == n:
        return len(proof) == 0 and old_root == new_root
    if m == 0:
        return len(proof) == 0 and old_root == hashlib.sha256(b"").digest()
    if m > n or m < 0 or n < 0 or not proof:
        return False

    is_power_of_two = (m & (m - 1)) == 0
    idx = 0
    if is_power_of_two:
        fn = old_root
        sn = old_root
    else:
        fn = proof[0]
        sn = proof[0]
        idx = 1

    fn_idx = m - 1
    sn_idx = n - 1

    while fn_idx % 2 == 1:
        fn_idx //= 2
        sn_idx //= 2

    for p in proof[idx:]:
        if sn_idx == 0:
            return False
        if fn_idx % 2 == 1 or fn_idx == sn_idx:
            fn = hashlib.sha256(b"\x01" + p + fn).digest()
            sn = hashlib.sha256(b"\x01" + p + sn).digest()
            while fn_idx % 2 == 0 and fn_idx != 0:
                fn_idx //= 2
                sn_idx //= 2
        else:
            sn = hashlib.sha256(b"\x01" + sn + p).digest()
        fn_idx //= 2
        sn_idx //= 2

    return fn == old_root and sn == new_root and sn_idx == 0


# ---------------------------------------------------------------------------
# Unit & Conformance Tests
# ---------------------------------------------------------------------------

def test_consistency_zero_and_equal():
    """Test 0 -> 0, 0 -> n, and m == n transitions."""
    leaves = [f"record_{i}\n".encode("utf-8") for i in range(4)]
    root = export_merkle_root(leaves)

    # 0 -> 0
    assert consistency_proof(0, []) == []
    empty_root = hashlib.sha256(b"").digest()
    assert verify_consistency_proof(0, 0, empty_root, empty_root, []) is True

    # m == n
    assert consistency_proof(4, leaves) == []
    assert verify_consistency_proof(4, 4, root, root, []) is True

    # m == n with wrong root or non-empty proof
    assert verify_consistency_proof(4, 4, root, b"\xaa" * 32, []) is False
    assert verify_consistency_proof(4, 4, root, root, [b"\xaa" * 32]) is False


@pytest.mark.parametrize(
    "old_size,new_size",
    [
        (1, 1),
        (1, 2),
        (1, 3),
        (1, 4),
        (1, 7),
        (2, 3),
        (2, 4),
        (2, 5),
        (3, 4),
        (3, 5),
        (3, 7),
        (4, 5),
        (4, 8),
        (5, 8),
        (7, 8),
        (5, 11),
        (7, 15),
        (8, 16),
        (13, 29),
        (50, 100),
        (100, 250),
    ],
)
def test_consistency_power_and_non_power_of_two_transitions(old_size: int, new_size: int):
    """Test standard and arbitrary non-power-of-two transitions."""
    all_leaves = [f'{{"seq":{i},"text":"msg_{i}"}}\n'.encode("utf-8") for i in range(new_size)]
    old_leaves = all_leaves[:old_size]

    old_root = export_merkle_root(old_leaves)
    new_root = export_merkle_root(all_leaves)

    proof = consistency_proof(old_size, all_leaves)

    # 1. Production verification
    assert verify_consistency_proof(old_size, new_size, old_root, new_root, proof) is True

    # 2. Cross-implementation sanity check against independent reference
    ref_proof = _ref_consistency_proof(old_size, all_leaves)
    assert proof == ref_proof
    assert _ref_verify_consistency(old_size, new_size, old_root, new_root, proof) is True


def test_consistency_adversarial_mutations():
    """Negative tests: verify all mutations and tampering are rejected."""
    leaves = [f"line_{i}\n".encode("utf-8") for i in range(11)]
    old_leaves = leaves[:5]
    old_root = export_merkle_root(old_leaves)
    new_root = export_merkle_root(leaves)
    proof = consistency_proof(5, leaves)

    assert verify_consistency_proof(5, 11, old_root, new_root, proof) is True

    # 1. Wrong old root
    assert verify_consistency_proof(5, 11, b"\x01" * 32, new_root, proof) is False

    # 2. Wrong new root
    assert verify_consistency_proof(5, 11, old_root, b"\x02" * 32, proof) is False

    # 3. Modified proof node
    tampered_proof = [b"\xff" * 32] + proof[1:]
    assert verify_consistency_proof(5, 11, old_root, new_root, tampered_proof) is False

    # 4. Truncated proof
    assert verify_consistency_proof(5, 11, old_root, new_root, proof[:-1]) is False

    # 5. Extraneous proof node
    assert verify_consistency_proof(5, 11, old_root, new_root, proof + [b"\x00" * 32]) is False

    # 6. Swapped tree sizes (m > n)
    assert verify_consistency_proof(11, 5, old_root, new_root, proof) is False

    # 7. Changed historical leaf (non-prefix)
    corrupted_new = [f"line_{i}\n".encode("utf-8") for i in range(11)]
    corrupted_new[2] = b"tampered_line\n"
    corrupted_root = export_merkle_root(corrupted_new)
    corrupted_proof = consistency_proof(5, corrupted_new)
    # The proof built from corrupted tree cannot verify against uncorrupted old_root
    assert verify_consistency_proof(5, 11, old_root, corrupted_root, corrupted_proof) is False

    # 8. Reordered leaves
    reordered_new = list(leaves)
    reordered_new[0], reordered_new[1] = reordered_new[1], reordered_new[0]
    reordered_root = export_merkle_root(reordered_new)
    reordered_proof = consistency_proof(5, reordered_new)
    assert verify_consistency_proof(5, 11, old_root, reordered_root, reordered_proof) is False


def test_consistency_artifact_full_lifecycle():
    """Test artifact generation, file serialization, and schema validation."""
    old_lines = [b'{"room":"test-room","seq":1,"text":"first"}\n', b'{"room":"test-room","seq":2,"text":"second"}\n']
    new_lines = old_lines + [
        b'{"room":"test-room","seq":3,"text":"third"}\n',
        b'{"room":"test-room","seq":4,"text":"fourth"}\n',
        b'{"room":"test-room","seq":5,"text":"fifth"}\n',
    ]

    with tempfile.TemporaryDirectory() as tmp_dir:
        old_path = Path(tmp_dir) / "gen1.jsonl"
        new_path = Path(tmp_dir) / "gen2.jsonl"
        proof_path = Path(tmp_dir) / "proof.json"

        old_path.write_bytes(b"".join(old_lines))
        new_path.write_bytes(b"".join(new_lines))

        # Build artifact
        artifact = build_consistency_proof_artifact(
            old_export_path=str(old_path),
            new_export_path=str(new_path),
            room="test-room",
            old_generation=1,
            new_generation=2,
        )

        assert artifact["schema"] == "tc-ledger/consistency-proof/v1"
        assert artifact["old_generation"] == 1
        assert artifact["new_generation"] == 2
        assert artifact["old_tree_size"] == 2
        assert artifact["new_tree_size"] == 5

        # Write and verify
        write_consistency_proof_artifact(str(proof_path), artifact)
        loaded = json.loads(proof_path.read_text(encoding="utf-8"))

        res = verify_consistency_proof_artifact(
            loaded,
            expected_room="test-room",
            expected_old_generation=1,
            expected_new_generation=2,
            expected_old_root=artifact["old_root"],
            expected_new_root=artifact["new_root"],
        )
        assert res["valid"] is True
        assert res["error"] is None

        # Rejection on wrong expectations
        assert verify_consistency_proof_artifact(loaded, expected_room="wrong-room")["valid"] is False
        assert verify_consistency_proof_artifact(loaded, expected_old_generation=99)["valid"] is False
        assert verify_consistency_proof_artifact(loaded, expected_new_generation=99)["valid"] is False
        assert verify_consistency_proof_artifact(loaded, expected_old_root="00" * 32)["valid"] is False
        assert verify_consistency_proof_artifact(loaded, expected_new_root="00" * 32)["valid"] is False


def test_consistency_property_fuzz():
    """Property test over 50 randomized append-only tree pairs with fixed seed."""
    rng = random.Random(42)
    for _ in range(50):
        n = rng.randint(2, 60)
        m = rng.randint(1, n)
        leaves = [f"leaf_{i}_{rng.getrandbits(32)}\n".encode("utf-8") for i in range(n)]
        old_root = export_merkle_root(leaves[:m])
        new_root = export_merkle_root(leaves)

        proof = consistency_proof(m, leaves)
        assert verify_consistency_proof(m, n, old_root, new_root, proof) is True

def test_consistency_invalid_types_and_malformed_inputs():
    """Test that type errors and malformed inputs are strictly rejected."""
    good_root = b"\x00" * 32
    bad_short_root = b"\x00" * 31
    bad_long_root = b"\x00" * 33

    # Type errors on tree sizes
    with pytest.raises(TypeError):
        verify_consistency_proof(True, 2, good_root, good_root, [])  # bool
    with pytest.raises(TypeError):
        verify_consistency_proof(1, "2", good_root, good_root, [])   # str size

    # Bad root lengths
    with pytest.raises(ValueError, match="old_root must be a 32-byte hash"):
        verify_consistency_proof(1, 2, bad_short_root, good_root, [good_root])
    with pytest.raises(ValueError, match="new_root must be a 32-byte hash"):
        verify_consistency_proof(1, 2, good_root, bad_long_root, [good_root])

    # Malformed hex strings
    with pytest.raises(ValueError, match="old_root is not valid hex"):
        verify_consistency_proof(1, 2, "not-valid-hex-zzz", good_root.hex(), [good_root.hex()])
    with pytest.raises(ValueError, match="new_root is not valid hex"):
        verify_consistency_proof(1, 2, good_root.hex(), "xyz!", [good_root.hex()])
    with pytest.raises(ValueError, match="proof node is not valid hex"):
        verify_consistency_proof(1, 2, good_root.hex(), good_root.hex(), ["invalid-node-hex"])

    # Proof node not 32 bytes
    with pytest.raises(ValueError, match="each proof node must be a 32-byte hash"):
        verify_consistency_proof(1, 2, good_root, good_root, [b"short"])

    # Invalid proof container type
    with pytest.raises(TypeError):
        verify_consistency_proof(1, 2, good_root, good_root, "not-a-list")


def test_consistency_artifact_generation_order_validation():
    """Test artifact generation rejects inverted or invalid generations."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        p1 = Path(tmp_dir) / "f1.jsonl"
        p2 = Path(tmp_dir) / "f2.jsonl"
        p1.write_bytes(b'{"room":"r1","seq":1,"text":"a"}\n')
        p2.write_bytes(b'{"room":"r1","seq":1,"text":"a"}\n{"room":"r1","seq":2,"text":"b"}\n')

        # Inverted generation: old_generation > new_generation
        with pytest.raises(ValueError, match="cannot exceed new_generation"):
            build_consistency_proof_artifact(str(p1), str(p2), "r1", old_generation=2, new_generation=1)

        # Inverted tree size (p2 -> p1)
        with pytest.raises(ValueError, match="cannot exceed new export line count"):
            build_consistency_proof_artifact(str(p2), str(p1), "r1", old_generation=1, new_generation=2)

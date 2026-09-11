import hashlib
import json
from pathlib import Path
import subprocess
import sys
import jsonschema
import pytest

from tc_ledger.ledger import (
    verify_commitment_artifact,
    verify_inclusion_proof_artifact,
    verify_export_inclusion_proof,
    verify_consistency_proof_artifact,
    verify_export,
    export_merkle_root,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = ROOT / "examples"
SCHEMAS_DIR = ROOT / "schemas"
EXPORT_FILE = EXAMPLES_DIR / "synthetic_export.jsonl"
COMMIT_FILE = EXAMPLES_DIR / "commitment.json"
PROOF_FILE = EXAMPLES_DIR / "proof_leaf1.json"
RECORD_FILE = EXAMPLES_DIR / "record_1.bin"

EXPECTED_ROOT = "0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9"
EXPECTED_SHA256 = "94c652282e09877eeac0909f066cee1c1d729f374751d8cb9afc8a55e9f63c0a"
EXPECTED_BYTE_COUNT = 1041
ROOM = "demo-room"
GENERATION = 1


def test_shipped_examples_exist_and_exact_bytes():
    assert EXPORT_FILE.is_file(), "synthetic_export.jsonl must exist"
    assert COMMIT_FILE.is_file(), "commitment.json must exist"
    assert PROOF_FILE.is_file(), "proof_leaf1.json must exist"
    assert RECORD_FILE.is_file(), "record_1.bin must exist"

    raw_bytes = EXPORT_FILE.read_bytes()
    assert len(raw_bytes) == EXPECTED_BYTE_COUNT
    assert hashlib.sha256(raw_bytes).hexdigest() == EXPECTED_SHA256

    raw_lines = raw_bytes.splitlines(keepends=True)
    assert len(raw_lines) == 4
    assert RECORD_FILE.read_bytes() == raw_lines[1]


def test_shipped_commitment_artifact_verifies():
    artifact = json.loads(COMMIT_FILE.read_text(encoding="utf-8"))
    assert artifact["version"] == 1
    assert artifact["profile"] == "tc-ledger/1"
    assert artifact["room"] == ROOM
    assert artifact["export_generation"] == GENERATION
    assert artifact["export_root"] == EXPECTED_ROOT
    assert artifact["byte_count"] == EXPECTED_BYTE_COUNT
    assert artifact["file_sha256"] == EXPECTED_SHA256

    # Verify commitment artifact directly
    assert verify_commitment_artifact(
        EXPORT_FILE,
        COMMIT_FILE,
        expected_root=EXPECTED_ROOT,
        expected_room=ROOM,
        expected_generation=GENERATION,
    )

    # Generation mismatch must fail
    assert not verify_commitment_artifact(
        EXPORT_FILE,
        COMMIT_FILE,
        expected_root=EXPECTED_ROOT,
        expected_room=ROOM,
        expected_generation=GENERATION + 1,
    )

    # Room mismatch must fail
    assert not verify_commitment_artifact(
        EXPORT_FILE,
        COMMIT_FILE,
        expected_root=EXPECTED_ROOT,
        expected_room="wrong-room",
        expected_generation=GENERATION,
    )


def test_shipped_inclusion_proof_verifies():
    proof = json.loads(PROOF_FILE.read_text(encoding="utf-8"))
    assert proof["export_root"] == EXPECTED_ROOT
    assert proof["leaf_index"] == 1
    assert proof["tree_size"] == 4
    assert proof["export_generation"] == GENERATION
    assert proof["room"] == ROOM

    record_bytes = RECORD_FILE.read_bytes()
    assert verify_export_inclusion_proof(
        record_bytes,
        proof,
        expected_root=EXPECTED_ROOT,
        expected_room=ROOM,
        expected_generation=GENERATION,
    )

    # Re-derivation from full export
    assert verify_inclusion_proof_artifact(
        proof,
        EXPORT_FILE,
        expected_root=EXPECTED_ROOT,
        expected_room=ROOM,
        expected_generation=GENERATION,
    )

    # Generation mismatch must fail
    assert not verify_export_inclusion_proof(
        record_bytes,
        proof,
        expected_root=EXPECTED_ROOT,
        expected_room=ROOM,
        expected_generation=GENERATION + 99,
    )


def test_schemas_validate_shipped_artifacts():
    commit_schema = json.loads((SCHEMAS_DIR / "export-commitment-v1.schema.json").read_text(encoding="utf-8"))
    proof_schema = json.loads((SCHEMAS_DIR / "inclusion-proof-v1.schema.json").read_text(encoding="utf-8"))

    commit_data = json.loads(COMMIT_FILE.read_text(encoding="utf-8"))
    proof_data = json.loads(PROOF_FILE.read_text(encoding="utf-8"))

    jsonschema.validate(commit_data, commit_schema)
    jsonschema.validate(proof_data, proof_schema)


def test_crlf_vs_lf_fixture_behavior():
    lf_bytes = EXPORT_FILE.read_bytes()
    crlf_bytes = lf_bytes.replace(b"\n", b"\r\n")

    assert len(crlf_bytes) == len(lf_bytes) + 4
    assert hashlib.sha256(crlf_bytes).hexdigest() != EXPECTED_SHA256

    lf_root = export_merkle_root(lf_bytes.splitlines(keepends=True)).hex()
    crlf_root = export_merkle_root(crlf_bytes.splitlines(keepends=True)).hex()

    assert lf_root == EXPECTED_ROOT
    assert crlf_root != lf_root


def test_demo_script_leaves_working_tree_clean():
    # Run demo.py in read-only mode
    demo_script = EXAMPLES_DIR / "demo.py"
    res = subprocess.run(
        [sys.executable, str(demo_script)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"demo.py failed:\n{res.stdout}\n{res.stderr}"

    # Check git status for examples directory
    status_res = subprocess.run(
        ["git", "status", "--porcelain", "examples/"],
        capture_output=True,
        text=True,
    )
    assert status_res.returncode == 0
    # No untracked or modified files in examples/
    uncommitted = [line for line in status_res.stdout.splitlines() if line.strip() and not line.startswith(" M")]
    # Tracked files should not have been modified by demo execution
    diff_res = subprocess.run(
        ["git", "diff", "--name-only", "examples/"],
        capture_output=True,
        text=True,
    )
    assert diff_res.returncode == 0
    # Shipped files shouldn't change when demo is executed


def test_shipped_consistency_proof_verifies():
    gen2_file = EXAMPLES_DIR / "synthetic_export_gen2.jsonl"
    consistency_file = EXAMPLES_DIR / "consistency_proof.json"
    consistency_schema = json.loads((SCHEMAS_DIR / "consistency-proof-v1.schema.json").read_text(encoding="utf-8"))

    assert gen2_file.is_file(), "synthetic_export_gen2.jsonl must exist"
    assert consistency_file.is_file(), "consistency_proof.json must exist"

    artifact = json.loads(consistency_file.read_text(encoding="utf-8"))
    jsonschema.validate(artifact, consistency_schema)

    assert artifact["schema"] == "tc-ledger/consistency-proof/v1"
    assert artifact["version"] == 1
    assert artifact["profile"] == "tc-ledger/1"
    assert artifact["room"] == ROOM
    assert artifact["old_generation"] == 1
    assert artifact["new_generation"] == 2
    assert artifact["old_tree_size"] == 4
    assert artifact["new_tree_size"] == 6
    assert artifact["old_root"] == EXPECTED_ROOT

    # Verify consistency artifact
    res = verify_consistency_proof_artifact(
        artifact,
        expected_room=ROOM,
        expected_old_generation=1,
        expected_new_generation=2,
        expected_old_root=EXPECTED_ROOT,
        expected_new_root=artifact["new_root"],
    )
    assert res["valid"] is True, f"Consistency verification failed: {res.get('error')}"

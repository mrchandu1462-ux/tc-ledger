import json
from pathlib import Path
import subprocess
import sys
import tempfile
import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
EXPORT_FILE = EXAMPLES / "synthetic_export.jsonl"
COMMIT_FILE = EXAMPLES / "commitment.json"
PROOF_FILE = EXAMPLES / "proof_leaf1.json"
RECORD_FILE = EXAMPLES / "record_1.bin"

EXPECTED_ROOT = "0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9"
ROOM = "demo-room"
GENERATION = 1


def run_cli(args: list[str]) -> tuple[int, str, str]:
    res = subprocess.run(
        [sys.executable, "-m", "tc_ledger", *args],
        capture_output=True,
        text=True,
    )
    return res.returncode, res.stdout, res.stderr


def test_cli_vectors_json():
    code, stdout, stderr = run_cli(["vectors", "--json"])
    assert code == 0
    assert not stderr.strip()
    data = json.loads(stdout)
    assert data["command"] == "vectors"
    assert data["valid"] is True
    assert data["profile"] == "tc-ledger/1"


def test_cli_verify_json_valid():
    code, stdout, stderr = run_cli(["verify", str(EXPORT_FILE), "--room", ROOM, "--json"])
    assert code == 0
    data = json.loads(stdout)
    assert data["command"] == "verify"
    assert data["valid"] is True
    assert data["room"] == ROOM
    assert data["line_count"] == 4
    assert data["verification"]["VALID"] == 4
    assert data["verification"]["INVALID"] == 0


def test_cli_verify_json_invalid_and_exit_1():
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = Path(tmpdir) / "bad_export.jsonl"
        bad_bytes = EXPORT_FILE.read_bytes().replace(b"did:key", b"bad:key")
        bad_file.write_bytes(bad_bytes)

        code, stdout, stderr = run_cli(["verify", str(bad_file), "--room", ROOM, "--json"])
        assert code == 1
        data = json.loads(stdout)
        assert data["command"] == "verify"
        assert data["valid"] is False
        assert data["verification"]["UNSUPPORTED_KEY"] > 0 or data["verification"]["MALFORMED"] > 0


def test_cli_verify_missing_file_exit_3():
    code, stdout, stderr = run_cli(["verify", "nonexistent_file.jsonl", "--room", ROOM, "--json"])
    assert code == 3
    assert not stdout.strip()
    assert "FAIL" in stderr


def test_cli_commit_json():
    code, stdout, stderr = run_cli([
        "commit",
        str(EXPORT_FILE),
        "--room",
        ROOM,
        "--generation",
        str(GENERATION),
        "--json",
    ])
    assert code == 0
    data = json.loads(stdout)
    assert data["command"] == "commit"
    assert data["valid"] is True
    assert data["export_root"] == EXPECTED_ROOT
    assert data["export_generation"] == GENERATION
    assert data["artifact"]["export_generation"] == GENERATION


def test_cli_prove_json_and_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_proof = Path(tmpdir) / "out_proof.json"
        code, stdout, stderr = run_cli([
            "prove",
            str(EXPORT_FILE),
            "--room",
            ROOM,
            "--leaf-index",
            "1",
            "--generation",
            str(GENERATION),
            "--output",
            str(out_proof),
            "--json",
        ])
        assert code == 0
        data = json.loads(stdout)
        assert data["command"] == "prove"
        assert data["valid"] is True
        assert data["artifact"]["leaf_index"] == 1
        assert data["artifact"]["export_generation"] == GENERATION
        assert out_proof.is_file()


def test_cli_verify_proof_json_success():
    code, stdout, stderr = run_cli([
        "verify-proof",
        str(PROOF_FILE),
        "--record",
        str(RECORD_FILE),
        "--expected-root",
        EXPECTED_ROOT,
        "--expected-room",
        ROOM,
        "--expected-generation",
        str(GENERATION),
        "--json",
    ])
    assert code == 0
    data = json.loads(stdout)
    assert data["command"] == "verify-proof"
    assert data["valid"] is True


def test_cli_verify_proof_json_mismatch_fails_exit_1():
    code, stdout, stderr = run_cli([
        "verify-proof",
        str(PROOF_FILE),
        "--record",
        str(RECORD_FILE),
        "--expected-generation",
        str(GENERATION + 1),
        "--json",
    ])
    assert code == 1
    data = json.loads(stdout)
    assert data["command"] == "verify-proof"
    assert data["valid"] is False


def test_cli_verify_proof_usage_error_exit_2():
    code, stdout, stderr = run_cli(["verify-proof", str(PROOF_FILE), "--json"])
    assert code == 2
    assert "either --record or --export" in stderr


def test_cli_verify_artifact_json_success():
    code, stdout, stderr = run_cli([
        "verify-artifact",
        str(EXPORT_FILE),
        str(COMMIT_FILE),
        "--expected-room",
        ROOM,
        "--expected-root",
        EXPECTED_ROOT,
        "--expected-generation",
        str(GENERATION),
        "--json",
    ])
    assert code == 0
    data = json.loads(stdout)
    assert data["command"] == "verify-artifact"
    assert data["valid"] is True


def test_cli_verify_artifact_json_generation_mismatch_exit_1():
    code, stdout, stderr = run_cli([
        "verify-artifact",
        str(EXPORT_FILE),
        str(COMMIT_FILE),
        "--expected-generation",
        str(GENERATION + 5),
        "--json",
    ])
    assert code == 1
    data = json.loads(stdout)
    assert data["command"] == "verify-artifact"
    assert data["valid"] is False


def test_cli_verify_artifact_missing_file_exit_3():
    code, stdout, stderr = run_cli([
        "verify-artifact",
        "nonexistent_export.jsonl",
        str(COMMIT_FILE),
        "--json",
    ])
    assert code == 1 or code == 3

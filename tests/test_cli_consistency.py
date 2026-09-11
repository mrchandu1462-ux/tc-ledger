"""Tests for C7 consistency CLI commands: consistency-proof and verify-consistency."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_cli(args: list[str]) -> tuple[int, str, str]:
    res = subprocess.run(
        [sys.executable, "-m", "tc_ledger", *args],
        capture_output=True,
        text=True,
    )
    return res.returncode, res.stdout, res.stderr


def test_cli_consistency_help():
    code, stdout, _ = run_cli(["consistency-proof", "--help"])
    assert code == 0
    assert "consistency-proof" in stdout

    code2, stdout2, _ = run_cli(["verify-consistency", "--help"])
    assert code2 == 0
    assert "verify-consistency" in stdout2


def test_cli_consistency_lifecycle_human_and_json():
    old_lines = [
        '{"room":"lobby","seq":1,"text":"first"}\n',
        '{"room":"lobby","seq":2,"text":"second"}\n',
    ]
    new_lines = old_lines + [
        '{"room":"lobby","seq":3,"text":"third"}\n',
        '{"room":"lobby","seq":4,"text":"fourth"}\n',
    ]

    with tempfile.TemporaryDirectory() as tmp_dir:
        old_export = Path(tmp_dir) / "gen1.jsonl"
        new_export = Path(tmp_dir) / "gen2.jsonl"
        proof_file = Path(tmp_dir) / "proof.json"

        old_export.write_text("".join(old_lines), encoding="utf-8")
        new_export.write_text("".join(new_lines), encoding="utf-8")

        # 1. Generate proof (human output)
        code, stdout, stderr = run_cli([
            "consistency-proof",
            str(old_export),
            str(new_export),
            "--room", "lobby",
            "--old-generation", "1",
            "--new-generation", "2",
            "--output", str(proof_file),
        ])
        assert code == 0, stderr
        assert proof_file.exists()
        assert "Consistency proof artifact" in stdout

        # 2. Verify proof (human output)
        code_v, stdout_v, stderr_v = run_cli([
            "verify-consistency",
            str(proof_file),
            "--expected-room", "lobby",
            "--expected-old-generation", "1",
            "--expected-new-generation", "2",
        ])
        assert code_v == 0, stderr_v
        assert "VALID" in stdout_v

        # 3. Generate proof (--json output)
        proof_json_file = Path(tmp_dir) / "proof2.json"
        code_json, stdout_json, stderr_json = run_cli([
            "consistency-proof",
            str(old_export),
            str(new_export),
            "--room", "lobby",
            "--old-generation", "1",
            "--new-generation", "2",
            "--output", str(proof_json_file),
            "--json",
        ])
        assert code_json == 0, stderr_json
        parsed_out = json.loads(stdout_json)
        assert parsed_out["command"] == "consistency-proof"
        assert parsed_out["valid"] is True
        assert parsed_out["old_generation"] == 1
        assert parsed_out["new_generation"] == 2
        assert parsed_out["artifact"]["old_tree_size"] == 2
        assert parsed_out["artifact"]["new_tree_size"] == 4

        # 4. Verify proof (--json output)
        code_v_json, stdout_v_json, stderr_v_json = run_cli([
            "verify-consistency",
            str(proof_json_file),
            "--expected-room", "lobby",
            "--expected-old-generation", "1",
            "--expected-new-generation", "2",
            "--json",
        ])
        assert code_v_json == 0, stderr_v_json
        parsed_v = json.loads(stdout_v_json)
        assert parsed_v["command"] == "verify-consistency"
        assert parsed_v["valid"] is True
        assert parsed_v["old_tree_size"] == 2
        assert parsed_v["new_tree_size"] == 4


def test_cli_consistency_verification_failures():
    old_lines = ['{"room":"lobby","seq":1,"text":"first"}\n']
    new_lines = old_lines + ['{"room":"lobby","seq":2,"text":"second"}\n']

    with tempfile.TemporaryDirectory() as tmp_dir:
        old_export = Path(tmp_dir) / "gen1.jsonl"
        new_export = Path(tmp_dir) / "gen2.jsonl"
        proof_file = Path(tmp_dir) / "proof.json"

        old_export.write_text("".join(old_lines), encoding="utf-8")
        new_export.write_text("".join(new_lines), encoding="utf-8")

        code, _, stderr = run_cli([
            "consistency-proof",
            str(old_export),
            str(new_export),
            "--room", "lobby",
            "--old-generation", "1",
            "--new-generation", "2",
            "--output", str(proof_file),
        ])
        assert code == 0, stderr

        # Wrong expected room -> exit code 1
        code_bad_room, stdout_bad_room, _ = run_cli([
            "verify-consistency",
            str(proof_file),
            "--expected-room", "wrong-room",
            "--json",
        ])
        assert code_bad_room == 1
        payload = json.loads(stdout_bad_room)
        assert payload["command"] == "verify-consistency"
        assert payload["valid"] is False
        assert "room mismatch" in payload["error"]

        # Wrong expected generation -> exit code 1
        code_bad_gen, stdout_bad_gen, _ = run_cli([
            "verify-consistency",
            str(proof_file),
            "--expected-old-generation", "99",
            "--json",
        ])
        assert code_bad_gen == 1
        payload = json.loads(stdout_bad_gen)
        assert payload["command"] == "verify-consistency"
        assert payload["valid"] is False
        assert "generation mismatch" in payload["error"]

        # Tampered proof node -> exit code 1
        proof_data = json.loads(proof_file.read_text(encoding="utf-8"))
        proof_data["proof"] = ["00" * 32]
        bad_proof_file = Path(tmp_dir) / "tampered.json"
        bad_proof_file.write_text(json.dumps(proof_data), encoding="utf-8")

        code_tampered, stdout_tampered, _ = run_cli([
            "verify-consistency",
            str(bad_proof_file),
            "--json",
        ])
        assert code_tampered == 1
        payload = json.loads(stdout_tampered)
        assert payload["command"] == "verify-consistency"
        assert payload["valid"] is False


def test_cli_consistency_usage_and_io_errors():
    # Non-existent file -> exit code 3 (I/O error), diagnostics to stderr
    code_io, stdout_io, stderr_io = run_cli([
        "verify-consistency",
        "non_existent_file.json",
        "--json",
    ])
    assert code_io == 3
    assert not stdout_io.strip()
    assert "FAIL" in stderr_io

    # Missing required argument for consistency-proof -> exit code 2 (usage error)
    code_usage, _, stderr_usage = run_cli(["consistency-proof"])
    assert code_usage == 2

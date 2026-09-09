"""
End-to-end demonstration of the tc-ledger evidence and verification pipeline.

Demonstrates:
1. Verifying signed Technocore records in an export.
2. Generating RFC 8785 (JCS) evidence commitments.
3. Constructing an export Merkle tree and export commitment artifact.
4. Independently verifying and re-deriving the export commitment artifact (verify-commitment).
5. Generating an Export Inclusion Proof v1 for an individual record.
6. Verifying the inclusion proof independently without the full export or network access.
7. Proving that tampered record bytes are rejected fail-closed.
"""
from pathlib import Path
import json
import subprocess
import sys

EXAMPLES_DIR = Path(__file__).parent.resolve()
EXPORT_FILE = EXAMPLES_DIR / "synthetic_export.jsonl"
ROOM = "demo-room"


def run_cmd(args: list[str]) -> tuple[int, str]:
    res = subprocess.run(
        [sys.executable, "-m", "tc_ledger.ledger", *args],
        capture_output=True,
        text=True,
    )
    return res.returncode, (res.stdout + res.stderr).strip()


def main():
    print("=" * 70)
    print("TC-LEDGER END-TO-END VERIFICATION DEMO")
    print("=" * 70)
    print(f"\n[1] Export Source: {EXPORT_FILE.name}")
    raw_lines = EXPORT_FILE.read_bytes().splitlines(keepends=True)
    print(f"    Loaded {len(raw_lines)} physical lines from synthetic export.")

    print("\n[2] Verifying Signatures (tc-ledger verify)...")
    code, out = run_cmd(["verify", str(EXPORT_FILE), "--room", ROOM])
    print(f"    Return code: {code}")
    for line in out.splitlines():
        print(f"    {line}")
    assert code == 0, "Verification failed!"

    print("\n[3] Generating Export Commitment (tc-ledger commit)...")
    commit_artifact = EXAMPLES_DIR / "commitment.json"
    code, out = run_cmd(
        ["commit", str(EXPORT_FILE), "--room", ROOM, "--output", str(commit_artifact)]
    )
    print(f"    Return code: {code}")
    for line in out.splitlines():
        print(f"    {line}")
    assert code == 0, "Commit failed!"

    artifact_data = json.loads(commit_artifact.read_text(encoding="utf-8"))
    export_root = artifact_data["export_root"]
    print(f"    Committed Export Merkle Root: {export_root}")

    print("\n[4] Re-Deriving & Verifying Commitment Artifact (tc-ledger verify-commitment)...")
    code, out = run_cmd(
        [
            "verify-commitment",
            str(EXPORT_FILE),
            str(commit_artifact),
            "--expected-room",
            ROOM,
        ]
    )
    print(f"    Return code: {code}")
    print(f"    Output: {out}")
    assert code == 0 and "VERIFY-COMMITMENT: VALID" in out, "Commitment artifact re-derivation failed!"

    print("\n[5] Generating Inclusion Proof for Leaf Index 1 (tc-ledger prove)...")
    proof_file = EXAMPLES_DIR / "proof_leaf1.json"
    code, out = run_cmd(
        [
            "prove",
            str(EXPORT_FILE),
            "--room",
            ROOM,
            "--leaf-index",
            "1",
            "--generation",
            "1",
            "--output",
            str(proof_file),
        ]
    )
    print(f"    Return code: {code}")
    for line in out.splitlines():
        print(f"    {line}")
    assert code == 0, "Proof generation failed!"

    record_file = EXAMPLES_DIR / "record_1.bin"
    record_file.write_bytes(raw_lines[1])
    print(f"    Extracted target leaf 1 raw line to: {record_file.name} ({len(raw_lines[1])} bytes)")

    print("\n[6] Independent Offline Proof Verification (tc-ledger verify-proof)...")
    print("    Verifier holds ONLY:")
    print(f"    - Raw record bytes ({record_file.name})")
    print(f"    - Inclusion proof artifact ({proof_file.name})")
    print(f"    - Expected trust anchors (room={ROOM}, root={export_root[:16]}...)")
    code, out = run_cmd(
        [
            "verify-proof",
            str(proof_file),
            "--record",
            str(record_file),
            "--expected-root",
            export_root,
            "--expected-room",
            ROOM,
            "--expected-generation",
            "1",
        ]
    )
    print(f"    Return code: {code}")
    print(f"    Output: {out}")
    assert code == 0 and "VERIFY-PROOF: VALID" in out, "Proof verification failed!"

    print("\n[7] Adversarial Check: Tampered Record Byte Verification...")
    tampered_file = EXAMPLES_DIR / "tampered_record.bin"
    tampered_bytes = raw_lines[1].replace(b"Bob", b"Mallory")
    tampered_file.write_bytes(tampered_bytes)
    code, out = run_cmd(
        [
            "verify-proof",
            str(proof_file),
            "--record",
            str(tampered_file),
            "--expected-root",
            export_root,
            "--expected-room",
            ROOM,
        ]
    )
    print(f"    Return code: {code} (Expected: non-zero)")
    print(f"    Output: {out}")
    assert code != 0 and "VERIFY-PROOF: INVALID" in out, "Tampered proof unexpectedly succeeded!"
    tampered_file.unlink()

    print("\n" + "=" * 70)
    print("DEMO COMPLETE: All verification stages succeeded deterministically!")
    print("=" * 70)


if __name__ == "__main__":
    main()
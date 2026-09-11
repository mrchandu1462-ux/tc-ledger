"""
End-to-end demonstration of the tc-ledger evidence and verification pipeline.

Demonstrates:
1. Verifying signed Technocore records in an export.
2. Generating/checking RFC 8785 (JCS) evidence commitments.
3. Constructing an export Merkle tree and export commitment artifact.
4. Independently verifying and re-deriving the export commitment artifact (verify-commitment).
5. Generating an Export Inclusion Proof v1 for an individual record.
6. Verifying the inclusion proof independently without the full export or network access.
7. Proving that tampered record bytes are rejected fail-closed.

By default, this script operates in READ-ONLY mode, verifying existing shipped artifacts
without modifying git-tracked files. Pass --regenerate to intentionally regenerate artifacts.
"""
from pathlib import Path
import argparse
import json
import subprocess
import sys
import tempfile

EXAMPLES_DIR = Path(__file__).parent.resolve()
EXPORT_FILE = EXAMPLES_DIR / "synthetic_export.jsonl"
ROOM = "demo-room"
GENERATION = 1


def run_cmd(args: list[str]) -> tuple[int, str]:
    res = subprocess.run(
        [sys.executable, "-m", "tc_ledger", *args],
        capture_output=True,
        text=True,
    )
    return res.returncode, (res.stdout + res.stderr).strip()


def main():
    parser = argparse.ArgumentParser(description="TC-Ledger demo verification script")
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Regenerate committed example artifacts in-place",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("TC-LEDGER END-TO-END VERIFICATION DEMO")
    print(f"Mode: {'REGENERATE' if args.regenerate else 'READ-ONLY VERIFICATION'}")
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

    commit_artifact = EXAMPLES_DIR / "commitment.json"
    proof_file = EXAMPLES_DIR / "proof_leaf1.json"
    record_file = EXAMPLES_DIR / "record_1.bin"

    if args.regenerate:
        print("\n[3] Regenerating Export Commitment (tc-ledger commit)...")
        code, out = run_cmd([
            "commit",
            str(EXPORT_FILE),
            "--room",
            ROOM,
            "--generation",
            str(GENERATION),
            "--output",
            str(commit_artifact),
        ])
        print(f"    Return code: {code}")
        assert code == 0, "Commit regeneration failed!"

        print("\n[4] Regenerating Inclusion Proof for Leaf Index 1 (tc-ledger prove)...")
        code, out = run_cmd([
            "prove",
            str(EXPORT_FILE),
            "--room",
            ROOM,
            "--leaf-index",
            "1",
            "--generation",
            str(GENERATION),
            "--output",
            str(proof_file),
        ])
        print(f"    Return code: {code}")
        assert code == 0, "Proof regeneration failed!"

        record_file.write_bytes(raw_lines[1])
        print(f"    Updated record_1.bin ({len(raw_lines[1])} bytes)")

    artifact_data = json.loads(commit_artifact.read_text(encoding="utf-8"))
    export_root = artifact_data["export_root"]
    print(f"\n[3] Committed Export Merkle Root: {export_root}")
    print(f"    Committed Export Generation: {artifact_data.get('export_generation')}")

    print("\n[4] Re-Deriving & Verifying Commitment Artifact (tc-ledger verify-artifact)...")
    code, out = run_cmd([
        "verify-artifact",
        str(EXPORT_FILE),
        str(commit_artifact),
        "--expected-room",
        ROOM,
        "--expected-root",
        export_root,
        "--expected-generation",
        str(GENERATION),
    ])
    print(f"    Return code: {code}")
    print(f"    Output: {out}")
    assert code == 0 and "VERIFY-ARTIFACT: VALID" in out, "Commitment artifact re-derivation failed!"

    print("\n[5] Independent Offline Proof Verification (tc-ledger verify-proof)...")
    print(f"    Verifier holds ONLY:")
    print(f"    - Raw record bytes ({record_file.name}, {len(record_file.read_bytes())} bytes)")
    print(f"    - Inclusion proof artifact ({proof_file.name})")
    print(f"    - Expected trust anchors (room={ROOM}, root={export_root[:16]}..., gen={GENERATION})")
    code, out = run_cmd([
        "verify-proof",
        str(proof_file),
        "--record",
        str(record_file),
        "--expected-root",
        export_root,
        "--expected-room",
        ROOM,
        "--expected-generation",
        str(GENERATION),
    ])
    print(f"    Return code: {code}")
    print(f"    Output: {out}")
    assert code == 0 and "VERIFY-PROOF: VALID" in out, "Proof verification failed!"

    print("\n[6] Adversarial Check: Tampered Record Byte Verification...")
    with tempfile.TemporaryDirectory() as tmpdir:
        tampered_file = Path(tmpdir) / "tampered_record.bin"
        tampered_bytes = raw_lines[1].replace(b"Bob", b"Mallory")
        tampered_file.write_bytes(tampered_bytes)
        code, out = run_cmd([
            "verify-proof",
            str(proof_file),
            "--record",
            str(tampered_file),
            "--expected-root",
            export_root,
            "--expected-room",
            ROOM,
            "--expected-generation",
            str(GENERATION),
        ])
        print(f"    Return code: {code} (Expected: 1)")
        print(f"    Output: {out}")
        assert code == 1 and "VERIFY-PROOF: INVALID" in out, "Tampered proof unexpectedly succeeded!"

    # C7: Cross-Generation Merkle Consistency Proof
    gen2_export = EXAMPLES_DIR / "synthetic_export_gen2.jsonl"
    consistency_proof_file = EXAMPLES_DIR / "consistency_proof.json"

    if args.regenerate:
        print("\n[7] Regenerating Cross-Generation Consistency Proof (tc-ledger consistency-proof)...")
        code, out = run_cmd([
            "consistency-proof",
            str(EXPORT_FILE),
            str(gen2_export),
            "--room",
            ROOM,
            "--old-generation",
            "1",
            "--new-generation",
            "2",
            "--output",
            str(consistency_proof_file),
        ])
        print(f"    Return code: {code}")
        assert code == 0, "Consistency proof regeneration failed!"

    print("\n[7] Cross-Generation Consistency Proof Verification (tc-ledger verify-consistency)...")
    code, out = run_cmd([
        "verify-consistency",
        str(consistency_proof_file),
        "--expected-room",
        ROOM,
        "--expected-old-generation",
        "1",
        "--expected-new-generation",
        "2",
        "--expected-old-root",
        export_root,
    ])
    print(f"    Return code: {code}")
    print(f"    Output: {out}")
    assert code == 0 and "VERIFY-CONSISTENCY: VALID" in out, "Consistency proof verification failed!"

    print("\n[8] Adversarial Check: Tampered Consistency Proof...")
    with tempfile.TemporaryDirectory() as tmpdir:
        tampered_proof_path = Path(tmpdir) / "tampered_proof.json"
        proof_obj = json.loads(consistency_proof_file.read_text(encoding="utf-8"))
        proof_obj["proof"] = ["00" * 32]
        tampered_proof_path.write_text(json.dumps(proof_obj), encoding="utf-8")
        code, out = run_cmd([
            "verify-consistency",
            str(tampered_proof_path),
            "--expected-room",
            ROOM,
            "--expected-old-generation",
            "1",
            "--expected-new-generation",
            "2",
        ])
        print(f"    Return code: {code} (Expected: 1)")
        print(f"    Output: {out}")
        assert code == 1 and "VERIFY-CONSISTENCY: INVALID" in out, "Tampered consistency proof unexpectedly succeeded!"

    print("\n" + "=" * 70)
    print("DEMO COMPLETE: All verification stages succeeded deterministically!")
    print("=" * 70)


if __name__ == "__main__":
    main()

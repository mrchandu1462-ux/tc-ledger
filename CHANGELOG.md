# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-09-11

### Added
- Read-only live Technocore activity discovery.
- DID activity lookup with ACTIVE, STALE, and NO DATA semantics.
- Live Explorer mode with retained-room activity and record inspection.
- JSON indexer output and local read-only indexer adapter.
- Live integration and browser journey tests.
- Live integration boundary documentation.

### Security
- Preserved frozen v0.3.1 cryptographic verification behavior.
- Added explicit live-data trust, retention, and failure-boundary documentation.
- Live failures never silently fall back to synthetic data.

## [0.3.1] - 2026-09-11

### Security Hardening & Audit Remediation
- **F-1: New Tree Size Verification Semantics**: Added explicit verifier checks and CLI flags (`--expected-old-tree-size`, `--expected-new-tree-size`) to ensure tree sizes are not accepted as authenticated without caller trust anchors. Returns `"tree_sizes_authenticated": true` only when anchored.
- **F-2: Trust-Anchor Envelope Boundaries**: Documented and tested that artifact metadata fields (`room`, `old_generation`, `new_generation`, tree sizes) are self-attested envelope properties; verifiers must anchor against caller expectations.
- **F-3: Strict Canonical Base64URL Signature Decoding**: Implemented strict validation rejecting rogue characters, malformed/non-matching padding (`=`), and non-zero unused padding bits (preventing signature malleability).
- **F-4: Nonce Representation Documentation & Tests**: Documented the distinction between wire payload string interpolation (`room|nonce|text`) and RFC 8785 (JCS) type-preserving evidence commitment differentiation (`{"nonce": 1001}` vs `{"nonce": "1001"}`).
- **F-5: Pipe Delimiter Enforcement**: Strictly reject room identifiers containing `|` in `verify_signed_record`, `evidence_commitment`, and `build_consistency_proof_artifact` to prevent payload injection or field confusion.
- **C7 Adversarial & Retention Regression Tests**: Added comprehensive test matrix covering tree size tampering, room mutation, generation mutation, proof mutation, root tampering, truncated paths, extra nodes, non-power-of-two trees, and server retention eviction failures.
- **Documentation Hygiene**: Fixed all NUL bytes, corrupted control characters, and single-backtick code fences across tracked Markdown files. Added automated hygiene test `tests/test_hygiene.py`.

## [0.3.0] - 2026-09-11

### Added
- **C7 Cryptographic Cross-Generation Consistency**: Upgraded `export_generation` into a cryptographically verifiable append-only continuity mechanism based on RFC 6962 §2.1.2 Merkle consistency proofs.
- **Consistency Proof Generation & Verification Engine**: Implemented `consistency_proof`, `verify_consistency_proof`, `build_consistency_proof_artifact`, `write_consistency_proof_artifact`, and `verify_consistency_proof_artifact`.
- **Additive C7 Artifact & Schema**: Defined `tc-ledger/consistency-proof/v1` schema (`schemas/consistency-proof-v1.schema.json`) with strict validation of room, generations, tree sizes, roots, and audit paths.
- **C7 CLI Commands**: Added `tc-ledger consistency-proof` and `tc-ledger verify-consistency` with full `--json` support and deterministic exit codes (0 = valid, 1 = invalid, 2 = usage error, 3 = I/O error).
- **C7 Conformance Vectors**: Added 20 comprehensive positive and negative consistency vectors to `vectors/conformance.json` and standalone `vectors/c7_consistency_vectors.json`.
- **C7 Shipped Examples**: Added `examples/synthetic_export_gen2.jsonl`, `examples/consistency_proof.json`, and updated `examples/demo.py`.
- **Specification Document**: Created comprehensive C7 protocol specification in `docs/consistency-proof-format-v1.md`.

### Unchanged
- **C6 Protocol & Artifacts Frozen**: Zero modifications to `evidence-v1`, `merkle-v1`, `export-commitment-v1`, or `inclusion-proof-v1`. Full backward compatibility preserved across all previous tests and conformance suites.

## [0.2.0] - 2026-09-11

### Added
- **C6 Reproducible Verifier Release**: Fully reproducible offline verification across Linux, macOS, and Windows.
- **Machine-Readable CLI Contract**: Added --json flag to verify, commit, vectors, prove, verify-proof, and verify-artifact / verify-commitment with deterministic structured outputs and strict stdout/stderr separation.
- **Standardized Process Exit Codes**:
  - 0: Successful execution / valid verification
  - 1: Verification failure / invalid evidence
  - 2: Command-line usage / argument syntax error
  - 3: I/O, parse, or runtime data error
- **Verified Generation Anchors**: Explicit --generation support on commit and --expected-generation validation on verify-artifact and verify-proof preventing epoch confusion.
- **Root .gitattributes Policy**: Protects raw cryptographic JSONL, binary files, and artifacts from OS-specific line-ending conversions (*.jsonl -text, *.bin -text, examples/** -text).
- **Comprehensive Conformance Vectors (C0-C5)**: Extended test suite covering Technocore export verification, RFC 8785 (JCS) deterministic evidence commitment, RFC 6962 Merkle leaf/node prefixes, odd-node promotion, byte model edge cases, and inclusion proof verification.
- **Live Technocore Protocol Boundary Coverage**: Added boundary test cases for 1-19 digit decimal nonces, 4096-character message limits, sparse retained export sequences, and epoch trust anchors.
- **JSON Schemas**: Added formal schemas under schemas/ for export-commitment-v1, inclusion-proof-v1, and evidence-v1.
- **Public Python API**: Streamlined src/tc_ledger/__init__.py exposing clean functions, data types, exceptions, and __version__ = "0.2.0".
- **Read-Only Demo**: examples/demo.py now executes in read-only mode by default without mutating repository fixtures, with an optional --regenerate flag.
- **CI Hardening**: Enhanced multi-OS GitHub Actions workflow validating Python tests, TypeScript rail tests, Foundry contracts, CLI JSON mode, and working-tree cleanliness.

### Changed
- Standardized examples/synthetic_export.jsonl to byte-exact LF endings (1041 bytes, root 0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9).
- Shipped example artifacts regenerated and independently verified.

## [0.1.0] - 2026-09-02

### Added
- Initial implementation of tc-ledger evidence verification and export commitment pipeline.
- RFC 6962 export Merkle tree calculation.
- Ed25519 signature verification over Technocore records (room|nonce|text).
- Offline export inclusion proof generation and verification.
- Initial test suite and frozen RFC 6962 test vectors.

# tc-ledger End-to-End Demonstration

This directory contains a self-contained, reproducible demonstration of the `tc-ledger` evidence and verification lifecycle using a synthetic 4-record export fixture (`synthetic_export.jsonl`).

## Files

* `synthetic_export.jsonl`: Deterministic synthetic export containing valid Ed25519 signatures from `did:key:z...` identities.
* `demo.py`: Python script executing the complete pipeline via the `tc-ledger` CLI.
* `commitment.json`: Export commitment artifact generated during the demo.
* `proof_leaf1.json`: Export Inclusion Proof v1 generated for leaf index 1.
* `record_1.bin`: Extracted raw line bytes for leaf index 1 used in offline verification.

## Running the Demo

From the repository root:

```bash
uv run python examples/demo.py
```

## Lifecycle Steps Demonstrated

1. **Signature Verification (`tc-ledger verify`)**: Confirms all Ed25519 signatures over `room|nonce|text`.
2. **Export Commitment (`tc-ledger commit`)**: Computes the RFC 6962-compliant export Merkle root across all raw physical lines and maps evidence identifiers.
3. **Inclusion Proof Generation (`tc-ledger prove`)**: Generates a self-contained inclusion proof artifact containing audit path siblings and positions.
4. **Independent Offline Verification (`tc-ledger verify-proof`)**: Proves the individual line is present in the committed export Merkle root without accessing the original export file or network.
5. **Adversarial Invalidation**: Demonstrates that altering any bytes in the record triggers an immediate `VERIFY-PROOF: INVALID` failure.
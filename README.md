# TC-Ledger

An open-source cryptographic evidence layer for making signed Technocore activity independently verifiable after the original room history is unavailable.

## Why It Exists

Application history is operational. Evidence should be independently verifiable.

In modern agentic and collaborative messaging platforms like Technocore, activities and outputs are cryptographically signed by participants. However:

* **Operational Ephemerality**: Chat backends, rooms, and server databases eventually get archived, pruned, reset, or taken offline.
* **Integrity of Captured Logs**: Storing flat text exports (e.g. JSONL) leaves them vulnerable to silent line deletions, reordering, or modification.
* **Trustless Verification**: Independent auditors, participants, and downstream consumers need a deterministic, reproducible way to verify what was signed and what export data was committed—without continuous server access or blind trust in an operator.

`tc-ledger` bridges this gap by turning signed JSONL exports into deterministic cryptographic commitments, Merkle completeness trees, and self-contained inclusion proofs.

## Architecture

```text
       Signed Technocore Export (JSONL)
                      |
                      v
             Record Verification
        (Ed25519, did:key, canonical binding)
                      |
                      v
             Evidence Commitments
         (JCS RFC 8785, SHA-256 v1 IDs)
                      |
                      v
              Export Commitment
     (Raw line byte tree, LF/CRLF preserved)
                      |
                      v
                 Merkle Root
       (RFC 6962 domain separation, 0x01)
                      |
                      v
               Inclusion Proof
        (Audit path, directions, metadata)
                      |
                      v
             Independent Verifier
       (Offline, zero-network verification)
```

### Component Boundaries

* **`tc-ledger` (Core)**: Python package and CLI implementing the cryptographic evidence, Merkle aggregation, export completeness commitment, and inclusion proof verification layer.
* **`tclk-rail-evm` (Sub-project)**: An experimental EVM Hash Time Locked Contract (HTLC) settlement rail for atomic lock/claim/refund operations. It is a separate settlement component and is not required for core evidence verification.

## Guarantees & Non-Guarantees

### What TC-Ledger Guarantees

* **Signature Validity**: Cryptographically verifies that a record was signed by the Ed25519 private key corresponding to its declared `did:key:z6Mk...` identifier over the exact canonical payload `room|nonce|text`.
* **Exact Record Identity**: Normalizes valid evidence payloads via RFC 8785 JCS to yield a unique, deterministic evidence identifier (`tc-ledger:v1:<sha256-hex>`).
* **Export Completeness & Ordering**: Binds physical export lines in source order without re-serialization, preserving byte-exact line terminators (LF, CRLF, or unterminated lines) and blank lines.
* **Merkle Inclusion Proofs**: Generates compact, standard audit paths allowing any individual export line to be proven against a known Merkle root.
* **Self-Contained Offline Verification**: Allows an independent third party to verify an inclusion proof using only the target record bytes, the proof artifact, and expected trust anchors—with zero network access or full export downloads.

### What TC-Ledger Does Not Guarantee

* **Application Truthfulness**: It proves that an identity signed a specific message; it does not prove the factual truth of the message contents.
* **Key Ownership / Identity Attribution**: It verifies signatures against public keys encoded in `did:key`; it does not establish real-world identity or solve private key compromise.
* **Permanent Data Availability**: It commits to and proves inclusion within export files, but does not provide distributed consensus or decentralized storage. Users and operators must maintain durable backups of export artifacts.
* **Arbitrary Token Support**: The EVM settlement rail intentionally supports standard ERC-20 and native ETH transfers; it does not support fee-on-transfer or deflationary token economics.

## Capabilities (C0–C5)

The core implementation is structured across capabilities C0 through C5:

| Milestone | Capability | Status & Source Implementation |
| :--- | :--- | :--- |
| **C0** | **Signed Technocore Export Verification** | Parses JSONL; decodes `did:key:z6Mk...` (RFC 8032 Ed25519, multicodec `0xed01`, 32-byte key); validates 1–19 digit nonces; verifies Ed25519 signatures over `room\|nonce\|text`; classifies lines (`tc-ledger verify`). |
| **C1** | **Export Stream Verification & Classification** | Line-by-line classification of exports into valid, invalid, unsigned, malformed, and unsupported key types; preserves line order and index mappings. |
| **C2** | **Evidence Format v1 Commitments** | RFC 8785 JSON Canonicalization Scheme (JCS); SHA-256 content hashing; deterministic IDs `tc-ledger:v1:<sha256-hex>`; bidirectional mapping to export line indices. |
| **C3** | **Merkle Aggregation Primitives** | Binary Merkle tree with RFC 6962 domain separation (`0x00` leaf, `0x01` internal node); odd-node promotion without duplication; validated against frozen test vectors (`tc-ledger vectors`). |
| **C4** | **Export Commitment Artifacts** | Binds raw physical export bytes; preserves exact line terminators; classifies anomalies; records export Merkle root, line counts, and evidence mappings into JSON commitment artifacts (`tc-ledger commit`). |
| **C5** | **Export Inclusion Proofs** | Generates audit paths with sibling hashes and `left`/`right` positions; provides offline self-contained verification against expected roots, rooms, and generations (`tc-ledger prove` and `tc-ledger verify-proof`). |

## Cryptographic Model

| Primitive | Standard / Model | Details |
| :--- | :--- | :--- |
| **Signature Scheme** | Ed25519 (RFC 8032) | Verified via `nacl.signing.VerifyKey`. |
| **Key Identifier** | W3C `did:key` | Multibase `z` (base58btc) with multicodec `0xed01` (Ed25519 public key) and exactly 32 raw key bytes. |
| **Message Binding** | Canonical UTF-8 string | Formatted as `room\|nonce\|text`. Nonce must be 1–19 ASCII digits. |
| **Canonicalization** | JCS (RFC 8785) | Deterministic key sorting and number representation for evidence payloads. |
| **Hash Function** | SHA-256 (FIPS 180-4) | Applied to canonical evidence payloads, leaves, and parent nodes. |
| **Leaf Hashing** | RFC 6962 Domain Separation | Leaf: `SHA-256(0x00 \|\| raw_line_bytes)`. |
| **Node Hashing** | RFC 6962 Domain Separation | Internal Node: `SHA-256(0x01 \|\| left_hash \|\| right_hash)`. |
| **Odd-Node Handling** | Unpaired Promotion | Trailing unpaired nodes in odd levels are promoted to the next level without duplication or self-hashing. |

## CLI Reference

The CLI entrypoint `tc-ledger` is installed via `pyproject.toml` pointing to `tc_ledger.ledger:main`.

### `tc-ledger verify`
Verifies Ed25519 signatures and classifies every record in a Technocore JSONL export.
```bash
tc-ledger verify <path-to-export.jsonl> --room <room-id>
```

### `tc-ledger commit`
Computes the raw-byte export Merkle root, maps evidence commitments, and writes an export commitment artifact.
```bash
tc-ledger commit <path-to-export.jsonl> --room <room-id> [--output <artifact.json>]
```

### `tc-ledger vectors`
Validates frozen v1 test vectors (`vectors/vectors.json`) covering trivial trees, byte-model edge cases, and synthetic exports.
```bash
tc-ledger vectors
```

### `tc-ledger prove`
Extracts an Export Inclusion Proof v1 artifact for an export line at a designated leaf index.
```bash
tc-ledger prove <path-to-export.jsonl> --room <room-id> --leaf-index <index> [--generation <gen>] [--output <proof.json>]
```

### `tc-ledger verify-commitment`
Re-derives and independently verifies an Export Commitment v1 artifact against raw export bytes, asserting line count, byte count, file SHA-256, Merkle root, verification counts, and anomaly indices.
```bash
tc-ledger verify-commitment <path-to-export.jsonl> <path-to-artifact.json> [--expected-room <room>] [--expected-generation <gen>]
```

### `tc-ledger verify-proof`
Independently verifies an Export Inclusion Proof artifact against an extracted record or export file.
```bash
# Offline verification with single record and trust anchors
tc-ledger verify-proof <proof.json> --record <record.bin> --expected-root <hex> --expected-room <room>

# Verification against full export
tc-ledger verify-proof <proof.json> --export <export.jsonl> --expected-root <hex>
```

## End-to-End Walkthrough

A reproducible demonstration is provided in [`examples/`](examples):

```bash
# Run the automated end-to-end demo script
uv run python examples/demo.py
```

### Manual CLI Walkthrough

Using the provided synthetic export fixture:

```bash
# 1. Verify signatures in the export
tc-ledger verify examples/synthetic_export.jsonl --room demo-room

# 2. Generate export commitment artifact
tc-ledger commit examples/synthetic_export.jsonl --room demo-room --output examples/commitment.json

# 3. Independently verify and re-derive the commitment artifact
tc-ledger verify-commitment examples/synthetic_export.jsonl examples/commitment.json --expected-room demo-room
# Outputs: VERIFY-COMMITMENT: VALID (exit code 0)

# 4. Generate inclusion proof for leaf index 1 (Bob''s record)
tc-ledger prove examples/synthetic_export.jsonl --room demo-room --leaf-index 1 --generation 1 --output examples/proof_leaf1.json

# 5. Verify the proof offline against extracted record bytes and expected root
tc-ledger verify-proof examples/proof_leaf1.json \
  --record examples/record_1.bin \
  --expected-root aae69af634f328ce701799c7d9e6a7b67403733e0c9f2ddd7de42469e17dcc00 \
  --expected-room demo-room \
  --expected-generation 1
# Outputs: VERIFY-PROOF: VALID (exit code 0)
```

## Specifications

Detailed specification documents are maintained in [`docs/`](docs):

* [docs/evidence-format-v1.md](docs/evidence-format-v1.md): JCS canonicalization, evidence commitment format, and `tc-ledger:v1:<sha256-hex>` identifiers.
* [docs/export-commitment-format-v1.md](docs/export-commitment-format-v1.md): Raw export byte stream semantics, line-terminator preservation, blank lines, and completeness tree structure.
* [docs/merkle-format-v1.md](docs/merkle-format-v1.md): RFC 6962-style Merkle aggregation, leaf hashing (`0x00`), internal node hashing (`0x01`), and odd-node promotion.
* [docs/inclusion-proof-format-v1.md](docs/inclusion-proof-format-v1.md): Export Inclusion Proof v1 schema, audit path representation, trust anchors, and verification algorithm.

## EVM Settlement Rail (`tclk-rail-evm`)

Located in [`tclk-rail-evm/`](tclk-rail-evm), this sub-project provides an EVM-based Hash Time Locked Contract (HTLC) settlement rail for atomic value transfers linked to commitments.

* **Smart Contract (`contracts/Htlc.sol`)**:
  * Native ETH and ERC-20 token escrows.
  * Operations: `lock()`, `claim()`, and `refund()`.
  * SafeERC20 compatibility including zero-return tokens.
  * Reentrancy protection and Checks-Effects-Interactions (CEI) ordering.
  * Fail-closed balance delta verification.
* **TypeScript Client Library (`src/rail.ts`)**:
  * Viem-based client (`EvmHtlcRail`) with DID-to-EVM address resolvers (`StaticAddressResolver`, `Secp256k1KeyAddressResolver`, `CompositeAddressResolver`).
  * Idempotent handling for repeated claims and refunds, with automatic in-flight race recovery against on-chain confirmations.

## Security Audit Status

Detailed findings for the EVM settlement rail are documented in [`tclk-rail-evm/SECURITY-FINDINGS.md`](tclk-rail-evm/SECURITY-FINDINGS.md):

* **SEC-HTLC-01 (Claim Idempotency & In-Flight Race)**: **Resolved**. Calling `claim()` on an already-claimed escrow resolves idempotently if the secret matches the hashlock. In-flight transaction failures are intercepted and rechecked against on-chain contract state.
* **SEC-HTLC-02 (Refund Idempotency & In-Flight Race)**: **Resolved**. Calling `refund()` on an already-refunded escrow converges idempotently. Reverted transactions are re-read against on-chain state to gracefully handle races with concurrent sweeps.
* **SEC-HTLC-03 (Fee-on-Transfer ERC-20 Accounting Policy)**: **Resolved / Closed (Fail-Closed by Design)**. `Htlc.sol` strictly verifies the actual balance delta:
  ```solidity
  uint256 balanceBefore = IERC20(token).balanceOf(address(this));
  _safeTransferFrom(token, msg.sender, address(this), amount);
  uint256 balanceAfter = IERC20(token).balanceOf(address(this));
  if (balanceAfter - balanceBefore != amount) revert TransferFailed();
  ```
  Deflationary or fee-on-transfer tokens revert atomically, preventing underfunded escrows. Standard ERC-20 behavior is required by design.

## Testing & Verification

All test suites and vectors pass against the current codebase:

```bash
# 1. Python unit, integration, and vector tests (91 passed)
uv run pytest

# 2. Frozen vector CLI validation (C3 vectors: OK)
uv run tc-ledger vectors

# 3. EVM Smart Contract Foundry test suite (33 passed)
cd tclk-rail-evm
$env:Path += ";$env:USERPROFILE\.foundry\bin"
forge test

# 4. TypeScript rail integration test suite (41 passed)
npm test

# 5. TypeScript build check
npm run build:ts
```

## Installation & Development Setup

### Prerequisites

* Python >= 3.12 with [uv](https://docs.astral.sh/uv/)
* Node.js >= 18 and npm
* [Foundry](https://book.getfoundry.sh/) (`forge` and `anvil`) for EVM contract tests

### Setup `tc-ledger` (Python)

```bash
git clone <repo-url>
cd tc-ledger
uv sync
uv run pytest
```

### Setup `tclk-rail-evm` (TypeScript / Solidity)

```bash
cd tclk-rail-evm
npm install
forge test
npm run build:ts
npm test
```

## Current Status & Scope Notice

* **Implementation State**: Milestones C0 through C5 and the EVM settlement rail are implemented with passing regression suites and frozen test vectors.
* **Scope Notice**: `tc-ledger` is an open-source engineering implementation. It is **not** currently deployed in production by Technocore or Flop Labs, has not undergone an external third-party security certification, and does not claim to replace existing Technocore infrastructure.

## Potential Future Integration

In a future production deployment, `tc-ledger` could integrate with Technocore workflows as an asynchronous auditing pipeline:

```text
Technocore Infrastructure
         |
         | (periodic JSONL room export snapshots)
         v
     TC-Ledger
         |
         +---> Generates deterministic evidence IDs
         +---> Produces export commitment artifacts
         +---> Calculates export Merkle roots
         +---> Generates lightweight inclusion proofs
         |
         v
Independent Verifier / Auditor
(Verifies individual records with zero server queries or full export downloads)
```
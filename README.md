# tc-ledger & TC Verify (`tclk-proof`)

**A reproducible, self-contained cryptographic evidence and cross-layer settlement verification engine for Technocore (TCLK) agreements and EVM HTLC settlement rails.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![Specification: RFC 8785 (JCS) / RFC 6962](https://img.shields.io/badge/spec-RFC%208785%20%7C%20RFC%206962-green)](#)

---

## Table of Contents

1. [Overview](#overview)
2. [Threat & Trust Model](#threat--trust-model)
3. [Architecture & Pipeline](#architecture--pipeline)
4. [Settlement Evidence Provenance Levels](#settlement-evidence-provenance-levels)
5. [CLI Usage](#cli-usage)
6. [End-to-End Local Anvil Demonstration](#end-to-end-local-anvil-demonstration)
7. [Test Results & Verification](#test-results--verification)
8. [Current Limitations & Future Roadmap](#current-limitations--future-roadmap)
9. [License](#license)

---

## Overview

Technocore (`tclk/1`) rooms enable counterparties to negotiate cryptographic financial agreements via Ed25519-signed messages (`did:key:z...`). **TC Verify** (`tclk-proof` / `tc-ledger cross-verify`) bridges signed off-chain negotiation transcripts with on-chain Hash Time-Locked Contract (HTLC) execution on EVM blockchains without third-party RPC libraries or heavy client runtimes.

TC Verify produces canonical machine-readable proof artifacts (`tclk-proof/1`) validating:
- **Transcript Authenticity**: Ed25519 signature validation and RFC 6962 Merkle tree root commitments.
- **Agreement Reconstruction**: Deterministic contract ID derivation over canonical JCS JSON (RFC 8785) offer/accept frames.
- **On-Chain Settlement Provenance**: Direct JSON-RPC receipt evaluation of `Locked`, `Claimed`, and `Refunded` events emitted by `Htlc.sol`.
- **Cross-Layer Semantic Conformance**: Exact equality checks for contract ID, asset/token, amount, SHA-256 hashlock, preimage reveal, payer/payee addresses, and temporal deadlines.

---

## Threat & Trust Model

TC Verify enforces a strict, fail-closed trust hierarchy:

```
┌────────────────────────────────────────────────────────┐
│               SETTLEMENT EVIDENCE SOURCE               │
└───────────────────────────┬────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
  Unverified Caller JSON          Active JSON-RPC Receipts
  (Filesystem / Dict Input)       (fetch_transaction_receipt)
            │                               │
            ▼                               ▼
 forced: "self_attested"         set: "rpc_receipt_verified"
            │                               │
            ▼                               ▼
 on_chain_execution_proven=False  on_chain_execution_proven=True
            │                               │
            ▼                               ▼
   is_conformant=False             is_conformant=True
  (Terminal Non-Conformant)       (Eligible for Conformant)
```

### Core Security Guarantees

1. **Unverified Caller JSON Cannot Forge On-Chain Execution**:
   - Any external `settlement.json` supplied by a user is forced to `provenance: "self_attested"`.
   - Even if the caller sets `"provenance": "rpc_receipt_verified"` in their JSON, the verifier downgrades it to `self_attested` and emits `is_conformant: false`.
2. **Mandatory Chain ID Trust Anchor**:
   - When RPC verification is requested, the caller must supply `--chain-id` (or `trust_anchors["chain_id"]`). Mismatched or omitted chain IDs fail closed immediately, preventing cross-chain replay attacks.
3. **Mandatory Lock Receipt**:
   - Evaluating a `claim_tx` or `refund_tx` requires the corresponding `lock_tx` receipt to authenticate escrow parameters (`amount`, `token`, `payer`, `payee`, `hashlock`, and `refundTimestamp`) directly from the on-chain `Locked` event log.
4. **Strict Receipt & Event Validation**:
   - Receipts must have `status == 0x1` (non-reverted).
   - Queried transaction hashes must match `receipt.transactionHash`.
   - Contract addresses and log emitters must match the expected HTLC contract.
   - Ambiguous or duplicate events fail closed.

---

## Architecture & Pipeline

```
 signed transcript (.jsonl)
           │
           ▼
 ┌───────────────────┐
 │ parse_export_lines│ ──► Verify Ed25519 signatures & RFC 6962 Merkle tree
 └─────────┬─────────┘
           │ (Reconstruct canonical AgreementState)
           ▼
 ┌───────────────────┐
 │   JSON-RPC EVM    │ ──► Fetch mined receipts: lock_tx, claim_tx, refund_tx
 │     Verifier      │ ──► Parse & validate Locked(..) / Claimed(..) events
 └─────────┬─────────┘ ──► Extract on-chain contractId, asset, amount, secret
           │
           ▼
 ┌───────────────────┐
 │verify_cross_layer │ ──► Validate semantic equality between transcript & EVM
 └─────────┬─────────┘ ──► Verify sha256(secret) == hashlock & temporal order
           │
           ▼
    proof.json (tclk-proof/1 schema conformant)
```

---

## Settlement Evidence Provenance Levels

| Provenance Level | Description | `on_chain_execution_proven` | `is_conformant` Eligible |
| :--- | :--- | :---: | :---: |
| `self_attested` | Unauthenticated JSON supplied by caller without active RPC validation. | `false` | **`false`** |
| `rpc_receipt_verified` | Verified against active EVM JSON-RPC provider (receipt status, address, logs, chain ID). | `true` | **`true`** (if terms match) |
| `cryptographic_receipt_proof` | Trustless Merkle-Patricia Trie inclusion proof against block headers *(future phase)*. | `true` | **`true`** |

---

## CLI Usage

TC Verify provides both flag-based and positional CLI entrypoints:

```bash
# Verify against live EVM JSON-RPC provider
uv run tclk-proof verify \
  --transcript transcript.jsonl \
  --rpc-url http://127.0.0.1:8545 \
  --lock-tx 0x83480e992a920825f88a38110bd5a60000cf2792fa9e312d977003ebe61cbc0f \
  --claim-tx 0x4bd4883432d7556eb8e6dca5c4971e0b59d40b8c0fd7cf9a702e259fdc0fc023 \
  --htlc-address 0x5fbdb2315678afecb367f032d93f642f64180aa3 \
  --chain-id 31337 \
  --output proof.json

# Check semantic conformance against static settlement JSON (self-attested)
uv run tclk-proof transcript.jsonl settlement.json --output proof.json

# Integrated tc-ledger subparser
uv run tc-ledger cross-verify transcript.jsonl --rpc-url http://127.0.0.1:8545 --lock-tx 0x... --claim-tx 0x... --chain-id 31337
```

---

## End-to-End Local Anvil Demonstration

Run the automated, self-contained local Anvil integration demo:

```bash
uv run python examples/e2e_tclk_proof.py
```

### Output:
```text
TCLK-PROOF E2E DEMO
===================

Transcript:
  signatures              ✓
  Merkle commitment       ✓

Agreement:
  contract ID             ✓

EVM:
  lock receipt             ✓
  claim receipt            ✓
  contract binding         ✓
  hashlock binding         ✓
  amount binding           ✓
  asset binding            ✓
  secret verification      ✓
  temporal ordering        ✓
  chain ID                 ✓

Result:
  CONFORMANT ✓
```

Canonical proof artifacts are generated at `examples/output/proof.json`.

---

## Test Results & Verification

### Test Suites

1. **Python Cross-Verification, EVM Verifier & Live Anvil Suite**:
   ```bash
   uv run pytest tests/test_cross_verify.py tests/test_evm_verifier.py tests/test_e2e_tclk_proof.py -v
   ```
   `50 passed in 11.24s`

2. **Full Repository Python Suite**:
   ```bash
   uv run pytest -q -k "not TestLiveIntegration and not test_known_live_did_activity and not test_stale_activity_window_semantics"
   ```
   `260 passed, 11 deselected in 19.14s`

3. **EVM Settlement Rail TypeScript / Vitest Suite**:
   ```bash
   cd tclk-rail-evm && npx vitest run
   ```
   `8 test files passed, 140 tests passed in 97.84s`

---

## Current Limitations & Future Roadmap

1. **RPC Provider Trust Anchor**:
   - `rpc_receipt_verified` establishes that a given EVM JSON-RPC provider returned valid, mined transaction receipts matching the HTLC contract address, non-reverted status (`0x1`), expected topics, and chain ID.
   - It assumes the connected JSON-RPC endpoint is non-adversarial.
2. **Future Phase — Cryptographic Block Header Inclusion (`cryptographic_receipt_proof`)**:
   - Future extensions will add standalone Merkle-Patricia Trie inclusion proofs against Ethereum block headers, eliminating RPC provider trust completely.
3. **DID-to-Ethereum Address Binding**:
   - When agreements omit secp256k1 `paymentKey` fields, DID-to-address bindings emit non-blocking `unverified_external_mapping` warnings while verifying semantic terms conformance and on-chain execution.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

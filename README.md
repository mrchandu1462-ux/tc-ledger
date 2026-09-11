# tc-ledger

**A reproducible, self-contained evidence verification layer and explorer for Technocore room exports.**

[![CI](https://github.com/mrchandu1462-ux/tc-ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/mrchandu1462-ux/tc-ledger/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)

Technocore servers retain and emit raw JSONL exports of room conversations containing Ed25519-signed messages from decentralized identifiers (`did:key:z...`). However, consumers and counterparties need a way to verify the authenticity of signed records, commit to exact export contents, prove that individual records are included in an export, and verify those proofs offline without network access or downloading full exports.

tc-ledger bridges this gap by turning signed JSONL exports into deterministic cryptographic commitments, Merkle completeness trees, self-contained inclusion and consistency proofs, and providing a public Explorer for discovery and client-side cryptographic inspection.

---

## Project Independence & Disclaimer

> [!NOTE]
> **Independent Project**: TC-Ledger is an independent, open-source project and is **not affiliated with, endorsed by, or sponsored by Technocore or Flop Labs**.
>
> All live network interactions are strictly **read-only** against publicly accessible HTTP endpoints. TC-Ledger does not post messages, issue write requests, generate server rooms, publish DIDs, or require API credentials.

---

## Critical Trust Boundary & Retention Limits

> [!IMPORTANT]
> **What TC-Ledger Proves vs. Server Retention:**
> 1. **Exact Retained Export Bytes**: TC-Ledger proves the exact physical bytes of exports supplied to it. It does **not** prove complete lifetime room history, nor does it recover deleted or evicted history.
> 2. **Append-Only Consistency Proofs (C7)**: A consistency proof proves that a later committed export tree contains the earlier tree as its **exact, unaltered prefix**. C7 guarantees append-only progression of retained logs.
> 3. **Retention and Eviction Failure**: If a Technocore server evicts or prunes older messages under retention limits before generating a later export, the prefix relationship is broken. In this case, consistency verification **will and must FAIL** rather than falsely asserting continuity.
> 4. **No "Tamper-Proof" Claims**: Mathematical commitments detect tampering; they do not physically prevent modification or deletion of untrusted server storage.
> 5. **No Trusted Timestamping**: Timestamps inside record payloads (`ts`) are self-reported by authors or servers. TC-Ledger verifies signature integrity over the payload string, but makes no claim of trusted third-party timestamping or monotonic time enforcement.
> 6. **No Server Provenance Claims**: Technocore exports currently lack server-side signatures. TC-Ledger proves author Ed25519 signatures and exact byte commitments, but does not attest to server origin.
> 7. **Live Verification Depends on Trusted Inputs**: Live discovery and indexer results reflect only the specific public rooms and export streams inspected at query time.
> 8. **Durable Preservation Required**: TC-Ledger verifies mathematical commitments; it does not store history. Retained export files and trust anchors must be durably preserved by an archiver or participant for subsequent verification.
> 9. **Metadata Envelope Trust Boundaries**: Artifact metadata fields (`room`, `old_generation`, `new_generation`, `old_tree_size`, `new_tree_size`) are self-attested envelope properties. Cryptographic authentication requires validating them against caller-specified trust anchors (`--expected-*`).

---

## TC-Ledger Explorer & Live Discovery

The **TC-Ledger Explorer** provides an interactive interface for discovering retained public activity for decentralized identifiers (`did:key:z...`), inspecting retained messages, and performing client-side Ed25519 verification.

* **Live Deployed Explorer**: [https://mrchandu1462-ux.github.io/tc-ledger/explorer.html](https://mrchandu1462-ux.github.io/tc-ledger/explorer.html)
* **Showcase Site**: [https://mrchandu1462-ux.github.io/tc-ledger/](https://mrchandu1462-ux.github.io/tc-ledger/)

### Operating Modes

1. **Live Technocore Mode**: Queries live, publicly readable Technocore room export streams (such as `#tclk-offers` and `#lobby`) directly in the browser via CORS or through a local read-only indexer adapter. Every record signature is cryptographically verified on the client using WebCrypto / Ed25519.
2. **Synthetic Demo Mode**: Provides an offline, isolated sandbox demonstrating active (`Bob`), stale (`Alice`), and nonexistent identity states using fixed synthetic fixtures without making network calls.

### Activity Status Semantics

The Explorer uses strict, honest activity indicators:
* **ACTIVE**: Recent cryptographically verified activity was observed within the analysis window (e.g. past 24 hours). **This indicates verified activity only; it does NOT imply online presence, active sockets, or heartbeat availability.**
* **STALE**: Verified activity was observed historically for this DID, but falls outside the recent activity window. **This indicates elapsed time since last verified message; it does NOT mean the agent is offline.**
* **NO DATA FOUND**: No verified activity for the DID was observed in currently inspected public retained streams. **This indicates absence of data in the inspected dataset; it does NOT mean the DID does not exist.**

**Zero Silent Fallback**: Live query failures, unreachable rooms, or unobserved DIDs never silently fall back to synthetic demo data.

---

## Architecture Overview

```text
               +--------------------------------------------------+
               |            Public Technocore Endpoints           |
               |  GET /r/<room>/export | GET /r/<room>?format=json|
               +--------------------------------------------------+
                                        | (Read-Only HTTP / CORS)
                                        v
     +-----------------------------------------------------------------------+
     |                       Discovery & Presentation                        |
     |                                                                       |
     |   +--------------------------+      +-----------------------------+   |
     |   |   Live Indexer CLI       |      |    TC-Ledger Explorer       |   |
     |   | (tools/tc_live_indexer)  |      |   (site/explorer.html/.js)  |   |
     |   +--------------------------+      +-----------------------------+   |
     |                 |                                  |                  |
     |                 +--------------+    +--------------+                  |
     |                                |    |                                 |
     |                                v    v                                 |
     |              Client-Side Ed25519 Signature Verification               |
     |              (RFC 8785 JCS payload: room|nonce|text)                  |
     +-----------------------------------------------------------------------+
                                        |
                                        v
     +-----------------------------------------------------------------------+
     |                   Frozen Cryptographic Core (v0.3.1)                  |
     |                                                                       |
     |       Record Verification (Ed25519, did:key multicodec 0xed01)        |
     |                                  |                                    |
     |            RFC 8785 JCS Deterministic Evidence Commitment             |
     |                                  |                                    |
     |               Byte-Exact Physical Export Line Hashing                 |
     |                                  |                                    |
     |             RFC 6962 Merkle Tree Roots (0x00 / 0x01)                  |
     |                                  |                                    |
     |          Export Inclusion Proofs (v1) & Leaf Audit Paths              |
     |                                  |                                    |
     |         Cross-Generation Append-Only Consistency Proofs (C7)          |
     |                                  |                                    |
     |        Self-Contained Offline Verifier & Smart Contract Anchors       |
     +-----------------------------------------------------------------------+
```

---

## Read-Only Live Indexer CLI & Local Adapter

TC-Ledger provides read-only command-line tools for discovering and indexing public Technocore activity.

### Running the Live Indexer CLI

```bash
# Discover activity for a DID across seed rooms
uv run python tools/tc_live_indexer.py --did did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z

# Discover activity across specific rooms with a custom activity window
uv run python tools/tc_live_indexer.py \
  --did did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z \
  --rooms tclk-offers,lobby \
  --window-hours 48.0

# Output machine-readable JSON report or save artifact
uv run python tools/tc_live_indexer.py \
  --did did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z \
  --json \
  --output live_index.json
```

### Running the Local Indexer Server

The optional local adapter server runs on `http://127.0.0.1:8088` and provides a read-only CORS proxy for full room enumeration:

```bash
# Start local read-only adapter
uv run python tools/tc_indexer_server.py --port 8088
```

---

## Machine-Readable CLI Contract

tc-ledger provides a stable CLI contract with machine-readable `--json` output and standardized process exit codes.

### Process Exit Codes

* 0: **Success / Valid** (Verification passed, operation succeeded)
* 1: **Verification Failure** (Cryptographic verification failed, invalid evidence or proof)
* 2: **Usage Error** (Invalid syntax or missing required mutual flags)
* 3: **I/O / Runtime Error** (File not found, parse failure, runtime data error)

### CLI Reference

```bash
# 1. Verify signatures across an export
tc-ledger verify <path.jsonl> --room <room> [--json]

# 2. Commit export bytes and bind generation epoch
tc-ledger commit <path.jsonl> --room <room> [--generation <int>] [--output <commitment.json>] [--json]

# 3. Validate frozen test vectors
tc-ledger vectors [--json]

# 4. Generate inclusion proof for a leaf
tc-ledger prove <path.jsonl> --room <room> --leaf-index <int> [--generation <int>] [--output <proof.json>] [--json]

# 5. Verify inclusion proof offline
tc-ledger verify-proof <proof.json> --record <record.bin> --expected-root <hex> --expected-room <room> [--expected-generation <int>] [--json]

# 6. Verify and re-derive commitment artifact
tc-ledger verify-artifact <path.jsonl> <commitment.json> --expected-root <hex> --expected-room <room> [--expected-generation <int>] [--json]

# 7. Generate cross-generation consistency proof
tc-ledger consistency-proof <old-export.jsonl> <new-export.jsonl> --room <room> --old-generation <int> --new-generation <int> [--output <proof.json>] [--json]

# 8. Verify cross-generation consistency proof
tc-ledger verify-consistency <consistency_proof.json> [--expected-room <room>] [--expected-old-generation <int>] [--expected-new-generation <int>] [--expected-old-root <hex>] [--expected-new-root <hex>] [--expected-old-tree-size <int>] [--expected-new-tree-size <int>] [--json]
```

Full CLI documentation is available in [docs/cli-contract-v1.md](docs/cli-contract-v1.md).

---

## Reproducible Example Walkthrough

A fully reproducible, read-only demonstration is provided in [examples/](examples):

```bash
# Run the automated end-to-end demo (executes read-only without modifying repo)
uv run python examples/demo.py
```

### Manual Verification Flow

```bash
# 1. Verify signatures in the synthetic export
uv run tc-ledger verify examples/synthetic_export.jsonl --room demo-room

# 2. Re-derive and verify the commitment artifact
uv run tc-ledger verify-artifact examples/synthetic_export.jsonl examples/commitment.json \
  --expected-room demo-room \
  --expected-root 0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9 \
  --expected-generation 1

# 3. Verify the inclusion proof offline against raw record bytes
uv run tc-ledger verify-proof examples/proof_leaf1.json \
  --record examples/record_1.bin \
  --expected-root 0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9 \
  --expected-room demo-room \
  --expected-generation 1

# 4. Verify cross-generation consistency proof
uv run tc-ledger verify-consistency examples/consistency_proof.json \
  --expected-room demo-room \
  --expected-old-generation 1 \
  --expected-new-generation 2 \
  --expected-old-root 0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9 \
  --expected-old-tree-size 4 \
  --expected-new-tree-size 7
```

---

## JSON Schemas & Conformance Vectors

* **Schemas**: Formal JSON Schemas are maintained in [schemas/](schemas):
  * `schemas/export-commitment-v1.schema.json`
  * `schemas/inclusion-proof-v1.schema.json`
  * `schemas/consistency-proof-v1.schema.json`
  * `schemas/evidence-v1.schema.json`
* **Conformance Vectors**: Comprehensive test vectors are located in `vectors/vectors.json` and `vectors/conformance.json`.

---

## Testing & Verification

All test suites and vectors pass against the codebase:

```bash
# 1. Python unit, integration, and conformance tests (205 passed)
uv run pytest tests/

# 2. Live Technocore indexer test suite (9 passed)
uv run pytest tools/test_tc_live_indexer.py

# 3. Frozen vector CLI validation (C3 vectors: OK)
uv run tc-ledger vectors
uv run tc-ledger vectors --json

# 4. EVM Smart Contract Foundry test suite (33 passed)
cd tclk-rail-evm && forge test

# 5. TypeScript rail integration test suite (140 passed across 8 suites)
cd tclk-rail-evm && npm test
```

---

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).

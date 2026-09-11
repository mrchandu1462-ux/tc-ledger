# Security Policy

## Scope and Core Cryptographic Model

tc-ledger provides an offline evidence and verification pipeline for Technocore room exports.

### Trust Boundaries and Verification Guarantees

#### 1. Author Signature Verification (C0)
* **Signature Authenticity**: Ed25519 signatures from `did:key:z6Mk...` authors are verified against the exact canonical payload:
  `room|nonce|text`
* **Delimiter Security**: Room identifiers must not contain the pipe delimiter `|`. TC-Ledger rejects records or rooms containing `|` to prevent payload injection or field confusion.
* **Strict Base64URL Decoding**: Signatures must be strictly canonical 86-character Base64URL encodings without rogue characters, malformed padding, or non-zero unused bits. Malleable encodings are rejected fail-closed.
* **Nonce Handling**: Technocore author signatures treat integer nonces (e.g. `1001`) and digit string nonces (e.g. `"1001"`) equivalently on the wire payload `room|nonce|text`. However, RFC 8785 JSON Canonicalization Scheme (JCS) strictly preserves JSON types, producing distinct C1 evidence identifiers (`tc-ledger:v1:...`).

#### 2. Raw Export Byte Commitments (C2–C6)
* **Byte-Exact Commitment**: The RFC 6962-compliant Merkle root commits to the exact physical byte stream of the exported JSONL lines (including exact whitespace and line delimiters).
* **JCS vs. Raw Export Bytes**: While C1 evidence IDs commit to semantic canonical JSON of individual records, C2–C7 commitments bind the exact raw wire bytes. Any re-serialization, JSON key reordering, formatting changes, or line-ending mutations (CRLF vs. LF) alters the raw bytes and invalidates the Merkle root.
* **Inclusion Proofs**: An independent verifier can prove that an individual physical line is included within a committed export without requiring the full export.

#### 3. Cross-Generation Consistency Proofs (C7)
* **Append-Only Prefix Continuity**: Given trusted Merkle root $R_m$ of export generation $m$ (size $m$) and trusted Merkle root $R_n$ of export generation $n$ (size $n$, where $n \ge m$), an RFC 6962 consistency proof proves that the first $m$ leaves of generation $n$ are identical byte-for-byte to generation $m$.
* **Retention and Eviction Failure Mode**: A consistency proof requires the later committed tree to contain the earlier tree as its exact prefix. If a Technocore server prunes or evicts older messages under retention limits before generating export $n$, the prefix relationship is broken. The consistency proof will and MUST FAIL.
* **Artifact Metadata Trust Boundaries**: The artifact envelope fields (`room`, `old_generation`, `new_generation`, `old_tree_size`, `new_tree_size`) are self-attested envelope metadata. The Merkle root commits to physical export lines, not the metadata envelope. Full cryptographic assurance requires the verifier to validate these fields against external trust anchors (`--expected-room`, `--expected-old-generation`, `--expected-new-generation`, `--expected-old-root`, `--expected-new-root`, `--expected-old-tree-size`, `--expected-new-tree-size`).
* **Tree Size Authentication**: A claimed `new_tree_size` or `old_tree_size` in the artifact is NOT authenticated merely because it is present in the JSON artifact. Verifiers only mark `tree_sizes_authenticated: true` when both sizes match caller-supplied external expectations.

### What TC-Ledger Does NOT Prove
* **Complete Lifetime History**: TC-Ledger proves only the exact retained export bytes supplied to it. It does not prove complete room history across server restarts or rolling log evictions, and it cannot recover deleted history.
* **Root Publication Authenticity**: TC-Ledger verifies mathematical consistency between roots. The caller or downstream system must anchor roots to trusted publications (such as signed checkpoints or smart contracts).
* **Data Availability**: TC-Ledger verifies commitments and proofs; it does not store historical data. An archiver or counterparty must durably retain export artifacts for future auditability.

## Reporting a Vulnerability

If you discover a security vulnerability in tc-ledger, please report it privately:

1. Open a private security advisory on GitHub:
   https://github.com/mrchandu1462-ux/tc-ledger/security/advisories/new
2. Or contact the maintainer via email:
   btech21279@gmail.com

Please provide:
- A description of the issue.
- Minimal reproducible test vectors or proof-of-concept steps.
- Any potential impact on evidence integrity.

We appreciate responsible disclosure and will respond promptly to security reports.

# Security Policy

## Scope and Core Cryptographic Model

	c-ledger provides an offline evidence and verification pipeline for Technocore room exports.

### What TC-Ledger Proves
### 4. Cross-Generation Cryptographic Consistency Proofs (C7)
- **Append-Only Extension**: Given trusted Merkle root $R_m$ of export generation $m$ (size $m$) and trusted Merkle root $R_n$ of export generation $n$ (size $n$, $n \ge m$), an RFC 6962-compliant consistency proof cryptographically proves that the first $m$ leaves of generation $n$ are identical byte-for-byte to generation $m$.
- **Room and Generation Binding**: C7 consistency proof artifacts bind the room, old generation, new generation, old tree size, new tree size, old root, and new root together. Verifiers reject artifacts with mismatched rooms, inverted generations, or mismatched roots.
- **Fail-Closed Verification**: Any altered proof node, truncated path, extraneous node, or modified root causes verification to fail with exit code 1.

### What TC-Ledger Does NOT Prove
- **Complete Lifetime History**: Technocore servers can prune historical records or rolling buffers. A consistency proof proves continuity between two specific committed export snapshots; it does not prove that the server never pruned earlier uncommitted records.
- **Root Publication Authenticity**: TC-Ledger verifies consistency between two given roots. It relies on the verifier (or upstream trust anchors such as signed commitment headers or on-chain anchors) to provide authentic roots.
- **Absence of Server-Side Selective Omission**: Consistency proofs only prove that an existing committed tree is a prefix of a later committed tree.

1. **Cryptographic Authenticity of Records**:
   Ed25519 signatures from did:key:z... authors are verified against the exact canonical payload:

oom|nonce|text
2. **Exact Export Byte Commitments**:
   An RFC 6962-compliant Merkle tree commits to the exact physical lines of the export file as observed.
3. **Inclusion Proofs**:
   A recipient can independently verify that a specific record was present in the committed export without network access or access to the rest of the export.

### Security Boundaries and Trust Assumptions
- **Retained Export vs Full History**:
  	c-ledger proves the exact retained export bytes supplied to it. It does **not** prove complete lifetime room history or prevent server-side pruning prior to export.
- **Server-Attested Metadata**:
  The seq (sequence number) and 	s (receipt timestamp) are server-attested metadata. They are covered by the evidence commitment hash (	c-ledger:v1:...) but are not signed by the individual author's Ed25519 key.
- **Fail-Closed Verification**:
  Any byte modification, invalid signature, corrupted proof, or mismatched room/root/generation causes verification to fail closed.

## Reporting a Vulnerability

If you discover a security vulnerability in 	c-ledger, please report it privately:

1. Open a private security advisory on GitHub:
   https://github.com/mrchandu1462-ux/tc-ledger/security/advisories/new
2. Or contact the maintainer via email:
   btech21279@gmail.com

Please provide:
- A description of the issue.
- Minimal reproducible test vectors or proof-of-concept steps.
- Any potential impact on evidence integrity.

We appreciate responsible disclosure and will respond promptly to security reports.

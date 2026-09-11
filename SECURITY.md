# Security Policy

## Scope and Core Cryptographic Model

	c-ledger provides an offline evidence and verification pipeline for Technocore room exports.

### What TC-Ledger Proves
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

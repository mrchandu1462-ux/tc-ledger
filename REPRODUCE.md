# TC-Ledger & TC Verify: Reproducibility & Verification Guide

This document maps every public engineering metric and claim to the exact command and test suite that reproduces it.

## 1. Automated Test Suites & Engineering Metrics

All test suites run in clean environments with zero external network dependencies (network calls are mocked or run against local test adapters).

| Test Suite | Scope | Command | Expected Result |
| :--- | :--- | :--- | :--- |
| **Core Protocol & Cryptography** | RFC 6962 Merkle trees, JCS (RFC 8785), C7 consistency proofs, inclusion proofs, evidence formats, EVM rail compatibility | `uv run pytest tests/` | **205 passed** |
| **Live Indexer Core** | Room pagination, generation tracking, export retrieval, record parsing, rate limits | `uv run pytest tools/test_tc_live_indexer.py` | **9 passed** |
| **Local Adapter Hardening** | CORS allowlist, parameter clamping, bounded cache, SSRF protection, path validation | `uv run pytest tests/test_adapter_hardening.py` | **7 passed** |
| **Browser Explorer Hardening** | B-1 (fail-closed WebCrypto), B-2 (strict self-verification), B-3 (DOM XSS inertness), live semantics, proof download gating | `node --test tests/test_explorer_hardening.mjs` | **All assertions pass** |
| **Syntax Verification** | Frontend JavaScript syntax correctness | `node --check site/explorer.js`<br>`node --check site/app.js` | **Clean exit (0)** |

### Running the Complete Test Suite

```bash
# Run all Python tests (221 tests total)
uv run pytest tests/ tools/test_tc_live_indexer.py

# Run browser verifier hardening tests
node --test tests/test_explorer_hardening.mjs

# Syntax check site JavaScript
node --check site/explorer.js
node --check site/app.js
```

---

## 2. Cryptographic & Protocol Conventions

### Leaf-Byte Convention (Raw Export Verification)
TC-Ledger v0.4.0 commits to line-delimited JSON (NDJSON) exports using exact physical byte sequences:
1. **Raw Byte Exactness**: Each line is hashed exactly as captured in the byte stream without decoding or normalisation.
2. **Line Terminators**:
   - Lines ending in LF (`0x0A`) include `0x0A` in their leaf hash input.
   - Lines ending in CRLF (`0x0D 0x0A`) include both `0x0D 0x0A` in their leaf hash input.
   - The final line without a trailing terminator includes only its raw bytes.
3. **Blank Lines**: A blank physical line (e.g. `\n`) is treated as a valid export leaf whose input is the terminator byte(s).
4. **Malformed Lines**: Unparseable or malformed lines are preserved as leaves using their exact raw bytes to ensure completeness commitments cannot be forged by omitting corrupted lines.
5. **RFC 6962 Domain Separation**:
   - Leaf Hash: `SHA-256(0x00 || raw_line_bytes)`
   - Node Hash: `SHA-256(0x01 || left_hash || right_hash)`

---

## 3. Browser Verifier & WebCrypto Support

The TC Verify Explorer implements strict, fail-closed verification semantics in client-side JavaScript:
1. **WebCrypto Ed25519 Requirement**: Signature verification requires browser support for the standard WebCrypto API (`crypto.subtle.verify` with algorithm `{ name: "Ed25519" }`).
2. **Fail-Closed Guarantee**:
   - If WebCrypto Ed25519 is unavailable or unsupported by the browser, verification **fails closed** and returns `valid: false` with the explicit diagnostic: `"Ed25519 verification unavailable in this browser."`.
   - Structural regex matching (such as matching an 86-character base64url string) is **never** treated as cryptographic validity.
   - DIDs with unverified signatures are never marked `ACTIVE`.
3. **Self-Verification / Inclusion Proofs**:
   - Self-verification requires an explicit, non-empty trusted Merkle root.
   - Missing leaf hash, missing index, missing tree size, or empty/fabricated audit paths result in `"NO VERDICT: Invalid Input"` or `"INVALID"`.
   - A verdict of `"VALID"` is emitted **only** if the calculated Merkle root exactly matches the trusted root.

---

## 4. Live Discovery Scope & Trust Boundaries

1. **Discovery Scope**:
   - In browser-direct mode, discovery is bounded to currently retained public rooms (`#tclk-offers`, `#lobby`).
   - Private, unlisted, or evicted rooms are not discoverable.
   - A `NO DATA FOUND` verdict means no matching retained activity was found in the inspected rooms; it does not prove the DID does not exist.
2. **Direct Browser Request Disclosure**:
   - Live browser mode contacts Technocore endpoints directly from the client browser. TC Verify does not proxy, intercept, or modify these requests.
3. **Independence**:
   - TC Verify and TC-Ledger are independent open-source projects not affiliated with Technocore or Flop Labs.

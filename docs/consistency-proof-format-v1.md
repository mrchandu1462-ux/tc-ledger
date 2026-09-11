# TC-Ledger Consistency Proof Format Specification v1

**Profile**: `tc-ledger/1`
**Schema**: `tc-ledger/consistency-proof/v1`
**Standard Reference**: RFC 6962 §2.1.2 (Merkle Consistency Proofs)
**Status**: Normative Specification (C7 Protocol Layer)

---

## 1. Overview and Purpose

In TC-Ledger Single-Generation commitments (C0–C6), an export commitment binds the exact byte sequence of an export file to a Merkle root for a given epoch (`export_generation`).

While single-generation commitments enable offline verification that a specific record was present in that export, they do not inherently prove continuity across export generations. A malicious or confused service could publish divergent exports across generations (e.g. silently deleting or rewriting past records in generation $G_{N+1}$).

**C7 Cross-Generation Consistency** upgrades `export_generation` from an administrative trust anchor into a cryptographically verifiable append-only continuity mechanism. Using Merkle consistency proofs, a verifier holding a trusted earlier root $R_m$ at generation $G_m$ and a newly observed root $R_n$ at generation $G_n$ can verify that:

$$\\text{Export } m \\text{ is an exact prefix of Export } n$$

without trusting third-party statements and without downloading or storing the full historical export $m$.

---

## 2. Terminology and Data Model

* **Old Tree Size ($m$)**: Non-negative integer representing the physical line (leaf) count of the earlier export ($G_m$).
* **New Tree Size ($n$)**: Non-negative integer representing the physical line (leaf) count of the later export ($G_n$), where $n \\ge m$.
* **Old Root ($R_m$)**: 32-byte hex-encoded SHA-256 Merkle root of the earlier export.
* **New Root ($R_n$)**: 32-byte hex-encoded SHA-256 Merkle root of the later export.
* **Old Generation ($G_m$)**: Integer epoch counter of the earlier export.
* **New Generation ($G_n$)**: Integer epoch counter of the later export ($G_n \\ge G_m$).
* **Room**: Canonical string identifier of the Technocore room.
* **Audit Path / Consistency Proof ($P$)**: Ordered list of 32-byte SHA-256 node hashes required to reconstruct $R_m$ and verify that $R_m$'s subtrees form the exact left prefix of $R_n$.

---

## 3. Merkle Tree Byte Model & Mathematical Equivalence

TC-Ledger uses the RFC 6962 byte model with strict domain separation:

* **Leaf Hash**:
  $$\\text{Leaf}(D) = \\text{SHA-256}(0\\text{x}00 \\mathbin{\\Vert} D)$$
  where $D$ is the exact raw byte sequence of the physical export line (including its newline delimiter).
* **Node Hash**:
  $$\\text{Node}(L, R) = \\text{SHA-256}(0\\text{x}01 \\mathbin{\\Vert} L \\mathbin{\\Vert} R)$$
  where $L$ and $R$ are 32-byte child hashes.

### Odd-Node Promotion Equivalence
TC-Ledger constructs levels bottom-up by pairing adjacent nodes and promoting any unpaired odd node directly to the next level without hashing or duplication.

Mathematically, this bottom-up binary promotion structure is **identical** to RFC 6962's top-down recursive Merkle Tree Hash ($MTH$) definition split at the largest power of 2 less than $n$ ($k = 2^{\\lfloor \\log_2(n-1) \\rfloor}$). Because both constructions yield identical roots for all $n \\ge 1$, standard RFC 6962 consistency proofs apply directly without modification to TC-Ledger's tree architecture.

---

## 4. Consistency Proof Generation Algorithm

Given an ordered list of leaf byte sequences $D[0..n-1]$ and a prefix size $m \\le n$:

### Subproof Algorithm (`subproof(m, D[0..n-1], b)`)
1. If $m = n$:
   * If $b = \\text{true}$, return `[]` (empty list).
   * If $b = \\text{false}$, return `[ MTH(D[0..n-1]) ]`.
2. Let $k = 2^{\\lfloor \\log_2(n-1) \\rfloor}$ (largest power of 2 strictly less than $n$).
3. If $m \\le k$:
   * Return $\\text{subproof}(m, D[0..k-1], b) \\mathbin{\\Vert} [ \\text{MTH}(D[k..n-1]) ]$.
4. If $m > k$:
   * Return $\\text{subproof}(m - k, D[k..n-1], \\text{false}) \\mathbin{\\Vert} [ \\text{MTH}(D[0..k-1]) ]$.

### Proof Algorithm (`proof(m, D[0..n-1])`)
1. If $m = n$ or $m = 0$:
   * Return `[]`.
2. Let $k = 2^{\\lfloor \\log_2(n-1) \\rfloor}$.
3. If $m \\le k$:
   * Return $\\text{subproof}(m, D[0..k-1], \\text{true}) \\mathbin{\\Vert} [ \\text{MTH}(D[k..n-1]) ]$.
4. If $m > k$:
   * Return $\\text{subproof}(m - k, D[k..n-1], \\text{false}) \\mathbin{\\Vert} [ \\text{MTH}(D[0..k-1]) ]$.

---

## 5. Consistency Proof Verification Algorithm

Given $m$, $n$, $R_m$, $R_n$, and proof path $P = [p_0, p_1, \\dots, p_{k-1}]$:

1. **Size Validation**:
   * If $m > n$ or $m < 0$ or $n < 0$, reject as INVALID.
   * If $m = n$:
     * Valid if and only if $P = []$ and $R_m = R_n$.
   * If $m = 0$:
     * Valid if and only if $P = []$ and $R_m = \\text{SHA-256}(\"\").
   * If $m > 0$ and $P = []$, reject as INVALID.

2. **Initialization**:
   * If $m$ is a power of 2 (i.e. $m \\mathbin{\\&} (m - 1) = 0$):
     * Set $f_n = R_m$, $s_n = R_m$, and start index $idx = 0$.
   * Else:
     * Set $f_n = p_0$, $s_n = p_0$, and start index $idx = 1$.
   * Let $fn\\_idx = m - 1$ and $sn\\_idx = n - 1$.
   * While $fn\\_idx \\pmod 2 = 1$:
     * $fn\\_idx \\leftarrow \\lfloor fn\\_idx / 2 \\rfloor$
     * $sn\\_idx \\leftarrow \\lfloor sn\\_idx / 2 \\rfloor$

3. **Path Traversal**:
   * For each node $p$ in $P[idx..]$:
     * If $sn\\_idx = 0$, reject as INVALID (extraneous proof node).
     * If $fn\\_idx \\pmod 2 = 1$ or $fn\\_idx = sn\\_idx$:
       * $f_n \\leftarrow \\text{Node}(p, f_n)$
       * $s_n \\leftarrow \\text{Node}(p, s_n)$
       * While $fn\\_idx \\pmod 2 = 0$ and $fn\\_idx \\ne 0$:
         * $fn\\_idx \\leftarrow \\lfloor fn\\_idx / 2 \\rfloor$
         * $sn\\_idx \\leftarrow \\lfloor sn\\_idx / 2 \\rfloor$
     * Else:
       * $s_n \\leftarrow \\text{Node}(s_n, p)$
     * $fn\\_idx \\leftarrow \\lfloor fn\\_idx / 2 \\rfloor$
     * $sn\\_idx \\leftarrow \\lfloor sn\\_idx / 2 \\rfloor$

4. **Root Comparison**:
   * Verification succeeds if and only if:
     $$f_n = R_m \\quad \\text{AND} \\quad s_n = R_n \\quad \\text{AND} \\quad sn\\_idx = 0$$

---

## 6. Normative JSON Artifact Format

The C7 proof artifact is serialized as canonical JSON:

```json
{
  "schema": "tc-ledger/consistency-proof/v1",
  "version": 1,
  "profile": "tc-ledger/1",
  "room": "demo-room",
  "old_generation": 1,
  "new_generation": 2,
  "old_tree_size": 4,
  "new_tree_size": 7,
  "old_root": "0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9",
  "new_root": "a24fa68a2d1d0ee1c741eef554625b187515f45ea0f05809bb45e317c093630f",
  "proof": [
    "5fec67c43336306541604a8449c7f694676643ad1e4f454a85a4a51e6d97c729",
    "60ad2c0eddd6fc52e505886653df32c25ae9e07fb8d89e504b7321e25e1a141b"
  ]
}
```

---

## 7. Security Boundaries and Trust Assumptions

1. **Append-Only Consistency Requirement**:
   A valid consistency proof proves strictly that the leaves of export $m$ appear in the identical position and with the identical byte content in export $n$ (i.e. export $m$ is an exact prefix of export $n$).

2. **Retention and Eviction Failure Mode**:
   A consistency proof requires the later committed tree to contain the earlier tree as its required prefix. If a Technocore server evicts, prunes, or rolls older records under storage retention policies prior to emitting export $n$, that prefix relationship is broken. If older records have been evicted, consistency verification **will and must FAIL** rather than falsely asserting continuity. TC-Ledger does not recover deleted history, nor does it prove complete lifetime room history.

3. **Artifact Metadata Trust Boundaries (F-1 & F-2)**:
   The JSON artifact fields (`room`, `old_generation`, `new_generation`, `old_tree_size`, `new_tree_size`) are self-attested envelope metadata. The Merkle root commits to physical export lines, not the metadata envelope.
   - A claimed `new_tree_size` or `old_tree_size` is **not authenticated** merely because it is present in the artifact.
   - An independent verifier must supply expected trust anchors (`--expected-room`, `--expected-old-generation`, `--expected-new-generation`, `--expected-old-root`, `--expected-new-root`, `--expected-old-tree-size`, `--expected-new-tree-size`).
   - The verifier returns `"tree_sizes_authenticated": true` **only** when both tree sizes have been explicitly checked against caller-provided expectations.

4. **Durable Preservation Required**:
   TC-Ledger verifies mathematical commitments; it does not provide distributed consensus or durable storage. Retained export files and trust anchors must be durably preserved by an archiver or participant for subsequent verification.

---

## 8. Relationship Between C1 (JCS) and C2–C7 (Raw Export Bytes)

TC-Ledger maintains a strict architectural separation between individual record evidence IDs (C1) and export-level Merkle commitments (C2–C7):

* **C1 Semantic Normalization (RFC 8785 JCS)**:
  Evidence IDs (`tc-ledger:v1:<sha256>`) commit to the *semantic canonical JSON* of individual records. RFC 8785 normalizes whitespace, escapes, and key order so that equivalent JSON payloads produce the identical evidence ID. Furthermore, RFC 8785 strictly preserves data types: an integer nonce `1001` and a string nonce `"1001"` yield distinct evidence IDs.
* **C2–C7 Physical Wire Commitment (Exact Raw Bytes)**:
  Merkle roots commit to the *exact physical byte stream* of the exported lines (`SHA-256(0x00 || raw_line_bytes)`).
* **Why Raw-Byte Commitment Exists**:
  Raw-byte commitment ensures bit-for-bit auditability of what was transferred across the wire or archived to cold storage. It eliminates any ambiguity from JSON parser float rounding, escape discrepancies, or serializer re-ordering.
* **Consequence of Serializer / Line-Ending Changes**:
  Any modification to line delimiters (e.g. converting LF `\n` to CRLF `\r\n`), blank lines, or pretty-printing whitespace changes the physical bytes of the leaf and invalidates the C2–C7 Merkle root and all consistency proofs.

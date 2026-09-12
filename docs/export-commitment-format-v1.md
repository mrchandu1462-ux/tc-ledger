# tc-ledger Export Commitment Format v1

## Status

Draft specification for the `tc-ledger` export completeness commitment format.

## 1. Scope

This format commits to the complete captured JSONL export as observed.

The export commitment preserves two separate properties:

1. Completeness: every retained physical export line is committed in source order.
2. Validity: records that parse and contain valid Technocore signatures may additionally have
   `tc-ledger:v1:` evidence identifiers.

The export commitment does not replace the original export.

## 2. Source Representation

The source of truth for the completeness tree is the captured export byte stream.

No JSON reserialization is performed before hashing.

No Unicode normalization is performed.

No whitespace normalization is performed.

Each physical JSONL line is treated as raw bytes exactly as captured.

## 3. Line Boundaries

A line terminator is part of the raw byte representation when it is present in the captured export.

Therefore:

- a line ending in `LF` includes the `0x0a` byte in its leaf input;
- a line ending in `CRLF` includes both `0x0d 0x0a` bytes in its leaf input;
- a final line without a terminator is committed without an added terminator.

The implementation MUST NOT invent a line terminator that was not present in the source.

The implementation MUST NOT remove a line terminator that was present in the source.

## 4. Blank Lines

Blank physical lines are retained and committed when present in the captured export.

A blank line is therefore a real export leaf whose raw byte input is its captured line-terminator representation.

Blank lines MUST NOT be silently removed before tree construction.

## 5. Malformed JSON Lines

A physical line does not need to parse successfully in order to be committed.

Malformed or otherwise unparseable JSON lines MUST remain in the completeness tree using their exact captured raw bytes.

Parsing and verification status are separate metadata.

This prevents malformed content from becoming silently excluded from the completeness commitment.

## 6. Leaf Hashing

Each export leaf is domain-separated from internal Merkle nodes.

The export leaf hash is:

`SHA-256(0x00 || raw_line_bytes)`

where `raw_line_bytes` are the exact bytes of one retained physical export line.

The `0x00` prefix MUST be one actual byte with value zero.

It MUST NOT be represented by the two ASCII characters backslash and x, followed by 00.

## 7. Internal Node Hashing

Internal nodes use the same domain-separated node construction established by Merkle Format v1:

`SHA-256(0x01 || left || right)`

where `left` and `right` are 32-byte child hashes.

The `0x01` prefix MUST be one actual byte with value one.

## 8. Ordering

Export leaves MUST remain in their original physical order.

The implementation MUST NOT sort, deduplicate, or otherwise reorder lines before tree construction.

The resulting root therefore commits to both membership and sequence.

## 9. Odd-Node Promotion

When a Merkle level contains an unpaired final node, that node MUST be promoted unchanged to the next level.

It MUST NOT be duplicated.

It MUST NOT be hashed by itself.

If the promoted node later obtains a sibling at a higher level, the pair MUST be combined using the internal node formula.

## 10. Empty Export

An export containing zero physical lines has the canonical root:

`SHA-256(b"")`

which is:

`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

## 11. Single-Line Export

An export containing exactly one physical line has a root equal to that line's leaf hash.

No internal node is created.

## 12. Relationship to Evidence Format v1

An export leaf represents raw captured bytes.

An evidence identifier represents a parsed evidence record.

These are deliberately different commitments.

For a valid signed record, the implementation MAY derive:

`tc-ledger:v1:<sha256-hex>`

using Evidence Format v1.

That evidence identifier MUST NOT be substituted for the raw export line when constructing the completeness tree.

## 13. Evidence Identifier Mapping

For each record that successfully produces an Evidence Format v1 evidence identifier, the implementation SHOULD maintain an explicit mapping:

`evidence_id`
`export_leaf_index`
`export_root`

The mapping identifies where a separately verified evidence claim occurs inside the complete export commitment.

Example:

```json
{
  "evidence_id": "tc-ledger:v1:<sha256-hex>",
  "export_leaf_index": 42,
  "export_root": "<sha256-hex>"
}
```

The leaf index is zero-based.

Records that do not produce an evidence identifier may still be present in the export commitment.

## 14. Classification Metadata

Record classification MUST remain separate from tree membership.

A physical line may be classified as:

- `VALID`
- `INVALID`
- `UNSIGNED`
- `MALFORMED`
- `UNSUPPORTED_KEY`

regardless of whether it is included in the completeness tree.

The completeness tree commits to the captured source.

The classification describes what the verifier was able to establish about that source.

## 15. Verification Model

An independent verifier can reproduce an export root by:

1. obtaining the exact captured export byte stream;
2. preserving each physical line and its existing terminator;
3. hashing each line with the export leaf formula;
4. preserving physical sequence order;
5. applying the Merkle construction rules;
6. comparing the resulting root with the published export root.

Reproduction MUST operate on the captured bytes rather than a newly serialized JSON representation.

## 16. Normative Synthetic Test Vector

The following deterministic synthetic export tests raw-byte completeness and evidence classification mapping.

It consists of six physical lines:

1. a valid signed JSON record ending in LF;
2. a valid signed JSON record ending in LF;
3. a blank physical line containing LF;
4. an intentionally malformed JSON line without a final line terminator;
5. an unsigned JSON record ending in LF;
6. a JSON record with a deliberately invalid signature ending in LF.

The signing keys are deterministic fixed 32-byte seeds:

- line 0: bytes 0 through 31;
- line 1: bytes 32 through 63;
- line 4: bytes 64 through 95;
- line 5: bytes 96 through 127.

The exact bytes MUST be used as captured.

The vector MUST be generated by running the implementation and independently reproduced with the specified hashing formulas.

### Exact input bytes

```text
Line 0: b'{"seq":1,"ts":"2026-09-01T00:00:00Z","from":"did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd","text":"alpha","nonce":10001,"sig":"vbbgbnpJxW8eDanqiGp4JFmsaZkYVrfy1knKYhj12TuyYJEiy3dHnEwLqx-knnyR-sBOO-e-ZmtAu5EprzwyDQ"}\n'
Line 1: b'{"seq":2,"ts":"2026-09-01T00:00:00Z","from":"did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2","text":"beta","nonce":10002,"sig":"ysKcaI38cGAcKm-iGxQK8sXXUcAft4B8MWdpv-EmtvVKFY_wDCINRACxYropLKQN6wuAHqa1stkR-ru-8LIlDg"}\n'
Line 2: b'\n'
Line 3: b'{"seq":4,"text":'
Line 4: b'{"seq":5,"ts":"2026-09-01T00:00:00Z","from":"did:key:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG","text":"unsigned"}\n'
Line 5: b'{"seq":6,"ts":"2026-09-01T00:00:00Z","from":"did:key:z6Mkg26jczDiqsPK4momfvhZTTyFefWEyxYiSisFJ2wWJFkg","text":"tampered-after-signing","nonce":10006,"sig":"kL9IDWNpa9s47zhIV5FzxJz0qmjUaMOgQo5og45MKKB_QjRmeiI8izrPSLVrj9DD0FYc-ls_NqwAqwyxfhHpCw"}\n'
```

### Classification

```text
Line 0: VALID
Line 1: VALID
Line 2: BLANK / SKIPPED
Line 3: MALFORMED
Line 4: UNSIGNED
Line 5: INVALID
```

The classifications above were confirmed against the real export verifier.

### Byte lengths

```text
Line 0: 228
Line 1: 227
Line 2: 1
Line 3: 16
Line 4: 122
Line 5: 245
```

### Leaf hashes

```text
Line 0: b7d33d0e88ca571a80929436d575502df24805cf7f0f4d55fa8a4e15972dbec6
Line 1: fefdc379caee222dc772df4c9755e75467c6670d81fc5e44a840f903cdf11e0e
Line 2: 67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e
Line 3: 7936ffce621bbe88ce1f3144f450b640c337efe2656facde4c113189b39c2d54
Line 4: 83022378c19715c785c4a4bfe648a679d5905564e3d85ee503a907693f3cb163
Line 5: 617f31dcb0201bb0c37fc9c67607b2420dfc69093b49cb14550e675782a9a112
```

### Evidence identifiers

Only VALID lines produce evidence identifiers:

```text
Line 0: tc-ledger:v1:91e246308a156e69afcd0837bb8d403e96f5ca0a3f0c6576e2243acc77ec3617
Line 1: tc-ledger:v1:9b70bb047371584384fc49b61c6206f9316520cebae3a741e279f330f55e73f9
```

### Intermediate levels

```text
LEVEL 1
0: c0fad41d366ccdd70717e3ad1d8ef855248b629eaf1468cecbded74636c78a2f
1: 4709daef7050d01c88cdeddbfeeab75f45f1389c40d0bed0bb42cc0ce596addd
2: f98ac1df29fc0879c25a9d2e2d147d227876bbb1dbbe5067464cad519b3f5bc5

LEVEL 2
0: 401ef3906320484abd382cd4db69158e3bf567e7fd65e057993f416fb060da47
1: f98ac1df29fc0879c25a9d2e2d147d227876bbb1dbbe5067464cad519b3f5bc5

LEVEL 3
0: f43ea7c83535b25d01b218be956e0768d5015179dddb681569d0dc4929de40d5
```

### Root

```text
f43ea7c83535b25d01b218be956e0768d5015179dddb681569d0dc4929de40d5
```

The root was independently reproduced using:

`SHA-256(0x00 || raw_line_bytes)` for leaves and

`SHA-256(0x01 || left || right)` for internal nodes.

The independently reproduced root exactly matches the implementation-generated root.

The two VALID records map to export leaf indices 0 and 1 respectively.

## 17. Implementation Status

Completed:

- Evidence Format v1
- Merkle Format v1
- evidence identifier commitments
- Merkle tree construction
- Merkle inclusion proofs
- inclusion proof verification
- proof tamper rejection
- raw export leaf hashing
- export completeness tree
- export commitment test vector
- independent export vector reproduction

Shipped (v0.2.0 - v0.4.0):

- Evidence ID and raw export record verification
- Export verifier integration (`tc-ledger verify`, `tc-ledger verify-proof`)
- Self-contained offline inclusion proof verification (Python engine and fail-closed browser verifier)

Historical context: External anchor/settlement layer is decoupled from the core format specification.

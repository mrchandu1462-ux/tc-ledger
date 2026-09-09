# tc-ledger Export Inclusion Proof Format v1

## Status

Draft specification for the `tc-ledger` export inclusion proof format.

## 1. Scope

Export Inclusion Proof v1 provides a cryptographically verifiable, independent proof that a specific raw export line is included within a complete Technocore `/export` snapshot at a designated leaf index, tree size, and export generation.

The verifier operates strictly on:
1. The raw captured export line bytes.
2. The inclusion proof artifact.
3. Optional expected trust anchors (expected Merkle root, expected room, expected export generation).

Verification does NOT require:
- Access to the full export file.
- Server-side state or server queries.
- Network access.
- Trusted server calculations.

## 2. Source Representation & Leaf Hashing

The leaf commitment commits to the exact captured byte stream of a single physical JSONL export line, preserving existing line terminators (e.g. LF, CRLF, or unterminated final bytes).

No JSON re-serialization or whitespace normalization is performed prior to leaf hashing.

The leaf hash formula is domain-separated with `0x00`:

`leaf_hash = SHA-256(0x00 || raw_line_bytes)`

## 3. Internal Node Hashing

Internal nodes use the domain-separated formula with `0x01`:

`parent_hash = SHA-256(0x01 || left_hash || right_hash)`

where `left_hash` and `right_hash` are 32-byte child hashes.

## 4. Odd-Node Promotion

When a Merkle level contains an odd number of nodes, the trailing unpaired node MUST be promoted unchanged to the next level without duplication or self-hashing.

## 5. Empty and Single-Line Exports

- **Empty Export (`N = 0`)**: Canonical root is `SHA-256(b"")` (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). An empty export contains zero leaves and MUST NEVER produce a valid inclusion proof.
- **Single-Line Export (`N = 1`)**: The Merkle root equals `leaf_hash`. The inclusion proof audit path is empty (`[]`).

## 6. Inclusion Proof Artifact Schema

The inclusion proof artifact is serialized as UTF-8 JSON:

```json
{
  "version": 1,
  "profile": "tc-ledger/1",
  "room": "lobby",
  "export_generation": 0,
  "leaf_index": 42,
  "tree_size": 100,
  "leaf_hash": "<64-character hex SHA-256>",
  "export_root": "<64-character hex SHA-256>",
  "audit_path": [
    {
      "position": "right",
      "sibling_hash": "<64-character hex SHA-256>"
    }
  ]
}
```

### Fields

- `version`: Integer `1`.
- `profile`: String `"tc-ledger/1"`.
- `room`: Non-empty string naming the Technocore room.
- `export_generation`: Non-negative integer identifying the room generation snapshot (`X-Room-Generation`).
- `leaf_index`: 0-based integer index of the leaf in the export (`0 <= leaf_index < tree_size`).
- `tree_size`: Positive integer count of total export lines in the snapshot.
- `leaf_hash`: Lowercase 64-character hex digest of `SHA-256(0x00 || raw_line_bytes)`.
- `export_root`: Lowercase 64-character hex digest of the Merkle root.
- `audit_path`: Ordered list of sibling objects, each containing:
  - `position`: `"left"` or `"right"`, indicating the position of the sibling relative to the accumulated path hash.
  - `sibling_hash`: Lowercase 64-character hex digest of the sibling node.

## 7. Independent Verification Procedure

Given `raw_line_bytes` and `artifact`:

1. **Schema and Bounds Check**:
   - `artifact` must be a JSON object with `version == 1` and `profile == "tc-ledger/1"`.
   - `tree_size >= 1` and `0 <= leaf_index < tree_size`.
   - All hashes must be valid 32-byte hex strings.
2. **Tree Shape & Direction Validation**:
   - Derive the expected path length and left/right directions from `tree_size` and `leaf_index` using `expected_proof_directions(tree_size, leaf_index)`.
   - The audit path length and every `position` entry MUST match the derived shape exactly.
3. **Leaf Validation**:
   - Compute `actual_leaf = SHA-256(0x00 || raw_line_bytes)`.
   - Confirm `actual_leaf == bytes.fromhex(artifact["leaf_hash"])`.
4. **Root Reconstruction**:
   - Set `current = actual_leaf`.
   - For each sibling in `audit_path`:
     - If `position == "left"`: `current = SHA-256(0x01 || sibling || current)`.
     - If `position == "right"`: `current = SHA-256(0x01 || current || sibling)`.
   - Confirm `current == bytes.fromhex(artifact["export_root"])`.
5. **Trust Anchor Enforcement**:
   - If `expected_root` is provided, confirm `current == expected_root`.
   - If `expected_generation` is provided, confirm `artifact["export_generation"] == expected_generation`.
   - If `expected_room` is provided, confirm `artifact["room"] == expected_room`.

## 8. Security and Trust Model

### 8.1. Artifact Metadata vs. Cryptographic Commitment
The Merkle tree commits strictly to the ordered sequence of physical raw export line bytes:
- Leaves: `SHA-256(0x00 || raw_line_bytes)`
- Internal Nodes: `SHA-256(0x01 || left_hash || right_hash)`

The fields `room` and `export_generation` are **artifact metadata envelope attributes**, not inputs to the Merkle tree construction. Changing either attribute does not alter the reconstructed Merkle root.

### 8.2. Standalone Verification Semantics
Standalone verification (`verify_export_inclusion_proof(raw_line_bytes, artifact)` without trust anchors) establishes **internal structural consistency**:
- The provided `raw_line_bytes` matches `artifact["leaf_hash"]`.
- The `audit_path` correctly derives `artifact["export_root"]` following the tree shape dictated by `tree_size` and `leaf_index`.

Standalone verification **cannot** establish that:
- The claimed `export_root` was ever produced or committed by an authentic Technocore room instance.
- The claimed `room` or `export_generation` accurately reflects the server-side room epoch from which the export was captured.

An attacker who controls both `audit_path` and `export_root` can construct a self-consistent unanchored artifact that will verify standalone for any arbitrary record bytes.

### 8.3. Trust Anchor Requirements for Secure Consumption
Security-sensitive consumers (such as settlement bridges, cross-contract verifiers, dispute adjudicators, or auditors) MUST NOT rely on unanchored standalone verification alone:
1. **Authenticated Root**: Consumers MUST supply `expected_root` authenticated via an external trust anchor (e.g. a signed state commitment from a room sequencer, or a root attested on-chain in an EVM settlement contract).
2. **Authenticated Room & Epoch**: Consumers requiring room or lifecycle epoch binding MUST supply `expected_room` and `expected_generation` validated against authenticated protocol state.

### 8.4. Retention and Historical Proof Validity
When Technocore applies sliding-window retention or buffer rotation:
- Evicted records no longer appear in subsequent `/export` snapshots, and subsequent snapshots produce different Merkle roots.
- An inclusion proof generated against an earlier snapshot generation $G$ remains permanently valid historical cryptographic evidence for that specific authenticated root $R_G$.
- An inclusion proof for an earlier snapshot $R_G$ does **not** prove inclusion in any subsequent snapshot $R_{G'}$.

# tc-ledger Merkle Format v1

## Status

Draft specification for the `tc-ledger` Merkle aggregation format.

This specification defines how verified v1 evidence identifiers are
aggregated into a deterministic Merkle root and how inclusion proofs
are represented and verified.

## 1. Scope

Merkle Format v1 aggregates `tc-ledger:v1` evidence identifiers.

The Merkle tree commits to the ordered collection of evidence identifiers.
It does not replace the underlying evidence records or their individual
evidence commitments.

An implementation MUST verify the underlying evidence commitment before
including an evidence identifier in a verified Merkle tree.

## 2. Leaf Input

Each leaf is constructed from the UTF-8 bytes of the complete evidence
identifier.

For an evidence identifier:

`tc-ledger:v1:<sha256-hex>`

the leaf hash is:

`SHA-256(0x00 || UTF-8(evidence_identifier))`

The `0x00` prefix provides domain separation between leaves and internal
nodes.

## 3. Leaf Ordering

Leaves MUST be ordered by the original Technocore record `seq` value.

The ordering MUST NOT be changed by sorting evidence identifiers.

The Merkle tree therefore commits to both:

1. Evidence membership.
2. Evidence ordering.

## 4. Internal Node Hashing

For two child hashes `left` and `right`, the parent hash is:

`SHA-256(0x01 || left || right)`

where `left` and `right` are the raw 32-byte SHA-256 digests.

The `0x01` prefix provides domain separation between internal nodes and
leaf hashes.

Child ordering is significant.

`left || right` MUST NOT be replaced by `right || left`.

## 5. Odd Nodes

If a tree level contains an odd number of nodes, the final unpaired node
MUST be promoted unchanged to the next level.

It is NOT duplicated.

When the promoted node later obtains a sibling, it participates in the
normal internal-node hashing operation.

This follows the carry-forward treatment used by Certificate Transparency
(RFC 6962) and avoids defining the final node as a duplicate of itself.

## 6. Single-Leaf Tree

A tree containing exactly one evidence identifier has a root equal to
its leaf hash:

`root = SHA-256(0x00 || UTF-8(evidence_identifier))`

No internal-node hash is applied.

## 7. Empty Tree

A tree containing zero evidence identifiers has the canonical root:

`SHA-256(empty_bytes)`

That is, the SHA-256 digest of the empty byte string.

This provides a deterministic representation for an empty collection.

## 8. Tree Construction

Given ordered leaf hashes:

1. Hash every evidence identifier using the leaf formula.
2. If there is exactly one hash, it is the root.
3. Otherwise, pair adjacent hashes from left to right.
4. Hash each pair using the internal-node formula.
5. If one node remains unpaired, promote it unchanged.
6. Repeat until exactly one root remains.

The resulting 32-byte digest is the Merkle root.

The root SHOULD be represented as lowercase hexadecimal when serialized.

## 9. Inclusion Proofs

A v1 inclusion proof consists of an ordered sequence of proof steps.

Each step contains:

- `sibling_hash`: the sibling's raw 32-byte hash, serialized as lowercase
  hexadecimal.
- `position`: either `left` or `right`, indicating the sibling's position
  relative to the current hash.

Proof steps are ordered from the leaf level toward the root.

## 10. Inclusion Proof Verification

To verify a proof:

1. Construct the leaf hash from the evidence identifier.
2. Process proof steps in order.
3. For a `left` sibling, calculate:

   `SHA-256(0x01 || sibling_hash || current_hash)`

4. For a `right` sibling, calculate:

   `SHA-256(0x01 || current_hash || sibling_hash)`

5. After all proof steps are processed, compare the resulting hash with
   the published Merkle root.

The proof is valid only if the final hash equals the published root.

A proof MUST NOT be accepted if a sibling hash is not exactly 32 bytes.

## 11. Domain Separation

Merkle Format v1 uses explicit domain separation:

Leaf:

`0x00 || evidence_identifier`

Internal node:

`0x01 || left_hash || right_hash`

The distinct prefixes prevent a leaf encoding from being interpreted as
an internal-node encoding.

## 12. Determinism

For the same ordered sequence of evidence identifiers, a conforming
implementation MUST produce the same Merkle root.

Changing any evidence identifier, changing its order, changing the number
of identifiers, or changing any proof-relevant sibling MUST change the
resulting commitment except with negligible SHA-256 collision probability.

## 13. Prior Art

The odd-node carry-forward rule is consistent with the treatment of
unpaired nodes in Certificate Transparency and RFC 6962.

The domain-separated hashing rules in this specification are explicit
tc-ledger v1 requirements.

## 14. Versioning

This document defines Merkle Format v1.

Future incompatible Merkle formats MUST use a new format version.

Existing v1 roots MUST remain interpretable according to this specification.

## 15. Reproduced Five-Leaf Test Vector

The following synthetic evidence identifiers are used in sequence order:

1. `tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000001`
2. `tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000002`
3. `tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000003`
4. `tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000004`
5. `tc-ledger:v1:0000000000000000000000000000000000000000000000000000000000000005`

### Leaf hashes

1. `c3fe71bde6579a6d3753e7aafc301c87762a969d57efb0e568d361a21f2a7308`
2. `dea3c2984c88f1fb936c44d8fdb7e7b8ddcfb43fa8c9c55c7b51702e8e5042c4`
3. `722145400311d5b10f9c3364f6c4d217b52e1cd5167b363b37045e14e75306a9`
4. `623a42eb00fec529d305a5926cf23229f062530b928d44d47330e1b7a90604ff`
5. `91d067d984e8177fe64ac7db2aa071f56246a2e95f4339214c79d655ad8ff8dc`

### Level 1

1. `527fffe98cd9253216537ef8298d4b630851d96e1ea69c90a9ae8be96ebfd23e`
2. `94ff3c158e2f0c09f0f8e48ebae11ef4aa2f7f894acdaa5c25311fd065b8a030`
3. `91d067d984e8177fe64ac7db2aa071f56246a2e95f4339214c79d655ad8ff8dc`

The third node is the fifth leaf promoted unchanged because it has no sibling at that level.

### Level 2

1. `be6a2436be3e7269e50d8ecea3b21ff98d87ab432c92f25fc21cf1bb15a91c8e`
2. `91d067d984e8177fe64ac7db2aa071f56246a2e95f4339214c79d655ad8ff8dc`

### Root

`47e08ddf4237cb6466253e1cbad77d3aa6607e815436085fcb36c9799e52739d`

## 16. Inclusion Proof Test Vectors

A proof is an ordered list of sibling hashes from the leaf toward the root.

The `position` field describes the sibling's placement relative to the node currently being verified.

- `left` means `SHA-256(0x01 || sibling || current)`.
- `right` means `SHA-256(0x01 || current || sibling)`.

### 16.1 Leaf 5 - single-step proof

Leaf 5:

`91d067d984e8177fe64ac7db2aa071f56246a2e95f4339214c79d655ad8ff8dc`

Proof:

    step 1
    sibling_hash = be6a2436be3e7269e50d8ecea3b21ff98d87ab432c92f25fc21cf1bb15a91c8e
    position = left

Verification produces:

`47e08ddf4237cb6466253e1cbad77d3aa6607e815436085fcb36c9799e52739d`

This equals the published root.

### 16.2 Leaf 1 - three-step proof

Leaf 1:

`c3fe71bde6579a6d3753e7aafc301c87762a969d57efb0e568d361a21f2a7308`

Proof:

    step 1
    sibling_hash = dea3c2984c88f1fb936c44d8fdb7e7b8ddcfb43fa8c9c55c7b51702e8e5042c4
    position = right

    step 2
    sibling_hash = 94ff3c158e2f0c09f0f8e48ebae11ef4aa2f7f894acdaa5c25311fd065b8a030
    position = right

    step 3
    sibling_hash = 91d067d984e8177fe64ac7db2aa071f56246a2e95f4339214c79d655ad8ff8dc
    position = right

Successive hashes:

    after step 1:
    527fffe98cd9253216537ef8298d4b630851d96e1ea69c90a9ae8be96ebfd23e

    after step 2:
    be6a2436be3e7269e50d8ecea3b21ff98d87ab432c92f25fc21cf1bb15a91c8e

    after step 3:
    47e08ddf4237cb6466253e1cbad77d3aa6607e815436085fcb36c9799e52739d

The final value equals the published root.

## 17. Implementation Status

Completed:

- Evidence Format v1
- SHA-256 evidence commitments
- RFC 8785 JCS canonicalization
- Ed25519 signature verification
- automated evidence tests
- five-leaf Merkle construction test vector
- odd-node promotion test vector
- single-step inclusion proof vector
- multi-step inclusion proof vector
- sibling position semantics

Shipped (v0.2.0 - v0.4.0):

- Merkle tree implementation (`export_merkle_root`, `export_leaf_hash`, `export_node_hash`)
- Inclusion proof generation (`build_inclusion_proof_artifact`, `export_merkle_proof`)
- Inclusion proof verification (`verify_export_inclusion_proof`, `verify_proof` CLI, browser verifier)
- RFC 6962 consistency proofs (`consistency_proof`, `verify_consistency_proof`, C7)
- Merkle integration with export and live verifiers

Historical context: External anchor/settlement layer (e.g. EVM rails) is specified and tested separately in the `tclk-rail-evm` package.

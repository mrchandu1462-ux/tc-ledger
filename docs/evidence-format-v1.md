# tc-ledger Evidence Format v1

## Status

Draft specification for the `tc-ledger` evidence commitment format.

## 1. Scope

`tc-ledger` preserves two separate things:

1. The original Technocore record observed in an export.
2. A cryptographic commitment derived from that record.

The commitment does not replace the original evidence.

## 2. Evidence Payload

The v1 evidence payload contains:

- `version`
- `room`
- `seq`
- `ts`
- `from`
- `text`
- `nonce`
- `sig`

`seq` and `ts` are server-attested metadata.

The Technocore signature cryptographically binds:

`room|nonce|text`

The `from` DID identifies the public key used for signature verification.

## 3. Canonicalization

The payload MUST be canonicalized using the JSON Canonicalization Scheme (JCS), RFC 8785.

The JCS output MUST be encoded as UTF-8 bytes.

No additional Unicode normalization is performed by `tc-ledger`.

## 4. Signature

The `sig` field is included in the evidence commitment.

The original Technocore signature MUST be verified before the record is accepted as verified evidence.

The evidence commitment therefore covers the exact signature representation observed in the export.

## 5. Hash

The canonical UTF-8 bytes are hashed using SHA-256.

The digest is represented as lowercase hexadecimal.

The evidence identifier format is:

`tc-ledger:v1:<sha256-hex>`

## 6. Verification Pipeline

Technocore export

-> parse record

-> validate fields

-> decode `did:key`

-> verify Ed25519 signature

-> JCS canonicalization

-> UTF-8 encoding

-> SHA-256

-> evidence identifier

A hash alone MUST NOT be treated as proof of signature validity.

## 7. Normative Test Vector

This is a deterministic synthetic canonicalization-only test vector.

The DID and signature are deliberately placeholders and are NOT valid Technocore credentials.

Input:

version = 1
room = kibble
seq = 123456
ts = 2026-09-01T00:00:00Z
from = did:key:z6MkTestVector
text = tc-ledger v1 test
nonce = 17002
sig = TEST_SIGNATURE_64_BYTES_PLACEHOLDER

Canonical JSON:

{"from":"did:key:z6MkTestVector","nonce":17002,"room":"kibble","seq":123456,"sig":"TEST_SIGNATURE_64_BYTES_PLACEHOLDER","text":"tc-ledger v1 test","ts":"2026-09-01T00:00:00Z","version":1}

UTF-8 byte length:

187

SHA-256:

892e8c6b6cd74e6bee0b60ab5ed0e1d546f1640195c7f0604687218bdfc6c677

Evidence ID:

tc-ledger:v1:892e8c6b6cd74e6bee0b60ab5ed0e1d546f1640195c7f0604687218bdfc6c677

## 8. Adversarial Test Vectors

### 8.1 Trailing whitespace

Changing `text` from `hello` to `hello ` changes the canonical bytes and therefore the digest.

hello:
51e41ee327c87234586230f4ed06ff051631dd779292761709c58b6c85a770b2

hello-space:
297b0364c1e4aa643bdf6520233bf33c38847c72a982f0dbf7c85b9e2301852c

### 8.2 JSON type change

Changing `nonce` from numeric `17002` to string `"17002"` changes the canonical representation and digest.

numeric:
51e41ee327c87234586230f4ed06ff051631dd779292761709c58b6c85a770b2

string:
451ec469601f188c079ce7ae8a311ad1a60588cc5f175bb15e1f15597df1cac5

## 9. Cryptographic Attestation vs Server Trust

The following distinction is normative.

The Ed25519 signature cryptographically authenticates:

`room|nonce|text`

The `from` DID supplies the public key used to verify that signature.

`seq` is server-attested ordering metadata.

`ts` is server-attested receipt-time metadata.

Therefore, `seq` and `ts` are committed by the evidence hash but are not independently authenticated by the author's Ed25519 signature.

## 10. Raw Evidence Preservation

The original export record MUST remain separate from its derived commitment.

A hash is a commitment to evidence, not a replacement for the evidence.

A verifier must be able to obtain the original record and independently reproduce its evidence identifier.

## 11. Versioning

This document defines evidence format v1.

Future incompatible evidence formats MUST use a new format version.

Existing v1 identifiers MUST remain interpretable according to this specification.

## 12. Implementation Status

Completed:

- Ed25519 signed-record verification
- DID key extraction
- failure-mode classification
- tamper detection
- CLI verification command
- automated test suite
- RFC 8785 JCS dependency
- JCS behavior verification
- deterministic canonicalization test vectors

Shipped (v0.2.0 - v0.4.0):

- Merkle aggregation layer (`export_merkle_root` over RFC 8785 canonical evidence IDs and raw export records)
- Inclusion proofs and consistency proofs (v1)

Historical context: External anchor/settlement layer is decoupled from the core format specification.

# TC-Ledger CLI Contract v1

This document defines the normative CLI interface, argument contract, machine-readable JSON format, and process exit codes for 	c-ledger.

## Exit Codes

| Exit Code | Meaning | Description |
|---|---|---|
| **0** | Success / Valid | The operation completed successfully or cryptographic verification succeeded. |
| **1** | Verification Failure | Cryptographic verification failed (invalid signature, corrupted proof, root/generation mismatch). |
| **2** | Usage Error | Invalid command-line arguments or missing mutually exclusive arguments (e.g. neither --record nor --export supplied). |
| **3** | I/O / Runtime Error | File not found, permission denied, unparseable JSON/JSONL, or runtime data error. |

---

## Machine-Readable JSON Mode (--json)

Passing --json enables machine-readable JSON output on stdout.

### Strict Rules for --json:
1. **stdout is pure JSON**: No human prose or logging messages are printed to stdout.
2. **Diagnostics to stderr**: Informational diagnostics, parse warnings, and error messages are written exclusively to stderr.
3. **Deterministic output**: JSON keys are consistently ordered and formatted.

---

## Commands

### 1. 	c-ledger verify
Verifies Ed25519 signatures across all records in a Technocore JSONL export.

`ash
tc-ledger verify <path> --room <room> [--json]
`

**JSON Output (stdout)**:
`json
{
  "command": "verify",
  "room": "demo-room",
  "valid": true,
  "line_count": 4,
  "verification": {
    "VALID": 4,
    "INVALID": 0,
    "UNSIGNED": 0,
    "MALFORMED": 0,
    "UNSUPPORTED_KEY": 0
  },
  "anomaly_indices": []
}
`

---

### 2. 	c-ledger commit
Calculates the RFC 6962 export Merkle root across all physical lines, maps evidence IDs, and optionally writes a commitment artifact.

`ash
tc-ledger commit <path> --room <room> [--generation <int>] [--output <path>] [--json]
`

**JSON Output (stdout)**:
`json
{
  "command": "commit",
  "room": "demo-room",
  "valid": true,
  "line_count": 4,
  "export_root": "0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9",
  "export_generation": 1,
  "verification": {
    "VALID": 4,
    "INVALID": 0,
    "UNSIGNED": 0,
    "MALFORMED": 0,
    "UNSUPPORTED_KEY": 0
  },
  "anomaly_indices": [],
  "artifact": { ... }
}
`

---

### 3. 	c-ledger vectors
Validates the frozen test vectors against the running engine.

`ash
tc-ledger vectors [--json]
`

**JSON Output (stdout)**:
`json
{
  "command": "vectors",
  "profile": "tc-ledger/1",
  "status": "OK",
  "valid": true
}
`

---

### 4. 	c-ledger prove
Constructs a self-contained RFC 6962 inclusion proof artifact for a 0-indexed leaf in an export.

`ash
tc-ledger prove <path> --room <room> --leaf-index <int> [--generation <int>] [--output <path>] [--json]
`

**JSON Output (stdout)**:
`json
{
  "command": "prove",
  "room": "demo-room",
  "leaf_index": 1,
  "export_generation": 1,
  "output": "examples/proof_leaf1.json",
  "valid": true,
  "artifact": { ... }
}
`

---

### 5. 	c-ledger verify-proof
Independently verifies an inclusion proof artifact against raw record bytes or an export file.

`ash
# Verify against standalone record bytes
tc-ledger verify-proof <proof-path> --record <record-path> [--expected-root <hex>] [--expected-room <str>] [--expected-generation <int>] [--json]

# Verify against full export file
tc-ledger verify-proof <proof-path> --export <export-path> [--expected-root <hex>] [--expected-room <str>] [--expected-generation <int>] [--json]
`

**JSON Output (stdout)**:
`json
{
  "command": "verify-proof",
  "valid": true
}
`

---

### 6. 	c-ledger verify-artifact (alias: erify-commitment)
Re-derives and verifies a commitment artifact against raw export bytes.

`ash
tc-ledger verify-artifact <export-path> <artifact-path> [--expected-root <hex>] [--expected-room <str>] [--expected-generation <int>] [--json]
`

**JSON Output (stdout)**:
`json
{
  "command": "verify-artifact",
  "valid": true
}
`

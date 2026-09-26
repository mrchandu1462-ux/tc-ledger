# Security Policy & Invariant Specification

## Threat Model & Security Invariants

TC Verify (`tclk-proof` / `tc-ledger cross-verify`) is security-critical verification software designed to audit off-chain negotiation transcripts against on-chain settlement execution.

### Invariant 1: Unverified Input Separation
External settlement JSON files supplied by callers are unauthenticated. The verifier strictly forces all file-based settlement evidence to `provenance: "self_attested"`. Self-attested evidence produces `on_chain_execution_proven: false` and `is_conformant: false`. Only active, verified JSON-RPC queries executed by `build_rpc_settlement_evidence()` may set `provenance: "rpc_receipt_verified"`.

### Invariant 2: Mandatory Chain Identity Binding
EVM transactions must be anchored to an explicit `chain_id`. Omitting `--chain-id` during RPC verification fails closed to prevent cross-chain transaction relay and testnet-to-mainnet spoofing.

### Invariant 3: Mandatory Escrow Lock Authentication
Evaluating terminal state transactions (`claim_tx` or `refund_tx`) strictly requires `--lock-tx`. Escrow terms (`amount`, `token`, `payer`, `payee`, `hashlock`, `refundTimestamp`) are authenticated directly from the on-chain `Locked` event log data.

---

## Remediated Vulnerabilities (Phase 2 / Phase 3 Red-Team Audit)

| Vulnerability ID | Severity | Description | Remediation |
| :--- | :---: | :--- | :--- |
| **SEC-01** | **CRITICAL** | **Settlement Provenance Spoofing**: Caller-supplied `settlement.json` containing `"provenance": "rpc_receipt_verified"` could produce `is_conformant: true` without executing RPC verification. | `parse_settlement_evidence()` forces `provenance = "self_attested"` for all file/dict inputs. Only `build_rpc_settlement_evidence()` produces `rpc_receipt_verified`. |
| **SEC-02** | **MEDIUM** | **Missing Chain ID Trust Anchor**: If `--chain-id` was omitted, the verifier accepted whatever chain ID the RPC node reported, enabling cross-chain replays. | `build_rpc_settlement_evidence()` requires `expected_chain_id` and fails closed if omitted. |
| **SEC-03** | **LOW** | **Unanchored Claim Receipt**: Evaluating `claim_tx` without `lock_tx` left escrow parameters (`amount`, `token`, `hashlock`) unanchored on-chain. | `build_rpc_settlement_evidence()` requires `lock_tx` when evaluating claim or refund receipts. |

---

## Reporting a Vulnerability

If you discover a security vulnerability in `tc-ledger` or `tclk-proof`, please report it responsibly by contacting the maintainers or filing a confidential security advisory on GitHub. Please do not disclose vulnerabilities publicly until a fix has been released.

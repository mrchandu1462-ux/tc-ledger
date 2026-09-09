# Security Findings: EVM HTLC Rail (`tclk/1`)

## Finding 1 (SEC-HTLC-03): Fee-on-Transfer ERC-20 Accounting Policy

### Status
Resolved / Closed (Fail-Closed by Design)

### Overview
A potential accounting deficit scenario was investigated where fee-on-transfer (deflationary) ERC-20 tokens could theoretically cause the contract to record more escrowed balance than actually received if transfers were not balance-verified.

### Security Invariants & Behavior
1. **Exact Balance Delta Verification**: In `contracts/Htlc.sol`, `lock()` strictly measures the actual token balance change:
   ```solidity
   uint256 balanceBefore = IERC20(token).balanceOf(address(this));
   _safeTransferFrom(token, msg.sender, address(this), amount);
   uint256 balanceAfter = IERC20(token).balanceOf(address(this));
   if (balanceAfter - balanceBefore != amount) revert TransferFailed();
   ```
2. **Atomic Reversion**: Any transfer where fees are deducted results in `balanceAfter - balanceBefore != amount`, triggering an immediate atomic revert (`revert TransferFailed()`).
3. **No Underfunded Escrows**: Because failed transfers revert atomically, no underfunded or unbacked escrow struct can ever be created in contract storage, and no event is emitted.
4. **Intentional Unsupported-Token Policy**: The `tclk/1` settlement rail intentionally requires standard, non-deflationary ERC-20 behavior. Supporting fee-on-transfer tokens would violate off-chain `LockTerms.amount` settlement invariants and require protocol-level redesign of net/gross amounts and fee slippage.
5. **Permanent Regression Test**: Foundry test `test_Erc20_FeeOnTransfer_Lock_Reverts` in `test/Htlc.t.sol` permanently asserts that fee-on-transfer token locks revert fail-closed.

---

## Finding 2 (SEC-HTLC-01): EVM HTLC Claim Idempotency and In-Flight Race

### Status
Resolved

### Overview
Calling `EvmHtlcRail.claim()` on an escrow that had already transitioned to `Claimed` (either via duplicate client invocation or third-party/sweeper execution) threw `EscrowNotLockedError` rather than converging idempotently. In addition, an in-flight race condition where a claim was mined on-chain between the pre-flight `read()` check and transaction submission caused `Htlc.claim()` to revert with `NotLocked()`, bubbling up an unhandled transaction execution error.

### Remediation
1. **Pre-flight Idempotency Guard**: Added a pre-flight check verifying whether `held.status === EscrowStatus.Claimed`. If claimed and `computeSha256(secretHash) === held.hashlock`, the call resolves cleanly (`return;`). If the secret does not match the hashlock, `InvalidSecretError` is thrown.
2. **In-Flight Race Recheck**: Wrapped contract execution in a `try...catch` block. On failure, `claim()` re-checks on-chain state via `this.read(contractId)`. If the on-chain status is `Claimed` and the secret matches the hashlock, it resolves idempotently. Otherwise, the caught error is re-thrown.
3. **State Integrity**: Claims against already-refunded or uninitialized escrows continue to throw `EscrowNotLockedError` or `EscrowNotFoundError`.

---

## Finding 3 (SEC-HTLC-02): EVM HTLC Refund Idempotency and In-Flight Race

### Status
Resolved

### Overview
Calling `EvmHtlcRail.refund()` on an escrow that had already transitioned to `Refunded` (e.g. from an earlier client call, retry, or third-party execution) threw `EscrowNotLockedError` rather than converging idempotently. Additionally, in-flight race conditions where an on-chain refund confirmed between the pre-flight `read()` check and transaction confirmation resulted in on-chain transaction reversion with `NotLocked()`, surfacing as an unhandled viem transaction execution error.

### Technical Analysis
1. `EvmHtlcRail.refund()` in `src/rail.ts` checked `if (held.status !== EscrowStatus.Locked) throw new EscrowNotLockedError(...)` without permitting the terminal `Refunded` state.
2. Contract transaction dispatch via `wallet.writeContract` lacked error interception and on-chain status reconciliation, failing to gracefully handle concurrent confirmations.

### Remediation
1. **Pre-flight Idempotency Guard**: Added `if (held.status === EscrowStatus.Refunded) return;` before the locked check in `EvmHtlcRail.refund()`.
2. **In-Flight Race Recheck**: Wrapped `wallet.writeContract` and `waitForTransactionReceipt` in a `try...catch` block. On caught error, `this.read(contractId)` is called:
   - If `recheck.status === EscrowStatus.Refunded`, the refund has already been confirmed on-chain and funds returned to payer; the call returns successfully.
   - If `recheck.status` is not `Refunded` (e.g. if the escrow was claimed during the race, or an unrelated error occurred), the caught error is re-thrown.
3. **Strict Validation Preserved**:
   - Escrows in `Claimed` status continue to throw `EscrowNotLockedError`.
   - Invocations before `refundTimestamp` continue to throw `RefundTooEarlyError`.
   - Unknown/uninitialized contract IDs continue to throw `EscrowNotFoundError`.

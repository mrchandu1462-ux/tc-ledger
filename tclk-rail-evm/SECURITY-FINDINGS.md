# Security Findings: EVM HTLC Rail (`tclk/1`)

## Finding 1: Fee-on-Transfer ERC-20 Accounting Deficit

### Overview
The `Htlc` contract (`contracts/Htlc.sol`) is vulnerable to an accounting deficit when used with Fee-on-Transfer (deflationary) ERC-20 tokens.

### Technical Analysis
During execution of `Htlc.lock(...)`:
1. `Htlc.sol` invokes `IERC20(token).transferFrom(msg.sender, address(this), amount)`.
2. For Fee-on-Transfer ERC-20 tokens, the token contract deducts a transfer fee `FEE`, so `address(this)` receives only `amount - FEE` tokens.
3. `Htlc.sol` unconditionally records `escrows[contractId].amount = amount` in contract storage without inspecting the actual balance change of the contract.

### Impact & Demonstration
As demonstrated in Foundry test `test_Erc20_FeeOnTransfer_Lock_RecordsMoreThanReceived` ([`test/Htlc.t.sol`](file:///c:/Users/mrcha/tc-ledger/tclk-rail-evm/test/Htlc.t.sol#L635-L670)):
- **Requested Amount (`amount`)**: `1,000,000,000,000,000,000,000` (`1000e18`).
- **Actual HTLC Balance**: `999,999,999,999,999,999,900` (`1000e18 - 100`).
- **Accounting Deficit**: Recorded Escrow > Actual Token Custody.

When `htlc.claim(...)` or `htlc.refund(...)` is invoked:
- **Isolated Escrow Case**: The payee or payer is **permanently locked out** from claiming or refunding funds because `IERC20(token).transfer(to, amount)` fails due to insufficient HTLC token balance.
- **Shared Balance Case**: If the contract holds tokens from other escrows, the first claimer will drain funds belonging to other escrows, leading to cross-escrow insolvency and Denial of Service (DoS) for subsequent claimers.

### Remediation
Compute the actual balance increase during `lock()`:
```solidity
uint256 balanceBefore = IERC20(token).balanceOf(address(this));
bool ok = IERC20(token).transferFrom(msg.sender, address(this), amount);
if (!ok) revert TransferFailed();
uint256 actualReceived = IERC20(token).balanceOf(address(this)) - balanceBefore;
if (actualReceived == 0) revert InvalidAmount();
// Record actualReceived in escrow struct
```

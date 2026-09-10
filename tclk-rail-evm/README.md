# @flop-labs/tclk-rail-evm

EVM HTLC Settlement Rail, Deal Transport, Archival Evidence Binding, and Deal Wallet for Technocore Lock Protocol (`tclk/1`).

## Overview

`tclk-rail-evm` provides the EVM settlement layer, signed room message transport, offline verifiable archival, and interactive deal wallet for the **TC-Ledger** system.

### Core Modules

1. **Smart Contracts (`contracts/Htlc.sol`, `contracts/MockERC20.sol`)**:
   - Native ETH and ERC-20 token escrows with timelocked refunds.
   - Operations: `lock()`, `claim()`, and `refund()`.
   - Checks-Effects-Interactions (CEI) and reentrancy protection.
   - Fail-closed token balance delta checks against fee-on-transfer / rebasing tokens.
   - SafeERC20 compatibility supporting zero-return and non-standard ERC-20 implementations.

2. **EVM Settlement Rail (`src/rail.ts`, `src/resolver.ts`)**:
   - Viem-based client (`EvmHtlcRail`) interfacing with `Htlc.sol`.
   - DID-to-EVM address resolvers (`StaticAddressResolver`, `Secp256k1KeyAddressResolver`, `CompositeAddressResolver`).
   - Idempotent claim and refund handling with automatic race recovery against confirmed transactions.

3. **Deal Protocol & Transport (`src/deal.ts`, `src/transport.ts`)**:
   - Cryptographic state machine managing deal lifecycle: `OFFERED` -> `ACCEPTED` -> `LOCKED` -> `VERIFIED` -> `REVEALED` -> `CLAIMED` / `REFUNDED` / `CANCELLED`.
   - Technocore Ed25519-signed frame protocol: `offer`, `accept`, `lock`, `reveal`, `claim`, `receipt`, `refund`, `cancel`.
   - Line length enforcement (`MAX_FRAME_CHARS = 1000`) and text sweeping.
   - Zero plaintext secret leakage policy: secret preimages are erased from memory and never serialized in deal records or public messages.

4. **Deal Archiver & Cryptographic Evidence Binding (`src/archiver.ts`)**:
   - Binds completed deal transcripts directly to RFC 6962-style Merkle export commitments produced by `tc-ledger`.
   - Packages `DealArchive` artifacts containing full cryptographic proofs:
     - Stage records with preserved raw bytes and physical line indices.
     - Per-stage Merkle inclusion audit paths (`TcInclusionProof`).
     - Root export commitment (`TcExportCommitment`).
   - Independent offline verifier (`verifyDealArchive`): validates signatures, inclusion proofs, Merkle root, and state machine integrity with zero server or network calls.

5. **Deal Wallet Application & Server (`src/app/`)**:
   - `WalletSession` (`src/app/session.ts`): Secure session management with encrypted identity derivation and read-only balance helpers.
   - `ArchiveStore` (`src/app/store.ts`): Local deal archive persistence (`.deal-wallet/archives/`) with automatic on-disk tamper detection.
   - `DealWalletApp` (`src/app/orchestrator.ts`): Orchestrator coordinating transport, session, rail, and archiver across the two-party deal flow.
   - `DealWalletServer` (`src/app/server.ts`): Zero-credential loopback HTTP server (`127.0.0.1`) serving REST API endpoints and an interactive local dashboard UI.

---

## Installation & Build

```bash
# Install dependencies
npm install

# Compile Solidity contracts with Foundry
npm run build:contracts

# Compile TypeScript
npm run build:ts

# Full build
npm run build
```

---

## Testing & Verification

```bash
# Run Foundry contract test suite (33 tests)
forge test

# Run full Vitest integration suite (140 tests across 8 test suites)
npm test

# Run specific test suites
npx vitest run tests/htlc.test.ts
npx vitest run tests/deal.test.ts
npx vitest run tests/archiver.test.ts
npx vitest run tests/session_store.test.ts
npx vitest run tests/orchestrator.test.ts
npx vitest run tests/server.test.ts
```

---

## Demos & CLI

### Deal Archival & Offline Verification Demo

```bash
npm run demo:archive
```
Generates a realistic synthetic room export, creates an EVM deal archive via `tc-ledger` inclusion proofs, executes independent offline verification, and writes the verified archive artifact to `dist/sample_deal_archive.json`.

### Deal Wallet Local Server

```bash
# Start local Deal Wallet HTTP server and dashboard
npm run wallet -- --port 3456 --room demo-room
```

Access the dashboard at `http://127.0.0.1:3456` to monitor deals, inspect verified archives, and trigger deal lifecycle transitions.

---

## Security Policies

- **Strict Loopback Binding**: `DealWalletServer` strictly binds to `127.0.0.1` and explicitly rejects non-loopback bindings.
- **Zero Secret Exposure**: Preimage secrets are never returned in HTTP responses, logs, or stored archives.
- **Fail-Closed Escrows**: Contract enforces exact balance changes to prevent underfunded escrows from fee-on-transfer tokens.
- **Tamper Detection**: `ArchiveStore` independently verifies hash commitments and inclusion proofs on every disk load.

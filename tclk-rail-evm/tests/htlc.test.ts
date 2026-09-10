// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import { type Address, type Hash, parseEther, zeroAddress, getAddress } from "viem";
import {
  startAnvil,
  type AnvilContext,
  payerAccount,
  payeeAccount,
  strangerAccount,
} from "./fixtures.js";
import { EvmHtlcRail } from "../src/rail.js";
import { StaticAddressResolver } from "../src/resolver.js";
import { computeSha256 } from "../src/utils.js";
import {
  UnsupportedLockKindError,
  RefundWindowOpenError,
  ClaimTooLateError,
  RefundTooEarlyError,
  InvalidSecretError,
  EscrowNotLockedError,
  EscrowNotFoundError,
  InvalidTermsError,
} from "../src/errors.js";
import type { LockTerms } from "../src/types.js";
import { ERC20_ABI, HTLC_ABI } from "../src/abi.js";

const PAYER_DID = "did:key:z6Mkffffffffffffffffffffffffffffffffffffffffffff";
const PAYEE_DID = "did:key:z6Mkgggggggggggggggggggggggggggggggggggggggggggg";
const STRANGER_DID = "did:key:z6Mkhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";

const SECRET_HEX = "0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff" as Hash;
const WRONG_SECRET_HEX = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" as Hash;
const STATEMENT_HEX = computeSha256(SECRET_HEX);

describe("EvmHtlcRail integration tests (Anvil local node)", () => {
  let anvil: AnvilContext;
  let simulatedTimeMs: number;
  let addressResolver: StaticAddressResolver;
  let payerRail: EvmHtlcRail;
  let payeeRail: EvmHtlcRail;

  let contractCounter = 1;
  function nextContractId(): Hash {
    const id = (contractCounter++).toString(16).padStart(64, "0");
    return `0x${id}`;
  }

  beforeAll(async () => {
    anvil = await startAnvil();
  });

  afterAll(async () => {
    if (anvil) {
      await anvil.stop();
    }
  });

  beforeEach(async () => {
    // Sync simulated clock to current Anvil block timestamp
    const blockTs = await anvil.getBlockTimestamp();
    simulatedTimeMs = Number(blockTs) * 1000;

    // Ensure strangerAccount has ETH for gas when performing third-party actions
    const fundStrangerTx = await anvil.payerWallet.sendTransaction({
      to: strangerAccount.address,
      value: parseEther("1"),
      account: payerAccount,
      chain: anvil.payerWallet.chain,
    });
    await anvil.publicClient.waitForTransactionReceipt({ hash: fundStrangerTx });

    addressResolver = new StaticAddressResolver({
      [PAYER_DID]: payerAccount.address,
      [PAYEE_DID]: payeeAccount.address,
      [STRANGER_DID]: strangerAccount.address,
    });

    const clock = () => simulatedTimeMs;

    payerRail = new EvmHtlcRail({
      publicClient: anvil.publicClient,
      walletClient: anvil.payerWallet,
      account: payerAccount,
      htlcAddress: anvil.htlcAddress,
      addressResolver,
      assetResolver: (asset: string) => {
        if (asset === "ETH") return zeroAddress;
        if (asset === "USDC") return anvil.tokenAddress;
        return getAddress(asset);
      },
      clock,
    });

    payeeRail = new EvmHtlcRail({
      publicClient: anvil.publicClient,
      walletClient: anvil.payeeWallet,
      account: payeeAccount,
      htlcAddress: anvil.htlcAddress,
      addressResolver,
      assetResolver: (asset: string) => {
        if (asset === "ETH") return zeroAddress;
        if (asset === "USDC") return anvil.tokenAddress;
        return getAddress(asset);
      },
      clock,
    });
  });

  async function advanceTimeTo(targetSeconds: bigint): Promise<void> {
    await anvil.setNextBlockTimestamp(targetSeconds);
    await anvil.mineBlock();
    simulatedTimeMs = Number(targetSeconds) * 1000;
  }

  function makeEthTerms(overrides: Partial<LockTerms> = {}): LockTerms {
    const nowSec = Math.floor(simulatedTimeMs / 1000);
    const refundAfterSec = nowSec + 3600; // 1 hour window
    return {
      contract: nextContractId(),
      lock: "hash",
      statement: STATEMENT_HEX,
      amount: parseEther("1").toString(),
      asset: "ETH",
      payer: PAYER_DID,
      payee: PAYEE_DID,
      claimByMs: (refundAfterSec - 1800) * 1000,
      refundAfterMs: refundAfterSec * 1000,
      ...overrides,
    };
  }

  function makeErc20Terms(overrides: Partial<LockTerms> = {}): LockTerms {
    const nowSec = Math.floor(simulatedTimeMs / 1000);
    const refundAfterSec = nowSec + 3600;
    return {
      contract: nextContractId(),
      lock: "hash",
      statement: STATEMENT_HEX,
      amount: "100000000000000000000", // 100 tokens (18 dec)
      asset: "USDC",
      payer: PAYER_DID,
      payee: PAYEE_DID,
      claimByMs: (refundAfterSec - 1800) * 1000,
      refundAfterMs: refundAfterSec * 1000,
      ...overrides,
    };
  }

  /* -------------------------------------------------------------------------- */
  /*                  1. ETH Successful Lock & Exact verifyLock                 */
  /* -------------------------------------------------------------------------- */

  it("locks ETH successfully and returns terms.contract as ref", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    expect(ref).toBe(terms.contract);
    expect(await payeeRail.verifyLock(terms, ref)).toBe(true);

    const onChain = await payerRail.read(ref);
    expect(onChain).not.toBeNull();
    expect(onChain?.amount).toBe(BigInt(terms.amount));
    expect(onChain?.token).toBe(zeroAddress);
    expect(onChain?.hashlock.toLowerCase()).toBe(terms.statement.toLowerCase());
  });

  /* -------------------------------------------------------------------------- */
  /*                      2. verifyLock Tampering Defenses                      */
  /* -------------------------------------------------------------------------- */

  it("verifyLock returns false for nonexistent/unknown ref", async () => {
    const terms = makeEthTerms();
    const unknownRef = nextContractId();
    expect(await payeeRail.verifyLock(terms, unknownRef)).toBe(false);
  });

  it("verifyLock returns false when amount is tampered", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const tampered = { ...terms, amount: parseEther("2").toString() };
    expect(await payeeRail.verifyLock(tampered, ref)).toBe(false);
  });

  it("verifyLock returns false when asset is tampered", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const tampered = { ...terms, asset: "USDC" };
    expect(await payeeRail.verifyLock(tampered, ref)).toBe(false);
  });

  it("verifyLock returns false when payer or payee is tampered", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const tamperedPayee = { ...terms, payee: STRANGER_DID };
    expect(await payeeRail.verifyLock(tamperedPayee, ref)).toBe(false);

    const tamperedPayer = { ...terms, payer: STRANGER_DID };
    expect(await payeeRail.verifyLock(tamperedPayer, ref)).toBe(false);
  });

  it("verifyLock returns false when statement is tampered", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const tampered = { ...terms, statement: computeSha256(WRONG_SECRET_HEX) };
    expect(await payeeRail.verifyLock(tampered, ref)).toBe(false);
  });

  it("verifyLock returns false when refund deadline is tampered", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const tampered = { ...terms, refundAfterMs: terms.refundAfterMs + 5000 };
    expect(await payeeRail.verifyLock(tampered, ref)).toBe(false);
  });

  it("verifyLock returns false when claimByMs equals refundAfterMs", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const tampered = { ...terms, claimByMs: terms.refundAfterMs };
    expect(await payeeRail.verifyLock(tampered, ref)).toBe(false);
  });

  it("verifyLock returns false when claimByMs exceeds refundAfterMs", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const tampered = { ...terms, claimByMs: terms.refundAfterMs + 1000 };
    expect(await payeeRail.verifyLock(tampered, ref)).toBe(false);
  });

  /* -------------------------------------------------------------------------- */
  /*                         3. Claim Guard and Execution                       */
  /* -------------------------------------------------------------------------- */

  it("rejects claim with wrong secret without moving funds", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    await expect(payeeRail.claim(ref, WRONG_SECRET_HEX)).rejects.toThrow(
      InvalidSecretError,
    );

    // Escrow must still be locked
    expect(await payeeRail.verifyLock(terms, ref)).toBe(true);
  });

  it("executes successful ETH claim before refund deadline", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const payeeBalanceBefore = await anvil.publicClient.getBalance({
      address: payeeAccount.address,
    });

    await payeeRail.claim(ref, SECRET_HEX);

    const payeeBalanceAfter = await anvil.publicClient.getBalance({
      address: payeeAccount.address,
    });

    // Payee received the escrowed amount (minus gas if payee called)
    expect(payeeBalanceAfter).toBeGreaterThan(payeeBalanceBefore);
    expect(await payeeRail.verifyLock(terms, ref)).toBe(false);

    const onChain = await payeeRail.read(ref);
    expect(onChain?.status).toBe(2); // Claimed
  });

  /* -------------------------------------------------------------------------- */
  /*                        4. Refund Guard and Execution                       */
  /* -------------------------------------------------------------------------- */

  it("rejects refund before refund deadline", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    await expect(payerRail.refund(ref)).rejects.toThrow(RefundTooEarlyError);
    expect(await payeeRail.verifyLock(terms, ref)).toBe(true);
  });

  it("succeeds with refund exactly at refund deadline", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const refundTimestampSec = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    await advanceTimeTo(refundTimestampSec);

    const payerBalanceBefore = await anvil.publicClient.getBalance({
      address: payerAccount.address,
    });

    await payerRail.refund(ref);

    const payerBalanceAfter = await anvil.publicClient.getBalance({
      address: payerAccount.address,
    });

    // Payer received refund
    expect(payerBalanceAfter).toBeGreaterThan(payerBalanceBefore);
    const onChain = await payerRail.read(ref);
    expect(onChain?.status).toBe(3); // Refunded
  });

  it("executes successful ETH refund after refund deadline", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const refundTimestampSec = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    await advanceTimeTo(refundTimestampSec + 60n);

    await payerRail.refund(ref);

    const onChain = await payerRail.read(ref);
    expect(onChain?.status).toBe(3); // Refunded
    expect(await payeeRail.verifyLock(terms, ref)).toBe(false);
  });

  /* -------------------------------------------------------------------------- */
  /*                       5. Duplicate & Cross Reverts                         */
  /* -------------------------------------------------------------------------- */

  it("treats duplicate valid claim and duplicate refund as idempotent", async () => {
    // Duplicate claim is idempotent for valid secret
    const termsClaim = makeEthTerms();
    const refClaim = await payerRail.lock(termsClaim);
    await payeeRail.claim(refClaim, SECRET_HEX);
    await expect(payeeRail.claim(refClaim, SECRET_HEX)).resolves.toBeUndefined();

    // Duplicate refund is idempotent
    const termsRefund = makeEthTerms();
    const refRefund = await payerRail.lock(termsRefund);
    const refundTs = BigInt(Math.ceil(termsRefund.refundAfterMs / 1000));
    await advanceTimeTo(refundTs);
    await payerRail.refund(refRefund);
    await expect(payerRail.refund(refRefund)).resolves.toBeUndefined();
  });

  it("resolves successfully when escrow was already refunded by a third party", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const refundTs = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    await advanceTimeTo(refundTs);

    // Stranger refunds on-chain directly
    const tx = await anvil.strangerWallet.writeContract({
      address: anvil.htlcAddress,
      abi: HTLC_ABI,
      functionName: "refund",
      args: [ref],
      account: strangerAccount,
      chain: anvil.strangerWallet.chain,
    });
    await anvil.publicClient.waitForTransactionReceipt({ hash: tx });

    // Verify on-chain escrow is already Refunded
    const onChain = await payerRail.read(ref);
    expect(onChain?.status).toBe(3); // Refunded

    // Payer calls refund -> resolves idempotently
    await expect(payerRail.refund(ref)).resolves.toBeUndefined();
  });

  it("handles concurrent race where escrow is refunded between pre-flight read and tx execution", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const refundTs = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    await advanceTimeTo(refundTs);

    let readCallCount = 0;
    const originalRead = payerRail.read.bind(payerRail);
    const readSpy = vi.spyOn(payerRail, "read").mockImplementation(async (r: string) => {
      readCallCount++;
      if (readCallCount === 1) {
        // First read: pre-flight check in refund().
        // Fetch real Locked state, but immediately execute stranger's refund on-chain
        // before payer's writeContract runs.
        const lockedState = await originalRead(r);
        const tx = await anvil.strangerWallet.writeContract({
          address: anvil.htlcAddress,
          abi: HTLC_ABI,
          functionName: "refund",
          args: [ref],
          account: strangerAccount,
          chain: anvil.strangerWallet.chain,
        });
        await anvil.publicClient.waitForTransactionReceipt({ hash: tx });
        return lockedState;
      }
      // Subsequent reads (inside catch block) see the actual Refunded state
      return originalRead(r);
    });

    try {
      await expect(payerRail.refund(ref)).resolves.toBeUndefined();
      expect(readCallCount).toBeGreaterThanOrEqual(2);
    } finally {
      readSpy.mockRestore();
    }
  });

  it("fails refund when escrow is claimed between pre-flight read and tx execution", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    let readCallCount = 0;
    const originalRead = payerRail.read.bind(payerRail);
    const readSpy = vi.spyOn(payerRail, "read").mockImplementation(async (r: string) => {
      readCallCount++;
      if (readCallCount === 1) {
        // Pre-flight check in refund().
        // Stranger claims on-chain with valid secret before refund tx executes
        const tx = await anvil.strangerWallet.writeContract({
          address: anvil.htlcAddress,
          abi: HTLC_ABI,
          functionName: "claim",
          args: [ref, SECRET_HEX],
          account: strangerAccount,
          chain: anvil.strangerWallet.chain,
        });
        await anvil.publicClient.waitForTransactionReceipt({ hash: tx });

        // Advance time so refund pre-flight timestamp check passes
        const refundTs = BigInt(Math.ceil(terms.refundAfterMs / 1000));
        await advanceTimeTo(refundTs);

        // Return synthetic Locked state to simulate pre-flight having passed before claim
        const actualState = await originalRead(r);
        return {
          ...actualState!,
          status: 1, // Locked
          refundTimestamp: BigInt(Math.floor(simulatedTimeMs / 1000) - 10),
        };
      }
      // Recheck in catch block returns actual on-chain state (Claimed = 2)
      return originalRead(r);
    });

    try {
      await expect(payerRail.refund(ref)).rejects.toThrow();
      expect(readCallCount).toBeGreaterThanOrEqual(2);
    } finally {
      readSpy.mockRestore();
    }
  });

  it("resolves successfully when escrow was already claimed by a third party with valid secret", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    // Stranger claims on-chain directly
    const tx = await anvil.strangerWallet.writeContract({
      address: anvil.htlcAddress,
      abi: HTLC_ABI,
      functionName: "claim",
      args: [ref, SECRET_HEX],
      account: strangerAccount,
      chain: anvil.strangerWallet.chain,
    });
    await anvil.publicClient.waitForTransactionReceipt({ hash: tx });

    // Verify on-chain escrow is already Claimed
    const onChain = await payeeRail.read(ref);
    expect(onChain?.status).toBe(2); // Claimed

    // Payee calls claim with the valid secret -> resolves idempotently
    await expect(payeeRail.claim(ref, SECRET_HEX)).resolves.toBeUndefined();
  });

  it("rejects claim with invalid secret on an already-claimed escrow", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    // Stranger claims on-chain with valid secret
    const tx = await anvil.strangerWallet.writeContract({
      address: anvil.htlcAddress,
      abi: HTLC_ABI,
      functionName: "claim",
      args: [ref, SECRET_HEX],
      account: strangerAccount,
      chain: anvil.strangerWallet.chain,
    });
    await anvil.publicClient.waitForTransactionReceipt({ hash: tx });

    // Payee calls claim with wrong secret -> rejects with InvalidSecretError
    await expect(payeeRail.claim(ref, WRONG_SECRET_HEX)).rejects.toThrow(
      InvalidSecretError,
    );
  });

  it("rejects claim on an escrow that has already been refunded", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const refundTs = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    await advanceTimeTo(refundTs);
    await payerRail.refund(ref);

    // Verify on-chain escrow is Refunded
    const onChain = await payeeRail.read(ref);
    expect(onChain?.status).toBe(3); // Refunded

    // Payee calls claim with valid secret -> must reject
    await expect(payeeRail.claim(ref, SECRET_HEX)).rejects.toThrow(
      EscrowNotLockedError,
    );
  });

  it("handles concurrent race where escrow is claimed between pre-flight read and tx execution", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    let readCallCount = 0;
    const originalRead = payeeRail.read.bind(payeeRail);
    const readSpy = vi.spyOn(payeeRail, "read").mockImplementation(async (r: string) => {
      readCallCount++;
      if (readCallCount === 1) {
        // First read: pre-flight check in claim().
        // Fetch real Locked state, but immediately execute stranger's claim on-chain
        // before payee's writeContract runs.
        const lockedState = await originalRead(r);
        const tx = await anvil.strangerWallet.writeContract({
          address: anvil.htlcAddress,
          abi: HTLC_ABI,
          functionName: "claim",
          args: [ref, SECRET_HEX],
          account: strangerAccount,
          chain: anvil.strangerWallet.chain,
        });
        await anvil.publicClient.waitForTransactionReceipt({ hash: tx });
        return lockedState;
      }
      // Subsequent reads (e.g. inside catch block) see the actual Claimed state
      return originalRead(r);
    });

    try {
      await expect(payeeRail.claim(ref, SECRET_HEX)).resolves.toBeUndefined();
      expect(readCallCount).toBeGreaterThanOrEqual(2);
    } finally {
      readSpy.mockRestore();
    }
  });

  it("rejects refund after claim and rejects claim after refund", async () => {
    // Refund after claim
    const terms1 = makeEthTerms();
    const ref1 = await payerRail.lock(terms1);
    await payeeRail.claim(ref1, SECRET_HEX);
    const refundTs1 = BigInt(Math.ceil(terms1.refundAfterMs / 1000));
    await advanceTimeTo(refundTs1);
    await expect(payerRail.refund(ref1)).rejects.toThrow(EscrowNotLockedError);

    // Claim after refund
    const terms2 = makeEthTerms();
    const ref2 = await payerRail.lock(terms2);
    const refundTs2 = BigInt(Math.ceil(terms2.refundAfterMs / 1000));
    await advanceTimeTo(refundTs2);
    await payerRail.refund(ref2);
    await expect(payeeRail.claim(ref2, SECRET_HEX)).rejects.toThrow(
      EscrowNotLockedError,
    );
  });

  /* -------------------------------------------------------------------------- */
  /*                  6. Pre-flight & Window Lock Rejections                    */
  /* -------------------------------------------------------------------------- */

  it("refuses to lock into an already-open refund window", async () => {
    const terms = makeEthTerms();
    // Advance time past the terms.refundAfterMs
    const refundTs = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    await advanceTimeTo(refundTs);

    await expect(payerRail.lock(terms)).rejects.toThrow(RefundWindowOpenError);
  });

  it("rejects lock when claimByMs equals refundAfterMs", async () => {
    const terms = makeEthTerms();
    const equalDeadlines = { ...terms, claimByMs: terms.refundAfterMs };

    await expect(payerRail.lock(equalDeadlines)).rejects.toThrow(
      InvalidTermsError,
    );
  });

  it("rejects lock when claimByMs exceeds refundAfterMs", async () => {
    const terms = makeEthTerms();
    const invertedDeadlines = { ...terms, claimByMs: terms.refundAfterMs + 1000 };

    await expect(payerRail.lock(invertedDeadlines)).rejects.toThrow(
      InvalidTermsError,
    );
  });

  /* -------------------------------------------------------------------------- */
  /*                    7. Timestamp Boundary Verification                      */
  /* -------------------------------------------------------------------------- */

  it("allows claim at exact boundary refundTimestamp - 1 second", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const refundTs = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    // 1 second before refund deadline
    await advanceTimeTo(refundTs - 1n);

    await payeeRail.claim(ref, SECRET_HEX);
    const onChain = await payeeRail.read(ref);
    expect(onChain?.status).toBe(2); // Claimed
  });

  it("reverts claim at exact refundTimestamp boundary", async () => {
    const terms = makeEthTerms();
    const ref = await payerRail.lock(terms);

    const refundTs = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    // Exactly at refund deadline
    await advanceTimeTo(refundTs);

    await expect(payeeRail.claim(ref, SECRET_HEX)).rejects.toThrow(
      ClaimTooLateError,
    );
  });

  /* -------------------------------------------------------------------------- */
  /*                       8. ERC-20 Token Lock & Settle                        */
  /* -------------------------------------------------------------------------- */

  it("supports full ERC-20 lock -> claim lifecycle", async () => {
    const terms = makeErc20Terms();

    // Payer approves HTLC for ERC-20 token amount
    const approveTx = await anvil.payerWallet.writeContract({
      address: anvil.tokenAddress,
      abi: ERC20_ABI,
      functionName: "approve",
      args: [anvil.htlcAddress, BigInt(terms.amount)],
      account: payerAccount,
      chain: anvil.payerWallet.chain,
    });
    await anvil.publicClient.waitForTransactionReceipt({ hash: approveTx });

    // Lock ERC-20
    const ref = await payerRail.lock(terms);
    expect(await payeeRail.verifyLock(terms, ref)).toBe(true);

    const payeeTokensBefore = (await anvil.publicClient.readContract({
      address: anvil.tokenAddress,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [payeeAccount.address],
    })) as bigint;

    // Claim ERC-20
    await payeeRail.claim(ref, SECRET_HEX);

    const payeeTokensAfter = (await anvil.publicClient.readContract({
      address: anvil.tokenAddress,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [payeeAccount.address],
    })) as bigint;

    expect(payeeTokensAfter).toBe(payeeTokensBefore + BigInt(terms.amount));
    expect(await payeeRail.verifyLock(terms, ref)).toBe(false);
  });

  it("supports full ERC-20 lock -> refund lifecycle", async () => {
    const terms = makeErc20Terms();

    // Payer approves HTLC
    const approveTx = await anvil.payerWallet.writeContract({
      address: anvil.tokenAddress,
      abi: ERC20_ABI,
      functionName: "approve",
      args: [anvil.htlcAddress, BigInt(terms.amount)],
      account: payerAccount,
      chain: anvil.payerWallet.chain,
    });
    await anvil.publicClient.waitForTransactionReceipt({ hash: approveTx });

    // Lock ERC-20
    const ref = await payerRail.lock(terms);
    expect(await payeeRail.verifyLock(terms, ref)).toBe(true);

    const payerTokensBefore = (await anvil.publicClient.readContract({
      address: anvil.tokenAddress,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [payerAccount.address],
    })) as bigint;

    // Advance time past deadline
    const refundTs = BigInt(Math.ceil(terms.refundAfterMs / 1000));
    await advanceTimeTo(refundTs + 10n);

    // Refund ERC-20
    await payerRail.refund(ref);

    const payerTokensAfter = (await anvil.publicClient.readContract({
      address: anvil.tokenAddress,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [payerAccount.address],
    })) as bigint;

    expect(payerTokensAfter).toBe(payerTokensBefore + BigInt(terms.amount));
    expect(await payeeRail.verifyLock(terms, ref)).toBe(false);
  });

  /* -------------------------------------------------------------------------- */
  /*                  9. Explicit Rejection of Point Locks                      */
  /* -------------------------------------------------------------------------- */

  it("explicitly rejects lock: 'point' since V1 only supports hash-locks", async () => {
    const terms = makeEthTerms({ lock: "point" });
    await expect(payerRail.lock(terms)).rejects.toThrow(
      UnsupportedLockKindError,
    );
    await expect(payerRail.lock(terms)).rejects.toThrow(
      /V1 does not support "point" locks/,
    );
  });
});

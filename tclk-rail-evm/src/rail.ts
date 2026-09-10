// SPDX-License-Identifier: Apache-2.0

import {
  type Address,
  type Hash,
  type PublicClient,
  type WalletClient,
  type Account,
  zeroAddress,
  getAddress,
} from "viem";
import type {
  LockTerms,
  SettlementRail,
  EvmHtlcRailConfig,
  OnChainEscrow,
  EvmAddressResolver,
} from "./types.js";
import { EscrowStatus } from "./types.js";
import { HTLC_ABI } from "./abi.js";
import {
  toEvmTimestamp,
  isValidHex32,
  normalizeHex32,
  computeSha256,
  areAddressesEqual,
} from "./utils.js";
import {
  UnsupportedLockKindError,
  InvalidTermsError,
  EscrowNotFoundError,
  EscrowNotLockedError,
  RefundWindowOpenError,
  ClaimTooLateError,
  RefundTooEarlyError,
  InvalidSecretError,
  EvmRailError,
} from "./errors.js";

export class EvmHtlcRail implements SettlementRail {
  readonly id = "evm-htlc";

  private readonly publicClient: PublicClient;
  private readonly walletClient?: WalletClient;
  private readonly account?: Account | Address;
  private readonly htlcAddress: Address;
  private readonly addressResolver: EvmAddressResolver;
  private readonly assetResolver?: (asset: string) => Address | Promise<Address>;
  private readonly clock: () => number;
  private readonly minLockWindowMs: number;

  constructor(config: EvmHtlcRailConfig) {
    this.publicClient = config.publicClient;
    this.walletClient = config.walletClient;
    this.account = config.account;
    this.htlcAddress = getAddress(config.htlcAddress);
    this.addressResolver = config.addressResolver;
    this.clock = config.clock ?? Date.now;
    this.minLockWindowMs = config.minLockWindowMs ?? 0;

    if (typeof config.assetResolver === "function") {
      this.assetResolver = config.assetResolver;
    } else if (config.assetResolver && typeof config.assetResolver.resolve === "function") {
      const resolver = config.assetResolver;
      this.assetResolver = (asset: string) => resolver.resolve(asset);
    }
  }

  /**
   * Deposit funds on-chain under the terms; returns the rail-specific reference (terms.contract).
   */
  async lock(terms: LockTerms): Promise<string> {
    if (terms.lock !== "hash") {
      if (terms.lock === "point") {
        throw new UnsupportedLockKindError("point");
      }
      throw new InvalidTermsError(`unsupported lock kind: ${String(terms.lock)}`);
    }

    if (!isValidHex32(terms.contract)) {
      throw new InvalidTermsError(`invalid contract id: ${terms.contract}`);
    }
    if (!isValidHex32(terms.statement)) {
      throw new InvalidTermsError(`invalid statement: ${terms.statement}`);
    }
    if (terms.claimByMs >= terms.refundAfterMs) {
      throw new InvalidTermsError("claimByMs must be strictly less than refundAfterMs");
    }

    const now = this.clock();
    if (now >= terms.refundAfterMs) {
      throw new RefundWindowOpenError();
    }
    if (this.minLockWindowMs > 0 && terms.refundAfterMs - now < this.minLockWindowMs) {
      throw new RefundWindowOpenError("refund window is too close for safe inclusion");
    }

    const contractId = normalizeHex32(terms.contract);
    const hashlock = normalizeHex32(terms.statement);
    const amount = BigInt(terms.amount);
    if (amount <= 0n) {
      throw new InvalidTermsError("amount must be positive");
    }

    const refundTimestamp = toEvmTimestamp(terms.refundAfterMs);
    const payeeAddress = await this.addressResolver.resolve(terms.payee);
    const tokenAddress = await this.resolveAssetAddress(terms.asset);

    const existing = await this.read(contractId);
    if (existing && existing.status !== EscrowStatus.None) {
      throw new EvmRailError(`rail already holds a lock for ${terms.contract}`);
    }

    const wallet = this.requireWallet("lock");
    const account = this.account ?? wallet.account;
    if (!account) {
      throw new EvmRailError("account required for lock transaction");
    }

    const isEth = areAddressesEqual(tokenAddress, zeroAddress);

    const hash = await wallet.writeContract({
      address: this.htlcAddress,
      abi: HTLC_ABI,
      functionName: "lock",
      args: [contractId, payeeAddress, tokenAddress, amount, hashlock, refundTimestamp],
      value: isEth ? amount : 0n,
      account,
      chain: wallet.chain,
    });

    await this.publicClient.waitForTransactionReceipt({ hash });
    return terms.contract;
  }

  /**
   * True iff ref holds a live lock matching terms exactly. Fail-closed.
   */
  async verifyLock(terms: LockTerms, ref: string): Promise<boolean> {
    try {
      if (terms.lock !== "hash") return false;
      if (terms.claimByMs >= terms.refundAfterMs) return false;
      if (!isValidHex32(ref) || !isValidHex32(terms.contract)) return false;
      if (ref.toLowerCase() !== terms.contract.toLowerCase()) return false;

      const contractId = normalizeHex32(ref);
      const held = await this.read(contractId);
      if (!held || held.status !== EscrowStatus.Locked) return false;

      const expectedPayer = await this.addressResolver.resolve(terms.payer);
      const expectedPayee = await this.addressResolver.resolve(terms.payee);
      const expectedToken = await this.resolveAssetAddress(terms.asset);
      const expectedAmount = BigInt(terms.amount);
      const expectedRefundTimestamp = toEvmTimestamp(terms.refundAfterMs);

      return (
        held.hashlock.toLowerCase() === terms.statement.toLowerCase() &&
        held.amount === expectedAmount &&
        held.refundTimestamp === expectedRefundTimestamp &&
        areAddressesEqual(held.payer, expectedPayer) &&
        areAddressesEqual(held.payee, expectedPayee) &&
        areAddressesEqual(held.token, expectedToken)
      );
    } catch {
      return false;
    }
  }

  /**
   * Release to payee with the secret that opens the statement strictly before refund deadline.
   */
  async claim(ref: string, secret: string): Promise<void> {
    if (!isValidHex32(ref)) {
      throw new InvalidTermsError(`invalid ref: ${ref}`);
    }
    if (!isValidHex32(secret)) {
      throw new InvalidSecretError(`invalid secret format: ${secret}`);
    }

    const contractId = normalizeHex32(ref);
    const secretHash = normalizeHex32(secret);

    const held = await this.read(contractId);
    if (!held || held.status === EscrowStatus.None) {
      throw new EscrowNotFoundError(ref);
    }

    if (held.status === EscrowStatus.Claimed) {
      if (computeSha256(secretHash) !== held.hashlock.toLowerCase()) {
        throw new InvalidSecretError();
      }
      return;
    }

    if (held.status !== EscrowStatus.Locked) {
      throw new EscrowNotLockedError(ref, EscrowStatus[held.status]);
    }

    const now = this.clock();
    if (now >= Number(held.refundTimestamp) * 1000) {
      throw new ClaimTooLateError();
    }

    if (computeSha256(secretHash) !== held.hashlock.toLowerCase()) {
      throw new InvalidSecretError();
    }

    const wallet = this.requireWallet("claim");
    const account = this.account ?? wallet.account;
    if (!account) {
      throw new EvmRailError("account required for claim transaction");
    }

    try {
      const hash = await wallet.writeContract({
        address: this.htlcAddress,
        abi: HTLC_ABI,
        functionName: "claim",
        args: [contractId, secretHash],
        account,
        chain: wallet.chain,
      });

      await this.publicClient.waitForTransactionReceipt({ hash });
    } catch (err) {
      const recheck = await this.read(contractId);
      if (
        recheck &&
        recheck.status === EscrowStatus.Claimed &&
        computeSha256(secretHash) === recheck.hashlock.toLowerCase()
      ) {
        return;
      }
      throw err;
    }
  }

  /**
   * Return funds to payer at or after refundAfterMs.
   */
  async refund(ref: string): Promise<void> {
    if (!isValidHex32(ref)) {
      throw new InvalidTermsError(`invalid ref: ${ref}`);
    }

    const contractId = normalizeHex32(ref);
    const held = await this.read(contractId);
    if (!held || held.status === EscrowStatus.None) {
      throw new EscrowNotFoundError(ref);
    }
    if (held.status === EscrowStatus.Refunded) {
      return;
    }
    if (held.status !== EscrowStatus.Locked) {
      throw new EscrowNotLockedError(ref, EscrowStatus[held.status]);
    }

    const now = this.clock();
    if (now < Number(held.refundTimestamp) * 1000) {
      throw new RefundTooEarlyError();
    }

    const wallet = this.requireWallet("refund");
    const account = this.account ?? wallet.account;
    if (!account) {
      throw new EvmRailError("account required for refund transaction");
    }

    try {
      const hash = await wallet.writeContract({
        address: this.htlcAddress,
        abi: HTLC_ABI,
        functionName: "refund",
        args: [contractId],
        account,
        chain: wallet.chain,
      });

      await this.publicClient.waitForTransactionReceipt({ hash });
    } catch (err) {
      const recheck = await this.read(contractId);
      if (recheck && recheck.status === EscrowStatus.Refunded) {
        return;
      }
      throw err;
    }
  }

  /**
   * Inspect current on-chain state of an escrow.
   */
  async read(ref: string): Promise<OnChainEscrow | null> {
    if (!isValidHex32(ref)) return null;
    const contractId = normalizeHex32(ref);

    try {
      const data = await this.publicClient.readContract({
        address: this.htlcAddress,
        abi: HTLC_ABI,
        functionName: "getEscrow",
        args: [contractId],
      });

      if (data.status === EscrowStatus.None) {
        return null;
      }

      return {
        contractId: data.contractId,
        payer: data.payer,
        payee: data.payee,
        token: data.token,
        amount: data.amount,
        hashlock: data.hashlock,
        refundTimestamp: data.refundTimestamp,
        status: data.status as EscrowStatus,
      };
    } catch {
      return null;
    }
  }

  private async resolveAssetAddress(asset: string): Promise<Address> {
    if (this.assetResolver) {
      return this.assetResolver(asset);
    }
    if (asset.toUpperCase() === "ETH" || asset.toUpperCase() === "NATIVE") {
      return zeroAddress;
    }
    if (asset.startsWith("0x") && asset.length === 42) {
      return getAddress(asset);
    }
    throw new EvmRailError(`unknown asset identifier: ${asset}`);
  }

  private requireWallet(op: string): WalletClient {
    if (!this.walletClient) {
      throw new EvmRailError(`wallet client required to perform "${op}"`);
    }
    return this.walletClient;
  }
}

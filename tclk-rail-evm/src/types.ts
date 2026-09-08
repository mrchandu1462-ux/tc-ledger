// SPDX-License-Identifier: Apache-2.0

import type { PublicClient, WalletClient, Account, Address, Hash } from "viem";

export type LockKind = "hash" | "point";

/**
 * Exact LockTerms projection from accepted tclk contract state.
 */
export interface LockTerms {
  contract: string;
  lock: LockKind;
  statement: string;
  amount: string;
  asset: string;
  payer: string;
  payee: string;
  claimByMs: number;
  refundAfterMs: number;
}

/**
 * Technocore tclk/1 settlement rail interface.
 */
export interface SettlementRail {
  readonly id: string;
  lock(terms: LockTerms): Promise<string>;
  verifyLock(terms: LockTerms, ref: string): Promise<boolean>;
  claim(ref: string, secret: string): Promise<void>;
  refund(ref: string): Promise<void>;
}

export enum EscrowStatus {
  None = 0,
  Locked = 1,
  Claimed = 2,
  Refunded = 3,
}

export interface OnChainEscrow {
  contractId: Hash;
  payer: Address;
  payee: Address;
  token: Address;
  amount: bigint;
  hashlock: Hash;
  refundTimestamp: bigint;
  status: EscrowStatus;
}

export interface EvmAddressResolver {
  resolve(did: string): Promise<Address>;
}

export interface AssetResolver {
  resolve(asset: string): Promise<Address>;
}

export interface EvmHtlcRailConfig {
  publicClient: PublicClient;
  walletClient?: WalletClient;
  account?: Account | Address;
  htlcAddress: Address;
  addressResolver: EvmAddressResolver;
  assetResolver?: AssetResolver | ((asset: string) => Address | Promise<Address>);
  clock?: () => number;
  minLockWindowMs?: number;
}

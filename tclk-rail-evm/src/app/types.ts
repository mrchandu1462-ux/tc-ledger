// SPDX-License-Identifier: Apache-2.0

import type { Address, Hex, PublicClient, WalletClient, PrivateKeyAccount } from "viem";
import type { TechnocoreSigner } from "../transport.js";
import type { DealArchive } from "../archiver.js";
import type { StaticAddressResolver } from "../resolver.js";

export type SessionRole = "payer" | "payee" | "dual";

export interface WalletSessionConfig {
  htlcAddress: Address;
  chainId: number;
  rpcUrl: string;
  publicClient: PublicClient;
  walletClient: WalletClient;
  account: PrivateKeyAccount;
  signer: TechnocoreSigner;
  role?: SessionRole;
  addressResolver?: StaticAddressResolver;
}

export interface SessionMetadata {
  did: string;
  evmAddress: Address;
  chainId: number;
  role: SessionRole;
  htlcAddress: Address;
}

export interface TokenBalanceInfo {
  address: Address;
  symbol: string;
  decimals: number;
  balance: bigint;
  formatted: string;
}

export interface SessionBalance {
  nativeEth: bigint;
  formattedEth: string;
  tokens: Record<string, TokenBalanceInfo>;
}

export interface AppConfig {
  rpcUrl: string;
  chainId: number;
  htlcAddress: Address;
  updatedAtMs: number;
}

export interface ContactEntry {
  did: string;
  alias: string;
  evmAddress: Address;
  updatedAtMs: number;
}

export interface ArchivedDealSummary {
  contractId: string;
  room: string;
  status: string;
  payerDid: string;
  payeeDid: string;
  amount?: string;
  asset?: string;
  rail?: string;
  ref?: string;
  fileName: string;
  exportRoot: string;
  archivedAtMs: number;
  verifiedOffline: boolean;
}

export interface ArchiveStoreIndex {
  version: 1;
  updatedAtMs: number;
  deals: Record<string, ArchivedDealSummary>;
}

// -----------------------------------------------------------------------------
// Dedicated Errors
// -----------------------------------------------------------------------------

export class SessionError extends Error {
  constructor(message: string) {
    super(`session: ${message}`);
    this.name = "SessionError";
  }
}

export class InsecureDemoAccountError extends SessionError {
  constructor(chainId: number) {
    super(`Anvil demo accounts are restricted to local testnet (chain 31337); connected chain is ${chainId}`);
    this.name = "InsecureDemoAccountError";
  }
}

export class ArchiveStoreError extends Error {
  constructor(message: string) {
    super(`archive-store: ${message}`);
    this.name = "ArchiveStoreError";
  }
}

export class TamperedArchiveError extends ArchiveStoreError {
  constructor(public readonly contractId: string, public readonly verificationErrors: string[]) {
    super(`archive for contract ${contractId} is tampered or invalid: ${verificationErrors.join("; ")}`);
    this.name = "TamperedArchiveError";
  }
}

export class ArchiveNotFoundError extends ArchiveStoreError {
  constructor(public readonly contractId: string) {
    super(`archive not found for contract ${contractId}`);
    this.name = "ArchiveNotFoundError";
  }
}

export class InvalidContactError extends ArchiveStoreError {
  constructor(message: string) {
    super(`invalid contact: ${message}`);
    this.name = "InvalidContactError";
  }
}

export class InsecureConfigError extends ArchiveStoreError {
  constructor(message: string) {
    super(`insecure configuration: ${message}`);
    this.name = "InsecureConfigError";
  }
}

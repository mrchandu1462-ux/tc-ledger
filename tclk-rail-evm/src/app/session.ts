// SPDX-License-Identifier: Apache-2.0

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  type PrivateKeyAccount,
  formatEther,
  formatUnits,
  getAddress,
  createWalletClient,
  http,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { foundry } from "viem/chains";
import { TechnocoreSigner } from "../transport.js";
import { StaticAddressResolver } from "../resolver.js";
import { ERC20_ABI } from "../abi.js";
import { computeSha256, normalizeHex32 } from "../utils.js";
import {
  type SessionRole,
  type WalletSessionConfig,
  type SessionMetadata,
  type SessionBalance,
  type TokenBalanceInfo,
  SessionError,
  InsecureDemoAccountError,
} from "./types.js";

// Standard Anvil pre-funded test keys (strictly restricted to chainId 31337)
const ANVIL_PRIVATE_KEYS = [
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex, // Account 0
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex, // Account 1
  "0x5de4111afa1a4b93908f11f6bdd09feac5f22a21e50915a4f0e137a867ac860f" as Hex, // Account 2
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex, // Account 3
] as const;

export class WalletSession {
  public readonly htlcAddress: Address;
  public readonly chainId: number;
  public readonly rpcUrl: string;
  public readonly publicClient: PublicClient;
  public readonly walletClient: WalletClient;
  public readonly evmAddress: Address;
  public readonly role: SessionRole;
  public readonly addressResolver: StaticAddressResolver;

  // Private cryptographic instances
  private readonly _account: PrivateKeyAccount;
  private readonly _signer: TechnocoreSigner;

  // Transient in-memory storage for payee HTLC preimages (never serialized, never persisted)
  private readonly _transientPreimages = new Map<string, Hex>();

  constructor(config: WalletSessionConfig) {
    this.htlcAddress = getAddress(config.htlcAddress);
    this.chainId = config.chainId;
    this.rpcUrl = config.rpcUrl;
    this.publicClient = config.publicClient;
    this.walletClient = config.walletClient;
    this._account = config.account;
    this._signer = config.signer;
    this.evmAddress = config.account.address;
    this.role = config.role ?? "dual";
    this.addressResolver = config.addressResolver ?? new StaticAddressResolver();
  }

  // ---------------------------------------------------------------------------
  // Public Identity Getters
  // ---------------------------------------------------------------------------

  get did(): string {
    return this._signer.did;
  }

  get signer(): TechnocoreSigner {
    return this._signer;
  }

  get account(): PrivateKeyAccount {
    return this._account;
  }

  // ---------------------------------------------------------------------------
  // Safe Factories
  // ---------------------------------------------------------------------------

  /**
   * Generates a fresh in-memory session with random Ed25519 and EVM keys.
   * Nothing is written to disk.
   */
  static createRandom(params: {
    htlcAddress: Address;
    chainId: number;
    rpcUrl: string;
    publicClient: PublicClient;
    walletClient?: WalletClient;
    role?: SessionRole;
    addressResolver?: StaticAddressResolver;
  }): WalletSession {
    const signer = TechnocoreSigner.generate();
    const evmPrivKey = generatePrivateKey();
    const account = privateKeyToAccount(evmPrivKey);

    const walletClient =
      params.walletClient ??
      createWalletClient({
        account,
        chain: {
          id: params.chainId,
          name: `Chain-${params.chainId}`,
          nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
          rpcUrls: { default: { http: [params.rpcUrl] } },
        },
        transport: http(params.rpcUrl),
      });

    return new WalletSession({
      htlcAddress: params.htlcAddress,
      chainId: params.chainId,
      rpcUrl: params.rpcUrl,
      publicClient: params.publicClient,
      walletClient,
      account,
      signer,
      role: params.role,
      addressResolver: params.addressResolver,
    });
  }

  /**
   * Instantiates a session from runtime-supplied credentials.
   * Credentials are held in memory only and never serialized or logged.
   */
  static fromCredentials(
    evmPrivateKey: Hex,
    technocoreSeedOrPrivKey: Uint8Array | string,
    params: {
      htlcAddress: Address;
      chainId: number;
      rpcUrl: string;
      publicClient: PublicClient;
      walletClient?: WalletClient;
      role?: SessionRole;
      addressResolver?: StaticAddressResolver;
    },
  ): WalletSession {
    const signer =
      typeof technocoreSeedOrPrivKey === "string"
        ? TechnocoreSigner.fromSeed(technocoreSeedOrPrivKey)
        : new TechnocoreSigner(technocoreSeedOrPrivKey);

    const account = privateKeyToAccount(evmPrivateKey);

    const walletClient =
      params.walletClient ??
      createWalletClient({
        account,
        chain: {
          id: params.chainId,
          name: `Chain-${params.chainId}`,
          nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
          rpcUrls: { default: { http: [params.rpcUrl] } },
        },
        transport: http(params.rpcUrl),
      });

    return new WalletSession({
      htlcAddress: params.htlcAddress,
      chainId: params.chainId,
      rpcUrl: params.rpcUrl,
      publicClient: params.publicClient,
      walletClient,
      account,
      signer,
      role: params.role,
      addressResolver: params.addressResolver,
    });
  }

  /**
   * Instantiates a local Anvil testing session.
   * Strictly enforces that connected chainId is 31337. Rejects all other networks.
   */
  static async fromAnvil(
    accountIndex: number,
    params: {
      htlcAddress: Address;
      rpcUrl?: string;
      publicClient: PublicClient;
      walletClient?: WalletClient;
      role?: SessionRole;
      addressResolver?: StaticAddressResolver;
    },
  ): Promise<WalletSession> {
    if (accountIndex < 0 || accountIndex >= ANVIL_PRIVATE_KEYS.length) {
      throw new SessionError(`Anvil account index must be between 0 and ${ANVIL_PRIVATE_KEYS.length - 1}`);
    }

    const chainId = await params.publicClient.getChainId();
    if (chainId !== 31337) {
      throw new InsecureDemoAccountError(chainId);
    }

    const rpcUrl = params.rpcUrl ?? "http://127.0.0.1:8545";
    const evmPrivKey = ANVIL_PRIVATE_KEYS[accountIndex];
    const account = privateKeyToAccount(evmPrivKey);

    // Deterministic Ed25519 signer matching account index for repeatable testing
    const seedBytes = new Uint8Array(32).fill(accountIndex + 1);
    const signer = new TechnocoreSigner(seedBytes);

    const walletClient =
      params.walletClient ??
      createWalletClient({
        account,
        chain: foundry,
        transport: http(rpcUrl),
      });

    return new WalletSession({
      htlcAddress: params.htlcAddress,
      chainId: 31337,
      rpcUrl,
      publicClient: params.publicClient,
      walletClient,
      account,
      signer,
      role: params.role,
      addressResolver: params.addressResolver,
    });
  }

  // ---------------------------------------------------------------------------
  // Balance Queries
  // ---------------------------------------------------------------------------

  /**
   * Queries native ETH balance for the session address.
   */
  async getEthBalance(): Promise<{ balance: bigint; formatted: string }> {
    const balance = await this.publicClient.getBalance({ address: this.evmAddress });
    return {
      balance,
      formatted: formatEther(balance),
    };
  }

  /**
   * Queries ERC-20 token balance for a specified token address.
   */
  async getTokenBalance(tokenAddress: Address): Promise<TokenBalanceInfo> {
    const cleanAddress = getAddress(tokenAddress);
    const [balance, decimals, symbol] = await Promise.all([
      this.publicClient.readContract({
        address: cleanAddress,
        abi: ERC20_ABI,
        functionName: "balanceOf",
        args: [this.evmAddress],
      }) as Promise<bigint>,
      this.publicClient.readContract({
        address: cleanAddress,
        abi: ERC20_ABI,
        functionName: "decimals",
      }) as Promise<number>,
      this.publicClient.readContract({
        address: cleanAddress,
        abi: ERC20_ABI,
        functionName: "symbol",
      }) as Promise<string>,
    ]);

    return {
      address: cleanAddress,
      symbol,
      decimals,
      balance,
      formatted: formatUnits(balance, decimals),
    };
  }

  // ---------------------------------------------------------------------------
  // Address Resolution
  // ---------------------------------------------------------------------------

  async resolveCounterparty(did: string): Promise<Address> {
    return this.addressResolver.resolve(did);
  }

  registerCounterparty(did: string, evmAddress: string): void {
    this.addressResolver.set(did, evmAddress);
  }

  // ---------------------------------------------------------------------------
  // Transient Preimage Management (Payee Only, In-Memory Only)
  // ---------------------------------------------------------------------------

  /**
   * Generates a random 32-byte secret preimage and returns { secret, hashlock }.
   * Stores secret transiently in memory keyed by normalized hashlock.
   */
  createPreimage(): { secret: Hex; hashlock: Hex } {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    const secret = (`0x` + Buffer.from(randomBytes).toString("hex")) as Hex;
    const hashlock = computeSha256(secret) as Hex;

    this._transientPreimages.set(hashlock.toLowerCase(), secret);
    return { secret, hashlock };
  }

  getPreimage(hashlock: string): Hex | undefined {
    return this._transientPreimages.get(normalizeHex32(hashlock).toLowerCase());
  }

  clearPreimage(hashlock: string): void {
    this._transientPreimages.delete(normalizeHex32(hashlock).toLowerCase());
  }

  // ---------------------------------------------------------------------------
  // Safe Public Inspection & Serialization (Zero Secret Exposure)
  // ---------------------------------------------------------------------------

  getMetadata(): SessionMetadata {
    return {
      did: this.did,
      evmAddress: this.evmAddress,
      chainId: this.chainId,
      role: this.role,
      htlcAddress: this.htlcAddress,
    };
  }

  /**
   * JSON serialization strictly exposes non-sensitive public metadata only.
   * Private keys, seeds, and preimages are completely omitted.
   */
  toJSON(): SessionMetadata {
    return this.getMetadata();
  }
}

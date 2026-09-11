// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { Address, Hex } from "viem";
import {
  DealManager,
  DealStatus,
  type OfferFrame,
  type AcceptFrame,
  type LockFrame,
  type RevealFrame,
  type RefundFrame,
  type CancelFrame,
  type ReceiptFrame,
  computeContractId,
  computeOfferId,
  canonicalJson,
  toAscii,
  DealValidationError,
  InvalidDealTransitionError,
} from "../deal.js";
import {
  type TechnocoreRecord,
  type TechnocoreTransport,
  HttpTechnocoreTransport,
  RoomDealAdapter,
  type IngestResult,
  encodeTclkFrame,
  decodeTclkFrame,
  tryDecodeTclkFrame,
  isTclkLine,
  TransportError,
} from "../transport.js";
import { EvmHtlcRail } from "../rail.js";
import { EscrowStatus, type LockKind, type LockTerms, type OnChainEscrow } from "../types.js";
import { TcLedgerArchiver, type DealArchive } from "../archiver.js";
import { toEvmTimestamp } from "../utils.js";
import { WalletSession } from "./session.js";
import { ArchiveStore } from "./store.js";
import type { ArchivedDealSummary } from "./types.js";

// -----------------------------------------------------------------------------
// Orchestrator Errors
// -----------------------------------------------------------------------------

export class OrchestratorError extends Error {
  constructor(message: string) {
    super(`deal-wallet-app: ${message}`);
    this.name = "OrchestratorError";
  }
}

export class UnknownTransactionOutcomeError extends OrchestratorError {
  public override readonly cause?: unknown;
  constructor(operation: string, contractId: string, cause?: unknown) {
    super(`Transaction outcome unknown for ${operation} on contract ${contractId}. On-chain verification pending.`);
    this.name = "UnknownTransactionOutcomeError";
    this.cause = cause;
  }
}

export class PreimageNotFoundError extends OrchestratorError {
  constructor(statement: string) {
    super(`No transient preimage found for statement: ${statement}`);
    this.name = "PreimageNotFoundError";
  }
}

export class DealStateMismatchError extends OrchestratorError {
  constructor(message: string) {
    super(message);
    this.name = "DealStateMismatchError";
  }
}

export class UnauthorizedActorError extends OrchestratorError {
  constructor(message: string) {
    super(message);
    this.name = "UnauthorizedActorError";
  }
}

// -----------------------------------------------------------------------------
// Async In-Memory Mutex for Per-Contract Coordination
// -----------------------------------------------------------------------------

class AsyncLock {
  private queue: Promise<void> = Promise.resolve();

  async runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this.queue;
    let release: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.queue = previous.then(() => current);
    try {
      await previous;
      return await fn();
    } finally {
      release!();
    }
  }
}

// -----------------------------------------------------------------------------
// Configuration & Parameter Types
// -----------------------------------------------------------------------------

export interface DealWalletAppConfig {
  session: WalletSession;
  room: string;
  transport?: TechnocoreTransport; // Defaults to HttpTechnocoreTransport
  store?: ArchiveStore;           // Defaults to new ArchiveStore()
  minLockWindowMs?: number;       // Buffer for lock window
  clock?: () => number;           // Custom clock for testing / time advance
  pythonPath?: string;            // Python executable for tc_ledger
  repoRoot?: string;              // Repo root for tc_ledger execution
  autoArchive?: boolean;          // Default false
}

export interface CreateOfferParams {
  role: "payer" | "payee";
  amount: string;
  asset: string;
  lock?: LockKind;
  rails?: string[];
  claimByMs: number;
  refundAfterMs: number;
  expiresMs: number;
  counterpartyDid?: string;
  paymentKey?: string;
  job?: Record<string, unknown>;
}

export interface AcceptDealParams {
  offerId: string;
  statement?: Hex; // Optional: auto-generated from transient session preimage if payee
}

// -----------------------------------------------------------------------------
// DealWalletApp Orchestrator
// -----------------------------------------------------------------------------

export class DealWalletApp {
  public readonly session: WalletSession;
  public readonly room: string;
  public readonly transport: TechnocoreTransport;
  public readonly store: ArchiveStore;
  public readonly rail: EvmHtlcRail;
  public readonly adapter: RoomDealAdapter;
  public readonly archiver: TcLedgerArchiver;
  public readonly autoArchive: boolean;

  private readonly contractLocks = new Map<string, AsyncLock>();

  constructor(private readonly config: DealWalletAppConfig) {
    this.session = config.session;
    this.room = config.room;
    this.transport = config.transport ?? new HttpTechnocoreTransport();
    this.store = config.store ?? new ArchiveStore();
    this.autoArchive = config.autoArchive ?? false;

    // Ensure session's own identity is resolvable
    this.session.addressResolver.set(this.session.did, this.session.evmAddress);

    this.rail = new EvmHtlcRail({
      publicClient: this.session.publicClient,
      walletClient: this.session.walletClient,
      account: this.session.account,
      htlcAddress: this.session.htlcAddress,
      addressResolver: this.session.addressResolver,
      minLockWindowMs: config.minLockWindowMs ?? 0,
      clock: config.clock,
    });

    this.adapter = new RoomDealAdapter(
      this.room,
      this.transport,
      this.session.addressResolver,
    );

    this.archiver = new TcLedgerArchiver(config.pythonPath ?? "python", config.repoRoot);
  }

  private get nowMs(): number {
    return this.config.clock ? this.config.clock() : Date.now();
  }

  // ---------------------------------------------------------------------------
  // Internal Helpers
  // ---------------------------------------------------------------------------

  private getLock(contractOrOfferId: string): AsyncLock {
    const key = contractOrOfferId.toLowerCase();
    let lock = this.contractLocks.get(key);
    if (!lock) {
      lock = new AsyncLock();
      this.contractLocks.set(key, lock);
    }
    return lock;
  }

  private async withContractLock<T>(contractId: string, fn: () => Promise<T>): Promise<T> {
    const lock = this.getLock(contractId);
    return lock.runExclusive(fn);
  }

  /**
   * Validates on-chain escrow against deal terms to verify authority before reconciling.
   */
  private async validateEscrowAgainstTerms(
    contractId: string,
    terms: LockTerms,
  ): Promise<OnChainEscrow | null> {
    const held = await this.rail.read(contractId);
    if (!held || held.status === EscrowStatus.None) {
      return null;
    }
    // Verify hashlock / statement
    if (held.hashlock.toLowerCase() !== terms.statement.toLowerCase()) {
      return null;
    }
    // Verify amount
    if (held.amount !== BigInt(terms.amount)) {
      return null;
    }
    // Verify refund timestamp (in seconds)
    const expectedRefund = toEvmTimestamp(terms.refundAfterMs);
    if (held.refundTimestamp !== expectedRefund) {
      return null;
    }
    // Verify addresses if resolvable
    try {
      const expectedPayer = await this.session.addressResolver.resolve(terms.payer);
      if (held.payer.toLowerCase() !== expectedPayer.toLowerCase()) {
        return null;
      }
    } catch {
      // Ignored if unresolvable locally
    }

    try {
      const expectedPayee = await this.session.addressResolver.resolve(terms.payee);
      if (held.payee.toLowerCase() !== expectedPayee.toLowerCase()) {
        return null;
      }
    } catch {
      // Ignored if unresolvable locally
    }

    return held;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle & Synchronization
  // ---------------------------------------------------------------------------

  /**
   * Initializes the application store and synchronizes room transcript.
   */
  async start(): Promise<void> {
    await this.store.initialize();
    await this.sync();
  }

  /**
   * Synchronizes room messages in sequence order and reconciles on-chain state safely.
   */
  async sync(): Promise<IngestResult[]> {
    const records = await this.transport.fetchMessages(this.room);
    const results: IngestResult[] = [];

    for (const record of records) {
      // If record is a receipt frame with outcome: "claimed", ensure deal is transitioned to CLAIMED before applying receipt
      const frame = tryDecodeTclkFrame(record.text);
      if (frame && frame.type === "receipt" && frame.outcome === "claimed") {
        const deal = this.adapter.getDealByContractId(frame.contract);
        if (deal && deal.status === DealStatus.REVEALED) {
          deal.applyClaim();
        }
      } else if (frame && frame.type === "refund") {
        const deal = this.adapter.getDealByContractId(frame.contract);
        if (deal && !deal.isTerminal()) {
          const refundTime = Math.max(
            Date.parse(record.ts) || 0,
            this.nowMs,
            deal.terms?.refundAfterMs ?? 0,
          );
          deal.applyRefund(frame.from, refundTime);
        }
      }
      results.push(await this.adapter.ingestRecord(record));
    }

    // Reconcile active deals against authoritative EVM on-chain state
    for (const deal of this.adapter.getAllDeals()) {
      if (!deal.contractId || !deal.terms) continue;

      try {
        const held = await this.validateEscrowAgainstTerms(deal.contractId, deal.terms);
        if (!held) continue;

        if (held.status === EscrowStatus.Locked && deal.status === DealStatus.LOCKED) {
          deal.markVerified(deal.contractId);
        } else if (
          held.status === EscrowStatus.Claimed &&
          deal.status === DealStatus.REVEALED
        ) {
          deal.applyClaim();
        } else if (
          held.status === EscrowStatus.Refunded &&
          (deal.status === DealStatus.LOCKED ||
            deal.status === DealStatus.VERIFIED ||
            deal.status === DealStatus.REVEALED)
        ) {
          deal.applyRefund(deal.state.payer.did, this.nowMs);
        }
      } catch {
        // Soft error during background sync reconciliation
      }
    }

    return results;
  }

  /**
   * Sends an arbitrary chat message signed by the session identity.
   */
  async sendChat(text: string): Promise<TechnocoreRecord> {
    const record = await this.transport.sendSigned(this.room, text, this.session.signer);
    await this.adapter.ingestRecord(record);
    return record;
  }

  // ---------------------------------------------------------------------------
  // Deal Inspection
  // ---------------------------------------------------------------------------

  getDeal(contractOrOfferId: string): DealManager | undefined {
    return (
      this.adapter.getDealByContractId(contractOrOfferId) ??
      this.adapter.getDealByOfferId(contractOrOfferId)
    );
  }

  listActiveDeals(): DealManager[] {
    return this.adapter.getAllDeals().filter((d) => !d.isTerminal());
  }

  listCompletedDeals(): DealManager[] {
    return this.adapter.getAllDeals().filter((d) => d.isTerminal());
  }

  // ---------------------------------------------------------------------------
  // Protocol Actions
  // ---------------------------------------------------------------------------

  /**
   * Creates a new deal offer and broadcasts it to the room.
   */
  async createOffer(params: CreateOfferParams): Promise<{ deal: DealManager; offerId: string }> {
    const dealManager = DealManager.createOffer({
      room: this.room,
      creator: { did: this.session.did, evmAddress: this.session.evmAddress },
      role: params.role,
      counterparty: params.counterpartyDid ? { did: params.counterpartyDid } : undefined,
      amount: params.amount,
      asset: params.asset,
      lock: params.lock ?? "hash",
      rails: params.rails ?? ["evm-htlc"],
      claimByMs: params.claimByMs,
      refundAfterMs: params.refundAfterMs,
      expiresMs: params.expiresMs,
      paymentKey: params.paymentKey,
      job: params.job,
      nowMs: this.config.clock ? this.config.clock() : undefined,
    });

    const offerFrame = dealManager.state.offer;
    const line = encodeTclkFrame(offerFrame);
    const record = await this.transport.sendSigned(this.room, line, this.session.signer);
    await this.adapter.ingestRecord(record);

    const deal = this.adapter.getDealByOfferId(offerFrame.id);
    if (!deal) {
      throw new OrchestratorError("Failed to ingest created offer");
    }

    return { deal, offerId: offerFrame.id };
  }

  /**
   * Accepts an existing deal offer.
   * If caller is payee and no statement is provided, automatically generates
   * a transient preimage/hashlock in memory.
   */
  async acceptDeal(params: AcceptDealParams): Promise<{ deal: DealManager; contractId: string }> {
    return this.withContractLock(params.offerId, async () => {
      const deal = this.adapter.getDealByOfferId(params.offerId);
      if (!deal) {
        throw new OrchestratorError(`Offer not found: ${params.offerId}`);
      }

      let statement = params.statement;
      if (!statement) {
        // If caller is payee, generate transient preimage
        if (deal.state.offer.role === "payer") {
          const preimage = this.session.createPreimage();
          statement = preimage.hashlock;
        } else {
          throw new OrchestratorError("Statement hashlock must be provided when accepting as payer");
        }
      }

      const nonce = Math.random().toString(16).slice(2).padStart(16, "0");
      const acceptCore = {
        from: this.session.did,
        ref: deal.state.offer.id,
        statement,
        nonce,
      };

      const contractId = computeContractId(deal.state.offer, acceptCore);
      const acceptFrame: AcceptFrame = {
        type: "accept",
        ...acceptCore,
        contract: contractId,
      };

      const line = encodeTclkFrame(acceptFrame);
      const record = await this.transport.sendSigned(this.room, line, this.session.signer);
      await this.adapter.ingestRecord(record, this.session.evmAddress);

      return { deal, contractId };
    });
  }

  /**
   * Locks funds on the EVM HTLC contract and publishes the LockFrame.
   */
  async lockFunds(contractId: string): Promise<{ txHash?: string }> {
    return this.withContractLock(contractId, async () => {
      const deal = this.getDeal(contractId);
      if (!deal) {
        throw new OrchestratorError(`Deal not found: ${contractId}`);
      }
      if (deal.status !== DealStatus.ACCEPTED && deal.status !== DealStatus.LOCKED) {
        throw new DealStateMismatchError(`Cannot lock deal in status: ${deal.status}`);
      }
      if (deal.state.payer.did !== this.session.did) {
        throw new UnauthorizedActorError(`Only payer (${deal.state.payer.did}) can lock funds`);
      }
      if (!deal.terms) {
        throw new DealStateMismatchError("Deal terms missing from accepted contract");
      }

      // Check if already locked on-chain
      let isAlreadyLocked = false;
      try {
        isAlreadyLocked = await this.rail.verifyLock(deal.terms, contractId);
      } catch {
        // On-chain check failed, proceed with lock attempt
      }

      if (!isAlreadyLocked) {
        try {
          await this.rail.lock(deal.terms);
        } catch (err) {
          // Transaction failure handling: verify whether it executed despite error
          const held = await this.rail.read(contractId).catch(() => null);
          if (held && held.status === EscrowStatus.Locked) {
            // Succeeded on-chain!
          } else if (held && held.status === EscrowStatus.None) {
            throw err; // Definitely failed before on-chain execution
          } else {
            throw new UnknownTransactionOutcomeError("lock", contractId, err);
          }
        }
      }

      // Verify lock on-chain
      const verified = await this.rail.verifyLock(deal.terms, contractId);
      if (!verified) {
        throw new OrchestratorError("On-chain lock verification failed after submission");
      }

      // Broadcast LockFrame to room
      const lockFrame: LockFrame = {
        type: "lock",
        from: this.session.did,
        contract: contractId,
        rail: "evm-htlc",
        ref: contractId,
      };

      const line = encodeTclkFrame(lockFrame);
      const record = await this.transport.sendSigned(this.room, line, this.session.signer);
      await this.adapter.ingestRecord(record);

      return { txHash: contractId };
    });
  }

  /**
   * Verifies the on-chain lock against deal terms and marks the deal verified.
   */
  async verifyLock(contractId: string): Promise<boolean> {
    const deal = this.getDeal(contractId);
    if (!deal) {
      throw new OrchestratorError(`Deal not found: ${contractId}`);
    }
    if (!deal.terms) {
      return false;
    }

    const ref = deal.state.ref || contractId;
    const verified = await this.rail.verifyLock(deal.terms, ref);
    if (verified && deal.status === DealStatus.LOCKED) {
      deal.markVerified(ref);
    }
    return verified;
  }

  /**
   * Payee reveals the secret to the room without returning the secret.
   * Clears the transient preimage immediately afterward.
   */
  async revealSecret(contractId: string): Promise<void> {
    await this.withContractLock(contractId, async () => {
      const deal = this.getDeal(contractId);
      if (!deal) {
        throw new OrchestratorError(`Deal not found: ${contractId}`);
      }
      if (deal.status !== DealStatus.VERIFIED && deal.status !== DealStatus.LOCKED) {
        throw new DealStateMismatchError(`Cannot reveal secret in status: ${deal.status}`);
      }
      if (deal.state.payee.did !== this.session.did) {
        throw new UnauthorizedActorError(`Only payee (${deal.state.payee.did}) can reveal secret`);
      }
      if (!deal.terms) {
        throw new DealStateMismatchError("Deal terms missing");
      }

      const secret = this.session.getPreimage(deal.terms.statement);
      if (!secret) {
        throw new PreimageNotFoundError(deal.terms.statement);
      }

      const revealFrame: RevealFrame = {
        type: "reveal",
        from: this.session.did,
        contract: contractId,
        secret,
      };

      const line = encodeTclkFrame(revealFrame);
      const record = await this.transport.sendSigned(this.room, line, this.session.signer);
      await this.adapter.ingestRecord(record);

      // Wipe transient preimage from session memory
      this.session.clearPreimage(deal.terms.statement);
    });
  }

  /**
   * Executes on-chain claim using transient preimage or room reveal frame.
   * Emits terminal receipt upon completion.
   */
  async claimFunds(contractId: string): Promise<void> {
    await this.withContractLock(contractId, async () => {
      const deal = this.getDeal(contractId);
      if (!deal) {
        throw new OrchestratorError(`Deal not found: ${contractId}`);
      }
      if (!deal.terms) {
        throw new DealStateMismatchError("Deal terms missing");
      }

      // 1. Check if already claimed on-chain
      const held = await this.rail.read(contractId);
      if (held && held.status === EscrowStatus.Claimed) {
        if (deal.status === DealStatus.REVEALED) {
          deal.applyClaim();
        }
      } else {
        // Retrieve secret: from transient session or from room reveal frame
        let secret = this.session.getPreimage(deal.terms.statement);
        if (!secret) {
          // Look up RevealFrame in room messages
          const records = await this.transport.fetchMessages(this.room);
          for (const r of records) {
            const frame = tryDecodeTclkFrame(r.text);
            if (
              frame &&
              frame.type === "reveal" &&
              frame.contract.toLowerCase() === contractId.toLowerCase()
            ) {
              secret = frame.secret as Hex;
              break;
            }
          }
        }

        if (!secret) {
          throw new PreimageNotFoundError(deal.terms.statement);
        }

        try {
          await this.rail.claim(contractId, secret);
        } catch (err) {
          const recheck = await this.rail.read(contractId).catch(() => null);
          if (recheck && recheck.status === EscrowStatus.Claimed) {
            // Claim succeeded on-chain
          } else {
            throw new UnknownTransactionOutcomeError("claim", contractId, err);
          }
        }

        // Wipe preimage from session memory if present
        this.session.clearPreimage(deal.terms.statement);

        // Transition deal state
        if (deal.status === DealStatus.REVEALED) {
          deal.applyClaim();
        }
      }

      // Broadcast terminal receipt
      const receiptFrame: ReceiptFrame = {
        type: "receipt",
        from: this.session.did,
        contract: contractId,
        outcome: "claimed",
        rail: "evm-htlc",
        ref: contractId,
      };

      const line = encodeTclkFrame(receiptFrame);
      const record = await this.transport.sendSigned(this.room, line, this.session.signer);
      await this.adapter.ingestRecord(record);

      if (this.autoArchive) {
        await this.archiveDeal(contractId);
      }
    });
  }

  /**
   * Executes on-chain refund after timeout and broadcasts terminal receipt.
   */
  async refundDeal(contractId: string): Promise<void> {
    await this.withContractLock(contractId, async () => {
      const deal = this.getDeal(contractId);
      if (!deal) {
        throw new OrchestratorError(`Deal not found: ${contractId}`);
      }
      if (deal.state.payer.did !== this.session.did) {
        throw new UnauthorizedActorError(`Only payer (${deal.state.payer.did}) can execute refund`);
      }

      const held = await this.rail.read(contractId);
      if (held && held.status === EscrowStatus.Refunded) {
        if (!deal.isTerminal()) {
          deal.applyRefund(this.session.did, this.nowMs);
        }
      } else {
        try {
          await this.rail.refund(contractId);
        } catch (err) {
          const recheck = await this.rail.read(contractId).catch(() => null);
          if (recheck && recheck.status === EscrowStatus.Refunded) {
            // Succeeded on-chain
          } else {
            throw new UnknownTransactionOutcomeError("refund", contractId, err);
          }
        }

        if (!deal.isTerminal()) {
          deal.applyRefund(this.session.did, this.nowMs);
        }
      }

      // Broadcast RefundFrame
      const refundFrame: RefundFrame = {
        type: "refund",
        from: this.session.did,
        contract: contractId,
        ref: contractId,
      };
      const refundRec = await this.transport.sendSigned(
        this.room,
        encodeTclkFrame(refundFrame),
        this.session.signer,
      );
      await this.adapter.ingestRecord(refundRec);

      // Broadcast ReceiptFrame
      const receiptFrame: ReceiptFrame = {
        type: "receipt",
        from: this.session.did,
        contract: contractId,
        outcome: "refunded",
        rail: "evm-htlc",
        ref: contractId,
      };
      const receiptRec = await this.transport.sendSigned(
        this.room,
        encodeTclkFrame(receiptFrame),
        this.session.signer,
      );
      await this.adapter.ingestRecord(receiptRec);

      if (this.autoArchive) {
        await this.archiveDeal(contractId);
      }
    });
  }

  /**
   * Cancels a deal before funds are locked on-chain.
   */
  async cancelDeal(contractOrOfferId: string, reason?: string): Promise<void> {
    await this.withContractLock(contractOrOfferId, async () => {
      const deal = this.getDeal(contractOrOfferId);
      if (!deal) {
        throw new OrchestratorError(`Deal not found: ${contractOrOfferId}`);
      }

      // Ensure funds are not locked on-chain
      if (deal.contractId) {
        const held = await this.rail.read(deal.contractId);
        if (held && held.status === EscrowStatus.Locked) {
          throw new DealStateMismatchError("Cannot cancel deal with funds locked on-chain");
        }
      }

      deal.applyCancel(this.session.did, reason);

      const cancelFrame: CancelFrame = {
        type: "cancel",
        from: this.session.did,
        contract: deal.contractId || deal.state.offer.id,
        reason,
      };

      const line = encodeTclkFrame(cancelFrame);
      const record = await this.transport.sendSigned(this.room, line, this.session.signer);
      await this.adapter.ingestRecord(record);

      if (this.autoArchive) {
        await this.archiveDeal(deal.contractId || deal.state.offer.id);
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Archival & Storage
  // ---------------------------------------------------------------------------

  /**
   * Generates a verified DealArchive from room export and stores it in ArchiveStore.
   */
  async archiveDeal(contractId: string): Promise<DealArchive> {
    return this.withContractLock(contractId, async () => {
      const deal = this.getDeal(contractId);
      if (!deal) {
        throw new OrchestratorError(`Deal not found: ${contractId}`);
      }
      if (!deal.isTerminal()) {
        throw new DealStateMismatchError(`Cannot archive non-terminal deal (${deal.status})`);
      }

      // 1. Fetch complete room transcript
      const records = await this.transport.exportRoom(this.room);

      // 2. Write exact JSONL lines to a temporary file
      const tmpDir = path.join(os.tmpdir(), "tc-deal-wallet-exports");
      if (!fs.existsSync(tmpDir)) {
        fs.mkdirSync(tmpDir, { recursive: true });
      }
      const tempExportPath = path.join(
        tmpDir,
        `${this.room}-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`,
      );

      try {
        const lines = records.map((r) => {
          return (
            JSON.stringify({
              seq: r.seq,
              ts: r.ts,
              from: r.from,
              text: r.text,
              nonce: r.nonce,
              sig: r.sig,
            }) + "\n"
          );
        });
        fs.writeFileSync(tempExportPath, lines.join(""), "utf8");

        // 3. Check if settled on-chain for evidence
        let onChainVerified = false;
        if (deal.terms && deal.contractId) {
          const held = await this.rail.read(deal.contractId);
          onChainVerified = held !== null && held.status !== EscrowStatus.None;
        }

        // 4. Archive deal via TcLedgerArchiver
        const archive = await this.archiver.archiveDeal(deal, tempExportPath, {
          pythonPath: this.config.pythonPath,
          onChainVerified,
          settlementRef: deal.state.ref,
        });

        // 5. Persist via ArchiveStore (enforces offline cryptographic verification)
        await this.store.saveArchive(archive);

        return archive;
      } finally {
        if (fs.existsSync(tempExportPath)) {
          fs.unlinkSync(tempExportPath);
        }
      }
    });
  }

  /**
   * Lists summaries of all verified stored archives.
   */
  async listArchives(): Promise<ArchivedDealSummary[]> {
    return this.store.listArchives();
  }

  /**
   * Loads a verified archive from storage.
   */
  async getArchive(contractId: string): Promise<DealArchive> {
    return this.store.loadArchive(contractId);
  }
}

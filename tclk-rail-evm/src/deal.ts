// SPDX-License-Identifier: Apache-2.0

import { sha256 } from "@noble/hashes/sha2.js";
import type { Address, Hash } from "viem";
import type { LockKind, LockTerms } from "./types.js";
import {
  computeSha256,
  isValidHex32,
  normalizeHex32,
  bytesToHex,
} from "./utils.js";

/**
 * tclk/1 protocol domain identifier for canonical domain separation.
 */
export const TCLK_DOMAIN = "FLOP::tclk::v1";

/**
 * Standard lifecycle states for a Technocore tclk/1 deal.
 */
export enum DealStatus {
  OFFERED = "OFFERED",
  ACCEPTED = "ACCEPTED",
  LOCKED = "LOCKED",
  VERIFIED = "VERIFIED",
  REVEALED = "REVEALED",
  CLAIMED = "CLAIMED",
  REFUNDED = "REFUNDED",
  CANCELLED = "CANCELLED",
}

/**
 * Error classes for deal coordination and transition validation.
 */
export class DealError extends Error {
  constructor(message: string) {
    super(`deal-manager: ${message}`);
    this.name = "DealError";
  }
}

export class InvalidDealTransitionError extends DealError {
  constructor(from: DealStatus, to: DealStatus, reason?: string) {
    super(`invalid transition from ${from} to ${to}${reason ? `: ${reason}` : ""}`);
    this.name = "InvalidDealTransitionError";
  }
}

export class DealValidationError extends DealError {
  constructor(reason: string) {
    super(`validation failed: ${reason}`);
    this.name = "DealValidationError";
  }
}

/**
 * Participant identity binding a Technocore DID (Ed25519) to an optional EVM address.
 */
export interface ParticipantIdentity {
  did: string;
  evmAddress?: Address;
}

/**
 * Wire frame structures derived from tclk/1 specification.
 */
export interface OfferFrame {
  type: "offer";
  from: string;
  role: "payer" | "payee";
  amount: string;
  asset: string;
  lock: LockKind;
  rails: string[];
  claimByMs: number;
  refundAfterMs: number;
  expiresMs: number;
  nonce: string;
  id: string;
  paymentKey?: string;
  job?: Record<string, unknown>;
}

export interface AcceptCore {
  from: string;
  ref: string;
  statement: string;
  paymentKey?: string;
  nonce: string;
}

export interface AcceptFrame extends AcceptCore {
  type: "accept";
  contract: string;
}

export interface LockFrame {
  type: "lock";
  from: string;
  contract: string;
  rail: string;
  ref: string;
  presig?: Record<string, unknown>;
}

export interface RevealFrame {
  type: "reveal";
  from: string;
  contract: string;
  ref?: string;
  secret: string;
}

export interface RefundFrame {
  type: "refund";
  from: string;
  contract: string;
  ref?: string;
  reason?: string;
}

export interface CancelFrame {
  type: "cancel";
  from: string;
  contract: string;
  reason?: string;
}

export interface ReceiptFrame {
  type: "receipt";
  from: string;
  contract: string;
  outcome: "claimed" | "refunded" | "cancelled";
  rail?: string;
  ref?: string;
}

/**
 * Mapping structure to later correlate the deal with Technocore room export lines
 * and TC Ledger Merkle commitment / inclusion proofs.
 */
export interface DealLedgerEvidence {
  room: string;
  recordSequences: {
    offerSeq?: number;
    acceptSeq?: number;
    lockSeq?: number;
    revealSeq?: number;
    claimSeq?: number;
    refundSeq?: number;
    receiptSeq?: number;
  };
  signedRecordHashes: Record<string, string>;
  exportRoot?: string;
  inclusionProof?: Record<string, unknown>;
  inclusionProofs?: Record<string, Record<string, unknown>>;
  commitmentArtifact?: Record<string, unknown>;
}

/**
 * Complete deal record state representation.
 * NOTE: Does NOT store or expose raw secret preimages.
 */
export interface DealRecord {
  contractId: string;
  room: string;
  status: DealStatus;
  payer: ParticipantIdentity;
  payee: ParticipantIdentity;
  terms?: LockTerms;
  offer: OfferFrame;
  accept?: AcceptFrame;
  rail?: string;
  ref?: string;
  secretRevealed?: boolean;
  secretHash?: string;
  createdAtMs: number;
  updatedAtMs: number;
  receipt?: ReceiptFrame;
  ledgerEvidence: DealLedgerEvidence;
}

// -----------------------------------------------------------------------------
// Canonicalization and Identifier Derivation
// -----------------------------------------------------------------------------

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) representation:
 * Deterministic JSON with lexicographically sorted keys and compact formatting.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new DealValidationError("unsupported value");
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

/**
 * Escapes non-ASCII characters to standard Unicode escape sequences (\uXXXX)
 * ensuring stored bytes match signed wire bytes.
 */
export function toAscii(json: string): string {
  return json.replace(
    /[\u0080-\uffff]/g,
    (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

/**
 * Domain-tagged SHA-256 hash according to tclk/1 specification.
 */
export function domainHash(tag: string, payload: string): Hash {
  const bytes = new TextEncoder().encode(`${TCLK_DOMAIN}|${tag}|${toAscii(payload)}`);
  return bytesToHex(sha256(bytes)).toLowerCase() as Hash;
}

/**
 * Computes tclk/1 offer id from offer fields.
 */
export function computeOfferId(fields: Omit<OfferFrame, "id">): Hash {
  return domainHash("offer", canonicalJson(fields));
}

/**
 * Computes tclk/1 contract id from offer and accept core.
 */
export function computeContractId(offer: OfferFrame, accept: AcceptCore): Hash {
  return domainHash("contract", canonicalJson({ offer, accept }));
}

/**
 * Projects LockTerms from accepted tclk/1 offer and accept frames.
 */
export function projectLockTerms(offer: OfferFrame, accept: AcceptFrame): LockTerms {
  const payer = offer.role === "payer" ? offer.from : accept.from;
  const payee = offer.role === "payee" ? offer.from : accept.from;
  return {
    contract: accept.contract,
    lock: offer.lock,
    statement: accept.statement,
    amount: offer.amount,
    asset: offer.asset,
    payer,
    payee,
    claimByMs: offer.claimByMs,
    refundAfterMs: offer.refundAfterMs,
  };
}

// -----------------------------------------------------------------------------
// Deal Manager Core
// -----------------------------------------------------------------------------

export interface CreateDealOfferParams {
  room: string;
  creator: ParticipantIdentity;
  role: "payer" | "payee";
  counterparty?: ParticipantIdentity;
  amount: string;
  asset: string;
  lock?: LockKind;
  rails?: string[];
  claimByMs: number;
  refundAfterMs: number;
  expiresMs: number;
  nonce?: string;
  paymentKey?: string;
  job?: Record<string, unknown>;
  nowMs?: number;
}

/**
 * DealManager orchestrates the tclk/1 deal state machine with explicit,
 * fail-closed transition checks and evidence tracking.
 */
export class DealManager {
  private record: DealRecord;

  constructor(initialRecord: DealRecord) {
    this.record = {
      ...initialRecord,
      ledgerEvidence: {
        room: initialRecord.room,
        recordSequences: { ...initialRecord.ledgerEvidence?.recordSequences },
        signedRecordHashes: { ...initialRecord.ledgerEvidence?.signedRecordHashes },
        exportRoot: initialRecord.ledgerEvidence?.exportRoot,
        inclusionProof: initialRecord.ledgerEvidence?.inclusionProof,
        inclusionProofs: { ...initialRecord.ledgerEvidence?.inclusionProofs },
        commitmentArtifact: initialRecord.ledgerEvidence?.commitmentArtifact,
      },
    };
  }

  /**
   * Initializes a new deal in the OFFERED state.
   */
  static createOffer(params: CreateDealOfferParams): DealManager {
    if (!params.room || typeof params.room !== "string") {
      throw new DealValidationError("room identifier is required");
    }
    if (!params.creator?.did) {
      throw new DealValidationError("creator did is required");
    }
    if (params.claimByMs >= params.refundAfterMs) {
      throw new DealValidationError("claimByMs must be strictly less than refundAfterMs");
    }
    const now = params.nowMs ?? Date.now();
    if (now >= params.expiresMs) {
      throw new DealValidationError("offer is already expired");
    }
    if (BigInt(params.amount) <= 0n) {
      throw new DealValidationError("amount must be positive");
    }

    const nonce = params.nonce ?? Math.random().toString(16).slice(2).padStart(16, "0");
    const rails = params.rails && params.rails.length > 0 ? [...new Set(params.rails)].sort() : ["evm-htlc"];

    const offerFields: Omit<OfferFrame, "id"> = {
      type: "offer",
      from: params.creator.did,
      role: params.role,
      amount: params.amount,
      asset: params.asset,
      lock: params.lock ?? "hash",
      rails,
      claimByMs: params.claimByMs,
      refundAfterMs: params.refundAfterMs,
      expiresMs: params.expiresMs,
      nonce,
      paymentKey: params.paymentKey,
      job: params.job,
    };

    const id = computeOfferId(offerFields);
    const offer: OfferFrame = { ...offerFields, id };

    const payer: ParticipantIdentity =
      params.role === "payer"
        ? params.creator
        : params.counterparty ?? { did: "" };

    const payee: ParticipantIdentity =
      params.role === "payee"
        ? params.creator
        : params.counterparty ?? { did: "" };

    const dealRecord: DealRecord = {
      contractId: "", // Pending counterparty accept
      room: params.room,
      status: DealStatus.OFFERED,
      payer,
      payee,
      offer,
      createdAtMs: now,
      updatedAtMs: now,
      ledgerEvidence: {
        room: params.room,
        recordSequences: {},
        signedRecordHashes: {},
      },
    };

    return new DealManager(dealRecord);
  }

  get state(): Readonly<DealRecord> {
    return this.record;
  }

  get status(): DealStatus {
    return this.record.status;
  }

  get contractId(): string {
    return this.record.contractId;
  }

  get terms(): LockTerms | undefined {
    return this.record.terms;
  }

  get room(): string {
    return this.record.room;
  }

  isTerminal(): boolean {
    return (
      this.record.status === DealStatus.CLAIMED ||
      this.record.status === DealStatus.REFUNDED ||
      this.record.status === DealStatus.CANCELLED
    );
  }

  /**
   * Applies an accept frame closing contract terms.
   * Computes and verifies the exact contractId and projects LockTerms.
   */
  applyAccept(accept: AcceptFrame, counterpartyEvmAddress?: Address, nowMs?: number): void {
    if (this.record.status === DealStatus.ACCEPTED) {
      if (this.record.contractId.toLowerCase() === accept.contract.toLowerCase()) return; // Idempotent
      throw new InvalidDealTransitionError(
        this.record.status,
        DealStatus.ACCEPTED,
        "contract already accepted under different contractId",
      );
    }
    if (this.record.status !== DealStatus.OFFERED) {
      throw new InvalidDealTransitionError(this.record.status, DealStatus.ACCEPTED);
    }

    if (accept.ref !== this.record.offer.id) {
      throw new DealValidationError(`accept ref mismatch: expected ${this.record.offer.id}, got ${accept.ref}`);
    }
    if (accept.from === this.record.offer.from) {
      throw new DealValidationError("accept.from must differ from offer.from");
    }

    const now = nowMs ?? Date.now();
    if (now >= this.record.offer.expiresMs) {
      throw new DealValidationError("cannot accept expired offer");
    }

    if (!isValidHex32(accept.statement)) {
      throw new DealValidationError(`invalid statement format: ${accept.statement}`);
    }

    const acceptCore: AcceptCore = {
      from: accept.from,
      ref: accept.ref,
      statement: normalizeHex32(accept.statement),
      paymentKey: accept.paymentKey,
      nonce: accept.nonce,
    };

    const expectedContractId = computeContractId(this.record.offer, acceptCore);
    if (accept.contract.toLowerCase() !== expectedContractId.toLowerCase()) {
      throw new DealValidationError(
        `contractId mismatch: expected ${expectedContractId}, got ${accept.contract}`,
      );
    }

    const terms = projectLockTerms(this.record.offer, accept);
    if (terms.claimByMs >= terms.refundAfterMs) {
      throw new DealValidationError("terms violate claimByMs < refundAfterMs");
    }

    // Update identities
    if (this.record.offer.role === "payer") {
      this.record.payee = { did: accept.from, evmAddress: counterpartyEvmAddress };
    } else {
      this.record.payer = { did: accept.from, evmAddress: counterpartyEvmAddress };
    }

    this.record.contractId = expectedContractId;
    this.record.accept = accept;
    this.record.terms = terms;
    this.record.status = DealStatus.ACCEPTED;
    this.record.updatedAtMs = now;
  }

  /**
   * Records on-chain escrow lock reference.
   */
  applyLock(lock: LockFrame, nowMs?: number): void {
    if (this.record.status === DealStatus.LOCKED) {
      if (this.record.ref === lock.ref && this.record.rail === lock.rail) return; // Idempotent
      throw new InvalidDealTransitionError(this.record.status, DealStatus.LOCKED, "lock already recorded with different ref");
    }
    if (this.record.status !== DealStatus.ACCEPTED) {
      throw new InvalidDealTransitionError(this.record.status, DealStatus.LOCKED);
    }

    if (lock.contract.toLowerCase() !== this.record.contractId.toLowerCase()) {
      throw new DealValidationError(`lock contract mismatch: expected ${this.record.contractId}, got ${lock.contract}`);
    }
    if (lock.from !== this.record.payer.did) {
      throw new DealValidationError(`only payer (${this.record.payer.did}) can issue lock frame`);
    }
    if (!this.record.offer.rails.includes(lock.rail)) {
      throw new DealValidationError(`rail ${lock.rail} was not included in offer rails`);
    }

    const now = nowMs ?? Date.now();
    if (this.record.terms && now >= this.record.terms.refundAfterMs) {
      throw new DealValidationError("cannot lock into an expired refund window");
    }

    this.record.rail = lock.rail;
    this.record.ref = lock.ref;
    this.record.status = DealStatus.LOCKED;
    this.record.updatedAtMs = now;
  }

  /**
   * Marks the lock as verified against the on-chain settlement rail.
   */
  markVerified(ref?: string): void {
    if (this.record.status === DealStatus.VERIFIED) {
      if (!ref || ref === this.record.ref) return; // Idempotent
      throw new InvalidDealTransitionError(this.record.status, DealStatus.VERIFIED, "already verified under different ref");
    }
    if (this.record.status !== DealStatus.LOCKED) {
      throw new InvalidDealTransitionError(this.record.status, DealStatus.VERIFIED);
    }
    if (ref && ref !== this.record.ref) {
      throw new DealValidationError(`verified ref mismatch: expected ${this.record.ref}, got ${ref}`);
    }

    this.record.status = DealStatus.VERIFIED;
    this.record.updatedAtMs = Date.now();
  }

  /**
   * Validates secret preimage reveal without persisting the raw secret in the deal record.
   */
  applyReveal(secret: string, from: string, nowMs?: number): void {
    if (!isValidHex32(secret)) {
      throw new DealValidationError(`invalid secret format: ${secret}`);
    }
    const secretHash = computeSha256(normalizeHex32(secret));

    if (this.record.status === DealStatus.REVEALED) {
      if (this.record.secretHash === secretHash) return; // Idempotent
      throw new InvalidDealTransitionError(this.record.status, DealStatus.REVEALED, "revealed with different secret");
    }
    if (this.record.status !== DealStatus.VERIFIED && this.record.status !== DealStatus.LOCKED) {
      throw new InvalidDealTransitionError(this.record.status, DealStatus.REVEALED);
    }

    if (from !== this.record.payee.did) {
      throw new DealValidationError(`only payee (${this.record.payee.did}) can reveal secret`);
    }

    if (!this.record.terms || secretHash !== this.record.terms.statement.toLowerCase()) {
      throw new DealValidationError("secret preimage does not open the statement");
    }

    const now = nowMs ?? Date.now();
    if (now >= this.record.terms.refundAfterMs) {
      throw new DealValidationError("reveal occurred after refund deadline");
    }

    // Record verified reveal evidence WITHOUT storing plaintext secret
    this.record.secretRevealed = true;
    this.record.secretHash = secretHash;
    this.record.status = DealStatus.REVEALED;
    this.record.updatedAtMs = now;
  }

  /**
   * Confirms settlement claim completion (terminal).
   */
  applyClaim(nowMs?: number): void {
    if (this.record.status === DealStatus.CLAIMED) return; // Idempotent
    if (this.record.status !== DealStatus.REVEALED) {
      throw new InvalidDealTransitionError(
        this.record.status,
        DealStatus.CLAIMED,
        "must be in REVEALED state before confirming claim",
      );
    }

    this.record.status = DealStatus.CLAIMED;
    this.record.updatedAtMs = nowMs ?? Date.now();
  }

  /**
   * Confirms escrow refund completion (terminal).
   */
  applyRefund(from: string, nowMs: number): void {
    if (this.record.status === DealStatus.REFUNDED) return; // Idempotent
    if (
      this.record.status !== DealStatus.LOCKED &&
      this.record.status !== DealStatus.VERIFIED &&
      this.record.status !== DealStatus.REVEALED
    ) {
      throw new InvalidDealTransitionError(this.record.status, DealStatus.REFUNDED);
    }

    if (from !== this.record.payer.did) {
      throw new DealValidationError(`only payer (${this.record.payer.did}) can execute refund`);
    }

    if (this.record.terms && nowMs < this.record.terms.refundAfterMs) {
      throw new DealValidationError("cannot refund before refund deadline");
    }

    this.record.status = DealStatus.REFUNDED;
    this.record.updatedAtMs = nowMs;
  }

  /**
   * Cancels a deal before any funds are locked on-chain (terminal).
   */
  applyCancel(from: string, reason?: string, nowMs?: number): void {
    if (this.record.status === DealStatus.CANCELLED) return; // Idempotent
    if (this.record.status !== DealStatus.OFFERED && this.record.status !== DealStatus.ACCEPTED) {
      throw new InvalidDealTransitionError(
        this.record.status,
        DealStatus.CANCELLED,
        "cannot cancel after funds are locked",
      );
    }

    if (from !== this.record.payer.did && from !== this.record.payee.did && from !== this.record.offer.from) {
      throw new DealValidationError("only deal participants can cancel");
    }

    this.record.status = DealStatus.CANCELLED;
    this.record.updatedAtMs = nowMs ?? Date.now();
  }

  /**
   * Records a terminal post-settlement receipt frame.
   */
  applyReceipt(receipt: ReceiptFrame): void {
    if (!this.isTerminal()) {
      throw new DealValidationError("cannot apply receipt to non-terminal deal");
    }
    if (receipt.contract.toLowerCase() !== this.record.contractId.toLowerCase()) {
      throw new DealValidationError("receipt contract mismatch");
    }
    if (receipt.outcome !== this.record.status.toLowerCase()) {
      throw new DealValidationError(
        `receipt outcome mismatch: expected ${this.record.status.toLowerCase()}, got ${receipt.outcome}`,
      );
    }

    this.record.receipt = receipt;
    this.record.updatedAtMs = Date.now();
  }

  /**
   * Records sequence numbers and hashes for later TC Ledger Merkle verification.
   */
  recordLedgerSequence(
    stage: keyof DealLedgerEvidence["recordSequences"],
    seq: number,
    signedRecordHash?: string,
  ): void {
    this.record.ledgerEvidence.recordSequences[stage] = seq;
    if (signedRecordHash) {
      this.record.ledgerEvidence.signedRecordHashes[stage] = signedRecordHash;
    }
  }

  /**
   * Attaches committed Merkle root and proof artifact.
   */
  attachLedgerCommitment(
    exportRoot: string,
    inclusionProof?: Record<string, unknown>,
    inclusionProofs?: Record<string, Record<string, unknown>>,
    commitmentArtifact?: Record<string, unknown>,
  ): void {
    this.record.ledgerEvidence.exportRoot = exportRoot;
    if (inclusionProof) {
      this.record.ledgerEvidence.inclusionProof = inclusionProof;
    }
    if (inclusionProofs) {
      this.record.ledgerEvidence.inclusionProofs = inclusionProofs;
    }
    if (commitmentArtifact) {
      this.record.ledgerEvidence.commitmentArtifact = commitmentArtifact;
    }
  }
}

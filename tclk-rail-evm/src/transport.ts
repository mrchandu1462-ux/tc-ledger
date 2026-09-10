// SPDX-License-Identifier: Apache-2.0

import { ed25519 } from "@noble/curves/ed25519.js";
import { base58, base64urlnopad } from "@scure/base";
import type { Address } from "viem";
import {
  DealManager,
  type OfferFrame,
  type AcceptFrame,
  type LockFrame,
  type RevealFrame,
  type RefundFrame,
  type CancelFrame,
  type ReceiptFrame,
  canonicalJson,
  toAscii,
  computeOfferId,
  computeContractId,
  DealValidationError,
} from "./deal.js";
import type { EvmAddressResolver } from "./types.js";
import { computeSha256, isValidHex32 } from "./utils.js";

/** Prefix required for all tclk/1 wire frames */
export const TCLK_PREFIX = "tclk1 " as const;
export const MAX_FRAME_CHARS = 4096;

/** Multicodec header for Ed25519 public key (0xed, 0x01) */
const MULTICODEC_ED25519 = new Uint8Array([0xed, 0x01]);

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

export class TransportError extends Error {
  constructor(message: string) {
    super(`technocore-transport: ${message}`);
    this.name = "TransportError";
  }
}

export class InvalidSignatureError extends TransportError {
  constructor(reason: string) {
    super(`invalid signature: ${reason}`);
    this.name = "InvalidSignatureError";
  }
}

export class InvalidRoomError extends TransportError {
  constructor(expected: string, got: string) {
    super(`room mismatch: expected ${expected}, got ${got}`);
    this.name = "InvalidRoomError";
  }
}

export class MalformedFrameError extends TransportError {
  constructor(reason: string) {
    super(`malformed frame: ${reason}`);
    this.name = "MalformedFrameError";
  }
}

export class DealNotFoundError extends TransportError {
  constructor(ref: string) {
    super(`deal not found for ref ${ref}`);
    this.name = "DealNotFoundError";
  }
}

// -----------------------------------------------------------------------------
// Text Sweeping and Canonical String
// -----------------------------------------------------------------------------

/**
 * Text sweeping matching Technocore's store.py / sign.py clean_text:
 * Characters with Unicode category Cc, Cf, Cs, Co, Zl, Zp become spaces, trimmed.
 */
export function sweptText(text: string): string {
  const cleaned = text.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu, " ").trim();
  if (cleaned.length === 0) {
    throw new TransportError("nothing visible left after sweep");
  }
  if (cleaned.length > MAX_FRAME_CHARS) {
    throw new TransportError(`text exceeds ${MAX_FRAME_CHARS} character cap`);
  }
  return cleaned;
}

// -----------------------------------------------------------------------------
// Technocore Signer / Verifier
// -----------------------------------------------------------------------------

export class TechnocoreSigner {
  public readonly privateKey: Uint8Array;
  public readonly publicKey: Uint8Array;
  public readonly did: string;

  constructor(privateKey: Uint8Array) {
    if (privateKey.length !== 32) {
      throw new TransportError("private key must be 32 bytes");
    }
    this.privateKey = privateKey;
    this.publicKey = ed25519.getPublicKey(privateKey);

    // did:key = "did:key:z" + base58(0xed01 + pubKey)
    const multicodecKey = new Uint8Array(2 + this.publicKey.length);
    multicodecKey.set(MULTICODEC_ED25519, 0);
    multicodecKey.set(this.publicKey, 2);
    this.did = `did:key:z${base58.encode(multicodecKey)}`;
  }

  static generate(): TechnocoreSigner {
    const privKey = crypto.getRandomValues(new Uint8Array(32));
    return new TechnocoreSigner(privKey);
  }

  static fromSeed(seedHexOrPassphrase: string): TechnocoreSigner {
    if (/^[0-9a-fA-F]{64}$/.test(seedHexOrPassphrase)) {
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        bytes[i] = parseInt(seedHexOrPassphrase.slice(i * 2, i * 2 + 2), 16);
      }
      return new TechnocoreSigner(bytes);
    }
    // Hash passphrase with SHA-256 (matching sign.py behavior)
    const digest = computeSha256(
      "0x" + Buffer.from(seedHexOrPassphrase, "utf-8").toString("hex"),
    ).slice(2);
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(digest.slice(i * 2, i * 2 + 2), 16);
    }
    return new TechnocoreSigner(bytes);
  }

  /**
   * Signs a Technocore room message:
   * Canonical string: `${room}|${nonce}|${swept(text)}`
   */
  sign(room: string, nonce: string | number, text: string): string {
    const swept = sweptText(text);
    const canonical = `${room}|${nonce}|${swept}`;
    const sigBytes = ed25519.sign(new TextEncoder().encode(canonical), this.privateKey);
    return base64urlnopad.encode(sigBytes);
  }

  /**
   * Extracts Ed25519 public key bytes from a did:key string.
   */
  static publicKeyFromDid(did: string): Uint8Array {
    if (!did.startsWith("did:key:z")) {
      throw new InvalidSignatureError("did must start with did:key:z");
    }
    const mb = did.slice("did:key:z".length);
    const raw = base58.decode(mb);
    if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) {
      throw new InvalidSignatureError("not an Ed25519 did:key multicodec");
    }
    return raw.slice(2);
  }

  /**
   * Verifies an Ed25519 signature over `${room}|${nonce}|${swept(text)}`.
   */
  static verify(
    room: string,
    nonce: string | number,
    text: string,
    signatureBase64Url: string,
    did: string,
  ): boolean {
    try {
      const pubKey = TechnocoreSigner.publicKeyFromDid(did);
      const sigBytes = base64urlnopad.decode(signatureBase64Url);
      if (sigBytes.length !== 64) return false;
      const swept = sweptText(text);
      const canonical = `${room}|${nonce}|${swept}`;
      return ed25519.verify(sigBytes, new TextEncoder().encode(canonical), pubKey);
    } catch {
      return false;
    }
  }
}

// -----------------------------------------------------------------------------
// tclk/1 Frame Parser & Formatter
// -----------------------------------------------------------------------------

export type TclkFrame =
  | OfferFrame
  | AcceptFrame
  | LockFrame
  | RevealFrame
  | RefundFrame
  | CancelFrame
  | ReceiptFrame;

export function isTclkLine(text: string): boolean {
  return typeof text === "string" && text.startsWith(TCLK_PREFIX);
}

export function encodeTclkFrame(frame: TclkFrame): string {
  const json = toAscii(canonicalJson(frame));
  const line = `${TCLK_PREFIX}${json}`;
  if (line.length > MAX_FRAME_CHARS) {
    throw new MalformedFrameError(`frame exceeds ${MAX_FRAME_CHARS} char limit`);
  }
  return line;
}

export function decodeTclkFrame(text: string): TclkFrame {
  if (!isTclkLine(text)) {
    throw new MalformedFrameError("not a tclk/1 frame line");
  }
  if (text.length > MAX_FRAME_CHARS) {
    throw new MalformedFrameError(`frame exceeds ${MAX_FRAME_CHARS} chars`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.slice(TCLK_PREFIX.length));
  } catch {
    throw new MalformedFrameError("invalid JSON payload");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new MalformedFrameError("frame must be a JSON object");
  }

  const obj = parsed as Record<string, unknown>;
  const type = obj.type;
  if (typeof type !== "string") {
    throw new MalformedFrameError("frame is missing type field");
  }

  switch (type) {
    case "offer": {
      if (typeof obj.from !== "string" || !obj.from.startsWith("did:key:")) {
        throw new MalformedFrameError("offer frame invalid 'from' DID");
      }
      if (obj.role !== "payer" && obj.role !== "payee") {
        throw new MalformedFrameError("offer frame invalid 'role'");
      }
      if (typeof obj.amount !== "string" || !/^[1-9][0-9]*$/.test(obj.amount)) {
        throw new MalformedFrameError("offer frame invalid 'amount'");
      }
      if (typeof obj.asset !== "string" || !obj.asset) {
        throw new MalformedFrameError("offer frame missing 'asset'");
      }
      if (obj.lock !== "hash" && obj.lock !== "point") {
        throw new MalformedFrameError("offer frame invalid 'lock'");
      }
      if (!Array.isArray(obj.rails) || obj.rails.length === 0) {
        throw new MalformedFrameError("offer frame requires non-empty rails array");
      }
      if (typeof obj.claimByMs !== "number" || typeof obj.refundAfterMs !== "number") {
        throw new MalformedFrameError("offer frame requires numeric deadlines");
      }
      if (obj.claimByMs >= obj.refundAfterMs) {
        throw new MalformedFrameError("offer claimByMs must be strictly less than refundAfterMs");
      }
      if (typeof obj.expiresMs !== "number") {
        throw new MalformedFrameError("offer frame requires numeric expiresMs");
      }
      if (typeof obj.nonce !== "string") {
        throw new MalformedFrameError("offer frame requires nonce");
      }
      if (typeof obj.id !== "string" || !isValidHex32(obj.id)) {
        throw new MalformedFrameError("offer frame invalid id");
      }
      return obj as unknown as OfferFrame;
    }

    case "accept": {
      if (typeof obj.from !== "string" || !obj.from.startsWith("did:key:")) {
        throw new MalformedFrameError("accept frame invalid 'from' DID");
      }
      if (typeof obj.ref !== "string" || !isValidHex32(obj.ref)) {
        throw new MalformedFrameError("accept frame invalid 'ref'");
      }
      if (typeof obj.statement !== "string" || !isValidHex32(obj.statement)) {
        throw new MalformedFrameError("accept frame invalid 'statement'");
      }
      if (typeof obj.contract !== "string" || !isValidHex32(obj.contract)) {
        throw new MalformedFrameError("accept frame invalid 'contract'");
      }
      if (typeof obj.nonce !== "string") {
        throw new MalformedFrameError("accept frame requires nonce");
      }
      return obj as unknown as AcceptFrame;
    }

    case "lock": {
      if (typeof obj.from !== "string") throw new MalformedFrameError("lock frame missing 'from'");
      if (typeof obj.contract !== "string" || !isValidHex32(obj.contract)) {
        throw new MalformedFrameError("lock frame invalid 'contract'");
      }
      if (typeof obj.rail !== "string" || !obj.rail) {
        throw new MalformedFrameError("lock frame missing 'rail'");
      }
      if (typeof obj.ref !== "string" || !obj.ref) {
        throw new MalformedFrameError("lock frame missing 'ref'");
      }
      return obj as unknown as LockFrame;
    }

    case "reveal": {
      if (typeof obj.from !== "string") throw new MalformedFrameError("reveal frame missing 'from'");
      if (typeof obj.contract !== "string" || !isValidHex32(obj.contract)) {
        throw new MalformedFrameError("reveal frame invalid 'contract'");
      }
      if (typeof obj.secret !== "string" || !isValidHex32(obj.secret)) {
        throw new MalformedFrameError("reveal frame invalid 'secret'");
      }
      return obj as unknown as RevealFrame;
    }

    case "refund": {
      if (typeof obj.from !== "string") throw new MalformedFrameError("refund frame missing 'from'");
      if (typeof obj.contract !== "string" || !isValidHex32(obj.contract)) {
        throw new MalformedFrameError("refund frame invalid 'contract'");
      }
      return obj as unknown as RefundFrame;
    }

    case "cancel": {
      if (typeof obj.from !== "string") throw new MalformedFrameError("cancel frame missing 'from'");
      if (typeof obj.contract !== "string" || !isValidHex32(obj.contract)) {
        throw new MalformedFrameError("cancel frame invalid 'contract'");
      }
      return obj as unknown as CancelFrame;
    }

    case "receipt": {
      if (typeof obj.from !== "string") throw new MalformedFrameError("receipt frame missing 'from'");
      if (typeof obj.contract !== "string" || !isValidHex32(obj.contract)) {
        throw new MalformedFrameError("receipt frame invalid 'contract'");
      }
      if (obj.outcome !== "claimed" && obj.outcome !== "refunded" && obj.outcome !== "cancelled") {
        throw new MalformedFrameError("receipt frame invalid 'outcome'");
      }
      return obj as unknown as ReceiptFrame;
    }

    default:
      throw new MalformedFrameError(`unsupported tclk frame type: ${String(type)}`);
  }
}

export function tryDecodeTclkFrame(text: string): TclkFrame | null {
  try {
    return decodeTclkFrame(text);
  } catch {
    return null;
  }
}

// -----------------------------------------------------------------------------
// Technocore Room Records and Transport Abstraction
// -----------------------------------------------------------------------------

export interface TechnocoreRecord {
  room: string;
  seq: number;
  ts: string;
  from: string;
  nonce: string | number;
  sig: string;
  text: string;
}

export interface TechnocoreTransport {
  sendSigned(
    room: string,
    text: string,
    signer: TechnocoreSigner,
    nonce?: string | number,
  ): Promise<TechnocoreRecord>;
  fetchMessages(room: string): Promise<TechnocoreRecord[]>;
  exportRoom(room: string): Promise<TechnocoreRecord[]>;
}

/**
 * In-memory deterministic mock transport for local testing and unit tests.
 */
export class InMemoryTechnocoreTransport implements TechnocoreTransport {
  private rooms = new Map<string, TechnocoreRecord[]>();
  private nextSeq = 1;

  async sendSigned(
    room: string,
    text: string,
    signer: TechnocoreSigner,
    customNonce?: string | number,
  ): Promise<TechnocoreRecord> {
    const nonce = customNonce ?? Date.now().toString();
    const sig = signer.sign(room, nonce, text);
    const record: TechnocoreRecord = {
      room,
      seq: this.nextSeq++,
      ts: new Date().toISOString(),
      from: signer.did,
      nonce,
      sig,
      text,
    };
    if (!this.rooms.has(room)) {
      this.rooms.set(room, []);
    }
    this.rooms.get(room)!.push(record);
    return record;
  }

  async fetchMessages(room: string): Promise<TechnocoreRecord[]> {
    return [...(this.rooms.get(room) ?? [])];
  }

  async exportRoom(room: string): Promise<TechnocoreRecord[]> {
    return this.fetchMessages(room);
  }
}

/**
 * Real HTTP client for technocore.chat endpoints.
 */
export class HttpTechnocoreTransport implements TechnocoreTransport {
  constructor(public readonly host = "https://technocore.chat") {}

  buildSignedUrl(
    room: string,
    did: string,
    sig: string,
    nonce: string | number,
    text: string,
  ): string {
    const q = encodeURIComponent;
    return `${this.host.replace(/\/+$/, "")}/r/${q(room)}/say-signed/${q(did)}/${q(sig)}/${q(String(nonce))}/${q(text)}`;
  }

  async sendSigned(
    room: string,
    text: string,
    signer: TechnocoreSigner,
    customNonce?: string | number,
  ): Promise<TechnocoreRecord> {
    const nonce = customNonce ?? Date.now().toString();
    const sig = signer.sign(room, nonce, text);
    const url = this.buildSignedUrl(room, signer.did, sig, nonce, text);

    const res = await fetch(url);
    if (!res.ok) {
      throw new TransportError(`failed to submit message: HTTP ${res.status}`);
    }
    // Room message was accepted by server; return local record representation
    return {
      room,
      seq: 0, // Server assigns seq in export
      ts: new Date().toISOString(),
      from: signer.did,
      nonce,
      sig,
      text,
    };
  }

  async fetchMessages(room: string): Promise<TechnocoreRecord[]> {
    return this.exportRoom(room);
  }

  async exportRoom(room: string): Promise<TechnocoreRecord[]> {
    const url = `${this.host.replace(/\/+$/, "")}/r/${encodeURIComponent(room)}/export`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new TransportError(`failed to export room: HTTP ${res.status}`);
    }
    const text = await res.text();
    const records: TechnocoreRecord[] = [];
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const item = JSON.parse(trimmed) as TechnocoreRecord;
        item.room = room;
        records.push(item);
      } catch {
        // Skip malformed export lines
      }
    }
    return records;
  }
}

// -----------------------------------------------------------------------------
// Room Deal Adapter
// -----------------------------------------------------------------------------

export interface IngestResult {
  status: "accepted" | "ignored" | "duplicate";
  deal?: DealManager;
  frame?: TclkFrame;
  reason?: string;
}

/**
 * Bridges Technocore room transport to DealManager state machines.
 */
export class RoomDealAdapter {
  private dealsByOffer = new Map<string, DealManager>();
  private dealsByContract = new Map<string, DealManager>();
  private seenRecordKeys = new Set<string>();

  constructor(
    public readonly room: string,
    public readonly transport: TechnocoreTransport,
    public readonly addressResolver?: EvmAddressResolver,
  ) {}

  getDealByOfferId(offerId: string): DealManager | undefined {
    return this.dealsByOffer.get(offerId);
  }

  getDealByContractId(contractId: string): DealManager | undefined {
    return this.dealsByContract.get(contractId.toLowerCase());
  }

  getAllDeals(): DealManager[] {
    const unique = new Set<DealManager>();
    for (const d of this.dealsByOffer.values()) unique.add(d);
    for (const d of this.dealsByContract.values()) unique.add(d);
    return Array.from(unique);
  }

  /**
   * Ingests a single room record, verifying signatures, room binding, and idempotency.
   */
  async ingestRecord(
    record: TechnocoreRecord,
    counterpartyEvmAddress?: Address,
  ): Promise<IngestResult> {
    // 1. Room binding check
    if (record.room !== this.room) {
      throw new InvalidRoomError(this.room, record.room);
    }

    // 2. Idempotency check on delivery
    const deliveryKey = `${record.room}:${record.seq}:${record.sig}`;
    if (this.seenRecordKeys.has(deliveryKey)) {
      const frame = tryDecodeTclkFrame(record.text);
      let deal: DealManager | undefined;
      if (frame) {
        if (frame.type === "offer") deal = this.dealsByOffer.get(frame.id);
        else deal = this.dealsByContract.get(frame.contract.toLowerCase());
      }
      return { status: "duplicate", deal, frame: frame ?? undefined };
    }

    // 3. Signature verification
    const sigValid = TechnocoreSigner.verify(
      record.room,
      record.nonce,
      record.text,
      record.sig,
      record.from,
    );
    if (!sigValid) {
      throw new InvalidSignatureError(`signature on seq ${record.seq} failed verification`);
    }

    // 4. Non-tclk chat filtering (ignore cleanly without modifying deals)
    if (!isTclkLine(record.text)) {
      this.seenRecordKeys.add(deliveryKey);
      return { status: "ignored", reason: "non-tclk chat message" };
    }

    // 5. Decode frame
    const frame = decodeTclkFrame(record.text);

    // 6. Identity binding: frame.from MUST match record.from
    if (frame.from !== record.from) {
      throw new DealValidationError(
        `frame sender (${frame.from}) does not match message transport signer (${record.from})`,
      );
    }

    // Compute record hash for TC Ledger evidence binding
    const recordHash = computeSha256(
      "0x" + Buffer.from(toAscii(canonicalJson(record)), "utf-8").toString("hex"),
    );
    const tsMs = Date.parse(record.ts) || Date.now();

    // 7. Route to DealManager
    let deal: DealManager;

    switch (frame.type) {
      case "offer": {
        deal = DealManager.createOffer({
          room: this.room,
          creator: { did: frame.from },
          role: frame.role,
          amount: frame.amount,
          asset: frame.asset,
          lock: frame.lock,
          rails: frame.rails,
          claimByMs: frame.claimByMs,
          refundAfterMs: frame.refundAfterMs,
          expiresMs: frame.expiresMs,
          nonce: frame.nonce,
          paymentKey: frame.paymentKey,
          job: frame.job as Record<string, unknown> | undefined,
          nowMs: tsMs,
        });

        // Verify computed offer id matches wire id
        if (deal.state.offer.id !== frame.id) {
          throw new DealValidationError(
            `offer id mismatch: computed ${deal.state.offer.id}, wire got ${frame.id}`,
          );
        }

        deal.recordLedgerSequence("offerSeq", record.seq, recordHash);
        this.dealsByOffer.set(frame.id, deal);
        break;
      }

      case "accept": {
        const existing = this.dealsByOffer.get(frame.ref);
        if (!existing) {
          throw new DealNotFoundError(frame.ref);
        }
        deal = existing;

        let evmAddr = counterpartyEvmAddress;
        if (!evmAddr && this.addressResolver) {
          try {
            evmAddr = await this.addressResolver.resolve(frame.from);
          } catch {
            // Resolver optional / reported as Phase 3 integration gap
          }
        }

        deal.applyAccept(frame, evmAddr, tsMs);
        deal.recordLedgerSequence("acceptSeq", record.seq, recordHash);
        this.dealsByContract.set(deal.contractId.toLowerCase(), deal);
        break;
      }

      case "lock": {
        const existing = this.dealsByContract.get(frame.contract.toLowerCase());
        if (!existing) {
          throw new DealNotFoundError(frame.contract);
        }
        deal = existing;
        deal.applyLock(frame, tsMs);
        deal.recordLedgerSequence("lockSeq", record.seq, recordHash);
        break;
      }

      case "reveal": {
        const existing = this.dealsByContract.get(frame.contract.toLowerCase());
        if (!existing) {
          throw new DealNotFoundError(frame.contract);
        }
        deal = existing;
        deal.applyReveal(frame.secret, frame.from, tsMs);
        deal.recordLedgerSequence("revealSeq", record.seq, recordHash);
        break;
      }

      case "refund": {
        const existing = this.dealsByContract.get(frame.contract.toLowerCase());
        if (!existing) {
          throw new DealNotFoundError(frame.contract);
        }
        deal = existing;
        deal.applyRefund(frame.from, tsMs);
        deal.recordLedgerSequence("refundSeq", record.seq, recordHash);
        break;
      }

      case "cancel": {
        const existing =
          this.dealsByContract.get(frame.contract.toLowerCase()) ??
          this.dealsByOffer.get(frame.contract);
        if (!existing) {
          throw new DealNotFoundError(frame.contract);
        }
        deal = existing;
        deal.applyCancel(frame.from, frame.reason, tsMs);
        break;
      }

      case "receipt": {
        const existing = this.dealsByContract.get(frame.contract.toLowerCase());
        if (!existing) {
          throw new DealNotFoundError(frame.contract);
        }
        deal = existing;
        deal.applyReceipt(frame);
        deal.recordLedgerSequence("receiptSeq", record.seq, recordHash);
        break;
      }
    }

    this.seenRecordKeys.add(deliveryKey);
    return { status: "accepted", deal, frame };
  }

  /**
   * Synchronizes entire room transcript from transport.
   */
  async sync(): Promise<IngestResult[]> {
    const records = await this.transport.fetchMessages(this.room);
    const results: IngestResult[] = [];
    for (const record of records) {
      results.push(await this.ingestRecord(record));
    }
    return results;
  }
}

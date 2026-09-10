// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { createHash } from "node:crypto";
import {
  DealManager,
  DealStatus,
  type OfferFrame,
  type AcceptFrame,
  type LockFrame,
  type RevealFrame,
  type ReceiptFrame,
  type RefundFrame,
  type CancelFrame,
  TechnocoreSigner,
  encodeTclkFrame,
  TcLedgerArchiver,
  verifyDealArchive,
  createSignedExportRecord,
  sliceRawExportLines,
  type DealArchive,
  computeContractId,
} from "../src/index.js";

describe("Phase 3: TC Ledger Archival & Cryptographic Evidence Binding", () => {
  const tmpDirs: string[] = [];

  const aliceKey = new Uint8Array(32).fill(0x11);
  const bobKey = new Uint8Array(32).fill(0x22);

  let aliceSigner: TechnocoreSigner;
  let bobSigner: TechnocoreSigner;

  const ALICE_EVM = "0x1111111111111111111111111111111111111111" as const;
  const BOB_EVM = "0x2222222222222222222222222222222222222222" as const;

  const repoRoot = path.resolve(__dirname, "../..");

  function makeTmpDir(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-archival-test-"));
    tmpDirs.push(dir);
    return dir;
  }

  beforeAll(() => {
    aliceSigner = new TechnocoreSigner(aliceKey);
    bobSigner = new TechnocoreSigner(bobKey);
  });

  afterAll(() => {
    for (const d of tmpDirs) {
      if (fs.existsSync(d)) {
        fs.rmSync(d, { recursive: true, force: true });
      }
    }
  });

  function buildSyntheticExport(
    dir: string,
    room: string,
    records: Array<{ signer: TechnocoreSigner; text: string; seq: number; nonce: number }>,
  ): string {
    const filePath = path.join(dir, `${room}.jsonl`);
    const lines = records.map((r) =>
      createSignedExportRecord(r.signer, room, r.seq, r.text, r.nonce),
    );
    fs.writeFileSync(filePath, lines.join(""), "utf8");
    return filePath;
  }

  function createTestDeal(
    room: string,
    secretHash: string,
    now = Date.now(),
  ): {
    deal: DealManager;
    offer: OfferFrame;
    accept: AcceptFrame;
    contractId: string;
    now: number;
  } {
    const deal = DealManager.createOffer({
      room,
      creator: { did: aliceSigner.did, evmAddress: ALICE_EVM },
      role: "payer",
      amount: "1000",
      asset: "0x0000000000000000000000000000000000000000",
      lock: "hash",
      rails: ["evm-htlc"],
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
      nonce: "offer_nonce_" + Math.random().toString(16).slice(2),
      nowMs: now,
    });
    const offer = deal.state.offer;
    const acceptCore = {
      from: bobSigner.did,
      ref: offer.id,
      statement: secretHash,
      nonce: "accept_nonce_" + Math.random().toString(16).slice(2),
    };
    const contractId = computeContractId(offer, acceptCore);
    const accept: AcceptFrame = {
      type: "accept",
      ...acceptCore,
      contract: contractId,
    };
    return { deal, offer, accept, contractId, now };
  }

  it("1. successful archive of claimed deal", async () => {
    const testDir = makeTmpDir();
    const room = "claimed-deal-room";
    const secret = "0x" + "aa".repeat(32);
    const secretHash = "0x" + createHash("sha256").update(Buffer.from("aa".repeat(32), "hex")).digest("hex");

    const { deal, offer, accept, contractId } = createTestDeal(room, secretHash);
    deal.applyAccept(accept, BOB_EVM);

    const lock: LockFrame = {
      type: "lock",
      from: aliceSigner.did,
      contract: contractId,
      rail: "evm-htlc",
      ref: "0xlocktxhashclaimed",
    };
    deal.applyLock(lock);

    const reveal: RevealFrame = {
      type: "reveal",
      from: bobSigner.did,
      contract: contractId,
      secret,
    };
    deal.applyReveal(secret, bobSigner.did);

    deal.applyClaim(BOB_EVM, "0xclaimtxhashclaimed");

    const receipt: ReceiptFrame = {
      type: "receipt",
      from: bobSigner.did,
      contract: contractId,
      outcome: "claimed",
      ref: "0xclaimtxhashclaimed",
    };
    deal.applyReceipt(receipt);

    deal.recordLedgerSequence("offerSeq", 2);
    deal.recordLedgerSequence("acceptSeq", 3);
    deal.recordLedgerSequence("lockSeq", 4);
    deal.recordLedgerSequence("revealSeq", 5);
    deal.recordLedgerSequence("receiptSeq", 6);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 101, text: "Welcome to the trading room" },
      { signer: aliceSigner, seq: 2, nonce: 102, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 3, nonce: 103, text: encodeTclkFrame(accept) },
      { signer: aliceSigner, seq: 4, nonce: 104, text: encodeTclkFrame(lock) },
      { signer: bobSigner, seq: 5, nonce: 105, text: encodeTclkFrame(reveal) },
      { signer: bobSigner, seq: 6, nonce: 106, text: encodeTclkFrame(receipt) },
      { signer: bobSigner, seq: 7, nonce: 107, text: "Deal concluded successfully." },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath, {
      settlementRef: "0xclaimtxhashclaimed",
      onChainVerified: true,
    });

    expect(archive.deal.status).toBe(DealStatus.CLAIMED);
    expect(archive.deal.contractId).toBe(contractId);
    expect(archive.commitment.export_root).toBeDefined();
    expect(archive.records.offer).toBeDefined();
    expect(archive.records.accept).toBeDefined();
    expect(archive.records.lock).toBeDefined();
    expect(archive.records.reveal).toBeDefined();
    expect(archive.records.receipt).toBeDefined();

    const vResult = await verifyDealArchive(archive, { useCli: true, repoRoot });
    expect(vResult.valid).toBe(true);
    expect(vResult.errors).toHaveLength(0);
    expect(vResult.stagesVerified).toContain("offer");
    expect(vResult.stagesVerified).toContain("receipt");
  });

  it("2. successful archive of refunded deal", async () => {
    const testDir = makeTmpDir();
    const room = "refunded-deal-room";
    const secretHash = "0x" + "cc".repeat(32);

    const { deal, offer, accept, contractId, now } = createTestDeal(room, secretHash);
    deal.applyAccept(accept, BOB_EVM);

    const lock: LockFrame = {
      type: "lock",
      from: aliceSigner.did,
      contract: contractId,
      rail: "evm-htlc",
      ref: "0xlocktxhashrefunded",
    };
    deal.applyLock(lock);

    const refund: RefundFrame = {
      type: "refund",
      from: aliceSigner.did,
      contract: contractId,
      ref: "0xrefundtxhash",
      reason: "timelock expired",
    };
    // Timelock reached
    deal.applyRefund(aliceSigner.did, now + 1500000, "0xrefundtxhash");

    const receipt: ReceiptFrame = {
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "refunded",
      ref: "0xrefundtxhash",
    };
    deal.applyReceipt(receipt);

    deal.recordLedgerSequence("offerSeq", 1);
    deal.recordLedgerSequence("acceptSeq", 2);
    deal.recordLedgerSequence("lockSeq", 3);
    deal.recordLedgerSequence("refundSeq", 4);
    deal.recordLedgerSequence("receiptSeq", 5);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 201, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 2, nonce: 202, text: encodeTclkFrame(accept) },
      { signer: aliceSigner, seq: 3, nonce: 203, text: encodeTclkFrame(lock) },
      { signer: aliceSigner, seq: 4, nonce: 204, text: encodeTclkFrame(refund) },
      { signer: aliceSigner, seq: 5, nonce: 205, text: encodeTclkFrame(receipt) },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath, {
      settlementRef: "0xrefundtxhash",
    });

    expect(archive.deal.status).toBe(DealStatus.REFUNDED);
    const vResult = await verifyDealArchive(archive, { useCli: true, repoRoot });
    expect(vResult.valid).toBe(true);
    expect(vResult.stagesVerified).toContain("refund");
  });

  it("3. successful archive of cancelled deal if protocol semantics permit archival", async () => {
    const testDir = makeTmpDir();
    const room = "cancelled-deal-room";
    const secretHash = "0x" + "dd".repeat(32);

    const { deal, offer, accept, contractId } = createTestDeal(room, secretHash);
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did, "cancelled before lock");

    const receipt: ReceiptFrame = {
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    };
    deal.applyReceipt(receipt);

    deal.recordLedgerSequence("offerSeq", 1);
    deal.recordLedgerSequence("acceptSeq", 2);
    deal.recordLedgerSequence("receiptSeq", 3);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 301, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 2, nonce: 302, text: encodeTclkFrame(accept) },
      { signer: aliceSigner, seq: 3, nonce: 303, text: encodeTclkFrame(receipt) },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    expect(archive.deal.status).toBe(DealStatus.CANCELLED);
    const vResult = await verifyDealArchive(archive, { useCli: false });
    expect(vResult.valid).toBe(true);
  });

  it("4. multiple deals in one room", async () => {
    const testDir = makeTmpDir();
    const room = "multi-deal-room";

    const { deal: deal1, offer: offer1, accept: accept1 } = createTestDeal(room, "0x" + "11".repeat(32));
    deal1.applyAccept(accept1, BOB_EVM);
    deal1.applyCancel(aliceSigner.did);
    const receipt1: ReceiptFrame = {
      type: "receipt",
      from: aliceSigner.did,
      contract: deal1.contractId,
      outcome: "cancelled",
    };
    deal1.applyReceipt(receipt1);
    deal1.recordLedgerSequence("offerSeq", 2);
    deal1.recordLedgerSequence("acceptSeq", 3);
    deal1.recordLedgerSequence("receiptSeq", 4);

    const { deal: deal2, offer: offer2, accept: accept2 } = createTestDeal(room, "0x" + "22".repeat(32));
    deal2.applyAccept(accept2, BOB_EVM);
    deal2.applyCancel(aliceSigner.did);
    const receipt2: ReceiptFrame = {
      type: "receipt",
      from: aliceSigner.did,
      contract: deal2.contractId,
      outcome: "cancelled",
    };
    deal2.applyReceipt(receipt2);
    deal2.recordLedgerSequence("offerSeq", 5);
    deal2.recordLedgerSequence("acceptSeq", 6);
    deal2.recordLedgerSequence("receiptSeq", 7);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 401, text: "Starting multi-deal session" },
      { signer: aliceSigner, seq: 2, nonce: 402, text: encodeTclkFrame(offer1) },
      { signer: bobSigner, seq: 3, nonce: 403, text: encodeTclkFrame(accept1) },
      { signer: aliceSigner, seq: 4, nonce: 404, text: encodeTclkFrame(receipt1) },
      { signer: aliceSigner, seq: 5, nonce: 405, text: encodeTclkFrame(offer2) },
      { signer: bobSigner, seq: 6, nonce: 406, text: encodeTclkFrame(accept2) },
      { signer: aliceSigner, seq: 7, nonce: 407, text: encodeTclkFrame(receipt2) },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive1 = await archiver.archiveDeal(deal1, exportPath);
    const archive2 = await archiver.archiveDeal(deal2, exportPath);

    expect(archive1.commitment.export_root).toBe(archive2.commitment.export_root);
    expect(archive1.deal.contractId).toBe(deal1.contractId);
    expect(archive2.deal.contractId).toBe(deal2.contractId);

    expect((await verifyDealArchive(archive1)).valid).toBe(true);
    expect((await verifyDealArchive(archive2)).valid).toBe(true);
  });

  it("5. correct sequence-to-proof mapping & 6. exact record-byte preservation", async () => {
    const testDir = makeTmpDir();
    const room = "mapping-room";
    const { deal, offer, accept, contractId } = createTestDeal(room, "0x" + "55".repeat(32));
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did);
    const receipt: ReceiptFrame = {
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    };
    deal.applyReceipt(receipt);

    deal.recordLedgerSequence("offerSeq", 2);
    deal.recordLedgerSequence("receiptSeq", 4);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 501, text: "Noise 1" },
      { signer: aliceSigner, seq: 2, nonce: 502, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 3, nonce: 503, text: "Noise 2" },
      { signer: aliceSigner, seq: 4, nonce: 504, text: encodeTclkFrame(receipt) },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    expect(archive.records.offer.seq).toBe(2);
    expect(archive.records.offer.leafIndex).toBe(1);
    expect(archive.records.offer.proof.leaf_index).toBe(1);

    expect(archive.records.receipt.seq).toBe(4);
    expect(archive.records.receipt.leafIndex).toBe(3);
    expect(archive.records.receipt.proof.leaf_index).toBe(3);

    const rawFileBytes = fs.readFileSync(exportPath);
    const rawLines = sliceRawExportLines(rawFileBytes);
    expect(archive.records.offer.rawLine).toBe(rawLines[1].str);
    expect(archive.records.receipt.rawLine).toBe(rawLines[3].str);
  });

  it("7. commitment root attached to correct deal & 8. inclusion proof attached to correct sequence", async () => {
    const testDir = makeTmpDir();
    const room = "attachment-room";
    const { deal, offer, accept, contractId } = createTestDeal(room, "0x" + "77".repeat(32));
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did);
    const receipt: ReceiptFrame = {
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    };
    deal.applyReceipt(receipt);
    deal.recordLedgerSequence("offerSeq", 1);
    deal.recordLedgerSequence("receiptSeq", 2);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 701, text: encodeTclkFrame(offer) },
      { signer: aliceSigner, seq: 2, nonce: 702, text: encodeTclkFrame(receipt) },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    expect(deal.state.ledgerEvidence.exportRoot).toBe(archive.commitment.export_root);
    expect(deal.state.ledgerEvidence.inclusionProofs?.offer).toBeDefined();
    expect(deal.state.ledgerEvidence.inclusionProofs?.receipt).toBeDefined();
    expect(deal.state.ledgerEvidence.commitmentArtifact).toBeDefined();
  });

  it("9. offline verification succeeds", async () => {
    const testDir = makeTmpDir();
    const room = "offline-room";
    const { deal, offer, accept, contractId } = createTestDeal(room, "0x" + "99".repeat(32));
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did);
    deal.applyReceipt({
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    });
    deal.recordLedgerSequence("offerSeq", 1);
    deal.recordLedgerSequence("acceptSeq", 2);
    deal.recordLedgerSequence("receiptSeq", 3);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 901, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 2, nonce: 902, text: encodeTclkFrame(accept) },
      {
        signer: aliceSigner,
        seq: 3,
        nonce: 903,
        text: encodeTclkFrame({
          type: "receipt",
          from: aliceSigner.did,
          contract: contractId,
          outcome: "cancelled",
        }),
      },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    const result = await verifyDealArchive(archive, { useCli: false });
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.stagesVerified.length).toBeGreaterThan(0);
  });

  it("10. tampered record fails verification", async () => {
    const testDir = makeTmpDir();
    const room = "tampered-record-room";
    const { deal, offer, accept, contractId } = createTestDeal(room, "0x" + "10".repeat(32));
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did);
    deal.applyReceipt({
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    });
    deal.recordLedgerSequence("offerSeq", 1);
    deal.recordLedgerSequence("acceptSeq", 2);
    deal.recordLedgerSequence("receiptSeq", 3);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 1001, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 2, nonce: 1002, text: encodeTclkFrame(accept) },
      {
        signer: aliceSigner,
        seq: 3,
        nonce: 1003,
        text: encodeTclkFrame({
          type: "receipt",
          from: aliceSigner.did,
          contract: contractId,
          outcome: "cancelled",
        }),
      },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    const tampered = JSON.parse(JSON.stringify(archive)) as DealArchive;
    tampered.records.offer.rawLine = tampered.records.offer.rawLine.replace("1000", "999999");

    const result = await verifyDealArchive(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("leaf hash mismatch"))).toBe(true);
  });

  it("11. tampered proof fails verification", async () => {
    const testDir = makeTmpDir();
    const room = "tampered-proof-room";
    const { deal, offer, accept, contractId } = createTestDeal(room, "0x" + "11".repeat(32));
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did);
    deal.applyReceipt({
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    });
    deal.recordLedgerSequence("offerSeq", 1);
    deal.recordLedgerSequence("acceptSeq", 2);
    deal.recordLedgerSequence("receiptSeq", 3);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 1101, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 2, nonce: 1102, text: encodeTclkFrame(accept) },
      {
        signer: aliceSigner,
        seq: 3,
        nonce: 1103,
        text: encodeTclkFrame({
          type: "receipt",
          from: aliceSigner.did,
          contract: contractId,
          outcome: "cancelled",
        }),
      },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    const tampered = JSON.parse(JSON.stringify(archive)) as DealArchive;
    tampered.records.offer.proof.audit_path[0].sibling_hash = "00".repeat(32);

    const result = await verifyDealArchive(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("inclusion proof Merkle verification failed"))).toBe(true);
  });

  it("12. wrong root fails verification", async () => {
    const testDir = makeTmpDir();
    const room = "wrong-root-room";
    const { deal, offer, accept, contractId } = createTestDeal(room, "0x" + "12".repeat(32));
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did);
    deal.applyReceipt({
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    });
    deal.recordLedgerSequence("offerSeq", 1);
    deal.recordLedgerSequence("acceptSeq", 2);
    deal.recordLedgerSequence("receiptSeq", 3);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 1201, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 2, nonce: 1202, text: encodeTclkFrame(accept) },
      {
        signer: aliceSigner,
        seq: 3,
        nonce: 1203,
        text: encodeTclkFrame({
          type: "receipt",
          from: aliceSigner.did,
          contract: contractId,
          outcome: "cancelled",
        }),
      },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    const tampered = JSON.parse(JSON.stringify(archive)) as DealArchive;
    tampered.commitment.export_root = "bad0".repeat(16);

    const result = await verifyDealArchive(tampered);
    expect(result.valid).toBe(false);
  });

  it("13. wrong sequence fails verification / archival", async () => {
    const testDir = makeTmpDir();
    const room = "wrong-seq-room";
    const { deal, offer, accept, contractId } = createTestDeal(room, "0x" + "13".repeat(32));
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did);
    deal.applyReceipt({
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    });
    deal.recordLedgerSequence("offerSeq", 999);
    deal.recordLedgerSequence("receiptSeq", 2);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 1301, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 2, nonce: 1302, text: encodeTclkFrame(accept) },
      {
        signer: aliceSigner,
        seq: 3,
        nonce: 1303,
        text: encodeTclkFrame({
          type: "receipt",
          from: aliceSigner.did,
          contract: contractId,
          outcome: "cancelled",
        }),
      },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    await expect(archiver.archiveDeal(deal, exportPath)).rejects.toThrow(
      /stage offer \(seq: 999\) not found/i,
    );
  });

  it("14. archive never contains plaintext HTLC secret", async () => {
    const testDir = makeTmpDir();
    const room = "no-secrets-room";
    const secret = "0x" + "7f".repeat(32);
    const secretHash = "0x" + createHash("sha256").update(Buffer.from("7f".repeat(32), "hex")).digest("hex");

    const { deal, offer, accept, contractId } = createTestDeal(room, secretHash);
    deal.applyAccept(accept, BOB_EVM);
    const lock: LockFrame = {
      type: "lock",
      from: aliceSigner.did,
      contract: contractId,
      rail: "evm-htlc",
      ref: "0xlockref",
    };
    deal.applyLock(lock);
    deal.applyReveal(secret, bobSigner.did);
    deal.applyClaim(BOB_EVM, "0xclaimref");
    deal.applyReceipt({
      type: "receipt",
      from: bobSigner.did,
      contract: contractId,
      outcome: "claimed",
      ref: "0xclaimref",
    });

    deal.recordLedgerSequence("offerSeq", 1);
    deal.recordLedgerSequence("acceptSeq", 2);
    deal.recordLedgerSequence("lockSeq", 3);
    deal.recordLedgerSequence("receiptSeq", 4);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 1401, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 2, nonce: 1402, text: encodeTclkFrame(accept) },
      { signer: aliceSigner, seq: 3, nonce: 1403, text: encodeTclkFrame(lock) },
      {
        signer: bobSigner,
        seq: 4,
        nonce: 1404,
        text: encodeTclkFrame({
          type: "receipt",
          from: bobSigner.did,
          contract: contractId,
          outcome: "claimed",
        }),
      },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    const archiveJson = JSON.stringify(archive);
    expect(archiveJson).not.toContain(secret);
    expect(archiveJson).not.toContain("7f".repeat(32));
  });

  it("15. incomplete/non-terminal deal cannot be finalized as a completed settlement archive unless explicitly represented", async () => {
    const testDir = makeTmpDir();
    const room = "incomplete-room";
    const { deal, offer } = createTestDeal(room, "0x" + "15".repeat(32));
    deal.recordLedgerSequence("offerSeq", 1);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 1501, text: encodeTclkFrame(offer) },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    await expect(archiver.archiveDeal(deal, exportPath)).rejects.toThrow(
      /cannot archive non-terminal deal/i,
    );

    const incompleteArchive = await archiver.archiveDeal(deal, exportPath, {
      allowIncomplete: true,
    });
    expect(incompleteArchive.deal.status).toBe(DealStatus.OFFERED);
  });

  it("16. normal non-deal chat records remain part of the room commitment but are not incorrectly attributed to a deal", async () => {
    const testDir = makeTmpDir();
    const room = "chat-room";
    const { deal, offer, accept, contractId } = createTestDeal(room, "0x" + "16".repeat(32));
    deal.applyAccept(accept, BOB_EVM);
    deal.applyCancel(aliceSigner.did);
    deal.applyReceipt({
      type: "receipt",
      from: aliceSigner.did,
      contract: contractId,
      outcome: "cancelled",
    });
    deal.recordLedgerSequence("offerSeq", 2);
    deal.recordLedgerSequence("receiptSeq", 5);

    const exportPath = buildSyntheticExport(testDir, room, [
      { signer: aliceSigner, seq: 1, nonce: 1601, text: "Hello Bob! Let's trade" },
      { signer: aliceSigner, seq: 2, nonce: 1602, text: encodeTclkFrame(offer) },
      { signer: bobSigner, seq: 3, nonce: 1603, text: encodeTclkFrame(accept) },
      { signer: bobSigner, seq: 4, nonce: 1604, text: "Wait, conditions changed" },
      {
        signer: aliceSigner,
        seq: 5,
        nonce: 1605,
        text: encodeTclkFrame({
          type: "receipt",
          from: aliceSigner.did,
          contract: contractId,
          outcome: "cancelled",
        }),
      },
      { signer: bobSigner, seq: 6, nonce: 1606, text: "Okay, maybe next time!" },
    ]);

    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath);

    expect(archive.commitment.line_count).toBe(6);
    expect(Object.keys(archive.records)).toEqual(["offer", "receipt"]);
    expect(archive.records.offer.seq).toBe(2);
    expect(archive.records.receipt.seq).toBe(5);
  });
});

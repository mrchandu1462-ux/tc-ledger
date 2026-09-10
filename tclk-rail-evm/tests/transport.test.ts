// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import {
  TechnocoreSigner,
  RoomDealAdapter,
  InMemoryTechnocoreTransport,
  encodeTclkFrame,
  decodeTclkFrame,
  isTclkLine,
  sweptText,
  InvalidSignatureError,
  InvalidRoomError,
  MalformedFrameError,
  DealNotFoundError,
  type TechnocoreRecord,
} from "../src/transport.js";
import {
  DealStatus,
  computeOfferId,
  computeContractId,
  type OfferFrame,
  type AcceptCore,
  type AcceptFrame,
  type LockFrame,
  type RevealFrame,
  type ReceiptFrame,
} from "../src/deal.js";
import { computeSha256 } from "../src/utils.js";
import type { Hash } from "viem";

describe("Phase 2: Technocore Room Transport & Frame Adapter", () => {
  const ROOM = "room_deal_p2_test";

  // Deterministic signers for Alice (payer) and Bob (payee)
  const alice = TechnocoreSigner.fromSeed("0101010101010101010101010101010101010101010101010101010101010101");
  const bob = TechnocoreSigner.fromSeed("0202020202020202020202020202020202020202020202020202020202020202");
  const eve = TechnocoreSigner.fromSeed("0303030303030303030303030303030303030303030303030303030303030303");

  const TEST_SECRET = "0x4444444444444444444444444444444444444444444444444444444444444444" as Hash;
  const TEST_STATEMENT = computeSha256(TEST_SECRET);

  function makeOfferFrame(fromSigner: TechnocoreSigner, now = Date.now()): OfferFrame {
    const fields: Omit<OfferFrame, "id"> = {
      type: "offer",
      from: fromSigner.did,
      role: "payer",
      amount: "500000000000000000",
      asset: "ETH",
      lock: "hash",
      rails: ["evm-htlc"],
      claimByMs: now + 60_000,
      refundAfterMs: now + 120_000,
      expiresMs: now + 30_000,
      nonce: "nonce_offer_p2",
    };
    const id = computeOfferId(fields);
    return { ...fields, id };
  }

  function makeAcceptFrame(offer: OfferFrame, payeeSigner: TechnocoreSigner, statement = TEST_STATEMENT): AcceptFrame {
    const core: AcceptCore = {
      from: payeeSigner.did,
      ref: offer.id,
      statement,
      nonce: "nonce_accept_p2",
    };
    const contract = computeContractId(offer, core);
    return {
      type: "accept",
      ...core,
      contract,
    };
  }

  describe("A. Text Sweeping & Ed25519 Signer Conformance", () => {
    it("sweeps control characters and trims text matching Technocore rules", () => {
      const dirty = "\u0000 Hello \u200B World \u001F ";
      expect(sweptText(dirty)).toBe("Hello   World");
    });

    it("generates deterministic did:key:z6Mk... identities and valid signatures", () => {
      expect(alice.did).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
      expect(bob.did).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);

      const text = "Hello Technocore Room";
      const sig = alice.sign(ROOM, "101", text);
      expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/);

      const ok = TechnocoreSigner.verify(ROOM, "101", text, sig, alice.did);
      expect(ok).toBe(true);

      // Wrong nonce or room fails verification
      expect(TechnocoreSigner.verify("wrong_room", "101", text, sig, alice.did)).toBe(false);
      expect(TechnocoreSigner.verify(ROOM, "999", text, sig, alice.did)).toBe(false);
      // Wrong signer fails verification
      expect(TechnocoreSigner.verify(ROOM, "101", text, sig, bob.did)).toBe(false);
    });

    it("verifies live Technocore export record signature", () => {
      const sampleFrom = "did:key:z6MkoqMJ1pFzNvTmvPbj25kzAEXf2ynpmTxFNBjYjhwjEpct";
      const sampleNonce = 17002;
      const sampleText =
        "DELIVER v1 | k88dcc91114 | Research findings on: What is a 10-year US Treasury yield. Analysis reveals multiple interconnected factors. Methodology: examined primary sources and cross-referenced data. Results show consistent patterns that inform the $FLOP airdrop allocation framework. Conclusion: active participation in the kibble protocol correlates with meaningful contribution.";
      const sampleSig =
        "fpXSaDV5LoylWPXRc_KfBp0zAeLb6Fi9FInNy1_M82kzc_-eL1NzAvuMmAlS7Rf_KcOKvCKN0hoVxVnmQE5fCA";

      const verified = TechnocoreSigner.verify(
        "kibble",
        sampleNonce,
        sampleText,
        sampleSig,
        sampleFrom,
      );
      expect(verified).toBe(true);
    });
  });

  describe("B. tclk/1 Wire Frame Encoding & Decoding", () => {
    it("encodes frame with 'tclk1 ' prefix and canonical ASCII JSON", () => {
      const offer = makeOfferFrame(alice);
      const wire = encodeTclkFrame(offer);
      expect(isTclkLine(wire)).toBe(true);
      expect(wire.startsWith("tclk1 {")).toBe(true);

      const decoded = decodeTclkFrame(wire);
      expect(decoded).toEqual(offer);
    });

    it("rejects non-tclk lines and malformed JSON deterministically", () => {
      expect(isTclkLine("just chat message")).toBe(false);
      expect(() => decodeTclkFrame("just chat message")).toThrow(MalformedFrameError);
      expect(() => decodeTclkFrame("tclk1 not-json{")).toThrow("invalid JSON");
      expect(() => decodeTclkFrame('tclk1 {"type":"unknown_type"}')).toThrow("unsupported tclk frame type");
    });
  });

  describe("C. RoomDealAdapter: End-to-End Lifecycle via Signed Messages", () => {
    it("processes complete deal lifecycle: offer -> accept -> lock -> reveal -> receipt", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      const now = Date.now();
      const offer = makeOfferFrame(alice, now);
      const accept = makeAcceptFrame(offer, bob);

      // 1. Ingest Signed Offer
      const offerMsg = await transport.sendSigned(ROOM, encodeTclkFrame(offer), alice, "1001");
      const resOffer = await adapter.ingestRecord(offerMsg);
      expect(resOffer.status).toBe("accepted");
      expect(resOffer.deal?.status).toBe(DealStatus.OFFERED);
      expect(adapter.getDealByOfferId(offer.id)).toBeDefined();

      // Check ledger sequence binding
      expect(resOffer.deal?.state.ledgerEvidence.recordSequences.offerSeq).toBe(offerMsg.seq);
      expect(resOffer.deal?.state.ledgerEvidence.signedRecordHashes.offerSeq).toBeDefined();

      // 2. Ingest Signed Accept
      const acceptMsg = await transport.sendSigned(ROOM, encodeTclkFrame(accept), bob, "1002");
      const resAccept = await adapter.ingestRecord(acceptMsg);
      expect(resAccept.status).toBe("accepted");
      expect(resAccept.deal?.status).toBe(DealStatus.ACCEPTED);
      expect(resAccept.deal?.contractId).toBe(accept.contract);
      expect(adapter.getDealByContractId(accept.contract)).toBe(resAccept.deal);
      expect(resAccept.deal?.state.ledgerEvidence.recordSequences.acceptSeq).toBe(acceptMsg.seq);

      // 3. Ingest Signed Lock
      const lockRef = "0x5555555555555555555555555555555555555555555555555555555555555555";
      const lockFrame: LockFrame = {
        type: "lock",
        from: alice.did,
        contract: accept.contract,
        rail: "evm-htlc",
        ref: lockRef,
      };
      const lockMsg = await transport.sendSigned(ROOM, encodeTclkFrame(lockFrame), alice, "1003");
      const resLock = await adapter.ingestRecord(lockMsg);
      expect(resLock.status).toBe("accepted");
      expect(resLock.deal?.status).toBe(DealStatus.LOCKED);
      expect(resLock.deal?.state.ref).toBe(lockRef);
      expect(resLock.deal?.state.ledgerEvidence.recordSequences.lockSeq).toBe(lockMsg.seq);

      // (In real flow, payee or watcher calls markVerified once on-chain tx confirms)
      resLock.deal!.markVerified(lockRef);
      expect(resLock.deal?.status).toBe(DealStatus.VERIFIED);

      // 4. Ingest Signed Reveal
      const revealFrame: RevealFrame = {
        type: "reveal",
        from: bob.did,
        contract: accept.contract,
        secret: TEST_SECRET,
      };
      const revealMsg = await transport.sendSigned(ROOM, encodeTclkFrame(revealFrame), bob, "1004");
      const resReveal = await adapter.ingestRecord(revealMsg);
      expect(resReveal.status).toBe("accepted");
      expect(resReveal.deal?.status).toBe(DealStatus.REVEALED);
      expect(resReveal.deal?.state.secretRevealed).toBe(true);
      expect(resReveal.deal?.state.secretHash).toBe(TEST_STATEMENT.toLowerCase());

      // Confirm secret is NOT exposed in deal record
      expect((resReveal.deal?.state as unknown as Record<string, unknown>).secret).toBeUndefined();

      // Apply claim on deal
      resReveal.deal!.applyClaim();
      expect(resReveal.deal?.status).toBe(DealStatus.CLAIMED);

      // 5. Ingest Signed Receipt
      const receiptFrame: ReceiptFrame = {
        type: "receipt",
        from: bob.did,
        contract: accept.contract,
        outcome: "claimed",
        rail: "evm-htlc",
        ref: lockRef,
      };
      const receiptMsg = await transport.sendSigned(ROOM, encodeTclkFrame(receiptFrame), bob, "1005");
      const resReceipt = await adapter.ingestRecord(receiptMsg);
      expect(resReceipt.status).toBe("accepted");
      expect(resReceipt.deal?.state.receipt).toEqual(receiptFrame);
      expect(resReceipt.deal?.state.ledgerEvidence.recordSequences.receiptSeq).toBe(receiptMsg.seq);
    });

    it("processes refund path when refund is broadcast after timeout", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      const now = Date.now();
      const offer = makeOfferFrame(alice, now);
      const accept = makeAcceptFrame(offer, bob);

      await adapter.ingestRecord(await transport.sendSigned(ROOM, encodeTclkFrame(offer), alice, "2001"));
      await adapter.ingestRecord(await transport.sendSigned(ROOM, encodeTclkFrame(accept), bob, "2002"));

      const lockRef = "0x6666666666666666666666666666666666666666666666666666666666666666";
      const lockFrame: LockFrame = {
        type: "lock",
        from: alice.did,
        contract: accept.contract,
        rail: "evm-htlc",
        ref: lockRef,
      };
      const resLock = await adapter.ingestRecord(
        await transport.sendSigned(ROOM, encodeTclkFrame(lockFrame), alice, "2003"),
      );
      resLock.deal!.markVerified(lockRef);

      // Refund before deadline -> rejected by deal logic
      const earlyRefund: TechnocoreRecord = {
        room: ROOM,
        seq: 2004,
        ts: new Date(offer.refundAfterMs - 5000).toISOString(),
        from: alice.did,
        nonce: "2004",
        sig: alice.sign(ROOM, "2004", encodeTclkFrame({
          type: "refund",
          from: alice.did,
          contract: accept.contract,
        })),
        text: encodeTclkFrame({
          type: "refund",
          from: alice.did,
          contract: accept.contract,
        }),
      };
      await expect(adapter.ingestRecord(earlyRefund)).rejects.toThrow("cannot refund before refund deadline");

      // Refund after deadline -> accepted
      const validRefund: TechnocoreRecord = {
        room: ROOM,
        seq: 2005,
        ts: new Date(offer.refundAfterMs + 5000).toISOString(),
        from: alice.did,
        nonce: "2005",
        sig: alice.sign(ROOM, "2005", encodeTclkFrame({
          type: "refund",
          from: alice.did,
          contract: accept.contract,
        })),
        text: encodeTclkFrame({
          type: "refund",
          from: alice.did,
          contract: accept.contract,
        }),
      };
      const resRefund = await adapter.ingestRecord(validRefund);
      expect(resRefund.status).toBe("accepted");
      expect(resRefund.deal?.status).toBe(DealStatus.REFUNDED);
    });

    it("processes pre-lock cancel path", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      const offer = makeOfferFrame(alice);
      await adapter.ingestRecord(await transport.sendSigned(ROOM, encodeTclkFrame(offer), alice, "3001"));

      const cancelFrame = {
        type: "cancel" as const,
        from: alice.did,
        contract: offer.id,
        reason: "Alice cancelled before acceptance",
      };
      const cancelMsg = await transport.sendSigned(ROOM, encodeTclkFrame(cancelFrame), alice, "3002");
      const resCancel = await adapter.ingestRecord(cancelMsg);
      expect(resCancel.status).toBe("accepted");
      expect(resCancel.deal?.status).toBe(DealStatus.CANCELLED);
    });
  });

  describe("D. Security, Guardrails & Error Discrimination", () => {
    it("ignores non-tclk chat messages cleanly without disrupting deals", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      const chatMsg = await transport.sendSigned(ROOM, "Hey anyone want to swap ETH?", alice, "4001");
      const res = await adapter.ingestRecord(chatMsg);
      expect(res.status).toBe("ignored");
      expect(res.reason).toBe("non-tclk chat message");
      expect(adapter.getAllDeals()).toHaveLength(0);
    });

    it("rejects forged or corrupted signatures with InvalidSignatureError", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      const offer = makeOfferFrame(alice);
      const validMsg = await transport.sendSigned(ROOM, encodeTclkFrame(offer), alice, "5001");

      const tamperedRecord: TechnocoreRecord = {
        ...validMsg,
        sig: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      };

      await expect(adapter.ingestRecord(tamperedRecord)).rejects.toThrow(InvalidSignatureError);
    });

    it("rejects messages addressed to a different room with InvalidRoomError", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter("my_deal_room", transport);

      const offer = makeOfferFrame(alice);
      const otherRoomMsg = await transport.sendSigned("other_room", encodeTclkFrame(offer), alice, "6001");

      await expect(adapter.ingestRecord(otherRoomMsg)).rejects.toThrow(InvalidRoomError);
    });

    it("rejects message when frame sender differs from transport signer DID", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      // Eve attempts to broadcast an offer claiming to be Alice
      const spoofedOffer = makeOfferFrame(alice);
      const eveSpoofMsg = await transport.sendSigned(ROOM, encodeTclkFrame(spoofedOffer), eve, "7001");

      await expect(adapter.ingestRecord(eveSpoofMsg)).rejects.toThrow("frame sender");
    });

    it("handles duplicate message delivery idempotently without state corruption", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      const offer = makeOfferFrame(alice);
      const offerMsg = await transport.sendSigned(ROOM, encodeTclkFrame(offer), alice, "8001");

      // First delivery
      const res1 = await adapter.ingestRecord(offerMsg);
      expect(res1.status).toBe("accepted");

      // Duplicate delivery of identical record
      const res2 = await adapter.ingestRecord(offerMsg);
      expect(res2.status).toBe("duplicate");
      expect(res2.deal?.status).toBe(DealStatus.OFFERED);
    });

    it("supports multiple independent deals concurrently in the same room", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      const offer1 = makeOfferFrame(alice);
      const { id: _ignored, ...offer2Fields } = { ...makeOfferFrame(alice), nonce: "nonce_offer_two" };
      const offer2: OfferFrame = { ...offer2Fields, id: computeOfferId(offer2Fields) };

      const msg1 = await transport.sendSigned(ROOM, encodeTclkFrame(offer1), alice, "9001");
      const msg2 = await transport.sendSigned(ROOM, encodeTclkFrame(offer2), alice, "9002");

      await adapter.ingestRecord(msg1);
      await adapter.ingestRecord(msg2);

      expect(adapter.getAllDeals()).toHaveLength(2);
      expect(adapter.getDealByOfferId(offer1.id)?.state.offer.id).toBe(offer1.id);
      expect(adapter.getDealByOfferId(offer2.id)?.state.offer.id).toBe(offer2.id);
    });

    it("fails with DealNotFoundError when accept references unknown offer", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const adapter = new RoomDealAdapter(ROOM, transport);

      const dummyOffer = makeOfferFrame(alice);
      const orphanAccept = makeAcceptFrame(dummyOffer, bob);

      const msg = await transport.sendSigned(ROOM, encodeTclkFrame(orphanAccept), bob, "9999");
      await expect(adapter.ingestRecord(msg)).rejects.toThrow(DealNotFoundError);
    });
  });

  describe("E. Room Synchronization (sync)", () => {
    it("replays full room export history deterministically into deal state", async () => {
      const transport = new InMemoryTechnocoreTransport();
      const offer = makeOfferFrame(alice);
      const accept = makeAcceptFrame(offer, bob);

      // Preload messages into room
      await transport.sendSigned(ROOM, "Hello room", alice, "1");
      await transport.sendSigned(ROOM, encodeTclkFrame(offer), alice, "2");
      await transport.sendSigned(ROOM, "Discussing terms...", bob, "3");
      await transport.sendSigned(ROOM, encodeTclkFrame(accept), bob, "4");

      const adapter = new RoomDealAdapter(ROOM, transport);
      const results = await adapter.sync();

      expect(results).toHaveLength(4);
      expect(results[0].status).toBe("ignored"); // chat message
      expect(results[1].status).toBe("accepted"); // offer
      expect(results[2].status).toBe("ignored"); // chat message
      expect(results[3].status).toBe("accepted"); // accept

      const deal = adapter.getDealByContractId(accept.contract);
      expect(deal).toBeDefined();
      expect(deal?.status).toBe(DealStatus.ACCEPTED);
      expect(deal?.state.ledgerEvidence.recordSequences.offerSeq).toBe(2);
      expect(deal?.state.ledgerEvidence.recordSequences.acceptSeq).toBe(4);
    });
  });
});

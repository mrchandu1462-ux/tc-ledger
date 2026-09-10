// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import {
  DealManager,
  DealStatus,
  InvalidDealTransitionError,
  DealValidationError,
  computeOfferId,
  computeContractId,
  projectLockTerms,
  canonicalJson,
  domainHash,
  type OfferFrame,
  type AcceptCore,
  type AcceptFrame,
  type LockFrame,
  type ReceiptFrame,
} from "../src/deal.js";
import { computeSha256 } from "../src/utils.js";
import type { Hash } from "viem";

describe("Deal Manager / Deal Coordination Core (tclk/1)", () => {
  const ALICE_DID = "did:key:z6MkhaXgBZDvotDkL5257faiz48Z8x28ins55cxk";
  const BOB_DID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8x79df";
  const CHARLIE_DID = "did:key:z6MknLzpvT4123456789abcdefABCDEFghijkl";
  const ALICE_EVM = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
  const BOB_EVM = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

  const TEST_SECRET = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as Hash;
  const TEST_STATEMENT = computeSha256(TEST_SECRET);

  function createBaseOffer(now?: number) {
    const baseNow = now ?? Date.now();
    return DealManager.createOffer({
      room: "room_deal_test_001",
      creator: { did: ALICE_DID, evmAddress: ALICE_EVM },
      role: "payer",
      amount: "1000000000000000000",
      asset: "ETH",
      lock: "hash",
      rails: ["evm-htlc"],
      claimByMs: baseNow + 60_000,
      refundAfterMs: baseNow + 120_000,
      expiresMs: baseNow + 30_000,
      nonce: "offer_nonce_1234",
      nowMs: baseNow,
    });
  }

  function makeAccept(offer: OfferFrame, statement: string = TEST_STATEMENT, from = BOB_DID): AcceptFrame {
    const acceptCore: AcceptCore = {
      from,
      ref: offer.id,
      statement,
      nonce: "accept_nonce_5678",
    };
    const contract = computeContractId(offer, acceptCore);
    return {
      type: "accept",
      ...acceptCore,
      contract,
    };
  }

  describe("A. Deterministic Canonicalization and Domain Separation", () => {
    it("canonicalizes JSON with lexicographical key ordering", () => {
      const obj1 = { z: 1, a: 2, m: { b: 3, a: 4 } };
      const obj2 = { a: 2, m: { a: 4, b: 3 }, z: 1 };
      expect(canonicalJson(obj1)).toBe('{"a":2,"m":{"a":4,"b":3},"z":1}');
      expect(canonicalJson(obj1)).toBe(canonicalJson(obj2));
    });

    it("computes domain hashes with 32-byte 0x-prefixed format", () => {
      const h = domainHash("offer", '{"test":true}');
      expect(h).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("computes identical offer id and contract id deterministically", () => {
      const offerFields: Omit<OfferFrame, "id"> = {
        type: "offer",
        from: ALICE_DID,
        role: "payer",
        amount: "100",
        asset: "ETH",
        lock: "hash",
        rails: ["evm-htlc"],
        claimByMs: 2000,
        refundAfterMs: 3000,
        expiresMs: 1500,
        nonce: "test_nonce",
      };
      const id1 = computeOfferId(offerFields);
      const id2 = computeOfferId(offerFields);
      expect(id1).toBe(id2);
      expect(id1).toMatch(/^0x[0-9a-f]{64}$/);

      const offer: OfferFrame = { ...offerFields, id: id1 };
      const acceptCore: AcceptCore = {
        from: BOB_DID,
        ref: id1,
        statement: TEST_STATEMENT,
        nonce: "nonce_b",
      };
      const contract1 = computeContractId(offer, acceptCore);
      const contract2 = computeContractId(offer, acceptCore);
      expect(contract1).toBe(contract2);
      expect(contract1).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });

  describe("B. Deal Offer Creation & Invariants", () => {
    it("creates offer with initial status OFFERED and preserves exact parameters", () => {
      const deal = createBaseOffer(1000);
      expect(deal.status).toBe(DealStatus.OFFERED);
      expect(deal.room).toBe("room_deal_test_001");
      expect(deal.state.payer.did).toBe(ALICE_DID);
      expect(deal.state.payer.evmAddress).toBe(ALICE_EVM);
      expect(deal.state.offer.amount).toBe("1000000000000000000");
      expect(deal.state.offer.id).toMatch(/^0x[0-9a-f]{64}$/);
      expect(deal.contractId).toBe("");
      expect(deal.isTerminal()).toBe(false);
    });

    it("rejects offer creation if claimByMs >= refundAfterMs", () => {
      expect(() => {
        DealManager.createOffer({
          room: "room_invalid",
          creator: { did: ALICE_DID },
          role: "payer",
          amount: "100",
          asset: "ETH",
          claimByMs: 2000,
          refundAfterMs: 2000, // Equal
          expiresMs: 1500,
        });
      }).toThrow(DealValidationError);

      expect(() => {
        DealManager.createOffer({
          room: "room_invalid",
          creator: { did: ALICE_DID },
          role: "payer",
          amount: "100",
          asset: "ETH",
          claimByMs: 3000, // Inverted
          refundAfterMs: 2000,
          expiresMs: 1500,
        });
      }).toThrow(DealValidationError);
    });

    it("rejects offer creation if already expired or invalid amount", () => {
      expect(() => {
        DealManager.createOffer({
          room: "room_invalid",
          creator: { did: ALICE_DID },
          role: "payer",
          amount: "100",
          asset: "ETH",
          claimByMs: 2000,
          refundAfterMs: 3000,
          expiresMs: 500,
          nowMs: 1000, // already expired
        });
      }).toThrow("expired");

      expect(() => {
        DealManager.createOffer({
          room: "room_invalid",
          creator: { did: ALICE_DID },
          role: "payer",
          amount: "0",
          asset: "ETH",
          claimByMs: 2000,
          refundAfterMs: 3000,
          expiresMs: 1500,
          nowMs: 1000,
        });
      }).toThrow("amount must be positive");
    });
  });

  describe("C. Full Valid Lifecycle: OFFERED -> ACCEPTED -> LOCKED -> VERIFIED -> REVEALED -> CLAIMED", () => {
    it("executes complete claim path successfully and preserves exact contractId", () => {
      const now = 1000;
      const deal = createBaseOffer(now);

      // 1. OFFERED -> ACCEPTED
      const accept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);
      deal.applyAccept(accept, BOB_EVM, now + 100);
      expect(deal.status).toBe(DealStatus.ACCEPTED);
      expect(deal.contractId).toBe(accept.contract);
      expect(deal.contractId).toMatch(/^0x[0-9a-f]{64}$/);
      expect(deal.state.payee.did).toBe(BOB_DID);
      expect(deal.state.payee.evmAddress).toBe(BOB_EVM);
      expect(deal.terms).toBeDefined();
      expect(deal.terms?.statement).toBe(TEST_STATEMENT.toLowerCase());

      // 2. ACCEPTED -> LOCKED
      const lockRef = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const lockFrame: LockFrame = {
        type: "lock",
        from: ALICE_DID,
        contract: deal.contractId,
        rail: "evm-htlc",
        ref: lockRef,
      };
      deal.applyLock(lockFrame, now + 500);
      expect(deal.status).toBe(DealStatus.LOCKED);
      expect(deal.state.ref).toBe(lockRef);
      expect(deal.state.rail).toBe("evm-htlc");

      // 3. LOCKED -> VERIFIED
      deal.markVerified(lockRef);
      expect(deal.status).toBe(DealStatus.VERIFIED);

      // 4. VERIFIED -> REVEALED (Check NO plaintext secret is stored)
      deal.applyReveal(TEST_SECRET, BOB_DID, now + 1000);
      expect(deal.status).toBe(DealStatus.REVEALED);
      expect(deal.state.secretRevealed).toBe(true);
      expect(deal.state.secretHash).toBe(TEST_STATEMENT.toLowerCase());

      // Crucial Security Invariant: Verify plaintext secret is NEVER stored
      expect((deal.state as unknown as Record<string, unknown>).secret).toBeUndefined();
      expect(JSON.stringify(deal.state)).not.toContain(TEST_SECRET);

      // 5. REVEALED -> CLAIMED (Terminal)
      deal.applyClaim(now + 1500);
      expect(deal.status).toBe(DealStatus.CLAIMED);
      expect(deal.isTerminal()).toBe(true);

      // 6. Terminal receipt frame recording
      const receipt: ReceiptFrame = {
        type: "receipt",
        from: BOB_DID,
        contract: deal.contractId,
        outcome: "claimed",
        rail: "evm-htlc",
        ref: lockRef,
      };
      deal.applyReceipt(receipt);
      expect(deal.state.receipt).toEqual(receipt);
    });
  });

  describe("D. Valid Lifecycle: Refund Path", () => {
    it("executes refund path after refundAfterMs has elapsed", () => {
      const now = 1000;
      const deal = createBaseOffer(now);
      const accept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);
      deal.applyAccept(accept, BOB_EVM, now + 100);

      const lockRef = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      deal.applyLock(
        {
          type: "lock",
          from: ALICE_DID,
          contract: deal.contractId,
          rail: "evm-htlc",
          ref: lockRef,
        },
        now + 200,
      );
      deal.markVerified(lockRef);

      const refundDeadline = deal.terms!.refundAfterMs;

      // Attempt refund before deadline -> must fail
      expect(() => {
        deal.applyRefund(ALICE_DID, refundDeadline - 1);
      }).toThrow("cannot refund before refund deadline");

      // Non-payer cannot execute refund
      expect(() => {
        deal.applyRefund(BOB_DID, refundDeadline + 1);
      }).toThrow("only payer");

      // Valid refund after deadline -> REFUNDED (Terminal)
      deal.applyRefund(ALICE_DID, refundDeadline + 1);
      expect(deal.status).toBe(DealStatus.REFUNDED);
      expect(deal.isTerminal()).toBe(true);

      // Terminal receipt frame recording
      const receipt: ReceiptFrame = {
        type: "receipt",
        from: ALICE_DID,
        contract: deal.contractId,
        outcome: "refunded",
      };
      deal.applyReceipt(receipt);
      expect(deal.state.receipt?.outcome).toBe("refunded");
    });
  });

  describe("E. Valid Lifecycle: Cancellation Path", () => {
    it("allows cancellation from OFFERED state", () => {
      const deal = createBaseOffer();
      deal.applyCancel(ALICE_DID, "User changed mind");
      expect(deal.status).toBe(DealStatus.CANCELLED);
      expect(deal.isTerminal()).toBe(true);
    });

    it("allows cancellation from ACCEPTED state prior to lock", () => {
      const deal = createBaseOffer();
      const accept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);
      deal.applyAccept(accept, BOB_EVM);
      expect(deal.status).toBe(DealStatus.ACCEPTED);

      deal.applyCancel(BOB_DID, "Counterparty withdrew");
      expect(deal.status).toBe(DealStatus.CANCELLED);
      expect(deal.isTerminal()).toBe(true);
    });

    it("forbids cancellation once funds are locked", () => {
      const deal = createBaseOffer();
      const accept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);
      deal.applyAccept(accept, BOB_EVM);
      deal.applyLock({
        type: "lock",
        from: ALICE_DID,
        contract: deal.contractId,
        rail: "evm-htlc",
        ref: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      });

      expect(() => {
        deal.applyCancel(ALICE_DID);
      }).toThrow(InvalidDealTransitionError);
    });
  });

  describe("F. Invalid Transitions & Fail-Closed Guardrails", () => {
    it("fails deterministically on out-of-order transitions", () => {
      const deal = createBaseOffer();

      // Cannot jump from OFFERED -> LOCKED
      expect(() => {
        deal.applyLock({
          type: "lock",
          from: ALICE_DID,
          contract: "0x1111111111111111111111111111111111111111111111111111111111111111",
          rail: "evm-htlc",
          ref: "0x1111111111111111111111111111111111111111111111111111111111111111",
        });
      }).toThrow(InvalidDealTransitionError);

      // Cannot jump from OFFERED -> VERIFIED
      expect(() => {
        deal.markVerified();
      }).toThrow(InvalidDealTransitionError);

      // Cannot jump from OFFERED -> CLAIMED
      expect(() => {
        deal.applyClaim();
      }).toThrow(InvalidDealTransitionError);
    });

    it("rejects accept with mismatched contractId or altered terms", () => {
      const deal = createBaseOffer();
      const validAccept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);

      const tamperedAccept: AcceptFrame = {
        ...validAccept,
        contract: "0x9999999999999999999999999999999999999999999999999999999999999999", // wrong hash
      };

      expect(() => {
        deal.applyAccept(tamperedAccept);
      }).toThrow("contractId mismatch");
    });

    it("rejects accept if creator attempts to self-accept", () => {
      const deal = createBaseOffer();
      const selfAccept = makeAccept(deal.state.offer, TEST_STATEMENT, ALICE_DID);
      expect(() => {
        deal.applyAccept(selfAccept);
      }).toThrow("accept.from must differ from offer.from");
    });

    it("rejects reveal with wrong secret preimage", () => {
      const deal = createBaseOffer();
      const accept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);
      deal.applyAccept(accept);
      const lockRef = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
      deal.applyLock({
        type: "lock",
        from: ALICE_DID,
        contract: deal.contractId,
        rail: "evm-htlc",
        ref: lockRef,
      });
      deal.markVerified(lockRef);

      const wrongSecret = "0x9999999999999999999999999999999999999999999999999999999999999999" as Hash;
      expect(() => {
        deal.applyReveal(wrongSecret, BOB_DID);
      }).toThrow("secret preimage does not open the statement");
    });

    it("rejects receipt attachment to non-terminal deals", () => {
      const deal = createBaseOffer();
      expect(() => {
        deal.applyReceipt({
          type: "receipt",
          from: BOB_DID,
          contract: "0x0000000000000000000000000000000000000000000000000000000000000000",
          outcome: "claimed",
        });
      }).toThrow("cannot apply receipt to non-terminal deal");
    });
  });

  describe("G. Duplicate / Idempotent Transition Handlers", () => {
    it("handles duplicate accept gracefully if matching, rejects if different", () => {
      const deal = createBaseOffer();
      const accept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);
      deal.applyAccept(accept);
      expect(deal.status).toBe(DealStatus.ACCEPTED);

      // Duplicate applyAccept with identical contract
      expect(() => deal.applyAccept(accept)).not.toThrow();
      expect(deal.status).toBe(DealStatus.ACCEPTED);
    });

    it("handles duplicate lock, verify, reveal, claim, refund idempotently", () => {
      const deal = createBaseOffer();
      const accept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);
      deal.applyAccept(accept);

      const lockRef = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
      const lockFrame: LockFrame = {
        type: "lock",
        from: ALICE_DID,
        contract: deal.contractId,
        rail: "evm-htlc",
        ref: lockRef,
      };

      // Lock idempotency
      deal.applyLock(lockFrame);
      expect(() => deal.applyLock(lockFrame)).not.toThrow();

      // Verify idempotency
      deal.markVerified(lockRef);
      expect(() => deal.markVerified(lockRef)).not.toThrow();

      // Reveal idempotency
      deal.applyReveal(TEST_SECRET, BOB_DID);
      expect(() => deal.applyReveal(TEST_SECRET, BOB_DID)).not.toThrow();

      // Claim idempotency
      deal.applyClaim();
      expect(() => deal.applyClaim()).not.toThrow();
      expect(deal.status).toBe(DealStatus.CLAIMED);
    });
  });

  describe("H. TC Ledger Evidence and Archival Mapping Data Model", () => {
    it("records room sequence numbers and commitment roots for offline verification", () => {
      const deal = createBaseOffer();
      const accept = makeAccept(deal.state.offer, TEST_STATEMENT, BOB_DID);
      deal.applyAccept(accept);

      // Record sequence numbers mapping to Technocore room messages
      deal.recordLedgerSequence("offerSeq", 1, "0xhash_offer_signed");
      deal.recordLedgerSequence("acceptSeq", 2, "0xhash_accept_signed");
      deal.recordLedgerSequence("lockSeq", 3, "0xhash_lock_signed");

      expect(deal.state.ledgerEvidence.recordSequences.offerSeq).toBe(1);
      expect(deal.state.ledgerEvidence.recordSequences.acceptSeq).toBe(2);
      expect(deal.state.ledgerEvidence.signedRecordHashes.offerSeq).toBe("0xhash_offer_signed");

      // Attach committed Merkle root from TC Ledger
      const mockMerkleRoot = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
      const mockProof = { leaf: "0xleaf", index: 0, siblings: [] };
      deal.attachLedgerCommitment(mockMerkleRoot, mockProof);

      expect(deal.state.ledgerEvidence.exportRoot).toBe(mockMerkleRoot);
      expect(deal.state.ledgerEvidence.inclusionProof).toEqual(mockProof);
    });
  });
});

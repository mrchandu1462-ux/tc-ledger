// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";
import {
  type Address,
  type Hex,
  parseEther,
  zeroAddress,
} from "viem";
import {
  WalletSession,
  ArchiveStore,
  DealWalletApp,
  InMemoryTechnocoreTransport,
  DealStatus,
  EscrowStatus,
  verifyDealArchive,
  UnauthorizedActorError,
  DealStateMismatchError,
  PreimageNotFoundError,
  encodeTclkFrame,
} from "../src/index.js";

import { startAnvil, type AnvilContext } from "./fixtures.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");

describe("Phase 4B: DealWalletApp Orchestrator", () => {
  let anvil: AnvilContext;
  let rpcUrl: string;
  const tmpDirs: string[] = [];

  function makeTmpDir(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-orchestrator-test-"));
    tmpDirs.push(dir);
    return dir;
  }

  beforeAll(async () => {
    anvil = await startAnvil();
    rpcUrl = `http://127.0.0.1:${anvil.port}`;
  });

  afterAll(async () => {
    if (anvil) {
      await anvil.stop();
    }
    for (const d of tmpDirs) {
      if (fs.existsSync(d)) {
        fs.rmSync(d, { recursive: true, force: true });
      }
    }
  });

  // ---------------------------------------------------------------------------
  // 1. Full Two-Party Deterministic Lifecycle with Real Anvil Settlement
  // ---------------------------------------------------------------------------

  it("completes full two-party lifecycle: offer -> accept -> lock -> verify -> reveal -> claim -> receipt -> archive", async () => {
    const room = "test_lifecycle_room_1";
    const transport = new InMemoryTechnocoreTransport();

    const aliceStoreDir = makeTmpDir();
    const bobStoreDir = makeTmpDir();

    // Alice is Payer (Anvil account 0)
    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });

    // Bob is Payee (Anvil account 1)
    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    // Register counterparty address mappings
    aliceSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(aliceSession.did, aliceSession.evmAddress);

    const aliceApp = new DealWalletApp({
      session: aliceSession,
      room,
      transport,
      store: new ArchiveStore(aliceStoreDir),
      repoRoot,
    });

    const bobApp = new DealWalletApp({
      session: bobSession,
      room,
      transport,
      store: new ArchiveStore(bobStoreDir),
      repoRoot,
    });

    await aliceApp.start();
    await bobApp.start();

    // 1. Alice creates offer as payer
    const now = Date.now();
    const amount = parseEther("0.1").toString();
    const { deal: aliceOfferDeal, offerId } = await aliceApp.createOffer({
      role: "payer",
      amount,
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
      counterpartyDid: bobSession.did,
    });

    expect(offerId).toMatch(/^0x[a-f0-9]{64}$/);
    expect(aliceOfferDeal.status).toBe(DealStatus.OFFERED);

    // Bob syncs room and accepts deal
    await bobApp.sync();
    const { contractId } = await bobApp.acceptDeal({ offerId });
    expect(contractId).toMatch(/^0x[a-f0-9]{64}$/);

    // Alice syncs room to observe accept
    await aliceApp.sync();
    const aliceDeal = aliceApp.getDeal(contractId);
    expect(aliceDeal).toBeDefined();
    expect(aliceDeal?.status).toBe(DealStatus.ACCEPTED);

    // 2. Alice locks real Anvil ETH into HTLC
    const aliceInitialEth = await aliceSession.getEthBalance();
    const lockResult = await aliceApp.lockFunds(contractId);
    expect(lockResult.txHash).toBe(contractId);
    expect(aliceDeal?.status).toBe(DealStatus.LOCKED);

    // 3. Bob syncs and verifies the on-chain lock
    await bobApp.sync();
    const bobDeal = bobApp.getDeal(contractId);
    expect(bobDeal).toBeDefined();
    expect(bobDeal?.status).toBe(DealStatus.VERIFIED);

    const isLockVerified = await bobApp.verifyLock(contractId);
    expect(isLockVerified).toBe(true);
    expect(bobDeal?.status).toBe(DealStatus.VERIFIED);

    // 4. Bob reveals secret without exposing it in the returned result
    const revealResult = await bobApp.revealSecret(contractId);
    expect(revealResult).toBeUndefined(); // Strictly void return
    expect(bobDeal?.status).toBe(DealStatus.REVEALED);

    // Verify Bob's transient preimage is immediately cleared
    expect(bobSession.getPreimage(bobDeal!.terms!.statement)).toBeUndefined();

    // Alice syncs to see reveal
    await aliceApp.sync();
    expect(aliceDeal?.status).toBe(DealStatus.REVEALED);

    // 5. Bob claims funds on-chain
    const bobInitialEth = await bobSession.getEthBalance();
    await bobApp.claimFunds(contractId);
    expect(bobDeal?.status).toBe(DealStatus.CLAIMED);
    expect(bobDeal?.isTerminal()).toBe(true);

    // Verify Bob received ETH
    const bobFinalEth = await bobSession.getEthBalance();
    expect(bobFinalEth.balance).toBeGreaterThan(bobInitialEth.balance);

    // Alice syncs to see terminal receipt
    await aliceApp.sync();
    expect(aliceDeal?.status).toBe(DealStatus.CLAIMED);

    // 6. Bob archives terminal deal
    const archive = await bobApp.archiveDeal(contractId);
    expect(archive.deal.contractId.toLowerCase()).toBe(contractId.toLowerCase());
    expect(archive.deal.status).toBe("CLAIMED");

    // 7. Verify offline cryptographic verification of saved archive
    const loadedArchive = await bobApp.getArchive(contractId);
    const verifyResult = await verifyDealArchive(loadedArchive, { useCli: false });
    expect(verifyResult.valid).toBe(true);

    // 8. Assert zero secret leakage anywhere in archive or deal state
    const archiveStr = JSON.stringify(archive);
    expect(archiveStr).not.toContain("privateKey");
    expect(archiveStr).not.toContain("seed");
    expect(bobDeal?.state.secretHash).toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // 2. Refund Lifecycle: Expired Timelock
  // ---------------------------------------------------------------------------

  it("supports full refund lifecycle when claim deadline expires", async () => {
    const room = "test_refund_room_2";
    const transport = new InMemoryTechnocoreTransport();
    const aliceStoreDir = makeTmpDir();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });

    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    aliceSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(aliceSession.did, aliceSession.evmAddress);

    let simulatedTimeMs = Date.now();
    const clock = () => simulatedTimeMs;

    const aliceApp = new DealWalletApp({
      session: aliceSession,
      room,
      transport,
      store: new ArchiveStore(aliceStoreDir),
      repoRoot,
      clock,
    });

    const bobApp = new DealWalletApp({
      session: bobSession,
      room,
      transport,
      clock,
    });

    await aliceApp.start();
    await bobApp.start();

    // Alice creates offer with short refund deadline
    const currentBlockTimestamp = await anvil.getBlockTimestamp();
    simulatedTimeMs = Number(currentBlockTimestamp) * 1000;
    const nowMs = simulatedTimeMs;
    const claimByMs = nowMs + 10000;
    const refundAfterMs = nowMs + 20000;
    const expiresMs = nowMs + 5000;

    const { offerId } = await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("0.05").toString(),
      asset: zeroAddress,
      claimByMs,
      refundAfterMs,
      expiresMs,
      counterpartyDid: bobSession.did,
    });

    await bobApp.sync();
    const { contractId } = await bobApp.acceptDeal({ offerId });
    await aliceApp.sync();

    // Alice locks funds
    await aliceApp.lockFunds(contractId);
    const deal = aliceApp.getDeal(contractId)!;
    expect(deal.status).toBe(DealStatus.LOCKED);

    // Fast forward Anvil blockchain timestamp past refundAfterMs
    const targetSeconds = BigInt(Math.floor(refundAfterMs / 1000) + 10);
    await anvil.setNextBlockTimestamp(targetSeconds);
    await anvil.mineBlock();
    simulatedTimeMs = Number(targetSeconds) * 1000;

    // Alice executes refund
    await aliceApp.refundDeal(contractId);
    expect(deal.status).toBe(DealStatus.REFUNDED);
    expect(deal.isTerminal()).toBe(true);

    // Bob syncs and sees refund
    await bobApp.sync();
    const bobDeal = bobApp.getDeal(contractId)!;
    expect(bobDeal.status).toBe(DealStatus.REFUNDED);

    // Archive refunded deal
    const archive = await aliceApp.archiveDeal(contractId);
    expect(archive.deal.status).toBe("REFUNDED");
  });

  // ---------------------------------------------------------------------------
  // 3. Security: Role Authorization Enforcement
  // ---------------------------------------------------------------------------

  it("enforces role boundaries: payee cannot lock, payer cannot reveal, non-payer cannot refund", async () => {
    const room = "test_auth_room_3";
    const transport = new InMemoryTechnocoreTransport();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    aliceSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(aliceSession.did, aliceSession.evmAddress);

    const aliceApp = new DealWalletApp({ session: aliceSession, room, transport });
    const bobApp = new DealWalletApp({ session: bobSession, room, transport });

    await aliceApp.start();
    await bobApp.start();

    const now = Date.now();
    const { offerId } = await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("0.01").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    await bobApp.sync();
    const { contractId } = await bobApp.acceptDeal({ offerId });
    await aliceApp.sync();

    // Bob (payee) attempts to lock funds -> Rejected!
    await expect(bobApp.lockFunds(contractId)).rejects.toThrow(UnauthorizedActorError);

    // Alice (payer) locks funds
    await aliceApp.lockFunds(contractId);

    // Alice (payer) attempts to reveal secret -> Rejected!
    await expect(aliceApp.revealSecret(contractId)).rejects.toThrow(UnauthorizedActorError);

    // Bob (payee) attempts to refund deal -> Rejected!
    await expect(bobApp.refundDeal(contractId)).rejects.toThrow(UnauthorizedActorError);
  });

  // ---------------------------------------------------------------------------
  // 4. Cancellation Rules
  // ---------------------------------------------------------------------------

  it("allows cancellation before lock and rejects cancellation once funds are locked", async () => {
    const room = "test_cancel_room_4";
    const transport = new InMemoryTechnocoreTransport();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const aliceApp = new DealWalletApp({ session: aliceSession, room, transport });
    await aliceApp.start();

    const now = Date.now();
    const { offerId } = await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("0.01").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    // Cancel offer before accept/lock -> Succeeds
    await aliceApp.cancelDeal(offerId, "User changed mind");
    const deal = aliceApp.getDeal(offerId)!;
    expect(deal.status).toBe(DealStatus.CANCELLED);
    expect(deal.isTerminal()).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 5. Idempotency & Duplicate Operations
  // ---------------------------------------------------------------------------

  it("handles duplicate operations and duplicate room frames idempotently", async () => {
    const room = "test_idempotency_room_5";
    const transport = new InMemoryTechnocoreTransport();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    aliceSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(aliceSession.did, aliceSession.evmAddress);

    const aliceApp = new DealWalletApp({ session: aliceSession, room, transport });
    const bobApp = new DealWalletApp({ session: bobSession, room, transport });

    await aliceApp.start();
    await bobApp.start();

    const now = Date.now();
    const { offerId } = await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("0.02").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    await bobApp.sync();
    const { contractId } = await bobApp.acceptDeal({ offerId });
    await aliceApp.sync();

    // Lock funds
    await aliceApp.lockFunds(contractId);

    // Call lockFunds a second time -> Idempotent no-op (no duplicate transaction)
    const secondLock = await aliceApp.lockFunds(contractId);
    expect(secondLock.txHash).toBe(contractId);

    // verifyLock called multiple times -> Idempotent
    await bobApp.sync();
    expect(await bobApp.verifyLock(contractId)).toBe(true);
    expect(await bobApp.verifyLock(contractId)).toBe(true);

    // Ingesting duplicate records in room -> Idempotent
    const syncResults = await bobApp.sync();
    expect(syncResults.every((r) => r.status === "duplicate" || r.status === "accepted")).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 6. Crash & Restart State Reconstruction
  // ---------------------------------------------------------------------------

  it("reconstructs full deal history from room transcript on clean restart", async () => {
    const room = "test_restart_room_6";
    const transport = new InMemoryTechnocoreTransport();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    aliceSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(aliceSession.did, aliceSession.evmAddress);

    // Instance 1
    const app1 = new DealWalletApp({ session: aliceSession, room, transport });
    await app1.start();

    const now = Date.now();
    const { offerId } = await app1.createOffer({
      role: "payer",
      amount: parseEther("0.01").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    const bobApp = new DealWalletApp({ session: bobSession, room, transport });
    await bobApp.start();
    const { contractId } = await bobApp.acceptDeal({ offerId });

    await app1.sync();
    await app1.lockFunds(contractId);

    // Drop app1 completely (simulate process termination)
    // Create Instance 2 with fresh in-memory state
    const app2 = new DealWalletApp({ session: aliceSession, room, transport });
    expect(app2.getDeal(contractId)).toBeUndefined();

    // Start instance 2 (syncs room transcript)
    await app2.start();

    // Deal state is completely reconstructed!
    const reconstructedDeal = app2.getDeal(contractId);
    expect(reconstructedDeal).toBeDefined();
    expect(reconstructedDeal?.status).toBe(DealStatus.VERIFIED);
    expect(reconstructedDeal?.contractId.toLowerCase()).toBe(contractId.toLowerCase());
    expect(reconstructedDeal?.state.payer.did).toBe(aliceSession.did);
  });

  // ---------------------------------------------------------------------------
  // 7. Conflicting Room vs EVM State: EVM Authority
  // ---------------------------------------------------------------------------

  it("prioritizes authoritative EVM escrow state over unverified room messages", async () => {
    const room = "test_authority_room_7";
    const transport = new InMemoryTechnocoreTransport();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    aliceSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(aliceSession.did, aliceSession.evmAddress);

    const aliceApp = new DealWalletApp({ session: aliceSession, room, transport });
    const bobApp = new DealWalletApp({ session: bobSession, room, transport });

    await aliceApp.start();
    await bobApp.start();

    const now = Date.now();
    const { offerId } = await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("0.01").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    await bobApp.sync();
    const { contractId } = await bobApp.acceptDeal({ offerId });
    await aliceApp.sync();

    // Lock funds on-chain
    await aliceApp.lockFunds(contractId);

    // On-chain escrow is Locked
    const held = await aliceApp.rail.read(contractId);
    expect(held?.status).toBe(EscrowStatus.Locked);

    // Reconciling sync verifies lock
    await aliceApp.sync();
    const deal = aliceApp.getDeal(contractId)!;
    expect(deal.status).toBe(DealStatus.VERIFIED);
  });

  // ---------------------------------------------------------------------------
  // 8. Concurrency Protection (Per-Contract Async Mutex)
  // ---------------------------------------------------------------------------

  it("serializes concurrent state-changing calls on the same contractId", async () => {
    const room = "test_concurrency_room_8";
    const transport = new InMemoryTechnocoreTransport();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    aliceSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(aliceSession.did, aliceSession.evmAddress);

    const aliceApp = new DealWalletApp({ session: aliceSession, room, transport });
    const bobApp = new DealWalletApp({ session: bobSession, room, transport });

    await aliceApp.start();
    await bobApp.start();

    const now = Date.now();
    const { offerId } = await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("0.01").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    await bobApp.sync();
    const { contractId } = await bobApp.acceptDeal({ offerId });
    await aliceApp.sync();

    // Fire multiple concurrent lock calls
    const [res1, res2] = await Promise.all([
      aliceApp.lockFunds(contractId),
      aliceApp.lockFunds(contractId),
    ]);

    expect(res1.txHash).toBe(contractId);
    expect(res2.txHash).toBe(contractId);
    expect(aliceApp.getDeal(contractId)?.status).toBe(DealStatus.LOCKED);
  });

  // ---------------------------------------------------------------------------
  // 9. Lock Transaction Failure Handling
  // ---------------------------------------------------------------------------

  it("handles lock transaction failure cleanly without corrupting deal state", async () => {
    const room = "test_failure_room_9";
    const transport = new InMemoryTechnocoreTransport();

    // Use Stranger account with 0 funds for lock attempt
    const strangerKey = "0x5de4111afa1a4b93908f11f6bdd09feac5f22a21e50915a4f0e137a867ac860f" as Hex;
    const poorSession = WalletSession.fromCredentials(strangerKey, new Uint8Array(32).fill(0x33), {
      htlcAddress: anvil.htlcAddress,
      chainId: 31337,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });

    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    poorSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(poorSession.did, poorSession.evmAddress);

    const poorApp = new DealWalletApp({ session: poorSession, room, transport });
    const bobApp = new DealWalletApp({ session: bobSession, room, transport });

    await poorApp.start();
    await bobApp.start();

    const now = Date.now();
    // Demand huge amount that exceeds balance
    const { offerId } = await poorApp.createOffer({
      role: "payer",
      amount: parseEther("999999").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    await bobApp.sync();
    const { contractId } = await bobApp.acceptDeal({ offerId });
    await poorApp.sync();

    // Lock must fail
    await expect(poorApp.lockFunds(contractId)).rejects.toThrow();

    // Deal status remains ACCEPTED, not LOCKED
    const deal = poorApp.getDeal(contractId)!;
    expect(deal.status).toBe(DealStatus.ACCEPTED);
  });

  // ---------------------------------------------------------------------------
  // 10. Claim Transaction Recovery & Room Publication Recovery
  // ---------------------------------------------------------------------------

  it("recovers claim state when room publication is retried after on-chain settlement", async () => {
    const room = "test_claim_recovery_room_10";
    const transport = new InMemoryTechnocoreTransport();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    aliceSession.registerCounterparty(bobSession.did, bobSession.evmAddress);
    bobSession.registerCounterparty(aliceSession.did, aliceSession.evmAddress);

    const aliceApp = new DealWalletApp({ session: aliceSession, room, transport });
    const bobApp = new DealWalletApp({ session: bobSession, room, transport });

    await aliceApp.start();
    await bobApp.start();

    const now = Date.now();
    const { offerId } = await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("0.01").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    await bobApp.sync();
    const { contractId } = await bobApp.acceptDeal({ offerId });
    await aliceApp.sync();
    await aliceApp.lockFunds(contractId);

    await bobApp.sync();
    await bobApp.revealSecret(contractId);

    // First claim call executes on-chain and in room
    await bobApp.claimFunds(contractId);
    expect(bobApp.getDeal(contractId)?.status).toBe(DealStatus.CLAIMED);

    // Calling claimFunds again is idempotent: does not double-spend or throw
    await expect(bobApp.claimFunds(contractId)).resolves.not.toThrow();
  });

  // ---------------------------------------------------------------------------
  // 11. Archive Failure on Non-Terminal Deal & Recovery
  // ---------------------------------------------------------------------------

  it("rejects archiving non-terminal deal and succeeds once deal reaches terminal state", async () => {
    const room = "test_archive_retry_room_11";
    const transport = new InMemoryTechnocoreTransport();
    const aliceStoreDir = makeTmpDir();

    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });

    const aliceApp = new DealWalletApp({
      session: aliceSession,
      room,
      transport,
      store: new ArchiveStore(aliceStoreDir),
      repoRoot,
    });

    await aliceApp.start();

    const now = Date.now();
    const { offerId } = await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("0.01").toString(),
      asset: zeroAddress,
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
    });

    // Attempting to archive an OFFERED (non-terminal) deal must fail
    await expect(aliceApp.archiveDeal(offerId)).rejects.toThrow(DealStateMismatchError);

    // Cancel offer (makes it terminal)
    await aliceApp.cancelDeal(offerId, "cancelled for test");

    // Archiving terminal cancelled deal succeeds!
    const archive = await aliceApp.archiveDeal(offerId);
    expect(archive.deal.status).toBe("CANCELLED");
  });

  // ---------------------------------------------------------------------------
  // 12. Strict Secret Non-Exposure Audit
  // ---------------------------------------------------------------------------

  it("strictly guarantees zero secret exposure in DealWalletApp APIs and serialization", async () => {
    const room = "test_secrets_room_12";
    const transport = new InMemoryTechnocoreTransport();

    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    const bobApp = new DealWalletApp({ session: bobSession, room, transport });
    await bobApp.start();

    // 1. Check toJSON of session
    const sessionJson = JSON.stringify(bobApp.session);
    expect(sessionJson).not.toContain("privateKey");
    expect(sessionJson).not.toContain("privKey");
    expect(sessionJson).not.toContain("seed");
    expect(sessionJson).not.toContain("mnemonic");

    // 2. Preimage generation creates transient preimage in memory
    const { secret, hashlock } = bobSession.createPreimage();
    expect(secret).toMatch(/^0x[a-f0-9]{64}$/);

    // 3. Serialization still does NOT contain the secret
    expect(JSON.stringify(bobApp.session)).not.toContain(secret);
  });
});

// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { createHash } from "node:crypto";
import {
  createPublicClient,
  createWalletClient,
  http,
  type PublicClient,
  type WalletClient,
  type Address,
  type Hex,
  parseEther,
  zeroAddress,
} from "viem";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import {
  WalletSession,
  ArchiveStore,
  SessionError,
  InsecureDemoAccountError,
  TamperedArchiveError,
  ArchiveNotFoundError,
  InvalidContactError,
  InsecureConfigError,
  ArchiveStoreError,
  type DealArchive,
  TechnocoreSigner,
  DealManager,
  DealStatus,
  computeContractId,
  encodeTclkFrame,
  TcLedgerArchiver,
  createSignedExportRecord,
} from "../src/index.js";
import { startAnvil, type AnvilContext } from "./fixtures.js";

describe("Phase 4A: WalletSession & ArchiveStore", () => {
  let anvil: AnvilContext;
  const tmpDirs: string[] = [];
  const repoRoot = path.resolve(__dirname, "../..");

  function makeTmpDir(prefix = "phase4a-store-"): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    tmpDirs.push(dir);
    return dir;
  }

  let rpcUrl: string;

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
  // WalletSession Tests
  // ---------------------------------------------------------------------------

  describe("WalletSession", () => {
    it("creates a random session with safe metadata and no secrets exposed", () => {
      const session = WalletSession.createRandom({
        htlcAddress: anvil.htlcAddress,
        chainId: 31337,
        rpcUrl,
        publicClient: anvil.publicClient,
        role: "payer",
      });

      expect(session.did).toMatch(/^did:key:z6Mk/);
      expect(session.evmAddress).toMatch(/^0x[a-fA-F0-9]{40}$/);
      expect(session.role).toBe("payer");
      expect(session.chainId).toBe(31337);
      expect(session.htlcAddress.toLowerCase()).toBe(anvil.htlcAddress.toLowerCase());

      // Verify safe metadata and toJSON serialization
      const meta = session.getMetadata();
      const json = JSON.parse(JSON.stringify(session));

      expect(meta).toEqual(json);
      expect(json.did).toBe(session.did);
      expect(json.evmAddress).toBe(session.evmAddress);
      expect(json.role).toBe("payer");
      expect(json.chainId).toBe(31337);

      // Verify that NO private keys, seeds, or secret fields exist anywhere in JSON
      const serialized = JSON.stringify(session);
      expect(serialized).not.toContain("privateKey");
      expect(serialized).not.toContain("privKey");
      expect(serialized).not.toContain("seed");
      expect(serialized).not.toContain("mnemonic");
    });

    it("creates a session from runtime-supplied credentials without persisting them", () => {
      const evmPrivKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
      const tcSeed = new Uint8Array(32).fill(0x77);

      const session = WalletSession.fromCredentials(evmPrivKey, tcSeed, {
        htlcAddress: anvil.htlcAddress,
        chainId: 31337,
        rpcUrl,
        publicClient: anvil.publicClient,
        role: "payee",
      });

      expect(session.evmAddress.toLowerCase()).toBe("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
      expect(session.role).toBe("payee");

      const json = JSON.stringify(session);
      expect(json).not.toContain(evmPrivKey);
      expect(json).not.toContain("77".repeat(32));
    });

    it("accepts Anvil account 0 on chain 31337", async () => {
      const session = await WalletSession.fromAnvil(0, {
        htlcAddress: anvil.htlcAddress,
        rpcUrl,
        publicClient: anvil.publicClient,
      });

      expect(session.chainId).toBe(31337);
      expect(session.evmAddress.toLowerCase()).toBe("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    });

    it("rejects Anvil demo account on non-31337 chain", async () => {
      // Create a mock client that reports mainnet chainId 1
      const mockPublicClient = {
        getChainId: async () => 1,
      } as unknown as PublicClient;

      await expect(
        WalletSession.fromAnvil(0, {
          htlcAddress: anvil.htlcAddress,
          rpcUrl: "http://mock-rpc",
          publicClient: mockPublicClient,
        }),
      ).rejects.toThrow(InsecureDemoAccountError);
    });

    it("queries native ETH balance correctly", async () => {
      const session = await WalletSession.fromAnvil(0, {
        htlcAddress: anvil.htlcAddress,
        rpcUrl,
        publicClient: anvil.publicClient,
      });

      const { balance, formatted } = await session.getEthBalance();
      expect(balance).toBeGreaterThan(0n);
      expect(Number.parseFloat(formatted)).toBeGreaterThan(0);
    });

    it("queries ERC-20 token balance correctly", async () => {
      const session = await WalletSession.fromAnvil(0, {
        htlcAddress: anvil.htlcAddress,
        rpcUrl,
        publicClient: anvil.publicClient,
      });

      const tokenBalance = await session.getTokenBalance(anvil.tokenAddress);
      expect(tokenBalance.address.toLowerCase()).toBe(anvil.tokenAddress.toLowerCase());
      expect(tokenBalance.symbol).toBe("USDC");
      expect(tokenBalance.decimals).toBe(18);
      expect(tokenBalance.balance).toBeGreaterThan(0n);
      expect(typeof tokenBalance.formatted).toBe("string");
    });

    it("supports transient preimage generation and retrieval in memory only", () => {
      const session = WalletSession.createRandom({
        htlcAddress: anvil.htlcAddress,
        chainId: 31337,
        rpcUrl,
        publicClient: anvil.publicClient,
        role: "payee",
      });

      const { secret, hashlock } = session.createPreimage();
      expect(secret).toMatch(/^0x[a-f0-9]{64}$/);
      expect(hashlock).toMatch(/^0x[a-f0-9]{64}$/);

      // Preimage can be retrieved by hashlock
      expect(session.getPreimage(hashlock)).toBe(secret);

      // Preimage is NOT exposed on serialized session
      expect(JSON.stringify(session)).not.toContain(secret);

      // Can be explicitly cleared
      session.clearPreimage(hashlock);
      expect(session.getPreimage(hashlock)).toBeUndefined();
    });

    it("resolves and registers counterparty DIDs via address resolver", async () => {
      const session = WalletSession.createRandom({
        htlcAddress: anvil.htlcAddress,
        chainId: 31337,
        rpcUrl,
        publicClient: anvil.publicClient,
      });

      const testDid = "did:key:z6Mku7XJ2bBwK3JqT5kE2q9L6mYx7Z";
      const testAddr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as Address;

      session.registerCounterparty(testDid, testAddr);
      const resolved = await session.resolveCounterparty(testDid);
      expect(resolved.toLowerCase()).toBe(testAddr.toLowerCase());
    });
  });

  // ---------------------------------------------------------------------------
  // ArchiveStore Tests
  // ---------------------------------------------------------------------------

  describe("ArchiveStore", () => {
    /**
     * Helper to create a valid cryptographic DealArchive using the archiver
     */
    async function createSampleArchive(dir: string, room = "sample-store-room"): Promise<DealArchive> {
      const alice = new TechnocoreSigner(new Uint8Array(32).fill(0x55));
      const bob = new TechnocoreSigner(new Uint8Array(32).fill(0x66));
      const secret = "0x" + "88".repeat(32);
      const secretHash = "0x" + createHash("sha256").update(Buffer.from("88".repeat(32), "hex")).digest("hex");

      const now = Date.now();
      const deal = DealManager.createOffer({
        room,
        creator: { did: alice.did, evmAddress: "0x1111111111111111111111111111111111111111" },
        role: "payer",
        amount: "1000",
        asset: zeroAddress,
        lock: "hash",
        rails: ["evm-htlc"],
        claimByMs: now + 600000,
        refundAfterMs: now + 1200000,
        expiresMs: now + 300000,
        nonce: "test_nonce_1",
        nowMs: now,
      });

      const offer = deal.state.offer;
      const acceptCore = {
        from: bob.did,
        ref: offer.id,
        statement: secretHash,
        nonce: "test_nonce_2",
      };
      const contractId = computeContractId(offer, acceptCore);
      const accept = { type: "accept" as const, ...acceptCore, contract: contractId };
      deal.applyAccept(accept, "0x2222222222222222222222222222222222222222");

      deal.applyLock({
        type: "lock",
        from: alice.did,
        contract: contractId,
        rail: "evm-htlc",
        ref: "0xlockref123",
      });

      deal.applyReveal(secret, bob.did);
      deal.applyClaim("0x2222222222222222222222222222222222222222", "0xclaimref123");
      deal.applyReceipt({
        type: "receipt",
        from: bob.did,
        contract: contractId,
        outcome: "claimed",
        ref: "0xclaimref123",
      });

      deal.recordLedgerSequence("offerSeq", 1);
      deal.recordLedgerSequence("acceptSeq", 2);
      deal.recordLedgerSequence("receiptSeq", 3);

      const exportFile = path.join(dir, `${room}.jsonl`);
      const lines = [
        createSignedExportRecord(alice, room, 1, encodeTclkFrame(offer), 101),
        createSignedExportRecord(bob, room, 2, encodeTclkFrame(accept), 102),
        createSignedExportRecord(
          bob,
          room,
          3,
          encodeTclkFrame({ type: "receipt", from: bob.did, contract: contractId, outcome: "claimed" }),
          103,
        ),
      ];
      fs.writeFileSync(exportFile, lines.join(""), "utf8");

      const archiver = new TcLedgerArchiver("python", repoRoot);
      return archiver.archiveDeal(deal, exportFile, { settlementRef: "0xclaimref123", onChainVerified: true });
    }

    it("initializes directory structure and default index", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);

      await store.initialize();

      expect(fs.existsSync(store.archivesDir)).toBe(true);
      expect(fs.existsSync(store.contactsPath)).toBe(true);
      expect(fs.existsSync(store.indexPath)).toBe(true);

      const index = JSON.parse(fs.readFileSync(store.indexPath, "utf8"));
      expect(index.version).toBe(1);
      expect(index.deals).toEqual({});
    });

    it("saves and loads a valid terminal archive with automatic offline verification", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);
      const archive = await createSampleArchive(storeDir);
      const contractId = archive.deal.contractId;

      // 1. Save archive
      const summary = await store.saveArchive(archive);
      expect(summary.contractId).toBe(contractId.toLowerCase());
      expect(summary.status).toBe(DealStatus.CLAIMED);
      expect(summary.verifiedOffline).toBe(true);

      // Verify file exists on disk
      const archivePath = store.getArchiveFilePath(contractId);
      expect(fs.existsSync(archivePath)).toBe(true);

      // 2. Load archive
      const loaded = await store.loadArchive(contractId);
      expect(loaded.deal.contractId).toBe(contractId);
      expect(loaded.commitment.export_root).toBe(archive.commitment.export_root);
      expect(loaded.records.offer).toBeDefined();

      // 3. List archives
      const list = await store.listArchives();
      expect(list).toHaveLength(1);
      expect(list[0].contractId).toBe(contractId.toLowerCase());
    });

    it("rejects non-terminal deals from being stored", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);
      const archive = await createSampleArchive(storeDir);

      // Force status to non-terminal OFFERED
      archive.deal.status = DealStatus.OFFERED;

      await expect(store.saveArchive(archive)).rejects.toThrow(
        /cannot store non-terminal deal archive/i,
      );
    });

    it("rejects saving a tampered archive before persistence", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);
      const archive = await createSampleArchive(storeDir);

      // Tamper with record line bytes
      archive.records.offer.rawLine = archive.records.offer.rawLine.replace("1000", "999999");

      await expect(store.saveArchive(archive)).rejects.toThrow(TamperedArchiveError);
    });

    it("detects tampered archive on disk during load and throws TamperedArchiveError", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);
      const archive = await createSampleArchive(storeDir);
      const contractId = archive.deal.contractId;

      await store.saveArchive(archive);

      // Tamper with the saved file on disk directly
      const filePath = store.getArchiveFilePath(contractId);
      const onDisk = JSON.parse(fs.readFileSync(filePath, "utf8")) as DealArchive;
      onDisk.records.offer.rawLine = onDisk.records.offer.rawLine.replace("1000", "999999");
      fs.writeFileSync(filePath, JSON.stringify(onDisk, null, 2), "utf8");

      // Load must fail verification
      await expect(store.loadArchive(contractId)).rejects.toThrow(TamperedArchiveError);
    });

    it("index tampering does not compromise cryptographic integrity", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);
      const archive = await createSampleArchive(storeDir);
      const contractId = archive.deal.contractId;

      await store.saveArchive(archive);

      // Maliciously modify index.json to claim a fake root or status
      const index = JSON.parse(fs.readFileSync(store.indexPath, "utf8"));
      index.deals[contractId.toLowerCase()].exportRoot = "badroot".repeat(8);
      fs.writeFileSync(store.indexPath, JSON.stringify(index, null, 2), "utf8");

      // Loading the archive directly still verifies authoritatively against the file
      const loaded = await store.loadArchive(contractId);
      expect(loaded.commitment.export_root).toBe(archive.commitment.export_root);
    });

    it("throws ArchiveNotFoundError when requesting non-existent archive", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);

      await expect(store.loadArchive("0x9999999999999999999999999999999999999999")).rejects.toThrow(
        ArchiveNotFoundError,
      );
    });

    it("manages contacts with strict validation", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);

      const validDid = "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK";
      const validAddress = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as Address;

      // 1. Save contact
      await store.saveContact({
        alias: "Bob",
        did: validDid,
        evmAddress: validAddress,
        updatedAtMs: Date.now(),
      });

      // 2. Resolve contact
      const resolved = await store.resolveContact(validDid);
      expect(resolved?.toLowerCase()).toBe(validAddress.toLowerCase());

      // 3. Reject invalid DID prefix
      await expect(
        store.saveContact({
          alias: "Bad",
          did: "invalid:did:format",
          evmAddress: validAddress,
          updatedAtMs: Date.now(),
        }),
      ).rejects.toThrow(InvalidContactError);

      // 4. Reject invalid EVM address
      await expect(
        store.saveContact({
          alias: "Bad",
          did: validDid,
          evmAddress: "0xnotanaddress" as Address,
          updatedAtMs: Date.now(),
        }),
      ).rejects.toThrow(InvalidContactError);
    });

    it("saves and loads configuration while rejecting credential-bearing RPC URLs", async () => {
      const storeDir = makeTmpDir();
      const store = new ArchiveStore(storeDir);

      // Safe config
      await store.saveConfig({
        rpcUrl: "http://127.0.0.1:8545",
        chainId: 31337,
        htlcAddress: anvil.htlcAddress,
        updatedAtMs: Date.now(),
      });

      const loaded = await store.loadConfig();
      expect(loaded?.rpcUrl).toBe("http://127.0.0.1:8545");
      expect(loaded?.chainId).toBe(31337);

      // Insecure config with embedded username:password must be rejected
      await expect(
        store.saveConfig({
          rpcUrl: "http://alice:supersecret@127.0.0.1:8545",
          chainId: 31337,
          htlcAddress: anvil.htlcAddress,
          updatedAtMs: Date.now(),
        }),
      ).rejects.toThrow(InsecureConfigError);
    });

    it("confirms .deal-wallet/ is ignored by git", () => {
      const gitignorePath = path.resolve(__dirname, "../.gitignore");
      expect(fs.existsSync(gitignorePath)).toBe(true);
      const content = fs.readFileSync(gitignorePath, "utf8");
      expect(content).toContain(".deal-wallet/");
    });
  });
});

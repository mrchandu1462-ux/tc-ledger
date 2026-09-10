// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";
import { parseEther } from "viem";
import {
  WalletSession,
  DealWalletApp,
  DealWalletServer,
  InMemoryTechnocoreTransport,
  ArchiveStore,
  DealStatus,
  type SafeDealDto,
  type SafeSessionMetadataDto,
  type SafeBalanceDto,
  type SafeDealsResponseDto,
  type SafeArchivesResponseDto,
  type HealthResponseDto,
  type SafeMessageDto,
  type SafeMessagesResponseDto,
  type CreateOfferRequestDto,
  type DealActionResponseDto,
} from "../src/index.js";

import { startAnvil, type AnvilContext } from "./fixtures.js";

describe("Phase 4C-1: Deal Wallet Local HTTP Server & Dashboard API", () => {
  let anvil: AnvilContext;
  let rpcUrl: string;
  const tmpDirs: string[] = [];

  function makeTmpDir(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-server-test-"));
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
  // 1. Server Lifecycle & Loopback Binding
  // ---------------------------------------------------------------------------

  it("binds to loopback 127.0.0.1 and starts/stops successfully", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const app = new DealWalletApp({ session, room: "test-room-lifecycle" });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });

    const started = await server.start();
    expect(started.host).toBe("127.0.0.1");
    expect(started.port).toBeGreaterThan(0);
    expect(server.url).toBe(`http://127.0.0.1:${started.port}`);

    // Verify HTTP connectivity
    const res = await fetch(`${server.url}/api/health`);
    expect(res.status).toBe(200);

    await server.stop();
    expect(server.server).toBeNull();
  });

  it("rejects non-loopback bindings", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const app = new DealWalletApp({ session, room: "test-room-nonloopback" });

    expect(() => {
      new DealWalletServer({ app, host: "0.0.0.0" as any, port: 3456 });
    }).toThrow(/must bind to loopback address/i);

    expect(() => {
      new DealWalletServer({ app, host: "192.168.1.100" as any, port: 3456 });
    }).toThrow(/must bind to loopback address/i);
  });

  // ---------------------------------------------------------------------------
  // 2. Dashboard HTML Serving
  // ---------------------------------------------------------------------------

  it("serves the embedded dashboard HTML at / and /index.html with security headers", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const app = new DealWalletApp({ session, room: "test-room-dashboard" });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });
    await server.start();

    try {
      // Test root /
      const resRoot = await fetch(server.url);
      expect(resRoot.status).toBe(200);
      expect(resRoot.headers.get("content-type")).toContain("text/html");
      expect(resRoot.headers.get("x-content-type-options")).toBe("nosniff");
      expect(resRoot.headers.get("x-frame-options")).toBe("DENY");

      const html = await resRoot.text();
      expect(html).toContain("Technocore Deal Wallet");
      expect(html).toContain("tclk/1 EVM Settlement Rail");
      expect(html).toContain("escapeHtml");
      expect(html).toContain("/api/session");
      expect(html).toContain("/api/deals");
      expect(html).toContain("/api/balance");
      expect(html).toContain("/api/archives");

      // Test /index.html
      const resIndex = await fetch(`${server.url}/index.html`);
      expect(resIndex.status).toBe(200);
      expect(resIndex.headers.get("content-type")).toContain("text/html");

      // Test HEAD request
      const resHead = await fetch(server.url, { method: "HEAD" });
      expect(resHead.status).toBe(200);
      expect(resHead.headers.get("content-type")).toContain("text/html");
      const headBody = await resHead.text();
      expect(headBody).toBe("");
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 3. Health Endpoint (/api/health)
  // ---------------------------------------------------------------------------

  it("returns server health metadata on /api/health", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const app = new DealWalletApp({ session, room: "test-room-health" });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });
    await server.start();

    try {
      const res = await fetch(`${server.url}/api/health`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("application/json");

      const data: HealthResponseDto = await res.json();
      expect(data.status).toBe("ok");
      expect(typeof data.uptime).toBe("number");
      expect(typeof data.timestamp).toBe("number");
      expect(data.uptime).toBeGreaterThanOrEqual(0);
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 4. Session Endpoint (/api/session) & Zero Secret Exposure
  // ---------------------------------------------------------------------------

  it("returns only safe public session metadata on /api/session without credentials", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const app = new DealWalletApp({ session, room: "alpha-settlement-room" });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });
    await server.start();

    try {
      const res = await fetch(`${server.url}/api/session`);
      expect(res.status).toBe(200);

      const rawJson = await res.text();
      const data: SafeSessionMetadataDto = JSON.parse(rawJson);

      expect(data.did).toBe(session.did);
      expect(data.evmAddress.toLowerCase()).toBe(session.evmAddress.toLowerCase());
      expect(data.chainId).toBe(31337);
      expect(data.role).toBe("payer");
      expect(data.htlcAddress.toLowerCase()).toBe(anvil.htlcAddress.toLowerCase());
      expect(data.room).toBe("alpha-settlement-room");

      // CRITICAL SECURITY CHECKS:
      // Must not contain Anvil private key
      expect(rawJson).not.toContain("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
      // Must not contain "privateKey" or "seed" or "signer" keys
      expect(rawJson).not.toContain("privateKey");
      expect(rawJson).not.toContain("_account");
      expect(rawJson).not.toContain("_signer");
      expect(rawJson).not.toContain("seed");
      expect(rawJson).not.toContain("secret");
      expect(rawJson).not.toContain("rpcUrl");
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 5. Balance Endpoint (/api/balance)
  // ---------------------------------------------------------------------------

  it("returns ETH balance for the session address on /api/balance", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const app = new DealWalletApp({ session, room: "test-room-balance" });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });
    await server.start();

    try {
      const res = await fetch(`${server.url}/api/balance`);
      expect(res.status).toBe(200);

      const data: SafeBalanceDto = await res.json();
      expect(data.evmAddress.toLowerCase()).toBe(session.evmAddress.toLowerCase());
      expect(data.chainId).toBe(31337);
      expect(BigInt(data.balance)).toBeGreaterThan(0n);
      expect(parseFloat(data.formatted)).toBeGreaterThan(100); // Anvil account 0 starts with ~10000 ETH
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 6. Deals Endpoint (/api/deals) & Preimage Secrecy
  // ---------------------------------------------------------------------------

  it("returns safe DTOs for active and completed deals, never leaking preimages", async () => {
    const transport = new InMemoryTechnocoreTransport();
    const room = "test-deals-dto-room";

    // Alice (Payer)
    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });

    // Bob (Payee)
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

    // Payee generates a transient secret preimage
    const { secret, hashlock } = bobSession.createPreimage();

    // Alice creates an offer
    const now = Date.now();
    await aliceApp.createOffer({
      role: "payer",
      amount: parseEther("1.5").toString(),
      asset: "ETH",
      claimByMs: now + 60000,
      refundAfterMs: now + 120000,
      expiresMs: now + 30000,
      counterpartyDid: bobSession.did,
    });

    // Bob syncs and accepts using hashlock
    await bobApp.sync();
    const offers = bobApp.listActiveDeals();
    expect(offers.length).toBe(1);
    const offerId = offers[0].state.offer.id;

    await bobApp.acceptDeal({
      offerId,
      statement: hashlock,
    });

    // Alice syncs
    await aliceApp.sync();

    // Start server for Bob (who holds the transient secret preimage in memory!)
    const bobServer = new DealWalletServer({ app: bobApp, host: "127.0.0.1", port: 0 });
    await bobServer.start();

    try {
      const res = await fetch(`${bobServer.url}/api/deals`);
      expect(res.status).toBe(200);

      const rawJson = await res.text();
      const data: SafeDealsResponseDto = JSON.parse(rawJson);

      expect(data.active.length).toBe(1);
      expect(data.completed.length).toBe(0);
      expect(data.counts.active).toBe(1);
      expect(data.counts.completed).toBe(0);

      const deal = data.active[0];
      expect(deal.status).toBe(DealStatus.ACCEPTED);
      expect(deal.amount).toBe(parseEther("1.5").toString());
      expect(deal.asset).toBe("ETH");
      expect(deal.statement?.toLowerCase()).toBe(hashlock.toLowerCase());
      expect(deal.payer.did).toBe(aliceSession.did);
      expect(deal.payee.did).toBe(bobSession.did);
      expect(deal.isTerminal).toBe(false);

      // CRITICAL PREIMAGE LEAK CHECK:
      // Secret preimage MUST NEVER appear anywhere in the HTTP response JSON!
      expect(rawJson).not.toContain(secret);
      expect(rawJson.toLowerCase()).not.toContain(secret.toLowerCase());
      // Raw internal collections must not be serialized
      expect(rawJson).not.toContain("_transientPreimages");
      expect(rawJson).not.toContain("ledgerEvidence");
    } finally {
      await bobServer.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 7. Archives Endpoint (/api/archives)
  // ---------------------------------------------------------------------------

  it("returns verified archive summaries on /api/archives", async () => {
    const storeDir = makeTmpDir();
    const store = new ArchiveStore(storeDir);
    await store.initialize();

    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const app = new DealWalletApp({ session, room: "test-room-archives", store });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });
    await server.start();

    try {
      const res = await fetch(`${server.url}/api/archives`);
      expect(res.status).toBe(200);

      const data: SafeArchivesResponseDto = await res.json();
      expect(Array.isArray(data.archives)).toBe(true);
      expect(data.count).toBe(0);
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 8. Security: Route 404 & Method 405 Rejections
  // ---------------------------------------------------------------------------

  it("returns 404 for unknown routes and 405 for unsupported HTTP methods", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const app = new DealWalletApp({ session, room: "test-room-errors" });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });
    await server.start();

    try {
      // 404 Unknown routes
      const notFound1 = await fetch(`${server.url}/api/unknown`);
      expect(notFound1.status).toBe(404);
      const json404 = await notFound1.json();
      expect(json404.error).toBe("Not Found");

      const notFound2 = await fetch(`${server.url}/admin`);
      expect(notFound2.status).toBe(404);

      // 405 Method Not Allowed (POST to GET-only endpoint)
      const postSession = await fetch(`${server.url}/api/session`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ malicious: true }),
      });
      expect(postSession.status).toBe(405);
      expect(postSession.headers.get("allow")).toContain("GET, HEAD");
      const json405 = await postSession.json();
      expect(json405.error).toBe("Method Not Allowed");

      // 405 PUT /api/deals
      const putDeals = await fetch(`${server.url}/api/deals`, { method: "PUT" });
      expect(putDeals.status).toBe(405);

      // 405 DELETE /api/balance
      const deleteBal = await fetch(`${server.url}/api/balance`, { method: "DELETE" });
      expect(deleteBal.status).toBe(405);
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 9. Multi-Instance Demonstration (Account 0 and Account 1 concurrently)
  // ---------------------------------------------------------------------------

  it("supports multiple concurrent server instances on distinct ports", async () => {
    const session0 = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const session1 = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });

    const app0 = new DealWalletApp({ session: session0, room: "demo-room" });
    const app1 = new DealWalletApp({ session: session1, room: "demo-room" });

    const server0 = new DealWalletServer({ app: app0, host: "127.0.0.1", port: 0 });
    const server1 = new DealWalletServer({ app: app1, host: "127.0.0.1", port: 0 });

    await server0.start();
    await server1.start();

    try {
      expect(server0.actualPort).not.toBe(server1.actualPort);

      const [res0, res1] = await Promise.all([
        fetch(`${server0.url}/api/session`),
        fetch(`${server1.url}/api/session`),
      ]);

      const data0: SafeSessionMetadataDto = await res0.json();
      const data1: SafeSessionMetadataDto = await res1.json();

      expect(data0.role).toBe("payer");
      expect(data1.role).toBe("payee");
      expect(data0.evmAddress.toLowerCase()).not.toBe(data1.evmAddress.toLowerCase());
      expect(data0.did).not.toBe(data1.did);
    } finally {
      await server0.stop();
      await server1.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 10. Background Sync Loop & Clean Shutdown
  // ---------------------------------------------------------------------------

  it("runs background sync loop periodically and shuts down cleanly", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const transport = new InMemoryTechnocoreTransport();
    const app = new DealWalletApp({ session, room: "test-sync-loop", transport });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0, syncIntervalMs: 50 });

    await server.start();
    try {
      expect(server.messageCache).toHaveLength(0);

      // Publish external message directly into transport
      await transport.sendSigned("test-sync-loop", "external message", session.signer);

      // Wait for background sync loop to pick it up
      await new Promise((r) => setTimeout(r, 120));

      const res = await fetch(`${server.url}/api/messages`);
      const data: SafeMessagesResponseDto = await res.json();
      expect(data.count).toBe(1);
      expect(data.messages[0].text).toBe("external message");
    } finally {
      await server.stop();
      expect(server.server).toBeNull();
    }
  });

  // ---------------------------------------------------------------------------
  // 11. GET /api/messages (Safe projection, Deduplication & Ordering)
  // ---------------------------------------------------------------------------

  it("returns safe room messages with chronological ordering and deduplication", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const transport = new InMemoryTechnocoreTransport();
    const app = new DealWalletApp({ session, room: "test-msgs-room", transport });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });

    await server.start();
    try {
      await transport.sendSigned("test-msgs-room", "hello world", session.signer);
      await transport.sendSigned("test-msgs-room", "second message", session.signer);
      await server.triggerSync();

      const res = await fetch(`${server.url}/api/messages`);
      expect(res.status).toBe(200);
      const data: SafeMessagesResponseDto = await res.json();
      expect(data.count).toBe(2);
      expect(data.messages[0].seq).toBeLessThan(data.messages[1].seq);
      expect(data.messages[0].isSelf).toBe(true);
      expect(data.messages[0].text).toBe("hello world");

      // Verify no cryptographic secrets or internal signer state exposed
      const serialized = JSON.stringify(data);
      expect(serialized).not.toContain("sig");
      expect(serialized).not.toContain("nonce");
      expect(serialized).not.toContain("privateKey");
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 12. POST /api/chat (Validation & Ingestion)
  // ---------------------------------------------------------------------------

  it("handles POST /api/chat with strict validation", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
    });
    const transport = new InMemoryTechnocoreTransport();
    const app = new DealWalletApp({ session, room: "test-chat-room", transport });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });

    await server.start();
    try {
      // 1. Successful chat
      const okRes = await fetch(`${server.url}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: "  hello from client  " }),
      });
      expect(okRes.status).toBe(200);
      const okData = await okRes.json();
      expect(okData.ok).toBe(true);

      const msgsRes = await fetch(`${server.url}/api/messages`);
      const msgsData: SafeMessagesResponseDto = await msgsRes.json();
      expect(msgsData.count).toBe(1);
      expect(msgsData.messages[0].text).toBe("hello from client"); // trimmed

      // 2. Reject empty text
      const emptyRes = await fetch(`${server.url}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: "   " }),
      });
      expect(emptyRes.status).toBe(400);

      // 3. Reject oversized text (>4096 chars)
      const oversizedText = "x".repeat(4097);
      const overRes = await fetch(`${server.url}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: oversizedText }),
      });
      expect(overRes.status).toBe(400);

      // 4. Reject malformed JSON
      const malformedRes = await fetch(`${server.url}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{ bad json",
      });
      expect(malformedRes.status).toBe(400);

      // 5. Reject oversized request payload (>64KB)
      const hugePayload = JSON.stringify({ text: "y".repeat(70000) });
      const hugeRes = await fetch(`${server.url}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: hugePayload,
      });
      expect(hugeRes.status).toBe(413);
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 13. POST /api/deals/offer (Validation & Creation)
  // ---------------------------------------------------------------------------

  it("handles POST /api/deals/offer and enforces strict validation and integer conversion", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const transport = new InMemoryTechnocoreTransport();
    const app = new DealWalletApp({ session, room: "test-offer-room", transport });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });

    await server.start();
    try {
      // 1. Successful offer creation
      const res = await fetch(`${server.url}/api/deals/offer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          amountEth: "0.05",
          claimBySec: 600,
          refundAfterSec: 1200,
          expiresSec: 300,
        }),
      });
      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.ok).toBe(true);
      expect(data.offerId).toBeDefined();
      expect(data.deal.amount).toBe(parseEther("0.05").toString()); // Exact 50000000000000000 wei
      expect(data.deal.status).toBe(DealStatus.OFFERED);

      // 2. Reject non-positive amount
      const nonPosRes = await fetch(`${server.url}/api/deals/offer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amountEth: "0" }),
      });
      expect(nonPosRes.status).toBe(400);

      // 3. Reject deadline ordering violation (claimBy >= refundAfter)
      const orderRes = await fetch(`${server.url}/api/deals/offer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          amountEth: "0.1",
          claimBySec: 1200,
          refundAfterSec: 600,
        }),
      });
      expect(orderRes.status).toBe(400);

      // 4. Reject role contradiction (payer session trying to create offer as payee)
      const roleRes = await fetch(`${server.url}/api/deals/offer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          amountEth: "0.1",
          role: "payee",
        }),
      });
      expect(roleRes.status).toBe(400);

      // 5. Reject invalid counterparty DID
      const didRes = await fetch(`${server.url}/api/deals/offer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          amountEth: "0.1",
          counterpartyDid: "not-a-did",
        }),
      });
      expect(didRes.status).toBe(400);
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 14. Action Endpoints Security (Reject browser secrets & unauthorized roles)
  // ---------------------------------------------------------------------------

  it("strictly rejects browser preimages and unauthorized actions", async () => {
    const session = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const transport = new InMemoryTechnocoreTransport();
    const app = new DealWalletApp({ session, room: "test-sec-actions", transport });
    const server = new DealWalletServer({ app, host: "127.0.0.1", port: 0 });

    await server.start();
    try {
      // Reject client trying to submit a secret
      const resSecret = await fetch(`${server.url}/api/deals/any-id/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ secret: "0x1234" }),
      });
      expect(resSecret.status).toBe(400);
      const secData = await resSecret.json();
      expect(secData.message).toContain("strictly managed server-side");

      // Reject non-existent deal action cleanly without stack trace
      const resNotFound = await fetch(`${server.url}/api/deals/non-existent/lock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(resNotFound.status).toBe(400);
      const nfData = await resNotFound.json();
      expect(nfData.error).toBe("Bad Request");
      expect(nfData).not.toHaveProperty("stack");
    } finally {
      await server.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // 15. Real Two-Instance Anvil Integration Test (Alice :3456, Bob :3457)
  // ---------------------------------------------------------------------------

  it("executes full end-to-end deal lifecycle between Alice and Bob instances over Anvil", async () => {
    const sharedTransport = new InMemoryTechnocoreTransport();
    const roomName = "shared-htlc-room";

    // Alice: Payer on Anvil Account 0
    const aliceSession = await WalletSession.fromAnvil(0, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payer",
    });
    const aliceApp = new DealWalletApp({
      session: aliceSession,
      room: roomName,
      transport: sharedTransport,
    });
    const aliceServer = new DealWalletServer({ app: aliceApp, host: "127.0.0.1", port: 0 });

    // Bob: Payee on Anvil Account 1
    const bobSession = await WalletSession.fromAnvil(1, {
      htlcAddress: anvil.htlcAddress,
      rpcUrl,
      publicClient: anvil.publicClient,
      role: "payee",
    });
    const bobApp = new DealWalletApp({
      session: bobSession,
      room: roomName,
      transport: sharedTransport,
    });
    const bobServer = new DealWalletServer({ app: bobApp, host: "127.0.0.1", port: 0 });

    // Pair address resolvers for both participants
    aliceSession.addressResolver.set(bobSession.did, bobSession.evmAddress);
    bobSession.addressResolver.set(aliceSession.did, aliceSession.evmAddress);

    await aliceServer.start();
    await bobServer.start();

    try {
      // Step 1: Alice sends a chat message
      const chatRes = await fetch(`${aliceServer.url}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: "Ready to initiate deal" }),
      });
      expect(chatRes.status).toBe(200);

      // Bob syncs and sees Alice's chat
      await bobServer.triggerSync();
      const bobMsgsRes = await fetch(`${bobServer.url}/api/messages`);
      const bobMsgs: SafeMessagesResponseDto = await bobMsgsRes.json();
      expect(bobMsgs.count).toBe(1);
      expect(bobMsgs.messages[0].text).toBe("Ready to initiate deal");
      expect(bobMsgs.messages[0].isSelf).toBe(false);

      // Step 2: Alice creates an offer (0.01 ETH)
      const offerRes = await fetch(`${aliceServer.url}/api/deals/offer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          amountEth: "0.01",
          counterpartyDid: bobSession.did,
          claimBySec: 120,
          refundAfterSec: 300,
          expiresSec: 60,
        }),
      });
      expect(offerRes.status).toBe(201);
      const offerData = await offerRes.json();
      const offerId = offerData.offerId;
      expect(offerId).toBeDefined();

      // Step 3: Bob syncs and accepts the offer
      await bobServer.triggerSync();
      const acceptRes = await fetch(`${bobServer.url}/api/deals/${encodeURIComponent(offerId)}/accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(acceptRes.status).toBe(200);
      const acceptData: DealActionResponseDto = await acceptRes.json();
      expect(acceptData.ok).toBe(true);
      expect(acceptData.deal?.status).toBe(DealStatus.ACCEPTED);
      const contractId = acceptData.deal!.contractId;
      expect(contractId).toBeDefined();

      // Step 4: Alice syncs and locks funds on Anvil HTLC
      await aliceServer.triggerSync();
      const lockRes = await fetch(`${aliceServer.url}/api/deals/${encodeURIComponent(contractId)}/lock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(lockRes.status).toBe(200);
      const lockData: DealActionResponseDto = await lockRes.json();
      expect([DealStatus.LOCKED, DealStatus.VERIFIED]).toContain(lockData.deal?.status);

      // Step 5: Bob syncs and verifies the lock on-chain
      await bobServer.triggerSync();
      const verifyRes = await fetch(`${bobServer.url}/api/deals/${encodeURIComponent(contractId)}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(verifyRes.status).toBe(200);
      const verifyData: DealActionResponseDto = await verifyRes.json();
      expect(verifyData.deal?.status).toBe(DealStatus.VERIFIED);

      // Step 6: Bob reveals the secret
      const revealRes = await fetch(`${bobServer.url}/api/deals/${encodeURIComponent(contractId)}/reveal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(revealRes.status).toBe(200);
      const revealData: DealActionResponseDto = await revealRes.json();
      expect(revealData.deal?.status).toBe(DealStatus.REVEALED);

      // CRITICAL SECURITY ASSERTION: Preimage NEVER appears in HTTP responses
      const revealBodyStr = JSON.stringify(revealData);
      expect(revealBodyStr).not.toContain("preimage");
      expect((revealData.deal as any)?.secret).toBeUndefined();
      expect(revealData.deal?.statement).toBeDefined();

      // Check messages endpoint on Alice's server: reveal secret is redacted
      await aliceServer.triggerSync();
      const aliceMsgsRes = await fetch(`${aliceServer.url}/api/messages`);
      const aliceMsgs: SafeMessagesResponseDto = await aliceMsgsRes.json();
      const revealMsg = aliceMsgs.messages.find((m) => m.frameType === "reveal");
      expect(revealMsg).toBeDefined();
      expect(revealMsg?.text).toContain("[REDACTED]");

      // Step 7: Bob claims the funds on Anvil HTLC
      const claimRes = await fetch(`${bobServer.url}/api/deals/${encodeURIComponent(contractId)}/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(claimRes.status).toBe(200);
      const claimData: DealActionResponseDto = await claimRes.json();
      expect(claimData.deal?.status).toBe(DealStatus.CLAIMED);
      expect(claimData.deal?.isTerminal).toBe(true);

      // Step 8: Alice syncs and sees the terminal CLAIMED deal
      await aliceServer.triggerSync();
      const aliceDealsRes = await fetch(`${aliceServer.url}/api/deals`);
      const aliceDeals: SafeDealsResponseDto = await aliceDealsRes.json();
      expect(aliceDeals.completed).toHaveLength(1);
      expect(aliceDeals.completed[0].contractId).toBe(contractId);
      expect(aliceDeals.completed[0].status).toBe(DealStatus.CLAIMED);
    } finally {
      await aliceServer.stop();
      await bobServer.stop();
    }
  });
});

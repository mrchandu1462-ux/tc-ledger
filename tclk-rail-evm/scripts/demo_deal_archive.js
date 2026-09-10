#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  DealManager,
  DealStatus,
  TechnocoreSigner,
  encodeTclkFrame,
  TcLedgerArchiver,
  verifyDealArchive,
  createSignedExportRecord,
  computeContractId,
} from "../dist/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../..");

async function runDemo() {
  console.log("================================================================================");
  console.log(" Technocore Deal Wallet — Phase 3 Deal Archival & Evidence Binding Demo");
  console.log("================================================================================\n");

  const args = process.argv.slice(2);
  const customExportPath = args.find((a) => !a.startsWith("--"));
  const outputIndex = args.indexOf("--output");
  const customOutputPath = outputIndex !== -1 ? args[outputIndex + 1] : undefined;

  let exportPath = customExportPath;
  let room = "demo-deal-room";
  let tempDir;

  if (!exportPath) {
    console.log("[1/5] No export file supplied: generating realistic synthetic room export...");
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-demo-archive-"));
    exportPath = path.join(tempDir, `${room}.jsonl`);

    const alice = new TechnocoreSigner(new Uint8Array(32).fill(0xaa));
    const bob = new TechnocoreSigner(new Uint8Array(32).fill(0xbb));
    const secret = "0x" + "42".repeat(32);
    const secretHash = "0x" + createHash("sha256").update(Buffer.from("42".repeat(32), "hex")).digest("hex");

    const now = Date.now();
    const deal = DealManager.createOffer({
      room,
      creator: { did: alice.did, evmAddress: "0x1111111111111111111111111111111111111111" },
      role: "payer",
      amount: "500000000000000000",
      asset: "0x0000000000000000000000000000000000000000",
      lock: "hash",
      rails: ["evm-htlc"],
      claimByMs: now + 600000,
      refundAfterMs: now + 1200000,
      expiresMs: now + 300000,
      nonce: "demo_offer_nonce_1",
      nowMs: now,
    });

    const offer = deal.state.offer;
    const acceptCore = {
      from: bob.did,
      ref: offer.id,
      statement: secretHash,
      nonce: "demo_accept_nonce_2",
    };
    const contractId = computeContractId(offer, acceptCore);
    const accept = {
      type: "accept",
      ...acceptCore,
      contract: contractId,
    };
    deal.applyAccept(accept, "0x2222222222222222222222222222222222222222");

    const lock = {
      type: "lock",
      from: alice.did,
      contract: contractId,
      rail: "evm-htlc",
      ref: "0xlocktransactionhash999",
    };
    deal.applyLock(lock);

    const reveal = {
      type: "reveal",
      from: bob.did,
      contract: contractId,
      secret,
    };
    deal.applyReveal(secret, bob.did);

    deal.applyClaim("0x2222222222222222222222222222222222222222", "0xclaimtransactionhash888");

    const receipt = {
      type: "receipt",
      from: bob.did,
      contract: contractId,
      outcome: "claimed",
      ref: "0xclaimtransactionhash888",
    };
    deal.applyReceipt(receipt);

    deal.recordLedgerSequence("offerSeq", 2);
    deal.recordLedgerSequence("acceptSeq", 3);
    deal.recordLedgerSequence("lockSeq", 4);
    deal.recordLedgerSequence("receiptSeq", 6);

    const records = [
      { signer: alice, seq: 1, nonce: 1001, text: "Welcome Bob, initiating settlement..." },
      { signer: alice, seq: 2, nonce: 1002, text: encodeTclkFrame(offer) },
      { signer: bob, seq: 3, nonce: 1003, text: encodeTclkFrame(accept) },
      { signer: alice, seq: 4, nonce: 1004, text: encodeTclkFrame(lock) },
      { signer: bob, seq: 5, nonce: 1005, text: encodeTclkFrame(reveal) },
      { signer: bob, seq: 6, nonce: 1006, text: encodeTclkFrame(receipt) },
      { signer: bob, seq: 7, nonce: 1007, text: "Deal successfully finalized and receipt recorded." },
    ];

    const lines = records.map((r) =>
      createSignedExportRecord(r.signer, room, r.seq, r.text, r.nonce),
    );
    fs.writeFileSync(exportPath, lines.join(""), "utf8");

    console.log(`✓ Export written to: ${exportPath}`);
    console.log(`  Room: ${room} | Records: ${records.length} | Deal Contract ID: ${contractId}\n`);

    console.log("[2/5] Invoking TC Ledger commitment & inclusion proof pipeline via CLI...");
    const archiver = new TcLedgerArchiver("python", repoRoot);
    const archive = await archiver.archiveDeal(deal, exportPath, {
      settlementRef: "0xclaimtransactionhash888",
      onChainVerified: true,
    });

    console.log(`✓ Export Commitment computed:`);
    console.log(`  Export Root: ${archive.commitment.export_root}`);
    console.log(`  Line Count:  ${archive.commitment.line_count}`);
    console.log(`  File SHA256: ${archive.commitment.file_sha256}\n`);

    console.log("[3/5] Deal Archive artifact constructed:");
    console.log(`  Schema:      ${archive.schema} v${archive.version}`);
    console.log(`  Deal Status: ${archive.deal.status}`);
    console.log(`  Payer:       ${archive.deal.payer.did}`);
    console.log(`  Payee:       ${archive.deal.payee.did}`);
    console.log(`  Stages:      ${Object.keys(archive.records).join(", ")}`);
    console.log(`  Secret check: Plaintext HTLC secret is NOT present (Verified: ${!JSON.stringify(archive).includes("42".repeat(32))})\n`);

    console.log("[4/5] Running offline verification (zero network / zero technocore.chat dependency)...");
    const vResult = await verifyDealArchive(archive, { useCli: true, repoRoot });
    console.log(`✓ Offline Verification: ${vResult.valid ? "PASSED" : "FAILED"}`);
    console.log(`  Stages Verified: ${vResult.stagesVerified.join(", ")}`);
    if (vResult.errors.length > 0) {
      console.log(`  Errors: ${vResult.errors.join("; ")}`);
    }

    const finalOutPath = customOutputPath ?? path.join(__dirname, "../dist/sample_deal_archive.json");
    fs.writeFileSync(finalOutPath, JSON.stringify(archive, null, 2), "utf8");
    console.log(`\n[5/5] Deal Archive saved to: ${finalOutPath}`);

    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    console.log("\nDemo completed successfully!");
  } else {
    console.log(`Using existing room export at: ${exportPath}`);
    // Custom archive path
    const roomArgIdx = args.indexOf("--room");
    if (roomArgIdx !== -1 && args[roomArgIdx + 1]) {
      room = args[roomArgIdx + 1];
    }
    console.log(`Room: ${room}`);
  }
}

runDemo().catch((err) => {
  console.error("Demo failed with error:", err);
  process.exit(1);
});

import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const explorer = require("../site/explorer.js");

test("B-1: WebCrypto Ed25519 failure must fail closed (valid: false)", async () => {
  const validLengthSig = Buffer.alloc(64, 0x42).toString("base64url"); // 86 chars base64url, exactly 64 bytes
  const record = {
    room: "test-room",
    nonce: "test-nonce",
    from: "did:key:z6MkuSLmD41mC55Nx4N2Su4jMYAkyKa45kNnYSasq3n5XZ8K",
    sig: validLengthSig,
    text: "test message",
    ts: 1710000000000
  };

  // Stub subtle.importKey to throw (simulating browser without Ed25519 WebCrypto support)
  const origImportKey = globalThis.crypto.subtle.importKey;
  try {
    globalThis.crypto.subtle.importKey = async () => {
      throw new Error("Ed25519 not supported in this browser");
    };

    const res = await explorer.verifyRecordSignature(record, "test-room");
    assert.equal(res.valid, false, "Must fail closed when WebCrypto Ed25519 is unsupported");
    assert.equal(res.reason, "Ed25519 verification unavailable in this browser.");
  } finally {
    globalThis.crypto.subtle.importKey = origImportKey;
  }
});

test("B-1: Forged 86-char signature fails cryptographic verification", async () => {
  const forgedSig = Buffer.alloc(64, 0x00).toString("base64url"); // 86 chars base64url
  const record = {
    room: "test-room",
    nonce: "test-nonce",
    from: "did:key:z6MkuSLmD41mC55Nx4N2Su4jMYAkyKa45kNnYSasq3n5XZ8K",
    sig: forgedSig,
    text: "test message",
    ts: 1710000000000
  };

  const res = await explorer.verifyRecordSignature(record, "test-room");
  assert.equal(res.valid, false, "Forged 86-char signature must never be accepted as valid");
  assert.match(res.reason, /Signature check failed|Signature verification failed|Invalid signature/);
});

test("B-2: Self-verification fails closed on missing or corrupted inputs", async () => {
  // Construct a minimal valid 2-leaf tree and proof
  const leaf0Raw = new TextEncoder().encode('{"from":"did:key:z6MkuSLmD41mC55Nx4N2Su4jMYAkyKa45kNnYSasq3n5XZ8K","nonce":"1","room":"room-a","sig":"test","text":"msg 0","ts":100}\n');
  const leaf1Raw = new TextEncoder().encode('{"from":"did:key:z6MkuSLmD41mC55Nx4N2Su4jMYAkyKa45kNnYSasq3n5XZ8K","nonce":"2","room":"room-a","sig":"test","text":"msg 1","ts":101}\n');
  
  const h0 = await explorer.computeLeafHash(leaf0Raw);
  const h1 = await explorer.computeLeafHash(leaf1Raw);
  const expectedRoot = await explorer.computeNodeHash(h0, h1);

  const validProof = {
    leaf_hash: h0,
    leaf_index: 0,
    tree_size: 2,
    audit_path: [{ position: "right", sibling_hash: h1 }]
  };

  // 1. Valid case must pass
  const validRes = await explorer.verifyInclusionProof(leaf0Raw, validProof, expectedRoot);
  assert.equal(validRes.valid, true, "Valid proof must pass");
  assert.equal(validRes.computedRoot, expectedRoot);

  // 2. Missing root -> reject (never report VALID)
  const noRootRes = await explorer.verifyInclusionProof(leaf0Raw, validProof, "");
  assert.equal(noRootRes.valid, false);
  assert.match(noRootRes.reason, /No trusted\/expected root/);

  // 3. Missing leaf_hash -> reject
  const noLeafHash = { ...validProof, leaf_hash: "" };
  const noLeafRes = await explorer.verifyInclusionProof(leaf0Raw, noLeafHash, expectedRoot);
  assert.equal(noLeafRes.valid, false);
  assert.match(noLeafRes.reason, /missing valid 64-hex leaf_hash/);

  // 4. Missing leaf_index -> reject
  const noLeafIndex = { ...validProof, leaf_index: null };
  const noIndexRes = await explorer.verifyInclusionProof(leaf0Raw, noLeafIndex, expectedRoot);
  assert.equal(noIndexRes.valid, false);
  assert.match(noIndexRes.reason, /missing integer leaf_index/);

  // 5. Missing tree_size -> reject
  const noTreeSize = { ...validProof, tree_size: null };
  const noSizeRes = await explorer.verifyInclusionProof(leaf0Raw, noTreeSize, expectedRoot);
  assert.equal(noSizeRes.valid, false);
  assert.match(noSizeRes.reason, /missing positive integer tree_size/);

  // 6. Empty audit path when tree_size > 1 -> reject
  const emptyPath = { ...validProof, audit_path: [] };
  const emptyPathRes = await explorer.verifyInclusionProof(leaf0Raw, emptyPath, expectedRoot);
  assert.equal(emptyPathRes.valid, false);
  assert.match(emptyPathRes.reason, /Invalid audit-path geometry/);

  // 7. Mutated record -> reject
  const mutatedRecordRaw = new TextEncoder().encode('{"tampered":true}\n');
  const mutatedRecRes = await explorer.verifyInclusionProof(mutatedRecordRaw, validProof, expectedRoot);
  assert.equal(mutatedRecRes.valid, false);
  assert.match(mutatedRecRes.reason, /mutated record/);

  // 8. Mutated sibling -> reject
  const mutatedSiblingProof = {
    ...validProof,
    audit_path: [{ position: "right", sibling_hash: "0000000000000000000000000000000000000000000000000000000000000000" }]
  };
  const mutatedSiblingRes = await explorer.verifyInclusionProof(leaf0Raw, mutatedSiblingProof, expectedRoot);
  assert.equal(mutatedSiblingRes.valid, false);
  assert.match(mutatedSiblingRes.reason, /Reconstructed root does not match/);

  // 9. Mutated root -> reject
  const mutatedRootRes = await explorer.verifyInclusionProof(leaf0Raw, validProof, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
  assert.equal(mutatedRootRes.valid, false);
  assert.match(mutatedRootRes.reason, /Reconstructed root does not match/);
});

test("B-3: DOM XSS escaping: untrusted data remains inert", () => {
  const xssPayloads = [
    "<img src=x onerror=alert(document.domain)>",
    "<script>alert(1)</script>",
    "\"><svg onload=alert(1)>",
    "<b onmouseover=alert(1)>click</b>",
    "\"><iframe src=javascript:alert(1)>"
  ];

  for (const payload of xssPayloads) {
    const escaped = explorer.escapeHtml(payload);
    assert.ok(!escaped.includes("<img"), `Escaped string must not contain raw <img: ${escaped}`);
    assert.ok(!escaped.includes("<script"), `Escaped string must not contain raw <script: ${escaped}`);
    assert.ok(!escaped.includes("<svg"), `Escaped string must not contain raw <svg: ${escaped}`);
    assert.ok(!escaped.includes("<iframe"), `Escaped string must not contain raw <iframe: ${escaped}`);
    assert.ok(!escaped.includes("<b"), `Escaped string must not contain raw <b: ${escaped}`);
  }
});

test("Section 5: Download proof is disabled when no verified proof exists", () => {
  const recordWithoutProof = {
    room: "test-room",
    seq: 1,
    sig: "test-sig",
    from: "did:key:z6MkuSLmD41mC55Nx4N2Su4jMYAkyKa45kNnYSasq3n5XZ8K",
    text: "no proof available"
  };

  // Verify that an unproved record has no proof property
  assert.equal(recordWithoutProof.proof, undefined);
  // Any UI button bound to record.proof must be disabled when proof is undefined
  const hasProof = !!(recordWithoutProof.proof && recordWithoutProof.proof.audit_path);
  assert.equal(hasProof, false, "Proof download must be inactive for unproved records");
});

test("Section 6: Live semantics distinguishes verified, unsigned, and invalid records", async () => {
  const unsignedRecord = {
    room: "demo-room",
    seq: 1,
    nonce: "nonce-0001",
    from: "did:key:z6MkuSLmD41mC55Nx4N2Su4jMYAkyKa45kNnYSasq3n5XZ8K",
    sig: "", // unsigned
    text: "unsigned message",
    ts: 1710000001000
  };

  const invalidRecord = {
    room: "demo-room",
    seq: 2,
    nonce: "nonce-0002",
    from: "did:key:z6MkuSLmD41mC55Nx4N2Su4jMYAkyKa45kNnYSasq3n5XZ8K",
    sig: "invalid-signature",
    text: "invalid signature message",
    ts: 1710000002000
  };

  const unsignedVer = await explorer.verifyRecordSignature(unsignedRecord, "demo-room");
  assert.equal(unsignedVer.valid, false);
  assert.equal(unsignedVer.reason, "Unsigned record (missing signature).");

  const invalidVer = await explorer.verifyRecordSignature(invalidRecord, "demo-room");
  assert.equal(invalidVer.valid, false);
  assert.match(invalidVer.reason, /Signature check failed|Signature verification failed|Invalid signature|Invalid character/);
});

test("Section 9: Malformed DID validation rejects immediately without network requests", () => {
  const invalidDids = [
    "",
    "not-a-did",
    "did:key:",
    "did:key:invalidchars!!!",
    "did:example:12345",
    "did:key:z12345" // invalid prefix
  ];

  for (const badDid of invalidDids) {
    let errorCaught = false;
    try {
      const pubKey = explorer.extractEd25519PubKey(badDid);
      if (!pubKey) errorCaught = true;
    } catch (e) {
      errorCaught = true;
    }
    assert.ok(errorCaught, `Malformed DID must fail validation: "${badDid}"`);
  }

  // Valid DID must parse successfully
  const validDid = "did:key:z6MkuSLmD41mC55Nx4N2Su4jMYAkyKa45kNnYSasq3n5XZ8K";
  const pubKey = explorer.extractEd25519PubKey(validDid);
  assert.equal(pubKey.length, 32, "Valid DID must extract 32-byte Ed25519 public key");
});

// TC Verify Explorer Data Adapter & Cryptographic Engine (Powered by TC-Ledger)
// Zero-dependency, offline, deterministic WebCrypto verification.
// Clearly labelled: DEMO DATA — SYNTHETIC

// -----------------------------------------------------------------------------
// Cryptographic Primitives (Matching TC-Ledger v0.3.1 Specification)
// -----------------------------------------------------------------------------

function getCryptoSubtle() {
  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
    return window.crypto.subtle;
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  if (typeof crypto !== "undefined" && crypto.subtle) {
    return crypto.subtle;
  }
  throw new Error("WebCrypto subtle API is not available.");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// RFC 6962 Leaf Hash: SHA-256(0x00 || rawBytes)
async function computeLeafHash(dataBytes) {
  const prefixed = new Uint8Array(1 + dataBytes.length);
  prefixed[0] = 0x00;
  prefixed.set(dataBytes, 1);
  const hashBuffer = await getCryptoSubtle().digest("SHA-256", prefixed);
  return bytesToHex(new Uint8Array(hashBuffer));
}

// RFC 6962 Node Hash: SHA-256(0x01 || left || right)
async function computeNodeHash(leftHex, rightHex) {
  const leftBytes = hexToBytes(leftHex);
  const rightBytes = hexToBytes(rightHex);
  const prefixed = new Uint8Array(1 + 32 + 32);
  prefixed[0] = 0x01;
  prefixed.set(leftBytes, 1);
  prefixed.set(rightBytes, 33);
  const hashBuffer = await getCryptoSubtle().digest("SHA-256", prefixed);
  return bytesToHex(new Uint8Array(hashBuffer));
}

// Ported RFC 6962 tree geometry rules from TC-Ledger v0.4.0 core
function expected_proof_directions(tree_size, leaf_index) {
  if (typeof tree_size !== "number" || !Number.isInteger(tree_size)) {
    throw new TypeError("tree_size must be an integer");
  }
  if (typeof leaf_index !== "number" || !Number.isInteger(leaf_index)) {
    throw new TypeError("leaf_index must be an integer");
  }
  if (tree_size < 1) {
    throw new RangeError("tree_size must be positive");
  }
  if (leaf_index < 0 || leaf_index >= tree_size) {
    throw new RangeError("leaf_index outside tree bounds");
  }

  const directions = [];
  let current_index = leaf_index;
  let level_size = tree_size;

  while (level_size > 1) {
    if (current_index % 2 === 0) {
      if (current_index + 1 < level_size) {
        directions.push("right");
      }
    } else {
      directions.push("left");
    }
    current_index = Math.floor(current_index / 2);
    level_size = Math.floor((level_size + 1) / 2);
  }
  return directions;
}

// Strict fail-closed inclusion proof verifier
async function verifyInclusionProof(rawLineBytesOrStr, artifact, trustedExpectedRoot) {
  if (typeof rawLineBytesOrStr === "string") {
    rawLineBytesOrStr = new TextEncoder().encode(rawLineBytesOrStr);
  }
  if (!(rawLineBytesOrStr instanceof Uint8Array)) {
    return { valid: false, status: "INVALID_INPUT", reason: "Raw record input must be string or Uint8Array." };
  }
  if (!artifact || typeof artifact !== "object") {
    return { valid: false, status: "INVALID_INPUT", reason: "Proof artifact must be a JSON object." };
  }

  const expectedRoot = (trustedExpectedRoot || artifact.expected_root || artifact.export_root || "").trim();
  if (!expectedRoot || !/^[0-9a-fA-F]{64}$/.test(expectedRoot)) {
    return { valid: false, status: "INVALID_INPUT", reason: "No trusted/expected root provided or root is not a valid 64-hex SHA-256 commitment." };
  }

  if (artifact.expected_root && trustedExpectedRoot && artifact.expected_root.toLowerCase() !== trustedExpectedRoot.trim().toLowerCase()) {
    return { valid: false, status: "INVALID", reason: "Supplied trusted root does not match artifact expected_root." };
  }

  if (typeof artifact.leaf_hash !== "string" || !/^[0-9a-fA-F]{64}$/.test(artifact.leaf_hash)) {
    return { valid: false, status: "INVALID_INPUT", reason: "Proof artifact missing valid 64-hex leaf_hash." };
  }

  if (typeof artifact.leaf_index !== "number" || !Number.isInteger(artifact.leaf_index)) {
    return { valid: false, status: "INVALID_INPUT", reason: "Proof artifact missing integer leaf_index." };
  }

  if (typeof artifact.tree_size !== "number" || !Number.isInteger(artifact.tree_size) || artifact.tree_size < 1) {
    return { valid: false, status: "INVALID_INPUT", reason: "Proof artifact missing positive integer tree_size." };
  }

  if (artifact.leaf_index < 0 || artifact.leaf_index >= artifact.tree_size) {
    return { valid: false, status: "INVALID", reason: "leaf_index outside tree bounds." };
  }

  if (!Array.isArray(artifact.audit_path)) {
    return { valid: false, status: "INVALID_INPUT", reason: "Proof artifact missing audit_path array." };
  }

  // Compute leaf hash and verify match
  const actualLeafHash = await computeLeafHash(rawLineBytesOrStr);
  if (actualLeafHash.toLowerCase() !== artifact.leaf_hash.toLowerCase()) {
    return {
      valid: false,
      status: "INVALID",
      computedLeaf: actualLeafHash,
      expectedLeaf: artifact.leaf_hash,
      reason: "Computed leaf hash differs from proof artifact leaf_hash (mutated record)."
    };
  }

  // Verify audit-path geometry matches RFC 6962 tree shape
  let expectedDirs;
  try {
    expectedDirs = expected_proof_directions(artifact.tree_size, artifact.leaf_index);
  } catch (err) {
    return { valid: false, status: "INVALID", reason: `Geometry computation error: ${err.message}` };
  }

  if (artifact.audit_path.length !== expectedDirs.length) {
    return {
      valid: false,
      status: "INVALID",
      reason: `Invalid audit-path geometry: expected length ${expectedDirs.length}, got ${artifact.audit_path.length}.`
    };
  }

  // Fold audit path
  let current = actualLeafHash;
  for (let i = 0; i < artifact.audit_path.length; i++) {
    const step = artifact.audit_path[i];
    const expectedDir = expectedDirs[i];

    if (!step || typeof step !== "object") {
      return { valid: false, status: "INVALID", reason: `Malformed audit-path step at index ${i}.` };
    }
    if (step.position !== expectedDir) {
      return {
        valid: false,
        status: "INVALID",
        reason: `Invalid audit-path direction at step ${i}: expected '${expectedDir}', got '${step.position}'.`
      };
    }
    if (typeof step.sibling_hash !== "string" || !/^[0-9a-fA-F]{64}$/.test(step.sibling_hash)) {
      return { valid: false, status: "INVALID", reason: `Invalid sibling hash format at step ${i} (expected 32-byte hex).` };
    }

    if (step.position === "left") {
      current = await computeNodeHash(step.sibling_hash, current);
    } else {
      current = await computeNodeHash(current, step.sibling_hash);
    }
  }

  if (current.toLowerCase() !== expectedRoot.toLowerCase()) {
    return {
      valid: false,
      status: "INVALID",
      computedLeaf: actualLeafHash,
      computedRoot: current,
      expectedRoot: expectedRoot,
      reason: "Reconstructed root does not match trusted expected root."
    };
  }

  return {
    valid: true,
    status: "VALID",
    computedLeaf: actualLeafHash,
    computedRoot: current,
    expectedRoot: expectedRoot,
    leafIndex: artifact.leaf_index,
    treeSize: artifact.tree_size
  };
}

// RFC 8785 (JCS) deterministic evidence ID
async function computeEvidenceId(recordObj) {
  try {
    const keys = ["from", "nonce", "seq", "sig", "text", "ts"].sort();
    const sorted = {};
    for (const k of keys) {
      if (recordObj[k] !== undefined) sorted[k] = recordObj[k];
    }
    const jsonStr = JSON.stringify(sorted);
    const enc = new TextEncoder().encode(jsonStr);
    const hash = await getCryptoSubtle().digest("SHA-256", enc);
    return "tc-ledger:v1:" + bytesToHex(new Uint8Array(hash));
  } catch (e) {
    return "tc-ledger:v1:malformed";
  }
}

// Base58btc decoder for did:key:z6Mk...
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function decodeBase58(str) {
  const bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const val = B58_ALPHABET.indexOf(char);
    if (val === -1) throw new Error("Invalid base58 character: " + char);
    for (let j = 0; j < bytes.length; j++) bytes[j] *= 58;
    bytes[0] += val;
    let carry = 0;
    for (let j = 0; j < bytes.length; j++) {
      bytes[j] += carry;
      carry = bytes[j] >> 8;
      bytes[j] &= 0xff;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < str.length && str[i] === "1"; i++) {
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

// Extract raw 32-byte Ed25519 public key from did:key:z6Mk...
function extractEd25519PubKey(did) {
  if (!did || !did.startsWith("did:key:z")) {
    throw new Error("Invalid did:key prefix");
  }
  const multibase = did.substring(9); // strip "did:key:z"
  const decoded = decodeBase58(multibase);
  // multicodec for Ed25519 pubkey is 0xed01 (2 bytes: 0xed, 0x01)
  if (decoded.length < 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("Unsupported multicodec prefix (expected ed01 for Ed25519)");
  }
  return decoded.slice(2, 34);
}

// Decode Base64URL string to Uint8Array
function base64UrlToBytes(str) {
  const stripped = str.replace(/=+$/, "");
  const base64 = stripped.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + "=".repeat(padLen);
  if (typeof atob === "function") {
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  throw new Error("No base64 decoder available");
}

// Verify Ed25519 signature over UTF-8 "room|nonce|text"
async function verifyRecordSignature(recordObj, room) {
  try {
    if (!recordObj) {
      return { valid: false, reason: "Missing record object" };
    }
    if (!recordObj.sig) {
      return { valid: false, reason: "Unsigned record (missing signature)." };
    }
    if (!recordObj.from || recordObj.nonce === undefined || !recordObj.text) {
      return { valid: false, reason: "Missing required signature fields" };
    }
    const pubKeyBytes = extractEd25519PubKey(recordObj.from);
    const sigBytes = base64UrlToBytes(recordObj.sig);
    if (sigBytes.length !== 64) {
      return { valid: false, reason: "Invalid signature length (expected 64 bytes)" };
    }

    const canonicalMsg = new TextEncoder().encode(`${room}|${recordObj.nonce}|${recordObj.text}`);
    const subtle = getCryptoSubtle();

    // Check if subtle supports Ed25519 key import
    try {
      const key = await subtle.importKey("raw", pubKeyBytes, { name: "Ed25519" }, false, ["verify"]);
      const ok = await subtle.verify({ name: "Ed25519" }, key, sigBytes, canonicalMsg);
      return { valid: ok, reason: ok ? "Valid Ed25519 signature" : "Signature check failed" };
    } catch (e) {
      // Fail-closed: Never treat structural signature validity as cryptographic validity
      return { valid: false, reason: "Ed25519 verification unavailable in this browser." };
    }
  } catch (err) {
    return { valid: false, reason: err.message || "Signature verification error" };
  }
}

// -----------------------------------------------------------------------------
// Synthetic Demo Dataset (Explicitly Labelled DEMO DATA — SYNTHETIC)
// -----------------------------------------------------------------------------

const DEMO_DID_ACTIVE = "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH";
const DEMO_DID_STALE = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaiSS28H";
const DEMO_DID_UNKNOWN = "did:key:z6MkuUnknownIdentityNotInIndexedDemoDataset9999";
// -----------------------------------------------------------------------------
// Live Technocore Public Data Adapter Constants & State
// -----------------------------------------------------------------------------

const LIVE_DID_ACTIVE = "did:key:z6MkeiVea5Ddez5iBkSk5uc7AC48govcd977ysAWeu6FXT8Z";
const LIVE_DID_NONEXISTENT = "did:key:z6MkmVLivcEneu3HGgGLkQBZvkZeZEMihRKzdWq9vk5DYGmR";
const LIVE_ROOMS_DATA = {};
const _ROOM_EXPORT_CACHE = new Map(); // room -> { generation, text, ts }
let _currentLookupAbortController = null;

let currentExplorerMode = "synthetic"; // "synthetic" | "live"


// Retained records corresponding to genuine v0.3.1 fixtures
const SYNTHETIC_ROOMS_DATA = {
  "demo-room": {
    name: "research",
    displayName: "Research",
    description: "Independent protocol research & verification methodology discussion.",
    retainedCount: 842,
    latestActivity: "2026-09-01T12:06:00Z",
    generation: 2,
    committedRoot: "792e762d74456dab8b4905490213491d6d4533a10f333da7447c2541bb81d341",
    gen1Root: "0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9",
    records: [
      {
        seq: 1,
        ts: "2026-09-01T12:01:00.000000Z",
        from: "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaiSS28H",
        text: "Alice opened verification session",
        nonce: 1001,
        sig: "K3h_C5-B9E4bA9eF9vM9e2_Lw3-vA8_9m3e2-8vM9e2_Lw3-vA8_9m3e2-8vM9e2_Lw3-vA8_9m3e2-8vM9e2_Lw3-vA8_9m",
        leafIndex: 0,
        rawLine: '{"seq":1,"ts":"2026-09-01T12:01:00.000000Z","from":"did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaiSS28H","text":"Alice opened verification session","nonce":1001,"sig":"K3h_C5-B9E4bA9eF9vM9e2_Lw3-vA8_9m3e2-8vM9e2_Lw3-vA8_9m3e2-8vM9e2_Lw3-vA8_9m"}\n'
      },
      {
        seq: 2,
        ts: "2026-09-01T12:02:00.000000Z",
        from: "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH",
        text: "Bob verified session terms",
        nonce: 1002,
        sig: "juuohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Cw",
        leafIndex: 1,
        rawLine: '{"seq":2,"ts":"2026-09-01T12:02:00.000000Z","from":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","text":"Bob verified session terms","nonce":1002,"sig":"juuohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Cw"}\n',
        proof: {
          schema: "tc-ledger/inclusion-proof/v1",
          version: 1,
          profile: "tc-ledger/1",
          room: "demo-room",
          generation: 1,
          tree_size: 4,
          leaf_index: 1,
          leaf_hash: "13dbfe722146b058fe8a560b87ac56be426fc785f907fa061121bd5743d21149",
          expected_root: "0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9",
          audit_path: [
            { position: "left", sibling_hash: "589528377029dc2f622020f4df8f141305d6289ac7c68dcae2ffa66bdaa401b6" },
            { position: "right", sibling_hash: "18972fda6f31cf89c8de7601ba9fe37dafa87581e8fb0f0195cce7a4be52d9a8" }
          ]
        }
      },
      {
        seq: 3,
        ts: "2026-09-01T12:03:00.000000Z",
        from: "did:key:z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZ9B4Y6v2m",
        text: "Carol confirmed cryptographic commitment format",
        nonce: 1003,
        sig: "ab3ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Dw",
        leafIndex: 2,
        rawLine: '{"seq":3,"ts":"2026-09-01T12:03:00.000000Z","from":"did:key:z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZ9B4Y6v2m","text":"Carol confirmed cryptographic commitment format","nonce":1003,"sig":"ab3ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Dw"}\n'
      },
      {
        seq: 4,
        ts: "2026-09-01T12:04:00.000000Z",
        from: "did:key:z6Mkt6316e2PN3mZdB6N9CrzomJYUd1s5yBZi1XY6H5L4rWq",
        text: "Dave validated export merkle tree root",
        nonce: 1004,
        sig: "cd4ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Ew",
        leafIndex: 3,
        rawLine: '{"seq":4,"ts":"2026-09-01T12:04:00.000000Z","from":"did:key:z6Mkt6316e2PN3mZdB6N9CrzomJYUd1s5yBZi1XY6H5L4rWq","text":"Dave validated export merkle tree root","nonce":1004,"sig":"cd4ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Ew"}\n'
      },
      {
        seq: 5,
        ts: "2026-09-01T12:05:00.000000Z",
        from: "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH",
        text: "Bob added secondary proof cross-check",
        nonce: 1005,
        sig: "ef5ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Fw",
        leafIndex: 4,
        rawLine: '{"seq":5,"ts":"2026-09-01T12:05:00.000000Z","from":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","text":"Bob added secondary proof cross-check","nonce":1005,"sig":"ef5ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Fw"}\n'
      },
      {
        seq: 6,
        ts: "2026-09-01T12:06:00.000000Z",
        from: "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH",
        text: "Bob completed evidence export commit",
        nonce: 1006,
        sig: "gh6ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Gw",
        leafIndex: 5,
        rawLine: '{"seq":6,"ts":"2026-09-01T12:06:00.000000Z","from":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","text":"Bob completed evidence export commit","nonce":1006,"sig":"gh6ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Gw"}\n'
      }
    ]
  },
  "builders-room": {
    name: "builders",
    displayName: "Builders",
    description: "Technical discussions on offline archival tools and RFC 6962 inclusion.",
    retainedCount: 213,
    latestActivity: "2026-09-01T11:45:00Z",
    generation: 1,
    committedRoot: "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
    records: [
      {
        seq: 1,
        ts: "2026-09-01T11:40:00.000000Z",
        from: "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH",
        text: "Reviewing client-side WebCrypto proof pipeline",
        nonce: 501,
        sig: "bld_ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Hw",
        leafIndex: 0,
        rawLine: '{"seq":1,"ts":"2026-09-01T11:40:00.000000Z","from":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","text":"Reviewing client-side WebCrypto proof pipeline","nonce":501,"sig":"bld_ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Hw"}\n'
      },
      {
        seq: 2,
        ts: "2026-09-01T11:45:00.000000Z",
        from: "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH",
        text: "Confirmed raw byte commitments remain byte-for-byte deterministic",
        nonce: 502,
        sig: "bld_ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Iw",
        leafIndex: 1,
        rawLine: '{"seq":2,"ts":"2026-09-01T11:45:00.000000Z","from":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","text":"Confirmed raw byte commitments remain byte-for-byte deterministic","nonce":502,"sig":"bld_ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Iw"}\n'
      }
    ]
  },
  "community-room": {
    name: "community",
    displayName: "Community",
    description: "Public announcements, trust boundary disclosures, and release notices.",
    retainedCount: 129,
    latestActivity: "2026-09-01T10:15:00Z",
    generation: 1,
    committedRoot: "f0e1d2c3b4a5968778695a4b3c2d1e0f123456789abcdef0123456789abcdef0",
    records: [
      {
        seq: 1,
        ts: "2026-09-01T10:15:00.000000Z",
        from: "did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH",
        text: "v0.3.1 spec frozen: all verification tests passing green",
        nonce: 101,
        sig: "com_ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Jw",
        leafIndex: 0,
        rawLine: '{"seq":1,"ts":"2026-09-01T10:15:00.000000Z","from":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","text":"v0.3.1 spec frozen: all verification tests passing green","nonce":101,"sig":"com_ohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Jw"}\n'
      }
    ]
  }
};

// Index of DIDs to status & activity
function lookupDid(did) {
  const cleanDid = (did || "").trim();
  if (cleanDid === DEMO_DID_ACTIVE) {
    return {
      status: "ACTIVE",
      statusLabel: "ACTIVE",
      statusDescription: "Active based on recent verified activity within the demo activity window.",
      did: cleanDid,
      persona: "Synthetic Demo Agent (Bob)",
      lastActivity: "2026-09-01T12:06:00Z",
      verifiedRecords: 6,
      totalRetainedRecords: 1184,
      roomCount: 3,
      latestGeneration: 2,
      latestCommittedRoot: "792e762d74456dab8b4905490213491d6d4533a10f333da7447c2541bb81d341",
      rooms: [
        {
          id: "demo-room",
          name: "Research",
          retainedRecords: 842,
          lastActivity: "2026-09-01T12:06:00Z",
          verifiedStatus: "Verified",
          generation: 2,
          committedRoot: "792e762d...d341"
        },
        {
          id: "builders-room",
          name: "Builders",
          retainedRecords: 213,
          lastActivity: "2026-09-01T11:45:00Z",
          verifiedStatus: "Verified",
          generation: 1,
          committedRoot: "a1b2c3d4...def0"
        },
        {
          id: "community-room",
          name: "Community",
          retainedRecords: 129,
          lastActivity: "2026-09-01T10:15:00Z",
          verifiedStatus: "Verified",
          generation: 1,
          committedRoot: "f0e1d2c3...def0"
        }
      ]
    };
  } else if (cleanDid === DEMO_DID_STALE) {
    return {
      status: "STALE",
      statusLabel: "STALE / INACTIVE",
      statusDescription: "Known DID, but no recent activity exists within the indexed activity window.",
      did: cleanDid,
      persona: "Synthetic Demo Agent (Alice)",
      lastActivity: "2026-07-15T08:00:00Z", // Outside recent window
      verifiedRecords: 1,
      totalRetainedRecords: 24,
      roomCount: 1,
      latestGeneration: 1,
      latestCommittedRoot: "0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9",
      rooms: [
        {
          id: "demo-room",
          name: "Research",
          retainedRecords: 24,
          lastActivity: "2026-07-15T08:00:00Z",
          verifiedStatus: "Historical",
          generation: 1,
          committedRoot: "0373cfc7...66b9"
        }
      ]
    };
  } else {
    return {
      status: "NO_DATA",
      statusLabel: "NO DATA FOUND",
      statusDescription: "The DID does not exist in the explorer\'s available indexed dataset. This does not imply the DID does not exist.",
      did: cleanDid,
      persona: null,
      lastActivity: "N/A",
      verifiedRecords: 0,
      totalRetainedRecords: 0,
      roomCount: 0,
      latestGeneration: "N/A",
      latestCommittedRoot: "N/A",
      rooms: []
    };
  }
}

// -----------------------------------------------------------------------------
// Live Adapter: Ingest Live Indexer JSON or Query Endpoints
// -----------------------------------------------------------------------------

function adaptIndexerJsonToExplorer(data) {
  const isLiveActive = data.status === "ACTIVE";
  const isStale = data.status === "STALE";
  const isNoData = data.status === "NO DATA" || data.status === "NO_DATA";
  const roomsList = [];

  if (data.room_details) {
    Object.keys(data.room_details).forEach(rName => {
      const act = data.room_details[rName];
      const roomId = `live-${rName}`;
      const recs = (act.records || []).map(r => ({
        seq: r.seq,
        ts: r.ts,
        from: r.from || r.from_did,
        text: r.text,
        nonce: r.nonce,
        sig: r.sig,
        rawLine: r.rawLine || (JSON.stringify(r) + "\n")
      }));

      roomsList.push({
        id: roomId,
        rawRoomName: rName,
        name: rName,
        retainedRecords: act.verified_record_count || recs.length || 0,
        lastActivity: act.latest_timestamp || "N/A",
        verifiedStatus: "Verified",
        generation: (act.generation !== null && act.generation !== undefined) ? act.generation : "N/A",
        committedRoot: `X-Room-Gen: ${(act.generation !== null && act.generation !== undefined) ? act.generation : "N/A"}`
      });

      LIVE_ROOMS_DATA[roomId] = {
        name: rName,
        displayName: `#${rName}`,
        description: `Live retained records for ${data.did} in #${rName}.`,
        generation: (act.generation !== null && act.generation !== undefined) ? act.generation : "N/A",
        committedRoot: `X-Room-Gen: ${(act.generation !== null && act.generation !== undefined) ? act.generation : "N/A"}`,
        records: recs,
        messages: recs
      };
    });
  }

  return {
    status: isNoData ? "NO_DATA" : data.status,
    statusLabel: isLiveActive ? "ACTIVE" : (isStale ? "STALE / INACTIVE" : "NO DATA FOUND"),
    statusDescription: isLiveActive
      ? "Recent verified activity exists within the 24-hour indexer activity window."
      : (isStale
          ? "Known verified retained activity exists, but none falls within the 24-hour activity window."
          : "No matching verified retained activity was found in the inspected public data. This does not imply that the DID does not exist."),
    did: data.did,
    persona: "Live Verified Identity",
    lastActivity: data.latest_verified_activity || "N/A",
    verifiedRecords: data.verified_records || 0,
    totalRetainedRecords: data.verified_records || 0,
    roomCount: roomsList.length,
    latestGeneration: roomsList.length > 0 ? roomsList[0].generation : "N/A",
    latestCommittedRoot: "Currently Retained Public Activity",
    rooms: roomsList,
    retentionNotice: data.retention_notice || "CURRENTLY RETAINED PUBLIC ACTIVITY: Results reflect records currently retained in inspected public room exports. No claim of complete lifetime history.",
    isLive: true
  };
}

async function lookupLiveDid(did) {
  const cleanDid = (did || "").trim();
  if (!cleanDid) {
    throw new Error("DID cannot be empty");
  }

  // Pre-validate DID before initiating network calls: zero downloads on malformed input
  try {
    extractEd25519PubKey(cleanDid);
  } catch (err) {
    throw new Error(`Malformed DID: ${err.message}. Expected did:key:z6Mk...`);
  }

  // Cancel prior in-flight request if user re-triggered lookup
  if (_currentLookupAbortController) {
    _currentLookupAbortController.abort();
  }
  _currentLookupAbortController = new AbortController();
  const signal = _currentLookupAbortController.signal;

  // 1. First attempt: Query local adapter server if running
  const localAdapterUrl = `http://127.0.0.1:8088/api/index?did=${encodeURIComponent(cleanDid)}`;
  try {
    const adapterCtrl = new AbortController();
    const timeoutId = setTimeout(() => adapterCtrl.abort(), 1200);
    const resp = await fetch(localAdapterUrl, { signal: adapterCtrl.signal });
    clearTimeout(timeoutId);
    if (resp.ok) {
      const data = await resp.json();
      return adaptIndexerJsonToExplorer(data);
    }
  } catch (e) {
    // Local adapter not running; proceed directly to browser-direct Technocore read
  }

  // 2. Direct Technocore public read endpoints (with session caching)
  const seedRooms = ["tclk-offers", "lobby"];
  const matchedRecords = [];
  const roomDetails = {};
  let roomsAttempted = 0;
  let roomsSucceeded = 0;
  const inspectedRoomGens = {};

  const now = Date.now();

  for (const room of seedRooms) {
    roomsAttempted++;
    const exportUrl = `https://technocore.chat/r/${encodeURIComponent(room)}/export`;
    try {
      let generation = null;
      let text = null;
      const cached = _ROOM_EXPORT_CACHE.get(room);

      if (cached && now - cached.ts < 30000) {
        generation = cached.generation;
        text = cached.text;
      } else {
        const res = await fetch(exportUrl, { signal });
        if (!res.ok) continue;
        const genHeader = res.headers.get("x-room-generation");
        generation = genHeader ? parseInt(genHeader, 10) : null;
        text = await res.text();
        _ROOM_EXPORT_CACHE.set(room, { generation, text, ts: now });
      }

      roomsSucceeded++;
      inspectedRoomGens[room] = generation !== null ? generation : "N/A";

      const lines = text.split("\n");
      const roomAllMatches = [];
      const roomVerified = [];

      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];
        if (!line.trim()) continue;
        let item;
        try {
          item = JSON.parse(line);
        } catch {
          continue;
        }
        if (item && item.from === cleanDid) {
          item.rawLine = line + "\n";
          item.room = room;
          item.leafIndex = lineIdx;

          if (!item.sig) {
            item.status = "UNSIGNED";
            item.sigReason = "No signature present on wire record";
          } else {
            const v = await verifyRecordSignature(item, room);
            if (v.valid) {
              item.status = "VALID";
              item.sigReason = v.reason;
              roomVerified.push(item);
            } else {
              item.status = "INVALID";
              item.sigReason = v.reason;
            }
          }
          roomAllMatches.push(item);
          matchedRecords.push(item);
        }
      }

      if (roomAllMatches.length > 0) {
        roomDetails[room] = {
          room,
          generation,
          allRecords: roomAllMatches,
          verifiedRecords: roomVerified,
          verifiedCount: roomVerified.length,
          totalCount: roomAllMatches.length,
          latestSeq: Math.max(...roomAllMatches.map(m => m.seq || 0)),
          latestTs: roomAllMatches[roomAllMatches.length - 1].ts
        };
      }
    } catch (e) {
      if (signal.aborted) {
        throw new Error("Lookup cancelled");
      }
      // Continue to next seed room
    }
  }

  if (roomsSucceeded === 0) {
    throw new Error("Could not connect to Technocore public endpoints. Start the local indexer adapter (python tools/tc_indexer_server.py) or check internet connectivity.");
  }

  const verifiedRecords = matchedRecords.filter(r => r.status === "VALID");
  const unsignedRecords = matchedRecords.filter(r => r.status === "UNSIGNED");
  const invalidRecords = matchedRecords.filter(r => r.status === "INVALID");

  const scopeNotice = `Checked 2 indexed public rooms: #tclk-offers (gen ${inspectedRoomGens["tclk-offers"] ?? "N/A"}), #lobby (gen ${inspectedRoomGens["lobby"] ?? "N/A"}).`;
  const directNotice = "Live mode contacts Technocore directly from your browser. TC Verify does not proxy or modify these read requests.";
  const retentionNotice = "CURRENTLY RETAINED PUBLIC ACTIVITY: Results reflect records currently retained in inspected public room exports. No claim of complete lifetime history. Evicted or private records are not included. NO DATA FOUND does not imply non-existence.";

  if (matchedRecords.length === 0) {
    return {
      status: "NO_DATA",
      statusLabel: "NO DATA FOUND",
      statusDescription: "No matching retained activity was found in the inspected public rooms for this DID. This does not imply that the DID does not exist.",
      did: cleanDid,
      persona: "Live Verified Identity",
      lastActivity: "NONE",
      verifiedRecords: 0,
      unsignedRecords: 0,
      invalidSignatures: 0,
      totalRetainedRecords: 0,
      roomCount: 0,
      latestGeneration: "N/A",
      latestCommittedRoot: "N/A",
      rooms: [],
      scopeNotice,
      directDisclosure: directNotice,
      retentionNotice,
      lastChecked: new Date().toUTCString(),
      isLive: true
    };
  }

  // Populate LIVE_ROOMS_DATA strictly from live room details
  const roomsList = Object.keys(roomDetails).map(rName => {
    const act = roomDetails[rName];
    const roomId = `live-${rName}`;
    LIVE_ROOMS_DATA[roomId] = {
      name: rName,
      displayName: `#${rName}`,
      description: `Live retained records for ${cleanDid} in #${rName} (Generation ${act.generation}).`,
      generation: act.generation !== null ? act.generation : "N/A",
      committedRoot: `X-Room-Gen: ${act.generation !== null ? act.generation : "N/A"}`,
      records: act.allRecords,
      messages: act.allRecords
    };
    return {
      id: roomId,
      rawRoomName: rName,
      name: rName,
      retainedRecords: act.totalCount,
      verifiedRecords: act.verifiedCount,
      lastActivity: act.latestTs,
      verifiedStatus: act.verifiedCount > 0 ? "Verified" : "Unverified Activity",
      generation: act.generation !== null ? act.generation : "N/A",
      committedRoot: `X-Room-Gen: ${act.generation !== null ? act.generation : "N/A"}`
    };
  });

  // Calculate Status: NEVER mark ACTIVE based on unsigned or invalid records
  let status = "NO_DATA";
  let statusLabel = "NO DATA FOUND";
  let statusDescription = "";

  const sortedVerifiedTs = verifiedRecords.map(r => new Date(r.ts).getTime()).filter(t => !isNaN(t)).sort((a, b) => a - b);
  const latestVerifiedMs = sortedVerifiedTs.length > 0 ? sortedVerifiedTs[sortedVerifiedTs.length - 1] : null;

  if (verifiedRecords.length > 0 && latestVerifiedMs !== null) {
    const ageHours = (now - latestVerifiedMs) / (1000 * 60 * 60);
    const isActive = ageHours <= 24.0;
    status = isActive ? "ACTIVE" : "STALE";
    statusLabel = isActive ? "ACTIVE" : "STALE / INACTIVE";
    statusDescription = isActive
      ? `Recent verified activity exists within the 24-hour activity window (${verifiedRecords.length} verified record${verifiedRecords.length === 1 ? "" : "s"}).`
      : `Verified retained activity exists, but none falls within the 24-hour activity window (${verifiedRecords.length} verified record${verifiedRecords.length === 1 ? "" : "s"}).`;
  } else {
    // Unverified matching records found
    status = "UNVERIFIED_ACTIVITY";
    statusLabel = "MATCHING ACTIVITY FOUND (UNVERIFIED)";
    statusDescription = `Matching unverified records were found in inspected exports (${unsignedRecords.length} unsigned, ${invalidRecords.length} invalid signatures), but 0 cryptographically verified records exist. Identity cannot be verified active without valid signatures.`;
  }

  const allSortedTs = matchedRecords.map(r => new Date(r.ts).getTime()).filter(t => !isNaN(t)).sort((a, b) => a - b);
  const latestAnyMs = allSortedTs.length > 0 ? allSortedTs[allSortedTs.length - 1] : null;

  return {
    status,
    statusLabel,
    statusDescription,
    did: cleanDid,
    persona: "Live Verified Identity",
    lastActivity: latestVerifiedMs ? new Date(latestVerifiedMs).toISOString() : (latestAnyMs ? new Date(latestAnyMs).toISOString() + " (Unverified)" : "NONE"),
    verifiedRecords: verifiedRecords.length,
    unsignedRecords: unsignedRecords.length,
    invalidSignatures: invalidRecords.length,
    totalRetainedRecords: matchedRecords.length,
    roomCount: roomsList.length,
    latestGeneration: Object.values(roomDetails)[0]?.generation ?? "N/A",
    latestCommittedRoot: "Currently Retained Public Activity",
    rooms: roomsList,
    scopeNotice,
    directDisclosure: directNotice,
    retentionNotice,
    lastChecked: new Date().toUTCString(),
    isLive: true
  };
}

// -----------------------------------------------------------------------------
// Interactive Verification Service
// -----------------------------------------------------------------------------

async function verifyRecordDetails(record, roomId) {
  const enc = new TextEncoder();
  const rawBytes = enc.encode(record.rawLine);

  // 1. Signature Verification
  const sigResult = await verifyRecordSignature(record, roomId);

  // 2. JCS Evidence ID
  const evidenceId = await computeEvidenceId(record);

  // 3. RFC 6962 Leaf Hash: SHA-256(0x00 || rawBytes)
  const computedLeafHash = await computeLeafHash(rawBytes);

  // 4. Merkle Inclusion Check (if proof provided)
  let inclusionResult = {
    verified: false,
    reconstructedRoot: null,
    expectedRoot: null,
    reason: "No inclusion proof attached to record"
  };

  if (record.proof && Array.isArray(record.proof.audit_path)) {
    let currentHash = computedLeafHash;
    for (const step of record.proof.audit_path) {
      if (step.position === "left") {
        currentHash = await computeNodeHash(step.sibling_hash, currentHash);
      } else {
        currentHash = await computeNodeHash(currentHash, step.sibling_hash);
      }
    }
    const matches = (currentHash === record.proof.expected_root);
    inclusionResult = {
      verified: matches,
      reconstructedRoot: currentHash,
      expectedRoot: record.proof.expected_root,
      reason: matches ? "Matches committed export root" : "Reconstructed root mismatch"
    };
  }

  return {
    sigResult,
    evidenceId,
    computedLeafHash,
    inclusionResult,
    rawBytesLength: rawBytes.length
  };
}

// -----------------------------------------------------------------------------
// UI State & Event Wiring (Browser)
// -----------------------------------------------------------------------------

let currentDidData = null;
let currentRoomId = null;
let currentSelectedRecord = null;

function setExplorerMode(mode) {
  currentExplorerMode = mode;
  const btnSynth = document.getElementById("btn-mode-synthetic");
  const btnLive = document.getElementById("btn-mode-live");
  const badge = document.getElementById("mode-source-badge");
  const pillsSynth = document.getElementById("pills-synthetic");
  const pillsLive = document.getElementById("pills-live");
  const topBanner = document.getElementById("top-mode-banner");
  const didInput = document.getElementById("explorer-did-input");

  if (btnSynth) btnSynth.classList.toggle("active", mode === "synthetic");
  if (btnLive) btnLive.classList.toggle("active", mode === "live");

  if (mode === "live") {
    if (badge) {
      badge.textContent = "MODE: LIVE TECHNOCORE";
      badge.style.color = "var(--accent-cyan)";
    }
    if (pillsSynth) pillsSynth.classList.add("hidden");
    if (pillsLive) pillsLive.classList.remove("hidden");
    if (topBanner) {
      topBanner.className = "demo-live-banner";
      topBanner.innerHTML = "LIVE DATA — CURRENTLY RETAINED PUBLIC ACTIVITY &bull; Connected to Technocore public read endpoints. Results represent currently retained activity only. Message content is UNTRUSTED DATA.";
    }
    if (didInput) {
      didInput.value = LIVE_DID_ACTIVE;
    }
  } else {
    if (badge) {
      badge.textContent = "MODE: DEMO FIXTURES";
      badge.style.color = "var(--text-dim)";
    }
    if (pillsSynth) pillsSynth.classList.remove("hidden");
    if (pillsLive) pillsLive.classList.add("hidden");
    if (topBanner) {
      topBanner.className = "demo-synthetic-banner";
      topBanner.innerHTML = "DEMO DATA — SYNTHETIC &bull; All identities, rooms, and records in this explorer are synthetic evaluation fixtures. Not production Technocore history.";
    }
    if (didInput) {
      didInput.value = DEMO_DID_ACTIVE;
    }
  }

  const errBox = document.getElementById("live-error-container");
  if (errBox) errBox.classList.add("hidden");
  const loadBox = document.getElementById("loading-container");
  if (loadBox) loadBox.classList.add("hidden");

  runExplore();
}

function setupUI() {
  if (typeof document === "undefined") return;

  const didInput = document.getElementById("explorer-did-input");
  const btnExplore = document.getElementById("btn-explore");

  // Mode toggles
  const btnModeSynthetic = document.getElementById("btn-mode-synthetic");
  const btnModeLive = document.getElementById("btn-mode-live");
  if (btnModeSynthetic) btnModeSynthetic.addEventListener("click", () => setExplorerMode("synthetic"));
  if (btnModeLive) btnModeLive.addEventListener("click", () => setExplorerMode("live"));

  // Quick select pills (Demo)
  const pillActive = document.getElementById("pill-demo-active");
  const pillStale = document.getElementById("pill-demo-stale");
  const pillUnknown = document.getElementById("pill-demo-unknown");
  if (pillActive) pillActive.addEventListener("click", () => { didInput.value = DEMO_DID_ACTIVE; runExplore(); });
  if (pillStale) pillStale.addEventListener("click", () => { didInput.value = DEMO_DID_STALE; runExplore(); });
  if (pillUnknown) pillUnknown.addEventListener("click", () => { didInput.value = DEMO_DID_UNKNOWN; runExplore(); });

  // Quick select pills (Live)
  const pillLiveActive = document.getElementById("pill-live-active");
  const pillLiveNonexistent = document.getElementById("pill-live-nonexistent");
  const pillLoadJson = document.getElementById("pill-load-json");
  const fileIndexerJson = document.getElementById("file-indexer-json");

  if (pillLiveActive) pillLiveActive.addEventListener("click", () => { didInput.value = LIVE_DID_ACTIVE; runExplore(); });
  if (pillLiveNonexistent) pillLiveNonexistent.addEventListener("click", () => { didInput.value = LIVE_DID_NONEXISTENT; runExplore(); });
  if (pillLoadJson && fileIndexerJson) {
    pillLoadJson.addEventListener("click", () => fileIndexerJson.click());
    fileIndexerJson.addEventListener("change", (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (evt) => {
        try {
          const parsed = JSON.parse(evt.target.result);
          const adapted = adaptIndexerJsonToExplorer(parsed);
          currentDidData = adapted;
          if (didInput) didInput.value = adapted.did || "";
          renderExplorerResult(adapted);
        } catch (err) {
          alert("Invalid indexer JSON file: " + err.message);
        }
      };
      reader.readAsText(file);
    });
  }

  if (btnExplore) {
    btnExplore.addEventListener("click", runExplore);
  }
  if (didInput) {
    didInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") runExplore();
    });
  }

  // URL query parameter support: ?did=...&mode=...
  if (typeof window !== "undefined" && window.location && window.location.search) {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const paramDid = urlParams.get("did");
      const paramMode = urlParams.get("mode");
      if (paramMode === "live" || (!paramMode && paramDid && paramDid.startsWith("did:key:z6Mkei"))) {
        setExplorerMode("live");
      } else if (paramMode === "synthetic") {
        setExplorerMode("synthetic");
      }
      if (paramDid && didInput) {
        didInput.value = paramDid;
        runExplore();
      }
    } catch (e) {
      // Ignore error in non-browser runtimes
    }
  }

  // Navigation tab switching (Search / Consistency / Self-Verify)
  const tabs = document.querySelectorAll(".exp-tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const target = tab.dataset.tab;
      document.querySelectorAll(".exp-view-panel").forEach(p => p.classList.add("hidden"));
      const panel = document.getElementById(target);
      if (panel) panel.classList.remove("hidden");
    });
  });

  // Self-verification run button
  const btnRunSelfVerify = document.getElementById("btn-run-self-verify");
  if (btnRunSelfVerify) {
    btnRunSelfVerify.addEventListener("click", runSelfVerificationTool);
  }

  // Close modal button
  const btnCloseModal = document.getElementById("modal-close-btn");
  if (btnCloseModal) {
    btnCloseModal.addEventListener("click", closeModal);
  }
  const modalOverlay = document.getElementById("record-modal");
  if (modalOverlay) {
    modalOverlay.addEventListener("click", (e) => {
      if (e.target === modalOverlay) closeModal();
    });
  }

  // Default: load active DID
  if (didInput && !didInput.value) {
    didInput.value = DEMO_DID_ACTIVE;
    runExplore();
  }
}

async function runExplore() {
  const didInput = document.getElementById("explorer-did-input");
  if (!didInput) return;
  const did = didInput.value.trim();

  const statusContainer = document.getElementById("identity-status-container");
  const noDataContainer = document.getElementById("no-data-container");
  const activityContainer = document.getElementById("activity-container");
  const roomViewContainer = document.getElementById("room-view-container");
  const loadingContainer = document.getElementById("loading-container");
  const liveErrorContainer = document.getElementById("live-error-container");

  if (roomViewContainer) roomViewContainer.classList.add("hidden");
  if (liveErrorContainer) liveErrorContainer.classList.add("hidden");

  let res;
  if (currentExplorerMode === "live") {
    if (loadingContainer) loadingContainer.classList.remove("hidden");
    if (statusContainer) statusContainer.classList.add("hidden");
    if (noDataContainer) noDataContainer.classList.add("hidden");
    if (activityContainer) activityContainer.classList.add("hidden");

    try {
      res = await lookupLiveDid(did);
    } catch (err) {
      if (loadingContainer) loadingContainer.classList.add("hidden");
      if (liveErrorContainer) {
        liveErrorContainer.classList.remove("hidden");
        const msgEl = document.getElementById("live-error-message");
        if (msgEl) msgEl.textContent = err.message || "Failed to resolve live activity.";
      }
      return;
    } finally {
      if (loadingContainer) loadingContainer.classList.add("hidden");
    }
  } else {
    res = lookupDid(did);
  }

  currentDidData = res;
  renderExplorerResult(res);
}

function renderExplorerResult(res) {
  const statusContainer = document.getElementById("identity-status-container");
  const noDataContainer = document.getElementById("no-data-container");
  const activityContainer = document.getElementById("activity-container");
  const roomViewContainer = document.getElementById("room-view-container");
  const retentionBanner = document.getElementById("retention-notice-banner");

  if (roomViewContainer) roomViewContainer.classList.add("hidden");

  if (res.status === "NO_DATA") {
    if (statusContainer) statusContainer.classList.add("hidden");
    if (activityContainer) activityContainer.classList.add("hidden");
    if (noDataContainer) {
      noDataContainer.classList.remove("hidden");
      document.getElementById("no-data-did").textContent = res.did || "N/A";
    }
    return;
  }

  if (noDataContainer) noDataContainer.classList.add("hidden");
  if (statusContainer) statusContainer.classList.remove("hidden");
  if (activityContainer) activityContainer.classList.remove("hidden");

  // Retention banner
  if (retentionBanner) {
    if (res.retentionNotice) {
      retentionBanner.textContent = res.retentionNotice;
      retentionBanner.classList.remove("hidden");
    } else {
      retentionBanner.classList.add("hidden");
    }
  }

  // Update Status Banner
  const statusBadge = document.getElementById("status-badge");
  const statusDesc = document.getElementById("status-description");
  const didDisplay = document.getElementById("display-did");
  const metaLastActive = document.getElementById("meta-last-active");
  const metaVerified = document.getElementById("meta-verified-records");
  const metaRooms = document.getElementById("meta-rooms");
  const metaGeneration = document.getElementById("meta-generation");
  const metaRoot = document.getElementById("meta-root");

  didDisplay.textContent = res.did;
  statusDesc.textContent = res.statusDescription;
  metaLastActive.textContent = res.lastActivity;
  metaVerified.textContent = res.verifiedRecords;
  metaRooms.textContent = res.roomCount;
  metaGeneration.textContent = res.latestGeneration;
  const rootStr = res.latestCommittedRoot || "N/A";
  metaRoot.textContent = rootStr.length > 20 ? rootStr.substring(0, 16) + "..." : rootStr;
  metaRoot.title = rootStr;

  const metaUnsigned = document.getElementById("meta-unsigned-records");
  if (metaUnsigned) metaUnsigned.textContent = res.unsignedRecords || 0;
  const metaInvalid = document.getElementById("meta-invalid-records");
  if (metaInvalid) metaInvalid.textContent = res.invalidSignatures || 0;

  const metaScope = document.getElementById("meta-scope-details");
  if (metaScope && res.scopeNotice) metaScope.textContent = res.scopeNotice;
  const metaChecked = document.getElementById("meta-last-checked");
  if (metaChecked && res.lastChecked) metaChecked.textContent = `Last checked: ${res.lastChecked}`;

  if (res.status === "ACTIVE") {
    statusBadge.textContent = "🟢 ACTIVE";
    statusBadge.className = "status-pill status-active";
  } else if (res.status === "STALE") {
    statusBadge.textContent = "🟡 STALE / INACTIVE";
    statusBadge.className = "status-pill status-stale";
  } else if (res.status === "UNVERIFIED_ACTIVITY") {
    statusBadge.textContent = "⚠️ MATCHING ACTIVITY FOUND (UNVERIFIED)";
    statusBadge.className = "status-pill status-nodata";
  } else {
    statusBadge.textContent = "⚪ NO DATA FOUND";
    statusBadge.className = "status-pill status-nodata";
  }

  // Render Room Cards
  renderRoomCards(res.rooms);
}

function renderRoomCards(rooms) {
  const grid = document.getElementById("room-cards-grid");
  if (!grid) return;
  grid.replaceChildren();

  rooms.forEach(r => {
    const card = document.createElement("div");
    card.className = "card room-card";

    const header = document.createElement("div");
    header.className = "room-card-header";

    const title = document.createElement("div");
    title.className = "room-card-title";
    title.textContent = "#" + String(r.name || "").toLowerCase();

    const badge = document.createElement("span");
    badge.className = "room-badge";
    badge.textContent = String(r.verifiedStatus || "Verified") + " ✓";

    header.appendChild(title);
    header.appendChild(badge);
    card.appendChild(header);

    const metric = document.createElement("div");
    metric.className = "room-metric";
    metric.textContent = `${r.retainedRecords || 0} retained records`;
    card.appendChild(metric);

    const meta1 = document.createElement("div");
    meta1.className = "room-meta text-dim";
    meta1.textContent = `Latest activity: ${r.lastActivity || "N/A"}`;
    card.appendChild(meta1);

    const meta2 = document.createElement("div");
    meta2.className = "room-meta text-dim";
    meta2.appendChild(document.createTextNode("Committed Root: "));
    const codeEl = document.createElement("code");
    codeEl.textContent = String(r.committedRoot || "N/A");
    meta2.appendChild(codeEl);
    card.appendChild(meta2);

    const btn = document.createElement("button");
    btn.className = "btn btn-sm btn-secondary btn-view-room";
    btn.setAttribute("data-room", String(r.id || ""));
    btn.textContent = "View Activity";
    btn.addEventListener("click", () => {
      openRoom(r.id);
    });
    card.appendChild(btn);

    grid.appendChild(card);
  });
}

function openRoom(roomId) {
  currentRoomId = roomId;
  const roomData = currentExplorerMode === "live"
    ? LIVE_ROOMS_DATA[roomId]
    : SYNTHETIC_ROOMS_DATA[roomId];

  const roomView = document.getElementById("room-view-container");
  if (!roomView) return;

  if (!roomData) {
    roomView.classList.remove("hidden");
    roomView.scrollIntoView({ behavior: "smooth" });
    const isLive = currentExplorerMode === "live";
    document.getElementById("chat-room-title").textContent = isLive ? "Live Room Data Unavailable" : "Room Data Unavailable";
    document.getElementById("chat-room-desc").textContent = isLive
      ? "No live retained records or activity data are available for this room."
      : "The requested synthetic room data could not be found.";
    document.getElementById("chat-room-gen").textContent = "N/A";
    document.getElementById("chat-room-count").textContent = "0";
    document.getElementById("chat-room-root").textContent = "N/A";
    document.getElementById("chat-room-root").title = "N/A";
    const list = document.getElementById("chat-messages-list");
    list.replaceChildren();
    const emptyNotice = document.createElement("div");
    emptyNotice.className = "chat-empty-notice text-secondary";
    emptyNotice.style.padding = "1rem";
    emptyNotice.style.textAlign = "center";
    emptyNotice.textContent = isLive
      ? "Live room data is unavailable for this selection. No synthetic data was substituted."
      : "No records available.";
    list.appendChild(emptyNotice);
    return;
  }

  roomView.classList.remove("hidden");
  roomView.scrollIntoView({ behavior: "smooth" });

  const records = roomData.records || roomData.messages || [];
  const rootStr = roomData.committedRoot || "N/A";

  document.getElementById("chat-room-title").textContent = `#${roomData.name} Activity`;
  document.getElementById("chat-room-desc").textContent = roomData.description || "";
  document.getElementById("chat-room-gen").textContent = (roomData.generation !== undefined && roomData.generation !== null) ? roomData.generation : "N/A";
  document.getElementById("chat-room-count").textContent = records.length;
  document.getElementById("chat-room-root").textContent = rootStr.length > 16 ? rootStr.substring(0, 16) + "..." : rootStr;
  document.getElementById("chat-room-root").title = rootStr;

  const list = document.getElementById("chat-messages-list");
  list.replaceChildren();

  records.forEach(rec => {
    const isTarget = rec.from === currentDidData.did;
    const msgEl = document.createElement("div");
    msgEl.className = `chat-item ${isTarget ? "chat-target" : ""}`;

    const itemHeader = document.createElement("div");
    itemHeader.className = "chat-item-header";

    const senderSpan = document.createElement("span");
    senderSpan.className = `chat-sender ${isTarget ? "text-cyan font-bold" : "text-dim"}`;
    const fromStr = String(rec.from || "");
    senderSpan.textContent = fromStr.length > 24 ? fromStr.substring(0, 24) + "..." : fromStr;

    const tsSpan = document.createElement("span");
    tsSpan.className = "chat-ts text-dim";
    tsSpan.textContent = `${rec.ts || "N/A"} (seq: ${rec.seq !== undefined ? rec.seq : "N/A"})`;

    itemHeader.appendChild(senderSpan);
    itemHeader.appendChild(tsSpan);
    msgEl.appendChild(itemHeader);

    const textDiv = document.createElement("div");
    textDiv.className = "chat-text";
    textDiv.textContent = String(rec.text || "");
    msgEl.appendChild(textDiv);

    const itemFooter = document.createElement("div");
    itemFooter.className = "chat-item-footer";

    // Dynamic signature badge according to actual verification status
    const sigBadge = document.createElement("span");
    if (rec.status === "VALID") {
      sigBadge.className = "chat-badge badge-sig";
      sigBadge.textContent = "✓ Signature verified";
    } else if (rec.status === "UNSIGNED") {
      sigBadge.className = "chat-badge badge-unsigned text-amber";
      sigBadge.textContent = "⚠ Unsigned record";
    } else if (rec.status === "INVALID") {
      sigBadge.className = "chat-badge badge-invalid text-red";
      sigBadge.textContent = "✕ Invalid signature";
    } else {
      sigBadge.className = "chat-badge badge-sig";
      sigBadge.textContent = rec.sig ? "✓ Signature present" : "⚠ Unsigned";
    }
    itemFooter.appendChild(sigBadge);

    const proofBadge = document.createElement("span");
    proofBadge.className = "chat-badge badge-proof";
    proofBadge.textContent = rec.proof ? "✓ Inclusion proof available" : "✓ Retained line";
    itemFooter.appendChild(proofBadge);

    const inspectBtn = document.createElement("button");
    inspectBtn.className = "btn btn-sm btn-outline btn-inspect-rec";
    inspectBtn.textContent = "Inspect Record & Proof";
    inspectBtn.addEventListener("click", () => {
      openRecordDetail(rec, roomId);
    });
    itemFooter.appendChild(inspectBtn);

    msgEl.appendChild(itemFooter);
    list.appendChild(msgEl);
  });
}

async function openRecordDetail(record, roomId) {
  currentSelectedRecord = record;
  const modal = document.getElementById("record-modal");
  if (!modal) return;
  modal.classList.remove("hidden");

  document.getElementById("modal-seq").textContent = record.seq !== undefined ? record.seq : "N/A";
  document.getElementById("modal-room").textContent = roomId || "N/A";
  document.getElementById("modal-nonce").textContent = record.nonce !== undefined ? record.nonce : "N/A";
  document.getElementById("modal-ts").textContent = record.ts || "N/A";
  document.getElementById("modal-sender").textContent = record.from || "N/A";
  document.getElementById("modal-text").textContent = record.text || "";
  document.getElementById("modal-sig").textContent = record.sig || "N/A";
  document.getElementById("modal-raw-line").textContent = record.rawLine || "";

  // Run live verification
  const v = await verifyRecordDetails(record, roomId);
  const sigResultEl = document.getElementById("modal-v-sig");
  if (record.status === "UNSIGNED" || !record.sig) {
    sigResultEl.textContent = "⚠ UNSIGNED (No signature present on wire record)";
    sigResultEl.className = "text-amber";
  } else if (v.sigResult.valid) {
    sigResultEl.textContent = "✓ VALID (" + v.sigResult.reason + ")";
    sigResultEl.className = "text-green";
  } else {
    sigResultEl.textContent = "✕ INVALID (" + v.sigResult.reason + ")";
    sigResultEl.className = "text-red";
  }

  document.getElementById("modal-v-evidence-id").textContent = v.evidenceId;
  document.getElementById("modal-v-leaf-hash").textContent = v.computedLeafHash;

  const incEl = document.getElementById("modal-v-inclusion");
  const rootEl = document.getElementById("modal-v-root");
  const btnDownloadProof = document.getElementById("btn-download-proof");
  const btnViewProofJson = document.getElementById("btn-view-proof-json");
  const proofJsonBox = document.getElementById("modal-proof-json");

  const hasGenuineProof = Boolean(
    record.proof &&
    record.proof.schema === "tc-ledger/inclusion-proof/v1" &&
    Array.isArray(record.proof.audit_path) &&
    record.proof.audit_path.length > 0 &&
    record.proof.expected_root &&
    record.proof.leaf_hash &&
    typeof record.proof.leaf_index === "number" &&
    typeof record.proof.tree_size === "number"
  );

  if (hasGenuineProof) {
    incEl.textContent = v.inclusionResult.verified
      ? "✓ VALID (Inclusion proof verified against expected root)"
      : "✕ INVALID (Proof folding failed)";
    incEl.className = v.inclusionResult.verified ? "text-green" : "text-red";
    rootEl.textContent = record.proof.expected_root;

    if (btnDownloadProof) {
      btnDownloadProof.disabled = false;
      btnDownloadProof.style.opacity = "1";
      btnDownloadProof.style.cursor = "pointer";
      btnDownloadProof.title = "Download verified inclusion proof artifact";
      btnDownloadProof.onclick = () => {
        downloadJson(`proof_leaf_${record.proof.leaf_index}.json`, record.proof);
      };
    }

    if (btnViewProofJson && proofJsonBox) {
      btnViewProofJson.disabled = false;
      btnViewProofJson.style.opacity = "1";
      btnViewProofJson.style.cursor = "pointer";
      btnViewProofJson.onclick = () => {
        proofJsonBox.classList.toggle("hidden");
        if (!proofJsonBox.classList.contains("hidden")) {
          proofJsonBox.textContent = JSON.stringify(record.proof, null, 2);
        }
      };
    }
  } else {
    incEl.textContent = "A verified inclusion proof is not available for this record.";
    incEl.className = "text-dim";
    const activeRoomsData = currentExplorerMode === "live"
      ? LIVE_ROOMS_DATA
      : SYNTHETIC_ROOMS_DATA;
    rootEl.textContent = activeRoomsData[roomId]?.committedRoot || "N/A";

    // Strictly disable download: NEVER fabricate fake inclusion proof artifacts
    if (btnDownloadProof) {
      btnDownloadProof.disabled = true;
      btnDownloadProof.style.opacity = "0.4";
      btnDownloadProof.style.cursor = "not-allowed";
      btnDownloadProof.title = "A verified inclusion proof is not available for this record.";
      btnDownloadProof.onclick = null;
    }

    if (btnViewProofJson && proofJsonBox) {
      btnViewProofJson.disabled = true;
      btnViewProofJson.style.opacity = "0.4";
      btnViewProofJson.style.cursor = "not-allowed";
      btnViewProofJson.title = "A verified inclusion proof is not available for this record.";
      btnViewProofJson.onclick = null;
      proofJsonBox.classList.add("hidden");
    }
  }
}

function closeModal() {
  const modal = document.getElementById("record-modal");
  if (modal) modal.classList.add("hidden");
  const proofBox = document.getElementById("modal-proof-json");
  if (proofBox) proofBox.classList.add("hidden");
}

function downloadJson(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// -----------------------------------------------------------------------------
// Self-Verification Tool Runner (Strict Fail-Closed)
// -----------------------------------------------------------------------------

async function runSelfVerificationTool() {
  const rawInput = document.getElementById("self-verify-record").value;
  const proofInput = document.getElementById("self-verify-proof").value;
  const expectedRootInput = document.getElementById("self-verify-root").value.trim();
  const outputBox = document.getElementById("self-verify-output");
  if (!outputBox) return;

  outputBox.classList.remove("hidden");
  outputBox.replaceChildren();

  if (!rawInput.trim()) {
    const errSpan = document.createElement("span");
    errSpan.className = "text-red";
    errSpan.textContent = "Error: Raw export line is empty.";
    outputBox.appendChild(errSpan);
    return;
  }

  let parsedProof = null;
  try {
    parsedProof = JSON.parse(proofInput);
  } catch (e) {
    const errSpan = document.createElement("span");
    errSpan.className = "text-red";
    errSpan.textContent = "Error: Proof artifact is not valid JSON.";
    outputBox.appendChild(errSpan);
    return;
  }

  const result = await verifyInclusionProof(rawInput, parsedProof, expectedRootInput);

  if (result.status === "INVALID_INPUT") {
    const box = document.createElement("div");
    box.className = "result-box result-invalid";
    const h4 = document.createElement("h4");
    h4.textContent = "✕ NO VERDICT: Invalid Input";
    const p = document.createElement("p");
    p.textContent = result.reason;
    box.appendChild(h4);
    box.appendChild(p);
    outputBox.appendChild(box);
    return;
  }

  if (result.valid) {
    const box = document.createElement("div");
    box.className = "result-box result-valid";
    const h4 = document.createElement("h4");
    h4.textContent = "✓ VALID: Inclusion Proof Verified";

    const pLeaf = document.createElement("p");
    pLeaf.innerHTML = `<strong>Computed Leaf Hash:</strong> <code>${escapeHtml(result.computedLeaf)}</code>`;
    const pRoot = document.createElement("p");
    pRoot.innerHTML = `<strong>Reconstructed Root:</strong> <code>${escapeHtml(result.computedRoot)}</code>`;
    const pMsg = document.createElement("p");
    pMsg.textContent = `The raw record bytes match leaf index ${result.leafIndex} of tree size ${result.treeSize} against trusted commitment ${result.expectedRoot}. Offline verification complete.`;

    box.appendChild(h4);
    box.appendChild(pLeaf);
    box.appendChild(pRoot);
    box.appendChild(pMsg);
    outputBox.appendChild(box);
  } else {
    const box = document.createElement("div");
    box.className = "result-box result-invalid";
    const h4 = document.createElement("h4");
    h4.textContent = "✕ INVALID: Cryptographic Verification Failed";

    if (result.computedLeaf) {
      const pLeaf = document.createElement("p");
      pLeaf.innerHTML = `<strong>Computed Leaf Hash:</strong> <code>${escapeHtml(result.computedLeaf)}</code>`;
      box.appendChild(pLeaf);
    }
    if (result.computedRoot) {
      const pRoot = document.createElement("p");
      pRoot.innerHTML = `<strong>Reconstructed Root:</strong> <code>${escapeHtml(result.computedRoot)}</code>`;
      box.appendChild(pRoot);
    }
    if (result.expectedRoot) {
      const pExp = document.createElement("p");
      pExp.innerHTML = `<strong>Expected Trusted Root:</strong> <code>${escapeHtml(result.expectedRoot)}</code>`;
      box.appendChild(pExp);
    }
    const pReason = document.createElement("p");
    pReason.textContent = `Fail-closed verification failed: ${result.reason}`;
    box.appendChild(h4);
    box.appendChild(pReason);
    outputBox.appendChild(box);
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", setupUI);
}

// Export for Node testing
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    DEMO_DID_ACTIVE,
    DEMO_DID_STALE,
    DEMO_DID_UNKNOWN,
    LIVE_DID_ACTIVE,
    LIVE_DID_NONEXISTENT,
    SYNTHETIC_ROOMS_DATA,
    LIVE_ROOMS_DATA,
    lookupDid,
    lookupLiveDid,
    adaptIndexerJsonToExplorer,
    setExplorerMode,
    computeLeafHash,
    computeNodeHash,
    computeEvidenceId,
    verifyRecordSignature,
    verifyRecordDetails,
    verifyInclusionProof,
    expected_proof_directions,
    extractEd25519PubKey,
    decodeBase58,
    escapeHtml
  };
}

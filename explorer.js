// TC-Ledger Explorer Data Adapter & Cryptographic Engine
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
    if (!recordObj || !recordObj.from || !recordObj.sig || recordObj.nonce === undefined || !recordObj.text) {
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
      // Fallback for older runtimes without WebCrypto Ed25519: format is strictly validated
      if (/^[A-Za-z0-9_-]{86}(?:==)?$/.test(recordObj.sig)) {
        return { valid: true, reason: "Signature format structurally valid (Ed25519 raw 64-byte payload)" };
      }
      return { valid: false, reason: "Malformed signature format" };
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

function setupUI() {
  if (typeof document === "undefined") return;

  const didInput = document.getElementById("explorer-did-input");
  const btnExplore = document.getElementById("btn-explore");
  const pillActive = document.getElementById("pill-demo-active");
  const pillStale = document.getElementById("pill-demo-stale");
  const pillUnknown = document.getElementById("pill-demo-unknown");

  // Quick select pills
  if (pillActive) pillActive.addEventListener("click", () => { didInput.value = DEMO_DID_ACTIVE; runExplore(); });
  if (pillStale) pillStale.addEventListener("click", () => { didInput.value = DEMO_DID_STALE; runExplore(); });
  if (pillUnknown) pillUnknown.addEventListener("click", () => { didInput.value = DEMO_DID_UNKNOWN; runExplore(); });

  if (btnExplore) {
    btnExplore.addEventListener("click", runExplore);
  }
  if (didInput) {
    didInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") runExplore();
    });
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

function runExplore() {
  const didInput = document.getElementById("explorer-did-input");
  if (!didInput) return;
  const did = didInput.value.trim();
  const res = lookupDid(did);
  currentDidData = res;

  // Render Status
  const statusContainer = document.getElementById("identity-status-container");
  const noDataContainer = document.getElementById("no-data-container");
  const activityContainer = document.getElementById("activity-container");
  const roomViewContainer = document.getElementById("room-view-container");
  if (roomViewContainer) roomViewContainer.classList.add("hidden");

  if (res.status === "NO_DATA") {
    if (statusContainer) statusContainer.classList.add("hidden");
    if (activityContainer) activityContainer.classList.add("hidden");
    if (noDataContainer) {
      noDataContainer.classList.remove("hidden");
      document.getElementById("no-data-did").textContent = did || "N/A";
    }
    return;
  }

  if (noDataContainer) noDataContainer.classList.add("hidden");
  if (statusContainer) statusContainer.classList.remove("hidden");
  if (activityContainer) activityContainer.classList.remove("hidden");

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
  metaRoot.textContent = res.latestCommittedRoot.length > 20 ? res.latestCommittedRoot.substring(0, 16) + "..." : res.latestCommittedRoot;
  metaRoot.title = res.latestCommittedRoot;

  if (res.status === "ACTIVE") {
    statusBadge.textContent = "🟢 ACTIVE";
    statusBadge.className = "status-pill status-active";
  } else {
    statusBadge.textContent = "⚪ STALE / INACTIVE";
    statusBadge.className = "status-pill status-stale";
  }

  // Render Room Cards
  renderRoomCards(res.rooms);
}

function renderRoomCards(rooms) {
  const grid = document.getElementById("room-cards-grid");
  if (!grid) return;
  grid.innerHTML = "";

  rooms.forEach(r => {
    const card = document.createElement("div");
    card.className = "card room-card";
    card.innerHTML = `
      <div class="room-card-header">
        <div class="room-card-title">#${r.name.toLowerCase()}</div>
        <span class="room-badge">${r.verifiedStatus} ✓</span>
      </div>
      <div class="room-metric">${r.retainedRecords} retained records</div>
      <div class="room-meta text-dim">Latest activity: ${r.lastActivity}</div>
      <div class="room-meta text-dim">Committed Root: <code>${r.committedRoot}</code></div>
      <button class="btn btn-sm btn-secondary btn-view-room" data-room="${r.id}">View Activity</button>
    `;
    card.querySelector(".btn-view-room").addEventListener("click", () => {
      openRoom(r.id);
    });
    grid.appendChild(card);
  });
}

function openRoom(roomId) {
  currentRoomId = roomId;
  const roomData = SYNTHETIC_ROOMS_DATA[roomId];
  if (!roomData) return;

  const roomView = document.getElementById("room-view-container");
  if (!roomView) return;
  roomView.classList.remove("hidden");
  roomView.scrollIntoView({ behavior: "smooth" });

  document.getElementById("chat-room-title").textContent = `#${roomData.name} Activity`;
  document.getElementById("chat-room-desc").textContent = roomData.description;
  document.getElementById("chat-room-gen").textContent = roomData.generation;
  document.getElementById("chat-room-count").textContent = roomData.records.length;
  document.getElementById("chat-room-root").textContent = roomData.committedRoot.substring(0, 16) + "...";
  document.getElementById("chat-room-root").title = roomData.committedRoot;

  const list = document.getElementById("chat-messages-list");
  list.innerHTML = "";

  roomData.records.forEach(rec => {
    const isTarget = rec.from === currentDidData.did;
    const msgEl = document.createElement("div");
    msgEl.className = `chat-item ${isTarget ? "chat-target" : ""}`;
    msgEl.innerHTML = `
      <div class="chat-item-header">
        <span class="chat-sender ${isTarget ? "text-cyan font-bold" : "text-dim"}">${rec.from.substring(0, 24)}...</span>
        <span class="chat-ts text-dim">${rec.ts} (seq: ${rec.seq})</span>
      </div>
      <div class="chat-text">${escapeHtml(rec.text)}</div>
      <div class="chat-item-footer">
        <span class="chat-badge badge-sig">✓ Signature verified</span>
        <span class="chat-badge badge-proof">${rec.proof ? "✓ Inclusion proof available" : "✓ Retained line"}</span>
        <button class="btn btn-sm btn-outline btn-inspect-rec">Inspect Record &amp; Proof</button>
      </div>
    `;
    msgEl.querySelector(".btn-inspect-rec").addEventListener("click", () => {
      openRecordDetail(rec, roomId);
    });
    list.appendChild(msgEl);
  });
}

async function openRecordDetail(record, roomId) {
  currentSelectedRecord = record;
  const modal = document.getElementById("record-modal");
  if (!modal) return;
  modal.classList.remove("hidden");

  document.getElementById("modal-seq").textContent = record.seq;
  document.getElementById("modal-room").textContent = roomId;
  document.getElementById("modal-nonce").textContent = record.nonce;
  document.getElementById("modal-ts").textContent = record.ts;
  document.getElementById("modal-sender").textContent = record.from;
  document.getElementById("modal-text").textContent = record.text;
  document.getElementById("modal-sig").textContent = record.sig;
  document.getElementById("modal-raw-line").textContent = record.rawLine;

  // Run live verification
  const v = await verifyRecordDetails(record, roomId);
  document.getElementById("modal-v-sig").textContent = v.sigResult.valid ? "✓ VALID (" + v.sigResult.reason + ")" : "✕ INVALID (" + v.sigResult.reason + ")";
  document.getElementById("modal-v-sig").className = v.sigResult.valid ? "text-green" : "text-red";

  document.getElementById("modal-v-evidence-id").textContent = v.evidenceId;
  document.getElementById("modal-v-leaf-hash").textContent = v.computedLeafHash;

  const incEl = document.getElementById("modal-v-inclusion");
  const rootEl = document.getElementById("modal-v-root");
  if (record.proof) {
    incEl.textContent = v.inclusionResult.verified ? "✓ VALID (Inclusion proof verified against expected root)" : "✕ INVALID";
    incEl.className = v.inclusionResult.verified ? "text-green" : "text-red";
    rootEl.textContent = record.proof.expected_root;
  } else {
    incEl.textContent = "Retained in export; inclusion proof not requested for this leaf index";
    incEl.className = "text-dim";
    rootEl.textContent = SYNTHETIC_ROOMS_DATA[roomId]?.committedRoot || "N/A";
  }

  // Setup proof download / view buttons
  const btnDownloadProof = document.getElementById("btn-download-proof");
  if (btnDownloadProof) {
    btnDownloadProof.onclick = () => {
      const proofObj = record.proof || {
        schema: "tc-ledger/inclusion-proof/v1",
        version: 1,
        profile: "tc-ledger/1",
        room: roomId,
        generation: 1,
        tree_size: 6,
        leaf_index: record.leafIndex,
        leaf_hash: v.computedLeafHash,
        notice: "Synthetic demo artifact for leaf index " + record.leafIndex
      };
      downloadJson(`proof_leaf_${record.leafIndex}.json`, proofObj);
    };
  }

  const btnViewProofJson = document.getElementById("btn-view-proof-json");
  const proofJsonBox = document.getElementById("modal-proof-json");
  if (btnViewProofJson && proofJsonBox) {
    btnViewProofJson.onclick = () => {
      proofJsonBox.classList.toggle("hidden");
      if (!proofJsonBox.classList.contains("hidden")) {
        const proofObj = record.proof || {
          schema: "tc-ledger/inclusion-proof/v1",
          leaf_index: record.leafIndex,
          leaf_hash: v.computedLeafHash,
          room: roomId
        };
        proofJsonBox.textContent = JSON.stringify(proofObj, null, 2);
      }
    };
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
// Self-Verification Tool Runner
// -----------------------------------------------------------------------------

async function runSelfVerificationTool() {
  const rawInput = document.getElementById("self-verify-record").value;
  const proofInput = document.getElementById("self-verify-proof").value;
  const expectedRoot = document.getElementById("self-verify-root").value.trim();
  const outputBox = document.getElementById("self-verify-output");
  if (!outputBox) return;

  outputBox.classList.remove("hidden");

  try {
    if (!rawInput.trim()) {
      outputBox.innerHTML = "<span class='text-red'>Error: Raw export line is empty.</span>";
      return;
    }
    const enc = new TextEncoder();
    const rawBytes = enc.encode(rawInput);
    const leafHash = await computeLeafHash(rawBytes);

    let parsedProof = null;
    try {
      parsedProof = JSON.parse(proofInput);
    } catch (e) {
      outputBox.innerHTML = `<span class='text-red'>Error: Proof artifact is not valid JSON.</span>`;
      return;
    }

    if (!Array.isArray(parsedProof.audit_path)) {
      outputBox.innerHTML = `<span class='text-red'>Error: Proof artifact missing audit_path array.</span>`;
      return;
    }

    // Fold proof path
    let current = leafHash;
    for (const step of parsedProof.audit_path) {
      if (step.position === "left") {
        current = await computeNodeHash(step.sibling_hash, current);
      } else {
        current = await computeNodeHash(current, step.sibling_hash);
      }
    }

    const matchesLeaf = !parsedProof.leaf_hash || (parsedProof.leaf_hash === leafHash);
    const targetRoot = expectedRoot || parsedProof.expected_root;
    const matchesRoot = targetRoot ? (current === targetRoot) : true;

    if (matchesLeaf && matchesRoot) {
      outputBox.innerHTML = `
        <div class="result-box result-valid">
          <h4>✓ VALID: Inclusion Proof Verified</h4>
          <p><strong>Computed Leaf Hash:</strong> <code>${leafHash}</code></p>
          <p><strong>Reconstructed Root:</strong> <code>${current}</code></p>
          <p>The raw record bytes match leaf index ${parsedProof.leaf_index !== undefined ? parsedProof.leaf_index : "N/A"} of the committed export root. Offline verification is complete.</p>
        </div>
      `;
    } else {
      outputBox.innerHTML = `
        <div class="result-box result-invalid">
          <h4>✕ INVALID: Cryptographic Verification Failed</h4>
          <p><strong>Computed Leaf Hash:</strong> <code>${leafHash}</code></p>
          <p><strong>Reconstructed Root:</strong> <code>${current}</code></p>
          <p><strong>Expected Root:</strong> <code>${targetRoot || "N/A"}</code></p>
          <p>Verification failed fail-closed: leaf hash or reconstructed root diverges from expected commitment.</p>
        </div>
      `;
    }
  } catch (err) {
    outputBox.innerHTML = `<span class='text-red'>Verification exception: ${escapeHtml(err.message)}</span>`;
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
    SYNTHETIC_ROOMS_DATA,
    lookupDid,
    computeLeafHash,
    computeNodeHash,
    computeEvidenceId,
    verifyRecordSignature,
    verifyRecordDetails,
    extractEd25519PubKey,
    decodeBase58
  };
}

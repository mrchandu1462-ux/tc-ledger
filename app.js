// TC-Ledger Showcase Interactive Verification Sandbox
// Deterministic, offline, dependency-free WebCrypto implementation.

const AUTHENTIC_RECORD_STRING = '{"seq":2,"ts":"2026-09-01T12:02:00.000000Z","from":"did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH","text":"Bob verified session terms","nonce":1002,"sig":"juuohrJ_zJ5oh5hscm5mXK8MykhGVWmKCMMU5cXJC0QrCx3UhanSjuCYOVwghQenfaDwmEWYllHh0cJM9KP7Cw"}\n';

// Fixture parameters from examples/commitment.json and examples/proof_leaf1.json
const EXPECTED_ROOM = "demo-room";
const EXPECTED_LEAF_INDEX = 1;
const EXPECTED_LEAF_HASH = "13dbfe722146b058fe8a560b87ac56be426fc785f907fa061121bd5743d21149";
const EXPECTED_ROOT = "0373cfc78e0b17cd733fd38318af51e119ef366954b0a0fbcba251ef15b066b9";

const AUDIT_PATH = [
  { position: "left", sibling_hash: "589528377029dc2f622020f4df8f141305d6289ac7c68dcae2ffa66bdaa401b6" },
  { position: "right", sibling_hash: "18972fda6f31cf89c8de7601ba9fe37dafa87581e8fb0f0195cce7a4be52d9a8" }
];

// Helper: hex to Uint8Array
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Helper: Uint8Array to hex
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Environment-agnostic WebCrypto accessor (browser window or Node globalThis)
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

// RFC 6962 Leaf Hash: SHA-256(0x00 || data)
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

// Recompute RFC 8785 (JCS) evidence ID simulation for demo
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

// Main verification runner
async function runVerification() {
  const inputEl = document.getElementById("record-input");
  if (!inputEl) return;
  const recordInput = inputEl.value;
  const encoder = new TextEncoder();
  const rawBytes = encoder.encode(recordInput);

  document.getElementById("record-length").textContent = rawBytes.length;

  let parsed = null;
  let isJsonValid = false;
  try {
    parsed = JSON.parse(recordInput);
    isJsonValid = true;
    document.getElementById("record-nonce").textContent = parsed.nonce !== undefined ? parsed.nonce : "N/A";
  } catch (e) {
    document.getElementById("record-nonce").textContent = "N/A";
  }

  // 1. Signature Format Check (strict 86 chars canonical base64url)
  const sigValid = isJsonValid && typeof parsed.sig === "string" && /^[A-Za-z0-9_-]{86}(?:==)?$/.test(parsed.sig);
  const iconSig = document.getElementById("icon-sig");
  if (sigValid) {
    iconSig.textContent = "✓";
    iconSig.className = "v-icon";
  } else {
    iconSig.textContent = "✗";
    iconSig.className = "v-icon fail";
  }

  // 2. Evidence ID
  let evidenceId = "N/A (Malformed JSON)";
  if (isJsonValid) {
    evidenceId = await computeEvidenceId(parsed);
  }
  document.getElementById("v-evidence-id").textContent = evidenceId;

  // 3. Leaf Hash: SHA-256(0x00 || rawBytes)
  const computedLeaf = await computeLeafHash(rawBytes);
  document.getElementById("v-leaf-hash").textContent = computedLeaf;
  const leafMatches = (computedLeaf === EXPECTED_LEAF_HASH);

  const iconLeaf = document.getElementById("icon-leaf");
  const leafMatchEl = document.getElementById("v-leaf-match");
  if (leafMatches) {
    iconLeaf.textContent = "✓";
    iconLeaf.className = "v-icon";
    leafMatchEl.textContent = "Matches proof leaf hash ✓";
    leafMatchEl.className = "v-subtext text-dim";
  } else {
    iconLeaf.textContent = "✗";
    iconLeaf.className = "v-icon fail";
    leafMatchEl.textContent = "Leaf hash mismatch with proof artifact ✗";
    leafMatchEl.className = "v-subtext text-red";
  }

  // 4. Reconstruct Root across Audit Path
  // Path step 0: position left -> computeNodeHash(sibling, leaf)
  const node1 = await computeNodeHash(AUDIT_PATH[0].sibling_hash, computedLeaf);

  // Path step 1: position right -> computeNodeHash(node1, sibling)
  const reconstructedRoot = await computeNodeHash(node1, AUDIT_PATH[1].sibling_hash);
  document.getElementById("v-reconstructed-root").textContent = reconstructedRoot;

  const rootMatches = (reconstructedRoot === EXPECTED_ROOT);
  const iconRoot = document.getElementById("icon-root");
  const rootMatchEl = document.getElementById("v-root-match");
  if (rootMatches) {
    iconRoot.textContent = "✓";
    iconRoot.className = "v-icon";
    rootMatchEl.textContent = "Matches Committed Export Root (Gen 1) ✓";
    rootMatchEl.className = "v-subtext text-dim";
  } else {
    iconRoot.textContent = "✗";
    iconRoot.className = "v-icon fail";
    rootMatchEl.textContent = `Root mismatch: expected ${EXPECTED_ROOT.substring(0, 16)}... ✗`;
    rootMatchEl.className = "v-subtext text-red";
  }

  // Update Status and Explanation
  const overallValid = sigValid && leafMatches && rootMatches;
  const pillStatus = document.getElementById("overall-status-pill");
  const pillRecord = document.getElementById("record-status-pill");
  const explanationBox = document.getElementById("explanation-box");

  if (overallValid) {
    pillStatus.textContent = "VALID";
    pillStatus.className = "pill pill-green";
    pillRecord.textContent = "Authentic";
    pillRecord.className = "pill pill-green";
    explanationBox.className = "explanation-box";
    explanationBox.innerHTML = `<strong>Verification Succeeded:</strong> The raw record bytes match leaf index 1 of the committed export root. Inclusion proof is valid against the committed root.`;
  } else {
    pillStatus.textContent = "INVALID";
    pillStatus.className = "pill pill-red";
    pillRecord.textContent = "Tampered / Modified";
    pillRecord.className = "pill pill-red";
    explanationBox.className = "explanation-box fail";

    let reason = "The record does not match the committed Merkle tree.";
    if (!leafMatches) {
      reason = "Because the raw line bytes were modified (e.g. byte alteration or line-ending change), the derived RFC 6962 leaf hash differs from the audit path. Verification fails closed.";
    } else if (!rootMatches) {
      reason = "The reconstructed Merkle root does not match the expected commitment root.";
    } else if (!sigValid) {
      reason = "The signature format is invalid or malleable.";
    }
    explanationBox.innerHTML = `<strong>Verification FAILED (Fail-Closed):</strong> ${reason}`;
  }
}

// UI Event Handlers
if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    const recordInput = document.getElementById("record-input");
    const btnReset = document.getElementById("btn-reset");
    const btnTamper = document.getElementById("btn-tamper");

    recordInput.value = AUTHENTIC_RECORD_STRING;

    recordInput.addEventListener("input", () => {
      runVerification();
    });

    btnReset.addEventListener("click", () => {
      recordInput.value = AUTHENTIC_RECORD_STRING;
      btnReset.className = "btn btn-sm btn-active";
      btnTamper.className = "btn btn-sm btn-danger";
      runVerification();
    });

    btnTamper.addEventListener("click", () => {
      // Modify text content to simulate unauthorized alteration
      const tampered = AUTHENTIC_RECORD_STRING.replace('"Bob verified session terms"', '"Bob verified altered terms [TAMPERED]"');
      recordInput.value = tampered;
      btnTamper.className = "btn btn-sm btn-active";
      btnReset.className = "btn btn-sm btn-secondary";
      runVerification();
    });

    // Initial calculation
    runVerification();
  });
}

// Export for headless testing if run under Node
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    AUTHENTIC_RECORD_STRING,
    EXPECTED_LEAF_HASH,
    EXPECTED_ROOT,
    AUDIT_PATH,
    computeLeafHash,
    computeNodeHash,
    computeEvidenceId,
  };
}

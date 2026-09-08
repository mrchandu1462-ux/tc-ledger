// SPDX-License-Identifier: Apache-2.0

import { sha256 } from "@noble/hashes/sha2.js";
import { type Address, type Hash, getAddress } from "viem";

const HEX32_RE = /^0x[0-9a-fA-F]{64}$/;

/**
 * Convert UTC milliseconds to EVM block timestamp in seconds.
 * Uses ceiling to ensure on-chain refund window cannot open before off-chain refundAfterMs.
 */
export function toEvmTimestamp(refundAfterMs: number): bigint {
  if (!Number.isSafeInteger(refundAfterMs) || refundAfterMs <= 0) {
    throw new Error(`invalid refundAfterMs: ${refundAfterMs}`);
  }
  return BigInt(Math.ceil(refundAfterMs / 1000));
}

export function isValidHex32(val: string): val is Hash {
  return typeof val === "string" && HEX32_RE.test(val);
}

export function normalizeHex32(val: string): Hash {
  if (!isValidHex32(val)) {
    throw new Error(`invalid 32-byte hex string: ${val}`);
  }
  return val.toLowerCase() as Hash;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("odd length hex string");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return `0x${hex}`;
}

export function computeSha256(preimageHex: string): Hash {
  const bytes = hexToBytes(preimageHex);
  const digest = sha256(bytes);
  return bytesToHex(digest).toLowerCase() as Hash;
}

export function verifyPreimage(statementHex: string, secretHex: string): boolean {
  try {
    return computeSha256(secretHex) === statementHex.toLowerCase();
  } catch {
    return false;
  }
}

export function areAddressesEqual(a: string, b: string): boolean {
  try {
    return getAddress(a) === getAddress(b);
  } catch {
    return false;
  }
}

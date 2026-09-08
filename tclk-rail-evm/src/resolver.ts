// SPDX-License-Identifier: Apache-2.0

import { type Address, getAddress, keccak256 } from "viem";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import type { EvmAddressResolver } from "./types.js";
import { EvmRailError } from "./errors.js";

/**
 * Address resolver using an explicit static dictionary.
 * Ideal for known counterparties, testing, and deterministic environments.
 */
export class StaticAddressResolver implements EvmAddressResolver {
  private readonly map = new Map<string, Address>();

  constructor(initialMapping: Record<string, string> = {}) {
    for (const [did, addr] of Object.entries(initialMapping)) {
      this.map.set(did.toLowerCase(), getAddress(addr));
    }
  }

  set(did: string, address: string): void {
    this.map.set(did.toLowerCase(), getAddress(address));
  }

  async resolve(did: string): Promise<Address> {
    const found = this.map.get(did.toLowerCase());
    if (!found) {
      throw new EvmRailError(`no EVM address registered for DID: ${did}`);
    }
    return found;
  }
}

/**
 * Address resolver that derives the 20-byte EVM address directly from a 33-byte SEC1
 * compressed secp256k1 public key:
 *   address = keccak256(uncompressedPubKey[1..65])[12..32]
 */
export class Secp256k1KeyAddressResolver implements EvmAddressResolver {
  async resolve(keyHex: string): Promise<Address> {
    try {
      const cleanHex = keyHex.startsWith("0x") ? keyHex.slice(2) : keyHex;
      const point = secp256k1.Point.fromHex(cleanHex);
      const uncompressed = point.toBytes(false); // 65 bytes (prefix 0x04)
      const hash = keccak256(uncompressed.subarray(1)); // 32 bytes keccak over (X || Y)
      return getAddress(`0x${hash.slice(26)}`); // last 20 bytes
    } catch (err) {
      throw new EvmRailError(`failed to derive EVM address from key ${keyHex}: ${String(err)}`);
    }
  }
}

/**
 * Composite resolver that tries resolvers in sequence until one resolves successfully.
 */
export class CompositeAddressResolver implements EvmAddressResolver {
  constructor(private readonly resolvers: EvmAddressResolver[]) {}

  async resolve(did: string): Promise<Address> {
    for (const resolver of this.resolvers) {
      try {
        return await resolver.resolve(did);
      } catch {
        // try next
      }
    }
    throw new EvmRailError(`none of the configured resolvers could resolve DID: ${did}`);
  }
}

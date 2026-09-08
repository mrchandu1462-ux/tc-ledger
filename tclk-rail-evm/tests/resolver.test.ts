// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { getAddress } from "viem";
import {
  StaticAddressResolver,
  Secp256k1KeyAddressResolver,
  CompositeAddressResolver,
} from "../src/resolver.js";
import { EvmRailError } from "../src/errors.js";

const PAYER_DID = "did:key:z6Mkffffffffffffffffffffffffffffffffffffffffffff";
const PAYEE_DID = "did:key:z6Mkgggggggggggggggggggggggggggggggggggggggggggg";
const UNKNOWN_DID = "did:key:z6Mkhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";

const PAYER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const PAYEE_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const STRANGER_ADDRESS = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

// Anvil Account 0 compressed public key (secp256k1, 33-byte SEC1) -> 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
const PAYER_PUBKEY = "0x038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75";
// Anvil Account 1 compressed public key (secp256k1, 33-byte SEC1) -> 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
const PAYEE_PUBKEY = "0x02ba5734d8f7091719471e7f7ed6b9df170dc70cc661ca05e688601ad984f068b0";

describe("StaticAddressResolver", () => {
  it("resolves registered DID to checksummed EVM address", async () => {
    const resolver = new StaticAddressResolver({
      [PAYER_DID]: PAYER_ADDRESS.toLowerCase(), // even if passed in lowercase
      [PAYEE_DID]: PAYEE_ADDRESS,
    });

    const payer = await resolver.resolve(PAYER_DID);
    const payee = await resolver.resolve(PAYEE_DID);

    expect(payer).toBe(getAddress(PAYER_ADDRESS));
    expect(payee).toBe(getAddress(PAYEE_ADDRESS));
  });

  it("is case-insensitive with respect to the input DID string", async () => {
    const resolver = new StaticAddressResolver({
      [PAYER_DID]: PAYER_ADDRESS,
    });

    const res = await resolver.resolve(PAYER_DID.toUpperCase());
    expect(res).toBe(getAddress(PAYER_ADDRESS));
  });

  it("allows setting mappings dynamically via set()", async () => {
    const resolver = new StaticAddressResolver();
    resolver.set(PAYER_DID, PAYER_ADDRESS);

    expect(await resolver.resolve(PAYER_DID)).toBe(getAddress(PAYER_ADDRESS));
  });

  it("throws EvmRailError on unknown DID", async () => {
    const resolver = new StaticAddressResolver({
      [PAYER_DID]: PAYER_ADDRESS,
    });

    await expect(resolver.resolve(UNKNOWN_DID)).rejects.toThrow(EvmRailError);
    await expect(resolver.resolve(UNKNOWN_DID)).rejects.toThrow(/no EVM address registered/);
  });

  it("rejects malformed/invalid EVM addresses on construction or set", () => {
    expect(() => new StaticAddressResolver({ [PAYER_DID]: "not-an-address" })).toThrow();
    expect(() => new StaticAddressResolver({ [PAYER_DID]: "0x1234" })).toThrow();

    const resolver = new StaticAddressResolver();
    expect(() => resolver.set(PAYER_DID, "0xdead")).toThrow();
  });

  it("provides deterministic resolution across repeated calls", async () => {
    const resolver = new StaticAddressResolver({ [PAYER_DID]: PAYER_ADDRESS });
    const first = await resolver.resolve(PAYER_DID);
    const second = await resolver.resolve(PAYER_DID);
    const third = await resolver.resolve(PAYER_DID);

    expect(first).toBe(second);
    expect(second).toBe(third);
  });
});

describe("Secp256k1KeyAddressResolver", () => {
  it("derives the correct EVM address from valid compressed secp256k1 public keys", async () => {
    const resolver = new Secp256k1KeyAddressResolver();

    const addr0 = await resolver.resolve(PAYER_PUBKEY);
    expect(addr0).toBe(getAddress(PAYER_ADDRESS));

    const addr1 = await resolver.resolve(PAYEE_PUBKEY);
    expect(addr1).toBe(getAddress(PAYEE_ADDRESS));
  });

  it("supports hex strings with or without 0x prefix", async () => {
    const resolver = new Secp256k1KeyAddressResolver();

    const withPrefix = await resolver.resolve(PAYER_PUBKEY);
    const withoutPrefix = await resolver.resolve(PAYER_PUBKEY.slice(2));

    expect(withPrefix).toBe(getAddress(PAYER_ADDRESS));
    expect(withoutPrefix).toBe(getAddress(PAYER_ADDRESS));
  });

  it("throws EvmRailError on invalid/malformed payment keys", async () => {
    const resolver = new Secp256k1KeyAddressResolver();

    // Not hex
    await expect(resolver.resolve("not-a-hex-key")).rejects.toThrow(EvmRailError);

    // Wrong length (32 bytes instead of 33 bytes)
    await expect(
      resolver.resolve("0x" + "11".repeat(32)),
    ).rejects.toThrow(/failed to derive EVM address/);

    // Invalid prefix for compressed key (0x01 instead of 0x02 or 0x03)
    await expect(
      resolver.resolve("0x01" + "11".repeat(32)),
    ).rejects.toThrow(EvmRailError);

    // Point not on secp256k1 curve
    await expect(
      resolver.resolve("0x02" + "ff".repeat(32)),
    ).rejects.toThrow(EvmRailError);
  });

  it("provides deterministic resolution across repeated calls", async () => {
    const resolver = new Secp256k1KeyAddressResolver();
    const first = await resolver.resolve(PAYER_PUBKEY);
    const second = await resolver.resolve(PAYER_PUBKEY);

    expect(first).toBe(second);
  });
});

describe("CompositeAddressResolver", () => {
  it("falls back to secondary resolvers when primary cannot resolve", async () => {
    const primary = new StaticAddressResolver({
      [PAYER_DID]: PAYER_ADDRESS,
    });
    const secondary = new StaticAddressResolver({
      [PAYEE_DID]: PAYEE_ADDRESS,
    });

    const composite = new CompositeAddressResolver([primary, secondary]);

    // Resolved by primary
    expect(await composite.resolve(PAYER_DID)).toBe(getAddress(PAYER_ADDRESS));
    // Resolved by secondary fallback
    expect(await composite.resolve(PAYEE_DID)).toBe(getAddress(PAYEE_ADDRESS));
  });

  it("respects precedence of earlier resolvers in the chain", async () => {
    const primary = new StaticAddressResolver({
      [PAYER_DID]: PAYER_ADDRESS,
    });
    const secondary = new StaticAddressResolver({
      [PAYER_DID]: STRANGER_ADDRESS, // conflicting address for same DID
    });

    const composite = new CompositeAddressResolver([primary, secondary]);

    // Must return the address from primary
    expect(await composite.resolve(PAYER_DID)).toBe(getAddress(PAYER_ADDRESS));
  });

  it("throws EvmRailError if none of the resolvers in the chain can resolve the DID", async () => {
    const primary = new StaticAddressResolver({ [PAYER_DID]: PAYER_ADDRESS });
    const secondary = new StaticAddressResolver({ [PAYEE_DID]: PAYEE_ADDRESS });

    const composite = new CompositeAddressResolver([primary, secondary]);

    await expect(composite.resolve(UNKNOWN_DID)).rejects.toThrow(EvmRailError);
    await expect(composite.resolve(UNKNOWN_DID)).rejects.toThrow(
      /none of the configured resolvers could resolve/,
    );
  });

  it("seamlessly composes Static and Secp256k1Key resolvers", async () => {
    const staticResolver = new StaticAddressResolver({
      [PAYER_DID]: PAYER_ADDRESS,
    });
    const keyResolver = new Secp256k1KeyAddressResolver();

    const composite = new CompositeAddressResolver([staticResolver, keyResolver]);

    // Resolved via DID in static resolver
    expect(await composite.resolve(PAYER_DID)).toBe(getAddress(PAYER_ADDRESS));
    // Resolved via secp256k1 public key
    expect(await composite.resolve(PAYEE_PUBKEY)).toBe(getAddress(PAYEE_ADDRESS));
  });
});

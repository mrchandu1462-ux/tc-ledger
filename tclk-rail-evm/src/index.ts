// SPDX-License-Identifier: Apache-2.0

export { EvmHtlcRail } from "./rail.js";
export {
  EscrowStatus,
  type LockKind,
  type LockTerms,
  type SettlementRail,
  type OnChainEscrow,
  type EvmAddressResolver,
  type AssetResolver,
  type EvmHtlcRailConfig,
} from "./types.js";
export {
  StaticAddressResolver,
  Secp256k1KeyAddressResolver,
  CompositeAddressResolver,
} from "./resolver.js";
export {
  EvmRailError,
  UnsupportedLockKindError,
  InvalidTermsError,
  EscrowNotFoundError,
  EscrowNotLockedError,
  RefundWindowOpenError,
  ClaimTooLateError,
  RefundTooEarlyError,
  InvalidSecretError,
} from "./errors.js";
export {
  toEvmTimestamp,
  computeSha256,
  verifyPreimage,
  isValidHex32,
  normalizeHex32,
  areAddressesEqual,
} from "./utils.js";
export { HTLC_ABI, ERC20_ABI } from "./abi.js";

// SPDX-License-Identifier: Apache-2.0

export class EvmRailError extends Error {
  constructor(message: string) {
    super(`evm-htlc: ${message}`);
    this.name = "EvmRailError";
  }
}

export class UnsupportedLockKindError extends EvmRailError {
  constructor(lock: string) {
    super(`V1 does not support "${lock}" locks (hash locks only)`);
    this.name = "UnsupportedLockKindError";
  }
}

export class InvalidTermsError extends EvmRailError {
  constructor(reason: string) {
    super(`invalid lock terms: ${reason}`);
    this.name = "InvalidTermsError";
  }
}

export class EscrowNotFoundError extends EvmRailError {
  constructor(ref: string) {
    super(`unknown escrow for ref ${ref}`);
    this.name = "EscrowNotFoundError";
  }
}

export class EscrowNotLockedError extends EvmRailError {
  constructor(ref: string, status: string) {
    super(`escrow ${ref} is in status ${status}, expected Locked`);
    this.name = "EscrowNotLockedError";
  }
}

export class RefundWindowOpenError extends EvmRailError {
  constructor(message = "refusing to lock into an already-open refund window") {
    super(message);
    this.name = "RefundWindowOpenError";
  }
}

export class ClaimTooLateError extends EvmRailError {
  constructor(message = "claim at or after refund deadline") {
    super(message);
    this.name = "ClaimTooLateError";
  }
}

export class RefundTooEarlyError extends EvmRailError {
  constructor(message = "refund before refund deadline") {
    super(message);
    this.name = "RefundTooEarlyError";
  }
}

export class InvalidSecretError extends EvmRailError {
  constructor(message = "secret does not open the statement") {
    super(message);
    this.name = "InvalidSecretError";
  }
}

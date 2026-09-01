from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass

import base58
import jcs
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


DID_PREFIX = "did:key:"
ED25519_MULTICODEC = b"\xed\x01"
EXPECTED_SIGNATURE_BYTES = 64
MAX_NONCE_DIGITS = 19


class VerificationError(Exception):
    """Base class for record verification failures."""


class MalformedRecord(VerificationError):
    pass


class UnsupportedKeyType(VerificationError):
    pass


class InvalidSignature(VerificationError):
    pass


@dataclass
class VerificationResult:
    seq: int
    status: str


def public_key_from_did(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise MalformedRecord("invalid DID prefix")

    multibase = did[len(DID_PREFIX):]

    if not multibase.startswith("z"):
        raise MalformedRecord("DID is not base58btc multibase")

    try:
        decoded = base58.b58decode(multibase[1:])
    except ValueError as exc:
        raise MalformedRecord("invalid base58btc DID") from exc

    if len(decoded) < 2:
        raise MalformedRecord("DID payload too short")

    if decoded[:2] != ED25519_MULTICODEC:
        raise UnsupportedKeyType(
            f"unsupported multicodec prefix: {decoded[:2].hex()}"
        )

    public_key = decoded[2:]

    if len(public_key) != 32:
        raise MalformedRecord(
            f"Ed25519 public key must be 32 bytes, got {len(public_key)}"
        )

    return public_key


def verify_signed_record(record: dict, room: str) -> VerificationResult:
    required = ("seq", "ts", "from", "text")

    for field in required:
        if field not in record:
            raise MalformedRecord(f"missing required field: {field}")

    if "sig" not in record:
        return VerificationResult(seq=record["seq"], status="UNSIGNED")

    for field in ("nonce", "sig"):
        if field not in record:
            raise MalformedRecord(f"missing signed field: {field}")

    if not isinstance(record["seq"], int):
        raise MalformedRecord("seq must be an integer")

    if not isinstance(record["from"], str):
        raise MalformedRecord("from must be a string")

    if not isinstance(record["text"], str):
        raise MalformedRecord("text must be a string")

    nonce = record["nonce"]

    if isinstance(nonce, bool) or not isinstance(nonce, int):
        raise MalformedRecord("nonce must be an integer")

    if nonce < 0 or len(str(nonce)) > MAX_NONCE_DIGITS:
        raise MalformedRecord("nonce outside supported range")

    if not isinstance(record["sig"], str):
        raise MalformedRecord("sig must be a string")

    try:
        public_key = public_key_from_did(record["from"])
    except VerificationError:
        raise

    try:
        signature = base64.urlsafe_b64decode(record["sig"] + "==")
    except Exception as exc:
        raise MalformedRecord("invalid base64url signature") from exc

    if len(signature) != EXPECTED_SIGNATURE_BYTES:
        raise MalformedRecord(
            f"signature must decode to 64 bytes, got {len(signature)}"
        )

    canonical = f"{room}|{nonce}|{record['text']}".encode("utf-8")

    try:
        VerifyKey(public_key).verify(canonical, signature)
    except BadSignatureError as exc:
        raise InvalidSignature("Ed25519 signature verification failed") from exc

    return VerificationResult(seq=record["seq"], status="VALID")


def evidence_commitment(record: dict, room: str) -> str:
    """Create a tc-ledger v1 evidence commitment.

    The caller is responsible for verifying the record's Technocore
    signature before treating the resulting commitment as verified evidence.
    """
    required = ("seq", "ts", "from", "text", "nonce", "sig")

    for field in required:
        if field not in record:
            raise MalformedRecord(f"missing evidence field: {field}")

    payload = {
        "version": 1,
        "room": room,
        "seq": record["seq"],
        "ts": record["ts"],
        "from": record["from"],
        "text": record["text"],
        "nonce": record["nonce"],
        "sig": record["sig"],
    }

    canonical = jcs.canonicalize(payload)
    digest = hashlib.sha256(canonical).hexdigest()

    return f"tc-ledger:v1:{digest}"


def verify_export(path: str, room: str) -> dict[str, int]:
    counts = {
        "VALID": 0,
        "INVALID": 0,
        "UNSIGNED": 0,
        "MALFORMED": 0,
        "UNSUPPORTED_KEY": 0,
    }

    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise MalformedRecord("record must be a JSON object")

                result = verify_signed_record(record, room)
                counts[result.status] += 1

            except UnsupportedKeyType as exc:
                counts["UNSUPPORTED_KEY"] += 1
                print(
                    f"UNSUPPORTED_KEY line {line_number}: {exc}",
                    file=sys.stderr,
                )

            except InvalidSignature as exc:
                counts["INVALID"] += 1
                print(
                    f"INVALID line {line_number}: {exc}",
                    file=sys.stderr,
                )

            except (json.JSONDecodeError, VerificationError) as exc:
                counts["MALFORMED"] += 1
                print(
                    f"MALFORMED line {line_number}: {exc}",
                    file=sys.stderr,
                )

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify signed records from a Technocore room export."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify",
        help="verify a JSONL Technocore export",
    )
    verify_parser.add_argument("path")
    verify_parser.add_argument("--room", required=True)

    args = parser.parse_args()

    if args.command == "verify":
        counts = verify_export(args.path, args.room)

        print(f"Room: {args.room}")
        print(f"Valid signatures: {counts['VALID']}")
        print(f"Invalid signatures: {counts['INVALID']}")
        print(f"Unsigned records: {counts['UNSIGNED']}")
        print(f"Malformed records: {counts['MALFORMED']}")
        print(f"Unsupported key types: {counts['UNSUPPORTED_KEY']}")

        if counts["INVALID"] or counts["MALFORMED"]:
            return 1

        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

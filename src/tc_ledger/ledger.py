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


def leaf_hash(evidence_id: str) -> bytes:
    """Hash an evidence identifier as a Merkle v1 leaf."""
    if not isinstance(evidence_id, str):
        raise TypeError("evidence_id must be a string")

    return hashlib.sha256(b"\x00" + evidence_id.encode("utf-8")).digest()



def export_leaf_hash(raw_line_bytes: bytes) -> bytes:
    """Hash one captured export line as an Export Commitment v1 leaf."""
    if not isinstance(raw_line_bytes, bytes):
        raise TypeError("raw_line_bytes must be bytes")

    return hashlib.sha256(b"\x00" + raw_line_bytes).digest()

def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash two Merkle v1 child nodes."""
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        raise TypeError("Merkle child hashes must be bytes")

    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle child hashes must be 32 bytes")

    return hashlib.sha256(b"\x01" + left + right).digest()



def _build_levels(evidence_ids: list[str]) -> list[list[bytes]]:
    """Build all Merkle v1 levels from ordered evidence identifiers."""
    if not evidence_ids:
        return [[hashlib.sha256(b"").digest()]]

    levels = [[leaf_hash(evidence_id) for evidence_id in evidence_ids]]

    while len(levels[-1]) > 1:
        level = levels[-1]
        next_level = []

        for index in range(0, len(level), 2):
            left = level[index]

            if index + 1 >= len(level):
                next_level.append(left)
            else:
                right = level[index + 1]
                next_level.append(node_hash(left, right))

        levels.append(next_level)

    return levels


def merkle_root(evidence_ids: list[str]) -> bytes:
    """Build a Merkle v1 root from ordered evidence identifiers."""
    return _build_levels(evidence_ids)[-1][0]


def merkle_proof(
    evidence_ids: list[str],
    index: int,
) -> list[tuple[bytes, str]]:
    """Generate a Merkle v1 inclusion proof for one evidence identifier."""
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("index must be an integer")

    if index < 0 or index >= len(evidence_ids):
        raise IndexError("index outside evidence identifier list")

    levels = _build_levels(evidence_ids)
    proof: list[tuple[bytes, str]] = []
    current_index = index

    for level in levels[:-1]:
        if current_index % 2 == 0:
            sibling_index = current_index + 1

            if sibling_index < len(level):
                proof.append((level[sibling_index], "right"))
        else:
            sibling_index = current_index - 1
            proof.append((level[sibling_index], "left"))

        current_index //= 2

    return proof

def verify_merkle_proof(
    evidence_id: str,
    proof: list[tuple[bytes, str]],
    expected_root: bytes,
) -> bool:
    """Verify a Merkle v1 inclusion proof."""
    if not isinstance(evidence_id, str):
        raise TypeError("evidence_id must be a string")

    if not isinstance(expected_root, bytes):
        raise TypeError("expected_root must be bytes")

    if len(expected_root) != 32:
        raise ValueError("expected_root must be 32 bytes")

    if not isinstance(proof, list):
        raise TypeError("proof must be a list")

    current = leaf_hash(evidence_id)

    for sibling, position in proof:
        if not isinstance(sibling, bytes):
            raise TypeError("proof sibling hash must be bytes")

        if len(sibling) != 32:
            raise ValueError("proof sibling hash must be 32 bytes")

        if position == "left":
            current = node_hash(sibling, current)
        elif position == "right":
            current = node_hash(current, sibling)
        else:
            raise ValueError("proof position must be 'left' or 'right'")

    return current == expected_root


def export_merkle_root(raw_lines: list[bytes]) -> bytes:
    """Build an Export Commitment v1 Merkle root from captured lines."""
    if not isinstance(raw_lines, list):
        raise TypeError("raw_lines must be a list")

    if not raw_lines:
        return hashlib.sha256(b"").digest()

    level = []

    for raw_line in raw_lines:
        if not isinstance(raw_line, bytes):
            raise TypeError("each raw line must be bytes")
        level.append(export_leaf_hash(raw_line))

    while len(level) > 1:
        next_level = []

        for index in range(0, len(level), 2):
            left = level[index]

            if index + 1 >= len(level):
                next_level.append(left)
            else:
                right = level[index + 1]
                next_level.append(node_hash(left, right))

        level = next_level

    return level[0]



@dataclass(frozen=True)
class EvidenceLeafMapping:
    evidence_id: str
    export_leaf_index: int


@dataclass(frozen=True)
class ExportEvidenceIndex:
    export_root: bytes
    mappings: list[EvidenceLeafMapping]


def map_evidence_to_export(
    raw_lines: list[bytes],
    room: str,
) -> ExportEvidenceIndex:
    """Map valid evidence identifiers to leaves in a complete export."""
    if not isinstance(raw_lines, list):
        raise TypeError("raw_lines must be a list")

    if not isinstance(room, str):
        raise TypeError("room must be a string")

    export_root = export_merkle_root(raw_lines)
    mappings: list[EvidenceLeafMapping] = []

    for index, raw_line in enumerate(raw_lines):
        if not isinstance(raw_line, bytes):
            raise TypeError("each raw line must be bytes")

        if not raw_line.strip():
            continue

        try:
            result = _classify_export_line(
                raw_line.decode("utf-8"),
                room,
            )
        except UnsupportedKeyType:
            continue
        except InvalidSignature:
            continue
        except (UnicodeDecodeError, json.JSONDecodeError, MalformedRecord):
            continue

        if result.status != "VALID":
            continue

        record = json.loads(raw_line)

        evidence_id = evidence_commitment(record, room)

        mappings.append(
            EvidenceLeafMapping(
                evidence_id=evidence_id,
                export_leaf_index=index,
            )
        )

    return ExportEvidenceIndex(
        export_root=export_root,
        mappings=mappings,
    )


def find_duplicate_evidence_ids(
    index: ExportEvidenceIndex,
) -> list[str]:
    """Return evidence IDs occurring more than once, preserving first-seen order."""
    seen: set[str] = set()
    duplicate_seen: set[str] = set()
    duplicates: list[str] = []

    for mapping in index.mappings:
        evidence_id = mapping.evidence_id

        if evidence_id in seen:
            if evidence_id not in duplicate_seen:
                duplicate_seen.add(evidence_id)
                duplicates.append(evidence_id)
        else:
            seen.add(evidence_id)

    return duplicates

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



def _classify_export_line(line: str, room: str) -> VerificationResult:
    """Classify one non-blank JSONL export line."""
    record = json.loads(line)

    if not isinstance(record, dict):
        raise MalformedRecord("record must be a JSON object")

    return verify_signed_record(record, room)

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
                result = _classify_export_line(line, room)
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

    commit_parser = subparsers.add_parser(
        "commit",
        help="commit a JSONL Technocore export",
    )
    commit_parser.add_argument("path")
    commit_parser.add_argument("--room", required=True)

    args = parser.parse_args()

    if args.command == "commit":
        with open(args.path, "rb") as f:
            raw_lines = f.readlines()
        index = map_evidence_to_export(raw_lines, args.room)
        counts = verify_export(args.path, args.room)

        print(f"Room: {args.room}")
        print(f"Export lines: {len(raw_lines)}")
        print(f"Export Merkle root: {index.export_root.hex()}")
        print(f"Valid signatures: {counts['VALID']}")
        print(f"Invalid signatures: {counts['INVALID']}")
        print(f"Unsigned records: {counts['UNSIGNED']}")
        print(f"Malformed records: {counts['MALFORMED']}")
        print(f"Unsupported key types: {counts['UNSUPPORTED_KEY']}")
        print(f"Evidence mappings: {len(index.mappings)}")
        print(f"Duplicate evidence IDs: {len(find_duplicate_evidence_ids(index))}")

        if counts["INVALID"] or counts["MALFORMED"]:
            return 1

        return 0

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

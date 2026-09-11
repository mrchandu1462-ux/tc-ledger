from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
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

    if isinstance(nonce, bool):
        raise MalformedRecord("nonce must not be a boolean")

    if isinstance(nonce, int):
        if nonce < 0 or len(str(nonce)) > MAX_NONCE_DIGITS:
            raise MalformedRecord("nonce outside supported range")
    elif isinstance(nonce, str):
        if not re.fullmatch(r"[0-9]{1,19}", nonce):
            raise MalformedRecord("nonce string must be 1-19 ASCII digits")
    else:
        raise MalformedRecord("nonce must be an integer or digit string")

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


def _build_export_levels(raw_lines: list[bytes]) -> list[list[bytes]]:
    """Build all Merkle levels for raw export lines."""
    if not isinstance(raw_lines, list):
        raise TypeError("raw_lines must be a list")

    if not raw_lines:
        return [[hashlib.sha256(b"").digest()]]

    level = []

    for raw_line in raw_lines:
        if not isinstance(raw_line, bytes):
            raise TypeError("each raw line must be bytes")
        level.append(export_leaf_hash(raw_line))

    levels = [level]

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
        levels.append(level)

    return levels

def export_merkle_proof(
    raw_lines: list[bytes],
    index: int,
) -> list[tuple[bytes, str]]:
    """Generate an Export Merkle v1 inclusion proof."""
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("index must be an integer")

    if index < 0 or index >= len(raw_lines):
        raise IndexError("index outside export line list")

    levels = _build_export_levels(raw_lines)
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

def verify_export_merkle_proof(
    raw_line_bytes: bytes,
    proof: list[tuple[bytes, str]],
    expected_root: bytes,
) -> bool:
    """Verify an Export Merkle v1 inclusion proof."""
    if not isinstance(raw_line_bytes, bytes):
        raise TypeError("raw_line_bytes must be bytes")

    if not isinstance(expected_root, bytes):
        raise TypeError("expected_root must be bytes")

    if len(expected_root) != 32:
        raise ValueError("expected_root must be 32 bytes")

    if not isinstance(proof, list):
        raise TypeError("proof must be a list")

    current = export_leaf_hash(raw_line_bytes)

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


def build_commitment_artifact(
    raw_lines: list[bytes],
    room: str,
    counts: dict[str, int],
    anomaly_indices: list[int],
    export_generation: int | None = None,
) -> dict:
    """Build a machine-readable Export Commitment v1 artifact."""
    artifact = {
        "version": 1,
        "profile": "tc-ledger/1",
        "room": room,
        "line_count": len(raw_lines),
        "byte_count": sum(len(line) for line in raw_lines),
        "file_sha256": hashlib.sha256(b"".join(raw_lines)).hexdigest(),
        "export_root": export_merkle_root(raw_lines).hex(),
        "verification": {
            "VALID": counts["VALID"],
            "INVALID": counts["INVALID"],
            "UNSIGNED": counts["UNSIGNED"],
            "MALFORMED": counts["MALFORMED"],
            "UNSUPPORTED_KEY": counts["UNSUPPORTED_KEY"],
        },
        "anomaly_indices": list(anomaly_indices),
    }
    if export_generation is not None:
        if not isinstance(export_generation, int) or isinstance(export_generation, bool):
            raise TypeError("export_generation must be an integer")
        if export_generation < 0:
            raise ValueError("export_generation must be non-negative")
        artifact["export_generation"] = export_generation
    return artifact


def classify_export_lines(
    raw_lines: list[bytes],
    room: str,
) -> tuple[dict[str, int], list[int]]:
    """Classify captured export lines and return anomaly indices.

    Blank physical lines are skipped and are not anomalies.
    UNSIGNED records are classified but are not anomalies.
    INVALID, MALFORMED, and UNSUPPORTED_KEY records are anomalies.
    """
    counts = {
        "VALID": 0,
        "INVALID": 0,
        "UNSIGNED": 0,
        "MALFORMED": 0,
        "UNSUPPORTED_KEY": 0,
    }
    anomaly_indices: list[int] = []

    for index, raw_line in enumerate(raw_lines):
        if not raw_line.strip():
            continue

        try:
            line = raw_line.decode("utf-8")
            result = _classify_export_line(line, room)
            counts[result.status] += 1

        except UnsupportedKeyType:
            counts["UNSUPPORTED_KEY"] += 1
            anomaly_indices.append(index)

        except InvalidSignature:
            counts["INVALID"] += 1
            anomaly_indices.append(index)

        except (UnicodeDecodeError, json.JSONDecodeError, VerificationError):
            counts["MALFORMED"] += 1
            anomaly_indices.append(index)

    return counts, anomaly_indices


def write_commitment_artifact(
    path: str,
    artifact: dict,
) -> None:
    """Write a deterministic JSON commitment artifact."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(
            artifact,
            handle,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        handle.write("\n")


def verify_commitment_artifact(
    export_target,
    artifact_target,
    expected_root: str | bytes | None = None,
    expected_room: str | None = None,
    expected_generation: int | None = None,
) -> bool:
    """Verify and re-derive an Export Commitment v1 artifact against raw export bytes.

    Accepts either file paths (str / Path) or loaded data structures (dict, list[bytes]).
    """
    raw_lines = None
    artifact = None

    # Handle backwards-compatible argument ordering (artifact: dict, raw_lines: list)
    if isinstance(export_target, dict) and isinstance(artifact_target, list):
        artifact = export_target
        raw_lines = artifact_target
    elif isinstance(export_target, list) and isinstance(artifact_target, dict):
        raw_lines = export_target
        artifact = artifact_target
    else:
        # Resolve export_target
        if isinstance(export_target, (str, Path)):
            try:
                with open(export_target, "rb") as f:
                    raw_lines = f.readlines()
            except OSError:
                return False
        elif isinstance(export_target, list):
            raw_lines = export_target

        # Resolve artifact_target
        if isinstance(artifact_target, (str, Path)):
            try:
                with open(artifact_target, "r", encoding="utf-8") as f:
                    artifact = json.load(f)
            except (OSError, json.JSONDecodeError):
                return False
        elif isinstance(artifact_target, dict):
            artifact = artifact_target

    if not isinstance(artifact, dict) or not isinstance(raw_lines, list):
        return False

    if artifact.get("version") != 1:
        return False

    if artifact.get("profile") != "tc-ledger/1":
        return False

    room = artifact.get("room")
    if not isinstance(room, str) or not room:
        return False

    if expected_room is not None and room != expected_room:
        return False

    artifact_generation = artifact.get("export_generation", artifact.get("generation"))
    if artifact_generation is not None:
        if not isinstance(artifact_generation, int) or isinstance(artifact_generation, bool):
            return False
        if artifact_generation < 0:
            return False

    if expected_generation is not None:
        if not isinstance(expected_generation, int) or isinstance(expected_generation, bool):
            return False
        if artifact_generation != expected_generation:
            return False

    if artifact.get("line_count") != len(raw_lines):
        return False

    if artifact.get("byte_count") != sum(len(line) for line in raw_lines):
        return False

    file_sha256 = hashlib.sha256(b"".join(raw_lines)).hexdigest()
    if artifact.get("file_sha256") != file_sha256:
        return False

    export_root = export_merkle_root(raw_lines).hex()
    if artifact.get("export_root", "").lower() != export_root.lower():
        return False

    if expected_root is not None:
        root_str = expected_root.hex() if isinstance(expected_root, bytes) else str(expected_root)
        if export_root.lower() != root_str.lower():
            return False

    counts, anomaly_indices = classify_export_lines(raw_lines, room)

    verification = artifact.get("verification")
    if not isinstance(verification, dict):
        return False

    for key in ("VALID", "INVALID", "UNSIGNED", "MALFORMED", "UNSUPPORTED_KEY"):
        if verification.get(key) != counts.get(key, 0):
            return False

    if artifact.get("anomaly_indices") != list(anomaly_indices):
        return False

    return True


def expected_proof_directions(tree_size: int, leaf_index: int) -> list[str]:
    """Compute expected audit path directions for a leaf in a Merkle tree."""
    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        raise TypeError("tree_size must be an integer")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise TypeError("leaf_index must be an integer")

    if tree_size < 1:
        raise ValueError("tree_size must be positive")
    if leaf_index < 0 or leaf_index >= tree_size:
        raise IndexError("leaf_index outside tree bounds")

    directions = []
    current_index = leaf_index
    level_size = tree_size

    while level_size > 1:
        if current_index % 2 == 0:
            if current_index + 1 < level_size:
                directions.append("right")
        else:
            directions.append("left")

        current_index //= 2
        level_size = (level_size + 1) // 2

    return directions


def build_inclusion_proof_artifact(
    raw_lines: list[bytes],
    room: str,
    index: int,
    export_generation: int = 0,
) -> dict:
    """Build an Export Inclusion Proof v1 artifact."""
    if not isinstance(raw_lines, list):
        raise TypeError("raw_lines must be a list")

    if not isinstance(room, str):
        raise TypeError("room must be a string")

    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("index must be an integer")

    if not isinstance(export_generation, int) or isinstance(export_generation, bool):
        raise TypeError("export_generation must be an integer")

    if export_generation < 0:
        raise ValueError("export_generation must be non-negative")

    if index < 0 or index >= len(raw_lines):
        raise IndexError("index outside export line list")

    proof = export_merkle_proof(raw_lines, index)

    return {
        "schema": "tc-ledger/inclusion-proof/v1",
        "version": 1,
        "profile": "tc-ledger/1",
        "room": room,
        "export_generation": export_generation,
        "leaf_index": index,
        "tree_size": len(raw_lines),
        "leaf_hash": export_leaf_hash(raw_lines[index]).hex(),
        "export_root": export_merkle_root(raw_lines).hex(),
        "audit_path": [
            {
                "position": position,
                "sibling_hash": sibling.hex(),
            }
            for sibling, position in proof
        ],
    }


def verify_export_inclusion_proof(
    raw_line_bytes: bytes | str,
    artifact: dict,
    expected_root: bytes | str | None = None,
    expected_generation: int | None = None,
    expected_room: str | None = None,
) -> bool:
    """Independently verify an Export Inclusion Proof v1 artifact from record bytes.

    Does not require server state or the full export file.
    """
    if isinstance(raw_line_bytes, str):
        raw_line_bytes = raw_line_bytes.encode("utf-8")

    if not isinstance(raw_line_bytes, (bytes, bytearray)):
        return False

    if not isinstance(artifact, dict):
        return False

    if artifact.get("version") != 1:
        return False

    if artifact.get("profile") != "tc-ledger/1":
        return False

    room = artifact.get("room")
    if not isinstance(room, str) or not room:
        return False

    if expected_room is not None and room != expected_room:
        return False

    leaf_index = artifact.get("leaf_index")
    tree_size = artifact.get("tree_size")
    artifact_generation = artifact.get("export_generation")

    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        return False

    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        return False

    if tree_size < 1 or leaf_index < 0 or leaf_index >= tree_size:
        return False

    if artifact_generation is not None:
        if not isinstance(artifact_generation, int) or isinstance(artifact_generation, bool):
            return False
        if artifact_generation < 0:
            return False

    if expected_generation is not None:
        if not isinstance(expected_generation, int) or isinstance(expected_generation, bool):
            return False
        if artifact_generation != expected_generation:
            return False

    leaf_hash_hex = artifact.get("leaf_hash")
    export_root_hex = artifact.get("export_root")
    audit_path = artifact.get("audit_path")

    if not isinstance(leaf_hash_hex, str) or not isinstance(export_root_hex, str):
        return False

    if not isinstance(audit_path, list):
        return False

    try:
        artifact_leaf_hash = bytes.fromhex(leaf_hash_hex)
        artifact_root = bytes.fromhex(export_root_hex)
    except (ValueError, TypeError):
        return False

    if len(artifact_leaf_hash) != 32 or len(artifact_root) != 32:
        return False

    # Verify actual leaf hash matches artifact leaf hash
    actual_leaf_hash = export_leaf_hash(raw_line_bytes)
    if actual_leaf_hash != artifact_leaf_hash:
        return False

    # Verify audit_path directions and length match expected tree shape
    try:
        expected_dirs = expected_proof_directions(tree_size, leaf_index)
    except (IndexError, ValueError):
        return False

    if len(audit_path) != len(expected_dirs):
        return False

    proof: list[tuple[bytes, str]] = []
    for item, expected_dir in zip(audit_path, expected_dirs):
        if not isinstance(item, dict):
            return False

        position = item.get("position")
        sibling_hash_hex = item.get("sibling_hash")

        if position != expected_dir:
            return False

        if not isinstance(sibling_hash_hex, str):
            return False

        try:
            sibling_hash = bytes.fromhex(sibling_hash_hex)
        except (ValueError, TypeError):
            return False

        if len(sibling_hash) != 32:
            return False

        proof.append((sibling_hash, position))

    if not verify_export_merkle_proof(
        raw_line_bytes,
        proof,
        artifact_root,
    ):
        return False

    if expected_root is not None:
        if isinstance(expected_root, str):
            try:
                expected_root_bytes = bytes.fromhex(expected_root)
            except (ValueError, TypeError):
                return False
        elif isinstance(expected_root, bytes):
            expected_root_bytes = expected_root
        else:
            return False

        if len(expected_root_bytes) != 32:
            return False

        if artifact_root != expected_root_bytes:
            return False

    return True


def verify_inclusion_proof_artifact(
    proof_target,
    export_target=None,
    expected_root: str | bytes | None = None,
    expected_room: str | None = None,
    expected_generation: int | None = None,
) -> bool:
    """Verify an Export Inclusion Proof v1 artifact against an export file or path.

    Accepts either file paths (str / Path) or loaded data structures.
    """
    artifact = None
    raw_lines = None

    if isinstance(proof_target, (str, Path)):
        try:
            with open(proof_target, "r", encoding="utf-8") as f:
                artifact = json.load(f)
        except (OSError, json.JSONDecodeError):
            return False
    elif isinstance(proof_target, dict):
        artifact = proof_target

    if export_target is not None:
        if isinstance(export_target, (str, Path)):
            try:
                with open(export_target, "rb") as f:
                    raw_lines = f.readlines()
            except OSError:
                return False
        elif isinstance(export_target, list):
            raw_lines = export_target

    if not isinstance(artifact, dict):
        return False

    if raw_lines is None:
        return False

    if not isinstance(raw_lines, list):
        return False

    tree_size = artifact.get("tree_size")
    leaf_index = artifact.get("leaf_index")

    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        return False

    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        return False

    if tree_size != len(raw_lines):
        return False

    if leaf_index < 0 or leaf_index >= len(raw_lines):
        return False

    if not verify_export_inclusion_proof(
        raw_lines[leaf_index],
        artifact,
        expected_root=expected_root,
        expected_generation=expected_generation,
        expected_room=expected_room,
    ):
        return False

    try:
        calculated_root = export_merkle_root(raw_lines)
        art_root = bytes.fromhex(artifact.get("export_root", ""))
    except (ValueError, TypeError):
        return False

    if calculated_root != art_root:
        return False

    if expected_root is not None:
        expected_bytes = bytes.fromhex(expected_root) if isinstance(expected_root, str) else expected_root
        if calculated_root != expected_bytes:
            return False

    return True

def write_inclusion_proof_artifact(
    path: str,
    artifact: dict,
) -> None:
    """Write a deterministic Export Inclusion Proof v1 artifact."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(
            artifact,
            handle,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        handle.write("\n")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify signed records from a Technocore room export."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output machine-readable JSON",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify",
        help="verify a JSONL Technocore export",
    )
    verify_parser.add_argument("path")
    verify_parser.add_argument("--room", required=True)
    verify_parser.add_argument("--json", action="store_true", help="output machine-readable JSON")

    commit_parser = subparsers.add_parser(
        "commit",
        help="commit a JSONL Technocore export",
    )
    commit_parser.add_argument("path")
    commit_parser.add_argument("--room", required=True)
    commit_parser.add_argument(
        "--generation",
        "--export-generation",
        dest="export_generation",
        type=int,
        default=None,
        help="expected room conversation epoch / generation",
    )
    commit_parser.add_argument("--output")
    commit_parser.add_argument("--json", action="store_true", help="output machine-readable JSON")

    vectors_parser = subparsers.add_parser(
        "vectors",
        help="validate frozen v1 test vectors",
    )
    vectors_parser.add_argument("--json", action="store_true", help="output machine-readable JSON")

    prove_parser = subparsers.add_parser(
        "prove",
        help="generate an Export Inclusion Proof v1 artifact",
    )
    prove_parser.add_argument("path")
    prove_parser.add_argument("--room", required=True)
    prove_parser.add_argument("--leaf-index", required=True, type=int)
    prove_parser.add_argument(
        "--generation",
        "--export-generation",
        dest="export_generation",
        type=int,
        default=0,
    )
    prove_parser.add_argument("--output")
    prove_parser.add_argument("--json", action="store_true", help="output machine-readable JSON")

    verify_proof_parser = subparsers.add_parser(
        "verify-proof",
        help="verify an Export Inclusion Proof v1 artifact",
    )
    verify_proof_parser.add_argument("path")
    verify_proof_parser.add_argument("--export")
    verify_proof_parser.add_argument("--record")
    verify_proof_parser.add_argument("--expected-root")
    verify_proof_parser.add_argument("--expected-generation", type=int)
    verify_proof_parser.add_argument("--expected-room")
    verify_proof_parser.add_argument("--json", action="store_true", help="output machine-readable JSON")

    verify_artifact_parser = subparsers.add_parser(
        "verify-artifact",
        help="verify and re-derive an Export Commitment v1 artifact against raw export bytes",
    )
    verify_artifact_parser.add_argument("export", help="path to raw export file")
    verify_artifact_parser.add_argument("artifact", help="path to commitment artifact JSON")
    verify_artifact_parser.add_argument("--expected-root", help="expected export Merkle root")
    verify_artifact_parser.add_argument("--expected-room", help="expected room identifier")
    verify_artifact_parser.add_argument("--expected-generation", type=int, help="expected export generation")
    verify_artifact_parser.add_argument("--json", action="store_true", help="output machine-readable JSON")

    verify_commit_parser = subparsers.add_parser(
        "verify-commitment",
        help="alias for verify-artifact",
    )
    verify_commit_parser.add_argument("export", help="path to raw export file")
    verify_commit_parser.add_argument("artifact", help="path to commitment artifact JSON")
    verify_commit_parser.add_argument("--expected-root", help="expected export Merkle root")
    verify_commit_parser.add_argument("--expected-room", help="expected room identifier")
    verify_commit_parser.add_argument("--expected-generation", type=int, help="expected export generation")
    verify_commit_parser.add_argument("--json", action="store_true", help="output machine-readable JSON")

    args = parser.parse_args()
    is_json = getattr(args, "json", False)

    if args.command == "vectors":
        vectors_path = (
            Path(__file__).resolve().parents[2]
            / "vectors"
            / "vectors.json"
        )

        if not vectors_path.is_file():
            print(f"Vectors not found: {vectors_path}", file=sys.stderr)
            return 3

        try:
            document = json.loads(
                vectors_path.read_text(encoding="utf-8")
            )

            if document["version"] != 1:
                raise ValueError("unsupported vector version")

            if document["profile"] != "tc-ledger/1":
                raise ValueError("unsupported vector profile")

            # Merkle vectors.
            for vector in document["merkle"]["trivial"]:
                lines = [
                    base64.b64decode(value)
                    for value in vector["leaves_b64"]
                ]

                if [
                    export_leaf_hash(line).hex()
                    for line in lines
                ] != vector["leaf_hashes"]:
                    raise ValueError(
                        f"leaf vector mismatch for n={vector['n']}"
                    )

                if export_merkle_root(lines).hex() != vector["root"]:
                    raise ValueError(
                        f"root vector mismatch for n={vector['n']}"
                    )

            # Byte-model vectors.
            for vector in document["byte_model"]:
                data = base64.b64decode(vector["data_b64"])
                leaves = [] if not data else [data]

                if [
                    base64.b64encode(line).decode("ascii")
                    for line in leaves
                ] != vector["leaves_b64"]:
                    raise ValueError(
                        f"byte-model leaf mismatch: {vector['name']}"
                    )

                if [
                    export_leaf_hash(line).hex()
                    for line in leaves
                ] != vector["leaf_hashes"]:
                    raise ValueError(
                        f"byte-model hash mismatch: {vector['name']}"
                    )

                if export_merkle_root(leaves).hex() != vector["root"]:
                    raise ValueError(
                        f"byte-model root mismatch: {vector['name']}"
                    )

            # Synthetic export vectors.
            synthetic = document["synthetic_export"]
            synthetic_lines = [
                base64.b64decode(item["bytes_b64"])
                for item in synthetic["lines"]
            ]

            if [
                len(line)
                for line in synthetic_lines
            ] != [
                item["byte_length"]
                for item in synthetic["lines"]
            ]:
                raise ValueError("synthetic byte-length mismatch")

            if [
                export_leaf_hash(line).hex()
                for line in synthetic_lines
            ] != [
                item["leaf_hash"]
                for item in synthetic["lines"]
            ]:
                raise ValueError("synthetic leaf-hash mismatch")

            if export_merkle_root(synthetic_lines).hex() != synthetic["root"]:
                raise ValueError("synthetic root mismatch")

            if is_json:
                print(json.dumps({
                    "command": "vectors",
                    "profile": "tc-ledger/1",
                    "status": "OK",
                    "valid": True,
                }, indent=2, sort_keys=True))
            else:
                print("C3 vectors: OK")
            return 0

        except (
            KeyError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
            UnicodeError,
        ) as exc:
            print(f"C3 vectors: FAIL: {exc}", file=sys.stderr)
            return 1 if "mismatch" in str(exc) else 3

    if args.command == "prove":
        try:
            with open(args.path, "rb") as f:
                raw_lines = f.readlines()
        except OSError as exc:
            print(f"PROVE: FAIL: {exc}", file=sys.stderr)
            return 3

        try:
            artifact = build_inclusion_proof_artifact(
                raw_lines,
                args.room,
                args.leaf_index,
                export_generation=args.export_generation,
            )
        except (ValueError, TypeError, IndexError) as exc:
            print(f"PROVE: FAIL: {exc}", file=sys.stderr)
            return 3

        if args.output:
            try:
                write_inclusion_proof_artifact(args.output, artifact)
            except OSError as exc:
                print(f"PROVE: FAIL: {exc}", file=sys.stderr)
                return 3

            if is_json:
                print(
                    json.dumps({
                        "command": "prove",
                        "valid": True,
                        "room": args.room,
                        "leaf_index": args.leaf_index,
                        "export_generation": args.export_generation,
                        "output": args.output,
                        "artifact": artifact,
                    }, indent=2, sort_keys=True)
                )
            else:
                print(f"Inclusion proof artifact: {args.output}")
        else:
            print(
                json.dumps(
                    artifact,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )

        return 0

    if args.command == "commit":
        try:
            with open(args.path, "rb") as f:
                raw_lines = f.readlines()
            index = map_evidence_to_export(raw_lines, args.room)
            counts = verify_export(args.path, args.room)
            _, anomaly_indices = classify_export_lines(raw_lines, args.room)
        except OSError as exc:
            print(f"COMMIT: FAIL: {exc}", file=sys.stderr)
            return 3
        except Exception as exc:
            print(f"COMMIT: FAIL: {exc}", file=sys.stderr)
            return 3

        is_valid = not (counts["INVALID"] or counts["MALFORMED"])

        artifact = None
        if args.output or is_json:
            try:
                artifact = build_commitment_artifact(
                    raw_lines,
                    args.room,
                    counts,
                    anomaly_indices,
                    export_generation=args.export_generation,
                )
            except Exception as exc:
                print(f"COMMIT: FAIL: {exc}", file=sys.stderr)
                return 3

        if args.output and artifact is not None:
            try:
                write_commitment_artifact(args.output, artifact)
            except OSError as exc:
                print(f"COMMIT: FAIL: {exc}", file=sys.stderr)
                return 3

        if is_json:
            out_obj = {
                "command": "commit",
                "room": args.room,
                "valid": is_valid,
                "line_count": len(raw_lines),
                "export_root": index.export_root.hex(),
                "verification": counts,
                "anomaly_indices": anomaly_indices,
            }
            if args.export_generation is not None:
                out_obj["export_generation"] = args.export_generation
            if args.output:
                out_obj["output"] = args.output
            if artifact is not None:
                out_obj["artifact"] = artifact
            print(json.dumps(out_obj, indent=2, sort_keys=True))
        else:
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
            if args.output:
                print(f"Commitment artifact: {args.output}")

        return 0 if is_valid else 1

    if args.command == "verify-proof":
        if not args.record and not args.export:
            print("Error: either --record or --export must be provided", file=sys.stderr)
            return 2

        try:
            artifact = json.loads(
                Path(args.path).read_text(encoding="utf-8")
            )

            if args.record:
                record_bytes = Path(args.record).read_bytes()
                valid = verify_export_inclusion_proof(
                    record_bytes,
                    artifact,
                    expected_root=args.expected_root,
                    expected_generation=args.expected_generation,
                    expected_room=args.expected_room,
                )
            else:
                with open(args.export, "rb") as f:
                    raw_lines = f.readlines()

                valid = verify_inclusion_proof_artifact(
                    artifact,
                    raw_lines,
                    expected_generation=args.expected_generation,
                    expected_room=args.expected_room,
                )
                if valid and args.expected_root:
                    if artifact.get("export_root", "").lower() != args.expected_root.lower():
                        valid = False

        except (
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            print(f"VERIFY-PROOF: FAIL: {exc}", file=sys.stderr)
            return 3

        if is_json:
            print(json.dumps({
                "command": "verify-proof",
                "valid": bool(valid),
            }, indent=2, sort_keys=True))
        else:
            if valid:
                print("VERIFY-PROOF: VALID")
            else:
                print("VERIFY-PROOF: INVALID", file=sys.stderr)

        return 0 if valid else 1

    if args.command in ("verify-artifact", "verify-commitment"):
        label = "VERIFY-ARTIFACT" if args.command == "verify-artifact" else "VERIFY-COMMITMENT"
        try:
            valid = verify_commitment_artifact(
                args.export,
                args.artifact,
                expected_root=args.expected_root,
                expected_room=args.expected_room,
                expected_generation=args.expected_generation,
            )
        except Exception as exc:
            print(f"{label}: FAIL: {exc}", file=sys.stderr)
            return 3

        if is_json:
            print(json.dumps({
                "command": args.command,
                "valid": bool(valid),
            }, indent=2, sort_keys=True))
        else:
            if valid:
                print(f"{label}: VALID")
            else:
                print(f"{label}: INVALID", file=sys.stderr)

        return 0 if valid else 1

    if args.command == "verify":
        try:
            with open(args.path, "rb") as f:
                raw_lines = f.readlines()
            counts = verify_export(args.path, args.room)
            _, anomaly_indices = classify_export_lines(raw_lines, args.room)
        except OSError as exc:
            print(f"VERIFY: FAIL: {exc}", file=sys.stderr)
            return 3
        except Exception as exc:
            print(f"VERIFY: FAIL: {exc}", file=sys.stderr)
            return 3

        is_valid = not (counts["INVALID"] or counts["MALFORMED"])

        if is_json:
            print(json.dumps({
                "command": "verify",
                "room": args.room,
                "valid": is_valid,
                "line_count": len(raw_lines),
                "verification": counts,
                "anomaly_indices": anomaly_indices,
            }, indent=2, sort_keys=True))
        else:
            print(f"Room: {args.room}")
            print(f"Valid signatures: {counts['VALID']}")
            print(f"Invalid signatures: {counts['INVALID']}")
            print(f"Unsigned records: {counts['UNSIGNED']}")
            print(f"Malformed records: {counts['MALFORMED']}")
            print(f"Unsupported key types: {counts['UNSUPPORTED_KEY']}")

        return 0 if is_valid else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

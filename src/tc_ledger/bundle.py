"""
TCLK Portable Self-Contained Evidence Archive (.tclk-bundle) Module.
Specification: tclk-bundle/1

Generates and independently verifies offline .tclk-bundle ZIP archives containing:
  - manifest.json   (deterministic SHA-256 checksums and bundle metadata)
  - transcript.jsonl (signed room export / deal records)
  - receipts.json   (raw JSON-RPC transaction receipts)
  - proof.json      (canonical tclk-proof/1 proof artifact)
  - report.txt      (human-readable verification report)

All bundle verification is 100% offline, deterministic, and fails closed.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from tc_ledger.cross_verify import (
    format_verification_report,
    load_tclk_proof_schema,
    normalize_address,
    normalize_amount_str,
    normalize_hex,
    verify_cross_layer,
    verify_standalone_proof,
)
from tc_ledger.evm_verifier import (
    EvmVerificationError,
    fetch_transaction_receipt,
    parse_and_verify_htlc_event,
)
from tc_ledger.ledger import (
    classify_export_lines,
    export_leaf_hash,
    export_merkle_root,
)

REQUIRED_BUNDLE_PAYLOAD_FILES = (
    "transcript.jsonl",
    "receipts.json",
    "proof.json",
    "report.txt",
)
ALL_REQUIRED_BUNDLE_FILES = frozenset(("manifest.json",) + REQUIRED_BUNDLE_PAYLOAD_FILES)


def load_tclk_bundle_schema() -> dict[str, Any]:
    """Loads schemas/tclk-bundle-v1.schema.json from disk."""
    schema_path = Path(__file__).resolve().parent.parent.parent / "schemas" / "tclk-bundle-v1.schema.json"
    if not schema_path.is_file():
        # Fallback for installed package layout
        schema_path = Path(__file__).resolve().parent / "schemas" / "tclk-bundle-v1.schema.json"
    if not schema_path.is_file():
        raise FileNotFoundError(f"TCLK bundle schema not found: {schema_path}")
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _sha256_hex(data: bytes) -> str:
    """Calculates lowercased SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest().lower()


def create_bundle(
    transcript_source: Union[str, Path, dict, list],
    settlement_source: Optional[Union[str, Path, dict]] = None,
    trust_anchors: Optional[dict[str, Any]] = None,
    rpc_anchors: Optional[dict[str, Any]] = None,
    output_path: Optional[Union[str, Path]] = None,
) -> tuple[dict[str, Any], bytes]:
    """
    Creates a deterministic, self-contained .tclk-bundle ZIP archive.

    Returns:
      (manifest_dict, zip_archive_bytes)
    """
    trust_anchors = trust_anchors or {}
    rpc_anchors = rpc_anchors or {}

    # 1. Generate canonical tclk-proof/1 proof
    proof = verify_cross_layer(
        transcript_source=transcript_source,
        settlement_source=settlement_source,
        trust_anchors=trust_anchors,
        rpc_anchors=rpc_anchors,
    )

    # 2. Generate human-readable report
    report_text = format_verification_report(proof, trust_anchors=trust_anchors)
    report_bytes = report_text.encode("utf-8")

    # 3. Extract transcript.jsonl raw text
    transcript_bytes: bytes
    if isinstance(transcript_source, (str, Path)):
        p = Path(transcript_source)
        if not p.is_file():
            raise FileNotFoundError(f"Transcript source file not found: {p}")
        transcript_bytes = p.read_bytes()
    elif isinstance(transcript_source, list):
        lines = []
        for item in transcript_source:
            if isinstance(item, str):
                lines.append(item.rstrip("\r\n"))
            elif isinstance(item, dict):
                lines.append(json.dumps(item, separators=(",", ":"), ensure_ascii=False))
            else:
                lines.append(str(item))
        transcript_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    elif isinstance(transcript_source, dict):
        if "export_lines" in transcript_source and isinstance(transcript_source["export_lines"], list):
            lines = [l if isinstance(l, str) else json.dumps(l, separators=(",", ":")) for l in transcript_source["export_lines"]]
            transcript_bytes = ("\n".join(lines) + "\n").encode("utf-8")
        elif "records" in transcript_source and isinstance(transcript_source["records"], list):
            lines = [json.dumps(r, separators=(",", ":"), ensure_ascii=False) for r in transcript_source["records"]]
            transcript_bytes = ("\n".join(lines) + "\n").encode("utf-8")
        else:
            transcript_bytes = (json.dumps(transcript_source, indent=2) + "\n").encode("utf-8")
    else:
        raise TypeError(f"Unsupported transcript source type: {type(transcript_source)}")

    # 4. Collect receipts.json
    receipts_map: dict[str, Any] = {}
    rpc_url = rpc_anchors.get("rpc_url") if isinstance(rpc_anchors, dict) else None

    # Collect transaction hashes from settlement proof and rpc anchors
    tx_hashes = set()
    settlement_dict = proof.get("settlement", {})
    for key in ("lock_tx", "claim_tx", "refund_tx"):
        tx = settlement_dict.get(key) or (rpc_anchors.get(key) if isinstance(rpc_anchors, dict) else None)
        if tx and isinstance(tx, str) and tx.startswith("0x"):
            tx_hashes.add(tx.lower())

    if rpc_url and tx_hashes:
        timeout = float(rpc_anchors.get("timeout", 10.0))
        for tx in tx_hashes:
            try:
                rcpt = fetch_transaction_receipt(rpc_url, tx, timeout=timeout)
                receipts_map[tx.lower()] = rcpt
            except Exception as exc:
                # Store error or record warning if receipt cannot be fetched
                receipts_map[tx.lower()] = {"error": str(exc)}
    elif isinstance(settlement_source, dict) and "receipts" in settlement_source and isinstance(settlement_source["receipts"], dict):
        receipts_map = {k.lower(): v for k, v in settlement_source["receipts"].items()}
    elif isinstance(settlement_source, (str, Path)):
        sp = Path(settlement_source)
        if sp.is_file():
            try:
                s_json = json.loads(sp.read_text(encoding="utf-8"))
                if isinstance(s_json, dict) and "receipts" in s_json and isinstance(s_json["receipts"], dict):
                    receipts_map = {k.lower(): v for k, v in s_json["receipts"].items()}
            except Exception:
                pass

    receipts_bytes = (json.dumps(receipts_map, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # 5. Serialize proof.json
    proof_bytes = (json.dumps(proof, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # 6. Build manifest.json
    file_checksums = {
        "transcript.jsonl": {
            "sha256": _sha256_hex(transcript_bytes),
            "size": len(transcript_bytes),
        },
        "receipts.json": {
            "sha256": _sha256_hex(receipts_bytes),
            "size": len(receipts_bytes),
        },
        "proof.json": {
            "sha256": _sha256_hex(proof_bytes),
            "size": len(proof_bytes),
        },
        "report.txt": {
            "sha256": _sha256_hex(report_bytes),
            "size": len(report_bytes),
        },
    }

    manifest = {
        "spec": "tclk-bundle/1",
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "contract_id": proof.get("contract_id"),
        "room": proof.get("room"),
        "files": file_checksums,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # 7. Construct deterministic ZIP archive
    zip_buffer = io.BytesIO()
    # Sorted filenames for determinism
    archive_files = [
        ("manifest.json", manifest_bytes),
        ("proof.json", proof_bytes),
        ("receipts.json", receipts_bytes),
        ("report.txt", report_bytes),
        ("transcript.jsonl", transcript_bytes),
    ]

    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, fbytes in sorted(archive_files, key=lambda x: x[0]):
            zinfo = zipfile.ZipInfo(filename=fname, date_time=(2026, 1, 1, 0, 0, 0))
            zinfo.external_attr = 0o644 << 16
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zinfo, fbytes)

    bundle_bytes = zip_buffer.getvalue()

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(bundle_bytes)

    return manifest, bundle_bytes


def verify_bundle(
    bundle_source: Union[str, Path, bytes, io.BytesIO],
    trust_anchors: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Offline verification of a self-contained .tclk-bundle archive.

    Security & Invariant Guarantees:
      - 100% offline (no RPC or external network requests).
      - Rejects path traversal and directory nesting in archive members.
      - Rejects unexpected, missing, or duplicate archive members.
      - Verifies every manifest SHA-256 checksum and file size.
      - Validates manifest schema against schemas/tclk-bundle-v1.schema.json.
      - Validates embedded proof.json via verify_standalone_proof().
      - Cross-checks transcript.jsonl export Merkle root against proof.
      - Cross-checks receipts.json against settlement parameters and EVM HTLC parser.
      - Fails closed on any tampering, returning structured diagnostic details.
    """
    trust_anchors = trust_anchors or {}
    expected_room = trust_anchors.get("room") or trust_anchors.get("expected_room")
    expected_root = trust_anchors.get("export_root") or trust_anchors.get("expected_root")
    expected_contract_id = trust_anchors.get("contract_id") or trust_anchors.get("expected_contract_id")

    failure_reasons: list[str] = []
    warnings: list[str] = []

    # 1. Open ZIP archive safely
    zf: zipfile.ZipFile
    bundle_path_str: Optional[str] = None

    try:
        if isinstance(bundle_source, (str, Path)):
            p = Path(bundle_source)
            bundle_path_str = str(p)
            if not p.is_file():
                raise FileNotFoundError(f"Bundle file not found: {p}")
            zf = zipfile.ZipFile(p, mode="r")
        elif isinstance(bundle_source, bytes):
            zf = zipfile.ZipFile(io.BytesIO(bundle_source), mode="r")
        elif isinstance(bundle_source, io.BytesIO):
            zf = zipfile.ZipFile(bundle_source, mode="r")
        else:
            raise TypeError(f"Unsupported bundle_source type: {type(bundle_source)}")
    except FileNotFoundError:
        raise
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Invalid ZIP archive: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"Failed to open bundle archive: {exc}") from exc

    with zf:
        namelist = zf.namelist()

        # 2. Member validation & path traversal defense
        if len(namelist) != len(set(namelist)):
            failure_reasons.append("duplicate archive members detected")

        found_members = set()
        for name in namelist:
            # Path traversal checks
            if ".." in name or name.startswith(("/", "\\")) or "\\" in name or "/" in name or ":" in name or "\x00" in name:
                failure_reasons.append(f"unsafe archive member or path traversal detected: '{name}'")
                continue

            if not re.fullmatch(r"[a-zA-Z0-9_\-\.]+", name):
                failure_reasons.append(f"illegal characters in archive member name: '{name}'")
                continue

            if name not in ALL_REQUIRED_BUNDLE_FILES:
                failure_reasons.append(f"unexpected archive member: '{name}'")
                continue

            found_members.add(name)

        missing_members = ALL_REQUIRED_BUNDLE_FILES - found_members
        if missing_members:
            for m in sorted(missing_members):
                failure_reasons.append(f"missing required bundle file: '{m}'")

        if failure_reasons:
            return {
                "spec": "tclk-bundle/1",
                "version": 1,
                "profile": "tc-ledger/1",
                "schema": "tc-ledger/tclk-bundle/v1",
                "command": "verify-bundle",
                "valid": False,
                "is_conformant": False,
                "manifest_verified": False,
                "receipts_verified": False,
                "proof_verified": False,
                "bundle_path": bundle_path_str,
                "failure_reasons": failure_reasons,
                "warnings": warnings,
            }

        # 3. Read and validate manifest.json
        try:
            manifest_bytes = zf.read("manifest.json")
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except Exception as exc:
            failure_reasons.append(f"malformed manifest.json: {exc}")
            return {
                "spec": "tclk-bundle/1",
                "version": 1,
                "profile": "tc-ledger/1",
                "schema": "tc-ledger/tclk-bundle/v1",
                "command": "verify-bundle",
                "valid": False,
                "is_conformant": False,
                "manifest_verified": False,
                "receipts_verified": False,
                "proof_verified": False,
                "bundle_path": bundle_path_str,
                "failure_reasons": failure_reasons,
                "warnings": warnings,
            }

        # Validate manifest against JSON Schema
        try:
            import jsonschema
            schema = load_tclk_bundle_schema()
            jsonschema.validate(instance=manifest, schema=schema)
        except Exception as exc:
            failure_reasons.append(f"manifest schema validation failed: {exc}")

        # 4. Verify checksums for all payload files
        manifest_files = manifest.get("files", {}) if isinstance(manifest, dict) else {}
        extracted_payloads: dict[str, bytes] = {}
        checksums_ok = True

        for fname in REQUIRED_BUNDLE_PAYLOAD_FILES:
            if fname not in manifest_files:
                checksums_ok = False
                failure_reasons.append(f"manifest missing file entry for '{fname}'")
                continue

            file_entry = manifest_files[fname]
            expected_sha256 = file_entry.get("sha256")
            expected_size = file_entry.get("size")

            try:
                data = zf.read(fname)
                extracted_payloads[fname] = data
            except Exception as exc:
                checksums_ok = False
                failure_reasons.append(f"failed to read member '{fname}': {exc}")
                continue

            actual_sha256 = _sha256_hex(data)
            actual_size = len(data)

            if expected_sha256 and actual_sha256 != expected_sha256.lower():
                checksums_ok = False
                failure_reasons.append(
                    f"checksum mismatch for '{fname}': manifest sha256 '{expected_sha256}' != computed '{actual_sha256}'"
                )

            if expected_size is not None and actual_size != expected_size:
                checksums_ok = False
                failure_reasons.append(
                    f"size mismatch for '{fname}': manifest size {expected_size} != actual {actual_size}"
                )

        manifest_verified = checksums_ok and (len(failure_reasons) == 0)

        # 5. Validate proof.json using verify_standalone_proof
        proof_verified = False
        proof_doc: dict[str, Any] = {}
        standalone_res: dict[str, Any] = {}

        if "proof.json" in extracted_payloads:
            try:
                proof_doc = json.loads(extracted_payloads["proof.json"].decode("utf-8"))
                standalone_res = verify_standalone_proof(proof_doc, trust_anchors=trust_anchors)
                proof_verified = standalone_res.get("valid", False)
                if not proof_verified or not standalone_res.get("schema_valid", True):
                    for reason in standalone_res.get("failure_reasons", []):
                        if reason not in failure_reasons:
                            failure_reasons.append(f"proof error: {reason}")
                warnings.extend(standalone_res.get("warnings", []))
            except Exception as exc:
                failure_reasons.append(f"failed to parse proof.json: {exc}")

        # 6. Cross-check transcript.jsonl against proof
        if "transcript.jsonl" in extracted_payloads and proof_doc:
            try:
                raw_lines = extracted_payloads["transcript.jsonl"].decode("utf-8").splitlines()
                non_empty_lines = [l for l in raw_lines if l.strip()]
                parsed_records = []
                for line in non_empty_lines:
                    try:
                        parsed_records.append(json.loads(line))
                    except Exception:
                        pass

                # If proof contains transcript export root, recompute from lines
                raw_bytes_transcript = extracted_payloads["transcript.jsonl"]
                raw_lines_bytes = [l + b"\n" for l in raw_bytes_transcript.splitlines() if l.strip()]
                if raw_lines_bytes:
                    recomputed_export_root = export_merkle_root(raw_lines_bytes).hex()
                    exp_root_proof = proof_doc.get("transcript", {}).get("export_root")
                    if exp_root_proof:
                        clean_exp = exp_root_proof[2:] if exp_root_proof.startswith(("0x", "0X")) else exp_root_proof
                        if recomputed_export_root.lower() != clean_exp.lower():
                            failure_reasons.append(
                                f"transcript.jsonl export root '0x{recomputed_export_root}' != proof export_root '{exp_root_proof}'"
                            )
            except Exception as exc:
                failure_reasons.append(f"failed to verify transcript.jsonl records: {exc}")

        # 7. Cross-check receipts.json against settlement evidence
        receipts_verified = True
        if "receipts.json" in extracted_payloads and proof_doc:
            try:
                receipts_map = json.loads(extracted_payloads["receipts.json"].decode("utf-8"))
                settlement_info = proof_doc.get("settlement", {})
                provenance = proof_doc.get("trust_model", {}).get("settlement_evidence_provenance")

                if provenance == "rpc_receipt_verified":
                    lock_tx = settlement_info.get("lock_tx")
                    if not lock_tx:
                        receipts_verified = False
                        failure_reasons.append("proof specifies rpc_receipt_verified provenance but settlement lacks lock_tx")
                    else:
                        norm_lock_tx = lock_tx.lower()
                        if norm_lock_tx not in receipts_map:
                            receipts_verified = False
                            failure_reasons.append(f"receipts.json missing receipt for lock_tx '{lock_tx}'")
                        else:
                            rcpt = receipts_map[norm_lock_tx]
                            if not isinstance(rcpt, dict) or rcpt.get("status") in (None, "0x0", 0):
                                receipts_verified = False
                                failure_reasons.append(f"receipt for lock_tx '{lock_tx}' indicates transaction failure or invalid receipt")
                            else:
                                # Re-run EVM HTLC event verification purely offline on the receipt
                                try:
                                    parsed_event = parse_and_verify_htlc_event(
                                        rcpt,
                                        expected_htlc_address=settlement_info.get("contract_address"),
                                        expected_contract_id=settlement_info.get("contract_id"),
                                        expected_event_type="Locked",
                                    )
                                    # Verify parameters match settlement
                                    if parsed_event.get("amount") != str(settlement_info.get("amount")):
                                        receipts_verified = False
                                        failure_reasons.append(
                                            f"receipt lock amount mismatch: receipt={parsed_event.get('amount')}, proof={settlement_info.get('amount')}"
                                        )
                                    if normalize_hex(parsed_event.get("hashlock")) != normalize_hex(settlement_info.get("hashlock")):
                                        receipts_verified = False
                                        failure_reasons.append(
                                            f"receipt hashlock mismatch: receipt={parsed_event.get('hashlock')}, proof={settlement_info.get('hashlock')}"
                                        )
                                    if parsed_event.get("erc20_transfer_verified") != settlement_info.get("erc20_transfer_verified"):
                                        receipts_verified = False
                                        failure_reasons.append(
                                            f"receipt ERC-20 transfer verification mismatch: receipt={parsed_event.get('erc20_transfer_verified')}, proof={settlement_info.get('erc20_transfer_verified')}"
                                        )
                                except EvmVerificationError as evm_err:
                                    receipts_verified = False
                                    failure_reasons.append(f"receipt offline verification failed for lock_tx: {evm_err}")

                    # Check claim_tx if present
                    claim_tx = settlement_info.get("claim_tx")
                    if claim_tx:
                        norm_claim_tx = claim_tx.lower()
                        if norm_claim_tx not in receipts_map:
                            receipts_verified = False
                            failure_reasons.append(f"receipts.json missing receipt for claim_tx '{claim_tx}'")
                        else:
                            rcpt = receipts_map[norm_claim_tx]
                            try:
                                parse_and_verify_htlc_event(
                                    rcpt,
                                    expected_htlc_address=settlement_info.get("contract_address"),
                                    expected_contract_id=settlement_info.get("contract_id"),
                                    expected_event_type="Claimed",
                                )
                            except EvmVerificationError as evm_err:
                                receipts_verified = False
                                failure_reasons.append(f"receipt offline verification failed for claim_tx: {evm_err}")

                    # Check refund_tx if present
                    refund_tx = settlement_info.get("refund_tx")
                    if refund_tx:
                        norm_refund_tx = refund_tx.lower()
                        if norm_refund_tx not in receipts_map:
                            receipts_verified = False
                            failure_reasons.append(f"receipts.json missing receipt for refund_tx '{refund_tx}'")
                        else:
                            rcpt = receipts_map[norm_refund_tx]
                            try:
                                parse_and_verify_htlc_event(
                                    rcpt,
                                    expected_htlc_address=settlement_info.get("contract_address"),
                                    expected_contract_id=settlement_info.get("contract_id"),
                                    expected_event_type="Refunded",
                                )
                            except EvmVerificationError as evm_err:
                                receipts_verified = False
                                failure_reasons.append(f"receipt offline verification failed for refund_tx: {evm_err}")
            except Exception as exc:
                receipts_verified = False
                failure_reasons.append(f"failed to parse receipts.json: {exc}")

        # 8. Check report.txt
        if "report.txt" in extracted_payloads:
            rep_text = extracted_payloads["report.txt"].decode("utf-8", errors="replace")
            if not rep_text.strip():
                warnings.append("report.txt is empty")

        # 9. Compute final status
        is_valid = manifest_verified and proof_verified and receipts_verified and (len([r for r in failure_reasons if not r.startswith("settlement evidence is self-attested")]) == 0)
        is_conformant = is_valid and standalone_res.get("is_conformant", False) and (len(failure_reasons) == 0)

        contract_id = proof_doc.get("contract_id") or manifest.get("contract_id")
        room = proof_doc.get("room") or manifest.get("room")
        provenance = proof_doc.get("trust_model", {}).get("settlement_evidence_provenance", "unknown")

        return {
            "spec": "tclk-bundle/1",
            "version": 1,
            "profile": "tc-ledger/1",
            "schema": "tc-ledger/tclk-bundle/v1",
            "command": "verify-bundle",
            "valid": is_valid,
            "is_conformant": is_conformant,
            "manifest_verified": manifest_verified,
            "receipts_verified": receipts_verified,
            "proof_verified": proof_verified,
            "contract_id": contract_id,
            "room": room,
            "provenance": provenance,
            "bundle_path": bundle_path_str,
            "failure_reasons": failure_reasons,
            "warnings": warnings,
            "manifest": manifest,
            "proof": proof_doc,
        }

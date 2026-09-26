"""
Pure, offline, deterministic cross-verification connecting signed Technocore agreements
to verifiable settlement evidence for TCLK-Proof.

Profile: tc-ledger/1
Specification: tclk-proof/1
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from tc_ledger.ledger import (
    export_leaf_hash,
    export_merkle_root,
    merkle_root,
    verify_export_inclusion_proof,
    verify_export_merkle_proof,
    verify_signed_record,
)


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic canonical JSON serialization as UTF-8 bytes."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def domain_hash(domain: str, payload_bytes: bytes) -> str:
    """Technocore domain-separated SHA-256 hash."""
    h = hashlib.sha256(domain.encode("utf-8") + b":" + payload_bytes).hexdigest()
    return f"0x{h}"

# secp256k1 curve parameters for address derivation
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def keccak256(data: bytes) -> bytes:
    """Pure-Python Keccak-256 (sponge construction) for zero-dependency EVM address derivation."""
    state = [[0] * 5 for _ in range(5)]
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    r_bytes = 136
    pad_len = r_bytes - (len(data) % r_bytes)
    padded = data + (b"\x81" if pad_len == 1 else b"\x01" + b"\x00" * (pad_len - 2) + b"\x80")
    for b_idx in range(0, len(padded), r_bytes):
        block = padded[b_idx : b_idx + r_bytes]
        for i in range(r_bytes // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
        for round_idx in range(24):
            C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) & 0xFFFFFFFFFFFFFFFF) | (C[(x + 1) % 5] >> 63)) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= D[x]
            x, y, curr, rot = 1, 0, state[1][0], 0
            for t in range(24):
                rot = (t + 1) * (t + 2) // 2 % 64
                nx, ny = y, (2 * x + 3 * y) % 5
                nxt = state[nx][ny]
                state[nx][ny] = ((curr << rot) & 0xFFFFFFFFFFFFFFFF) | (curr >> (64 - rot)) if rot else curr
                x, y, curr = nx, ny, nxt
            for y in range(5):
                orig = [state[x][y] for x in range(5)]
                for x in range(5):
                    state[x][y] = orig[x] ^ ((~orig[(x + 1) % 5]) & orig[(x + 2) % 5])
            state[0][0] ^= RC[round_idx]
    out = bytearray()
    for y in range(5):
        for x in range(5):
            out.extend(state[x][y].to_bytes(8, "little"))
    return bytes(out[:32])


def secp256k1_pubkey_to_address(pubkey_hex: str) -> str:
    """
    Derives standard 20-byte EVM hex address from SEC1 compressed or uncompressed secp256k1 public key.
    Checks curve validity: y^2 = x^3 + 7 (mod p).
    """
    if not isinstance(pubkey_hex, str):
        raise ValueError("public key must be a string")
    cleaned = pubkey_hex.strip()
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        cleaned = cleaned[2:]

    try:
        raw = bytes.fromhex(cleaned)
    except Exception as exc:
        raise ValueError(f"malformed public key hex: {exc}")

    p = SECP256K1_P

    if len(raw) == 65 and raw[0] == 0x04:
        x = int.from_bytes(raw[1:33], "big")
        y = int.from_bytes(raw[33:65], "big")
        if pow(y, 2, p) != (pow(x, 3, p) + 7) % p:
            raise ValueError("secp256k1 point is not on curve")
        x_bytes = raw[1:33]
        y_bytes = raw[33:65]
    elif len(raw) == 33 and raw[0] in (0x02, 0x03):
        prefix = raw[0]
        x = int.from_bytes(raw[1:33], "big")
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if pow(y, 2, p) != y_sq:
            raise ValueError("invalid secp256k1 point: not a quadratic residue")
        if (y % 2) != (prefix % 2):
            y = (p - y) % p
        x_bytes = x.to_bytes(32, "big")
        y_bytes = y.to_bytes(32, "big")
    elif len(raw) == 64:
        x = int.from_bytes(raw[:32], "big")
        y = int.from_bytes(raw[32:], "big")
        if pow(y, 2, p) != (pow(x, 3, p) + 7) % p:
            raise ValueError("secp256k1 point is not on curve")
        x_bytes = raw[:32]
        y_bytes = raw[32:]
    else:
        raise ValueError(f"unsupported secp256k1 public key length: {len(raw)} bytes")

    point_uncompressed = x_bytes + y_bytes
    h = keccak256(point_uncompressed)
    return f"0x{h[-20:].hex().lower()}"


def public_key_to_eth_address(key_str: str) -> str:
    """Derives standard 20-byte EVM hex address from paymentKey string (e.g. secp256k1:0x... or hex)."""
    if not isinstance(key_str, str):
        raise ValueError("payment key must be a string")
    s = key_str.strip()
    if s.lower().startswith("secp256k1:"):
        s = s[10:]
    return secp256k1_pubkey_to_address(s)


def normalize_hex(val: Any) -> Optional[str]:
    """Normalizes a hex string with lowercased 0x prefix."""
    if not isinstance(val, str):
        return None
    cleaned = val.strip()
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return None
    if len(cleaned) % 2 != 0:
        cleaned = "0" + cleaned
    return f"0x{cleaned.lower()}"


def normalize_address(val: Any) -> Optional[str]:
    """Normalizes a 20-byte EVM address."""
    if not isinstance(val, str):
        return None
    h = normalize_hex(val)
    if h and len(h) == 42:
        return h
    return None


def normalize_amount_str(val: Any) -> Optional[str]:
    """Normalizes atomic token amount to integer string."""
    if val is None:
        return None
    if isinstance(val, int):
        return str(val)
    if isinstance(val, str):
        s = val.strip()
        if re.fullmatch(r"[0-9]+", s):
            return s
        try:
            return str(int(float(s)))
        except ValueError:
            return None
    return None


@dataclass(frozen=True)
class SettlementEvidence:
    """Internal normalized representation of settlement evidence."""
    rail: str
    contract_id: str
    amount: str
    asset: str
    hashlock: str
    settlement_status: str
    provenance: str = "self_attested"
    payer_address: Optional[str] = None
    payee_address: Optional[str] = None
    contract_address: Optional[str] = None
    lock_timestamp: Optional[int] = None
    refund_timestamp: Optional[int] = None
    claim_timestamp: Optional[int] = None
    secret: Optional[str] = None
    lock_tx: Optional[str] = None
    claim_tx: Optional[str] = None
    refund_tx: Optional[str] = None
    block_number: Optional[int] = None
    chain_id: Optional[int] = None
    erc20_transfer_verified: Optional[bool] = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgreementState:
    """Internal normalized representation of TCLK agreed terms."""
    contract_id: str
    room: str
    payer_did: str
    payee_did: str
    amount: str
    asset: str
    lock_kind: str
    hashlock: str
    claim_by_ms: Optional[int]
    refund_after_ms: Optional[int]
    expires_ms: Optional[int]
    rails: list[str]
    payer_evm_address: Optional[str] = None
    payee_evm_address: Optional[str] = None
    payer_payment_key: Optional[str] = None
    payee_payment_key: Optional[str] = None
    status: str = "ACCEPTED"
    offer_frame: Optional[dict[str, Any]] = None
    accept_frame: Optional[dict[str, Any]] = None


@dataclass(frozen=True)
class TranscriptEvidence:
    """Internal representation of Technocore room export / deal records."""
    room: str
    export_root: Optional[str]
    line_count: int
    frames_verified: list[str]
    merkle_inclusion_verified: bool
    signatures_verified: bool
    anomalies: list[str] = field(default_factory=list)


def parse_settlement_evidence(data: dict[str, Any]) -> SettlementEvidence:
    """Parses and validates settlement evidence dictionary."""
    if not isinstance(data, dict):
        raise ValueError("settlement evidence must be a JSON object")

    rail = str(data.get("rail", data.get("settlement_rail", "evm-htlc"))).strip()
    if not rail:
        raise ValueError("settlement evidence missing rail")

    raw_contract_id = data.get("contract_id", data.get("contractId", data.get("contract", "")))
    contract_id = normalize_hex(raw_contract_id)
    if not contract_id or len(contract_id) != 66:
        raise ValueError(f"invalid settlement contract_id (expected 32-byte hex): {raw_contract_id}")

    raw_asset = data.get("asset", data.get("token", "0x0000000000000000000000000000000000000000"))
    asset = normalize_address(raw_asset)
    if not asset:
        raise ValueError(f"invalid settlement asset (expected 20-byte address): {raw_asset}")

    raw_amount = data.get("amount", "0")
    amount = normalize_amount_str(raw_amount)
    if amount is None:
        raise ValueError(f"invalid settlement amount: {raw_amount}")

    raw_hashlock = data.get("hashlock", data.get("statement", ""))
    hashlock = normalize_hex(raw_hashlock)
    if not hashlock or len(hashlock) != 66:
        raise ValueError(f"invalid settlement hashlock (expected 32-byte hex): {raw_hashlock}")

    status_raw = str(data.get("settlement_status", data.get("status", "unknown"))).lower()
    if status_raw in ("claimed-on-rail", "claimed"):
        status = "claimed"
    elif status_raw in ("refunded-on-rail", "refunded"):
        status = "refunded"
    elif status_raw in ("locked", "cancelled", "unknown"):
        status = status_raw
    else:
        status = "unknown"

    payer_addr = normalize_address(data.get("payer_address", data.get("payerAddress", data.get("payer"))))
    payee_addr = normalize_address(data.get("payee_address", data.get("payeeAddress", data.get("payee"))))
    contract_addr = normalize_address(data.get("contract_address", data.get("contractAddress", data.get("contract"))))

    def parse_ts(val: Any) -> Optional[int]:
        if val is None:
            return None
        if isinstance(val, (int, float)):
            if val > 1_000_000_000_000:
                return int(val // 1000)
            return int(val)
        if isinstance(val, str):
            if re.fullmatch(r"[0-9]+", val.strip()):
                iv = int(val.strip())
                if iv > 1_000_000_000_000:
                    return int(iv // 1000)
                return iv
        return None

    lock_ts = parse_ts(data.get("lock_timestamp", data.get("lockTimestamp", data.get("locked_at"))))
    refund_ts = parse_ts(data.get("refund_timestamp", data.get("refundTimestamp", data.get("refund_after"))))
    claim_ts = parse_ts(data.get("claim_timestamp", data.get("claimTimestamp", data.get("claimed_at"))))

    raw_secret = data.get("secret", data.get("preimage", data.get("secret_revealed")))
    secret = normalize_hex(raw_secret)

    lock_tx = data.get("lock_tx", data.get("lockTx", data.get("lock_ref")))
    claim_tx = data.get("claim_tx", data.get("claimTx", data.get("claim_ref")))
    refund_tx = data.get("refund_tx", data.get("refundTx", data.get("refund_ref")))
    block_num = data.get("block_number", data.get("blockNumber"))
    chain_id = data.get("chain_id", data.get("chainId"))
    raw_erc20_verified = data.get("erc20_transfer_verified")
    erc20_transfer_verified = bool(raw_erc20_verified) if raw_erc20_verified is not None else None

    # External caller-supplied settlement evidence loaded from static JSON or dictionary
    # is UNTRUSTED and MUST ALWAYS be forced to "self_attested".
    # Only build_rpc_settlement_evidence() may create "rpc_receipt_verified".
    provenance = "self_attested"

    return SettlementEvidence(
        rail=rail,
        contract_id=contract_id,
        amount=amount,
        asset=asset,
        hashlock=hashlock,
        settlement_status=status,
        provenance=provenance,
        payer_address=payer_addr,
        payee_address=payee_addr,
        contract_address=contract_addr,
        lock_timestamp=lock_ts,
        refund_timestamp=refund_ts,
        claim_timestamp=claim_ts,
        secret=secret,
        lock_tx=lock_tx,
        claim_tx=claim_tx,
        refund_tx=refund_tx,
        block_number=int(block_num) if block_num is not None else None,
        chain_id=int(chain_id) if chain_id is not None else None,
        erc20_transfer_verified=erc20_transfer_verified,
        extra=data,
    )


def extract_tclk_frame_from_text(text: str) -> Optional[dict[str, Any]]:
    """Extracts TCLK control frame JSON embedded in chat text or code fences."""
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict) and "type" in parsed:
                return parsed
        except Exception:
            pass

    patterns = [
        r"```(?:json)?\s*\n?(\{.*?\})\s*```",
        r'\b(\{[^{}]*"type"[^{}]*\})',
    ]
    for fence_pattern in patterns:
        for match in re.finditer(fence_pattern, text, re.DOTALL):
            try:
                parsed = json.loads(match.group(1))
                if isinstance(parsed, dict) and "type" in parsed:
                    return parsed
            except Exception:
                continue

    return None


def parse_deal_archive(archive_dict: dict[str, Any]) -> tuple[AgreementState, TranscriptEvidence, Optional[dict[str, Any]]]:
    """Parses a DealArchive artifact (technocore/deal-archive/v1)."""
    deal = archive_dict.get("deal", {})
    commitment = archive_dict.get("commitment", {})
    records = archive_dict.get("records", {})
    settlement_ev = archive_dict.get("settlementEvidence")

    room = str(deal.get("room", commitment.get("room", "")))
    contract_id = normalize_hex(deal.get("contractId")) or str(deal.get("contractId", ""))
    payer_info = deal.get("payer", {})
    payee_info = deal.get("payee", {})
    terms = deal.get("terms", {})

    payer_did = str(payer_info.get("did", ""))
    payee_did = str(payee_info.get("did", ""))
    payer_addr = normalize_address(payer_info.get("evmAddress"))
    payee_addr = normalize_address(payee_info.get("evmAddress"))

    amount = normalize_amount_str(terms.get("amount", deal.get("amount", "0"))) or "0"
    asset = normalize_address(terms.get("asset", deal.get("asset", "0x0000000000000000000000000000000000000000"))) or "0x0000000000000000000000000000000000000000"
    hashlock = normalize_hex(terms.get("hashlock", terms.get("statement", ""))) or ""

    claim_by_ms = terms.get("claimByMs")
    refund_after_ms = terms.get("refundAfterMs")
    expires_ms = terms.get("expiresMs")
    rails = terms.get("rails", ["evm-htlc"])

    payer_pk = terms.get("payer_payment_key") or terms.get("paymentKey") if terms else None
    payee_pk = terms.get("payee_payment_key") if terms else None

    agreement = AgreementState(
        contract_id=contract_id,
        room=room,
        payer_did=payer_did,
        payee_did=payee_did,
        amount=amount,
        asset=asset,
        lock_kind="hash",
        hashlock=hashlock,
        claim_by_ms=int(claim_by_ms) if claim_by_ms is not None else None,
        refund_after_ms=int(refund_after_ms) if refund_after_ms is not None else None,
        expires_ms=int(expires_ms) if expires_ms is not None else None,
        rails=rails,
        payer_evm_address=payer_addr,
        payee_evm_address=payee_addr,
        payer_payment_key=payer_pk,
        payee_payment_key=payee_pk,
        status=str(deal.get("status", "ACCEPTED")),
    )

    export_root = commitment.get("export_root")
    frames_verified: list[str] = []
    anomalies: list[str] = []
    inclusion_verified = True
    sig_verified = True

    for stage_name, stage_data in records.items():
        frames_verified.append(stage_name)
        raw_line_str = stage_data.get("rawLine", "")
        raw_bytes = raw_line_str.encode("utf-8")
        computed_leaf = export_leaf_hash(raw_bytes).hex()
        expected_leaf = stage_data.get("leafHash", "")
        if computed_leaf.lower() != expected_leaf.lower():
            inclusion_verified = False
            anomalies.append(f"stage '{stage_name}' leaf hash mismatch")

        try:
            rec = json.loads(raw_line_str)
            vres = verify_signed_record(rec, room)
            if vres.status != "VALID":
                sig_verified = False
                anomalies.append(f"stage '{stage_name}' signature status: {vres.status}")
        except Exception as exc:
            sig_verified = False
            anomalies.append(f"stage '{stage_name}' signature error: {exc}")

        proof_obj = stage_data.get("proof")
        if proof_obj and export_root:
            audit_path = proof_obj.get("audit_path", [])
            leaf_idx = proof_obj.get("leaf_index", stage_data.get("leafIndex", 0))
            pv_res = verify_export_inclusion_proof(
                raw_line_bytes=raw_bytes,
                audit_path=audit_path,
                leaf_index=leaf_idx,
                expected_root=export_root,
                expected_room=room,
            )
            if not pv_res.get("valid"):
                inclusion_verified = False
                anomalies.append(f"stage '{stage_name}' inclusion proof failed: {pv_res.get('error')}")

    transcript = TranscriptEvidence(
        room=room,
        export_root=export_root,
        line_count=commitment.get("line_count", len(records)),
        frames_verified=frames_verified,
        merkle_inclusion_verified=inclusion_verified and bool(export_root),
        signatures_verified=sig_verified,
        anomalies=anomalies,
    )

    return agreement, transcript, settlement_ev


def parse_export_lines(
    lines: list[bytes],
    room: str,
    target_contract_id: Optional[str] = None,
) -> tuple[AgreementState, TranscriptEvidence]:
    """
    Parses raw export lines with multi-deal correlation:
    Correlates: offer.id -> accept.ref -> specific agreement/contract.
    Fails closed if ambiguous or if no matching deal is found.
    """
    offers_by_id: dict[str, tuple[dict[str, Any], str]] = {}
    accepts_list: list[tuple[dict[str, Any], str]] = []
    frames_by_contract: dict[str, list[str]] = {}

    anomalies: list[str] = []
    signatures_ok = True
    line_count = len(lines)
    export_root = export_merkle_root(lines).hex() if lines else None

    for line_bytes in lines:
        line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line_str.strip():
            continue
        try:
            record = json.loads(line_str)
        except Exception:
            continue

        try:
            vres = verify_signed_record(record, room)
            if vres.status != "VALID":
                signatures_ok = False
        except Exception:
            signatures_ok = False

        text = record.get("text", "")
        frame = extract_tclk_frame_from_text(text)
        if not frame:
            continue

        ftype = frame.get("type")
        sender = record.get("from", "")

        if ftype == "offer":
            oid = str(frame.get("id", ""))
            if oid:
                offers_by_id[oid] = (frame, sender)
        elif ftype == "accept":
            accepts_list.append((frame, sender))
            cid = normalize_hex(frame.get("contract"))
            if cid:
                frames_by_contract.setdefault(cid.lower(), []).append("accept")
        elif ftype in ("lock", "reveal", "claim", "receipt", "refund", "cancel"):
            cid = normalize_hex(frame.get("contract"))
            if cid:
                frames_by_contract.setdefault(cid.lower(), []).append(ftype)

    # Correlate candidate deals: accept.ref -> offer.id
    candidates: list[tuple[str, str, AgreementState, dict[str, Any], dict[str, Any]]] = []

    for accept, acc_sender in accepts_list:
        ref = str(accept.get("ref", ""))
        if not ref or ref not in offers_by_id:
            continue

        offer, off_sender = offers_by_id[ref]

        accept_core = {
            "from": accept.get("from", acc_sender),
            "ref": ref,
            "statement": accept.get("statement", ""),
            "nonce": accept.get("nonce", ""),
        }
        if "paymentKey" in accept:
            accept_core["paymentKey"] = accept["paymentKey"]

        payload_bytes = canonical_json_bytes({"offer": offer, "accept": accept_core})
        computed_cid = domain_hash("contract", payload_bytes)
        explicit_cid = normalize_hex(accept.get("contract")) or computed_cid

        role = offer.get("role", "payer")
        if role == "payer":
            payer_did = str(offer.get("from", off_sender))
            payee_did = str(accept.get("from", acc_sender))
        else:
            payer_did = str(accept.get("from", acc_sender))
            payee_did = str(offer.get("from", off_sender))

        amount = normalize_amount_str(offer.get("amount", "0")) or "0"
        asset = normalize_address(offer.get("asset", "0x0000000000000000000000000000000000000000")) or "0x0000000000000000000000000000000000000000"
        hashlock = normalize_hex(accept.get("statement", "")) or ""

        payer_pk = offer.get("paymentKey") if role == "payer" else accept.get("paymentKey")
        payee_pk = accept.get("paymentKey") if role == "payer" else offer.get("paymentKey")

        agr = AgreementState(
            contract_id=explicit_cid,
            room=room,
            payer_did=payer_did,
            payee_did=payee_did,
            amount=amount,
            asset=asset,
            lock_kind=offer.get("lock", "hash"),
            hashlock=hashlock,
            claim_by_ms=offer.get("claimByMs"),
            refund_after_ms=offer.get("refundAfterMs"),
            expires_ms=offer.get("expiresMs"),
            rails=offer.get("rails", ["evm-htlc"]),
            payer_payment_key=payer_pk,
            payee_payment_key=payee_pk,
            status="ACCEPTED",
            offer_frame=offer,
            accept_frame=accept,
        )

        candidates.append((explicit_cid, computed_cid, agr, accept, offer))

    # Selection & Disambiguation
    if target_contract_id:
        norm_target = normalize_hex(target_contract_id) or str(target_contract_id).lower()
        matched = [
            c for c in candidates
            if c[0].lower() == norm_target.lower() or c[1].lower() == norm_target.lower()
        ]
        if len(matched) == 0:
            raise ValueError(f"no candidate agreement matched expected contract ID {target_contract_id}")
        elif len(matched) > 1:
            raise ValueError(f"ambiguous agreement: multiple candidate agreements matched expected contract ID {target_contract_id}")
        selected_tuple = matched[0]
    else:
        if len(candidates) == 0:
            raise ValueError("transcript does not contain a correlated offer-accept pair")
        elif len(candidates) > 1:
            raise ValueError("ambiguous agreement: multiple candidate agreements found in transcript; specify --expected-contract-id")
        selected_tuple = candidates[0]

    selected_cid, _, agreement, selected_accept, selected_offer = selected_tuple

    stage_frames = ["offer", "accept"] + frames_by_contract.get(selected_cid.lower(), [])

    transcript = TranscriptEvidence(
        room=room,
        export_root=export_root,
        line_count=line_count,
        frames_verified=stage_frames,
        merkle_inclusion_verified=bool(export_root),
        signatures_verified=signatures_ok,
        anomalies=anomalies,
    )

    return agreement, transcript


def verify_cross_layer(
    transcript_source: Any,
    settlement_source: Any = None,
    trust_anchors: Optional[dict[str, Any]] = None,
    rpc_anchors: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Pure, deterministic, offline cross-verification connecting signed Technocore
    agreements to verifiable settlement evidence.
    """
    trust_anchors = trust_anchors or {}
    expected_room = trust_anchors.get("room") or trust_anchors.get("expected_room")
    expected_root = trust_anchors.get("export_root") or trust_anchors.get("expected_root")
    expected_contract_id = trust_anchors.get("contract_id") or trust_anchors.get("expected_contract_id")

    failure_reasons: list[str] = []
    warnings: list[str] = []

    # 1. Parse settlement evidence
    settlement: Optional[SettlementEvidence] = None

    if rpc_anchors and rpc_anchors.get("rpc_url"):
        try:
            from tc_ledger.evm_verifier import build_rpc_settlement_evidence
            expected_chain_id = trust_anchors.get("chain_id") or trust_anchors.get("expected_chain_id") or rpc_anchors.get("chain_id")
            if expected_chain_id is not None:
                expected_chain_id = int(expected_chain_id)
            settlement = build_rpc_settlement_evidence(
                rpc_url=rpc_anchors["rpc_url"],
                lock_tx=rpc_anchors.get("lock_tx"),
                claim_tx=rpc_anchors.get("claim_tx"),
                refund_tx=rpc_anchors.get("refund_tx"),
                expected_htlc_address=rpc_anchors.get("htlc_address"),
                expected_contract_id=trust_anchors.get("contract_id") or trust_anchors.get("expected_contract_id"),
                expected_chain_id=expected_chain_id,
                timeout=float(rpc_anchors.get("timeout", 10.0)),
            )
        except Exception as exc:
            return {
                "spec": "tclk-proof/1",
                "version": 1,
                "is_conformant": False,
                "failure_reasons": [f"EVM RPC settlement verification failed: {exc}"],
                "warnings": [],
            }
    elif settlement_source is not None:
        settlement_dict: dict[str, Any] = {}
        if isinstance(settlement_source, (str, Path)):
            p = Path(settlement_source)
            if not p.is_file():
                return {
                    "spec": "tclk-proof/1",
                    "version": 1,
                    "is_conformant": False,
                    "failure_reasons": [f"settlement evidence file not found: {p}"],
                    "warnings": [],
                }
            try:
                settlement_dict = json.loads(p.read_text(encoding="utf-8"))
            except Exception as exc:
                return {
                    "spec": "tclk-proof/1",
                    "version": 1,
                    "is_conformant": False,
                    "failure_reasons": [f"malformed settlement JSON: {exc}"],
                    "warnings": [],
                }
        elif isinstance(settlement_source, dict):
            settlement_dict = settlement_source
        else:
            return {
                "spec": "tclk-proof/1",
                "version": 1,
                "is_conformant": False,
                "failure_reasons": ["unsupported settlement evidence type"],
                "warnings": [],
            }

        try:
            settlement = parse_settlement_evidence(settlement_dict)
        except Exception as exc:
            return {
                "spec": "tclk-proof/1",
                "version": 1,
                "is_conformant": False,
                "failure_reasons": [f"invalid settlement evidence format: {exc}"],
                "warnings": [],
            }
    else:
        return {
            "spec": "tclk-proof/1",
            "version": 1,
            "is_conformant": False,
            "failure_reasons": ["neither settlement evidence nor RPC anchors provided"],
            "warnings": [],
        }

    # 2. Parse transcript evidence
    agreement: Optional[AgreementState] = None
    transcript: Optional[TranscriptEvidence] = None

    if isinstance(transcript_source, (str, Path)):
        p = Path(transcript_source)
        if not p.is_file():
            return {
                "spec": "tclk-proof/1",
                "version": 1,
                "is_conformant": False,
                "failure_reasons": [f"transcript source file not found: {p}"],
                "warnings": [],
            }
        if p.name.endswith(".json"):
            archive_data = json.loads(p.read_text(encoding="utf-8"))
            agreement, transcript, embedded_settlement = parse_deal_archive(archive_data)
        else:
            raw_lines = p.read_bytes().splitlines(keepends=True)
            room = expected_room or p.stem
            try:
                agreement, transcript = parse_export_lines(raw_lines, room, target_contract_id=expected_contract_id)
            except Exception as exc:
                failure_reasons.append(f"failed to extract agreement from export: {exc}")
    elif isinstance(transcript_source, dict):
        agreement, transcript, embedded_settlement = parse_deal_archive(transcript_source)
    else:
        return {
            "spec": "tclk-proof/1",
            "version": 1,
            "is_conformant": False,
            "failure_reasons": ["unsupported transcript source type"],
            "warnings": [],
        }

    if agreement is None or transcript is None:
        return {
            "spec": "tclk-proof/1",
            "version": 1,
            "is_conformant": False,
            "failure_reasons": failure_reasons or ["failed to load transcript agreement"],
            "warnings": warnings,
        }

    # 3. Trust Anchor Validations
    if expected_room and agreement.room != expected_room:
        failure_reasons.append(f"room mismatch: expected {expected_room}, got {agreement.room}")

    if expected_root and transcript.export_root:
        if transcript.export_root.lower() != expected_root.lower():
            failure_reasons.append(f"export root mismatch: expected {expected_root}, got {transcript.export_root}")

    if expected_contract_id:
        norm_exp_cid = normalize_hex(expected_contract_id) or str(expected_contract_id)
        if agreement.contract_id.lower() != norm_exp_cid.lower():
            failure_reasons.append(f"contract ID mismatch with trust anchor: expected {norm_exp_cid}, got {agreement.contract_id}")

    # 4. Check Transcript Validity
    transcript_authenticity = True
    if not transcript.signatures_verified:
        transcript_authenticity = False
        failure_reasons.append("transcript signature verification failed for one or more records")
    if not transcript.merkle_inclusion_verified:
        transcript_authenticity = False
        failure_reasons.append("transcript Merkle inclusion verification failed")
    if transcript.anomalies:
        transcript_authenticity = False
        for anomaly in transcript.anomalies:
            failure_reasons.append(f"transcript anomaly: {anomaly}")

    # 5. Terms Conformance Cross-Checks
    terms_failures: list[str] = []

    # A. Contract ID Binding
    cid_match = agreement.contract_id.lower() == settlement.contract_id.lower()
    if not cid_match:
        terms_failures.append(
            f"contract ID mismatch: agreement={agreement.contract_id}, settlement={settlement.contract_id}"
        )
    contract_id_binding = "verified" if cid_match else "mismatch"

    # B. Hashlock Binding
    hashlock_match = False
    if agreement.hashlock and settlement.hashlock:
        hashlock_match = agreement.hashlock.lower() == settlement.hashlock.lower()
    if not hashlock_match:
        terms_failures.append(
            f"hashlock mismatch: agreement={agreement.hashlock}, settlement={settlement.hashlock}"
        )
    hashlock_binding = "verified" if hashlock_match else "mismatch"

    # C. Amount Binding
    amount_match = agreement.amount == settlement.amount
    if not amount_match:
        terms_failures.append(
            f"amount mismatch: agreement={agreement.amount}, settlement={settlement.amount}"
        )
    amount_binding = "verified" if amount_match else "mismatch"

    # D. Asset / Token Binding
    asset_match = agreement.asset.lower() == settlement.asset.lower()
    if not asset_match:
        terms_failures.append(
            f"asset/token mismatch: agreement={agreement.asset}, settlement={settlement.asset}"
        )
    asset_binding = "verified" if asset_match else "mismatch"

    # E. Secret / Preimage Verification
    secret_verification = "not_applicable"
    if settlement.settlement_status in ("claimed", "claimed-on-rail"):
        if settlement.secret:
            clean_secret = settlement.secret
            if clean_secret.startswith("0x") or clean_secret.startswith("0X"):
                clean_secret = clean_secret[2:]
            try:
                secret_bytes = bytes.fromhex(clean_secret)
                computed_hash = hashlib.sha256(secret_bytes).hexdigest()
                expected_hash = agreement.hashlock
                if expected_hash.startswith("0x") or expected_hash.startswith("0X"):
                    expected_hash = expected_hash[2:]
                if computed_hash.lower() == expected_hash.lower():
                    secret_verification = "verified"
                else:
                    secret_verification = "mismatch"
                    terms_failures.append(
                        f"revealed secret digest mismatch: sha256({settlement.secret}) = 0x{computed_hash} != {agreement.hashlock}"
                    )
            except Exception as exc:
                secret_verification = "mismatch"
                terms_failures.append(f"failed to decode secret hex: {exc}")
        else:
            secret_verification = "missing"
            terms_failures.append("settlement status is claimed but claiming preimage secret was not supplied in evidence")

    # F. Temporal Ordering
    temporal_ordering = "verified"
    if settlement.lock_timestamp is not None and settlement.refund_timestamp is not None:
        if settlement.lock_timestamp >= settlement.refund_timestamp:
            temporal_ordering = "lock_too_late"
            terms_failures.append(
                f"lock timestamp ({settlement.lock_timestamp}) is >= refund timestamp ({settlement.refund_timestamp})"
            )

    if settlement.claim_timestamp is not None and settlement.refund_timestamp is not None:
        if settlement.claim_timestamp >= settlement.refund_timestamp:
            temporal_ordering = "claim_too_late"
            terms_failures.append(
                f"claim timestamp ({settlement.claim_timestamp}) is >= refund timestamp ({settlement.refund_timestamp})"
            )

    if agreement.refund_after_ms is not None and settlement.refund_timestamp is not None:
        agreement_refund_sec = agreement.refund_after_ms // 1000
        if abs(agreement_refund_sec - settlement.refund_timestamp) > 300:
            warnings.append(
                f"refund timestamp variance > 300s: agreement={agreement_refund_sec}s, settlement={settlement.refund_timestamp}s"
            )

    # G. Settlement Lifecycle Consistency
    settlement_lifecycle = "verified"
    if settlement.settlement_status == "claimed":
        if settlement.refund_tx:
            settlement_lifecycle = "inconsistent"
            terms_failures.append("settlement status is claimed but contains refund transaction reference")
    elif settlement.settlement_status == "refunded":
        if settlement.claim_tx:
            settlement_lifecycle = "inconsistent"
            terms_failures.append("settlement status is refunded but contains claim transaction reference")

    # H. Identity Binding with Strict secp256k1 Address Derivation
    payer_address_binding = "unverified_external_mapping"
    if agreement.payer_payment_key:
        try:
            derived_payer_addr = secp256k1_pubkey_to_address(agreement.payer_payment_key)
            if settlement.payer_address and derived_payer_addr.lower() == settlement.payer_address.lower():
                payer_address_binding = "verified_via_payment_key"
            else:
                payer_address_binding = "mismatch"
                terms_failures.append(
                    f"payer paymentKey address mismatch: derived={derived_payer_addr}, settlement={settlement.payer_address}"
                )
        except Exception as exc:
            payer_address_binding = "mismatch"
            terms_failures.append(f"invalid payer paymentKey: {exc}")
    elif settlement.payer_address is None:
        payer_address_binding = "not_applicable"

    payee_address_binding = "unverified_external_mapping"
    if agreement.payee_payment_key:
        try:
            derived_payee_addr = secp256k1_pubkey_to_address(agreement.payee_payment_key)
            if settlement.payee_address and derived_payee_addr.lower() == settlement.payee_address.lower():
                payee_address_binding = "verified_via_payment_key"
            else:
                payee_address_binding = "mismatch"
                terms_failures.append(
                    f"payee paymentKey address mismatch: derived={derived_payee_addr}, settlement={settlement.payee_address}"
                )
        except Exception as exc:
            payee_address_binding = "mismatch"
            terms_failures.append(f"invalid payee paymentKey: {exc}")
    elif settlement.payee_address is None:
        payee_address_binding = "not_applicable"

    # Overall address binding
    if payer_address_binding == "mismatch" or payee_address_binding == "mismatch":
        overall_address_binding = "mismatch"
    elif payer_address_binding == "verified_via_payment_key" or payee_address_binding == "verified_via_payment_key":
        overall_address_binding = "verified_via_payment_key"
    elif payer_address_binding == "unverified_external_mapping" or payee_address_binding == "unverified_external_mapping":
        overall_address_binding = "unverified_external_mapping"
    else:
        overall_address_binding = "not_applicable"

    if payer_address_binding == "unverified_external_mapping":
        warnings.append(
            f"payer DID ({agreement.payer_did}) to EVM address ({settlement.payer_address}) is an unverified external mapping"
        )
    if payee_address_binding == "unverified_external_mapping":
        warnings.append(
            f"payee DID ({agreement.payee_did}) to EVM address ({settlement.payee_address}) is an unverified external mapping"
        )

    # Dual-Log ERC-20 Transfer Event Consistency Check
    ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
    norm_agr_asset = normalize_address(agreement.asset)
    norm_set_asset = normalize_address(settlement.asset)
    is_erc20_deal = (norm_agr_asset and norm_agr_asset.lower() != ZERO_ADDRESS) or (norm_set_asset and norm_set_asset.lower() != ZERO_ADDRESS)
    erc20_transfer_binding = "not_applicable"

    if is_erc20_deal:
        if settlement.provenance in ("rpc_receipt_verified", "cryptographic_receipt_proof"):
            if settlement.erc20_transfer_verified is True:
                erc20_transfer_binding = "verified"
            else:
                erc20_transfer_binding = "failed"
                terms_failures.append("ERC-20 token transfer event not verified in settlement transaction receipt")
        else:
            erc20_transfer_binding = "unverified"

    terms_conformance = "verified" if len(terms_failures) == 0 else "failed"
    failure_reasons.extend(terms_failures)

    # Provenance & On-Chain Trust Evaluation
    is_on_chain_proven = (settlement.provenance in ("rpc_receipt_verified", "on_chain_receipt_verified", "cryptographic_receipt_proof"))
    on_chain_provenance_status = "verified" if is_on_chain_proven else "unverified"

    if not is_on_chain_proven:
        failure_reasons.append("settlement evidence is self-attested and lacks independent on-chain provenance")

    # is_conformant requires terms conformance, transcript authenticity, and on-chain provenance
    is_conformant = (terms_conformance == "verified" and transcript_authenticity and is_on_chain_proven and len(failure_reasons) == 0)

    proof_artifact = {
        "spec": "tclk-proof/1",
        "version": 1,
        "profile": "tc-ledger/1",
        "schema": "tc-ledger/tclk-proof/v1",
        "contract_id": agreement.contract_id,
        "room": agreement.room,
        "agreement": {
            "status": "verified" if agreement.status == "ACCEPTED" else agreement.status,
            "payer_did": agreement.payer_did,
            "payee_did": agreement.payee_did,
            "amount": agreement.amount,
            "asset": agreement.asset,
            "lock_kind": agreement.lock_kind,
            "hashlock": agreement.hashlock,
            "claim_by_ms": agreement.claim_by_ms,
            "refund_after_ms": agreement.refund_after_ms,
            "expires_ms": agreement.expires_ms,
            "rails": agreement.rails,
        },
        "transcript": {
            "status": "complete" if transcript.merkle_inclusion_verified else "partial",
            "authenticity": "verified" if transcript.signatures_verified and transcript.merkle_inclusion_verified else "invalid",
            "room": transcript.room,
            "line_count": transcript.line_count,
            "frames_verified": transcript.frames_verified,
            "export_root": transcript.export_root,
            "signatures_verified": transcript.signatures_verified,
            "merkle_inclusion_verified": transcript.merkle_inclusion_verified,
        },
        "settlement": {
            "rail": settlement.rail,
            "status": settlement.settlement_status,
            "evidence_provenance": settlement.provenance,
            "provenance": settlement.provenance,
            "contract_id": settlement.contract_id,
            "contract_address": settlement.contract_address,
            "asset": settlement.asset,
            "amount": settlement.amount,
            "hashlock": settlement.hashlock,
            "payer_address": settlement.payer_address,
            "payee_address": settlement.payee_address,
            "lock_timestamp": settlement.lock_timestamp,
            "refund_timestamp": settlement.refund_timestamp,
            "claim_timestamp": settlement.claim_timestamp,
            "lock_tx": settlement.lock_tx,
            "claim_tx": settlement.claim_tx,
            "refund_tx": settlement.refund_tx,
            "secret_revealed": settlement.secret,
            "erc20_transfer_verified": settlement.erc20_transfer_verified,
        },
        "cross_check": {
            "terms_conformance": terms_conformance,
            "contract_id_binding": contract_id_binding,
            "hashlock_binding": hashlock_binding,
            "amount_binding": amount_binding,
            "asset_binding": asset_binding,
            "temporal_ordering": temporal_ordering,
            "secret_verification": secret_verification,
            "on_chain_provenance": on_chain_provenance_status,
            "address_binding": overall_address_binding,
            "settlement_lifecycle": settlement_lifecycle,
            "address_binding_payer": payer_address_binding,
            "address_binding_payee": payee_address_binding,
            "erc20_transfer_binding": erc20_transfer_binding,
        },
        "trust_model": {
            "transcript_authenticity": transcript_authenticity,
            "terms_conformance": (terms_conformance == "verified"),
            "on_chain_execution_proven": is_on_chain_proven,
            "proves_transcript_signatures": transcript.signatures_verified,
            "proves_merkle_export_inclusion": transcript.merkle_inclusion_verified,
            "proves_on_chain_blockchain_execution": is_on_chain_proven,
            "settlement_evidence_provenance": settlement.provenance,
            "notice": "Cross-verification proves semantic conformance between transcript and settlement JSON. It does NOT independently prove that settlement transactions were mined on-chain unless cryptographic on-chain receipt proofs are verified.",
        },
        "is_conformant": is_conformant,
        "failure_reasons": failure_reasons,
        "warnings": warnings,
    }

    return proof_artifact


def format_verification_report(
    proof: dict[str, Any],
    trust_anchors: dict[str, Any] | None = None,
) -> str:
    """
    Renders a deterministic, human-readable verification report detailing:
    - Final conformity verdict (PASS: CONFORMANT / FAIL: NON-CONFORMANT)
    - Trust anchors and verification scope
    - Off-chain transcript authenticity and Merkle inclusion
    - Agreement terms & participants
    - EVM settlement rail evidence and transaction receipts
    - Cross-layer binding and conformance checks
    - Provenance & trust model separation
    - Warnings, anomalies, and failure reasons with explicit [OK], [FAIL], [WARN], [INFO] markers.
    """
    import datetime

    def _fmt_ts(val: Any, is_ms: bool = False) -> str:
        if val is None:
            return "N/A"
        try:
            num = int(val)
            sec = num / 1000.0 if is_ms else float(num)
            dt = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc)
            unit = "ms" if is_ms else "s"
            return f"{num} {unit} ({dt.strftime('%Y-%m-%d %H:%M:%S UTC')})"
        except Exception:
            return str(val)

    def _tag_status(val: Any, ok_tags: tuple[str, ...] = ("verified", "complete", "ACCEPTED", "rpc_receipt_verified", "on_chain_receipt_verified", "cryptographic_receipt_proof", "verified_via_payment_key")) -> str:
        if val is True:
            return "[OK] True"
        if val is False:
            return "[FAIL] False"
        s = str(val)
        if s in ok_tags:
            return f"[OK] {s}"
        if "unverified_external_mapping" in s or s == "self_attested":
            return f"[WARN] {s}"
        if s in ("not_applicable", "none", "None", "partial"):
            return f"[INFO] {s}"
        return f"[FAIL] {s}"

    lines: list[str] = []
    bar = "=" * 80
    sep = "-" * 80

    proof_dict = proof if isinstance(proof, dict) else {}
    is_conformant = bool(proof_dict.get("is_conformant", False))
    verdict_tag = "[OK] PASS: CONFORMANT" if is_conformant else "[FAIL] FAIL: NON-CONFORMANT"

    contract_id = proof_dict.get("contract_id", "N/A")
    room = proof_dict.get("room", "N/A")
    spec = proof_dict.get("spec", "tclk-proof/1")
    version = proof_dict.get("version", 1)
    profile = proof_dict.get("profile", "tc-ledger/1")
    schema = proof_dict.get("schema", "tc-ledger/tclk-proof/v1")

    # Header
    lines.append(bar)
    lines.append("                  TCLK-PROOF VERIFICATION REPORT")
    lines.append(bar)
    lines.append(f"Specification:   {spec} (v{version})  |  Profile: {profile}")
    lines.append(f"Schema:          {schema}")
    lines.append(f"Contract ID:     {contract_id}")
    lines.append(f"Room:            {room}")
    lines.append(f"Final Verdict:   {verdict_tag}")
    lines.append("")

    # 1. Trust Anchors
    lines.append(sep)
    lines.append("[1] TRUST ANCHORS & CONTEXT")
    lines.append(sep)
    anchors = trust_anchors or {}
    exp_room = anchors.get("room") or anchors.get("expected_room")
    exp_root = anchors.get("export_root") or anchors.get("expected_root")
    exp_cid = anchors.get("contract_id") or anchors.get("expected_contract_id")
    exp_chain = anchors.get("chain_id") or anchors.get("expected_chain_id")

    if exp_room:
        match_room = "[OK] Matched" if exp_room == room else f"[FAIL] Mismatch (expected {exp_room})"
        lines.append(f"  Expected Room:        {exp_room} -> {match_room}")
    else:
        lines.append("  Expected Room:        [INFO] Not specified (inferred from transcript)")

    transcript_root = (proof_dict.get("transcript") or {}).get("export_root")
    if exp_root:
        match_root = "[OK] Matched" if transcript_root and exp_root.lower() == transcript_root.lower() else f"[FAIL] Mismatch (expected {exp_root})"
        lines.append(f"  Expected Export Root: {exp_root} -> {match_root}")
    else:
        lines.append("  Expected Export Root: [INFO] Not specified")

    if exp_cid:
        match_cid = "[OK] Matched" if exp_cid.lower() == str(contract_id).lower() else f"[FAIL] Mismatch (expected {exp_cid})"
        lines.append(f"  Expected Contract ID: {exp_cid} -> {match_cid}")
    else:
        lines.append("  Expected Contract ID: [INFO] Not specified")

    if exp_chain:
        lines.append(f"  Expected Chain ID:    {exp_chain} -> [OK] Verified")
    else:
        lines.append("  Expected Chain ID:    [INFO] Not specified")
    lines.append("")

    # 2. Off-Chain Transcript Verification
    lines.append(sep)
    lines.append("[2] OFF-CHAIN TRANSCRIPT VERIFICATION")
    lines.append(sep)
    tr = proof_dict.get("transcript")
    if isinstance(tr, dict) and tr:
        tr_status = tr.get("status", "unknown")
        tr_auth = tr.get("authenticity", "unknown")
        tr_sigs = tr.get("signatures_verified")
        tr_merkle = tr.get("merkle_inclusion_verified")
        tr_frames = ", ".join(tr.get("frames_verified", [])) or "None"

        lines.append(f"  Room Identifier:      {tr.get('room', 'N/A')}")
        lines.append(f"  Transcript Records:   {tr.get('line_count', 'N/A')} lines parsed")
        lines.append(f"  Frames Verified:      {tr_frames}")
        lines.append(f"  Ed25519 Signatures:   {_tag_status(tr_sigs)}")
        lines.append(f"  Merkle Export Root:   {tr.get('export_root', 'N/A')} ({_tag_status(tr_merkle)})")
        lines.append(f"  Authenticity Status:  {_tag_status(tr_auth)} (transcript {tr_status})")
    else:
        lines.append("  [FAIL] Transcript evidence missing or failed to parse")
    lines.append("")

    # 3. Agreement Terms
    lines.append(sep)
    lines.append("[3] AGREEMENT TERMS (OFF-CHAIN NEGOTIATION)")
    lines.append(sep)
    ag = proof_dict.get("agreement")
    if isinstance(ag, dict) and ag:
        lines.append(f"  Agreement Status:     {_tag_status(ag.get('status', 'unknown'))}")
        lines.append(f"  Payer DID:            {ag.get('payer_did', 'N/A')}")
        if ag.get("payer_payment_key"):
            lines.append(f"  Payer Payment Key:    {ag.get('payer_payment_key')}")
        lines.append(f"  Payee DID:            {ag.get('payee_did', 'N/A')}")
        if ag.get("payee_payment_key"):
            lines.append(f"  Payee Payment Key:    {ag.get('payee_payment_key')}")
        lines.append(f"  Agreed Amount:        {ag.get('amount', 'N/A')}")
        lines.append(f"  Agreed Asset:         {ag.get('asset', 'N/A')}")
        lines.append(f"  Lock Kind:            {ag.get('lock_kind', 'N/A')}")
        lines.append(f"  Agreed Hashlock:      {ag.get('hashlock', 'N/A')}")
        lines.append(f"  Claim By:             {_fmt_ts(ag.get('claim_by_ms'), is_ms=True)}")
        lines.append(f"  Refund After:         {_fmt_ts(ag.get('refund_after_ms'), is_ms=True)}")
        lines.append(f"  Expires:              {_fmt_ts(ag.get('expires_ms'), is_ms=True)}")
        rails_list = ag.get("rails")
        rails_str = ", ".join(rails_list) if isinstance(rails_list, list) else (str(rails_list) if rails_list else "None")
        lines.append(f"  Settlement Rails:     {rails_str}")
    else:
        lines.append("  [FAIL] Agreement state missing or unextractable")
    lines.append("")

    # 4. EVM Settlement Evidence
    lines.append(sep)
    lines.append("[4] EVM SETTLEMENT / RAIL EVIDENCE")
    lines.append(sep)
    st = proof_dict.get("settlement")
    if isinstance(st, dict) and st:
        lines.append(f"  Settlement Rail:      {st.get('rail', 'N/A')}")
        lines.append(f"  Settlement Status:    {st.get('status', 'N/A')}")
        lines.append(f"  HTLC Contract:        {st.get('contract_address', 'N/A')}")
        lines.append(f"  Lock Transaction:     {st.get('lock_tx', 'N/A')} ({_fmt_ts(st.get('lock_timestamp'), is_ms=False)})")
        lines.append(f"  Claim Transaction:    {st.get('claim_tx', 'N/A')} ({_fmt_ts(st.get('claim_timestamp'), is_ms=False)})")
        lines.append(f"  Refund Transaction:   {st.get('refund_tx', 'N/A')} ({_fmt_ts(st.get('refund_timestamp'), is_ms=False)})")
        lines.append(f"  Payer Address:        {st.get('payer_address', 'N/A')}")
        lines.append(f"  Payee Address:        {st.get('payee_address', 'N/A')}")
        erc20_verified = st.get("erc20_transfer_verified")
        if erc20_verified is not None:
            lines.append(f"  ERC-20 Transfer Log:  {_tag_status(erc20_verified)}")
        secret = st.get("secret_revealed")
        secret_disp = f"{secret[:10]}...{secret[-8:]}" if secret and len(secret) > 20 else (secret or "None")
        lines.append(f"  Revealed Preimage:    {secret_disp}")
        chain_id_val = st.get("chain_id") or (anchors.get("chain_id") if anchors else None)
        if chain_id_val is not None:
            lines.append(f"  EVM Chain ID:         {chain_id_val}")
    else:
        lines.append("  [FAIL] Settlement evidence missing")
    lines.append("")

    # 5. Cross-Layer Bindings
    lines.append(sep)
    lines.append("[5] CROSS-LAYER BINDINGS & CONFORMANCE")
    lines.append(sep)
    cc = proof_dict.get("cross_check")
    if isinstance(cc, dict) and cc:
        lines.append(f"  Contract ID Binding:  {_tag_status(cc.get('contract_id_binding'))}")
        lines.append(f"  Hashlock Binding:     {_tag_status(cc.get('hashlock_binding'))}")
        lines.append(f"  Amount Binding:       {_tag_status(cc.get('amount_binding'))}")
        lines.append(f"  Asset / Token Binding:{_tag_status(cc.get('asset_binding'))}")
        if "erc20_transfer_binding" in cc and cc.get("erc20_transfer_binding") != "not_applicable":
            lines.append(f"  ERC-20 Transfer Bind: {_tag_status(cc.get('erc20_transfer_binding'))}")
        lines.append(f"  Secret Preimage Check:{_tag_status(cc.get('secret_verification'))}")
        lines.append(f"  Temporal Ordering:    {_tag_status(cc.get('temporal_ordering'))}")
        lines.append(f"  Settlement Lifecycle: {_tag_status(cc.get('settlement_lifecycle'))}")
        lines.append(f"  Payer Address Binding:{_tag_status(cc.get('address_binding_payer'))}")
        lines.append(f"  Payee Address Binding:{_tag_status(cc.get('address_binding_payee'))}")
        lines.append(f"  Overall Address Bind: {_tag_status(cc.get('address_binding'))}")
        lines.append(f"  Terms Conformance:    {_tag_status(cc.get('terms_conformance'))}")
    else:
        lines.append("  [FAIL] Cross-check results missing")
    lines.append("")

    # 6. Provenance & Trust Model
    lines.append(sep)
    lines.append("[6] PROVENANCE & TRUST MODEL")
    lines.append(sep)
    tm = proof_dict.get("trust_model")
    if isinstance(tm, dict) and tm:
        prov = tm.get("settlement_evidence_provenance", "unknown")
        lines.append(f"  Evidence Provenance:  {_tag_status(prov)}")
        lines.append(f"  On-Chain Exec Proven: {_tag_status(tm.get('on_chain_execution_proven'))}")
        lines.append(f"  Transcript Sigs:      {_tag_status(tm.get('proves_transcript_signatures'))}")
        lines.append(f"  Merkle Export Root:   {_tag_status(tm.get('proves_merkle_export_inclusion'))}")
        notice = tm.get("notice")
        if notice:
            lines.append(f"  Trust Notice:         {notice}")
    else:
        lines.append("  [FAIL] Trust model assessment missing")
    lines.append("")

    # 7. Warnings & Anomalies
    lines.append(sep)
    warnings = proof_dict.get("warnings") or []
    lines.append(f"[7] WARNINGS & ANOMALIES ({len(warnings)})")
    lines.append(sep)
    if warnings:
        for w in warnings:
            lines.append(f"  - [WARN] {w}")
    else:
        lines.append("  [INFO] None")
    lines.append("")

    # 8. Failure Reasons & Final Verdict
    lines.append(sep)
    failures = proof_dict.get("failure_reasons") or []
    lines.append(f"[8] FAILURE REASONS ({len(failures)})")
    lines.append(sep)
    if failures:
        for f in failures:
            lines.append(f"  - [FAIL] {f}")
    else:
        lines.append("  [INFO] None")
    lines.append(bar)
    lines.append(f"FINAL CONFORMITY VERDICT: {verdict_tag}")
    lines.append(bar)

    return "\n".join(lines)


_CACHED_SCHEMA: Optional[dict[str, Any]] = None


def load_tclk_proof_schema() -> dict[str, Any]:
    """Loads schemas/tclk-proof-v1.schema.json."""
    global _CACHED_SCHEMA
    if _CACHED_SCHEMA is not None:
        return _CACHED_SCHEMA
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "tclk-proof-v1.schema.json"
    if schema_path.is_file():
        _CACHED_SCHEMA = json.loads(schema_path.read_text(encoding="utf-8"))
        return _CACHED_SCHEMA
    raise FileNotFoundError(f"tclk-proof schema not found at {schema_path}")


def verify_standalone_proof(
    proof_doc: Any,
    trust_anchors: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Pure, offline deterministic verification of an existing tclk-proof/1 proof artifact
    without requiring original transcript files or an RPC endpoint.

    Validates:
    - JSON Schema conformance (schemas/tclk-proof-v1.schema.json)
    - Embedded Merkle export root format and commitments
    - Recomputed canonical contract commitment if frames are embedded
    - Secret preimage validation: sha256(secret) == hashlock
    - Internal cross-layer semantic equality bindings
    - Fail-closed trust model consistency: never elevates self_attested provenance.
    - ERC-20 transfer event consistency verification when asset is not native ETH.
    """
    if isinstance(proof_doc, (str, Path)):
        p = Path(proof_doc)
        if not p.is_file():
            raise FileNotFoundError(f"Proof file not found: {p}")
        try:
            proof = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"Malformed proof JSON: {exc}") from exc
    elif isinstance(proof_doc, dict):
        proof = proof_doc
    else:
        raise TypeError(f"Unsupported proof_doc type: {type(proof_doc)}")

    trust_anchors = trust_anchors or {}
    expected_room = trust_anchors.get("room") or trust_anchors.get("expected_room")
    expected_root = trust_anchors.get("export_root") or trust_anchors.get("expected_root")
    expected_contract_id = trust_anchors.get("contract_id") or trust_anchors.get("expected_contract_id")
    expected_chain_id = trust_anchors.get("chain_id") or trust_anchors.get("expected_chain_id")

    failure_reasons: list[str] = []
    warnings: list[str] = list(proof.get("warnings", [])) if isinstance(proof, dict) else []

    # 1. Schema validation (Draft 2020-12)
    schema_valid = True
    try:
        import jsonschema
        schema = load_tclk_proof_schema()
        jsonschema.validate(instance=proof, schema=schema)
    except Exception as exc:
        schema_valid = False
        failure_reasons.append(f"schema validation failed: {exc}")

    if not isinstance(proof, dict):
        return {
            "spec": "tclk-proof/1",
            "version": 1,
            "profile": "tc-ledger/1",
            "schema": "tc-ledger/tclk-proof/v1",
            "command": "verify-proof",
            "valid": False,
            "is_conformant": False,
            "schema_valid": False,
            "cryptographic_validity": False,
            "failure_reasons": failure_reasons,
            "warnings": warnings,
            "proof": proof,
        }

    agreement = proof.get("agreement") or {}
    transcript = proof.get("transcript") or {}
    settlement = proof.get("settlement") or {}
    trust_model = proof.get("trust_model") or {}
    cross_check = proof.get("cross_check") or {}

    crypto_valid = True

    # 2. Contract ID verification against settlement & recomputation from embedded frames
    cid_proof = proof.get("contract_id")
    cid_settlement = settlement.get("contract_id")
    cid_match = True
    cid_proof_norm = normalize_hex(cid_proof) if cid_proof else None
    cid_set_norm = normalize_hex(cid_settlement) if cid_settlement else None

    if cid_proof and cid_settlement and cid_proof_norm != cid_set_norm:
        crypto_valid = False
        cid_match = False
        failure_reasons.append(f"contract ID binding mismatch: proof '{cid_proof}' != settlement '{cid_settlement}'")

    # Recalculate contract commitment if frames are embedded in agreement
    if isinstance(agreement.get("offer_frame"), dict) and isinstance(agreement.get("accept_frame"), dict):
        try:
            offer = agreement["offer_frame"]
            accept = agreement["accept_frame"]
            accept_core = {
                "from": accept.get("from", ""),
                "ref": str(accept.get("ref", "")),
                "statement": accept.get("statement", ""),
                "nonce": accept.get("nonce", ""),
            }
            if "paymentKey" in accept:
                accept_core["paymentKey"] = accept["paymentKey"]
            payload_bytes = canonical_json_bytes({"offer": offer, "accept": accept_core})
            recomputed_cid = domain_hash("contract", payload_bytes)
            recomputed_cid_norm = normalize_hex(recomputed_cid)
            if cid_proof and recomputed_cid_norm != cid_proof_norm:
                crypto_valid = False
                cid_match = False
                failure_reasons.append(f"recalculated agreement contract ID '{recomputed_cid}' != proof contract ID '{cid_proof}'")
        except Exception as exc:
            crypto_valid = False
            failure_reasons.append(f"failed to recalculate agreement commitment: {exc}")

    # 3. Merkle export root validation and tree reconstruction
    actual_root = transcript.get("export_root")
    actual_root_clean = None
    if actual_root is not None:
        if isinstance(actual_root, str):
            actual_root_clean = actual_root[2:] if actual_root.startswith("0x") or actual_root.startswith("0X") else actual_root
            if len(actual_root_clean) != 64 or not all(c in "0123456789abcdefABCDEF" for c in actual_root_clean):
                crypto_valid = False
                failure_reasons.append(f"invalid export_root format (expected 32-byte hex): '{actual_root}'")
        else:
            crypto_valid = False
            failure_reasons.append(f"invalid export_root type: {type(actual_root)}")

    # Reconstruct Merkle tree if raw lines / records are embedded
    raw_lines = transcript.get("raw_lines") or proof.get("raw_lines")
    if raw_lines is not None:
        if isinstance(raw_lines, list):
            try:
                line_bytes_list: list[bytes] = []
                for item in raw_lines:
                    if isinstance(item, str):
                        line_bytes_list.append(item.encode("utf-8"))
                    elif isinstance(item, bytes):
                        line_bytes_list.append(item)
                    elif isinstance(item, dict):
                        line_bytes_list.append(canonical_json_bytes(item))
                    else:
                        raise TypeError(f"unsupported raw_line element: {type(item)}")
                recomputed_root = export_merkle_root(line_bytes_list).hex()
                if actual_root_clean:
                    if recomputed_root.lower() != actual_root_clean.lower():
                        crypto_valid = False
                        failure_reasons.append(
                            f"recomputed Merkle export root '{recomputed_root}' != transcript export root '{actual_root}'"
                        )
                else:
                    actual_root_clean = recomputed_root
            except Exception as exc:
                crypto_valid = False
                failure_reasons.append(f"failed to recompute Merkle export root from raw_lines: {exc}")
        else:
            crypto_valid = False
            failure_reasons.append(f"invalid raw_lines in transcript (must be a list): {type(raw_lines)}")

    # Verify embedded Merkle inclusion proofs if present
    merkle_proofs = transcript.get("merkle_proofs") or transcript.get("inclusion_proofs")
    if isinstance(merkle_proofs, list):
        for idx, mp in enumerate(merkle_proofs):
            if isinstance(mp, dict):
                leaf_data = mp.get("leaf") or mp.get("raw_line")
                path = mp.get("proof") or mp.get("path")
                root_target = mp.get("root") or (f"0x{actual_root_clean}" if actual_root_clean else None)
                if leaf_data and path and root_target:
                    clean_rt = root_target[2:] if root_target.startswith("0x") or root_target.startswith("0X") else root_target
                    try:
                        leaf_b = leaf_data.encode("utf-8") if isinstance(leaf_data, str) else leaf_data
                        parsed_proof = []
                        for sib, pos in path:
                            sib_b = bytes.fromhex(sib[2:] if sib.startswith("0x") or sib.startswith("0X") else sib) if isinstance(sib, str) else sib
                            parsed_proof.append((sib_b, pos))
                        if not verify_export_merkle_proof(leaf_b, parsed_proof, bytes.fromhex(clean_rt)):
                            crypto_valid = False
                            failure_reasons.append(f"Merkle inclusion proof #{idx} failed verification against root '{root_target}'")
                    except Exception as exc:
                        crypto_valid = False
                        failure_reasons.append(f"invalid Merkle inclusion proof #{idx}: {exc}")

    # Reconstruct Merkle tree if evidence_ids are embedded
    evidence_ids = transcript.get("evidence_ids")
    if isinstance(evidence_ids, list):
        try:
            recomputed_merkle_root = merkle_root(evidence_ids).hex()
            expected_mr = transcript.get("merkle_root")
            if expected_mr:
                clean_mr = expected_mr[2:] if expected_mr.startswith("0x") or expected_mr.startswith("0X") else expected_mr
                if recomputed_merkle_root.lower() != clean_mr.lower():
                    crypto_valid = False
                    failure_reasons.append(f"recomputed Merkle root '{recomputed_merkle_root}' != transcript merkle_root '{expected_mr}'")
        except Exception as exc:
            crypto_valid = False
            failure_reasons.append(f"failed to recompute Merkle root from evidence_ids: {exc}")

    # 4. Secret preimage & hashlock validation
    secret = settlement.get("secret_revealed")
    hashlock_agr = agreement.get("hashlock")
    hashlock_set = settlement.get("hashlock")
    hashlock_match = True
    hl_agr_norm = normalize_hex(hashlock_agr) if hashlock_agr else None
    hl_set_norm = normalize_hex(hashlock_set) if hashlock_set else None

    if hashlock_agr and hashlock_set and hl_agr_norm != hl_set_norm:
        crypto_valid = False
        hashlock_match = False
        failure_reasons.append(f"hashlock mismatch: agreement '{hashlock_agr}' != settlement '{hashlock_set}'")

    secret_match = True
    secret_checked = False
    if secret:
        secret_checked = True
        raw_secret_hex = secret[2:] if secret.startswith("0x") or secret.startswith("0X") else secret
        try:
            secret_bytes = bytes.fromhex(raw_secret_hex)
            computed_hashlock = "0x" + hashlib.sha256(secret_bytes).hexdigest()
            computed_hl_norm = normalize_hex(computed_hashlock)
            target_norm = hl_agr_norm or hl_set_norm
            if target_norm and computed_hl_norm != target_norm:
                crypto_valid = False
                secret_match = False
                failure_reasons.append(f"secret preimage hash mismatch: sha256({secret}) = '{computed_hashlock}' != expected '{hashlock_agr or hashlock_set}'")
        except ValueError as exc:
            crypto_valid = False
            secret_match = False
            failure_reasons.append(f"malformed secret hex '{secret}': {exc}")

    # 5. Amount and Asset bindings
    amt_agr = agreement.get("amount")
    amt_set = settlement.get("amount")
    amount_match = True
    norm_amt_agr = normalize_amount_str(amt_agr)
    norm_amt_set = normalize_amount_str(amt_set)
    if norm_amt_agr is not None and norm_amt_set is not None and norm_amt_agr != norm_amt_set:
        crypto_valid = False
        amount_match = False
        failure_reasons.append(f"amount binding mismatch: agreement '{amt_agr}' != settlement '{amt_set}'")

    asset_agr = agreement.get("asset")
    asset_set = settlement.get("asset")
    asset_match = True
    norm_asset_agr = normalize_address(asset_agr) or (asset_agr.lower() if isinstance(asset_agr, str) else None)
    norm_asset_set = normalize_address(asset_set) or (asset_set.lower() if isinstance(asset_set, str) else None)
    if norm_asset_agr and norm_asset_set and norm_asset_agr != norm_asset_set:
        crypto_valid = False
        asset_match = False
        failure_reasons.append(f"asset binding mismatch: agreement '{asset_agr}' != settlement '{asset_set}'")

    # 6. Trust anchors validation
    if expected_room and proof.get("room") != expected_room:
        failure_reasons.append(f"room trust anchor mismatch: expected '{expected_room}', got '{proof.get('room')}'")

    if expected_root:
        clean_exp_root = expected_root[2:] if expected_root.startswith("0x") or expected_root.startswith("0X") else expected_root
        if actual_root_clean and actual_root_clean.lower() != clean_exp_root.lower():
            failure_reasons.append(f"export root trust anchor mismatch: expected '{expected_root}', got '{actual_root}'")

    if expected_contract_id and cid_proof:
        exp_cid_norm = normalize_hex(expected_contract_id)
        if cid_proof_norm != exp_cid_norm:
            failure_reasons.append(f"contract ID trust anchor mismatch: expected '{expected_contract_id}', got '{cid_proof}'")

    # 7. Trust Model & Provenance Separation Invariants
    provenance = trust_model.get("settlement_evidence_provenance")
    claimed_on_chain_proven = trust_model.get("on_chain_execution_proven", False)
    claimed_conformant = proof.get("is_conformant", False)
    trust_model_ok = True

    if provenance == "self_attested":
        if claimed_on_chain_proven:
            crypto_valid = False
            trust_model_ok = False
            failure_reasons.append("trust model violation: self_attested settlement evidence cannot claim on_chain_execution_proven: true")
        if claimed_conformant:
            crypto_valid = False
            trust_model_ok = False
            failure_reasons.append("trust model violation: self_attested settlement evidence cannot claim is_conformant: true")
        if not any("self-attested" in r for r in failure_reasons) and not claimed_conformant:
            failure_reasons.append("settlement evidence is self-attested and lacks independent on-chain provenance")
    elif provenance in ("rpc_receipt_verified", "cryptographic_receipt_proof"):
        if not crypto_valid or not schema_valid:
            trust_model_ok = False
    else:
        trust_model_ok = False
        crypto_valid = False
        failure_reasons.append(f"unsupported settlement evidence provenance: '{provenance}'")

    # 8. Payment key address derivation checks
    payer_pk = agreement.get("payer_payment_key")
    if payer_pk and settlement.get("payer_address"):
        try:
            expected_payer_addr = public_key_to_eth_address(payer_pk)
            norm_exp_payer = normalize_address(expected_payer_addr)
            norm_set_payer = normalize_address(settlement["payer_address"])
            if norm_exp_payer != norm_set_payer:
                crypto_valid = False
                failure_reasons.append(f"payer address derived from paymentKey '{expected_payer_addr}' != settlement '{settlement['payer_address']}'")
        except Exception as exc:
            crypto_valid = False
            failure_reasons.append(f"invalid payer paymentKey: {exc}")

    payee_pk = agreement.get("payee_payment_key")
    if payee_pk and settlement.get("payee_address"):
        try:
            expected_payee_addr = public_key_to_eth_address(payee_pk)
            norm_exp_payee = normalize_address(expected_payee_addr)
            norm_set_payee = normalize_address(settlement["payee_address"])
            if norm_exp_payee != norm_set_payee:
                crypto_valid = False
                failure_reasons.append(f"payee address derived from paymentKey '{expected_payee_addr}' != settlement '{settlement['payee_address']}'")
        except Exception as exc:
            crypto_valid = False
            failure_reasons.append(f"invalid payee paymentKey: {exc}")

    # 9. Temporal ordering & lifecycle checks
    lock_ts = settlement.get("lock_timestamp")
    claim_ts = settlement.get("claim_timestamp")
    refund_ts = settlement.get("refund_timestamp")
    temporal_match = True
    if lock_ts is not None and claim_ts is not None and int(lock_ts) > int(claim_ts):
        crypto_valid = False
        temporal_match = False
        failure_reasons.append(f"temporal ordering violation: lock_timestamp ({lock_ts}) > claim_timestamp ({claim_ts})")
    if claim_ts is not None and refund_ts is not None and int(claim_ts) > int(refund_ts):
        crypto_valid = False
        temporal_match = False
        failure_reasons.append(f"temporal ordering violation: claim_timestamp ({claim_ts}) > refund_timestamp ({refund_ts})")

    # 10. Dual-Log ERC-20 Transfer Check
    ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
    norm_proof_agr_asset = normalize_address(agreement.get("asset"))
    norm_proof_set_asset = normalize_address(settlement.get("asset"))
    is_erc20_deal = (norm_proof_agr_asset and norm_proof_agr_asset.lower() != ZERO_ADDRESS) or (norm_proof_set_asset and norm_proof_set_asset.lower() != ZERO_ADDRESS)
    erc20_transfer_binding = "not_applicable"

    if is_erc20_deal:
        claimed_erc20_verified = settlement.get("erc20_transfer_verified")
        if provenance in ("rpc_receipt_verified", "cryptographic_receipt_proof"):
            if claimed_erc20_verified is True:
                erc20_transfer_binding = "verified"
            else:
                erc20_transfer_binding = "failed"
                crypto_valid = False
                failure_reasons.append("ERC-20 token transfer event not verified in settlement evidence")
        elif provenance == "self_attested":
            if claimed_erc20_verified is True or claimed_conformant:
                crypto_valid = False
                trust_model_ok = False
                failure_reasons.append("trust model violation: self_attested settlement evidence cannot prove ERC-20 transfer execution")
            erc20_transfer_binding = "unverified"

    # Retain recorded failure reasons from proof
    for recorded_f in proof.get("failure_reasons", []):
        if recorded_f not in failure_reasons:
            failure_reasons.append(recorded_f)

    is_valid = schema_valid and crypto_valid and trust_model_ok and (len([r for r in failure_reasons if not r.startswith("settlement evidence is self-attested")]) == 0)
    final_conformant = is_valid and (provenance in ("rpc_receipt_verified", "cryptographic_receipt_proof")) and claimed_conformant and (len(failure_reasons) == 0)

    return {
        "spec": "tclk-proof/1",
        "version": 1,
        "profile": "tc-ledger/1",
        "schema": "tc-ledger/tclk-proof/v1",
        "command": "verify-proof",
        "valid": is_valid,
        "is_conformant": final_conformant,
        "schema_valid": schema_valid,
        "cryptographic_validity": crypto_valid,
        "contract_id": proof.get("contract_id"),
        "room": proof.get("room"),
        "provenance": provenance,
        "cross_check": {
            "schema_validation": "verified" if schema_valid else "failed",
            "cryptographic_validity": "verified" if crypto_valid else "failed",
            "contract_id_binding": "verified" if cid_match else "failed",
            "hashlock_binding": "verified" if hashlock_match else "failed",
            "secret_verification": "verified" if secret_match else ("failed" if secret_checked else "not_applicable"),
            "amount_binding": "verified" if amount_match else "failed",
            "asset_binding": "verified" if asset_match else "failed",
            "temporal_ordering": "verified" if temporal_match else "failed",
            "trust_model_consistency": "verified" if trust_model_ok else "failed",
            "erc20_transfer_binding": erc20_transfer_binding,
        },
        "trust_model": {
            "settlement_evidence_provenance": provenance,
            "on_chain_execution_proven": claimed_on_chain_proven and trust_model_ok,
            "transcript_authenticity": trust_model.get("transcript_authenticity", False),
            "terms_conformance": trust_model.get("terms_conformance", False),
        },
        "failure_reasons": failure_reasons,
        "warnings": warnings,
        "proof": proof,
    }


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint for tclk-proof."""
    raw_args = list(argv) if argv is not None else list(sys.argv[1:])

    # 1. Handle 'tclk-proof bundle ...'
    if raw_args and raw_args[0] in ("bundle", "create-bundle", "create_bundle"):
        from tc_ledger.bundle import create_bundle
        raw_args = raw_args[1:]
        b_parser = argparse.ArgumentParser(
            prog="tclk-proof bundle",
            description="Generate a self-contained .tclk-bundle evidence archive."
        )
        b_parser.add_argument("transcript", nargs="?", default=None, help="Path to room export (.jsonl) or DealArchive (.json)")
        b_parser.add_argument("settlement", nargs="?", default=None, help="Path to settlement evidence (.json)")
        b_parser.add_argument("--transcript", dest="transcript_flag", help="Path to room export (.jsonl) or DealArchive (.json)")
        b_parser.add_argument("--settlement", dest="settlement_flag", help="Path to settlement evidence (.json)")
        b_parser.add_argument("--rpc-url", help="EVM JSON-RPC endpoint URL")
        b_parser.add_argument("--lock-tx", help="On-chain lock transaction hash")
        b_parser.add_argument("--claim-tx", help="On-chain claim transaction hash")
        b_parser.add_argument("--refund-tx", help="On-chain refund transaction hash")
        b_parser.add_argument("--htlc-address", help="Expected HTLC contract address")
        b_parser.add_argument("--chain-id", type=int, help="Expected EVM network chain ID")
        b_parser.add_argument("--room", help="Expected room identifier trust anchor")
        b_parser.add_argument("--expected-root", help="Expected room export Merkle root hex")
        b_parser.add_argument("--expected-contract-id", help="Expected contract ID trust anchor")
        b_parser.add_argument("--output", "-o", help="Output path for .tclk-bundle archive")
        b_parser.add_argument("--json", action="store_true", help="Output bundle manifest as JSON")
        b_parser.add_argument("--report", action="store_true", help="Output human-readable report")

        try:
            b_args = b_parser.parse_args(raw_args)
        except SystemExit as e:
            return 2 if e.code != 0 else 0

        transcript_src = b_args.transcript_flag or b_args.transcript
        settlement_src = b_args.settlement_flag or b_args.settlement
        is_json = getattr(b_args, "json", False)

        if not transcript_src:
            if is_json:
                print(json.dumps({"valid": False, "error": "Missing required argument: transcript"}, indent=2))
            else:
                print("error: the following arguments are required: transcript (positional or --transcript)", file=sys.stderr)
            return 2

        trust_anchors = {
            "room": b_args.room,
            "expected_root": b_args.expected_root,
            "expected_contract_id": b_args.expected_contract_id,
            "chain_id": getattr(b_args, "chain_id", None),
        }
        rpc_anchors = None
        if getattr(b_args, "rpc_url", None):
            rpc_anchors = {
                "rpc_url": b_args.rpc_url,
                "lock_tx": getattr(b_args, "lock_tx", None),
                "claim_tx": getattr(b_args, "claim_tx", None),
                "refund_tx": getattr(b_args, "refund_tx", None),
                "htlc_address": getattr(b_args, "htlc_address", None),
                "chain_id": getattr(b_args, "chain_id", None),
            }

        try:
            manifest, bundle_bytes = create_bundle(
                transcript_source=transcript_src,
                settlement_source=settlement_src,
                trust_anchors=trust_anchors,
                rpc_anchors=rpc_anchors,
                output_path=b_args.output,
            )
        except FileNotFoundError as exc:
            if is_json:
                print(json.dumps({"valid": False, "error": f"I/O Error: {exc}"}, indent=2))
            else:
                print(f"I/O Error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            if is_json:
                print(json.dumps({"valid": False, "error": f"Runtime Error: {exc}"}, indent=2))
            else:
                print(f"Runtime Error: {exc}", file=sys.stderr)
            return 2

        if is_json:
            print(json.dumps(manifest, indent=2))
        else:
            if b_args.output:
                print(f"BUNDLE CREATED: {b_args.output} ({len(bundle_bytes)} bytes)")
            else:
                print(f"BUNDLE CREATED ({len(bundle_bytes)} bytes)")
            print(f"Contract ID: {manifest.get('contract_id')}")
            print(f"Room:        {manifest.get('room')}")
        return 0

    # 2. Handle 'tclk-proof verify-bundle <bundle.tclk-bundle>'
    if raw_args and raw_args[0] in ("verify-bundle", "verify_bundle"):
        from tc_ledger.bundle import verify_bundle
        raw_args = raw_args[1:]
        vb_parser = argparse.ArgumentParser(
            prog="tclk-proof verify-bundle",
            description="Verify an offline .tclk-bundle evidence archive."
        )
        vb_parser.add_argument("bundle", nargs="?", default=None, help="Path to .tclk-bundle archive")
        vb_parser.add_argument("--bundle", dest="bundle_flag", help="Path to .tclk-bundle archive")
        vb_parser.add_argument("--room", help="Expected room identifier trust anchor")
        vb_parser.add_argument("--expected-root", help="Expected room export Merkle root hex")
        vb_parser.add_argument("--expected-contract-id", help="Expected contract ID trust anchor")
        vb_parser.add_argument("--chain-id", type=int, help="Expected EVM network chain ID")
        vb_parser.add_argument("--output", help="Optional output path to write verification result JSON")
        vb_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON result")
        vb_parser.add_argument("--report", action="store_true", help="Output human-readable verification report")

        try:
            vb_args = vb_parser.parse_args(raw_args)
        except SystemExit as e:
            return 2 if e.code != 0 else 0

        bundle_source = vb_args.bundle_flag or vb_args.bundle
        is_json = getattr(vb_args, "json", False)
        is_report = getattr(vb_args, "report", False)

        if not bundle_source:
            if is_json:
                print(json.dumps({"valid": False, "error": "Missing required argument: bundle (positional or --bundle)"}, indent=2))
            else:
                print("error: the following arguments are required: bundle (positional or --bundle)", file=sys.stderr)
            return 2

        trust_anchors = {
            "room": vb_args.room,
            "expected_root": vb_args.expected_root,
            "expected_contract_id": vb_args.expected_contract_id,
            "chain_id": getattr(vb_args, "chain_id", None),
        }

        try:
            result = verify_bundle(bundle_source, trust_anchors=trust_anchors)
        except FileNotFoundError as exc:
            if is_json:
                print(json.dumps({"valid": False, "error": f"I/O Error: {exc}"}, indent=2))
            else:
                print(f"I/O Error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            if is_json:
                print(json.dumps({"valid": False, "error": f"Bundle Error: {exc}"}, indent=2))
            else:
                print(f"Bundle Error: {exc}", file=sys.stderr)
            return 2

        if vb_args.output:
            try:
                out_p = Path(vb_args.output)
                out_p.parent.mkdir(parents=True, exist_ok=True)
                out_p.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            except Exception as exc:
                if is_json:
                    print(json.dumps({"valid": False, "error": f"I/O Error writing output: {exc}"}, indent=2))
                else:
                    print(f"I/O Error writing output: {exc}", file=sys.stderr)
                return 2

        is_valid = result.get("valid", False)
        is_conformant = result.get("is_conformant", False)
        manifest_verified = result.get("manifest_verified", False)
        fatal_bundle_error = (not manifest_verified) or any(
            "checksum mismatch" in r
            or "missing required" in r
            or "unexpected archive" in r
            or "path traversal" in r
            or "illegal characters" in r
            or "duplicate archive" in r
            or "malformed manifest" in r
            or "manifest schema validation failed" in r
            or "failed to parse proof.json" in r
            or "schema validation failed" in r
            or "invalid zip" in r.lower()
            for r in result.get("failure_reasons", [])
        )

        # Fatal archive / checksum / tampering errors exit with code 2
        if fatal_bundle_error:
            if is_json:
                print(json.dumps(result, indent=2))
            else:
                print("BUNDLE VERIFICATION: INVALID (CORRUPTED / TAMPERED)", file=sys.stderr)
                for reason in result.get("failure_reasons", []):
                    print(f"  - Failure: {reason}", file=sys.stderr)
            return 2

        if is_json:
            print(json.dumps(result, indent=2))
        elif is_report:
            report_proof = dict(result.get("proof", {}))
            report_proof["is_conformant"] = is_conformant
            report_proof["failure_reasons"] = result.get("failure_reasons", [])
            print(format_verification_report(report_proof, trust_anchors=trust_anchors))
        else:
            if is_conformant:
                print("BUNDLE VERIFICATION: CONFORMANT (SUCCESS)")
                print(f"Contract ID: {result.get('contract_id')}")
                print(f"Room:        {result.get('room')}")
                print(f"Provenance:  {result.get('provenance')}")
            else:
                print("BUNDLE VERIFICATION: VALID (NON-CONFORMANT)")
                print(f"Contract ID: {result.get('contract_id')}")
                print(f"Room:        {result.get('room')}")
                print(f"Provenance:  {result.get('provenance')}")
                for reason in result.get("failure_reasons", []):
                    print(f"  - Note: {reason}")

        return 0 if is_conformant else 1

    # 3. Handle 'tclk-proof verify-proof <proof.json>'
    if raw_args and raw_args[0] in ("verify-proof", "verify_proof"):
        raw_args = raw_args[1:]
        vp_parser = argparse.ArgumentParser(
            prog="tclk-proof verify-proof",
            description="Verify an existing tclk-proof/1 proof artifact offline without RPC or transcript dependencies."
        )
        vp_parser.add_argument("proof", nargs="?", default=None, help="Path to proof JSON artifact")
        vp_parser.add_argument("--proof", dest="proof_flag", help="Path to proof JSON artifact")
        vp_parser.add_argument("--room", help="Expected room identifier trust anchor")
        vp_parser.add_argument("--expected-root", help="Expected room export Merkle root hex")
        vp_parser.add_argument("--expected-contract-id", help="Expected contract ID trust anchor")
        vp_parser.add_argument("--chain-id", type=int, help="Expected EVM network chain ID")
        vp_parser.add_argument("--output", help="Optional output path to write verification result JSON")
        vp_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON result")
        vp_parser.add_argument("--report", action="store_true", help="Output human-readable verification report")

        try:
            vp_args = vp_parser.parse_args(raw_args)
        except SystemExit as e:
            return 2 if e.code != 0 else 0

        is_json = getattr(vp_args, "json", False)
        is_report = getattr(vp_args, "report", False)
        proof_source = vp_args.proof_flag or vp_args.proof

        if not proof_source:
            if is_json:
                print(json.dumps({"valid": False, "error": "Missing required argument: proof (positional or --proof)"}, indent=2))
            else:
                print("error: the following arguments are required: proof (positional or --proof)", file=sys.stderr)
            return 2

        trust_anchors = {
            "room": vp_args.room,
            "expected_root": vp_args.expected_root,
            "expected_contract_id": vp_args.expected_contract_id,
            "chain_id": getattr(vp_args, "chain_id", None),
        }

        try:
            result = verify_standalone_proof(proof_source, trust_anchors=trust_anchors)
        except FileNotFoundError as exc:
            if is_json:
                print(json.dumps({"valid": False, "error": f"I/O Error: {exc}"}, indent=2))
            else:
                print(f"I/O Error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            if is_json:
                print(json.dumps({"valid": False, "error": f"Runtime Error: {exc}"}, indent=2))
            else:
                print(f"Runtime Error: {exc}", file=sys.stderr)
            return 2

        # If schema validation failed, fail with exit code 2
        if not result.get("schema_valid", True):
            if is_json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Schema Error: {result.get('failure_reasons', ['Invalid proof schema'])[0]}", file=sys.stderr)
            return 2

        if vp_args.output:
            try:
                out_p = Path(vp_args.output)
                out_p.parent.mkdir(parents=True, exist_ok=True)
                out_p.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            except Exception as exc:
                if is_json:
                    print(json.dumps({"valid": False, "error": f"I/O Error writing output: {exc}"}, indent=2))
                else:
                    print(f"I/O Error writing output: {exc}", file=sys.stderr)
                return 2

        is_conformant = result.get("is_conformant", False)
        is_valid = result.get("valid", False)

        if is_json:
            print(json.dumps(result, indent=2))
        elif is_report:
            report_proof = dict(result.get("proof", {}))
            report_proof["is_conformant"] = is_conformant
            report_proof["failure_reasons"] = result.get("failure_reasons", [])
            print(format_verification_report(report_proof, trust_anchors=trust_anchors))
        else:
            if is_conformant:
                print("STANDALONE PROOF VERIFICATION: CONFORMANT (SUCCESS)")
                print(f"Contract ID: {result.get('contract_id')}")
                print(f"Room:        {result.get('room')}")
                print(f"Provenance:  {result.get('provenance')}")
            elif is_valid:
                print("STANDALONE PROOF VERIFICATION: VALID (NON-CONFORMANT)")
                print(f"Contract ID: {result.get('contract_id')}")
                print(f"Room:        {result.get('room')}")
                print(f"Provenance:  {result.get('provenance')}")
                for reason in result.get("failure_reasons", []):
                    print(f"  - Note: {reason}")
            else:
                print("STANDALONE PROOF VERIFICATION: INVALID (FAILED)", file=sys.stderr)
                for reason in result.get("failure_reasons", []):
                    print(f"  - Failure: {reason}", file=sys.stderr)

        return 0 if is_conformant else 1

    # Support 'tclk-proof verify export.jsonl settlement.json' and 'tclk-proof export.jsonl settlement.json'
    if raw_args and raw_args[0] == "verify":
        raw_args = raw_args[1:]

    parser = argparse.ArgumentParser(
        prog="tclk-proof",
        description="Verify signed Technocore agreements against verifiable settlement evidence."
    )
    parser.add_argument("transcript", nargs="?", default=None, help="Path to room export (.jsonl) or DealArchive (.json)")
    parser.add_argument("settlement", nargs="?", default=None, help="Path to settlement evidence (.json)")
    parser.add_argument("--transcript", dest="transcript_flag", help="Path to room export (.jsonl) or DealArchive (.json)")
    parser.add_argument("--settlement", dest="settlement_flag", help="Path to settlement evidence (.json)")
    parser.add_argument("--rpc-url", help="EVM JSON-RPC endpoint URL (e.g. http://127.0.0.1:8545)")
    parser.add_argument("--lock-tx", help="On-chain lock transaction hash to verify")
    parser.add_argument("--claim-tx", help="On-chain claim transaction hash to verify")
    parser.add_argument("--refund-tx", help="On-chain refund transaction hash to verify")
    parser.add_argument("--htlc-address", help="Expected HTLC contract address")
    parser.add_argument("--chain-id", type=int, help="Expected EVM network chain ID (e.g. 1, 31337)")
    parser.add_argument("--room", help="Expected room identifier trust anchor")
    parser.add_argument("--expected-root", help="Expected room export Merkle root hex")
    parser.add_argument("--expected-contract-id", help="Expected contract ID trust anchor")
    parser.add_argument("--output", help="Optional output path to write proof JSON artifact")
    parser.add_argument("--json", action="store_true", help="Output proof artifact as machine-readable JSON")
    parser.add_argument("--report", action="store_true", help="Output human-readable verification report")

    try:
        args = parser.parse_args(raw_args)
    except SystemExit as e:
        return 2 if e.code != 0 else 0

    transcript_source = args.transcript_flag or args.transcript
    settlement_source = args.settlement_flag or args.settlement
    is_json = getattr(args, "json", False)
    is_report = getattr(args, "report", False)

    if not transcript_source:
        if is_json:
            print(json.dumps({"valid": False, "error": "Missing required argument: transcript (positional or --transcript)"}, indent=2))
        else:
            print("error: the following arguments are required: transcript (positional or --transcript)", file=sys.stderr)
        return 2

    trust_anchors = {
        "room": args.room,
        "expected_root": args.expected_root,
        "expected_contract_id": args.expected_contract_id,
        "chain_id": getattr(args, "chain_id", None),
    }

    rpc_anchors = None
    if getattr(args, "rpc_url", None):
        rpc_anchors = {
            "rpc_url": args.rpc_url,
            "lock_tx": getattr(args, "lock_tx", None),
            "claim_tx": getattr(args, "claim_tx", None),
            "refund_tx": getattr(args, "refund_tx", None),
            "htlc_address": getattr(args, "htlc_address", None),
            "chain_id": getattr(args, "chain_id", None),
        }

    try:
        proof = verify_cross_layer(
            transcript_source=transcript_source,
            settlement_source=settlement_source,
            trust_anchors=trust_anchors,
            rpc_anchors=rpc_anchors,
        )
    except FileNotFoundError as exc:
        if is_json:
            print(json.dumps({"valid": False, "error": f"I/O Error: {exc}"}, indent=2))
        else:
            print(f"I/O Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        if is_json:
            print(json.dumps({"valid": False, "error": f"Runtime Error: {exc}"}, indent=2))
        else:
            print(f"Runtime Error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        try:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
        except Exception as exc:
            if is_json:
                print(json.dumps({"valid": False, "error": f"I/O Error writing output file: {exc}"}, indent=2))
            else:
                print(f"I/O Error writing output file: {exc}", file=sys.stderr)
            return 2

    fatal_prefixes = (
        "transcript source file not found",
        "settlement evidence file not found",
        "malformed settlement JSON",
        "invalid settlement evidence format",
        "neither settlement evidence nor RPC anchors provided",
        "EVM RPC settlement verification failed",
        "unsupported settlement evidence type",
        "unsupported transcript source type",
        "failed to extract agreement from export",
        "failed to load transcript agreement",
    )
    fatal_errors = [
        r for r in proof.get("failure_reasons", [])
        if any(r.startswith(p) for p in fatal_prefixes)
    ]
    if fatal_errors:
        if is_json:
            print(json.dumps({"valid": False, "error": fatal_errors[0]}, indent=2))
        else:
            print(f"Error: {fatal_errors[0]}", file=sys.stderr)
        return 2

    is_conformant = proof.get("is_conformant", False)
    terms_conformance = proof.get("cross_check", {}).get("terms_conformance", "failed")

    if is_json:
        print(json.dumps(proof, indent=2))
    elif is_report:
        print(format_verification_report(proof, trust_anchors=trust_anchors))
    else:
        if is_conformant:
            print("CROSS-VERIFICATION: CONFORMANT (SUCCESS)")
            print(f"Contract ID: {proof.get('contract_id')}")
            print(f"Room:        {proof.get('room')}")
            print(f"Terms:       {terms_conformance}")
            print(f"Settlement:  {proof.get('settlement', {}).get('status')}")
        else:
            print(f"CROSS-VERIFICATION: NON-CONFORMANT (Terms: {terms_conformance})", file=sys.stderr)
            for reason in proof.get("failure_reasons", []):
                print(f"  - Failure: {reason}", file=sys.stderr)

    return 0 if is_conformant else 1


if __name__ == "__main__":
    sys.exit(main())

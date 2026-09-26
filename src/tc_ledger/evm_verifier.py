"""
EVM JSON-RPC Receipt Verifier and Event Parser for TCLK Settlement Rails.
Specification: tclk-settlement/1 ("evm-htlc")

Decodes and verifies on-chain HTLC events (Locked, Claimed, Refunded) from raw
EVM transaction receipts via standard JSON-RPC without third-party dependencies.
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from typing import Any, Optional

from tc_ledger.cross_verify import (
    SettlementEvidence,
    keccak256,
    normalize_address,
    normalize_amount_str,
    normalize_hex,
)

# Canonical HTLC Event topic0 hashes:
# Locked(bytes32,address,address,address,uint256,bytes32,uint64)
EVENT_LOCKED_TOPIC0 = "0x" + keccak256(b"Locked(bytes32,address,address,address,uint256,bytes32,uint64)").hex().lower()
# Claimed(bytes32,bytes32)
EVENT_CLAIMED_TOPIC0 = "0x" + keccak256(b"Claimed(bytes32,bytes32)").hex().lower()
# Refunded(bytes32)
EVENT_REFUNDED_TOPIC0 = "0x" + keccak256(b"Refunded(bytes32)").hex().lower()


class EvmVerificationError(ValueError):
    """Raised when an EVM receipt or on-chain event verification fails."""
    pass


def rpc_call(rpc_url: str, method: str, params: list[Any], timeout: float = 10.0) -> Any:
    """Executes a standard EVM JSON-RPC 2.0 POST request with strict validation."""
    if not isinstance(rpc_url, str) or not rpc_url.startswith(("http://", "https://")):
        raise EvmVerificationError(f"invalid RPC endpoint URL: {rpc_url}")

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=req_data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_body = resp.read().decode("utf-8")
            res_json = json.loads(raw_body)
    except urllib.error.HTTPError as exc:
        raise EvmVerificationError(f"RPC HTTP error {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise EvmVerificationError(f"RPC connection failed: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise EvmVerificationError(f"malformed JSON response from RPC provider: {exc}") from exc
    except Exception as exc:
        raise EvmVerificationError(f"RPC request error: {exc}") from exc

    if not isinstance(res_json, dict):
        raise EvmVerificationError("RPC response must be a JSON object")

    if "error" in res_json and res_json["error"]:
        err_obj = res_json["error"]
        err_msg = err_obj.get("message", str(err_obj)) if isinstance(err_obj, dict) else str(err_obj)
        raise EvmVerificationError(f"RPC error from {method}: {err_msg}")

    return res_json.get("result")


def fetch_chain_id(rpc_url: str, timeout: float = 10.0) -> int:
    """Queries eth_chainId via JSON-RPC to bind network identity."""
    res = rpc_call(rpc_url, "eth_chainId", [], timeout=timeout)
    if res is None:
        raise EvmVerificationError("RPC eth_chainId returned null")
    if isinstance(res, str):
        if not re.fullmatch(r"0x[0-9a-fA-F]+", res):
            raise EvmVerificationError(f"invalid chainId hex string: {res}")
        return int(res, 16)
    if isinstance(res, int):
        return res
    raise EvmVerificationError(f"unexpected chainId type: {type(res)}")


def fetch_transaction_receipt(rpc_url: str, tx_hash: str, timeout: float = 10.0) -> dict[str, Any]:
    """Fetches and validates the mined transaction receipt via JSON-RPC."""
    norm_tx = normalize_hex(tx_hash)
    if not norm_tx or len(norm_tx) != 66:
        raise EvmVerificationError(f"invalid transaction hash format: {tx_hash}")

    result = rpc_call(rpc_url, "eth_getTransactionReceipt", [norm_tx], timeout=timeout)
    if not result:
        raise EvmVerificationError(f"transaction receipt not found for hash {norm_tx}")

    if not isinstance(result, dict):
        raise EvmVerificationError("transaction receipt must be a JSON object")

    # Strict check: receipt.transactionHash MUST equal queried hash
    rcpt_tx = normalize_hex(result.get("transactionHash"))
    if not rcpt_tx or rcpt_tx.lower() != norm_tx.lower():
        raise EvmVerificationError(
            f"receipt transaction hash mismatch: queried {norm_tx}, got {rcpt_tx}"
        )

    return result


def parse_and_verify_htlc_event(
    receipt: dict[str, Any],
    expected_htlc_address: Optional[str] = None,
    expected_contract_id: Optional[str] = None,
    expected_event_type: Optional[str] = None,
) -> dict[str, Any]:
    """
    Parses and verifies HTLC events (Locked, Claimed, Refunded) from a transaction receipt.
    Fails closed if the transaction reverted, wrong address, or ambiguous logs.
    """
    status_raw = receipt.get("status")
    if status_raw is None:
        raise EvmVerificationError("receipt missing status field")

    if isinstance(status_raw, bool):
        status_int = 1 if status_raw else 0
    elif isinstance(status_raw, str):
        if not re.fullmatch(r"0x[0-9a-fA-F]+|[0-9]+", status_raw.strip()):
            raise EvmVerificationError(f"invalid status format: {status_raw}")
        status_int = int(status_raw, 16) if status_raw.startswith("0x") else int(status_raw)
    elif isinstance(status_raw, int):
        status_int = status_raw
    else:
        raise EvmVerificationError(f"unsupported receipt status type: {type(status_raw)}")

    if status_int != 1:
        raise EvmVerificationError(f"transaction failed on-chain (status = {status_raw})")

    # Check receipt.to if present and expected_htlc_address is specified
    norm_expected_htlc = normalize_address(expected_htlc_address) if expected_htlc_address else None
    if norm_expected_htlc and "to" in receipt and receipt["to"]:
        rcpt_to = normalize_address(receipt["to"])
        if rcpt_to and rcpt_to.lower() != norm_expected_htlc.lower():
            raise EvmVerificationError(
                f"receipt 'to' address mismatch: expected {norm_expected_htlc}, got {rcpt_to}"
            )

    logs = receipt.get("logs", [])
    if not isinstance(logs, list) or len(logs) == 0:
        raise EvmVerificationError("transaction contains no event logs")

    norm_expected_cid = normalize_hex(expected_contract_id) if expected_contract_id else None

    matching_events: list[dict[str, Any]] = []

    for log in logs:
        if not isinstance(log, dict):
            continue
        log_addr = normalize_address(log.get("address"))
        if not log_addr:
            continue

        if norm_expected_htlc and log_addr.lower() != norm_expected_htlc.lower():
            continue

        topics = log.get("topics", [])
        if not isinstance(topics, list) or len(topics) == 0:
            continue

        topic0 = str(topics[0]).lower()
        data_hex = str(log.get("data", "")).lower()
        if data_hex.startswith("0x"):
            data_hex = data_hex[2:]

        # Extract block number safely
        raw_block = receipt.get("blockNumber", "0")
        block_number = int(raw_block, 16) if isinstance(raw_block, str) and raw_block.startswith("0x") else int(raw_block)

        # 1. Check Locked Event
        if topic0 == EVENT_LOCKED_TOPIC0:
            if len(topics) < 4:
                continue
            cid = normalize_hex(topics[1])
            payer = normalize_address("0x" + topics[2][-40:])
            payee = normalize_address("0x" + topics[3][-40:])

            if len(data_hex) < 256:  # 4 * 32 bytes (token, amount, hashlock, refundTimestamp)
                continue

            token = normalize_address("0x" + data_hex[24:64])
            amount = str(int(data_hex[64:128], 16))
            hashlock = normalize_hex("0x" + data_hex[128:192])
            refund_ts = int(data_hex[192:256], 16)

            matching_events.append({
                "event_type": "Locked",
                "contract_id": cid,
                "contract_address": log_addr,
                "payer_address": payer,
                "payee_address": payee,
                "token": token,
                "amount": amount,
                "hashlock": hashlock,
                "refund_timestamp": refund_ts,
                "block_number": block_number,
                "tx_hash": receipt.get("transactionHash"),
            })

        # 2. Check Claimed Event
        elif topic0 == EVENT_CLAIMED_TOPIC0:
            if len(topics) < 2:
                continue
            cid = normalize_hex(topics[1])
            if len(data_hex) < 64:
                continue
            secret = normalize_hex("0x" + data_hex[:64])

            matching_events.append({
                "event_type": "Claimed",
                "contract_id": cid,
                "contract_address": log_addr,
                "secret": secret,
                "block_number": block_number,
                "tx_hash": receipt.get("transactionHash"),
            })

        # 3. Check Refunded Event
        elif topic0 == EVENT_REFUNDED_TOPIC0:
            if len(topics) < 2:
                continue
            cid = normalize_hex(topics[1])

            matching_events.append({
                "event_type": "Refunded",
                "contract_id": cid,
                "contract_address": log_addr,
                "block_number": block_number,
                "tx_hash": receipt.get("transactionHash"),
            })

    if norm_expected_cid:
        matching_events = [e for e in matching_events if e["contract_id"] and e["contract_id"].lower() == norm_expected_cid.lower()]

    if expected_event_type:
        matching_events = [e for e in matching_events if e["event_type"].lower() == expected_event_type.lower()]

    if len(matching_events) == 0:
        if norm_expected_htlc:
            other_addrs = [log.get("address") for log in logs if isinstance(log, dict)]
            if other_addrs and not any(a and normalize_address(a) == norm_expected_htlc for a in other_addrs):
                raise EvmVerificationError(f"receipt logs address mismatch: expected {norm_expected_htlc}, found {other_addrs}")
        raise EvmVerificationError("no matching HTLC events found in transaction receipt")

    if len(matching_events) > 1:
        raise EvmVerificationError(f"ambiguous logs: found {len(matching_events)} matching HTLC events in single transaction")

    return matching_events[0]


def build_rpc_settlement_evidence(
    rpc_url: str,
    lock_tx: Optional[str] = None,
    claim_tx: Optional[str] = None,
    refund_tx: Optional[str] = None,
    expected_htlc_address: Optional[str] = None,
    expected_contract_id: Optional[str] = None,
    expected_chain_id: Optional[int] = None,
    timeout: float = 10.0,
) -> SettlementEvidence:
    """
    Fetches and verifies on-chain receipts from an EVM JSON-RPC provider and
    constructs a canonical `SettlementEvidence` with `provenance="rpc_receipt_verified"`.
    """
    if not lock_tx and not claim_tx and not refund_tx:
        raise EvmVerificationError("lock_tx is required for EVM settlement verification")

    # Lock receipt is mandatory: claim/refund alone cannot authenticate amount, token, payer, payee, hashlock
    if not lock_tx:
        raise EvmVerificationError("lock_tx is required when verifying claim_tx or refund_tx to authenticate escrow parameters")

    # Mandatory chain identity binding
    if expected_chain_id is None:
        raise EvmVerificationError("expected_chain_id is required for RPC settlement verification (specify --chain-id)")

    chain_id = fetch_chain_id(rpc_url, timeout=timeout)
    if chain_id != expected_chain_id:
        raise EvmVerificationError(
            f"chain ID mismatch: expected {expected_chain_id}, got {chain_id} from {rpc_url}"
        )

    lock_event: Optional[dict[str, Any]] = None
    claim_event: Optional[dict[str, Any]] = None
    refund_event: Optional[dict[str, Any]] = None

    if lock_tx:
        rcpt = fetch_transaction_receipt(rpc_url, lock_tx, timeout=timeout)
        lock_event = parse_and_verify_htlc_event(
            rcpt,
            expected_htlc_address=expected_htlc_address,
            expected_contract_id=expected_contract_id,
            expected_event_type="Locked",
        )

    contract_id = lock_event["contract_id"] if lock_event else (normalize_hex(expected_contract_id) or "")
    htlc_addr = lock_event["contract_address"] if lock_event else (normalize_address(expected_htlc_address))

    if claim_tx:
        rcpt = fetch_transaction_receipt(rpc_url, claim_tx, timeout=timeout)
        claim_event = parse_and_verify_htlc_event(
            rcpt,
            expected_htlc_address=htlc_addr,
            expected_contract_id=contract_id if contract_id else expected_contract_id,
            expected_event_type="Claimed",
        )
        if not contract_id and claim_event:
            contract_id = claim_event["contract_id"]
        if not htlc_addr and claim_event:
            htlc_addr = claim_event["contract_address"]

    if refund_tx:
        rcpt = fetch_transaction_receipt(rpc_url, refund_tx, timeout=timeout)
        refund_event = parse_and_verify_htlc_event(
            rcpt,
            expected_htlc_address=htlc_addr,
            expected_contract_id=contract_id if contract_id else expected_contract_id,
            expected_event_type="Refunded",
        )
        if not contract_id and refund_event:
            contract_id = refund_event["contract_id"]
        if not htlc_addr and refund_event:
            htlc_addr = refund_event["contract_address"]

    # Lifecycle Consistency & Ordering Checks
    if claim_event and refund_event:
        raise EvmVerificationError("inconsistent on-chain lifecycle: contract cannot be both Claimed and Refunded")

    if lock_event and claim_event:
        if claim_event["block_number"] < lock_event["block_number"]:
            raise EvmVerificationError(
                f"invalid lifecycle ordering: Claimed block ({claim_event['block_number']}) is earlier than Locked block ({lock_event['block_number']})"
            )

    if lock_event and refund_event:
        if refund_event["block_number"] < lock_event["block_number"]:
            raise EvmVerificationError(
                f"invalid lifecycle ordering: Refunded block ({refund_event['block_number']}) is earlier than Locked block ({lock_event['block_number']})"
            )

    status = "locked"
    secret = None
    if claim_event:
        status = "claimed"
        secret = claim_event.get("secret")
    elif refund_event:
        status = "refunded"

    amount = lock_event["amount"] if lock_event else "0"
    asset = lock_event["token"] if lock_event else "0x0000000000000000000000000000000000000000"
    hashlock = lock_event["hashlock"] if lock_event else ""
    payer = lock_event.get("payer_address") if lock_event else None
    payee = lock_event.get("payee_address") if lock_event else None
    refund_ts = lock_event.get("refund_timestamp") if lock_event else None
    block_num = claim_event["block_number"] if claim_event else (refund_event["block_number"] if refund_event else (lock_event["block_number"] if lock_event else None))

    return SettlementEvidence(
        rail="evm-htlc",
        contract_id=contract_id,
        amount=amount,
        asset=asset,
        hashlock=hashlock,
        settlement_status=status,
        provenance="rpc_receipt_verified",
        payer_address=payer,
        payee_address=payee,
        contract_address=htlc_addr,
        lock_timestamp=None,
        refund_timestamp=refund_ts,
        claim_timestamp=None,
        secret=secret,
        lock_tx=lock_tx,
        claim_tx=claim_tx,
        refund_tx=refund_tx,
        block_number=block_num,
        chain_id=chain_id,
    )

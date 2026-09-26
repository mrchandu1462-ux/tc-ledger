"""
End-to-End Local Anvil Integration Tests for TCLK-Proof Cross-Layer Verification.
Validates real EVM transactions, mined receipts, and Technocore transcript conformance.
Includes adversarial test cases for tampered amounts, hashlocks, contract IDs, and addresses.
"""

from __future__ import annotations

import base58
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Generator

import pytest
from jsonschema import validate
from nacl.signing import SigningKey

from tc_ledger.cross_verify import (
    canonical_json_bytes,
    domain_hash,
    keccak256,
    main as cross_verify_main,
    verify_cross_layer,
)


def _find_anvil_binary() -> str | None:
    if "ANVIL_PATH" in os.environ and os.path.exists(os.environ["ANVIL_PATH"]):
        return os.environ["ANVIL_PATH"]
    which = shutil.which("anvil")
    if which:
        return which
    user_prof = os.environ.get("USERPROFILE") or os.environ.get("HOME") or ""
    if user_prof:
        cand = Path(user_prof) / ".foundry" / "bin" / ("anvil.exe" if os.name == "nt" else "anvil")
        if cand.exists():
            return str(cand)
    return None


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        if "error" in res and res["error"]:
            raise RuntimeError(f"RPC error from {method}: {res['error']}")
        return res.get("result")


def _wait_for_receipt(url: str, tx_hash: str, max_retries: int = 30) -> dict[str, Any]:
    for _ in range(max_retries):
        rcpt = _rpc(url, "eth_getTransactionReceipt", [tx_hash])
        if rcpt and isinstance(rcpt, dict) and rcpt.get("blockNumber") is not None:
            return rcpt
        time.sleep(0.05)
    raise TimeoutError(f"Transaction receipt for {tx_hash} not found after {max_retries} attempts")


def _make_keypair():
    sk = SigningKey.generate()
    raw_pub = sk.verify_key.encode()
    multicodec = b"\xed\x01" + raw_pub
    did = "did:key:z" + base58.b58encode(multicodec).decode("ascii")
    return sk, did


def _sign_record(sk: SigningKey, did: str, room: str, text: str, seq: int = 1) -> dict[str, Any]:
    nonce = str(1000 + seq)
    canonical = f"{room}|{nonce}|{text}".encode("utf-8")
    sig_raw = sk.sign(canonical).signature
    sig_str = base64.urlsafe_b64encode(sig_raw).decode("ascii").rstrip("=")
    return {
        "seq": seq,
        "ts": 1700000000000 + seq * 1000,
        "from": did,
        "text": text,
        "nonce": nonce,
        "sig": sig_str,
    }


@pytest.fixture(scope="module")
def anvil_environment() -> Generator[dict[str, Any], None, None]:
    anvil_bin = _find_anvil_binary()
    if not anvil_bin:
        pytest.skip("anvil binary not found on system; skipping live EVM E2E tests")

    port = _get_free_port()
    proc = subprocess.Popen(
        [anvil_bin, "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    rpc_url = f"http://127.0.0.1:{port}"

    try:
        # Wait for Anvil to become responsive
        ready = False
        for _ in range(50):
            try:
                cid = _rpc(rpc_url, "eth_chainId", [])
                if cid:
                    ready = True
                    break
            except Exception:
                time.sleep(0.1)

        if not ready:
            pytest.fail(f"Failed to connect to Anvil on {rpc_url}")

        accounts = _rpc(rpc_url, "eth_accounts", [])
        payer_eth = accounts[0]
        payee_eth = accounts[1]

        # Deploy HTLC contract
        htlc_json_path = Path(__file__).resolve().parent.parent / "tclk-rail-evm/out/Htlc.sol/Htlc.json"
        if not htlc_json_path.exists():
            pytest.fail(f"HTLC compiled artifact not found at {htlc_json_path}")

        bytecode = json.loads(htlc_json_path.read_text(encoding="utf-8"))["bytecode"]["object"]
        deploy_tx = _rpc(rpc_url, "eth_sendTransaction", [{"from": payer_eth, "data": bytecode}])

        deploy_rcpt = _wait_for_receipt(rpc_url, deploy_tx)
        htlc_address = deploy_rcpt["contractAddress"]

        yield {
            "rpc_url": rpc_url,
            "chain_id": int(cid, 16),
            "htlc_address": htlc_address,
            "payer_eth": payer_eth,
            "payee_eth": payee_eth,
        }

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_e2e_tclk_proof_happy_path(anvil_environment: dict[str, Any], tmp_path: Path):
    env = anvil_environment
    rpc_url = env["rpc_url"]
    htlc_addr = env["htlc_address"]
    payer_eth = env["payer_eth"]
    payee_eth = env["payee_eth"]

    room = "test-e2e-happy-room"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    secret_bytes = bytes.fromhex("cafe" * 16)
    secret_hex = "0x" + secret_bytes.hex()
    hashlock_hex = "0x" + hashlib.sha256(secret_bytes).hexdigest()

    amount_str = "1000000000000000"  # 0.001 ETH
    amount_int = int(amount_str)
    refund_ts = int(time.time()) + 3600
    refund_after_ms = refund_ts * 1000

    offer_frame = {
        "type": "offer",
        "id": "offer-e2e-001",
        "role": "payer",
        "amount": amount_str,
        "asset": "0x0000000000000000000000000000000000000000",
        "lock": "hash",
        "claimByMs": refund_after_ms,
        "refundAfterMs": refund_after_ms,
        "expiresMs": refund_after_ms + 600000,
        "rails": ["evm-htlc"],
    }

    accept_frame = {
        "type": "accept",
        "ref": "offer-e2e-001",
        "statement": hashlock_hex,
        "nonce": "nonce-e2e-101",
    }

    accept_core = {
        "from": payee_did,
        "ref": "offer-e2e-001",
        "statement": hashlock_hex,
        "nonce": "nonce-e2e-101",
    }

    payload = {"offer": offer_frame, "accept": accept_core}
    cid_bytes = canonical_json_bytes(payload)
    contract_id = domain_hash("contract", cid_bytes)

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_frame), seq=2)

    export_file = tmp_path / f"{room}.jsonl"
    export_file.write_bytes(json.dumps(rec1).encode("utf-8") + b"\n" + json.dumps(rec2).encode("utf-8") + b"\n")

    # Real on-chain lock
    lock_selector = keccak256(b"lock(bytes32,address,address,uint256,bytes32,uint64)")[:4].hex()
    calldata_lock = (
        "0x" + lock_selector +
        contract_id[2:].rjust(64, "0") +
        payee_eth[2:].rjust(64, "0") +
        ("0" * 64) +
        hex(amount_int)[2:].rjust(64, "0") +
        hashlock_hex[2:].rjust(64, "0") +
        hex(refund_ts)[2:].rjust(64, "0")
    )
    lock_tx = _rpc(rpc_url, "eth_sendTransaction", [{
        "from": payer_eth,
        "to": htlc_addr,
        "data": calldata_lock,
        "value": hex(amount_int),
    }])
    _wait_for_receipt(rpc_url, lock_tx)

    # Real on-chain claim
    claim_selector = keccak256(b"claim(bytes32,bytes32)")[:4].hex()
    calldata_claim = (
        "0x" + claim_selector +
        contract_id[2:].rjust(64, "0") +
        secret_hex[2:].rjust(64, "0")
    )
    claim_tx = _rpc(rpc_url, "eth_sendTransaction", [{
        "from": payee_eth,
        "to": htlc_addr,
        "data": calldata_claim,
    }])
    _wait_for_receipt(rpc_url, claim_tx)

    # Execute verify_cross_layer against live Anvil RPC
    proof = verify_cross_layer(
        transcript_source=str(export_file),
        rpc_anchors={
            "rpc_url": rpc_url,
            "lock_tx": lock_tx,
            "claim_tx": claim_tx,
            "htlc_address": htlc_addr,
        },
        trust_anchors={
            "chain_id": env["chain_id"],
        },
    )

    # Validate schema
    schema_path = Path(__file__).resolve().parent.parent / "schemas/tclk-proof-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validate(instance=proof, schema=schema)

    # Assert mandatory cross-layer verification invariants
    assert proof["is_conformant"] is True
    assert proof["contract_id"] == contract_id
    assert proof["trust_model"]["on_chain_execution_proven"] is True
    assert proof["trust_model"]["transcript_authenticity"] is True
    assert proof["trust_model"]["terms_conformance"] is True
    assert proof["settlement"]["evidence_provenance"] == "rpc_receipt_verified"
    assert proof["settlement"]["status"] == "claimed"
    assert proof["settlement"]["secret_revealed"] == secret_hex
    assert proof["cross_check"]["contract_id_binding"] == "verified"
    assert proof["cross_check"]["hashlock_binding"] == "verified"
    assert proof["cross_check"]["amount_binding"] == "verified"
    assert proof["cross_check"]["asset_binding"] == "verified"
    assert proof["cross_check"]["secret_verification"] == "verified"
    assert proof["cross_check"]["temporal_ordering"] == "verified"
    assert proof["cross_check"]["on_chain_provenance"] == "verified"
    assert len(proof["failure_reasons"]) == 0


def test_e2e_tclk_proof_negative_tampered_amount(anvil_environment: dict[str, Any], tmp_path: Path):
    env = anvil_environment
    rpc_url = env["rpc_url"]
    htlc_addr = env["htlc_address"]
    payer_eth = env["payer_eth"]
    payee_eth = env["payee_eth"]

    room = "test-e2e-tamper-amt-room"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    secret_bytes = bytes.fromhex("beef" * 16)
    secret_hex = "0x" + secret_bytes.hex()
    hashlock_hex = "0x" + hashlib.sha256(secret_bytes).hexdigest()

    on_chain_amount_str = "1000000000000000"
    on_chain_amount_int = int(on_chain_amount_str)
    tampered_transcript_amount = "2000000000000000"  # Attacker changes transcript to claim 2x amount
    refund_ts = int(time.time()) + 3600
    refund_after_ms = refund_ts * 1000

    # Build on-chain contract with real amount
    offer_frame_chain = {
        "type": "offer",
        "id": "offer-e2e-amt",
        "role": "payer",
        "amount": on_chain_amount_str,
        "asset": "0x0000000000000000000000000000000000000000",
        "lock": "hash",
        "claimByMs": refund_after_ms,
        "refundAfterMs": refund_after_ms,
        "expiresMs": refund_after_ms + 600000,
        "rails": ["evm-htlc"],
    }
    accept_core_chain = {
        "from": payee_did,
        "ref": "offer-e2e-amt",
        "statement": hashlock_hex,
        "nonce": "nonce-amt-1",
    }
    contract_id = domain_hash("contract", canonical_json_bytes({"offer": offer_frame_chain, "accept": accept_core_chain}))

    # Submit lock on-chain
    lock_selector = keccak256(b"lock(bytes32,address,address,uint256,bytes32,uint64)")[:4].hex()
    calldata_lock = (
        "0x" + lock_selector +
        contract_id[2:].rjust(64, "0") +
        payee_eth[2:].rjust(64, "0") +
        ("0" * 64) +
        hex(on_chain_amount_int)[2:].rjust(64, "0") +
        hashlock_hex[2:].rjust(64, "0") +
        hex(refund_ts)[2:].rjust(64, "0")
    )
    lock_tx = _rpc(rpc_url, "eth_sendTransaction", [{
        "from": payer_eth,
        "to": htlc_addr,
        "data": calldata_lock,
        "value": hex(on_chain_amount_int),
    }])
    _wait_for_receipt(rpc_url, lock_tx)

    # Build tampered transcript where offer has tampered amount
    offer_frame_tampered = dict(offer_frame_chain)
    offer_frame_tampered["amount"] = tampered_transcript_amount
    accept_frame = {
        "type": "accept",
        "ref": "offer-e2e-amt",
        "statement": hashlock_hex,
        "nonce": "nonce-amt-1",
    }

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame_tampered), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_frame), seq=2)

    export_file = tmp_path / f"{room}.jsonl"
    export_file.write_bytes(json.dumps(rec1).encode("utf-8") + b"\n" + json.dumps(rec2).encode("utf-8") + b"\n")

    proof = verify_cross_layer(
        transcript_source=str(export_file),
        trust_anchors={"chain_id": env["chain_id"]},
        rpc_anchors={
            "rpc_url": rpc_url,
            "lock_tx": lock_tx,
            "htlc_address": htlc_addr,
        },
    )

    assert proof["is_conformant"] is False
    assert proof["cross_check"]["amount_binding"] == "mismatch"
    assert any("amount mismatch" in r for r in proof["failure_reasons"])


def test_e2e_tclk_proof_negative_tampered_hashlock(anvil_environment: dict[str, Any], tmp_path: Path):
    env = anvil_environment
    rpc_url = env["rpc_url"]
    htlc_addr = env["htlc_address"]
    payer_eth = env["payer_eth"]
    payee_eth = env["payee_eth"]

    room = "test-e2e-tamper-hashlock-room"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    secret_bytes = bytes.fromhex("12" * 32)
    hashlock_real = "0x" + hashlib.sha256(secret_bytes).hexdigest()
    hashlock_fake = "0x" + "ff" * 32

    amount_str = "1000000000000000"
    amount_int = int(amount_str)
    refund_ts = int(time.time()) + 3600
    refund_after_ms = refund_ts * 1000

    offer_frame = {
        "type": "offer",
        "id": "offer-e2e-hl",
        "role": "payer",
        "amount": amount_str,
        "asset": "0x0000000000000000000000000000000000000000",
        "lock": "hash",
        "claimByMs": refund_after_ms,
        "refundAfterMs": refund_after_ms,
        "expiresMs": refund_after_ms + 600000,
        "rails": ["evm-htlc"],
    }
    accept_core_chain = {
        "from": payee_did,
        "ref": "offer-e2e-hl",
        "statement": hashlock_real,
        "nonce": "nonce-hl-1",
    }
    contract_id = domain_hash("contract", canonical_json_bytes({"offer": offer_frame, "accept": accept_core_chain}))

    # Submit lock on-chain with real hashlock
    lock_selector = keccak256(b"lock(bytes32,address,address,uint256,bytes32,uint64)")[:4].hex()
    calldata_lock = (
        "0x" + lock_selector +
        contract_id[2:].rjust(64, "0") +
        payee_eth[2:].rjust(64, "0") +
        ("0" * 64) +
        hex(amount_int)[2:].rjust(64, "0") +
        hashlock_real[2:].rjust(64, "0") +
        hex(refund_ts)[2:].rjust(64, "0")
    )
    lock_tx = _rpc(rpc_url, "eth_sendTransaction", [{
        "from": payer_eth,
        "to": htlc_addr,
        "data": calldata_lock,
        "value": hex(amount_int),
    }])
    _wait_for_receipt(rpc_url, lock_tx)

    # Build tampered transcript where accept has fake hashlock
    accept_frame_fake = {
        "type": "accept",
        "ref": "offer-e2e-hl",
        "statement": hashlock_fake,
        "nonce": "nonce-hl-1",
    }

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_frame_fake), seq=2)

    export_file = tmp_path / f"{room}.jsonl"
    export_file.write_bytes(json.dumps(rec1).encode("utf-8") + b"\n" + json.dumps(rec2).encode("utf-8") + b"\n")

    proof = verify_cross_layer(
        transcript_source=str(export_file),
        trust_anchors={"chain_id": env["chain_id"]},
        rpc_anchors={
            "rpc_url": rpc_url,
            "lock_tx": lock_tx,
            "htlc_address": htlc_addr,
        },
    )

    assert proof["is_conformant"] is False
    assert proof["cross_check"]["hashlock_binding"] == "mismatch"
    assert any("hashlock mismatch" in r for r in proof["failure_reasons"])


def test_e2e_tclk_proof_negative_tampered_tx_hash(anvil_environment: dict[str, Any], tmp_path: Path):
    env = anvil_environment
    rpc_url = env["rpc_url"]
    htlc_addr = env["htlc_address"]
    payer_eth = env["payer_eth"]
    payee_eth = env["payee_eth"]

    room = "test-e2e-tamper-tx-room"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    secret_bytes = bytes.fromhex("77" * 32)
    hashlock = "0x" + hashlib.sha256(secret_bytes).hexdigest()
    amount_str = "1000000000000000"

    offer_frame = {
        "type": "offer",
        "id": "offer-e2e-tx",
        "role": "payer",
        "amount": amount_str,
        "asset": "0x0000000000000000000000000000000000000000",
        "lock": "hash",
        "claimByMs": 1700000600000,
        "refundAfterMs": 1700000600000,
        "expiresMs": 1700000900000,
        "rails": ["evm-htlc"],
    }
    accept_frame = {
        "type": "accept",
        "ref": "offer-e2e-tx",
        "statement": hashlock,
        "nonce": "nonce-tx-1",
    }
    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_frame), seq=2)

    export_file = tmp_path / f"{room}.jsonl"
    export_file.write_bytes(json.dumps(rec1).encode("utf-8") + b"\n" + json.dumps(rec2).encode("utf-8") + b"\n")

    fake_lock_tx = "0x" + "88" * 32
    proof = verify_cross_layer(
        transcript_source=str(export_file),
        trust_anchors={"chain_id": env["chain_id"]},
        rpc_anchors={
            "rpc_url": rpc_url,
            "lock_tx": fake_lock_tx,
            "htlc_address": htlc_addr,
        },
    )

    assert proof["is_conformant"] is False
    assert any("transaction receipt not found" in r for r in proof["failure_reasons"])


def test_e2e_tclk_proof_negative_mismatched_htlc_address(anvil_environment: dict[str, Any], tmp_path: Path):
    env = anvil_environment
    rpc_url = env["rpc_url"]
    real_htlc = env["htlc_address"]
    payer_eth = env["payer_eth"]
    payee_eth = env["payee_eth"]

    room = "test-e2e-mismatch-addr-room"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    secret_bytes = bytes.fromhex("44" * 32)
    hashlock = "0x" + hashlib.sha256(secret_bytes).hexdigest()
    amount_str = "1000000000000000"
    amount_int = int(amount_str)
    refund_ts = int(time.time()) + 3600

    offer_frame = {
        "type": "offer",
        "id": "offer-e2e-addr",
        "role": "payer",
        "amount": amount_str,
        "asset": "0x0000000000000000000000000000000000000000",
        "lock": "hash",
        "claimByMs": refund_ts * 1000,
        "refundAfterMs": refund_ts * 1000,
        "expiresMs": (refund_ts + 600) * 1000,
        "rails": ["evm-htlc"],
    }
    accept_core = {
        "from": payee_did,
        "ref": "offer-e2e-addr",
        "statement": hashlock,
        "nonce": "nonce-addr-1",
    }
    contract_id = domain_hash("contract", canonical_json_bytes({"offer": offer_frame, "accept": accept_core}))

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps({"type": "accept", "ref": "offer-e2e-addr", "statement": hashlock, "nonce": "nonce-addr-1"}), seq=2)

    export_file = tmp_path / f"{room}.jsonl"
    export_file.write_bytes(json.dumps(rec1).encode("utf-8") + b"\n" + json.dumps(rec2).encode("utf-8") + b"\n")

    lock_selector = keccak256(b"lock(bytes32,address,address,uint256,bytes32,uint64)")[:4].hex()
    calldata_lock = (
        "0x" + lock_selector +
        contract_id[2:].rjust(64, "0") +
        payee_eth[2:].rjust(64, "0") +
        ("0" * 64) +
        hex(amount_int)[2:].rjust(64, "0") +
        hashlock[2:].rjust(64, "0") +
        hex(refund_ts)[2:].rjust(64, "0")
    )
    lock_tx = _rpc(rpc_url, "eth_sendTransaction", [{
        "from": payer_eth,
        "to": real_htlc,
        "data": calldata_lock,
        "value": hex(amount_int),
    }])
    _wait_for_receipt(rpc_url, lock_tx)

    # Provide fake HTLC contract address
    fake_htlc_addr = "0x" + "1" * 40
    proof = verify_cross_layer(
        transcript_source=str(export_file),
        trust_anchors={"chain_id": env["chain_id"]},
        rpc_anchors={
            "rpc_url": rpc_url,
            "lock_tx": lock_tx,
            "htlc_address": fake_htlc_addr,
        },
    )

    assert proof["is_conformant"] is False
    assert any("mismatch" in r or "no matching HTLC events" in r for r in proof["failure_reasons"])


def test_e2e_tclk_proof_cli_verify_clean_syntax(anvil_environment: dict[str, Any], tmp_path: Path):
    env = anvil_environment
    rpc_url = env["rpc_url"]
    htlc_addr = env["htlc_address"]
    payer_eth = env["payer_eth"]
    payee_eth = env["payee_eth"]

    room = "test-e2e-cli-syntax-room"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    secret_bytes = bytes.fromhex("33" * 32)
    secret_hex = "0x" + secret_bytes.hex()
    hashlock_hex = "0x" + hashlib.sha256(secret_bytes).hexdigest()

    amount_str = "500000000000000"
    amount_int = int(amount_str)
    refund_ts = int(time.time()) + 3600
    refund_after_ms = refund_ts * 1000

    offer_frame = {
        "type": "offer",
        "id": "offer-cli-001",
        "role": "payer",
        "amount": amount_str,
        "asset": "0x0000000000000000000000000000000000000000",
        "lock": "hash",
        "claimByMs": refund_after_ms,
        "refundAfterMs": refund_after_ms,
        "expiresMs": refund_after_ms + 600000,
        "rails": ["evm-htlc"],
    }
    accept_frame = {
        "type": "accept",
        "ref": "offer-cli-001",
        "statement": hashlock_hex,
        "nonce": "nonce-cli-101",
    }
    accept_core = {
        "from": payee_did,
        "ref": "offer-cli-001",
        "statement": hashlock_hex,
        "nonce": "nonce-cli-101",
    }

    contract_id = domain_hash("contract", canonical_json_bytes({"offer": offer_frame, "accept": accept_core}))

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_frame), seq=2)

    export_file = tmp_path / f"{room}.jsonl"
    export_file.write_bytes(json.dumps(rec1).encode("utf-8") + b"\n" + json.dumps(rec2).encode("utf-8") + b"\n")

    # Lock & claim on Anvil
    lock_selector = keccak256(b"lock(bytes32,address,address,uint256,bytes32,uint64)")[:4].hex()
    calldata_lock = (
        "0x" + lock_selector +
        contract_id[2:].rjust(64, "0") +
        payee_eth[2:].rjust(64, "0") +
        ("0" * 64) +
        hex(amount_int)[2:].rjust(64, "0") +
        hashlock_hex[2:].rjust(64, "0") +
        hex(refund_ts)[2:].rjust(64, "0")
    )
    lock_tx = _rpc(rpc_url, "eth_sendTransaction", [{
        "from": payer_eth,
        "to": htlc_addr,
        "data": calldata_lock,
        "value": hex(amount_int),
    }])
    _wait_for_receipt(rpc_url, lock_tx)

    claim_selector = keccak256(b"claim(bytes32,bytes32)")[:4].hex()
    calldata_claim = (
        "0x" + claim_selector +
        contract_id[2:].rjust(64, "0") +
        secret_hex[2:].rjust(64, "0")
    )
    claim_tx = _rpc(rpc_url, "eth_sendTransaction", [{
        "from": payee_eth,
        "to": htlc_addr,
        "data": calldata_claim,
    }])
    _wait_for_receipt(rpc_url, claim_tx)

    out_json = tmp_path / "cli_proof.json"

    # Test clean syntax CLI execution: uv run tclk-proof verify --transcript ...
    cli_args = [
        "verify",
        "--transcript", str(export_file),
        "--rpc-url", rpc_url,
        "--lock-tx", lock_tx,
        "--claim-tx", claim_tx,
        "--htlc-address", htlc_addr,
        "--chain-id", str(env["chain_id"]),
        "--output", str(out_json),
        "--json",
    ]

    ret = cross_verify_main(cli_args)
    assert ret == 0, f"Expected CLI returncode 0, got {ret}"
    assert out_json.exists()

    proof_data = json.loads(out_json.read_text(encoding="utf-8"))
    assert proof_data["is_conformant"] is True
    assert proof_data["contract_id"] == contract_id

    # Test CLI --report execution against live Anvil RPC
    cli_report_args = [
        "verify",
        "--transcript", str(export_file),
        "--rpc-url", rpc_url,
        "--lock-tx", lock_tx,
        "--claim-tx", claim_tx,
        "--htlc-address", htlc_addr,
        "--chain-id", str(env["chain_id"]),
        "--report",
    ]
    ret_rep = cross_verify_main(cli_report_args)
    assert ret_rep == 0

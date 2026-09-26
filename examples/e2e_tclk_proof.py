#!/usr/bin/env python3
"""
Reproducible End-to-End TCLK-Proof Demo on local Anvil EVM.
Executes:
1. Technocore signed transcript generation
2. Agreement reconstruction
3. Local Anvil startup & Htlc.sol deployment
4. On-chain lock transaction & receipt
5. On-chain claim transaction & receipt
6. Cross-layer RPC receipt verification
7. Canonical proof.json generation & validation
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
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

from jsonschema import validate
from nacl.signing import SigningKey

from tc_ledger.cross_verify import (
    canonical_json_bytes,
    domain_hash,
    format_verification_report,
    keccak256,
    verify_cross_layer,
)


def find_anvil_binary() -> str | None:
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


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rpc_call(url: str, method: str, params: list[Any], timeout: float = 10.0) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        if "error" in res and res["error"]:
            raise RuntimeError(f"RPC error from {method}: {res['error']}")
        return res.get("result")


def wait_for_receipt(url: str, tx_hash: str, max_retries: int = 40) -> dict[str, Any]:
    for _ in range(max_retries):
        rcpt = rpc_call(url, "eth_getTransactionReceipt", [tx_hash])
        if rcpt and isinstance(rcpt, dict) and rcpt.get("blockNumber") is not None:
            return rcpt
        time.sleep(0.05)
    raise TimeoutError(f"Transaction receipt for {tx_hash} not found after {max_retries} attempts")


def make_keypair():
    sk = SigningKey.generate()
    raw_pub = sk.verify_key.encode()
    multicodec = b"\xed\x01" + raw_pub
    did = "did:key:z" + base58.b58encode(multicodec).decode("ascii")
    return sk, did


def sign_record(sk: SigningKey, did: str, room: str, text: str, seq: int = 1) -> dict[str, Any]:
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


def run_demo() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    output_dir = repo_root / "examples/output"
    output_dir.mkdir(parents=True, exist_ok=True)
    proof_path = output_dir / "proof.json"
    transcript_path = output_dir / "anvil_demo_room.jsonl"

    anvil_bin = find_anvil_binary()
    if not anvil_bin:
        print("Error: Anvil binary not found. Please install Foundry or set ANVIL_PATH.", file=sys.stderr)
        return 1

    port = get_free_port()
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
                cid_hex = rpc_call(rpc_url, "eth_chainId", [])
                if cid_hex:
                    ready = True
                    break
            except Exception:
                time.sleep(0.1)

        if not ready:
            print(f"Error: Failed to connect to Anvil on {rpc_url}", file=sys.stderr)
            return 1

        chain_id = int(cid_hex, 16)
        accounts = rpc_call(rpc_url, "eth_accounts", [])
        payer_eth = accounts[0]
        payee_eth = accounts[1]

        # Deploy HTLC contract
        htlc_json_path = repo_root / "tclk-rail-evm/out/Htlc.sol/Htlc.json"
        if not htlc_json_path.exists():
            print(f"Error: HTLC artifact missing at {htlc_json_path}. Run 'forge build' in tclk-rail-evm.", file=sys.stderr)
            return 1

        bytecode = json.loads(htlc_json_path.read_text(encoding="utf-8"))["bytecode"]["object"]
        deploy_tx = rpc_call(rpc_url, "eth_sendTransaction", [{"from": payer_eth, "data": bytecode}])
        deploy_rcpt = wait_for_receipt(rpc_url, deploy_tx)
        htlc_address = deploy_rcpt["contractAddress"]

        # 1. Deterministic Technocore Deal Agreement & Transcript
        room = "anvil_demo_room"
        payer_sk, payer_did = make_keypair()
        payee_sk, payee_did = make_keypair()

        secret_bytes = bytes.fromhex("42" * 32)
        secret_hex = "0x" + secret_bytes.hex()
        hashlock_hex = "0x" + hashlib.sha256(secret_bytes).hexdigest()

        amount_str = "1000000000000000"  # 0.001 ETH
        amount_int = int(amount_str)
        refund_ts = int(time.time()) + 3600
        refund_after_ms = refund_ts * 1000

        offer_frame = {
            "type": "offer",
            "id": "offer-anvil-demo",
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
            "ref": "offer-anvil-demo",
            "statement": hashlock_hex,
            "nonce": "nonce-demo-42",
        }

        accept_core = {
            "from": payee_did,
            "ref": "offer-anvil-demo",
            "statement": hashlock_hex,
            "nonce": "nonce-demo-42",
        }

        payload = {"offer": offer_frame, "accept": accept_core}
        contract_id = domain_hash("contract", canonical_json_bytes(payload))

        rec1 = sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
        rec2 = sign_record(payee_sk, payee_did, room, json.dumps(accept_frame), seq=2)

        transcript_path.write_bytes(
            json.dumps(rec1).encode("utf-8") + b"\n" + json.dumps(rec2).encode("utf-8") + b"\n"
        )

        # 2. Real on-chain lock transaction
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
        lock_tx = rpc_call(rpc_url, "eth_sendTransaction", [{
            "from": payer_eth,
            "to": htlc_address,
            "data": calldata_lock,
            "value": hex(amount_int),
        }])
        wait_for_receipt(rpc_url, lock_tx)

        # 3. Real on-chain claim transaction
        claim_selector = keccak256(b"claim(bytes32,bytes32)")[:4].hex()
        calldata_claim = (
            "0x" + claim_selector +
            contract_id[2:].rjust(64, "0") +
            secret_hex[2:].rjust(64, "0")
        )
        claim_tx = rpc_call(rpc_url, "eth_sendTransaction", [{
            "from": payee_eth,
            "to": htlc_address,
            "data": calldata_claim,
        }])
        wait_for_receipt(rpc_url, claim_tx)

        # 4. Cross-layer verification
        proof = verify_cross_layer(
            transcript_source=str(transcript_path),
            rpc_anchors={
                "rpc_url": rpc_url,
                "lock_tx": lock_tx,
                "claim_tx": claim_tx,
                "htlc_address": htlc_address,
            },
            trust_anchors={
                "chain_id": chain_id,
            },
        )

        # 5. Validate schema and write proof.json
        schema_path = repo_root / "schemas/tclk-proof-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validate(instance=proof, schema=schema)

        proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")

        # 6. Output clean verification summary and full report
        report = format_verification_report(proof, trust_anchors={"chain_id": chain_id})
        print(report)
        print("")

        return 0 if proof["is_conformant"] else 1

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    sys.exit(run_demo())

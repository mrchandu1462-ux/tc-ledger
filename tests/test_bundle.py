"""
Comprehensive Adversarial Tests for Portable Self-Contained .tclk-bundle Archives.
Validates bundle creation, offline verification, checksums, and fail-closed security invariants.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from tc_ledger.bundle import (
    create_bundle,
    verify_bundle,
    load_tclk_bundle_schema,
)
from tc_ledger.cross_verify import main as tclk_proof_main


import base58
import base64
import hashlib
from nacl.signing import SigningKey
from tc_ledger.cross_verify import canonical_json_bytes, domain_hash
from tc_ledger.evm_verifier import (
    EVENT_LOCKED_TOPIC0,
    EVENT_CLAIMED_TOPIC0,
    EVENT_ERC20_TRANSFER_TOPIC0,
)


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


def _make_locked_log(htlc_addr, cid, payer, payee, token, amount, hashlock, refund_ts):
    data_hex = (
        "0x"
        + "0" * 24 + token.lower().replace("0x", "")
        + hex(amount)[2:].zfill(64)
        + hashlock.lower().replace("0x", "")
        + hex(refund_ts)[2:].zfill(64)
    )
    return {
        "address": htlc_addr,
        "topics": [
            EVENT_LOCKED_TOPIC0,
            cid.lower(),
            "0x" + "0" * 24 + payer.lower().replace("0x", ""),
            "0x" + "0" * 24 + payee.lower().replace("0x", ""),
        ],
        "data": data_hex,
    }


def _make_erc20_transfer_log(token_addr, from_addr, to_addr, amount):
    return {
        "address": token_addr,
        "topics": [
            EVENT_ERC20_TRANSFER_TOPIC0,
            "0x" + "0" * 24 + from_addr.lower().replace("0x", ""),
            "0x" + "0" * 24 + to_addr.lower().replace("0x", ""),
        ],
        "data": "0x" + hex(amount)[2:].zfill(64),
    }


import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockRpcServer:
    """Lightweight in-memory JSON-RPC mock server for deterministic testing."""

    def __init__(self, receipts: dict[str, Any], fail_http: bool = False, rpc_error: str = ""):
        self.receipts = receipts
        self.fail_http = fail_http
        self.rpc_error = rpc_error
        self.httpd: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.port: int = 0

    def start(self):
        receipts_ref = self.receipts
        fail_http_ref = self.fail_http
        rpc_error_ref = self.rpc_error

        class RequestHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                if fail_http_ref:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"Internal Server Error")
                    return

                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode("utf-8")
                req = json.loads(body)
                req_id = req.get("id", 1)
                method = req.get("method")
                params = req.get("params", [])

                if rpc_error_ref:
                    res = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": rpc_error_ref}}
                elif method == "eth_chainId":
                    res = {"jsonrpc": "2.0", "id": req_id, "result": "0x7a69"}  # default 31337
                elif method == "eth_getTransactionReceipt":
                    tx_hash = params[0] if params else ""
                    res_val = receipts_ref.get(tx_hash.lower())
                    res = {"jsonrpc": "2.0", "id": req_id, "result": res_val}
                else:
                    res = {"jsonrpc": "2.0", "id": req_id, "result": None}

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(res).encode("utf-8"))

            def log_message(self, format, *args):
                pass  # Silence stderr logs

        self.httpd = HTTPServer(("127.0.0.1", 0), RequestHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def _build_test_bundle_data(tmp_path: Path):
    """Helper to generate a clean, valid test bundle with mock transcript and receipts."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    room = "room:test-bundle-123"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    token_addr = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    htlc_addr = "0x1111111111111111111111111111111111111111"
    payer_addr = "0x2222222222222222222222222222222222222222"
    payee_addr = "0x3333333333333333333333333333333333333333"
    amount = 5000000

    secret_preimage = "0x" + "7" * 64
    secret_bytes = bytes.fromhex("7" * 64)
    hashlock = "0x" + hashlib.sha256(secret_bytes).hexdigest()

    offer_frame = {
        "type": "offer",
        "id": "offer-bundle-001",
        "role": "payer",
        "amount": str(amount),
        "asset": token_addr,
        "lock": "hash",
        "claimByMs": 1700000600000,
        "refundAfterMs": 1700000600000,
        "expiresMs": 1700000900000,
        "rails": ["evm-htlc"],
    }

    accept_frame = {
        "type": "accept",
        "ref": "offer-bundle-001",
        "statement": hashlock,
        "nonce": "nonce-bundle-1",
    }

    accept_core = {
        "from": payee_did,
        "ref": "offer-bundle-001",
        "statement": hashlock,
        "nonce": "nonce-bundle-1",
    }

    payload = {"offer": offer_frame, "accept": accept_core}
    cid_bytes = canonical_json_bytes(payload)
    contract_id = domain_hash("contract", cid_bytes)

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_frame), seq=2)

    transcript_path = tmp_path / "transcript.jsonl"
    transcript_path.write_bytes(b"".join([
        json.dumps(rec1).encode("utf-8") + b"\n",
        json.dumps(rec2).encode("utf-8") + b"\n",
    ]))

    lock_tx = "0x" + "2" * 64
    claim_tx = "0x" + "3" * 64

    locked_log = _make_locked_log(
        htlc_addr=htlc_addr,
        cid=contract_id,
        payer=payer_addr,
        payee=payee_addr,
        token=token_addr,
        amount=amount,
        hashlock=hashlock,
        refund_ts=1700000600,
    )
    transfer_log = _make_erc20_transfer_log(
        token_addr=token_addr,
        from_addr=payer_addr,
        to_addr=htlc_addr,
        amount=amount,
    )
    claimed_log = {
        "address": htlc_addr,
        "topics": [EVENT_CLAIMED_TOPIC0, contract_id.lower()],
        "data": "0x" + secret_preimage[2:],
    }

    receipts = {
        lock_tx.lower(): {
            "status": "0x1",
            "transactionHash": lock_tx,
            "blockNumber": "0x10",
            "logs": [transfer_log, locked_log],
        },
        claim_tx.lower(): {
            "status": "0x1",
            "transactionHash": claim_tx,
            "blockNumber": "0x11",
            "logs": [claimed_log],
        },
    }

    server = MockRpcServer(receipts)
    server.start()

    bundle_path = tmp_path / "deal.tclk-bundle"
    try:
        manifest, bundle_bytes = create_bundle(
            transcript_source=transcript_path,
            trust_anchors={"room": room, "chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": lock_tx,
                "claim_tx": claim_tx,
                "htlc_address": htlc_addr,
                "chain_id": 31337,
            },
            output_path=bundle_path,
        )
    finally:
        server.stop()

    return {
        "transcript_path": transcript_path,
        "bundle_path": bundle_path,
        "bundle_bytes": bundle_bytes,
        "manifest": manifest,
        "room": room,
        "contract_id": contract_id,
        "receipts": receipts,
        "lock_tx": lock_tx,
        "claim_tx": claim_tx,
        "htlc_addr": htlc_addr,
    }



def _mutate_zip_member(bundle_bytes: bytes, target_filename: str, new_content: bytes) -> bytes:
    """Helper to rewrite a single member in a ZIP archive without altering manifest."""
    zin = zipfile.ZipFile(io.BytesIO(bundle_bytes), mode="r")
    zout_buf = io.BytesIO()
    with zipfile.ZipFile(zout_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == target_filename:
                zout.writestr(item.filename, new_content)
            else:
                zout.writestr(item.filename, zin.read(item.filename))
    return zout_buf.getvalue()


# 1. Happy Path: Valid Bundle Creation & Offline Verification
def test_valid_bundle_offline_verification(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    res = verify_bundle(data["bundle_path"], trust_anchors={"room": data["room"]})
    assert res["valid"] is True
    assert res["is_conformant"] is True
    assert res["manifest_verified"] is True
    assert res["receipts_verified"] is True
    assert res["proof_verified"] is True
    assert len(res["failure_reasons"]) == 0


# 2. Tampered Transcript: Checksum & Content Mismatch
def test_bundle_tampered_transcript(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    tampered_zip = _mutate_zip_member(data["bundle_bytes"], "transcript.jsonl", b'{"tampered": true}\n')

    res = verify_bundle(tampered_zip)
    assert res["valid"] is False
    assert res["manifest_verified"] is False
    assert any("checksum mismatch for 'transcript.jsonl'" in r for r in res["failure_reasons"])


# 3. Tampered Receipt: Checksum Mismatch
def test_bundle_tampered_receipts(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    tampered_zip = _mutate_zip_member(data["bundle_bytes"], "receipts.json", b'{"tampered": true}\n')

    res = verify_bundle(tampered_zip)
    assert res["valid"] is False
    assert res["manifest_verified"] is False
    assert any("checksum mismatch for 'receipts.json'" in r for r in res["failure_reasons"])


# 4. Tampered Proof: Checksum Mismatch
def test_bundle_tampered_proof(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    tampered_zip = _mutate_zip_member(data["bundle_bytes"], "proof.json", b'{"spec": "tclk-proof/1", "tampered": true}\n')

    res = verify_bundle(tampered_zip)
    assert res["valid"] is False
    assert res["manifest_verified"] is False
    assert any("checksum mismatch for 'proof.json'" in r for r in res["failure_reasons"])


# 5. Tampered Report: Checksum Mismatch
def test_bundle_tampered_report(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    tampered_zip = _mutate_zip_member(data["bundle_bytes"], "report.txt", b"TAMPERED REPORT\n")

    res = verify_bundle(tampered_zip)
    assert res["valid"] is False
    assert res["manifest_verified"] is False
    assert any("checksum mismatch for 'report.txt'" in r for r in res["failure_reasons"])


# 6. Tampered Manifest Checksum: Forged Checksum in manifest.json
def test_bundle_tampered_manifest_checksum(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    zin = zipfile.ZipFile(io.BytesIO(data["bundle_bytes"]), mode="r")
    manifest = json.loads(zin.read("manifest.json").decode("utf-8"))
    manifest["files"]["proof.json"]["sha256"] = "0" * 64

    tampered_manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    tampered_zip = _mutate_zip_member(data["bundle_bytes"], "manifest.json", tampered_manifest_bytes)

    res = verify_bundle(tampered_zip)
    assert res["valid"] is False
    assert res["manifest_verified"] is False
    assert any("checksum mismatch for 'proof.json'" in r for r in res["failure_reasons"])


# 7. Missing Required Member (e.g. missing receipts.json)
def test_bundle_missing_member(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    zin = zipfile.ZipFile(io.BytesIO(data["bundle_bytes"]), mode="r")
    zout_buf = io.BytesIO()
    with zipfile.ZipFile(zout_buf, mode="w") as zout:
        for item in zin.infolist():
            if item.filename != "receipts.json":
                zout.writestr(item.filename, zin.read(item.filename))

    res = verify_bundle(zout_buf.getvalue())
    assert res["valid"] is False
    assert any("missing required bundle file: 'receipts.json'" in r for r in res["failure_reasons"])


# 8. Unexpected / Extraneous Member (e.g. malware.exe)
def test_bundle_unexpected_member(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    zin = zipfile.ZipFile(io.BytesIO(data["bundle_bytes"]), mode="r")
    zout_buf = io.BytesIO()
    with zipfile.ZipFile(zout_buf, mode="w") as zout:
        for item in zin.infolist():
            zout.writestr(item.filename, zin.read(item.filename))
        zout.writestr("unexpected_payload.bin", b"evil")

    res = verify_bundle(zout_buf.getvalue())
    assert res["valid"] is False
    assert any("unexpected archive member: 'unexpected_payload.bin'" in r for r in res["failure_reasons"])


# 9. Path Traversal in Archive Member Name
@pytest.mark.parametrize("bad_name", [
    "../etc/passwd",
    "../../transcript.jsonl",
    "/absolute/path/file",
    "subfolder/proof.json",
    "C:\\bad_windows_path.json",
])
def test_bundle_path_traversal_rejected(tmp_path, bad_name):
    data = _build_test_bundle_data(tmp_path)
    zin = zipfile.ZipFile(io.BytesIO(data["bundle_bytes"]), mode="r")
    zout_buf = io.BytesIO()
    with zipfile.ZipFile(zout_buf, mode="w") as zout:
        for item in zin.infolist():
            if item.filename == "transcript.jsonl":
                zout.writestr(bad_name, zin.read(item.filename))
            else:
                zout.writestr(item.filename, zin.read(item.filename))

    res = verify_bundle(zout_buf.getvalue())
    assert res["valid"] is False
    assert any("path traversal" in r or "illegal characters" in r for r in res["failure_reasons"])


# 10. Malformed Manifest JSON
def test_bundle_malformed_manifest(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    tampered_zip = _mutate_zip_member(data["bundle_bytes"], "manifest.json", b"{ malformed: json [")

    res = verify_bundle(tampered_zip)
    assert res["valid"] is False
    assert any("malformed manifest.json" in r for r in res["failure_reasons"])


# 11. Deterministic Archive Generation
def test_bundle_deterministic_generation(tmp_path):
    data1 = _build_test_bundle_data(tmp_path / "run1")

    server = MockRpcServer(data1["receipts"])
    server.start()
    try:
        _, bytes1 = create_bundle(
            transcript_source=data1["transcript_path"],
            trust_anchors={"room": data1["room"], "chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": data1["lock_tx"],
                "claim_tx": data1["claim_tx"],
                "htlc_address": data1["htlc_addr"],
                "chain_id": 31337,
            },
        )
        _, bytes2 = create_bundle(
            transcript_source=data1["transcript_path"],
            trust_anchors={"room": data1["room"], "chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": data1["lock_tx"],
                "claim_tx": data1["claim_tx"],
                "htlc_address": data1["htlc_addr"],
                "chain_id": 31337,
            },
        )
    finally:
        server.stop()

    m1 = json.loads(zipfile.ZipFile(io.BytesIO(bytes1)).read("manifest.json").decode("utf-8"))
    m2 = json.loads(zipfile.ZipFile(io.BytesIO(bytes2)).read("manifest.json").decode("utf-8"))
    assert m1["files"] == m2["files"]


# 12. CLI Contract: Valid Bundle -> Exit Code 0
def test_cli_verify_bundle_valid(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    code = tclk_proof_main(["verify-bundle", str(data["bundle_path"]), "--room", data["room"]])
    assert code == 0


# 13. CLI Contract: Non-Conformant Deal Terms -> Exit Code 1
def test_cli_verify_bundle_non_conformant_terms(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    # Trust anchor mismatch (e.g. wrong room) makes proof valid but non-conformant
    code = tclk_proof_main(["verify-bundle", str(data["bundle_path"]), "--room", "wrong-room"])
    assert code == 1


# 14. CLI Contract: Tampered / Corrupted Archive -> Exit Code 2
def test_cli_verify_bundle_tampered_exit_code_2(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    tampered_zip = _mutate_zip_member(data["bundle_bytes"], "proof.json", b"TAMPERED PROOF")
    bad_bundle_path = tmp_path / "bad.tclk-bundle"
    bad_bundle_path.write_bytes(tampered_zip)

    code = tclk_proof_main(["verify-bundle", str(bad_bundle_path)])
    assert code == 2


# 15. CLI Contract: Missing File / Bad Invocation -> Exit Code 2
def test_cli_verify_bundle_missing_file_exit_code_2(tmp_path):
    code = tclk_proof_main(["verify-bundle", str(tmp_path / "nonexistent.tclk-bundle")])
    assert code == 2
    code_no_args = tclk_proof_main(["verify-bundle"])
    assert code_no_args == 2


# 16. CLI Command: tclk-proof bundle --transcript ... --rpc-url ... --output ...
def test_cli_create_bundle(tmp_path):
    data = _build_test_bundle_data(tmp_path)
    out_bundle = tmp_path / "cli_created.tclk-bundle"

    server = MockRpcServer(data["receipts"])
    server.start()
    try:
        code = tclk_proof_main([
            "bundle",
            str(data["transcript_path"]),
            "--rpc-url", server.url,
            "--lock-tx", data["lock_tx"],
            "--claim-tx", data["claim_tx"],
            "--htlc-address", data["htlc_addr"],
            "--output", str(out_bundle),
            "--room", data["room"],
            "--chain-id", "31337",
        ])
    finally:
        server.stop()

    assert code == 0
    assert out_bundle.is_file()

    # Verify bundle is 100% offline (server already stopped)
    verify_code = tclk_proof_main(["verify-bundle", str(out_bundle), "--room", data["room"]])
    assert verify_code == 0


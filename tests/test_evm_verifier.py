"""
Adversarial and Unit Tests for EVM JSON-RPC Receipt Verification Layer.
Tests receipt parsing, event extraction, trust model elevation, lifecycle consistency,
and adversarial fault injection.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

from tc_ledger.cross_verify import (
    canonical_json_bytes,
    domain_hash,
    verify_cross_layer,
    main as cross_verify_main,
)
from tc_ledger.evm_verifier import (
    EVENT_LOCKED_TOPIC0,
    EVENT_CLAIMED_TOPIC0,
    EVENT_REFUNDED_TOPIC0,
    EvmVerificationError,
    build_rpc_settlement_evidence,
    fetch_transaction_receipt,
    parse_and_verify_htlc_event,
)
import base58
import base64

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
                    res = {"jsonrpc": "2.0", "id": req_id, "result": getattr(self.server, "chain_id_hex", "0x7a69")}  # default 31337 (Anvil)
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
        self.httpd.chain_id_hex = getattr(self, "chain_id_hex", "0x7a69")
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


def _make_locked_log(
    htlc_address: str,
    contract_id: str,
    payer: str,
    payee: str,
    token: str,
    amount: int,
    hashlock: str,
    refund_timestamp: int,
) -> dict[str, Any]:
    norm_cid = contract_id.lower()
    norm_payer = "0x" + "0" * 24 + payer.lower().replace("0x", "")
    norm_payee = "0x" + "0" * 24 + payee.lower().replace("0x", "")
    data_hex = (
        "0x"
        + "0" * 24 + token.lower().replace("0x", "")
        + hex(amount)[2:].zfill(64)
        + hashlock.lower().replace("0x", "")
        + hex(refund_timestamp)[2:].zfill(64)
    )
    return {
        "address": htlc_address,
        "topics": [EVENT_LOCKED_TOPIC0, norm_cid, norm_payer, norm_payee],
        "data": data_hex,
    }


def _make_claimed_log(htlc_address: str, contract_id: str, secret: str) -> dict[str, Any]:
    return {
        "address": htlc_address,
        "topics": [EVENT_CLAIMED_TOPIC0, contract_id.lower()],
        "data": "0x" + secret.lower().replace("0x", ""),
    }


def _make_refunded_log(htlc_address: str, contract_id: str) -> dict[str, Any]:
    return {
        "address": htlc_address,
        "topics": [EVENT_REFUNDED_TOPIC0, contract_id.lower()],
        "data": "0x",
    }


@pytest.fixture
def mock_deal_transcript(tmp_path: Path):
    room = "test-evm-receipt-room"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    secret_preimage = "0x" + "a" * 64
    secret_bytes = bytes.fromhex("a" * 64)
    import hashlib
    hashlock = "0x" + hashlib.sha256(secret_bytes).hexdigest()

    offer_frame = {
        "type": "offer",
        "id": "offer-evm-001",
        "role": "payer",
        "amount": "2500000",
        "asset": "0x0000000000000000000000000000000000000000",
        "lock": "hash",
        "claimByMs": 1700000600000,
        "refundAfterMs": 1700000600000,
        "expiresMs": 1700000900000,
        "rails": ["evm-htlc"],
    }

    accept_frame = {
        "type": "accept",
        "ref": "offer-evm-001",
        "statement": hashlock,
        "nonce": "nonce-evm-1",
    }

    accept_core = {
        "from": payee_did,
        "ref": "offer-evm-001",
        "statement": hashlock,
        "nonce": "nonce-evm-1",
    }

    payload = {"offer": offer_frame, "accept": accept_core}
    cid_bytes = canonical_json_bytes(payload)
    contract_id = domain_hash("contract", cid_bytes)

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_frame), seq=2)

    export_file = tmp_path / f"{room}.jsonl"
    export_file.write_bytes(b"".join([
        json.dumps(rec1).encode("utf-8") + b"\n",
        json.dumps(rec2).encode("utf-8") + b"\n",
    ]))

    htlc_addr = "0x1111111111111111111111111111111111111111"
    payer_addr = "0x2222222222222222222222222222222222222222"
    payee_addr = "0x3333333333333333333333333333333333333333"
    lock_tx = "0x" + "a" * 64
    claim_tx = "0x" + "b" * 64

    locked_log = _make_locked_log(
        htlc_address=htlc_addr,
        contract_id=contract_id,
        payer=payer_addr,
        payee=payee_addr,
        token="0x0000000000000000000000000000000000000000",
        amount=2500000,
        hashlock=hashlock,
        refund_timestamp=1700000600,
    )

    claimed_log = _make_claimed_log(
        htlc_address=htlc_addr,
        contract_id=contract_id,
        secret=secret_preimage,
    )

    receipts = {
        lock_tx.lower(): {
            "status": "0x1",
            "transactionHash": lock_tx,
            "blockNumber": "0x10",
            "logs": [locked_log],
        },
        claim_tx.lower(): {
            "status": "0x1",
            "transactionHash": claim_tx,
            "blockNumber": "0x15",
            "logs": [claimed_log],
        },
    }

    return {
        "room": room,
        "contract_id": contract_id,
        "hashlock": hashlock,
        "secret_preimage": secret_preimage,
        "htlc_addr": htlc_addr,
        "payer_addr": payer_addr,
        "payee_addr": payee_addr,
        "lock_tx": lock_tx,
        "claim_tx": claim_tx,
        "export_file": export_file,
        "receipts": receipts,
    }


# Test 1: Nonexistent Transaction
def test_evm_nonexistent_transaction(mock_deal_transcript):
    env = mock_deal_transcript
    server = MockRpcServer(env["receipts"])
    server.start()
    try:
        with pytest.raises(EvmVerificationError, match="transaction receipt not found"):
            fetch_transaction_receipt(server.url, "0x" + "9" * 64)
    finally:
        server.stop()


# Test 2: Failed Transaction (reverted on-chain)
def test_evm_failed_transaction(mock_deal_transcript):
    env = mock_deal_transcript
    failed_tx = "0x" + "f" * 64
    receipts = {
        failed_tx.lower(): {
            "status": "0x0",
            "transactionHash": failed_tx,
            "blockNumber": "0x10",
            "logs": [],
        }
    }
    server = MockRpcServer(receipts)
    server.start()
    try:
        with pytest.raises(EvmVerificationError, match="transaction failed on-chain"):
            parse_and_verify_htlc_event(receipts[failed_tx.lower()])
    finally:
        server.stop()


# Test 3: Wrong Contract Address
def test_evm_wrong_contract_address(mock_deal_transcript):
    env = mock_deal_transcript
    server = MockRpcServer(env["receipts"])
    server.start()
    try:
        wrong_htlc = "0x9999999999999999999999999999999999999999"
        with pytest.raises(EvmVerificationError, match="receipt logs address mismatch"):
            parse_and_verify_htlc_event(
                env["receipts"][env["lock_tx"].lower()],
                expected_htlc_address=wrong_htlc,
            )
    finally:
        server.stop()


# Test 4: Wrong Event (e.g. ERC-20 Transfer topic0)
def test_evm_wrong_event(mock_deal_transcript):
    wrong_topic_receipt = {
        "status": "0x1",
        "blockNumber": "0x10",
        "logs": [
            {
                "address": "0x1111111111111111111111111111111111111111",
                "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],
                "data": "0x0000000000000000000000000000000000000000000000000000000000000001",
            }
        ],
    }
    with pytest.raises(EvmVerificationError, match="no matching HTLC events found"):
        parse_and_verify_htlc_event(wrong_topic_receipt)


# Test 5: Wrong Amount in On-Chain Log
def test_evm_wrong_amount(mock_deal_transcript):
    env = mock_deal_transcript
    bad_locked_log = _make_locked_log(
        htlc_address=env["htlc_addr"],
        contract_id=env["contract_id"],
        payer=env["payer_addr"],
        payee=env["payee_addr"],
        token="0x0000000000000000000000000000000000000000",
        amount=99999999,  # Mismatched amount
        hashlock=env["hashlock"],
        refund_timestamp=1700000600,
    )
    receipts = {
        env["lock_tx"].lower(): {
            "status": "0x1",
            "transactionHash": env["lock_tx"],
            "blockNumber": "0x10",
            "logs": [bad_locked_log],
        }
    }
    server = MockRpcServer(receipts)
    server.start()
    try:
        proof = verify_cross_layer(
            transcript_source=env["export_file"],
            trust_anchors={"chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": env["lock_tx"],
                "htlc_address": env["htlc_addr"],
            },
        )
        assert proof["cross_check"]["amount_binding"] == "mismatch"
        assert proof["cross_check"]["terms_conformance"] == "failed"
        assert proof["is_conformant"] is False
    finally:
        server.stop()


# Test 6: Wrong Asset in On-Chain Log
def test_evm_wrong_asset(mock_deal_transcript):
    env = mock_deal_transcript
    bad_locked_log = _make_locked_log(
        htlc_address=env["htlc_addr"],
        contract_id=env["contract_id"],
        payer=env["payer_addr"],
        payee=env["payee_addr"],
        token="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC instead of ETH
        amount=2500000,
        hashlock=env["hashlock"],
        refund_timestamp=1700000600,
    )
    receipts = {
        env["lock_tx"].lower(): {
            "status": "0x1",
            "transactionHash": env["lock_tx"],
            "blockNumber": "0x10",
            "logs": [bad_locked_log],
        }
    }
    server = MockRpcServer(receipts)
    server.start()
    try:
        proof = verify_cross_layer(
            transcript_source=env["export_file"],
            trust_anchors={"chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": env["lock_tx"],
                "htlc_address": env["htlc_addr"],
            },
        )
        assert proof["cross_check"]["asset_binding"] == "mismatch"
        assert proof["cross_check"]["terms_conformance"] == "failed"
        assert proof["is_conformant"] is False
    finally:
        server.stop()


# Test 7: Wrong Hashlock in On-Chain Log
def test_evm_wrong_hashlock(mock_deal_transcript):
    env = mock_deal_transcript
    bad_locked_log = _make_locked_log(
        htlc_address=env["htlc_addr"],
        contract_id=env["contract_id"],
        payer=env["payer_addr"],
        payee=env["payee_addr"],
        token="0x0000000000000000000000000000000000000000",
        amount=2500000,
        hashlock="0x" + "e" * 64,
        refund_timestamp=1700000600,
    )
    receipts = {
        env["lock_tx"].lower(): {
            "status": "0x1",
            "transactionHash": env["lock_tx"],
            "blockNumber": "0x10",
            "logs": [bad_locked_log],
        }
    }
    server = MockRpcServer(receipts)
    server.start()
    try:
        proof = verify_cross_layer(
            transcript_source=env["export_file"],
            trust_anchors={"chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": env["lock_tx"],
                "htlc_address": env["htlc_addr"],
            },
        )
        assert proof["cross_check"]["hashlock_binding"] == "mismatch"
        assert proof["cross_check"]["terms_conformance"] == "failed"
        assert proof["is_conformant"] is False
    finally:
        server.stop()


# Test 8: Wrong Contract ID in On-Chain Log
def test_evm_wrong_contract_id(mock_deal_transcript):
    env = mock_deal_transcript
    bad_locked_log = _make_locked_log(
        htlc_address=env["htlc_addr"],
        contract_id="0x" + "9" * 64,
        payer=env["payer_addr"],
        payee=env["payee_addr"],
        token="0x0000000000000000000000000000000000000000",
        amount=2500000,
        hashlock=env["hashlock"],
        refund_timestamp=1700000600,
    )
    receipts = {
        env["lock_tx"].lower(): {
            "status": "0x1",
            "transactionHash": env["lock_tx"],
            "blockNumber": "0x10",
            "logs": [bad_locked_log],
        }
    }
    server = MockRpcServer(receipts)
    server.start()
    try:
        proof = verify_cross_layer(
            transcript_source=env["export_file"],
            trust_anchors={"chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": env["lock_tx"],
                "htlc_address": env["htlc_addr"],
            },
        )
        assert proof["cross_check"]["contract_id_binding"] == "mismatch"
        assert proof["cross_check"]["terms_conformance"] == "failed"
        assert proof["is_conformant"] is False
    finally:
        server.stop()


# Test 9: Missing Event in Log
def test_evm_missing_event(mock_deal_transcript):
    empty_log_receipt = {
        "status": "0x1",
        "blockNumber": "0x10",
        "logs": [],
    }
    with pytest.raises(EvmVerificationError, match="transaction contains no event logs"):
        parse_and_verify_htlc_event(empty_log_receipt)


# Test 10: Multiple Matching Events (Ambiguous Log)
def test_evm_multiple_matching_events(mock_deal_transcript):
    env = mock_deal_transcript
    locked_log = _make_locked_log(
        htlc_address=env["htlc_addr"],
        contract_id=env["contract_id"],
        payer=env["payer_addr"],
        payee=env["payee_addr"],
        token="0x0000000000000000000000000000000000000000",
        amount=2500000,
        hashlock=env["hashlock"],
        refund_timestamp=1700000600,
    )
    ambiguous_receipt = {
        "status": "0x1",
        "blockNumber": "0x10",
        "logs": [locked_log, locked_log],
    }
    with pytest.raises(EvmVerificationError, match="ambiguous logs"):
        parse_and_verify_htlc_event(ambiguous_receipt)


# Test 11: Incorrect Lifecycle Ordering (Claim block < Lock block)
def test_evm_incorrect_lifecycle_ordering(mock_deal_transcript):
    env = mock_deal_transcript
    receipts = dict(env["receipts"])
    # Invert block numbers
    receipts[env["lock_tx"].lower()]["blockNumber"] = "0x20"
    receipts[env["claim_tx"].lower()]["blockNumber"] = "0x10"

    server = MockRpcServer(receipts)
    server.start()
    try:
        with pytest.raises(EvmVerificationError, match="invalid lifecycle ordering"):
            build_rpc_settlement_evidence(
                rpc_url=server.url,
                lock_tx=env["lock_tx"],
                claim_tx=env["claim_tx"],
                expected_htlc_address=env["htlc_addr"],
                expected_chain_id=31337,
            )
    finally:
        server.stop()


# Test 12: Inconsistent Lifecycle (Both Claimed and Refunded)
def test_evm_inconsistent_both_claimed_and_refunded(mock_deal_transcript):
    env = mock_deal_transcript
    refund_tx = "0x" + "c" * 64
    refunded_log = _make_refunded_log(env["htlc_addr"], env["contract_id"])
    receipts = dict(env["receipts"])
    receipts[refund_tx.lower()] = {
        "status": "0x1",
        "transactionHash": refund_tx,
        "blockNumber": "0x25",
        "logs": [refunded_log],
    }
    server = MockRpcServer(receipts)
    server.start()
    try:
        with pytest.raises(EvmVerificationError, match="inconsistent on-chain lifecycle"):
            build_rpc_settlement_evidence(
                rpc_url=server.url,
                lock_tx=env["lock_tx"],
                claim_tx=env["claim_tx"],
                refund_tx=refund_tx,
                expected_htlc_address=env["htlc_addr"],
                expected_chain_id=31337,
            )
    finally:
        server.stop()


# Test 13: RPC Failure (HTTP 500 / Connection Error)
def test_evm_rpc_failure(mock_deal_transcript):
    env = mock_deal_transcript
    server = MockRpcServer(env["receipts"], fail_http=True)
    server.start()
    try:
        proof = verify_cross_layer(
            transcript_source=env["export_file"],
            trust_anchors={"chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": env["lock_tx"],
            },
        )
        assert proof["is_conformant"] is False
        assert any("RPC HTTP error 500" in f or "EVM RPC settlement verification failed" in f for f in proof["failure_reasons"])
    finally:
        server.stop()


# Test 14: Valid On-Chain Receipt Verification -> is_conformant: TRUE
def test_evm_valid_receipt_verification_conformant(mock_deal_transcript):
    env = mock_deal_transcript
    server = MockRpcServer(env["receipts"])
    server.start()
    try:
        proof = verify_cross_layer(
            transcript_source=env["export_file"],
            trust_anchors={"chain_id": 31337},
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": env["lock_tx"],
                "claim_tx": env["claim_tx"],
                "htlc_address": env["htlc_addr"],
            },
        )
        assert proof["contract_id"] == env["contract_id"]
        assert proof["settlement"]["provenance"] == "rpc_receipt_verified"
        assert proof["settlement"]["status"] == "claimed"
        assert proof["cross_check"]["on_chain_provenance"] == "verified"
        assert proof["cross_check"]["terms_conformance"] == "verified"
        assert proof["cross_check"]["secret_verification"] == "verified"
        assert proof["trust_model"]["on_chain_execution_proven"] is True
        assert proof["trust_model"]["terms_conformance"] is True
        assert proof["trust_model"]["transcript_authenticity"] is True
        assert proof["is_conformant"] is True
        assert len(proof["failure_reasons"]) == 0
    finally:
        server.stop()


# Test 15: CLI Integration with --rpc-url
def test_evm_cli_rpc_verification(mock_deal_transcript):
    env = mock_deal_transcript
    server = MockRpcServer(env["receipts"])
    server.start()
    try:
        ret = cross_verify_main([
            str(env["export_file"]),
            "--rpc-url", server.url,
            "--lock-tx", env["lock_tx"],
            "--claim-tx", env["claim_tx"],
            "--htlc-address", env["htlc_addr"],
            "--chain-id", "31337",
            "--json",
        ])
        assert ret == 0  # Conformant exit code 0
    finally:
        server.stop()


# Test 16: Chain ID / Network Mismatch
def test_evm_chain_id_mismatch(mock_deal_transcript):
    env = mock_deal_transcript
    server = MockRpcServer(env["receipts"])
    server.chain_id_hex = "0x1"  # Mainnet (chainId = 1)
    server.start()
    try:
        proof = verify_cross_layer(
            transcript_source=env["export_file"],
            trust_anchors={"chain_id": 31337},  # Expecting Anvil (31337)
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": env["lock_tx"],
            },
        )
        assert proof["is_conformant"] is False
        assert any("chain ID mismatch" in f for f in proof["failure_reasons"])
    finally:
        server.stop()


# Test 17: Receipt Transaction Hash Mismatch (RPC returns mismatched receipt)
def test_evm_receipt_tx_hash_mismatch(mock_deal_transcript):
    env = mock_deal_transcript
    queried_tx = env["lock_tx"]
    mismatched_receipt = dict(env["receipts"][queried_tx.lower()])
    mismatched_receipt["transactionHash"] = "0x" + "9" * 64

    receipts = {queried_tx.lower(): mismatched_receipt}
    server = MockRpcServer(receipts)
    server.start()
    try:
        with pytest.raises(EvmVerificationError, match="receipt transaction hash mismatch"):
            fetch_transaction_receipt(server.url, queried_tx)
    finally:
        server.stop()


# Test 18: Receipt 'to' Address Mismatch
def test_evm_receipt_to_address_mismatch(mock_deal_transcript):
    env = mock_deal_transcript
    queried_tx = env["lock_tx"]
    bad_to_receipt = dict(env["receipts"][queried_tx.lower()])
    bad_to_receipt["to"] = "0x9999999999999999999999999999999999999999"

    with pytest.raises(EvmVerificationError, match="receipt 'to' address mismatch"):
        parse_and_verify_htlc_event(bad_to_receipt, expected_htlc_address=env["htlc_addr"])


# Test 19: Malformed Non-JSON RPC Response
def test_evm_malformed_non_json_rpc():
    class BrokenHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len > 0:
                self.rfile.read(content_len)
            body = b"NOT VALID JSON"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        def log_message(self, format, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), BrokenHandler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        with pytest.raises(EvmVerificationError, match="malformed JSON response|RPC request error"):
            fetch_transaction_receipt(f"http://127.0.0.1:{port}", "0x" + "1" * 64)
    finally:
        httpd.shutdown()
        httpd.server_close()

# Test 20: Missing Mandatory Chain ID in RPC Verification
def test_evm_missing_mandatory_chain_id(mock_deal_transcript):
    env = mock_deal_transcript
    server = MockRpcServer(env["receipts"])
    server.start()
    try:
        proof = verify_cross_layer(
            transcript_source=env["export_file"],
            rpc_anchors={
                "rpc_url": server.url,
                "lock_tx": env["lock_tx"],
            },
        )
        assert proof["is_conformant"] is False
        assert any("expected_chain_id is required" in f for f in proof["failure_reasons"])
    finally:
        server.stop()


# Test 21: Claim Transaction Without Mandatory Lock Transaction
def test_evm_claim_without_lock_fails_closed(mock_deal_transcript):
    env = mock_deal_transcript
    server = MockRpcServer(env["receipts"])
    server.start()
    try:
        with pytest.raises(EvmVerificationError, match="lock_tx is required"):
            build_rpc_settlement_evidence(
                rpc_url=server.url,
                claim_tx=env["claim_tx"],
                expected_chain_id=31337,
            )
    finally:
        server.stop()


# Test 22: Refund Transaction Without Mandatory Lock Transaction
def test_evm_refund_without_lock_fails_closed(mock_deal_transcript):
    env = mock_deal_transcript
    refund_tx = "0x" + "c" * 64
    refunded_log = _make_refunded_log(env["htlc_addr"], env["contract_id"])
    receipts = dict(env["receipts"])
    receipts[refund_tx.lower()] = {
        "status": "0x1",
        "transactionHash": refund_tx,
        "blockNumber": "0x25",
        "logs": [refunded_log],
    }
    server = MockRpcServer(receipts)
    server.start()
    try:
        with pytest.raises(EvmVerificationError, match="lock_tx is required"):
            build_rpc_settlement_evidence(
                rpc_url=server.url,
                refund_tx=refund_tx,
                expected_chain_id=31337,
            )
    finally:
        server.stop()

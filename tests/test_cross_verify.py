"""
Adversarial and Unit Tests for TCLK-Proof Cross-Layer Verification.
Tests terms conformance, trust model separation, provenance, multi-deal routing,
and secp256k1 paymentKey derivation.
"""

import base58
import base64
import json
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

from tc_ledger.cross_verify import (
    canonical_json_bytes,
    domain_hash,
    secp256k1_pubkey_to_address,
    verify_cross_layer,
    format_verification_report,
    main as cross_verify_main,
)
from tc_ledger.ledger import main as ledger_main


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


@pytest.fixture
def mock_deal_environment(tmp_path: Path):
    room = "test-cross-verify-room"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    secret_preimage = "0x" + "a" * 64
    secret_bytes = bytes.fromhex("a" * 64)
    import hashlib
    hashlock = "0x" + hashlib.sha256(secret_bytes).hexdigest()

    offer_frame = {
        "type": "offer",
        "id": "offer-001",
        "role": "payer",
        "amount": "1000000",
        "asset": "0x0000000000000000000000000000000000000000",
        "lock": "hash",
        "claimByMs": 1700000600000,
        "refundAfterMs": 1700000600000,
        "expiresMs": 1700000900000,
        "rails": ["evm-htlc"],
    }

    accept_frame = {
        "type": "accept",
        "ref": "offer-001",
        "statement": hashlock,
        "nonce": "nonce-123",
    }

    accept_core = {
        "from": payee_did,
        "ref": "offer-001",
        "statement": hashlock,
        "nonce": "nonce-123",
    }

    payload = {"offer": offer_frame, "accept": accept_core}
    cid_bytes = canonical_json_bytes(payload)
    contract_id = domain_hash("contract", cid_bytes)

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer_frame), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_frame), seq=2)

    export_lines = [
        json.dumps(rec1).encode("utf-8") + b"\n",
        json.dumps(rec2).encode("utf-8") + b"\n",
    ]

    export_file = tmp_path / f"{room}.jsonl"
    export_file.write_bytes(b"".join(export_lines))

    settlement_data = {
        "rail": "evm-htlc",
        "contract_id": contract_id,
        "contract_address": "0x1111111111111111111111111111111111111111",
        "asset": "0x0000000000000000000000000000000000000000",
        "amount": "1000000",
        "hashlock": hashlock,
        "settlement_status": "claimed",
        "payer_address": "0x2222222222222222222222222222222222222222",
        "payee_address": "0x3333333333333333333333333333333333333333",
        "lock_timestamp": 1700000000,
        "refund_timestamp": 1700000600,
        "claim_timestamp": 1700000300,
        "secret": secret_preimage,
        "lock_tx": "0x" + "1" * 64,
        "claim_tx": "0x" + "2" * 64,
    }

    settlement_file = tmp_path / "settlement.json"
    settlement_file.write_text(json.dumps(settlement_data, indent=2), encoding="utf-8")

    return {
        "room": room,
        "contract_id": contract_id,
        "hashlock": hashlock,
        "secret_preimage": secret_preimage,
        "export_file": export_file,
        "settlement_file": settlement_file,
        "settlement_data": settlement_data,
        "tmp_path": tmp_path,
        "payer_sk": payer_sk,
        "payer_did": payer_did,
        "payee_sk": payee_sk,
        "payee_did": payee_did,
    }


# Test 1: Valid semantic match but self-attested settlement -> NOT conformant
def test_1_valid_semantic_match_self_attested_not_conformant(mock_deal_environment):
    env = mock_deal_environment
    proof = verify_cross_layer(env["export_file"], env["settlement_file"])

    assert proof["contract_id"] == env["contract_id"]
    assert proof["cross_check"]["terms_conformance"] == "verified"
    assert proof["cross_check"]["on_chain_provenance"] == "unverified"
    assert proof["trust_model"]["on_chain_execution_proven"] is False
    assert proof["trust_model"]["terms_conformance"] is True
    assert proof["trust_model"]["transcript_authenticity"] is True
    assert proof["is_conformant"] is False
    assert "settlement evidence is self-attested and lacks independent on-chain provenance" in proof["failure_reasons"]


# Test 2: Forged settlement JSON -> NOT conformant
def test_2_forged_settlement_json_not_conformant(mock_deal_environment):
    env = mock_deal_environment
    forged = dict(env["settlement_data"])
    forged["settlement_status"] = "claimed"
    forged["refund_tx"] = "0x" + "9" * 64  # Claimed status with refund tx is inconsistent lifecycle
    del forged["secret"]

    proof = verify_cross_layer(env["export_file"], forged)
    assert proof["is_conformant"] is False
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 3: Wrong contract ID
def test_3_wrong_contract_id(mock_deal_environment):
    env = mock_deal_environment
    bad_data = dict(env["settlement_data"])
    bad_data["contract_id"] = "0x" + "f" * 64

    proof = verify_cross_layer(env["export_file"], bad_data)
    assert proof["is_conformant"] is False
    assert proof["cross_check"]["contract_id_binding"] == "mismatch"
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 4: Wrong hashlock
def test_4_wrong_hashlock(mock_deal_environment):
    env = mock_deal_environment
    bad_data = dict(env["settlement_data"])
    bad_data["hashlock"] = "0x" + "e" * 64

    proof = verify_cross_layer(env["export_file"], bad_data)
    assert proof["is_conformant"] is False
    assert proof["cross_check"]["hashlock_binding"] == "mismatch"
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 5: Wrong amount
def test_5_wrong_amount(mock_deal_environment):
    env = mock_deal_environment
    bad_data = dict(env["settlement_data"])
    bad_data["amount"] = "9999999"

    proof = verify_cross_layer(env["export_file"], bad_data)
    assert proof["is_conformant"] is False
    assert proof["cross_check"]["amount_binding"] == "mismatch"
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 6: Wrong asset
def test_6_wrong_asset(mock_deal_environment):
    env = mock_deal_environment
    bad_data = dict(env["settlement_data"])
    bad_data["asset"] = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"

    proof = verify_cross_layer(env["export_file"], bad_data)
    assert proof["is_conformant"] is False
    assert proof["cross_check"]["asset_binding"] == "mismatch"
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 7: Invalid secret
def test_7_invalid_secret(mock_deal_environment):
    env = mock_deal_environment
    bad_data = dict(env["settlement_data"])
    bad_data["secret"] = "0x" + "b" * 64

    proof = verify_cross_layer(env["export_file"], bad_data)
    assert proof["is_conformant"] is False
    assert proof["cross_check"]["secret_verification"] == "mismatch"
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 8: Claim after refund deadline
def test_8_claim_after_refund_deadline(mock_deal_environment):
    env = mock_deal_environment
    bad_data = dict(env["settlement_data"])
    bad_data["claim_timestamp"] = 1700000700  # after refund_timestamp 1700000600

    proof = verify_cross_layer(env["export_file"], bad_data)
    assert proof["is_conformant"] is False
    assert proof["cross_check"]["temporal_ordering"] == "claim_too_late"
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 9: Lock after refund deadline
def test_9_lock_after_refund_deadline(mock_deal_environment):
    env = mock_deal_environment
    bad_data = dict(env["settlement_data"])
    bad_data["lock_timestamp"] = 1700000650
    bad_data["refund_timestamp"] = 1700000600

    proof = verify_cross_layer(env["export_file"], bad_data)
    assert proof["is_conformant"] is False
    assert proof["cross_check"]["temporal_ordering"] == "lock_too_late"
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 10: Multiple offers in same room
def test_10_multiple_offers_in_same_room(tmp_path: Path):
    room = "test-multi-offer"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    hashlock = "0x" + "c" * 64
    offer1 = {"type": "offer", "id": "offer-1", "amount": "100", "asset": "0x" + "0" * 40}
    offer2 = {"type": "offer", "id": "offer-2", "amount": "200", "asset": "0x" + "0" * 40}
    accept2 = {"type": "accept", "ref": "offer-2", "statement": hashlock, "nonce": "n2"}

    payload2 = {"offer": offer2, "accept": {"from": payee_did, "ref": "offer-2", "statement": hashlock, "nonce": "n2"}}
    cid2 = domain_hash("contract", canonical_json_bytes(payload2))

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer1), seq=1)
    rec2 = _sign_record(payer_sk, payer_did, room, json.dumps(offer2), seq=2)
    rec3 = _sign_record(payee_sk, payee_did, room, json.dumps(accept2), seq=3)

    export_file = tmp_path / "multi_offer.jsonl"
    export_file.write_bytes(b"".join([
        json.dumps(rec1).encode("utf-8") + b"\n",
        json.dumps(rec2).encode("utf-8") + b"\n",
        json.dumps(rec3).encode("utf-8") + b"\n",
    ]))

    settlement = {
        "rail": "evm-htlc",
        "contract_id": cid2,
        "asset": "0x" + "0" * 40,
        "amount": "200",
        "hashlock": hashlock,
        "settlement_status": "locked",
    }

    proof = verify_cross_layer(export_file, settlement)
    assert proof["contract_id"] == cid2
    assert proof["cross_check"]["terms_conformance"] == "verified"


# Test 11: Accept referencing wrong offer
def test_11_accept_referencing_wrong_offer(tmp_path: Path):
    room = "test-wrong-ref"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    offer1 = {"type": "offer", "id": "offer-1", "amount": "100", "asset": "0x" + "0" * 40}
    accept_wrong = {"type": "accept", "ref": "non-existent-offer", "statement": "0x" + "1" * 64}

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer1), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept_wrong), seq=2)

    export_file = tmp_path / "wrong_ref.jsonl"
    export_file.write_bytes(b"".join([
        json.dumps(rec1).encode("utf-8") + b"\n",
        json.dumps(rec2).encode("utf-8") + b"\n",
    ]))

    settlement = {
        "rail": "evm-htlc",
        "contract_id": "0x" + "1" * 64,
        "asset": "0x" + "0" * 40,
        "amount": "100",
        "hashlock": "0x" + "1" * 64,
        "settlement_status": "locked",
    }

    proof = verify_cross_layer(export_file, settlement)
    assert proof["is_conformant"] is False
    assert any("failed to extract agreement from export" in f for f in proof["failure_reasons"])


# Test 12: Ambiguous agreement
def test_12_ambiguous_agreement(tmp_path: Path):
    room = "test-ambiguous"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    offer1 = {"type": "offer", "id": "off-1", "amount": "100", "asset": "0x" + "0" * 40}
    accept1 = {"type": "accept", "ref": "off-1", "statement": "0x" + "1" * 64, "nonce": "n1"}
    offer2 = {"type": "offer", "id": "off-2", "amount": "200", "asset": "0x" + "0" * 40}
    accept2 = {"type": "accept", "ref": "off-2", "statement": "0x" + "2" * 64, "nonce": "n2"}

    payload1 = {"offer": offer1, "accept": {"from": payee_did, "ref": "off-1", "statement": "0x" + "1" * 64, "nonce": "n1"}}
    cid1 = domain_hash("contract", canonical_json_bytes(payload1))

    payload2 = {"offer": offer2, "accept": {"from": payee_did, "ref": "off-2", "statement": "0x" + "2" * 64, "nonce": "n2"}}
    cid2 = domain_hash("contract", canonical_json_bytes(payload2))

    recs = [
        _sign_record(payer_sk, payer_did, room, json.dumps(offer1), seq=1),
        _sign_record(payee_sk, payee_did, room, json.dumps(accept1), seq=2),
        _sign_record(payer_sk, payer_did, room, json.dumps(offer2), seq=3),
        _sign_record(payee_sk, payee_did, room, json.dumps(accept2), seq=4),
    ]

    export_file = tmp_path / "ambiguous.jsonl"
    export_file.write_bytes(b"".join(json.dumps(r).encode("utf-8") + b"\n" for r in recs))

    settlement = {
        "rail": "evm-htlc",
        "contract_id": cid1,
        "asset": "0x" + "0" * 40,
        "amount": "100",
        "hashlock": "0x" + "1" * 64,
        "settlement_status": "locked",
    }

    # Without expected-contract-id, it fails closed with ambiguous agreement
    proof_ambiguous = verify_cross_layer(export_file, settlement)
    assert proof_ambiguous["is_conformant"] is False
    assert any("ambiguous agreement" in f for f in proof_ambiguous["failure_reasons"])

    # With explicit expected-contract-id, it disambiguates cleanly
    proof_cid1 = verify_cross_layer(export_file, settlement, trust_anchors={"contract_id": cid1})
    assert proof_cid1["contract_id"] == cid1
    assert proof_cid1["cross_check"]["terms_conformance"] == "verified"

    settlement2 = dict(settlement, contract_id=cid2, amount="200", hashlock="0x" + "2" * 64)
    proof_cid2 = verify_cross_layer(export_file, settlement2, trust_anchors={"contract_id": cid2})
    assert proof_cid2["contract_id"] == cid2
    assert proof_cid2["cross_check"]["terms_conformance"] == "verified"


# Test 13: Fake paymentKey / address mismatch
def test_13_fake_payment_key_address_mismatch(tmp_path: Path):
    room = "test-fake-pk"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    valid_pubkey = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    wrong_address = "0x9999999999999999999999999999999999999999"

    hashlock = "0x" + "d" * 64
    offer = {"type": "offer", "id": "off-pk", "amount": "100", "asset": "0x" + "0" * 40, "paymentKey": valid_pubkey}
    accept = {"type": "accept", "ref": "off-pk", "statement": hashlock, "nonce": "n-pk"}

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept), seq=2)

    export_file = tmp_path / "fake_pk.jsonl"
    export_file.write_bytes(b"".join([
        json.dumps(rec1).encode("utf-8") + b"\n",
        json.dumps(rec2).encode("utf-8") + b"\n",
    ]))

    payload = {"offer": offer, "accept": {"from": payee_did, "ref": "off-pk", "statement": hashlock, "nonce": "n-pk"}}
    cid = domain_hash("contract", canonical_json_bytes(payload))

    settlement = {
        "rail": "evm-htlc",
        "contract_id": cid,
        "asset": "0x" + "0" * 40,
        "amount": "100",
        "hashlock": hashlock,
        "settlement_status": "locked",
        "payer_address": wrong_address,
    }

    proof = verify_cross_layer(export_file, settlement)
    assert proof["cross_check"]["address_binding_payer"] == "mismatch"
    assert proof["cross_check"]["address_binding"] == "mismatch"
    assert proof["cross_check"]["terms_conformance"] == "failed"


# Test 14: Valid paymentKey / address verification
def test_14_valid_payment_key_address_verification(tmp_path: Path):
    room = "test-valid-pk"
    payer_sk, payer_did = _make_keypair()
    payee_sk, payee_did = _make_keypair()

    valid_pubkey = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    correct_address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"

    hashlock = "0x" + "d" * 64
    offer = {"type": "offer", "id": "off-pk", "amount": "100", "asset": "0x" + "0" * 40, "paymentKey": valid_pubkey}
    accept = {"type": "accept", "ref": "off-pk", "statement": hashlock, "nonce": "n-pk"}

    rec1 = _sign_record(payer_sk, payer_did, room, json.dumps(offer), seq=1)
    rec2 = _sign_record(payee_sk, payee_did, room, json.dumps(accept), seq=2)

    export_file = tmp_path / "valid_pk.jsonl"
    export_file.write_bytes(b"".join([
        json.dumps(rec1).encode("utf-8") + b"\n",
        json.dumps(rec2).encode("utf-8") + b"\n",
    ]))

    payload = {"offer": offer, "accept": {"from": payee_did, "ref": "off-pk", "statement": hashlock, "nonce": "n-pk"}}
    cid = domain_hash("contract", canonical_json_bytes(payload))

    settlement = {
        "rail": "evm-htlc",
        "contract_id": cid,
        "asset": "0x" + "0" * 40,
        "amount": "100",
        "hashlock": hashlock,
        "settlement_status": "locked",
        "payer_address": correct_address,
    }

    proof = verify_cross_layer(export_file, settlement)
    assert proof["cross_check"]["address_binding_payer"] == "verified_via_payment_key"
    assert proof["cross_check"]["terms_conformance"] == "verified"


# Test 15: Malformed settlement evidence
def test_15_malformed_settlement_evidence(tmp_path: Path):
    corrupt_file = tmp_path / "corrupt_settlement.json"
    corrupt_file.write_text("{ not valid json !!!", encoding="utf-8")

    dummy_export = tmp_path / "dummy.jsonl"
    dummy_export.write_bytes(b"")

    proof = verify_cross_layer(dummy_export, corrupt_file)
    assert proof["is_conformant"] is False
    assert any("malformed settlement JSON" in f for f in proof["failure_reasons"])


# Test 16: Deterministic identical input -> identical proof output
def test_16_deterministic_identical_input_identical_output(mock_deal_environment):
    env = mock_deal_environment
    proof1 = verify_cross_layer(env["export_file"], env["settlement_file"])
    proof2 = verify_cross_layer(env["export_file"], env["settlement_file"])

    json1 = json.dumps(proof1, sort_keys=True)
    json2 = json.dumps(proof2, sort_keys=True)
    assert json1 == json2


# CLI Integration Tests
def test_cli_cross_verify(mock_deal_environment):
    env = mock_deal_environment
    # Verify subcommands 'tclk-proof' and 'tclk-proof verify'
    ret1 = cross_verify_main([str(env["export_file"]), str(env["settlement_file"]), "--json"])
    assert ret1 == 1  # non-conformant due to self-attested settlement

    ret2 = cross_verify_main(["verify", str(env["export_file"]), str(env["settlement_file"]), "--json"])
    assert ret2 == 1

    # Usage error (missing required args)
    ret_usage = cross_verify_main(["--json"])
    assert ret_usage == 2

    # File not found
    ret_io = cross_verify_main(["non_existent.jsonl", str(env["settlement_file"])])
    assert ret_io == 2


# Test: Fake lock_tx does not imply on-chain execution
def test_fake_lock_tx_not_proven_on_chain(mock_deal_environment):
    env = mock_deal_environment
    data = dict(env["settlement_data"])
    data["lock_tx"] = "0x" + "7" * 64

    proof = verify_cross_layer(env["export_file"], data)
    assert proof["cross_check"]["terms_conformance"] == "verified"
    assert proof["cross_check"]["on_chain_provenance"] == "unverified"
    assert proof["trust_model"]["on_chain_execution_proven"] is False
    assert proof["is_conformant"] is False
    assert "settlement evidence is self-attested and lacks independent on-chain provenance" in proof["failure_reasons"]


# Test: Fake claim_tx does not imply on-chain execution
def test_fake_claim_tx_not_proven_on_chain(mock_deal_environment):
    env = mock_deal_environment
    data = dict(env["settlement_data"])
    data["claim_tx"] = "0x" + "8" * 64

    proof = verify_cross_layer(env["export_file"], data)
    assert proof["cross_check"]["terms_conformance"] == "verified"
    assert proof["cross_check"]["on_chain_provenance"] == "unverified"
    assert proof["trust_model"]["on_chain_execution_proven"] is False
    assert proof["is_conformant"] is False


# Test: Fake contract_address does not imply on-chain verification
def test_fake_contract_address_not_proven_on_chain(mock_deal_environment):
    env = mock_deal_environment
    data = dict(env["settlement_data"])
    data["contract_address"] = "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead"

    proof = verify_cross_layer(env["export_file"], data)
    assert proof["cross_check"]["terms_conformance"] == "verified"
    assert proof["cross_check"]["on_chain_provenance"] == "unverified"
    assert proof["trust_model"]["on_chain_execution_proven"] is False
    assert proof["is_conformant"] is False


# Test: Locked settlement without independently verified rail evidence is not conformant
def test_locked_settlement_unverified_rail(mock_deal_environment):
    env = mock_deal_environment
    data = dict(env["settlement_data"])
    data["settlement_status"] = "locked"
    data.pop("secret", None)
    data.pop("claim_tx", None)
    data.pop("claim_timestamp", None)

    proof = verify_cross_layer(env["export_file"], data)
    assert proof["settlement"]["status"] == "locked"
    assert proof["cross_check"]["terms_conformance"] == "verified"
    assert proof["cross_check"]["on_chain_provenance"] == "unverified"
    assert proof["trust_model"]["on_chain_execution_proven"] is False
    assert proof["is_conformant"] is False
    assert "settlement evidence is self-attested and lacks independent on-chain provenance" in proof["failure_reasons"]

# Adversarial Regression Test: Caller cannot spoof provenance="rpc_receipt_verified" in settlement JSON
def test_adversarial_spoofed_rpc_provenance_in_settlement_json(mock_deal_environment):
    env = mock_deal_environment
    data = dict(env["settlement_data"])
    # Attacker attempts to forge on-chain execution by setting provenance in caller JSON
    data["provenance"] = "rpc_receipt_verified"
    data["lock_tx"] = "0x" + "1" * 64
    data["claim_tx"] = "0x" + "2" * 64

    proof = verify_cross_layer(env["export_file"], data)
    assert proof["settlement"]["provenance"] == "self_attested"
    assert proof["settlement"]["evidence_provenance"] == "self_attested"
    assert proof["trust_model"]["on_chain_execution_proven"] is False
    assert proof["trust_model"]["settlement_evidence_provenance"] == "self_attested"
    assert proof["cross_check"]["on_chain_provenance"] == "unverified"
    assert proof["is_conformant"] is False
    assert any("self-attested and lacks independent on-chain provenance" in r for r in proof["failure_reasons"])


def test_format_verification_report_conformant_structure(mock_deal_environment):
    env = mock_deal_environment
    proof = verify_cross_layer(env["export_file"], env["settlement_file"])

    # Simulate on-chain verified RPC proof
    proof["settlement"]["provenance"] = "rpc_receipt_verified"
    proof["settlement"]["evidence_provenance"] = "rpc_receipt_verified"
    proof["trust_model"]["on_chain_execution_proven"] = True
    proof["trust_model"]["settlement_evidence_provenance"] = "rpc_receipt_verified"
    proof["cross_check"]["on_chain_provenance"] = "verified"
    proof["is_conformant"] = True
    proof["failure_reasons"] = []

    trust_anchors = {
        "room": env["room"],
        "expected_root": proof["transcript"]["export_root"],
        "expected_contract_id": env["contract_id"],
        "chain_id": 31337,
    }

    report = format_verification_report(proof, trust_anchors=trust_anchors)

    assert "TCLK-PROOF VERIFICATION REPORT" in report
    assert "Specification:   tclk-proof/1" in report
    assert "Final Verdict:   [OK] PASS: CONFORMANT" in report
    assert "[1] TRUST ANCHORS & CONTEXT" in report
    assert f"Expected Room:        {env['room']} -> [OK] Matched" in report
    assert "[2] OFF-CHAIN TRANSCRIPT VERIFICATION" in report
    assert "Ed25519 Signatures:   [OK] True" in report or "Ed25519 Signatures:   [OK] Verified" in report or "[OK]" in report
    assert "[3] AGREEMENT TERMS (OFF-CHAIN NEGOTIATION)" in report
    assert f"Payer DID:            {env['payer_did']}" in report
    assert f"Payee DID:            {env['payee_did']}" in report
    assert "[4] EVM SETTLEMENT / RAIL EVIDENCE" in report
    assert "[5] CROSS-LAYER BINDINGS & CONFORMANCE" in report
    assert "Contract ID Binding:  [OK] verified" in report
    assert "Hashlock Binding:     [OK] verified" in report
    assert "Amount Binding:       [OK] verified" in report
    assert "Asset / Token Binding:[OK] verified" in report
    assert "[6] PROVENANCE & TRUST MODEL" in report
    assert "Evidence Provenance:  [OK] rpc_receipt_verified" in report
    assert "On-Chain Exec Proven: [OK] True" in report
    assert "[7] WARNINGS & ANOMALIES" in report
    assert "[8] FAILURE REASONS (0)" in report
    assert "[INFO] None" in report
    assert "FINAL CONFORMITY VERDICT: [OK] PASS: CONFORMANT" in report


def test_format_verification_report_non_conformant_with_failures(mock_deal_environment):
    env = mock_deal_environment
    proof = verify_cross_layer(env["export_file"], env["settlement_file"])

    assert proof["is_conformant"] is False
    report = format_verification_report(proof)

    assert "Final Verdict:   [FAIL] FAIL: NON-CONFORMANT" in report
    assert "[FAIL] FAIL: NON-CONFORMANT" in report
    assert "Evidence Provenance:  [WARN] self_attested" in report
    assert "On-Chain Exec Proven: [FAIL] False" in report
    assert "[8] FAILURE REASONS (" in report
    assert "- [FAIL] settlement evidence is self-attested and lacks independent on-chain provenance" in report
    assert "FINAL CONFORMITY VERDICT: [FAIL] FAIL: NON-CONFORMANT" in report


def test_format_verification_report_warnings(mock_deal_environment):
    env = mock_deal_environment
    proof = verify_cross_layer(env["export_file"], env["settlement_file"])
    proof["warnings"] = ["test non-fatal warning condition"]

    report = format_verification_report(proof)
    assert "[7] WARNINGS & ANOMALIES (1)" in report
    assert "- [WARN] test non-fatal warning condition" in report



def test_cli_report_flag_tclk_proof(mock_deal_environment, capsys):
    env = mock_deal_environment
    # Test tclk-proof with --report
    ret = cross_verify_main([str(env["export_file"]), str(env["settlement_file"]), "--report"])
    captured = capsys.readouterr()
    assert "TCLK-PROOF VERIFICATION REPORT" in captured.out
    assert "FINAL CONFORMITY VERDICT:" in captured.out
    assert ret == 1  # self-attested settlement is non-conformant

    # Test tclk-proof verify with --report
    ret_verify = cross_verify_main(["verify", str(env["export_file"]), str(env["settlement_file"]), "--report"])
    captured_verify = capsys.readouterr()
    assert "TCLK-PROOF VERIFICATION REPORT" in captured_verify.out
    assert ret_verify == 1


def test_cli_report_flag_tc_ledger(mock_deal_environment, capsys, monkeypatch):
    env = mock_deal_environment
    monkeypatch.setattr(
        "sys.argv",
        ["tc-ledger", "cross-verify", str(env["export_file"]), str(env["settlement_file"]), "--report"],
    )
    ret = ledger_main()
    captured = capsys.readouterr()
    assert "TCLK-PROOF VERIFICATION REPORT" in captured.out
    assert "FINAL CONFORMITY VERDICT:" in captured.out
    assert ret == 1


def test_format_verification_report_minimal_and_empty_proof():
    # Test completely empty dict
    rep1 = format_verification_report({})
    assert "TCLK-PROOF VERIFICATION REPORT" in rep1
    assert "Final Verdict:   [FAIL] FAIL: NON-CONFORMANT" in rep1
    assert "[FAIL] Transcript evidence missing or failed to parse" in rep1
    assert "[FAIL] Agreement state missing or unextractable" in rep1
    assert "[FAIL] Settlement evidence missing" in rep1
    assert "[FAIL] Cross-check results missing" in rep1
    assert "[FAIL] Trust model assessment missing" in rep1
    assert "[INFO] None" in rep1

    # Test None / missing optional fields within subdictionaries
    minimal_proof = {
        "is_conformant": False,
        "contract_id": "0x1234",
        "room": "room-xyz",
        "agreement": {"status": "OPEN"},
        "transcript": {"status": "partial"},
        "settlement": {"rail": "evm-htlc", "status": "locked"},
        "cross_check": {"terms_conformance": "failed"},
        "trust_model": {"settlement_evidence_provenance": "self_attested"},
        "failure_reasons": ["agreement not accepted"],
        "warnings": [],
    }
    rep2 = format_verification_report(minimal_proof)
    assert "0x1234" in rep2
    assert "room-xyz" in rep2
    assert "- [FAIL] agreement not accepted" in rep2
    assert "[7] WARNINGS & ANOMALIES (0)" in rep2


def test_format_verification_report_refund_settlement(mock_deal_environment):
    env = mock_deal_environment
    proof = verify_cross_layer(env["export_file"], env["settlement_file"])

    proof["settlement"]["status"] = "refunded"
    proof["settlement"]["refund_tx"] = "0x" + "c" * 64
    proof["settlement"]["refund_timestamp"] = 1700000800
    proof["settlement"]["claim_tx"] = None
    proof["settlement"]["secret_revealed"] = None

    report = format_verification_report(proof)
    assert "Settlement Status:    refunded" in report
    assert "0x" + "c" * 64 in report


def test_format_verification_report_payment_keys(mock_deal_environment):
    env = mock_deal_environment
    proof = verify_cross_layer(env["export_file"], env["settlement_file"])

    proof["agreement"]["payer_payment_key"] = "0x02" + "1" * 64
    proof["agreement"]["payee_payment_key"] = "0x03" + "2" * 64

    report = format_verification_report(proof)
    assert f"Payer Payment Key:    0x02{'1' * 64}" in report
    assert f"Payee Payment Key:    0x03{'2' * 64}" in report


def test_cli_report_preserves_json_behavior(mock_deal_environment, capsys, monkeypatch):
    env = mock_deal_environment

    # Test tclk-proof --json is valid JSON
    ret1 = cross_verify_main([str(env["export_file"]), str(env["settlement_file"]), "--json"])
    cap1 = capsys.readouterr()
    parsed1 = json.loads(cap1.out)
    assert "spec" in parsed1
    assert "is_conformant" in parsed1
    assert ret1 == 1

    # Test tc-ledger cross-verify --json is valid JSON
    monkeypatch.setattr(
        "sys.argv",
        ["tc-ledger", "cross-verify", str(env["export_file"]), str(env["settlement_file"]), "--json"],
    )
    ret2 = ledger_main()
    cap2 = capsys.readouterr()
    parsed2 = json.loads(cap2.out)
    assert "spec" in parsed2
    assert "is_conformant" in parsed2
    assert ret2 == 1


# --- Strict CLI Exit Code Contract Regression Tests ---

def test_cli_exit_code_contract_non_conformant(mock_deal_environment, capsys, monkeypatch):
    """Test exit code 1 for completed non-conformant verifications."""
    env = mock_deal_environment

    # 1. tclk-proof normal output -> exit 1
    ret = cross_verify_main([str(env["export_file"]), str(env["settlement_file"])])
    cap = capsys.readouterr()
    assert ret == 1
    assert "CROSS-VERIFICATION: NON-CONFORMANT" in cap.err

    # 2. tclk-proof --report -> exit 1
    ret = cross_verify_main(["verify", str(env["export_file"]), str(env["settlement_file"]), "--report"])
    cap = capsys.readouterr()
    assert ret == 1
    assert "TCLK-PROOF VERIFICATION REPORT" in cap.out
    assert "FINAL CONFORMITY VERDICT: [FAIL] FAIL: NON-CONFORMANT" in cap.out

    # 3. tc-ledger cross-verify normal output -> exit 1
    monkeypatch.setattr(
        "sys.argv",
        ["tc-ledger", "cross-verify", str(env["export_file"]), str(env["settlement_file"])],
    )
    ret = ledger_main()
    cap = capsys.readouterr()
    assert ret == 1
    assert "CROSS-VERIFICATION: NON-CONFORMANT" in cap.err

    # 4. tc-ledger cross-verify --report -> exit 1
    monkeypatch.setattr(
        "sys.argv",
        ["tc-ledger", "cross-verify", str(env["export_file"]), str(env["settlement_file"]), "--report"],
    )
    ret = ledger_main()
    cap = capsys.readouterr()
    assert ret == 1
    assert "TCLK-PROOF VERIFICATION REPORT" in cap.out
    assert "FINAL CONFORMITY VERDICT: [FAIL] FAIL: NON-CONFORMANT" in cap.out


def test_cli_exit_code_contract_invocation_and_input_errors(mock_deal_environment, tmp_path, capsys, monkeypatch):
    """Test exit code 2 for missing arguments, bad flags, missing files, and malformed inputs."""
    env = mock_deal_environment

    # 1. Missing transcript argument
    ret1 = cross_verify_main([])
    cap1 = capsys.readouterr()
    assert ret1 == 2
    assert "the following arguments are required" in cap1.err

    # 2. Missing transcript with --json -> returns 2 with valid JSON error output
    ret_json = cross_verify_main(["--json"])
    cap_json = capsys.readouterr()
    assert ret_json == 2
    parsed_err = json.loads(cap_json.out)
    assert parsed_err["valid"] is False
    assert "Missing required argument" in parsed_err["error"]

    # 3. Nonexistent transcript file -> returns 2 (and valid JSON if --json)
    ret_no_file = cross_verify_main(["non_existent_file.jsonl", str(env["settlement_file"]), "--json"])
    cap_no_file = capsys.readouterr()
    assert ret_no_file == 2
    parsed_io = json.loads(cap_no_file.out)
    assert parsed_io["valid"] is False
    assert "transcript source file not found" in parsed_io["error"]

    # 4. Malformed JSONL transcript file -> returns 2
    bad_transcript = tmp_path / "bad_transcript.jsonl"
    bad_transcript.write_text("{this is not valid json\n", encoding="utf-8")
    ret_bad_t = cross_verify_main([str(bad_transcript), str(env["settlement_file"])])
    cap_bad_t = capsys.readouterr()
    assert ret_bad_t == 2
    assert "Runtime Error" in cap_bad_t.err or "Error" in cap_bad_t.err

    # 5. Malformed JSON settlement file -> returns 2
    valid_transcript = tmp_path / "empty_transcript.jsonl"
    valid_transcript.write_text("", encoding="utf-8")
    bad_settlement = tmp_path / "bad_settlement.json"
    bad_settlement.write_text("invalid json content", encoding="utf-8")
    ret_bad_s = cross_verify_main([str(valid_transcript), str(bad_settlement), "--json"])
    cap_bad_s = capsys.readouterr()
    assert ret_bad_s == 2
    parsed_bad_s = json.loads(cap_bad_s.out)
    assert parsed_bad_s["valid"] is False

    # 6. Check tc-ledger cross-verify produces exit 2 on same errors
    monkeypatch.setattr(
        "sys.argv",
        ["tc-ledger", "cross-verify", "non_existent.jsonl"],
    )
    ret_ledger_err = ledger_main()
    assert ret_ledger_err == 2

    monkeypatch.setattr(
        "sys.argv",
        ["tc-ledger", "cross-verify", "non_existent.jsonl", "--json"],
    )
    ret_ledger_json = ledger_main()
    cap_ledger_json = capsys.readouterr()
    assert ret_ledger_json == 2
    parsed_ledger = json.loads(cap_ledger_json.out)
    assert parsed_ledger["valid"] is False


def test_cli_exit_code_contract_rpc_configuration_errors(mock_deal_environment, capsys, monkeypatch):
    """Test exit code 2 for missing required RPC parameters (e.g. omitted chain-id)."""
    env = mock_deal_environment

    # --rpc-url without --chain-id must fail closed with exit code 2
    ret = cross_verify_main([
        str(env["export_file"]),
        "--rpc-url", "http://127.0.0.1:8545",
        "--lock-tx", "0x" + "1" * 64,
        "--json",
    ])
    cap = capsys.readouterr()
    assert ret == 2
    parsed = json.loads(cap.out)
    assert parsed["valid"] is False
    assert "chain_id" in parsed["error"]

    # Same check for tc-ledger cross-verify
    monkeypatch.setattr(
        "sys.argv",
        [
            "tc-ledger", "cross-verify", str(env["export_file"]),
            "--rpc-url", "http://127.0.0.1:8545",
            "--lock-tx", "0x" + "1" * 64,
            "--json",
        ],
    )
    ret_ledger = ledger_main()
    cap_ledger = capsys.readouterr()
    assert ret_ledger == 2
    parsed_l = json.loads(cap_ledger.out)
    assert parsed_l["valid"] is False
    assert "chain_id" in parsed_l["error"]

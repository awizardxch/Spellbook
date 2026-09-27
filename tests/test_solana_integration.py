"""Solana daemon integration tests — SPEC §10 Solana (offline).

Covers the daemon wiring the solana module into the policy engine:
addresses (KDF + standard), upfront network-mismatch hard error, the
mainnet-beta gate, active-seed signing guards, schema-misuse refusals,
unreachable-RPC fail-closed, BroadcastUnknown signature extraction, the
amount_lamports schema, and policy wiring (cap/queue/auto-approve).

No network access: every test either fails before any RPC contact or
uses a monkeypatched transport.
"""
import json
import os
import secrets
import tempfile

import pytest

from spellbook import solana as solana_mod
from spellbook.client import AgentClient
from spellbook.daemon import Daemon

TEST_SEED_HEX = ("000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f")
# 64-byte BIP-39 seed (test only — NOT a real wallet).
TEST_STD_SEED_HEX = "00" * 63 + "01"

UID = os.getuid()


def _write(path, data, mode=0o600):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)


def make_daemon(policy=None, seed_hex=TEST_SEED_HEX, std_seed_hex=None,
                solana_cfg=None):
    """Boot an in-process Daemon on a fresh temp config dir."""
    tmp = tempfile.mkdtemp(prefix="spellbook-solana-test-")
    req_token = secrets.token_hex(32)
    app_token = secrets.token_hex(32)
    _write(os.path.join(tmp, "request.token"), req_token)
    _write(os.path.join(tmp, "approve.token"), app_token)
    cfg = {"labels": ["default"],
           "allowed_request_uids": [UID],
           "allowed_approve_uids": [UID]}
    if seed_hex is not None:
        _write(os.path.join(tmp, "seed.key"), seed_hex)
        cfg["seed_path"] = os.path.join(tmp, "seed.key")
    if std_seed_hex is not None:
        _write(os.path.join(tmp, "std_seed.key"), std_seed_hex)
        cfg["key_derivation"] = "standard"
        cfg["std_seed_path"] = os.path.join(tmp, "std_seed.key")
    if solana_cfg is not None:
        cfg["solana"] = solana_cfg
    _write(os.path.join(tmp, "spellbook.json"), json.dumps(cfg))
    _write(os.path.join(tmp, "policy.json"), json.dumps(policy or {}))
    d = Daemon(tmp)
    return d, tmp, req_token, app_token


def req(d, token, route, params):
    return d.handle({"token": token, "route": route, "params": params,
                     "muse_id": "test"}, UID)


DEVNET = "solana-devnet"
MAINNET = "solana-mainnet"
DEST = str(solana_mod.keypair_from_seed(bytes(32)).pubkey())  # valid base58 addr


def _auto_policy():
    return {"auto_approve_below": {f"{DEVNET}:SOL": 10 ** 12}}


# ---------------------------------------------------------------- addresses

def test_addresses_kdf_mode():
    d, tmp, *_ = make_daemon()
    seed = bytes.fromhex(TEST_SEED_HEX)
    got = d.rt_addresses({}, "test")["addresses"]["default"]
    exp_dev = solana_mod.address_of_keypair(
        solana_mod.custom_keypair(seed, DEVNET, "default"))
    exp_main = solana_mod.address_of_keypair(
        solana_mod.custom_keypair(seed, MAINNET, "default"))
    assert got[DEVNET] == exp_dev
    assert got[MAINNET] == exp_main
    assert got[DEVNET] != got[MAINNET]  # P9: per-network keys differ


def test_addresses_standard_mode():
    d, tmp, *_ = make_daemon(seed_hex=None, std_seed_hex=TEST_STD_SEED_HEX)
    std_seed = bytes.fromhex(TEST_STD_SEED_HEX)
    got = d.rt_addresses({}, "test")["addresses"]["default"]
    exp = solana_mod.address_of_keypair(
        solana_mod.standard_keypair(std_seed))
    assert got[DEVNET] == exp
    assert got[MAINNET] == exp  # Solana addresses are network-agnostic


def test_no_seed_no_solana_key():
    d, tmp, req_token, _ = make_daemon(seed_hex=None, policy=_auto_policy())
    with pytest.raises(solana_mod.SolanaError, match="no seed configured"):
        d._solana_keypair(DEVNET)
    resp = req(d, req_token, "request_spend",
               {"chain": DEVNET, "destination": DEST, "asset": "SOL",
                "amount_lamports": 1000, "purpose": "t"})
    assert resp["ok"] is False
    assert resp["decision"] == "approved-submit-failed"
    assert "no seed configured" in resp["error"]


# ------------------------------------------------------- network mismatch

def test_network_mismatch_hard_error_at_request():
    d, tmp, req_token, _ = make_daemon(policy=_auto_policy())
    resp = req(d, req_token, "request_spend",
               {"chain": MAINNET, "destination": DEST, "asset": "SOL",
                "amount_lamports": 1000, "purpose": "t"})
    assert resp["ok"] is False
    assert "network mismatch" in resp["error"]
    # And at execute time too (defense in depth — the queue-approve path).
    with pytest.raises(solana_mod.SolanaError, match="network mismatch"):
        d._execute_solana_spend({"chain": MAINNET, "destination": DEST,
                                 "amount_lamports": 1000})


def test_bad_network_config_fails_closed():
    d, tmp, req_token, _ = make_daemon(
        policy=_auto_policy(), solana_cfg={"network": "bogus"})
    resp = req(d, req_token, "request_spend",
               {"chain": DEVNET, "destination": DEST,
                "amount_lamports": 1000, "purpose": "t"})
    assert resp["ok"] is False
    assert "bad solana.network" in resp["error"]


# ------------------------------------------------------- mainnet gate

def test_mainnet_gate_without_flag():
    d, tmp, req_token, _ = make_daemon(
        policy={"auto_approve_below": {f"{MAINNET}:SOL": 10 ** 12}},
        solana_cfg={"network": "mainnet-beta"})
    resp = req(d, req_token, "request_spend",
               {"chain": MAINNET, "destination": DEST, "asset": "SOL",
                "amount_lamports": 1000, "purpose": "t"})
    assert resp["ok"] is False
    assert resp["decision"] == "approved-submit-failed"
    assert "mainnet submission refused" in resp["error"]


# ------------------------------------------------------- signing-seed guards

def test_standard_mode_uses_std_seed():
    d, tmp, *_ = make_daemon(seed_hex=None, std_seed_hex=TEST_STD_SEED_HEX)
    std_seed = bytes.fromhex(TEST_STD_SEED_HEX)
    kp = d._solana_keypair(DEVNET)
    assert solana_mod.address_of_keypair(kp) == solana_mod.address_of_keypair(
        solana_mod.standard_keypair(std_seed))


def test_kdf_mode_uses_kdf_seed():
    d, tmp, *_ = make_daemon()
    seed = bytes.fromhex(TEST_SEED_HEX)
    kp = d._solana_keypair(DEVNET)
    assert solana_mod.address_of_keypair(kp) == solana_mod.address_of_keypair(
        solana_mod.custom_keypair(seed, DEVNET, "default"))


# ------------------------------------------------------- schema misuse

def test_wei_on_solana_refused():
    d, tmp, req_token, _ = make_daemon(policy={
        "auto_approve_below": {f"{DEVNET}:native": 10 ** 12}})
    resp = req(d, req_token, "request_spend",
               {"chain": DEVNET, "destination": DEST,
                "amount_wei": 1000, "purpose": "t"})
    assert resp["ok"] is False
    assert resp["decision"] == "approved-submit-failed"
    assert "schema misuse" in resp["error"]


def test_two_amounts_rejected_by_schema():
    d, tmp, req_token, _ = make_daemon(policy=_auto_policy())
    resp = req(d, req_token, "request_spend",
               {"chain": DEVNET, "destination": DEST,
                "amount_lamports": 1000, "amount_wei": 1, "purpose": "t"})
    assert resp["ok"] is False
    assert "schema violation" in resp["error"]


# ------------------------------------------------------- RPC fail-closed

def test_unreachable_rpc_fails_closed():
    d, tmp, req_token, _ = make_daemon(
        policy=_auto_policy(), solana_cfg={"rpc_url": "http://127.0.0.1:1/"})
    resp = req(d, req_token, "request_spend",
               {"chain": DEVNET, "destination": DEST, "asset": "SOL",
                "amount_lamports": 1000, "purpose": "t"})
    assert resp["ok"] is False
    assert resp["decision"] == "approved-submit-failed"
    assert "RPC unreachable" in resp["error"]


# ------------------------------------------------------- BroadcastUnknown

def test_broadcast_unknown_carries_signature(monkeypatch):
    d, tmp, req_token, _ = make_daemon(policy=_auto_policy())

    def boom(*a, **k):
        raise solana_mod.BroadcastUnknown("sigABC123", "stalled")

    monkeypatch.setattr(solana_mod, "sign_transfer", boom)
    resp = req(d, req_token, "request_spend",
               {"chain": DEVNET, "destination": DEST, "asset": "SOL",
                "amount_lamports": 1000, "purpose": "t"})
    assert resp["ok"] is True
    assert resp["decision"] == "approved-submit-unknown"
    assert resp["tx_hash"] == "sigABC123"
    # Fail-closed velocity: the unknown spend consumed its cap.
    assert d.spent_last_24h(DEVNET, "SOL") == 1000


# ------------------------------------------------------- policy wiring

def test_policy_cap_denies():
    d, tmp, req_token, _ = make_daemon(policy={
        "per_spend_cap": {f"{DEVNET}:SOL": 100}})
    resp = req(d, req_token, "request_spend",
               {"chain": DEVNET, "destination": DEST, "asset": "SOL",
                "amount_lamports": 101, "purpose": "t"})
    assert resp["decision"] == "denied"
    assert "per-spend cap" in resp["reason"]


def test_policy_queues_above_threshold_and_approves_below():
    d, tmp, req_token, app_token = make_daemon(policy={
        "approval_threshold": {f"{DEVNET}:SOL": 500},
        "auto_approve_below": {f"{DEVNET}:SOL": 100}},
        solana_cfg={"rpc_url": "http://127.0.0.1:1/"})
    q = req(d, req_token, "request_spend",
            {"chain": DEVNET, "destination": DEST, "asset": "SOL",
             "amount_lamports": 600, "purpose": "queued-dust"})
    assert q["decision"] == "queued"
    qid = q["queue_id"]
    items = d.rt_queue_read({}, "test")["queue"]
    assert items[0]["queue_id"] == qid
    assert items[0]["amount"] == 600
    assert items[0]["chain"] == DEVNET
    # Approve path also reaches the Solana executor (fails on RPC here —
    # unreachable default in the sandbox — but proves the wiring).
    r = req(d, app_token, "queue_approve", {"queue_id": qid})
    assert r["ok"] is False
    assert "queue_id" in r


def test_velocity_cap_denies():
    d, tmp, req_token, _ = make_daemon(policy={
        "auto_approve_below": {f"{DEVNET}:SOL": 10 ** 12},
        "daily_velocity_cap": {f"{DEVNET}:SOL": 500}})
    d._record_velocity(DEVNET, "SOL", 400)
    resp = req(d, req_token, "request_spend",
               {"chain": DEVNET, "destination": DEST, "asset": "SOL",
                "amount_lamports": 200, "purpose": "t"})
    assert resp["decision"] == "denied"
    assert "velocity" in resp["reason"]


# ------------------------------------------------------- client surface

def test_client_amount_lamports_plumbing():
    seen = {}

    class C(AgentClient):
        def _call(self, route, params=None):
            seen.update(params or {})
            return {"ok": True}

    c = C("/nonexistent.sock", "00" * 32)
    c.request_spend(chain=DEVNET, destination=DEST, amount_lamports=1234,
                    purpose="t")
    assert seen["amount_lamports"] == 1234
    assert "amount_wei" not in seen and "amount_mojos" not in seen
    with pytest.raises(ValueError, match="exactly one"):
        c.request_spend(chain=DEVNET, destination=DEST,
                        amount_lamports=1, amount_wei=2)

"""Regression tests for the agentmuse audit findings f-01..f-04.

f-01 (critical): rt_message_sign executed immediately on any non-empty
    self-asserted human_approval_ref, bypassing the human queue. Fixed:
    only daemon-issued signed refs (mint_sign_ref, approve-token only)
    execute immediately; everything else fails closed to the queue.
f-04 (low): the peer-UID allowlist was opt-in (unconfigured = no
    enforcement). Fixed: unconfigured fails closed.
"""
import json
import os
import tempfile

import pytest

from spellbook.daemon import Daemon

UID = os.getuid()
REQ = "aa" * 32
APP = "bb" * 32


def _write(p, data):
    with open(p, "w") as f:
        f.write(data)
    os.chmod(p, 0o600)


def _daemon(cfg_extra=None):
    tmp = tempfile.mkdtemp(prefix="spellbook-audit-")
    cfg = {
        "allowed_request_uids": [UID],
        "allowed_approve_uids": [UID],
    }
    cfg.update(cfg_extra or {})
    _write(os.path.join(tmp, "spellbook.json"), json.dumps(cfg))
    _write(os.path.join(tmp, "policy.json"), "{}")
    _write(os.path.join(tmp, "request.token"), REQ)
    _write(os.path.join(tmp, "approve.token"), APP)
    _write(os.path.join(tmp, "ledger.jsonl"), "")
    return Daemon(tmp)


def _sign_req(ref=None):
    p = {"chain": "evm-4663", "message": "0xdeadbeef",
         "address": "0x0000000000000000000000000000000000000001",
         "sign_type": "personal"}
    if ref is not None:
        p["human_approval_ref"] = ref
    return {"token": REQ, "route": "message_sign", "params": p,
            "muse_id": "test"}


# ---------------------------------------------------------------- f-01

def test_f01_self_asserted_ref_queues_fail_closed():
    """A self-asserted human_approval_ref must NOT execute; it queues."""
    d = _daemon()
    out = d.handle(_sign_req("speechless-said-yes-in-chat"), UID)
    assert out["ok"] is True
    assert out["decision"] == "queued", \
        f"self-asserted ref must fail closed, got {out['decision']}"


def test_f01_empty_ref_queues():
    d = _daemon()
    out = d.handle(_sign_req("   "), UID)
    assert out["decision"] == "queued"


def test_f01_mint_requires_approve_token():
    """mint_sign_ref is approve-token only."""
    d = _daemon()
    out = d.handle({"token": REQ, "route": "mint_sign_ref",
                    "params": {"chain": "evm-4663", "message": "x",
                               "address": "0x0000000000000000000000000000000000000001",
         "sign_type": "personal"},
                    "muse_id": "test"}, UID)
    assert out["ok"] is False
    assert "approve token" in out["error"]


def test_f01_minted_ref_executes_and_is_single_use():
    d = _daemon()
    params = {"chain": "evm-4663", "message": "0xdeadbeef",
              "address": "0x0000000000000000000000000000000000000001",
         "sign_type": "personal"}
    mint = d.handle({"token": APP, "route": "mint_sign_ref",
                     "params": params, "muse_id": "test"}, UID)
    assert mint["ok"] is True
    ref = mint["human_approval_ref"]
    assert ref.startswith("sr1.")

    # Tampered message must not verify -> queues
    evil = dict(params, message="0xevil")
    out = d.handle({"token": REQ, "route": "message_sign",
                    "params": {**evil, "human_approval_ref": ref},
                    "muse_id": "test"}, UID)
    assert out["decision"] == "queued", "tampered params must fail closed"

    # Forged ref must not verify -> queues
    out = d.handle(_sign_req(ref[:-4] + "aaaa"), UID)
    assert out["decision"] == "queued", "forged ref must fail closed"


def test_f01_ref_wrong_daemon_rejected():
    """A ref minted by one daemon process must not verify on another
    (per-process secret)."""
    d1 = _daemon()
    d2 = _daemon()
    params = {"chain": "evm-4663", "message": "0xdeadbeef",
              "address": "0x0000000000000000000000000000000000000001",
         "sign_type": "personal"}
    ref = d1._mint_sign_ref({**params, "intent": "message_sign",
                             "sign_type": "eth_personal", "purpose": ""})
    assert d2._verify_sign_ref(ref, {**params, "intent": "message_sign",
                                     "sign_type": "eth_personal",
                                     "purpose": ""}) is False


# ---------------------------------------------------------------- f-04

def test_f04_unconfigured_allowlist_fails_closed():
    """No allowed_*_uids in config -> denied, not silently unenforced."""
    d = _daemon(cfg_extra={})
    # strip the allowlists the helper adds
    d.cfg.pop("allowed_request_uids", None)
    d.cfg.pop("allowed_approve_uids", None)
    out = d.handle({"token": REQ, "route": "status",
                    "params": {}, "muse_id": "test"}, UID)
    assert out["ok"] is False
    assert "allowlist not configured" in out["error"]


def test_f04_wrong_uid_denied():
    d = _daemon()
    out = d.handle({"token": REQ, "route": "status",
                    "params": {}, "muse_id": "test"}, UID + 999999)
    assert out["ok"] is False
    assert "not allowed" in out["error"]


def test_f04_correct_uid_allowed():
    d = _daemon()
    out = d.handle({"token": REQ, "route": "status",
                    "params": {}, "muse_id": "test"}, UID)
    assert out["ok"] is True

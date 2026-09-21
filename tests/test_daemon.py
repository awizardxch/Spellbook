"""End-to-end daemon test: socket up, two-token split, policy, persistent
queue, velocity accounting, peer-UID enforcement, KDF-wired addresses.

Uses the installed `spellbook` package and the published TEST seed only.
"""
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time

import pytest

from spellbook.client import AgentClient, HumanClient, SpellbookError
from spellbook.daemon import Daemon

TEST_SEED_HEX = ("000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f")
EXPECTED_EVM_ADDR = "0xdaaa8d5b2dd0728eeded4c2085555b2dabcbace1"  # vector evm-4663-sign-default

UID = os.getuid()


def _write(path, data, mode=0o600):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)


@pytest.fixture(scope="module")
def live():
    tmp = tempfile.mkdtemp(prefix="spellbook-test-")
    req_token = secrets.token_hex(32)
    app_token = secrets.token_hex(32)
    _write(os.path.join(tmp, "request.token"), req_token)
    _write(os.path.join(tmp, "approve.token"), app_token)
    _write(os.path.join(tmp, "seed.key"), TEST_SEED_HEX)
    _write(os.path.join(tmp, "spellbook.json"), json.dumps({
        "seed_path": os.path.join(tmp, "seed.key"),
        "labels": ["default"],
        "allowed_request_uids": [UID],
        "allowed_approve_uids": [UID],
    }))
    _write(os.path.join(tmp, "policy.json"), json.dumps({
        "per_spend_cap": {"evm-4663:native": 1000},
        "approval_threshold": {"evm-4663:native": 100},
        "auto_approve_below": {"evm-4663:native": 10},
        "daily_velocity_cap": {"evm-46630:native": 100},
    }))
    _write(os.path.join(tmp, "ledger.jsonl"), "")
    sock = os.path.join(tmp, "spellbook.sock")

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "spellbook.daemon",
             "--socket", sock, "--config", tmp],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("daemon did not come up: "
                               + proc.stdout.read().decode())
        return proc

    proc = start()
    agent = AgentClient(sock, req_token, muse_id="muse_test")
    human = HumanClient(sock, app_token, muse_id="human_test")
    yield {"tmp": tmp, "sock": sock, "agent": agent, "human": human,
           "req_token": req_token, "app_token": app_token,
           "proc": proc, "start": start}
    proc.terminate()
    proc.wait(timeout=5)


def test_bad_token_rejected(live):
    bad = AgentClient(live["sock"], "00" * 32)
    with pytest.raises(SpellbookError, match="bad token"):
        bad.status()


def test_peer_uid_enforced(live):
    # The kernel credential is ENFORCED, not observed: a valid token from a
    # UID outside the allowlist is denied (direct handle() call with a
    # forged peer UID exercises the check without forging kernel state).
    d = Daemon(live["tmp"])
    resp = d.handle({"token": live["req_token"], "route": "status",
                     "params": {}, "muse_id": "x"}, peer_uid=424242)
    assert resp["ok"] is False and "UID" in resp["error"]
    resp = d.handle({"token": live["req_token"], "route": "status",
                     "params": {}, "muse_id": "x"}, peer_uid=UID)
    assert resp["ok"] is True


def test_request_token_cannot_approve(live):
    # S7, structural: the agent's client has no approve surface at all...
    assert not hasattr(live["agent"], "approve")
    assert not hasattr(live["agent"], "reject")
    # ...and the daemon rejects the attempt anyway.
    with pytest.raises(SpellbookError, match="approve token required"):
        live["agent"]._call("queue_approve", {"queue_id": "1"})


def test_policy_tiers(live):
    agent = live["agent"]
    tiny = {"chain": "evm-4663", "destination": "0xabc", "amount_mojos": 5,
            "purpose": "tip"}
    r = agent.request_spend(**tiny)
    assert r["decision"] == "approved"
    r = agent.request_spend(chain="evm-4663", destination="0xabc",
                            amount_mojos=500, purpose="tip")
    assert r["decision"] == "queued" and "queue_id" in r
    r = agent.request_spend(chain="evm-4663", destination="0xabc",
                            amount_mojos=5000, purpose="tip")
    assert r["decision"] == "denied"


def test_contract_call_shape_rejected(live):
    with pytest.raises(SpellbookError, match="schema violation"):
        live["agent"]._call("request_spend",
                            {"chain": "evm-4663", "destination": "0xabc",
                             "amount_mojos": 5, "calldata": "0xdeadbeef"})


def test_velocity_cap(live):
    agent = live["agent"]
    kw = dict(chain="evm-46630", destination="0xabc", purpose="v")
    assert agent.request_spend(amount_mojos=60, **kw)["decision"] == "approved"
    r = agent.request_spend(amount_mojos=50, **kw)
    assert r["decision"] == "denied" and "velocity" in r["reason"]
    assert agent.request_spend(amount_mojos=40, **kw)["decision"] == "approved"


def test_queue_decoded_intent_and_approve(live):
    agent, human = live["agent"], live["human"]
    r = agent.request_spend(chain="evm-4663", destination="0xdead",
                            amount_mojos=500, purpose="invoice #42")
    qid = r["queue_id"]
    q = agent.queue()
    item = next(i for i in q if i["queue_id"] == qid)
    # O10: full decoded intent, never just a hash.
    assert item["destination"] == "0xdead"
    assert item["amount"] == 500
    assert item["purpose"] == "invoice #42"
    assert item["chain"] == "evm-4663"
    assert human.approve(qid)["ok"] is True
    assert all(i["queue_id"] != qid for i in agent.queue())


def test_queue_reject(live):
    agent, human = live["agent"], live["human"]
    qid = agent.request_spend(chain="evm-4663", destination="0xdead",
                              amount_mojos=500, purpose="nope")["queue_id"]
    assert human.reject(qid)["ok"] is True
    assert all(i["queue_id"] != qid for i in agent.queue())


def test_queue_survives_restart(live):
    agent = live["agent"]
    qid = agent.request_spend(chain="evm-4663", destination="0xbeef",
                              amount_mojos=700, purpose="restart-me")["queue_id"]
    live["proc"].terminate()
    live["proc"].wait(timeout=5)
    if os.path.exists(live["sock"]):
        os.unlink(live["sock"])
    live["proc"] = live["start"]()
    # Fresh client objects (new tokens not needed — same config dir).
    agent2 = AgentClient(live["sock"], live["req_token"], muse_id="muse_test")
    q = agent2.queue()
    assert any(i["queue_id"] == qid and i["purpose"] == "restart-me" for i in q)
    HumanClient(live["sock"], live["app_token"]).reject(qid)


def test_addresses_wired_to_kdf(live):
    addrs = live["agent"].addresses()
    assert addrs["default"]["evm-4663"] == EXPECTED_EVM_ADDR
    assert addrs["default"]["evm-46630"].startswith("0x")
    assert len(addrs["default"]["chia-mainnet"]) == 96  # 48-byte hex pubkey


def test_ledger_readable_via_api(live):
    rows = live["agent"].ledger()
    assert len(rows) >= 5
    for row in rows:
        assert set(row) == {"ts", "requester_muse", "canon_digest",
                            "sighash", "decision"}
    # No bearer token ever lands in the ledger.
    blob = json.dumps(rows)
    assert live["req_token"] not in blob and live["app_token"] not in blob


def test_s1_gate_closed_by_default(live):
    with pytest.raises(SpellbookError, match="S1"):
        live["agent"]._call("sign_musebook_request",
                            {"method": "POST", "path": "/api/post", "body": "{}"})


def test_cli_status(live):
    env = dict(os.environ, SPELLBOOK_SOCKET=live["sock"],
               SPELLBOOK_REQUEST_TOKEN=live["req_token"])
    out = subprocess.run([sys.executable, "-m", "spellbook.cli", "status"],
                         capture_output=True, text=True, env=env, timeout=15)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["ok"] is True

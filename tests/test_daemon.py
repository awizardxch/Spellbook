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
        "auto_approve_below": {"evm-4663:native": 10, "evm-46630:native": 1000},
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


def test_s4_queue_by_default_no_policy(tmp_path):
    """S4 regression (town-adopted, thread 37143): with no policy configured,
    nothing is auto-approved — every spend queues for human approval."""
    from spellbook.policy import Policy, evaluate
    p = Policy()  # empty: {} policy.json
    d = evaluate(p, "chia-testnet", "native", 1, "txch1abc", 0)
    assert d.verdict == "queued" and "S4" in d.reason
    d = evaluate(p, "evm-46630", "native", 1, "0xabc", 0)
    assert d.verdict == "queued"
    # ...but explicit human-configured auto_approve_below lifts the queue.
    p2 = Policy(auto_approve_below={("chia-testnet", "native"): 100})
    assert evaluate(p2, "chia-testnet", "native", 50, "txch1abc", 0).verdict == "approved"
    assert evaluate(p2, "chia-testnet", "native", 101, "txch1abc", 0).verdict == "queued"
    assert evaluate(p2, "chia-testnet", "native", 100, "txch1abc", 0).verdict == "approved"


def test_s4_queue_by_default_end_to_end(tmp_path):
    """Same guarantee through the live daemon: empty policy.json -> queued."""
    from spellbook.daemon import Daemon
    req = "aa" * 32
    _write(tmp_path / "request.token", req)
    _write(tmp_path / "approve.token", "bb" * 32)
    _write(tmp_path / "policy.json", "{}")
    _write(tmp_path / "spellbook.json", json.dumps({}))
    _write(tmp_path / "ledger.jsonl", "")
    d = Daemon(str(tmp_path))
    resp = d.handle({"token": req, "route": "request_spend", "muse_id": "m",
                     "params": {"chain": "chia-testnet",
                                "destination": "txch1abc",
                                "amount_mojos": 1000, "purpose": "t"}},
                    peer_uid=UID)
    assert resp["ok"] is True and resp["decision"] == "queued"


# ------------------------------------------------- EVM caveat hardening

from spellbook import evm as evm_mod


class _FakeEvmRpc:
    """Stands in for evm.Rpc. wait_receipt raises BroadcastUnknown."""

    def __init__(self, url):
        self.url = url
        self.sent = []

    def chain_id(self):
        return 46630

    def estimate_gas(self, *a):
        return 30000

    def nonce(self, addr):
        return 7

    def gas_price_wei(self):
        return 10 ** 9

    def send_raw_tx(self, raw):
        self.sent.append(raw)
        return "0xdeadbeef"

    def wait_receipt(self, tx_hash, timeout=90, poll=1.0):
        raise evm_mod.BroadcastUnknown(tx_hash, "no receipt in time")


def _evm_daemon(tmp_path, monkeypatch):
    from spellbook.daemon import Daemon
    seed_hex = "42" * 32
    _write(tmp_path / "seed.key", seed_hex)
    cfg = {
        "seed_path": str(tmp_path / "seed.key"),
        "evm": {"chains": {"evm-46630": {"enabled": True,
                                         "rpc_url": "http://fake"}}},
    }
    _write(tmp_path / "spellbook.json", json.dumps(cfg))
    _write(tmp_path / "policy.json", json.dumps(
        {"auto_approve_below": {"evm-46630:native": 10 ** 18}}))
    _write(tmp_path / "request.token", "aa" * 32)
    _write(tmp_path / "approve.token", "bb" * 32)
    _write(tmp_path / "ledger.jsonl", "")
    monkeypatch.setattr(evm_mod, "Rpc", _FakeEvmRpc)
    return Daemon(str(tmp_path))


def _evm_params():
    return {"chain": "evm-46630",
            "destination": "0x" + "11" * 20,
            "amount_wei": 10 ** 15, "purpose": "t"}


def test_evm_broadcast_unknown_is_not_a_failure(tmp_path, monkeypatch):
    """Receipt timeout: the tx left the machine, so the daemon reports
    approved-submit-unknown (never approved-submit-failed), ledgers the
    hash, and consumes velocity fail-closed. No blind retry is possible
    from this response."""
    from spellbook.daemon import Daemon
    d = _evm_daemon(tmp_path, monkeypatch)
    resp = d.rt_request_spend(_evm_params(), "muse_test")
    assert resp["ok"] is True
    assert resp["decision"] == "approved-submit-unknown"
    assert resp["tx_hash"] == "0xdeadbeef"
    # velocity consumed fail-closed (assume it lands)
    assert d.spent_last_24h("evm-46630", "native") == 10 ** 15
    rows = d.ledger.read_all()
    decisions = [r["decision"] for r in rows]
    assert any(x == "executing" for x in decisions)
    unknown = [r for r in rows
               if r["decision"].startswith("approved-submit-unknown")]
    assert len(unknown) == 1 and unknown[0]["sighash"] == "0xdeadbeef"


def test_unresolved_executions_flags_crash_window(tmp_path, monkeypatch):
    """An 'executing' line with no later resolution shows up in
    unresolved_executions() — the crash-window record. Once the outcome
    lands, it clears."""
    from spellbook.daemon import Daemon
    d = _evm_daemon(tmp_path, monkeypatch)
    canon = json.dumps(_evm_params(), sort_keys=True).encode()
    d.ledger.append("muse_test", canon, None, "executing")
    un = d.unresolved_executions()
    assert len(un) == 1 and un[0]["requester_muse"] == "muse_test"
    # the outcome arrives later under the same canon digest
    d.ledger.append("muse_test", canon, "0xabc", "approved")
    assert d.unresolved_executions() == []
    # and rt_status surfaces it
    assert "unresolved_executions" in d.rt_status({}, "muse_test")


def test_signed_intent_checks_are_not_asserts(tmp_path, monkeypatch):
    """The pre-broadcast intent re-check must be real code, not `assert`
    (stripped under python -O). Tamper the signed fields and confirm
    _execute_spend refuses before broadcast."""
    from spellbook.daemon import Daemon
    import spellbook.evm as evm_mod
    d = _evm_daemon(tmp_path, monkeypatch)
    real_sign = evm_mod.sign_legacy_transfer

    def bad_sign(*a, **k):
        out = real_sign(*a, **k)
        out["value_wei"] = out["value_wei"] + 1  # tamper post-signing
        return out

    monkeypatch.setattr(evm_mod, "sign_legacy_transfer", bad_sign)
    rpc = _FakeEvmRpc("x")
    rpc.wait_receipt = lambda h, timeout=90, poll=1.0: {"status": "0x1",
                                                       "blockNumber": "0x5"}
    monkeypatch.setattr(evm_mod, "Rpc", lambda url: rpc)
    with pytest.raises(evm_mod.EvmError, match="mismatch"):
        d._execute_spend(_evm_params())
    assert rpc.sent == []  # nothing left the machine


def test_serve_survives_broken_pipe(tmp_path):
    """Regression: a client that dies mid-request (BrokenPipeError on the
    server side) must not kill the daemon's accept loop."""
    import socket as socket_mod
    import threading

    from spellbook import daemon as daemon_mod

    sock_path = str(tmp_path / "spellbook.sock")
    calls = {"n": 0}

    class FakeDaemon:
        cfg = {}

        def handle(self, req, uid):
            calls["n"] += 1
            if calls["n"] == 1:
                raise BrokenPipeError("client went away mid-request")
            return {"ok": True, "n": calls["n"]}

    t = threading.Thread(target=daemon_mod.serve,
                         args=(sock_path, FakeDaemon()), daemon=True)
    t.start()
    for _ in range(100):
        if os.path.exists(sock_path):
            break
        time.sleep(0.05)

    def rpc(payload):
        c = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        c.connect(sock_path)
        c.sendall((json.dumps(payload) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = c.recv(65536)
            if not chunk:
                break
            buf += chunk
        c.close()
        return json.loads(buf.decode()) if buf else None

    rpc({"route": "ping"})  # server-side BrokenPipeError; must not kill serve
    resp = rpc({"route": "ping"})  # daemon must still be answering
    assert resp == {"ok": True, "n": 2}


def test_evm_gas_price_applies_headroom():
    """Every EVM submission must price gas above the node's quote.

    Regression test for the 2026-09-24 Robinhood mainnet failures: the
    daemon signed legacy txs at exactly eth_gasPrice and the node rejected
    both submissions with "max fee per gas less than block base fee".
    """
    from spellbook import daemon as daemon_mod

    class _R:
        def gas_price_wei(self):
            return 100

    assert daemon_mod.EVM_GAS_PRICE_BUMP_BPS == 2500
    assert daemon_mod._evm_gas_price(_R()) == 125


def test_dex_error_during_approve_is_submit_failed_not_crash(tmp_path, monkeypatch):
    """Regression 2026-09-24: a DexError raised mid-execution (e.g. the
    relay dropping the firm-quote fetch) must ledger approved-submit-failed
    and return a structured error — never escape and kill the daemon."""
    from spellbook import dex as dex_mod
    from spellbook.daemon import Daemon
    d = _evm_daemon(tmp_path, monkeypatch)
    params = {"chain": "evm-4663", "intent": "dex_swap",
              "sell_token": "0x" + "ee" * 20,
              "buy_token": "0x" + "ab" * 20,
              "sell_amount_wei": 10 ** 15,
              "min_buy_amount_wei": 1, "purpose": "t"}
    d.queue["99"] = {"params": params, "muse_id": "muse_test",
                     "queued_at": 0}

    def _boom(self, p):
        raise dex_mod.DexError("DEX API unreachable: boom")

    monkeypatch.setattr(Daemon, "_execute_spend", _boom)
    resp = d.rt_queue_approve({"queue_id": "99"}, "muse_test")
    assert resp["ok"] is False
    assert "unreachable" in resp["error"]
    rows = d.ledger.read_all()
    assert any(r["decision"].startswith("approved-submit-failed")
               for r in rows)

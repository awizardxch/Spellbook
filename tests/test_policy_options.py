"""S-02: option exercise and option/DID/NFT moves are never judged as a
zero-value fee, and never auto-approve.

Pure tests of the daemon's policy/velocity logic with a bare Daemon (no
socket, no config files) and a recording fake for the Sage RPC. Sage's
OptionRecord shape (sage-api records/option.rs: launcher_id,
strike_asset {asset_id, kind}, strike_amount) is what the fake serves.
"""
import json
import os

import pytest

from spellbook import chia
from spellbook.chia import SageError
from spellbook.daemon import ALWAYS_QUEUE_INTENTS, Daemon
from spellbook.ledger import Ledger
from spellbook.policy import Policy

SEED = bytes.fromhex("42" * 32)
CHAIN = "chia-testnet"
CAT = "ab" * 32
OPT1 = "option1" + "q" * 52 + "abc"
OPT2 = "option1" + "z" * 52 + "def"
DID1 = "did:chia:1" + "q" * 50
NFT1 = "nft1" + "q" * 55


def _bare_daemon(tmp_path, policy=None):
    d = Daemon.__new__(Daemon)
    d.config_dir = str(tmp_path)
    d.cfg = {"chia_enabled": True}
    d.chia_cfg = {"sage_data_home": str(tmp_path), "rpc_port": 9257}
    d.policy = policy or Policy()
    d.key_derivation = "kdf"
    d.seed = SEED
    d.std_seed = None
    d.ledger = Ledger(str(tmp_path / "ledger.jsonl"))
    d.queue = {}
    d.next_qid = 1
    d.queue_path = str(tmp_path / "queue.json")
    d.velocity = []
    d.velocity_path = str(tmp_path / "velocity.jsonl")
    d._sage_proc = None
    d._sage_started_pid = None
    d._sage_listener_preexisting = False
    d._save_queue = lambda: None  # keep the test pure
    return d


def _option(oid, strike_asset_id, strike_amount, kind="token"):
    return {"launcher_id": oid, "name": None, "visible": True,
            "coin_id": "cc" * 32, "address": "txch1x", "amount": "1",
            "underlying_asset": {"asset_id": "ef" * 32, "kind": "token"},
            "underlying_amount": "1", "underlying_coin_id": "dd" * 32,
            "strike_asset": {"asset_id": strike_asset_id, "kind": kind},
            "strike_amount": strike_amount,
            "expiration_seconds": 4_000_000_000}


class _FakeRpc:
    def __init__(self, options=()):
        self.options = list(options)
        self.exercised = []

    def get_options(self, offset=0, limit=50):
        return self.options

    def exercise_options(self, ids, fee_mojos=0, auto_submit=True):
        self.exercised.append(list(ids))
        return {"summary": {"inputs": [{"coin_id": "0xin"}]}}


def _patch_sage(d, monkeypatch, rpc):
    monkeypatch.setattr(d, "_chia_sage_rpc",
                        lambda chain: (rpc, 1, "txch1daemon"))


# ---------------------------------------------------- strike legs from Sage

def test_option_strike_legs_reads_xch_and_cat_strikes(tmp_path):
    rpc = _FakeRpc([_option(OPT1, None, "5000000"),
                    _option(OPT2, CAT.upper(), 250)])
    legs = Daemon._option_strike_legs(rpc, [OPT1, OPT2])
    assert legs == [("native", 5_000_000), (CAT, 250)]


def test_option_strike_legs_merge_per_asset(tmp_path):
    rpc = _FakeRpc([_option(OPT1, None, 100), _option(OPT2, None, 200)])
    assert Daemon._option_strike_legs(rpc, [OPT1, OPT2]) == [("native", 300)]


def test_option_strike_legs_refuse_unknown_option_and_odd_strikes():
    rpc = _FakeRpc([_option(OPT1, None, 100)])
    with pytest.raises(SageError, match="not in this wallet"):
        Daemon._option_strike_legs(rpc, [OPT2])
    rpc = _FakeRpc([_option(OPT1, "ef" * 32, 1, kind="nft")])
    with pytest.raises(SageError, match="strike is a 'nft'"):
        Daemon._option_strike_legs(rpc, [OPT1])
    rpc = _FakeRpc([_option(OPT1, None, 0)])
    with pytest.raises(SageError, match="non-positive strike"):
        Daemon._option_strike_legs(rpc, [OPT1])
    rpc = _FakeRpc([_option(OPT1, "zz", 5)])
    with pytest.raises(SageError, match="malformed strike"):
        Daemon._option_strike_legs(rpc, [OPT1])


# --------------------------------------------------------- velocity legs

def test_option_exercise_entries_carry_the_strike(tmp_path):
    d = _bare_daemon(tmp_path)
    params = {"intent": "option_exercise", "chain": CHAIN,
              "option_ids": [OPT1], "fee_mojos": 7,
              "_strike": [{"asset": "native", "amount_mojos": 5_000_000},
                          {"asset": CAT, "amount_mojos": 250}]}
    entries = d._velocity_entries(params)
    assert (CHAIN, "native", 5_000_007) in entries
    assert (CHAIN, CAT, 250) in entries
    assert (CHAIN, f"option:{OPT1}", 1) in entries
    assert (CHAIN, "native", 0) not in entries


@pytest.mark.parametrize("intent,id_key,prefix,ids", [
    ("option_transfer", "option_ids", "option", [OPT1, OPT2]),
    ("did_transfer", "did_ids", "did", [DID1]),
    ("nft_assign_did", "nft_ids", "nft", [NFT1]),
])
def test_non_fungible_moves_are_never_a_zero_fee_entry(tmp_path, intent,
                                                        id_key, prefix, ids):
    d = _bare_daemon(tmp_path)
    params = {"intent": intent, "chain": CHAIN, id_key: ids,
              "fee_mojos": 0, "destination": "txch1somewhere"}
    entries = d._velocity_entries(params)
    assert entries != [(CHAIN, "native", 0)]
    assert (CHAIN, "native", 0) not in entries
    for i in ids:
        assert (CHAIN, f"{prefix}:{i}", 1) in entries


# ----------------------------------------------------------- always queue

def test_always_queue_set_names_the_four_intents():
    assert ALWAYS_QUEUE_INTENTS == {"option_exercise", "option_transfer",
                                    "did_transfer", "nft_assign_did"}


def _permissive_policy(extra_keys=()):
    """auto_approve_below for every key a test could touch — the only way
    _decide_fund_intent would say 'approved'."""
    auto = {(CHAIN, "native"): 10 ** 12, (CHAIN, CAT): 10 ** 12}
    for k in extra_keys:
        auto[(CHAIN, k)] = 10 ** 12
    return Policy(auto_approve_below=auto)


@pytest.mark.parametrize("intent,extra", [
    ("option_exercise", {"option_ids": [OPT1],
                         "_strike": [{"asset": "native", "amount_mojos": 5}]}),
    ("option_transfer", {"option_ids": [OPT1], "destination": "txch1a"}),
    ("did_transfer", {"did_ids": [DID1], "destination": "txch1a"}),
    ("nft_assign_did", {"nft_ids": [NFT1], "did_id": DID1}),
])
def test_these_intents_queue_even_when_policy_would_approve(tmp_path,
                                                            monkeypatch,
                                                            intent, extra):
    keys = [f"option:{OPT1}", f"did:{DID1}", f"nft:{NFT1}"]
    d = _bare_daemon(tmp_path, _permissive_policy(keys))
    params = {"intent": intent, "chain": CHAIN, "fee_mojos": 0,
              "purpose": "", **extra}
    entries = d._velocity_entries(params)
    assert d._decide_fund_intent(entries)[0] == "approved"  # policy alone
    executed = []
    monkeypatch.setattr(d, "_execute_spend",
                        lambda p: executed.append(p) or {"submitted": True,
                                                         "tx_hash": "x"})
    out = d._run_fund_intent(params, "m", entries, intent)
    assert out["decision"] == "queued", out
    assert "human approval" in out["reason"]
    assert executed == []
    assert d.queue["1"]["params"] == params


def test_caps_still_deny_an_always_queued_intent(tmp_path, monkeypatch):
    d = _bare_daemon(tmp_path, Policy(
        per_spend_cap={(CHAIN, "native"): 1_000_000},
        auto_approve_below={(CHAIN, "native"): 1_000_000}))
    params = {"intent": "option_exercise", "chain": CHAIN, "fee_mojos": 0,
              "option_ids": [OPT1],
              "_strike": [{"asset": "native", "amount_mojos": 5_000_000}]}
    out = d._run_fund_intent(params, "m", d._velocity_entries(params),
                             "option_exercise")
    assert out["decision"] == "denied"
    assert "per-spend cap" in out["reason"]
    assert d.queue == {}


# --------------------------------------------------- the request route

def test_rt_option_exercise_reads_strike_and_queues(tmp_path, monkeypatch):
    d = _bare_daemon(tmp_path, _permissive_policy([f"option:{OPT1}"]))
    rpc = _FakeRpc([_option(OPT1, None, 5_000_000)])
    _patch_sage(d, monkeypatch, rpc)
    out = d.rt_option_exercise({"chain": CHAIN, "option_ids": [OPT1]}, "m")
    assert out["ok"] is True and out["decision"] == "queued", out
    q = d.queue["1"]["params"]
    assert q["_strike"] == [{"asset": "native", "amount_mojos": 5_000_000}]
    assert rpc.exercised == []
    # The human sees the strike in the decoded queue.
    d.queue["1"]["queued_at"] = 0
    shown = d._decoded_queue()[0]
    assert shown["strike_legs"] == q["_strike"]


def test_rt_option_exercise_refuses_when_strike_unreadable(tmp_path,
                                                           monkeypatch):
    d = _bare_daemon(tmp_path)
    _patch_sage(d, monkeypatch, _FakeRpc([]))
    out = d.rt_option_exercise({"chain": CHAIN, "option_ids": [OPT1]}, "m")
    assert out["ok"] is False and "not in this wallet" in out["error"]
    assert d.queue == {}


def test_execute_option_exercise_refuses_changed_or_missing_strike(
        tmp_path, monkeypatch):
    d = _bare_daemon(tmp_path)
    rpc = _FakeRpc([_option(OPT1, None, 5_000_000)])
    _patch_sage(d, monkeypatch, rpc)
    base = {"intent": "option_exercise", "chain": CHAIN, "fee_mojos": 0,
            "option_ids": [OPT1]}
    with pytest.raises(SageError, match="no approved strike legs"):
        d._execute_option_exercise_via_sage(dict(base))
    with pytest.raises(SageError, match="strike changed"):
        d._execute_option_exercise_via_sage(
            {**base, "_strike": [{"asset": "native", "amount_mojos": 1}]})
    assert rpc.exercised == []


def test_execute_option_exercise_proceeds_on_matching_strike(tmp_path,
                                                             monkeypatch):
    d = _bare_daemon(tmp_path)
    rpc = _FakeRpc([_option(OPT1, None, 5_000_000)])
    _patch_sage(d, monkeypatch, rpc)
    monkeypatch.setattr(d, "_submit_sage_tx",
                        lambda rpc, res, t0, desc: {"submitted": True,
                                                    "tx_hash": "0xin"})
    out = d._execute_option_exercise_via_sage(
        {"intent": "option_exercise", "chain": CHAIN, "fee_mojos": 0,
         "option_ids": [OPT1],
         "_strike": [{"asset": "native", "amount_mojos": 5_000_000}]})
    assert out["submitted"] is True
    assert rpc.exercised == [[OPT1]]

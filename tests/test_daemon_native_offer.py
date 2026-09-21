"""Daemon integration tests for the native XCH offer path.

The native route (rt_offer_make/take/cancel + _execute_offer_*_native)
must never touch Sage: _chia_sage_rpc is monkeypatched to raise, the
fake relay serves coins and broadcast, and no test touches the live
daemon or broadcasts anything real.
"""
import hashlib
import json
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from spellbook import chia_offer, chia_sign, kdf
from spellbook.chia_relay import BroadcastUnknown, RelayError
from spellbook.daemon import Daemon

TEST_SEED_HEX = ("000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f")
SEED = bytes.fromhex(TEST_SEED_HEX)
CHAIN = "chia-testnet"


def _write(path, data, mode=0o600):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)


def _wallet_ph(index: int):
    d = kdf.derive_labeled(SEED, CHAIN, "default")
    master_sk = bytes.fromhex(d["scalar_hex"])
    wsk = chia_sign.wallet_sk(master_sk, index)
    spk = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk))
    return chia_sign.puzzle_hash_for_synthetic_pk(spk)


def _fund_coin(index: int, amount: int):
    ph = _wallet_ph(index)
    parent = bytes.fromhex("bb" * 32)
    return {
        "coin_id": chia_sign.coin_id(parent, ph, amount).hex(),
        "parent_coin_info": parent.hex(),
        "puzzle_hash": ph.hex(),
        "amount_mojos": amount,
        "created_height": 100,
        "spent_height": None,
    }


class FakeRelayRpc:
    def __init__(self, url, token="", token_provider=None, timeout=60):
        self.url = url
        self.coins_list = []
        self.broadcast_body = None
        self.broadcast_txid = None  # override to simulate mismatch
        self.broadcast_result = {"ok": True, "status": 1,
                                 "status_name": "SUCCESS", "error": None}

    def status(self):
        return {"ok": True, "network": "testnet11", "peak_height": 4715326,
                "peers": [], "peers_connected": 3}

    def coins(self, puzzle_hashes):
        return list(self.coins_list)

    def broadcast(self, spend_bundle):
        self.broadcast_body = spend_bundle
        local_txid = hashlib.sha256(bytes.fromhex(spend_bundle)).hexdigest()
        res = dict(self.broadcast_result)
        res["expected_txid"] = local_txid
        res["txid"] = self.broadcast_txid or local_txid
        return res


@pytest.fixture()
def env(tmp_path, monkeypatch):
    cfgdir = str(tmp_path)
    _write(os.path.join(cfgdir, "seed.key"), TEST_SEED_HEX)
    _write(os.path.join(cfgdir, "request.token"), "11" * 32)
    _write(os.path.join(cfgdir, "approve.token"), "22" * 32)
    _write(os.path.join(cfgdir, "spellbook.json"), json.dumps({
        "seed_path": os.path.join(cfgdir, "seed.key"),
        "labels": ["default"],
        "chia": {
            "network": "testnet11",
            "relay_urls": {"testnet11": "https://relay.example.com"},
            "relay_token": "t" * 32,
            "fee_mojos": 0,
            "relay_scan_indices": 10,
        },
    }))
    _write(os.path.join(cfgdir, "policy.json"), json.dumps({}))
    _write(os.path.join(cfgdir, "ledger.jsonl"), "")
    fake = FakeRelayRpc("https://relay.example.com")
    import spellbook.chia_relay as relay_mod
    monkeypatch.setattr(relay_mod, "RelayRpc",
                        lambda url, token="", token_provider=None,
                        timeout=60: fake)

    d = Daemon(cfgdir)

    from spellbook import chia as chia_mod
    sage_calls = []
    d.sage_calls = sage_calls

    def _no_sage(chain):
        # Records the call (so tests can assert the native path never
        # uses Sage) then fails the way a sage-less environment does.
        sage_calls.append(chain)
        raise chia_mod.SageError(
            "no usable sage_bin configured — cannot start Sage RPC")
    monkeypatch.setattr(d, "_chia_sage_rpc", _no_sage)
    return d, fake


def _receive_address():
    return chia_sign.address_for_puzzle_hash(_wallet_ph(3), "txch")


def _make_queued(d, **kw):
    p = {"chain": CHAIN,
         "offered": [{"asset": "native", "amount_mojos": 400_000}],
         "requested": [{"asset": "native", "amount_mojos": 400_000}],
         "receive_address": _receive_address(),
         "fee_mojos": 0}
    p.update(kw)
    return d.rt_offer_make(p, "muse-test")


class TestNativeOfferMake:
    def test_make_queues_then_executes_offline(self, env):
        d, fake = env
        fake.coins_list = [_fund_coin(0, 1_000_000)]
        res = _make_queued(d)
        assert res["ok"] and res["decision"] == "queued", res
        qid = res["queue_id"]
        params = d.queue[qid]["params"]
        assert params["transport"] == "native"
        # Human approval: execute the queued intent directly.
        out = d._execute_chia_spend(params)
        assert out["submitted"] is False
        offer_id = out["offer_id"]
        # Atomic mode-600 storage.
        rec = d._offer_load(offer_id)
        assert rec is not None and rec["status"] == "open"
        assert rec["offer"] == out["offer"]
        assert rec["transport"] == "native"
        path = os.path.join(d._offer_store_dir(), offer_id + ".json")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert not os.path.exists(path + ".tmp")
        # The stored offer parses and its legs are exact.
        parsed = chia_offer.parse_offer(out["offer"])
        legs = chia_offer.summarize_offer(parsed)
        assert legs["offered"] == [("native", 400_000)]
        assert legs["requested"] == [("native", 400_000)]
        assert d.sage_calls == []  # native path never touched Sage

    def test_make_rejects_missing_receive_address(self, env):
        d, fake = env
        fake.coins_list = [_fund_coin(0, 1_000_000)]
        res = d.rt_offer_make(
            {"chain": CHAIN,
             "offered": [{"asset": "native", "amount_mojos": 100}],
             "requested": [{"asset": "native", "amount_mojos": 100}]},
            "muse-test")
        assert res["ok"] is False and "receive_address" in res["error"]

    def test_make_rejects_unfunded(self, env):
        d, fake = env
        fake.coins_list = [_fund_coin(0, 50)]
        res = _make_queued(d)
        assert res["ok"] is False and "insufficient" in res["error"]

    def test_make_rejects_cat_legs_without_sage(self, env):
        # CAT legs cannot take the native path; the Sage fallback is
        # environmentally unavailable, so the request fails closed.
        d, fake = env
        res = d.rt_offer_make(
            {"chain": CHAIN,
             "offered": [{"asset": "ab" * 32, "amount_mojos": 100}],
             "requested": [{"asset": "native", "amount_mojos": 100}],
             "receive_address": _receive_address()},
            "muse-test")
        assert res["ok"] is False

    def test_make_no_relay_fails_closed(self, tmp_path, monkeypatch):
        cfgdir = str(tmp_path)
        _write(os.path.join(cfgdir, "seed.key"), TEST_SEED_HEX)
        _write(os.path.join(cfgdir, "request.token"), "11" * 32)
        _write(os.path.join(cfgdir, "approve.token"), "22" * 32)
        _write(os.path.join(cfgdir, "spellbook.json"), json.dumps({
            "seed_path": os.path.join(cfgdir, "seed.key"),
            "labels": ["default"],
            "chia": {"network": "testnet11", "fee_mojos": 0},
        }))
        _write(os.path.join(cfgdir, "policy.json"), json.dumps({}))
        _write(os.path.join(cfgdir, "ledger.jsonl"), "")
        d = Daemon(cfgdir)
        res = d.rt_offer_make(
            {"chain": CHAIN,
             "offered": [{"asset": "native", "amount_mojos": 100}],
             "requested": [{"asset": "native", "amount_mojos": 100}],
             "receive_address": _receive_address()},
            "muse-test")
        assert res["ok"] is False and "relay" in res["error"]


class TestNativeOfferTake:
    def _made_offer(self, d, fake):
        fake.coins_list = [_fund_coin(0, 1_000_000)]
        res = _make_queued(d)
        assert res["decision"] == "queued", res
        out = d._execute_chia_spend(d.queue[res["queue_id"]]["params"])
        return out

    def test_take_full_flow(self, env):
        d, fake = env
        made = self._made_offer(d, fake)
        # Taker side: fresh coins (the fake never marks spends).
        fake.coins_list = [_fund_coin(1, 900_000)]
        res = d.rt_offer_take({"chain": CHAIN, "offer": made["offer"],
                               "fee_mojos": 0}, "muse-test")
        assert res["ok"] and res["decision"] == "queued", res
        params = d.queue[res["queue_id"]]["params"]
        assert params["transport"] == "native"
        assert params["_give"] == [{"asset": "native", "amount_mojos": 400_000}]
        assert params["_get"] == [{"asset": "native", "amount_mojos": 400_000}]
        out = d._execute_chia_spend(params)
        assert out["submitted"] is True
        # Strict txid identity: the daemon's tx_hash is sha256 of the
        # exact bytes it sent the fake relay.
        bundle_bytes = bytes.fromhex(fake.broadcast_body)
        assert out["tx_hash"] == hashlib.sha256(bundle_bytes).hexdigest()
        # The broadcast bundle parses and carries both sides.
        spends, _sig = chia_offer.parse_solutions_bundle(bundle_bytes)
        assert len(spends) == 4  # maker completion + maker + taker completion + taker
        assert d.sage_calls == []  # native path never touched Sage

    def test_take_rejects_term_change_at_execution(self, env):
        d, fake = env
        made = self._made_offer(d, fake)
        fake.coins_list = [_fund_coin(1, 900_000)]
        res = d.rt_offer_take({"chain": CHAIN, "offer": made["offer"]},
                              "muse-test")
        params = dict(d.queue[res["queue_id"]]["params"])
        params["_give"] = [{"asset": "native", "amount_mojos": 400_001}]
        with pytest.raises(RelayError, match="terms changed"):
            d._execute_chia_spend(params)

    def test_take_rejects_garbage_offer(self, env):
        d, fake = env
        # Not native-parseable -> Sage fallback -> environmentally refused.
        res = d.rt_offer_take({"chain": CHAIN, "offer": "offer1qqqqqqqqqqqqq"},
                              "muse-test")
        assert res["ok"] is False

    def test_take_broadcast_mismatch_is_unknown(self, env):
        d, fake = env
        made = self._made_offer(d, fake)
        fake.coins_list = [_fund_coin(1, 900_000)]
        fake.broadcast_txid = "00" * 32  # peer acks a different txid
        res = d.rt_offer_take({"chain": CHAIN, "offer": made["offer"]},
                              "muse-test")
        params = d.queue[res["queue_id"]]["params"]
        with pytest.raises(BroadcastUnknown):
            d._execute_chia_spend(params)


class TestNativeOfferCancel:
    def _made_offer(self, d, fake):
        fake.coins_list = [_fund_coin(0, 1_000_000)]
        res = _make_queued(d)
        out = d._execute_chia_spend(d.queue[res["queue_id"]]["params"])
        return out

    def test_cancel_full_flow(self, env):
        d, fake = env
        made = self._made_offer(d, fake)
        res = d.rt_offer_cancel({"chain": CHAIN, "offer_id": made["offer_id"]},
                                "muse-test")
        assert res["ok"] and res["decision"] == "queued", res
        params = d.queue[res["queue_id"]]["params"]
        assert params["transport"] == "native"
        out = d._execute_chia_spend(params)
        assert out["submitted"] is True
        bundle_bytes = bytes.fromhex(fake.broadcast_body)
        assert out["tx_hash"] == hashlib.sha256(bundle_bytes).hexdigest()
        rec = d._offer_load(made["offer_id"])
        assert rec["status"] == "cancelled"
        assert rec["cancel_txid"] == out["tx_hash"]
        assert d.sage_calls == []  # native path never touched Sage
        # Second cancel of the same offer refuses (no longer open).
        res2 = d.rt_offer_cancel({"chain": CHAIN,
                                  "offer_id": made["offer_id"]}, "muse-test")
        assert res2["ok"] is False and "not open" in res2["error"]

    def test_cancel_refuses_spent_maker_coins(self, env):
        d, fake = env
        made = self._made_offer(d, fake)
        # Relay now reports the maker coin as spent.
        spent = dict(_fund_coin(0, 1_000_000))
        spent["spent_height"] = 4715327
        fake.coins_list = [spent]
        res = d.rt_offer_cancel({"chain": CHAIN, "offer_id": made["offer_id"]},
                                "muse-test")
        params = d.queue[res["queue_id"]]["params"]
        with pytest.raises(RelayError, match="already spent"):
            d._execute_chia_spend(params)

    def test_cancel_unknown_offer_fails_closed(self, env):
        d, _fake = env
        res = d.rt_offer_cancel({"chain": CHAIN, "offer_id": "ff" * 32},
                                "muse-test")
        assert res["ok"] is False


class TestNativeOfferReads:
    def test_get_offer_serves_local_store(self, env):
        d, fake = env
        fake.coins_list = [_fund_coin(0, 1_000_000)]
        res = _make_queued(d)
        out = d._execute_chia_spend(d.queue[res["queue_id"]]["params"])
        got = d.rt_chia_read({"chain": CHAIN, "op": "get_offer",
                              "offer_id": out["offer_id"]}, "muse-test")
        assert got["ok"] is True
        assert got["result"]["offer_id"] == out["offer_id"]
        assert got["result"]["status"] == "open"

    def test_get_offers_lists_local(self, env):
        d, fake = env
        fake.coins_list = [_fund_coin(0, 1_000_000)]
        res = _make_queued(d)
        out = d._execute_chia_spend(d.queue[res["queue_id"]]["params"])
        got = d.rt_chia_read({"chain": CHAIN, "op": "get_offers"}, "muse-test")
        assert got["ok"] is True
        assert any(r["offer_id"] == out["offer_id"] for r in got["result"])

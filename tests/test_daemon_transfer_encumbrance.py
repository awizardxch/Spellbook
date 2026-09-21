"""Daemon regression tests: ordinary XCH transfers respect offer encumbrance.

The ordinary relay-backed transfer path
(``_execute_chia_spend_via_relay``) must never spend a coin committed as
a maker input to a locally-stored open native offer — otherwise the
maker coin is double-spent (the open offer's make spend and the plain
transfer both spend it) and the mempool rejects the bundle. The transfer
path keeps its own inline largest-first selection loop, so it needs its
own coverage proving it skips encumbered coins, fails closed when only
encumbered value could fund the transfer, and releases the coins once
the offer is no longer open.

Same mocking style as test_daemon_native_offer.py: the fake relay
serves coins and broadcast, Sage is unreachable, and nothing touches
the network or broadcasts anything real.
"""
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from spellbook import chia_offer, chia_sign, kdf
from spellbook.chia_relay import RelayError
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

    def status(self):
        return {"ok": True, "network": "testnet11", "peak_height": 4715326,
                "peers": [], "peers_connected": 3}

    def coins(self, puzzle_hashes):
        return list(self.coins_list)

    def broadcast(self, spend_bundle):
        self.broadcast_body = spend_bundle
        local_txid = hashlib.sha256(bytes.fromhex(spend_bundle)).hexdigest()
        return {"ok": True, "status": 1, "status_name": "SUCCESS",
                "error": None, "expected_txid": local_txid,
                "txid": local_txid}


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
        sage_calls.append(chain)
        raise chia_mod.SageError(
            "no usable sage_bin configured — cannot start Sage RPC")
    monkeypatch.setattr(d, "_chia_sage_rpc", _no_sage)
    return d, fake


def _receive_address():
    return chia_sign.address_for_puzzle_hash(_wallet_ph(3), "txch")


def _make_open_offer(d, fake, coins):
    """Create an open native offer; returns the maker coin id."""
    fake.coins_list = coins
    res = d.rt_offer_make(
        {"chain": CHAIN,
         "offered": [{"asset": "native", "amount_mojos": 400_000}],
         "requested": [{"asset": "native", "amount_mojos": 400_000}],
         "receive_address": _receive_address(),
         "fee_mojos": 0}, "muse-test")
    assert res["decision"] == "queued", res
    out = d._execute_chia_spend(d.queue[res["queue_id"]]["params"])
    rec = d._offer_load(out["offer_id"])
    assert rec["status"] == "open"
    return out["offer_id"], rec["maker_coins"][0]["coin_id"]


def _transfer(d, amount):
    return d._execute_chia_spend_via_relay({
        "chain": CHAIN,
        "destination": _receive_address(),
        "amount_mojos": amount,
    })


def _bundle_coin_ids(fake):
    assert fake.broadcast_body is not None, "nothing was broadcast"
    spends, _sig = chia_offer.parse_solutions_bundle(
        bytes.fromhex(fake.broadcast_body))
    return {sp.coin.coin_id().hex() for sp in spends}


class TestTransferEncumbrance:
    """Ordinary transfers must not spend offer-encumbered coins."""

    def test_transfer_fails_closed_when_only_encumbered_coin_can_fund(
            self, env):
        d, fake = env
        coins = [_fund_coin(0, 1_000_000), _fund_coin(1, 900_000)]
        _offer_id, encumbered = _make_open_offer(d, fake, coins)
        # The offer make is off-chain: the relay still reports both coins
        # unspent, so without the encumbrance check the 950_000 transfer
        # would pick the 1_000_000 encumbered coin.
        fake.coins_list = coins
        with pytest.raises(RelayError, match="insufficient balance"):
            _transfer(d, 950_000)
        assert fake.broadcast_body is None, \
            "transfer broadcast despite failing closed"

    def test_transfer_fails_closed_when_all_coins_encumbered(self, env):
        d, fake = env
        coins = [_fund_coin(0, 1_000_000)]
        _offer_id, encumbered = _make_open_offer(d, fake, coins)
        assert d._open_offer_coin_ids() == {encumbered}
        fake.coins_list = coins
        with pytest.raises(RelayError, match="insufficient balance"):
            _transfer(d, 100_000)
        assert fake.broadcast_body is None

    def test_transfer_skips_encumbered_coin_and_succeeds(self, env):
        d, fake = env
        coins = [_fund_coin(0, 1_000_000), _fund_coin(1, 900_000)]
        _offer_id, encumbered = _make_open_offer(d, fake, coins)
        fake.coins_list = coins
        out = _transfer(d, 100_000)
        assert out["submitted"] is True
        spent = _bundle_coin_ids(fake)
        assert encumbered not in spent, \
            "ordinary transfer spent the offer-encumbered maker coin"
        assert coins[1]["coin_id"] in spent, \
            "transfer did not spend the unencumbered coin"
        # Strict txid identity on the transfer broadcast.
        assert out["tx_hash"] == hashlib.sha256(
            bytes.fromhex(fake.broadcast_body)).hexdigest()
        assert d.sage_calls == []  # transfer path never touched Sage

    def test_transfer_can_use_coin_after_offer_cancelled(self, env):
        d, fake = env
        coins = [_fund_coin(0, 1_000_000), _fund_coin(1, 900_000)]
        offer_id, encumbered = _make_open_offer(d, fake, coins)
        # Cancel: the relay still reports the coin unspent, so the
        # cancel spend confirms against the same coins.
        fake.coins_list = coins
        res = d.rt_offer_cancel({"chain": CHAIN, "offer_id": offer_id},
                                "muse-test")
        assert res["decision"] == "queued", res
        d._execute_chia_spend(d.queue[res["queue_id"]]["params"])
        assert d._open_offer_coin_ids() == set()
        # The released 1_000_000 coin is now selectable for a plain
        # transfer that could not have funded it while encumbered.
        fake.broadcast_body = None
        out = _transfer(d, 950_000)
        assert out["submitted"] is True
        spent = _bundle_coin_ids(fake)
        assert encumbered in spent, \
            "transfer did not pick up the released coin"

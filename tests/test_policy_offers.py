"""S-03: policy sees exactly what the wallet spends on an offer.

Three undercounts, each tested with Sage-shaped summaries (the OfferAsset
shape from sage/src/utils/offer_summary.rs: {asset: {asset_id, kind},
amount, royalty, nft_royalty, option_assets}) and with daemon request
legs:
  - duplicate legs for one asset are refused at request time on every
    path, and merged before policy wherever legs can still reach it;
  - the offer fee is counted in the native entry and bounded by
    chia.max_offer_fee_mojos;
  - on take, Sage's `royalty` is added to the give leg in its asset, and
    option legs / unknown kinds are refused.
"""
import pytest

from spellbook import chia
from spellbook.chia import SageError
from spellbook.config import DEFAULT_MAX_OFFER_FEE_MOJOS
from spellbook.daemon import (Daemon, _merge_legs, _summary_legs,
                              _validate_offer_legs)
from spellbook.ledger import Ledger
from spellbook.policy import Policy

SEED = bytes.fromhex("42" * 32)
CHAIN = "chia-testnet"
CAT = "ab" * 32
CAT2 = "cd" * 32
NFT = "ef" * 32


def _sage_leg(asset_id, amount, kind="token", royalty=0, option_assets=None,
              nft_royalty=None):
    return {"asset": {"asset_id": asset_id, "name": None, "ticker": None,
                      "precision": 12, "icon_url": None, "description": None,
                      "is_sensitive_content": False, "is_visible": True,
                      "revocation_address": None, "kind": kind},
            "amount": str(amount), "royalty": str(royalty),
            "nft_royalty": nft_royalty, "option_assets": option_assets}


def _bare_daemon(tmp_path, policy=None, chia_cfg=None):
    d = Daemon.__new__(Daemon)
    d.config_dir = str(tmp_path)
    d.cfg = {"chia_enabled": True}
    d.chia_cfg = dict(chia_cfg or {"sage_data_home": str(tmp_path),
                                   "rpc_port": 9257})
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
    d._save_queue = lambda: None
    return d


# ------------------------------------------------- Sage-shaped summaries

def test_taker_royalty_is_added_to_the_give_leg():
    summary = {"maker": [_sage_leg(NFT, 1, kind="nft", nft_royalty={
                   "royalty_address": "txch1royalty",
                   "royalty_basis_points": 65535})],
               "taker": [_sage_leg(None, 900_000, royalty=5_899_000)]}
    assert _summary_legs(summary, "taker") == [("native", 6_799_000)]
    assert _summary_legs(summary, "maker") == [(f"nft:{NFT}", 1)]


def test_cat_royalty_is_added_in_the_cat():
    summary = {"maker": [_sage_leg(NFT, 1, kind="nft")],
               "taker": [_sage_leg(CAT.upper(), 1000, royalty=250)]}
    assert _summary_legs(summary, "taker") == [(CAT, 1250)]


def test_maker_side_royalty_is_not_added_to_what_we_receive():
    summary = {"maker": [_sage_leg(None, 1000, royalty=100)],
               "taker": [_sage_leg(NFT, 1, kind="nft")]}
    assert _summary_legs(summary, "maker") == [("native", 1000)]


def test_option_legs_and_unknown_kinds_are_refused():
    opt = {"underlying_asset": {"asset_id": CAT, "kind": "token"},
           "underlying_amount": "1",
           "strike_asset": {"asset_id": None, "kind": "token"},
           "strike_amount": "10", "expiration_seconds": 1}
    summary = {"maker": [_sage_leg(None, 10)],
               "taker": [_sage_leg(NFT, 1, kind="option", option_assets=opt)]}
    with pytest.raises(SageError, match="option"):
        _summary_legs(summary, "taker")
    summary = {"maker": [_sage_leg(None, 10)],
               "taker": [_sage_leg(NFT, 1, kind="token", option_assets=opt)]}
    with pytest.raises(SageError, match="option_assets"):
        _summary_legs(summary, "taker")
    for kind in ("did", "option", "something_new"):
        summary = {"maker": [_sage_leg(None, 10)],
                   "taker": [_sage_leg(NFT, 1, kind=kind)]}
        with pytest.raises(SageError, match="not supported"):
            _summary_legs(summary, "taker")


def test_duplicate_assets_in_a_summary_are_refused():
    summary = {"maker": [_sage_leg(None, 10)],
               "taker": [_sage_leg(None, 900_000), _sage_leg(None, 900_000)]}
    with pytest.raises(SageError, match="twice"):
        _summary_legs(summary, "taker")


# -------------------------------------------------- daemon request legs

def test_validate_offer_legs_refuses_duplicates():
    with pytest.raises(SageError, match="twice"):
        _validate_offer_legs([{"asset": "native", "amount_mojos": 900_000},
                              {"asset": "native", "amount_mojos": 900_000}],
                             "offered")
    with pytest.raises(SageError, match="twice"):
        _validate_offer_legs([{"asset": CAT, "amount_mojos": 1},
                              {"asset": CAT.upper(), "amount_mojos": 2}],
                             "requested")
    with pytest.raises(SageError, match="twice"):
        _validate_offer_legs([{"asset": f"nft:{NFT}", "amount_mojos": 1},
                              {"asset": f"nft:{NFT}", "amount_mojos": 1}],
                             "offered")
    # distinct assets still pass
    assert _validate_offer_legs(
        [{"asset": "native", "amount_mojos": 5},
         {"asset": CAT, "amount_mojos": 7}], "offered") == [
        ("native", 5), (CAT, 7)]


def test_merge_legs_sums_per_asset_in_order():
    assert _merge_legs([("native", 1), (CAT, 2), ("native", 3)]) == [
        ("native", 4), (CAT, 2)]


def test_rt_offer_make_rejects_split_legs_before_any_policy(tmp_path,
                                                            monkeypatch):
    d = _bare_daemon(tmp_path, Policy(
        auto_approve_below={(CHAIN, "native"): 1_000_000},
        per_spend_cap={(CHAIN, "native"): 1_000_000}))
    monkeypatch.setattr(d, "_chia_sage_rpc", lambda chain: (
        _ for _ in ()).throw(AssertionError("Sage reached")))
    monkeypatch.setattr(d, "_rt_offer_make_native", lambda *a: (
        _ for _ in ()).throw(AssertionError("native path reached")))
    out = d.rt_offer_make({
        "chain": CHAIN,
        "offered": [{"asset": "native", "amount_mojos": 900_000}] * 5,
        "requested": [{"asset": CAT, "amount_mojos": 1}]}, "m")
    assert out["ok"] is False and "twice" in out["error"]


# --------------------------------------------------- fee: counted + bounded

def test_offer_entries_merge_and_include_the_fee(tmp_path):
    d = _bare_daemon(tmp_path)
    make = {"intent": "offer_make", "chain": CHAIN, "fee_mojos": 11,
            "offered": [{"asset": "native", "amount_mojos": 5},
                        {"asset": CAT, "amount_mojos": 7}]}
    assert d._velocity_entries(make) == [(CHAIN, "native", 16),
                                         (CHAIN, CAT, 7)]
    take = {"intent": "offer_take", "chain": CHAIN, "fee_mojos": 3,
            "_give": [{"asset": CAT, "amount_mojos": 9}]}
    assert d._velocity_entries(take) == [(CHAIN, CAT, 9),
                                         (CHAIN, "native", 3)]
    # legs that somehow reached policy split are judged merged
    split = {"intent": "offer_make", "chain": CHAIN, "fee_mojos": 0,
             "offered": [{"asset": "native", "amount_mojos": 900_000}] * 5}
    assert d._velocity_entries(split) == [(CHAIN, "native", 4_500_000)]
    d.policy = Policy(per_spend_cap={(CHAIN, "native"): 1_000_000},
                      auto_approve_below={(CHAIN, "native"): 1_000_000},
                      daily_velocity_cap={(CHAIN, "native"): 1_500_000})
    assert d._decide_fund_intent(d._velocity_entries(split))[0] == "denied"


def test_fee_counts_against_the_native_cap(tmp_path):
    d = _bare_daemon(tmp_path, Policy(
        per_spend_cap={(CHAIN, "native"): 1_000_000},
        auto_approve_below={(CHAIN, "native"): 1_000_000}))
    make = {"intent": "offer_make", "chain": CHAIN, "fee_mojos": 200_000,
            "offered": [{"asset": "native", "amount_mojos": 900_000}]}
    assert d._decide_fund_intent(d._velocity_entries(make))[0] == "denied"


def test_offer_fee_is_bounded_by_config(tmp_path):
    d = _bare_daemon(tmp_path)
    assert DEFAULT_MAX_OFFER_FEE_MOJOS == 50_000_000
    d._chia_offer_guards({"fee_mojos": DEFAULT_MAX_OFFER_FEE_MOJOS}, CHAIN)
    with pytest.raises(SageError, match="max_offer_fee_mojos"):
        d._chia_offer_guards({"fee_mojos": 10 ** 12}, CHAIN)
    with pytest.raises(SageError, match="max_offer_fee_mojos"):
        d._chia_offer_guards({"fee_mojos": DEFAULT_MAX_OFFER_FEE_MOJOS + 1},
                             CHAIN)
    d.chia_cfg["max_offer_fee_mojos"] = 100
    d._chia_offer_guards({"fee_mojos": 100}, CHAIN)
    with pytest.raises(SageError, match="max_offer_fee_mojos"):
        d._chia_offer_guards({"fee_mojos": 101}, CHAIN)
    with pytest.raises(SageError, match="non-negative"):
        d._chia_offer_guards({"fee_mojos": True}, CHAIN)


def test_rt_offer_make_refuses_unbounded_fee(tmp_path, monkeypatch):
    d = _bare_daemon(tmp_path)
    out = d.rt_offer_make({
        "chain": CHAIN, "fee_mojos": 10 ** 12,
        "offered": [{"asset": "native", "amount_mojos": 1}],
        "requested": [{"asset": CAT, "amount_mojos": 1}]}, "m")
    assert out["ok"] is False and "max_offer_fee_mojos" in out["error"]
    out = d.rt_offer_take({"chain": CHAIN, "offer": "offer1x",
                           "fee_mojos": 10 ** 12}, "m")
    assert out["ok"] is False and "max_offer_fee_mojos" in out["error"]


# ------------------------------------------- take: royalty through policy

class _TakeRpc:
    def __init__(self, summary):
        self.summary = summary
        self.taken = []

    def view_offer(self, offer):
        return {"offer": self.summary, "status": "active"}

    def get_nfts(self, offset=0, limit=50):
        return []

    def get_cats(self):
        return []

    def sync_status(self):
        return {"selectable_balance": 10 ** 13}

    def take_offer(self, offer, fee_mojos=0, auto_submit=True):
        self.taken.append(offer)
        return {"transaction_id": "tx"}


def _take_daemon(tmp_path, monkeypatch, royalty):
    d = _bare_daemon(tmp_path, Policy(
        per_spend_cap={(CHAIN, "native"): 1_000_000},
        auto_approve_below={(CHAIN, "native"): 1_000_000}))
    summary = {"maker": [_sage_leg(NFT, 1, kind="nft", nft_royalty={
                   "royalty_address": "txch1royalty",
                   "royalty_basis_points": 5000})],
               "taker": [_sage_leg(None, 900_000, royalty=royalty)]}
    rpc = _TakeRpc(summary)
    monkeypatch.setattr(d, "_chia_sage_rpc", lambda chain: (rpc, 1, "txch1d"))
    executed = []
    monkeypatch.setattr(d, "_execute_spend",
                        lambda p: executed.append(p) or {"submitted": True,
                                                         "tx_hash": "tx"})
    return d, rpc, executed


def test_take_with_royalty_is_judged_on_the_full_payment(tmp_path,
                                                         monkeypatch):
    d, rpc, executed = _take_daemon(tmp_path, monkeypatch, royalty=500_000)
    out = d.rt_offer_take({"chain": CHAIN, "offer": "offer1notnative"}, "m")
    assert out["ok"] is True and out["decision"] == "denied", out
    assert "per-spend cap" in out["reason"]
    assert executed == [] and rpc.taken == []


def test_take_without_royalty_passes_the_same_policy(tmp_path, monkeypatch):
    d, rpc, executed = _take_daemon(tmp_path, monkeypatch, royalty=0)
    out = d.rt_offer_take({"chain": CHAIN, "offer": "offer1notnative"}, "m")
    assert out["decision"] == "approved", out
    assert executed and executed[0]["_give"] == [
        {"asset": "native", "amount_mojos": 900_000}]


def test_take_records_royalty_inclusive_give_leg_for_execution(tmp_path,
                                                               monkeypatch):
    """The queued/approved intent carries the royalty-inclusive give leg,
    and execution re-derives the same leg from Sage (terms unchanged)."""
    d, rpc, executed = _take_daemon(tmp_path, monkeypatch, royalty=50_000)
    out = d.rt_offer_take({"chain": CHAIN, "offer": "offer1notnative"}, "m")
    assert out["decision"] == "approved", out
    assert executed[0]["_give"] == [{"asset": "native",
                                     "amount_mojos": 950_000}]
    assert d.spent_last_24h(CHAIN, "native") == 950_000

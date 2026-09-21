"""Tests for Spellbook offer support: Sage RPC offer/coin/tx/asset/system
wrappers (payload shapes), daemon offer intent queueing/approval/
execution, the chia_read allowlist, velocity accounting, and decoded
queue rendering.

No live wallet is touched: the RPC layer is a recording stub and the
daemon layer monkeypatches chia.SageRpc with an offer-capable fake.
"""
import sys

import pytest

sys.path.insert(0, "tests")

from test_chia import _daemon_with_seed, _FakeSage  # noqa: E402

from spellbook import chia  # noqa: E402
from spellbook.chia import SageError, SageRpc  # noqa: E402
from spellbook.daemon import (  # noqa: E402
    _summary_legs,
    _validate_offer_legs,
)

CAT = "ab" * 32


# ------------------------------------------------- recording RPC stub


class _Rec(SageRpc):
    """Records (endpoint, payload) and serves canned responses."""

    def __init__(self, canned=None):
        self.calls = []
        self.canned = canned or {}

    def call(self, endpoint, payload=None):
        self.calls.append((endpoint, payload))
        return self.canned.get(endpoint, {})

    def last(self):
        return self.calls[-1]


def test_make_offer_payload_shape():
    rpc = _Rec({"make_offer": {"offer": "OFFER1", "offer_id": "id1"}})
    out = rpc.make_offer([{"asset": "native", "amount_mojos": 1000}],
                         [{"asset": CAT, "amount_mojos": 500}],
                         fee_mojos=7, receive_address="txch1r",
                         expires_at_second=123)
    assert out == {"offer": "OFFER1", "offer_id": "id1"}
    ep, body = rpc.last()
    assert ep == "make_offer"
    assert body["offered_assets"] == [{"amount": 1000}]
    assert body["requested_assets"] == [{"asset_id": CAT, "amount": 500}]
    assert body["fee"] == 7
    assert body["receive_address"] == "txch1r"
    assert body["expires_at_second"] == 123
    assert body["auto_import"] is True


def test_make_offer_optional_fields_omitted():
    rpc = _Rec({"make_offer": {"offer": "OFFER1", "offer_id": "id1"}})
    rpc.make_offer([{"asset": "native", "amount_mojos": 1}],
                   [{"asset": "native", "amount_mojos": 2}])
    _, body = rpc.last()
    assert "receive_address" not in body
    assert "expires_at_second" not in body


def test_make_offer_rejects_empty_sides():
    rpc = _Rec()
    with pytest.raises(SageError):
        rpc.make_offer([], [{"asset": "native", "amount_mojos": 1}])


def test_make_offer_rejects_bad_legs():
    rpc = _Rec()
    with pytest.raises(SageError):
        rpc.make_offer([{"asset": "native", "amount_mojos": 0}],
                       [{"asset": "native", "amount_mojos": 1}])
    with pytest.raises(SageError):
        rpc.make_offer([{"asset": "bogus", "amount_mojos": 1}],
                       [{"asset": "native", "amount_mojos": 1}])


def test_take_offer_payload_shape():
    rpc = _Rec({"take_offer": {"transaction_id": "tx1"}})
    out = rpc.take_offer("OFFERSTR", fee_mojos=3)
    assert out["transaction_id"] == "tx1"
    ep, body = rpc.last()
    assert ep == "take_offer"
    assert body == {"offer": "OFFERSTR", "fee": 3, "auto_submit": True}


def test_cancel_offer_payload_shapes():
    rpc = _Rec({"cancel_offer": {"ok": True},
                "cancel_offers": {"ok": True}})
    rpc.cancel_offer("oid1", fee_mojos=2)
    assert rpc.last() == ("cancel_offer",
                          {"offer_id": "oid1", "fee": 2, "auto_submit": True})
    rpc.cancel_offers(["oid1", "oid2"])
    assert rpc.last() == ("cancel_offers",
                          {"offer_ids": ["oid1", "oid2"], "fee": 0,
                           "auto_submit": True})


def test_offer_read_payload_shapes():
    rpc = _Rec({"get_offers": {"offers": [{"offer_id": "a"}]},
                "get_offer": {"offer": {"offer_id": "a"}},
                "get_offers_for_asset": {"offers": []},
                "view_offer": {"offer": {}, "status": "pending"},
                "import_offer": {"offer_id": "imp1"},
                "combine_offers": {"offer": "COMBINED"}})
    assert rpc.get_offers() == [{"offer_id": "a"}]
    assert rpc.last() == ("get_offers", {})
    assert rpc.get_offer("a") == {"offer_id": "a"}
    assert rpc.last() == ("get_offer", {"offer_id": "a"})
    assert rpc.get_offers_for_asset(CAT) == []
    assert rpc.last() == ("get_offers_for_asset", {"asset_id": CAT})
    assert rpc.view_offer("OFFERSTR")["status"] == "pending"
    assert rpc.last() == ("view_offer", {"offer": "OFFERSTR"})
    assert rpc.import_offer("OFFERSTR") == "imp1"
    assert rpc.last() == ("import_offer", {"offer": "OFFERSTR"})
    rpc.delete_offer("a")
    assert rpc.last() == ("delete_offer", {"offer_id": "a"})
    assert rpc.combine_offers(["O1", "O2"]) == "COMBINED"
    assert rpc.last() == ("combine_offers", {"offers": ["O1", "O2"]})


def test_coin_read_payload_shapes():
    rpc = _Rec({"get_coins": {"coins": [{"coin_id": "c"}]},
                "get_coins_by_ids": {"coins": []},
                "get_are_coins_spendable": {"spendable": True},
                "get_spendable_coin_count": {"count": 4}})
    assert rpc.get_coins() == [{"coin_id": "c"}]
    assert rpc.last() == ("get_coins", {"offset": 0, "limit": 50})
    rpc.get_coins(asset_id=CAT, offset=5, limit=10)
    assert rpc.last() == ("get_coins", {"offset": 5, "limit": 10,
                                        "asset_id": CAT})
    assert rpc.get_coins_by_ids(["c1"]) == []
    assert rpc.last() == ("get_coins_by_ids", {"coin_ids": ["c1"]})
    assert rpc.get_are_coins_spendable(["c1"]) is True
    assert rpc.last() == ("get_are_coins_spendable", {"coin_ids": ["c1"]})
    assert rpc.get_spendable_coin_count() == 4
    assert rpc.last() == ("get_spendable_coin_count", {})
    rpc.get_spendable_coin_count(asset_id=CAT)
    assert rpc.last() == ("get_spendable_coin_count", {"asset_id": CAT})


def test_transaction_read_payload_shapes():
    rpc = _Rec({"get_transaction": {"transaction_id": "t"},
                "get_pending_transactions": {"transactions": []}})
    assert rpc.get_transaction("t") == {"transaction_id": "t"}
    assert rpc.last() == ("get_transaction", {"transaction_id": "t"})
    assert rpc.get_pending_transactions() == []
    assert rpc.last() == ("get_pending_transactions", {})


def test_asset_read_payload_shapes():
    rpc = _Rec({"get_all_cats": {"cats": []},
                "get_nfts": {"nfts": []},
                "get_nft": {"nft": {"nft_id": "n"}},
                "get_nft_data": {"uris": []},
                "get_dids": {"dids": []},
                "get_minter_did_ids": {"minter_did_ids": []},
                "is_asset_owned": {"owned": True},
                "get_options": {"options": []},
                "get_option": {"option": {}}})
    assert rpc.get_all_cats() == []
    assert rpc.last() == ("get_all_cats", {})
    assert rpc.get_nfts() == []
    assert rpc.last() == ("get_nfts", {"offset": 0, "limit": 50})
    rpc.get_nfts(offset=2, limit=5, name="wiz")
    assert rpc.last() == ("get_nfts", {"offset": 2, "limit": 5,
                                       "name": "wiz"})
    assert rpc.get_nft("n") == {"nft_id": "n"}
    assert rpc.last() == ("get_nft", {"nft_id": "n"})
    assert rpc.get_nft_data("n") == {"uris": []}
    assert rpc.last() == ("get_nft_data", {"nft_id": "n"})
    assert rpc.get_dids() == []
    assert rpc.last() == ("get_dids", {})
    assert rpc.get_minter_did_ids() == []
    assert rpc.last() == ("get_minter_did_ids", {})
    assert rpc.is_asset_owned(CAT) is True
    assert rpc.last() == ("is_asset_owned", {"asset_id": CAT})
    assert rpc.get_options() == []
    assert rpc.last() == ("get_options", {"offset": 0, "limit": 50})
    assert rpc.get_option("o") == {}
    assert rpc.last() == ("get_option", {"option_id": "o"})


def test_system_read_payload_shapes():
    rpc = _Rec({"get_version": {"version": "0.13.1"},
                "get_network": {"name": "testnet11"},
                "get_peers": {"peers": []},
                "get_xch_usd_price": {"usd": 25.5},
                "check_address": {"valid": True},
                "get_derivations": {"derivations": []},
                "get_database_stats": {"size": 1}})
    assert rpc.get_version() == "0.13.1"
    assert rpc.last() == ("get_version", {})
    assert rpc.get_network() == {"name": "testnet11"}
    assert rpc.last() == ("get_network", {})
    assert rpc.get_peers() == []
    assert rpc.last() == ("get_peers", {})
    assert rpc.get_xch_usd_price() == 25.5
    assert rpc.last() == ("get_xch_usd_price", {})
    assert rpc.check_address("txch1a") is True
    assert rpc.last() == ("check_address", {"address": "txch1a"})
    assert rpc.get_derivations() == {"derivations": []}
    assert rpc.last() == ("get_derivations", {"offset": 0, "limit": 50,
                                              "hardened": False})
    assert rpc.get_database_stats() == {"size": 1}
    assert rpc.last() == ("get_database_stats", {})


# ------------------------------------------------- leg validation


def test_validate_offer_legs_happy():
    legs = _validate_offer_legs(
        [{"asset": "native", "amount_mojos": 100},
         {"asset": CAT, "amount_mojos": 50}], "offered")
    assert legs == [("native", 100), (CAT, 50)]


def test_validate_offer_legs_rejects():
    with pytest.raises(SageError):
        _validate_offer_legs([], "offered")
    with pytest.raises(SageError):
        _validate_offer_legs([{"asset": "native", "amount_mojos": 0}],
                             "offered")
    with pytest.raises(SageError):
        _validate_offer_legs([{"asset": "native", "amount_mojos": -1}],
                             "offered")
    with pytest.raises(SageError):
        _validate_offer_legs([{"asset": "nft:abc", "amount_mojos": 1}],
                             "offered")
    with pytest.raises(SageError):
        _validate_offer_legs([{"asset": "bogus", "amount_mojos": 1}],
                             "offered")
    with pytest.raises(SageError):
        _validate_offer_legs("not-a-list", "offered")
    # missing amount
    with pytest.raises(SageError):
        _validate_offer_legs([{"asset": "native"}], "offered")


def _leg(asset_id, amount, kind="token"):
    return {"asset": {"asset_id": asset_id, "kind": kind},
            "amount": str(amount)}


def test_summary_legs_converts():
    summary = {"maker": [_leg(None, 1000), _leg(CAT, 250)],
               "taker": [_leg(None, 10)]}
    assert _summary_legs(summary, "maker") == [("native", 1000), (CAT, 250)]
    assert _summary_legs(summary, "taker") == [("native", 10)]


def test_summary_legs_rejects_nft_kind():
    summary = {"maker": [_leg("nftid", 1, kind="nft")], "taker": []}
    with pytest.raises(SageError):
        _summary_legs(summary, "maker")


# ------------------------------------------------- offer-capable fake Sage


class _OfferFake(_FakeSage):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.records = {}       # offer_id -> record
        self.offer_strs = {}    # offer string -> summary+status
        self.made = []
        self.taken = []
        self.cancelled = []     # offer_ids passed to cancel
        self.pending_txs = []
        self.flip_to_cancelled = True

    def _summary_for(self, offered, requested):
        def leg(asset, amount):
            return {"asset": {"asset_id": None if asset == "native" else asset,
                              "kind": "token"},
                    "amount": str(amount)}
        return {"maker": [leg(a, m) for a, m in offered],
                "taker": [leg(a, m) for a, m in requested]}

    def make_offer(self, offered, requested, fee_mojos=0,
                   receive_address=None, expires_at_second=None):
        self.made.append((offered, requested, fee_mojos))
        oid = "oid%d" % len(self.made)
        summary = self._summary_for(offered, requested)
        self.records[oid] = {"offer_id": oid, "status": "pending",
                             "summary": summary, "offer": "OFFER" + oid}
        return {"offer_id": oid, "offer": "OFFER" + oid}

    def view_offer(self, offer):
        return self.offer_strs[offer]

    def get_offer(self, offer_id):
        return self.records[offer_id]

    def get_offers(self):
        return list(self.records.values())

    def take_offer(self, offer, fee_mojos=0, auto_submit=True):
        self.taken.append((offer, fee_mojos))
        tx_id = "tx_take_%d" % len(self.taken)
        self.pending_txs.append({"transaction_id": tx_id})
        return {"transaction_id": tx_id}

    def get_pending_transactions(self):
        return self.pending_txs

    def _do_cancel(self, ids, fee_mojos):
        self.cancelled.append((list(ids), fee_mojos))
        if self.flip_to_cancelled:
            for oid in ids:
                self.records[oid]["status"] = "cancelled"
        return {"summary": {"fee": fee_mojos,
                            "inputs": [{"coin_id": "coin_cancel",
                                        "amount": "1"}]},
                "coin_spends": []}

    def cancel_offer(self, offer_id, fee_mojos=0, auto_submit=True):
        return self._do_cancel([offer_id], fee_mojos)

    def cancel_offers(self, offer_ids, fee_mojos=0, auto_submit=True):
        return self._do_cancel(list(offer_ids), fee_mojos)


def _make_params():
    return {"chain": "chia-testnet",
            "offered": [{"asset": "native", "amount_mojos": 2_000_000}],
            "requested": [{"asset": CAT, "amount_mojos": 500}],
            "fee_mojos": 0, "purpose": "drill"}


def _offer_daemon(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _OfferFake("x")
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    return d, fake


def test_offer_make_queues_by_default(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    resp = d.rt_offer_make(_make_params(), "muse_test")
    assert resp["ok"] is True and resp["decision"] == "queued"
    assert resp["queue_id"] == "1"
    assert fake.made == []  # nothing built until approval


def test_offer_make_schema_violation(tmp_path, monkeypatch):
    d, _ = _offer_daemon(tmp_path, monkeypatch)
    p = _make_params()
    p["evil"] = "contract-call"
    assert d.rt_offer_make(p, "m")["ok"] is False
    p2 = _make_params()
    del p2["offered"]
    assert d.rt_offer_make(p2, "m")["ok"] is False
    p3 = _make_params()
    p3["chain"] = "evm-4663"
    assert d.rt_offer_make(p3, "m")["ok"] is False


def test_offer_make_denied_by_cap(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    from spellbook.policy import Policy
    d.policy = Policy(per_spend_cap={("chia-testnet", "native"): 100})
    resp = d.rt_offer_make(_make_params(), "muse_test")
    assert resp["decision"] == "denied"
    assert fake.made == []


def test_offer_make_auto_approved_executes(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    from spellbook.policy import Policy
    d.policy = Policy(
        auto_approve_below={("chia-testnet", "native"): 5_000_000,
                            ("chia-testnet", CAT): 5_000_000})
    resp = d.rt_offer_make(_make_params(), "muse_test")
    assert resp["ok"] is True and resp["decision"] == "approved"
    assert resp["offer_id"] == "oid1"
    assert resp["offer"] == "OFFERoid1"
    # make_offer called with daemon-normalized legs
    offered, requested, fee = fake.made[0]
    assert offered == [{"asset": "native", "amount_mojos": 2_000_000}]
    assert requested == [{"asset": CAT, "amount_mojos": 500}]
    # ledger: executing then approved
    decisions = [r["decision"] for r in d.ledger.read_all()]
    assert "executing" in decisions and "approved" in decisions
    # velocity consumed the offered legs only
    assert d.spent_last_24h("chia-testnet", "native") == 2_000_000


def test_offer_make_approval_consumed_once(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    qid = d.rt_offer_make(_make_params(), "m")["queue_id"]
    first = d.rt_queue_approve({"queue_id": qid}, "human")
    assert first["ok"] is True and first["offer_id"] == "oid1"
    second = d.rt_queue_approve({"queue_id": qid}, "human")
    assert second["ok"] is False  # one approval = one execution attempt


def test_offer_take_queues_with_decoded_legs(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    # someone else's offer: we give 1000 XCH, we get 250 CAT
    fake.offer_strs["OFFERX"] = {
        "offer": {"maker": [_leg(CAT, 250)], "taker": [_leg(None, 1000)]},
        "status": "pending"}
    resp = d.rt_offer_take({"chain": "chia-testnet", "offer": "OFFERX",
                            "fee_mojos": 0, "purpose": "take drill"},
                           "muse_test")
    assert resp["ok"] is True and resp["decision"] == "queued"
    q = d._decoded_queue()[0]
    assert q["kind"] == "offer_take"
    assert q["give"] == [{"asset": "native", "amount_mojos": 1000}]
    assert q["get"] == [{"asset": CAT, "amount_mojos": 250}]
    assert fake.taken == []  # nothing taken until approval


def test_offer_take_rejects_non_takeable(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    fake.offer_strs["OFFERX"] = {"offer": {"maker": [], "taker": []},
                                 "status": "completed"}
    resp = d.rt_offer_take({"chain": "chia-testnet", "offer": "OFFERX"},
                           "m")
    assert resp["ok"] is False and "takeable" in resp["error"]


def test_offer_take_approve_executes_and_counts_velocity(
        tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    fake.offer_strs["OFFERX"] = {
        "offer": {"maker": [_leg(CAT, 250)], "taker": [_leg(None, 1000)]},
        "status": "pending"}
    qid = d.rt_offer_take({"chain": "chia-testnet", "offer": "OFFERX",
                           "purpose": "t"}, "m")["queue_id"]
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["ok"] is True and out["tx_hash"] == "tx_take_1"
    assert fake.taken == [("OFFERX", 0)]
    # velocity counts what we give (1000 XCH), not what we get
    assert d.spent_last_24h("chia-testnet", "native") == 1000
    assert d.spent_last_24h("chia-testnet", CAT) == 0


def test_offer_take_refuses_changed_terms(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    summary = {"maker": [_leg(CAT, 250)], "taker": [_leg(None, 1000)]}
    fake.offer_strs["OFFERX"] = {"offer": summary, "status": "pending"}
    qid = d.rt_offer_take({"chain": "chia-testnet", "offer": "OFFERX"},
                          "m")["queue_id"]
    # the offer's terms change between request and approval
    fake.offer_strs["OFFERX"] = {
        "offer": {"maker": [_leg(CAT, 1)], "taker": [_leg(None, 1000)]},
        "status": "pending"}
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["ok"] is False and "changed" in out["error"]
    assert fake.taken == []
    # nothing spent: the approval is consumed but velocity untouched
    assert d.spent_last_24h("chia-testnet", "native") == 0


def test_offer_cancel_always_queues(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    from spellbook.policy import Policy
    # even with a permissive policy, cancel queues for a human
    d.policy = Policy(
        auto_approve_below={("chia-testnet", "native"): 10 ** 12,
                            ("chia-testnet", CAT): 10 ** 12})
    fake.records["oid9"] = {"offer_id": "oid9", "status": "pending",
                            "summary": fake._summary_for(
                                [("native", 2_000_000)], [("native", 1)]),
                            "offer": "OFFERoid9"}
    resp = d.rt_offer_cancel({"chain": "chia-testnet", "offer_id": "oid9",
                              "purpose": "cancel drill"}, "m")
    assert resp["ok"] is True and resp["decision"] == "queued"
    q = d._decoded_queue()[0]
    assert q["kind"] == "offer_cancel"
    assert q["offer_ids"] == ["oid9"]
    assert q["offered"][0]["offered"] == [
        {"asset": "native", "amount_mojos": 2_000_000}]
    assert fake.cancelled == []


def test_offer_cancel_refuses_closed(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    fake.records["oid9"] = {"offer_id": "oid9", "status": "cancelled",
                            "summary": {"maker": [], "taker": []},
                            "offer": "OFFERoid9"}
    resp = d.rt_offer_cancel({"chain": "chia-testnet", "offer_id": "oid9"},
                             "m")
    assert resp["ok"] is False and "not open" in resp["error"]


def test_offer_cancel_approve_executes(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    fake.records["oid9"] = {"offer_id": "oid9", "status": "pending",
                            "summary": fake._summary_for(
                                [("native", 2_000_000)], [("native", 1)]),
                            "offer": "OFFERoid9"}
    qid = d.rt_offer_cancel({"chain": "chia-testnet", "offer_id": "oid9",
                             "purpose": "cancel drill"}, "m")["queue_id"]
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["ok"] is True
    assert fake.cancelled == [(["oid9"], 0)]
    assert fake.records["oid9"]["status"] == "cancelled"
    # cancel is fund-preserving: no velocity consumed
    assert d.spent_last_24h("chia-testnet", "native") == 0
    decisions = [r["decision"] for r in d.ledger.read_all()]
    assert "approved-by-human" in decisions


def test_offer_cancel_unknown_fate_when_record_never_flips(
        tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    fake.flip_to_cancelled = False  # broadcast happened, wallet never shows it
    fake.records["oid9"] = {"offer_id": "oid9", "status": "pending",
                            "summary": fake._summary_for(
                                [("native", 2_000_000)], [("native", 1)]),
                            "offer": "OFFERoid9"}
    qid = d.rt_offer_cancel({"chain": "chia-testnet", "offer_id": "oid9"},
                            "m")["queue_id"]
    monkeypatch.setattr(d, "_sage_wait_timeout_s", lambda: 0)
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["ok"] is True
    assert out["decision"] == "approved-submit-unknown"
    decisions = [r["decision"] for r in d.ledger.read_all()]
    assert any(x.startswith("approved-submit-unknown")
               for x in decisions)


def test_chia_read_allowlist(tmp_path, monkeypatch):
    d, fake = _offer_daemon(tmp_path, monkeypatch)
    out = d.rt_chia_read({"chain": "chia-testnet", "op": "get_offers"}, "m")
    assert out["ok"] is True and out["result"] == []
    out = d.rt_chia_read({"chain": "chia-testnet", "op": "take_offer"}, "m")
    assert out["ok"] is False and "unknown chia_read op" in out["error"]
    out = d.rt_chia_read({"chain": "evm-4663", "op": "get_offers"}, "m")
    assert out["ok"] is False
    # secret-bearing ops are not on the allowlist
    out = d.rt_chia_read({"chain": "chia-testnet", "op": "get_secret_key"},
                         "m")
    assert out["ok"] is False


def test_chia_read_routes_in_request_routes():
    from spellbook.daemon import APPROVE_ROUTES, REQUEST_ROUTES
    assert "chia_read" in REQUEST_ROUTES
    assert "offer_make" in REQUEST_ROUTES
    assert "offer_take" in REQUEST_ROUTES
    assert "offer_cancel" in REQUEST_ROUTES
    assert "chia_read" not in APPROVE_ROUTES


def test_velocity_entries_per_intent(tmp_path, monkeypatch):
    d, _ = _offer_daemon(tmp_path, monkeypatch)
    assert d._velocity_entries(
        {"intent": "offer_make", "chain": "chia-testnet",
         "offered": [{"asset": "native", "amount_mojos": 5},
                     {"asset": CAT, "amount_mojos": 7}]}) == [
        ("chia-testnet", "native", 5), ("chia-testnet", CAT, 7)]
    assert d._velocity_entries(
        {"intent": "offer_take", "chain": "chia-testnet",
         "_give": [{"asset": "native", "amount_mojos": 9}]}) == [
        ("chia-testnet", "native", 9)]
    assert d._velocity_entries(
        {"intent": "offer_cancel", "chain": "chia-testnet",
         "offer_ids": ["x"]}) == []
    # plain transfers keep their single-leg shape
    assert d._velocity_entries(
        {"chain": "chia-testnet", "asset": "native",
         "amount_mojos": 3}) == [("chia-testnet", "native", 3)]


def test_decoded_queue_renders_offer_make(tmp_path, monkeypatch):
    d, _ = _offer_daemon(tmp_path, monkeypatch)
    d.rt_offer_make(_make_params(), "m")
    q = d._decoded_queue()[0]
    assert q["kind"] == "offer_make"
    assert q["offered"] == [{"asset": "native", "amount_mojos": 2_000_000}]
    assert q["requested"] == [{"asset": CAT, "amount_mojos": 500}]
    # no opaque-hash-only rendering: legs are fully decoded
    assert q["destination"] is None

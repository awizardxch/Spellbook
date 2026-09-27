"""Tests for the full Sage wallet surface: SageRpc payload shapes for the
new endpoints (minting, DIDs, options, clawback, coin ops, bulk sends,
message signing, local metadata), daemon intent routes, the mint gate,
NFT offer legs, and decoded queue rendering.

No live wallet is touched: the RPC layer is a recording stub and the
daemon layer monkeypatches Daemon._chia_sage_rpc with a surface-capable
fake.
"""
import hashlib
import json
import os
import sys
import time

import pytest

sys.path.insert(0, "tests")

from test_chia import _daemon_with_seed  # noqa: E402

from spellbook import chia  # noqa: E402
from spellbook.chia import SageError, SageRpc  # noqa: E402

CAT = "ab" * 32
COIN = "cd" * 32
NFT_LAUNCHER = "ef" * 32
NFT_LAUNCHER_OTHER = "12" * 32
DID_ADDR = "did:chia:1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqd2fjkn"
NFT1 = "nft1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9q6hm0"
OPT1 = "option1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz0x0abc"


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


# ------------------------------------------- chia.py payload shapes


def test_bulk_mint_nfts_payload_shape():
    rpc = _Rec({"bulk_mint_nfts": {"nft_ids": ["n1"]}})
    mints = [{"data_uris": ["ipfs://x"], "edition_number": 1,
              "edition_total": 1}]
    out = rpc.bulk_mint_nfts(mints, DID_ADDR, fee_mojos=5)
    assert out == {"nft_ids": ["n1"]}
    ep, body = rpc.last()
    assert ep == "bulk_mint_nfts"
    assert body["mints"] == mints
    assert body["did_id"] == DID_ADDR
    assert body["fee"] == 5
    assert body["auto_submit"] is True


def test_issue_cat_payload_shape():
    rpc = _Rec({"issue_cat": {"transaction_id": "t"}})
    rpc.issue_cat("Name", "TICK", 1_000_000, revocable=True, fee_mojos=3)
    ep, body = rpc.last()
    assert ep == "issue_cat"
    assert body["name"] == "Name"
    assert body["ticker"] == "TICK"
    assert body["amount"] == 1_000_000
    assert body["revocable"] is True
    assert body["fee"] == 3
    assert body["auto_submit"] is True


def test_issue_cat_rejects_bad_inputs():
    rpc = _Rec()
    with pytest.raises(SageError):
        rpc.issue_cat("", "T", 1)
    with pytest.raises(SageError):
        rpc.issue_cat("N", "", 1)
    with pytest.raises(SageError):
        rpc.issue_cat("N", "T", 0)


def test_create_did_payload_shape():
    rpc = _Rec({"create_did": {"transaction_id": "t"}})
    rpc.create_did("mydid", fee_mojos=2)
    ep, body = rpc.last()
    assert ep == "create_did"
    assert body == {"name": "mydid", "fee": 2, "auto_submit": True}


def test_transfer_and_normalize_dids_payload_shapes():
    rpc = _Rec()
    rpc.transfer_dids([DID_ADDR], "txch1dest", fee_mojos=1)
    ep, body = rpc.last()
    assert ep == "transfer_dids"
    assert body["did_ids"] == [DID_ADDR]
    assert body["address"] == "txch1dest"
    assert body["fee"] == 1
    rpc.normalize_dids([DID_ADDR])
    ep, body = rpc.last()
    assert ep == "normalize_dids"
    assert body["did_ids"] == [DID_ADDR]


def test_assign_nfts_to_did_payload_shape():
    rpc = _Rec()
    rpc.assign_nfts_to_did([NFT1], DID_ADDR, fee_mojos=1)
    ep, body = rpc.last()
    assert ep == "assign_nfts_to_did"
    assert body["nft_ids"] == [NFT1]
    assert body["did_id"] == DID_ADDR
    assert body["fee"] == 1
    # unassign: did_id is null (Sage: "DID ID (null to unassign)")
    rpc.assign_nfts_to_did([NFT1], None)
    _, body = rpc.last()
    assert body["did_id"] is None


def test_option_payload_shapes():
    rpc = _Rec()
    under = {"asset_id": None, "amount": 100}
    strike = {"asset_id": CAT, "amount": 50}
    rpc.mint_option(9_999_999, under, strike, fee_mojos=1)
    ep, body = rpc.last()
    assert ep == "mint_option"
    assert body["expiration_seconds"] == 9_999_999
    assert body["underlying"] == under
    assert body["strike"] == strike
    rpc.transfer_options([OPT1], "txch1dest")
    ep, body = rpc.last()
    assert ep == "transfer_options"
    assert body["option_ids"] == [OPT1]
    rpc.exercise_options([OPT1], fee_mojos=2)
    ep, body = rpc.last()
    assert ep == "exercise_options"
    assert body["option_ids"] == [OPT1]
    assert body["fee"] == 2


def test_mint_option_rejects_bad_legs():
    rpc = _Rec()
    with pytest.raises(SageError):
        rpc.mint_option(1, {"asset_id": None, "amount": 0},
                        {"asset_id": None, "amount": 1})


def test_finalize_clawback_payload_shape():
    rpc = _Rec()
    rpc.finalize_clawback([COIN], fee_mojos=1)
    ep, body = rpc.last()
    assert ep == "finalize_clawback"
    assert body["coin_ids"] == [COIN]
    assert body["fee"] == 1
    assert body["auto_submit"] is True


def test_combine_split_payload_shapes():
    rpc = _Rec()
    rpc.combine([COIN], fee_mojos=1)
    ep, body = rpc.last()
    assert ep == "combine"
    assert body["coin_ids"] == [COIN]
    rpc.split([COIN], 4)
    ep, body = rpc.last()
    assert ep == "split"
    assert body["coin_ids"] == [COIN]
    assert body["output_count"] == 4
    with pytest.raises(SageError):
        rpc.split([COIN], 1)


def test_auto_combine_payload_shapes():
    rpc = _Rec()
    rpc.auto_combine_xch(50, max_coin_amount=1_000_000)
    ep, body = rpc.last()
    assert ep == "auto_combine_xch"
    assert body["max_coins"] == 50
    assert body["max_coin_amount"] == 1_000_000
    rpc.auto_combine_cat(CAT, 25)
    ep, body = rpc.last()
    assert ep == "auto_combine_cat"
    assert body["asset_id"] == CAT
    assert body["max_coins"] == 25
    assert "max_coin_amount" not in body
    with pytest.raises(SageError):
        rpc.auto_combine_cat("nope", 25)


def test_bulk_send_payload_shapes():
    rpc = _Rec()
    rpc.bulk_send_xch(["txch1a", "txch1b"], 1000, fee_mojos=1,
                      memos=["hi"])
    ep, body = rpc.last()
    assert ep == "bulk_send_xch"
    assert body["addresses"] == ["txch1a", "txch1b"]
    assert body["amount"] == 1000
    assert body["memos"] == ["hi"]
    rpc.bulk_send_cat(CAT, ["txch1a"], 500)
    ep, body = rpc.last()
    assert ep == "bulk_send_cat"
    assert body["asset_id"] == CAT
    with pytest.raises(SageError):
        rpc.bulk_send_cat("nope", ["txch1a"], 500)


def test_multi_send_payload_shape():
    rpc = _Rec()
    pays = [{"asset_id": None, "address": "txch1a", "amount": 100,
             "memos": []},
            {"asset_id": CAT, "address": "txch1b", "amount": 50,
             "memos": ["m"]}]
    rpc.multi_send(pays, fee_mojos=1)
    ep, body = rpc.last()
    assert ep == "multi_send"
    assert body["payments"] == pays
    assert body["fee"] == 1
    with pytest.raises(SageError):
        rpc.multi_send([{"asset_id": None, "address": "x", "amount": 0}])
    with pytest.raises(SageError):
        rpc.multi_send([{"asset_id": "zz", "address": "x", "amount": 1}])


def test_sign_message_payload_shapes():
    rpc = _Rec({"sign_message_by_address": {"signature": "sig"}})
    rpc.sign_message_by_address("txch1a", "hello")
    assert rpc.last() == ("sign_message_by_address",
                          {"address": "txch1a", "message": "hello"})
    rpc.sign_message_with_public_key("pkhex", "hello")
    # Sage's WalletConnect struct uses camelCase for this field
    assert rpc.last() == ("sign_message_with_public_key",
                          {"publicKey": "pkhex", "message": "hello"})


def test_local_metadata_payload_shapes():
    rpc = _Rec()
    rpc.update_cat({"asset_id": CAT, "name": "N"})
    assert rpc.last() == ("update_cat", {"record": {"asset_id": CAT,
                                                   "name": "N"}})
    rpc.update_did(DID_ADDR, name="me", visible=False)
    assert rpc.last() == ("update_did",
                          {"did_id": DID_ADDR, "visible": False,
                           "name": "me"})
    rpc.update_nft(NFT1, visible=False)
    assert rpc.last() == ("update_nft", {"nft_id": NFT1, "visible": False})
    rpc.update_option(OPT1)
    assert rpc.last() == ("update_option", {"option_id": OPT1,
                                            "visible": True})
    rpc.update_nft_collection("col1", visible=False)
    assert rpc.last() == ("update_nft_collection",
                          {"collection_id": "col1", "visible": False})
    rpc.redownload_nft(NFT1)
    assert rpc.last() == ("redownload_nft", {"nft_id": NFT1})


def test_offer_local_ops_payload_shapes():
    rpc = _Rec({"import_offer": {"offer_id": "oid1"},
                "combine_offers": {"offer": "COMBINED"}})
    rpc.import_offer("OFFERSTR")
    assert rpc.last() == ("import_offer", {"offer": "OFFERSTR"})
    rpc.delete_offer("oid1")
    assert rpc.last() == ("delete_offer", {"offer_id": "oid1"})
    out = rpc.combine_offers(["O1", "O2"])
    assert out == "COMBINED"
    assert rpc.last() == ("combine_offers", {"offers": ["O1", "O2"]})


def test_get_transaction_takes_height():
    rpc = _Rec({"get_transaction": {"transaction": {"height": 9}}})
    assert rpc.get_transaction(9) == {"transaction": {"height": 9}}
    assert rpc.last() == ("get_transaction", {"height": 9})
    with pytest.raises(SageError):
        rpc.get_transaction(-1)
    with pytest.raises(SageError):
        rpc.get_transaction("9")


# ------------------------------------------- daemon surface fake


class _SurfaceFake:
    """Stands in for chia.SageRpc for the new intent routes."""

    def __init__(self):
        self.calls = []
        self.dids = []      # DidRecord-shaped dicts
        self.options = []   # OptionRecord-shaped dicts
        self.nfts = []      # NftRecord-shaped dicts
        self.tx_response = {"transaction_id": "tx1", "summary": {},
                            "coin_spends": []}

    def _rec(self, name, *args):
        self.calls.append((name, args))
        return self.tx_response

    # reads
    def get_dids(self):
        self.calls.append(("get_dids", ()))
        return list(self.dids)

    def get_options(self, offset=0, limit=1000):
        self.calls.append(("get_options", ()))
        return list(self.options)

    def get_nfts(self, offset=0, limit=1000):
        self.calls.append(("get_nfts", ()))
        return list(self.nfts)

    def get_nft(self, nft_id):
        self.calls.append(("get_nft", (nft_id,)))
        for n in self.nfts:
            if n.get("launcher_id") == nft_id:
                return n
        return {}

    def view_offer(self, offer):
        return {"offered": [], "requested": []}

    def get_offers(self, offset=0, limit=50):
        return []

    # transactions
    def bulk_mint_nfts(self, mints, did_id, fee_mojos=0, auto_submit=True):
        return self._rec("bulk_mint_nfts", mints, did_id, fee_mojos)

    def issue_cat(self, name, ticker, amount_mojos, revocable=False,
                  fee_mojos=0, auto_submit=True):
        return self._rec("issue_cat", name, ticker, amount_mojos)

    def mint_option(self, expiration_seconds, underlying, strike,
                    fee_mojos=0, auto_submit=True):
        return self._rec("mint_option", expiration_seconds)

    def create_did(self, name, fee_mojos=0, auto_submit=True):
        return self._rec("create_did", name)

    def transfer_dids(self, did_ids, address, fee_mojos=0, clawback=None,
                      auto_submit=True):
        return self._rec("transfer_dids", did_ids)

    def normalize_dids(self, did_ids, fee_mojos=0, auto_submit=True):
        return self._rec("normalize_dids", did_ids)

    def transfer_options(self, option_ids, address, fee_mojos=0,
                         clawback=None, auto_submit=True):
        return self._rec("transfer_options", option_ids)

    def exercise_options(self, option_ids, fee_mojos=0, auto_submit=True):
        return self._rec("exercise_options", option_ids)

    def assign_nfts_to_did(self, nft_ids, did_id, fee_mojos=0,
                           auto_submit=True):
        return self._rec("assign_nfts_to_did", nft_ids, did_id)

    def finalize_clawback(self, coin_ids, fee_mojos=0, auto_submit=True):
        return self._rec("finalize_clawback", coin_ids)

    def combine(self, coin_ids, fee_mojos=0, auto_submit=True):
        return self._rec("combine", coin_ids)

    def split(self, coin_ids, output_count, fee_mojos=0, auto_submit=True):
        return self._rec("split", coin_ids, output_count)

    def auto_combine_xch(self, max_coins, max_coin_amount=None,
                         fee_mojos=0, auto_submit=True):
        return self._rec("auto_combine_xch", max_coins)

    def auto_combine_cat(self, asset_id, max_coins, max_coin_amount=None,
                         fee_mojos=0, auto_submit=True):
        return self._rec("auto_combine_cat", asset_id, max_coins)

    def bulk_send_xch(self, addresses, amount_mojos, fee_mojos=0,
                      memos=None, auto_submit=True):
        return self._rec("bulk_send_xch", addresses, amount_mojos)

    def bulk_send_cat(self, asset_id, addresses, amount_mojos,
                      fee_mojos=0, memos=None, include_hint=True,
                      auto_submit=True):
        return self._rec("bulk_send_cat", asset_id, addresses)

    def multi_send(self, payments, fee_mojos=0, auto_submit=True):
        return self._rec("multi_send", payments)

    def sign_message_by_address(self, address, message):
        self.calls.append(("sign_message_by_address", (address, message)))
        return {"signature": "sig"}

    def sign_message_with_public_key(self, public_key, message):
        self.calls.append(("sign_message_with_public_key",
                           (public_key, message)))
        return {"signature": "sig"}

    # local metadata
    def import_offer(self, offer):
        self.calls.append(("import_offer", (offer,)))

    def delete_offer(self, offer_id):
        self.calls.append(("delete_offer", (offer_id,)))

    def combine_offers(self, offers):
        self.calls.append(("combine_offers", (offers,)))
        return {"offer": "COMBINED"}

    def update_cat(self, record):
        self.calls.append(("update_cat", (record,)))

    def update_did(self, did_id, name=None, visible=True):
        self.calls.append(("update_did", (did_id, name, visible)))

    def update_nft(self, nft_id, visible=True):
        self.calls.append(("update_nft", (nft_id, visible)))

    def update_option(self, option_id, visible=True):
        self.calls.append(("update_option", (option_id, visible)))

    def update_nft_collection(self, collection_id, visible=True):
        self.calls.append(("update_nft_collection",
                           (collection_id, visible)))

    def redownload_nft(self, nft_id):
        self.calls.append(("redownload_nft", (nft_id,)))

    # verification helpers used by _submit_sage_tx / wait paths
    def get_transactions(self, offset=0, limit=50, ascending=False,
                         find_value=None):
        return []


def _surface_daemon(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _SurfaceFake()
    monkeypatch.setattr(type(d), "_chia_sage_rpc",
                        lambda self, chain: (fake, 12345, "txch1sender"))
    # _submit_sage_tx verifies via spent inputs; bypass network reads by
    # stubbing it to return the tx_response directly.
    monkeypatch.setattr(
        type(d), "_submit_sage_tx",
        lambda self, rpc, res, t0, note: {
            "submitted": True, "tx_hash": res.get("transaction_id"),
            "note": note})
    return d, fake


_GATE_ATTESTATIONS = [
    "receive_95_percent_supply",
    "majority_holder",
    "hold_at_least_1_percent",
    "articles_of_description",
    "metadata_set",
    "website_exists",
]


def _digest_of(params):
    return hashlib.sha256(
        json.dumps(params, sort_keys=True).encode()).hexdigest()


def _open_mint_gate(tmp_path, digests, network="testnet11",
                    expires_at=None, **overrides):
    gate = {
        "granted_by": "human-test",
        "digests": digests,
        "network": network,
        "expires_at": expires_at if expires_at is not None
        else time.time() + 3600,
        "attestations": {a: True for a in _GATE_ATTESTATIONS},
    }
    gate.update(overrides)
    (tmp_path / "mint_gate.json").write_text(json.dumps(gate))
    return gate


def _cat_issue_params():
    return {"intent": "cat_issue", "chain": "chia-testnet",
            "name": "N", "ticker": "T", "amount_mojos": 1000,
            "revocable": False, "fee_mojos": 0, "purpose": "t"}


# ------------------------------------------- request-time validation


def test_rt_nft_mint_schema_validation(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    base = {"chain": "chia-testnet",
            "mints": [{"data_uris": ["ipfs://x"]}],
            "did_id": DID_ADDR, "fee_mojos": 0, "purpose": "t"}
    assert d.rt_nft_mint(dict(base), "m")["ok"] is True
    bad = dict(base)
    del bad["mints"]
    assert d.rt_nft_mint(bad, "m")["ok"] is False
    bad = dict(base)
    bad["did_id"] = "txch1notadid"
    assert d.rt_nft_mint(bad, "m")["ok"] is False
    bad = dict(base)
    bad["mints"] = [{"bogus_field": 1}]
    assert d.rt_nft_mint(bad, "m")["ok"] is False
    bad = dict(base)
    bad["mints"] = [{"royalty_ten_thousandths": 10001}]
    assert d.rt_nft_mint(bad, "m")["ok"] is False
    bad = dict(base)
    bad["chain"] = "evm-4663"
    assert d.rt_nft_mint(bad, "m")["ok"] is False


def test_rt_option_mint_schema_validation(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    base = {"chain": "chia-testnet", "expiration_seconds": 9_999_999,
            "underlying": {"asset_id": None, "amount": 100},
            "strike": {"asset_id": CAT, "amount": 50},
            "fee_mojos": 0, "purpose": "t"}
    assert d.rt_option_mint(dict(base), "m")["ok"] is True
    bad = dict(base)
    bad["expiration_seconds"] = -1
    assert d.rt_option_mint(bad, "m")["ok"] is False
    bad = dict(base)
    bad["strike"] = {"asset_id": "zz", "amount": 50}
    assert d.rt_option_mint(bad, "m")["ok"] is False
    bad = dict(base)
    bad["underlying"] = {"asset_id": None, "amount": 0}
    assert d.rt_option_mint(bad, "m")["ok"] is False


def test_rt_cat_issue_schema_validation(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    base = {"chain": "chia-testnet", "name": "N", "ticker": "T",
            "amount_mojos": 1000, "fee_mojos": 0, "purpose": "t"}
    assert d.rt_cat_issue(dict(base), "m")["ok"] is True
    bad = dict(base)
    bad["amount_mojos"] = 0
    assert d.rt_cat_issue(bad, "m")["ok"] is False
    bad = dict(base)
    bad["ticker"] = ""
    assert d.rt_cat_issue(bad, "m")["ok"] is False


def test_rt_did_routes_schema_validation(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    assert d.rt_did_create({"chain": "chia-testnet", "name": "me"},
                           "m")["ok"] is True
    assert d.rt_did_create({"chain": "chia-testnet", "name": ""},
                           "m")["ok"] is False
    ok = {"chain": "chia-testnet", "did_ids": [DID_ADDR],
          "destination": "txch1d"}
    assert d.rt_did_transfer(dict(ok), "m")["ok"] is True
    bad = dict(ok)
    bad["did_ids"] = ["txch1notadid"]
    assert d.rt_did_transfer(bad, "m")["ok"] is False
    assert d.rt_did_normalize({"chain": "chia-testnet",
                               "did_ids": [DID_ADDR]},
                              "m")["ok"] is True


def test_rt_coin_routes_schema_validation(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    base = {"chain": "chia-testnet", "coin_ids": [COIN]}
    assert d.rt_coin_combine(dict(base), "m")["ok"] is True
    bad = dict(base)
    bad["coin_ids"] = ["short"]
    assert d.rt_coin_combine(bad, "m")["ok"] is False
    split = dict(base)
    split["output_count"] = 3
    assert d.rt_coin_split(split, "m")["ok"] is True
    split["output_count"] = 1
    assert d.rt_coin_split(split, "m")["ok"] is False
    ac = {"chain": "chia-testnet", "max_coins": 50}
    assert d.rt_coin_autocombine(dict(ac), "m")["ok"] is True
    ac["asset"] = "zz"
    assert d.rt_coin_autocombine(ac, "m")["ok"] is False
    assert d.rt_clawback_finalize(dict(base), "m")["ok"] is True


def test_rt_bulk_and_multi_send_validation(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    bs = {"chain": "chia-testnet", "addresses": ["txch1a", "txch1b"],
          "amount_mojos": 1000}
    assert d.rt_bulk_send(dict(bs), "m")["ok"] is True
    bad = dict(bs)
    bad["addresses"] = []
    assert d.rt_bulk_send(bad, "m")["ok"] is False
    ms = {"chain": "chia-testnet",
          "payments": [{"asset_id": None, "address": "txch1a",
                        "amount": 100, "memos": []}]}
    assert d.rt_multi_send(dict(ms), "m")["ok"] is True
    bad = dict(ms)
    bad["payments"] = []
    assert d.rt_multi_send(bad, "m")["ok"] is False


def test_rt_message_sign_always_queues_and_validates(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    from spellbook.policy import Policy
    # Even a permissive auto-approve policy must not execute signing.
    d.policy = Policy(auto_approve_below={("chia-testnet", "native"): 10**12})
    resp = d.rt_message_sign({"chain": "chia-testnet", "message": "hi",
                              "address": "txch1a", "purpose": "t"}, "m")
    assert resp["ok"] is True and resp["decision"] == "queued"
    # nothing signed until the human approves the queued intent
    assert not [c for c in fake.calls
                if c[0] in ("sign_message_by_address",
                            "sign_message_with_public_key")]
    bad = d.rt_message_sign({"chain": "chia-testnet", "message": "hi",
                             "address": "a", "public_key": "b"}, "m")
    assert bad["ok"] is False
    # neither identity is an error
    bad = d.rt_message_sign({"chain": "chia-testnet", "message": "hi"},
                            "m")
    assert bad["ok"] is False
    # empty message is an error
    bad = d.rt_message_sign({"chain": "chia-testnet", "message": "",
                             "address": "a"}, "m")
    assert bad["ok"] is False


def test_rt_message_sign_queue_decodes_message(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    resp = d.rt_message_sign({"chain": "chia-testnet",
                              "message": "attack at dawn",
                              "public_key": "pk1", "purpose": "t"}, "m")
    qid = resp["queue_id"]
    shown = {q["queue_id"]: q for q in d._decoded_queue()}
    assert shown[qid]["kind"] == "message_sign"
    assert shown[qid]["message"] == "attack at dawn"
    assert shown[qid]["public_key"] == "pk1"


# ------------------------------------------- mint gate


def test_mint_gate_closed_by_default(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    with pytest.raises(SageError, match="mint/issuance gate is closed"):
        d._check_mint_gate(_cat_issue_params())
    # refused attempts are ledgered
    decisions = [r["decision"] for r in d.ledger.read_all()]
    assert any(x.startswith("mint-gate-refused") for x in decisions)
    assert fake.calls == []
    # a refused check consumes nothing
    assert not os.path.exists(d.mint_gate_consumed_path)


def test_mint_gate_opens_for_exact_digest(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    digest = _digest_of(params)
    _open_mint_gate(tmp_path, [digest])
    d._check_mint_gate(params)
    decisions = [r["decision"] for r in d.ledger.read_all()]
    assert f"mint-gate-open:cat_issue:{digest}" in decisions
    # one-shot: the digest is now consumed
    consumed = json.loads(
        (tmp_path / "mint_gate_consumed.json").read_text())
    assert digest in consumed["digests"]


def test_mint_gate_one_shot_no_replay(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    _open_mint_gate(tmp_path, [_digest_of(params)])
    d._check_mint_gate(params)  # first attempt opens
    with pytest.raises(SageError, match="already consumed"):
        d._check_mint_gate(params)  # replay refused
    decisions = [r["decision"] for r in d.ledger.read_all()]
    assert sum(x.startswith("mint-gate-open") for x in decisions) == 1
    assert any(x.startswith("mint-gate-refused") for x in decisions)


def test_mint_gate_refuses_missing_attestation(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    atts = {a: True for a in _GATE_ATTESTATIONS}
    atts["metadata_set"] = False  # one missing
    _open_mint_gate(tmp_path, [_digest_of(params)], attestations=atts)
    with pytest.raises(SageError, match="metadata_set"):
        d._check_mint_gate(params)


def test_mint_gate_refuses_unauthorized_digest(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    _open_mint_gate(tmp_path, ["ab" * 32])  # some other intent's digest
    with pytest.raises(SageError, match="not authorized"):
        d._check_mint_gate(_cat_issue_params())


def test_mint_gate_refuses_tampered_params(tmp_path, monkeypatch):
    # The gate authorized one exact params dict; changing the amount
    # changes the digest and the gate refuses.
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    _open_mint_gate(tmp_path, [_digest_of(params)])
    tampered = dict(params, amount_mojos=9999)
    with pytest.raises(SageError, match="not authorized"):
        d._check_mint_gate(tampered)


def test_mint_gate_refuses_missing_granted_by(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    _open_mint_gate(tmp_path, [_digest_of(params)], granted_by="  ")
    with pytest.raises(SageError, match="granted_by"):
        d._check_mint_gate(params)


def test_mint_gate_refuses_malformed_file(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    (tmp_path / "mint_gate.json").write_text("not json {{{")
    with pytest.raises(SageError, match="mint/issuance gate is closed"):
        d._check_mint_gate(_cat_issue_params())


def test_mint_gate_refuses_expired_gate(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    _open_mint_gate(tmp_path, [_digest_of(params)],
                    expires_at=time.time() - 1)
    with pytest.raises(SageError, match="expired"):
        d._check_mint_gate(params)


def test_mint_gate_refuses_wrong_network(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()  # chia-testnet -> testnet11
    _open_mint_gate(tmp_path, [_digest_of(params)], network="mainnet")
    with pytest.raises(SageError, match="network"):
        d._check_mint_gate(params)


def test_mint_gate_refuses_unknown_top_level_key(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    # a typo'd key like "expiry" instead of "expires_at" must fail loudly,
    # not be silently ignored
    _open_mint_gate(tmp_path, [_digest_of(params)], expiry=time.time() + 99)
    with pytest.raises(SageError, match="unknown top-level keys: expiry"):
        d._check_mint_gate(params)


def test_mint_gate_refuses_unknown_attestation_key(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    atts = {a: True for a in _GATE_ATTESTATIONS}
    atts["majority_holders"] = True  # typo'd extra
    _open_mint_gate(tmp_path, [_digest_of(params)], attestations=atts)
    with pytest.raises(SageError, match="unknown attestations"):
        d._check_mint_gate(params)


def test_mint_gate_refuses_bad_digest_shape(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    _open_mint_gate(tmp_path, ["not-hex"])
    with pytest.raises(SageError, match="64-hex"):
        d._check_mint_gate(params)
    _open_mint_gate(tmp_path, [])
    with pytest.raises(SageError, match="64-hex"):
        d._check_mint_gate(params)


def test_mint_gate_refuses_bool_expires_at(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    # bool is a subclass of int — must not pass as an epoch time
    _open_mint_gate(tmp_path, [_digest_of(params)], expires_at=True)
    with pytest.raises(SageError, match="expires_at"):
        d._check_mint_gate(params)


def test_mint_gate_refuses_corrupt_consumed_store(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    _open_mint_gate(tmp_path, [_digest_of(params)])
    (tmp_path / "mint_gate_consumed.json").write_text("garbage {{{")
    with pytest.raises(SageError, match="corrupt"):
        d._check_mint_gate(params)


def test_mint_gate_failed_check_triggers_no_rpc(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    with pytest.raises(SageError, match="gate is closed"):
        d._execute_chia_spend(params)
    assert not [c for c in fake.calls if c[0] == "issue_cat"]
    assert not os.path.exists(d.mint_gate_consumed_path)


def test_cat_issue_execution_requires_open_gate(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    params = _cat_issue_params()
    digest = _digest_of(params)
    with pytest.raises(SageError, match="gate is closed"):
        d._execute_chia_spend(params)
    assert not [c for c in fake.calls if c[0] == "issue_cat"]
    _open_mint_gate(tmp_path, [digest])
    out = d._execute_chia_spend(params)
    assert out["submitted"] is True
    assert ("issue_cat", ("N", "T", 1000)) in fake.calls
    # one-shot: the same grant cannot execute a second time
    with pytest.raises(SageError, match="already consumed"):
        d._execute_chia_spend(params)
    assert len([c for c in fake.calls if c[0] == "issue_cat"]) == 1


def test_decoded_queue_shows_canon_digest(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    r = d.rt_cat_issue({"chain": "chia-testnet", "name": "N", "ticker": "T",
                        "amount_mojos": 1000, "fee_mojos": 0,
                        "purpose": "t"}, "m")
    assert r["ok"] is True and r["decision"] == "queued"
    shown = {e["queue_id"]: e for e in d.rt_queue_read({}, "m")["queue"]}
    entry = shown[r["queue_id"]]
    assert entry["kind"] == "cat_issue"
    # the human authorizes exactly this digest in mint_gate.json
    assert entry["canon_digest"] == _digest_of(d.queue[r["queue_id"]]
                                              ["params"])


# ------------------------------------------- record-field correctness


def test_owned_option_ids_uses_launcher_id(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    fake.options = [{"launcher_id": "optlauncher" + "0" * 53,
                     "address": OPT1}]
    owned = d._owned_option_ids(fake)
    assert "optlauncher" + "0" * 53 in owned
    # the old wrong field name finds nothing
    assert "option1abc" not in owned


def test_nft_mint_did_ownership_uses_address_field(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    fake.dids = [{"launcher_id": "d" * 64, "address": DID_ADDR,
                  "name": "me", "visible": True, "coin_id": "c" * 64,
                  "amount": 1}]
    # this test exercises _execute_nft_mint_via_sage directly, bypassing
    # the mint gate (which runs in _execute_chia_spend)
    params = {"intent": "nft_mint", "chain": "chia-testnet",
              "mints": [{"data_uris": ["ipfs://x"]}],
              "did_id": DID_ADDR, "fee_mojos": 0, "purpose": "t"}
    out = d._execute_nft_mint_via_sage(params)
    assert out["submitted"] is True
    # a DID we do not own is refused even though launcher_id exists
    params["did_id"] = DID_ADDR[:-2] + "aa"
    with pytest.raises(SageError, match="not in this wallet"):
        d._execute_nft_mint_via_sage(params)


def test_nft_assign_did_ownership_uses_address_field(tmp_path,
                                                     monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    fake.dids = [{"launcher_id": "d" * 64, "address": DID_ADDR,
                  "name": "me", "visible": True, "coin_id": "c" * 64,
                  "amount": 1}]
    fake.nfts = [{"launcher_id": NFT_LAUNCHER, "coin_id": "c" * 64}]
    params = {"intent": "nft_assign_did", "chain": "chia-testnet",
              "nft_ids": [NFT_LAUNCHER], "did_id": DID_ADDR,
              "fee_mojos": 0, "purpose": "t"}
    out = d._execute_nft_assign_did_via_sage(params)
    assert out["submitted"] is True
    params["did_id"] = DID_ADDR[:-2] + "aa"
    with pytest.raises(SageError, match="not in this wallet"):
        d._execute_nft_assign_did_via_sage(params)


# ------------------------------------------- local metadata routes


def test_local_metadata_routes_call_rpc_directly(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    assert d.rt_offer_import({"chain": "chia-testnet",
                              "offer": "OFFERSTR"}, "m")["ok"] is True
    assert ("import_offer", ("OFFERSTR",)) in fake.calls
    assert d.rt_offer_delete({"chain": "chia-testnet",
                              "offer_id": "oid1"}, "m")["ok"] is True
    assert ("delete_offer", ("oid1",)) in fake.calls
    assert d.rt_offer_combine({"chain": "chia-testnet",
                               "offers": ["O1", "O2"]},
                              "m")["ok"] is True
    assert ("combine_offers", (["O1", "O2"],)) in fake.calls
    assert d.rt_did_update({"chain": "chia-testnet", "did_id": DID_ADDR,
                            "name": "me"}, "m")["ok"] is True
    assert ("update_did", (DID_ADDR, "me", True)) in fake.calls
    assert d.rt_nft_update({"chain": "chia-testnet", "nft_id": NFT1},
                           "m")["ok"] is True
    assert ("update_nft", (NFT1, True)) in fake.calls
    assert d.rt_nft_collection_update(
        {"chain": "chia-testnet", "collection_id": "c1",
         "visible": False}, "m")["ok"] is True
    assert ("update_nft_collection", ("c1", False)) in fake.calls
    assert d.rt_nft_redownload({"chain": "chia-testnet", "nft_id": NFT1},
                               "m")["ok"] is True
    assert ("redownload_nft", (NFT1,)) in fake.calls
    assert d.rt_option_update({"chain": "chia-testnet",
                               "option_id": OPT1}, "m")["ok"] is True
    assert ("update_option", (OPT1, True)) in fake.calls
    assert d.rt_cat_update({"chain": "chia-testnet",
                            "record": {"asset_id": CAT}},
                           "m")["ok"] is True
    assert ("update_cat", ({"asset_id": CAT},)) in fake.calls
    # nothing queued
    assert d.queue == {}


def test_local_routes_reject_schema_violations(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    assert d.rt_offer_import({"chain": "chia-testnet"}, "m")["ok"] is False
    assert d.rt_offer_import({"chain": "evm-4663",
                              "offer": "O"}, "m")["ok"] is False
    assert d.rt_offer_delete({"chain": "chia-testnet"}, "m")["ok"] is False
    assert d.rt_nft_update({"chain": "chia-testnet"}, "m")["ok"] is False
    assert d.rt_cat_update({"chain": "chia-testnet",
                            "record": "notadict"}, "m")["ok"] is False


# ------------------------------------------- NFT offer legs


def test_offer_make_resolves_nft_legs_at_request(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)
    fake.nfts = [{"launcher_id": NFT_LAUNCHER, "coin_id": "c" * 64}]
    p = {"chain": "chia-testnet",
         "offered": [{"asset": "nft:" + NFT_LAUNCHER, "amount_mojos": 1}],
         "requested": [{"asset": "native", "amount_mojos": 1000}],
         "fee_mojos": 0, "purpose": "t"}
    resp = d.rt_offer_make(p, "muse_test")
    assert resp["ok"] is True and resp["decision"] == "queued"
    queued = d.queue[resp["queue_id"]]["params"]
    # stored as launcher id — the human approves the exact NFT
    assert queued["offered"] == [{"asset": "nft:" + NFT_LAUNCHER,
                                  "amount_mojos": 1}]
    # unowned NFT fails fast at request time
    p2 = {"chain": "chia-testnet",
          "offered": [{"asset": "nft:" + NFT_LAUNCHER_OTHER, "amount_mojos": 1}],
          "requested": [{"asset": "native", "amount_mojos": 1000}],
          "fee_mojos": 0, "purpose": "t"}
    assert d.rt_offer_make(p2, "muse_test")["ok"] is False


# ------------------------------------------- handle() guard


def test_handle_returns_structured_error_on_bad_fee(tmp_path, monkeypatch):
    d, _ = _surface_daemon(tmp_path, monkeypatch)
    # _fee_of raises outside the handler's local try/except; handle()
    # must turn it into {"ok": False} instead of dropping the request.
    resp = d.handle(
        {"token": "aa" * 32, "route": "nft_mint", "muse_id": "m",
         "params": {"chain": "chia-testnet",
                    "mints": [{"data_uris": ["ipfs://x"]}],
                    "did_id": DID_ADDR, "fee_mojos": "not-an-int",
                    "purpose": "t"}},
        peer_uid=os.getuid())
    assert resp["ok"] is False
    assert "fee_mojos" in resp["error"]


def test_chia_read_get_transaction_takes_height(tmp_path, monkeypatch):
    d, fake = _surface_daemon(tmp_path, monkeypatch)

    class _TxFake(_SurfaceFake):
        def get_transaction(self, height):
            self.calls.append(("get_transaction", (height,)))
            return {"transaction": {"height": height}}

    fake2 = _TxFake()
    monkeypatch.setattr(type(d), "_chia_sage_rpc",
                        lambda self, chain: (fake2, 12345, "txch1sender"))
    resp = d.rt_chia_read({"chain": "chia-testnet", "op": "get_transaction",
                           "height": 9}, "m")
    assert resp["ok"] is True
    assert ("get_transaction", (9,)) in fake2.calls

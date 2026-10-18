"""forge_swap: a swap on the Forge (Chia AMM) through the agent wallet.

What is pinned here, because it is the custody boundary:

- the requester names bounds only (no route, quote, router URL or payee);
- the router comes from the daemon's config and must serve the right network;
- a forge_swap always queues for the human, even under auto-approve;
- execution quotes again, refuses below the approved minimum or on a changed
  router, has Sage make the offer (own payee, short expiry), rehearses, then
  settles ONCE: an ambiguous settle is reported with its watch, never resent;
- the read client retries only reads.

No network and no live wallet: the router is a recording fake behind
spellbook.forge's two transport functions, and Sage is the offer-capable fake
from test_offers.
"""
import sys
import time

import pytest

sys.path.insert(0, "tests")

from test_offers import _OfferFake, _offer_daemon  # noqa: E402

from spellbook import chia  # noqa: E402
from spellbook import forge as forge_mod  # noqa: E402
from spellbook.policy import Policy  # noqa: E402

CAT = "cd" * 32
NATIVE = "0" * 64
POOL = "aa" * 32
TESTNET_ROUTER = forge_mod.DEFAULT_RESPONDERS["testnet11"]
FEE = 6_000_000_000
TXID = "ab" * 32


def _quote(amount_in=2_000_000, amount_out=600, executable=True, give=NATIVE,
           take=CAT, body=None):
    return {"executable": executable,
            "settlement": {"venue": "forge", "body": body or {"launcher_id": POOL}},
            "intent": {"kind": "forge-swap",
                       "offer": [{"asset_id": give, "amount": str(amount_in)}],
                       "request": [{"asset_id": take, "amount": str(amount_out)}],
                       "price_impact_bps": 14, "total_fee_bps": 330,
                       "route": [{"pool": POOL, "in": give, "out": take}],
                       "branches": []}}


class _Router:
    """The Forge router: answers reads by path, settles from a script."""

    def __init__(self, network="testnet11"):
        self.network = network
        self.quotes = [_quote()]
        self.settles = []          # bodies POSTed to /swap, in order
        self.settle_script = []    # (status, payload) or an exception, per call
        self.reads = []
        self.status_answer = {"success": True, "confirmed": True,
                              "proof": "pre-trade tips spent", "pools": []}

    def read(self, method, url, body=None, timeout=30, sleep=None):
        self.reads.append((method, url, body))
        if url.endswith("/api/v1/agent/markets"):
            return {"success": True, "network": self.network, "markets": []}
        if url.endswith("/api/v1/agent/quote"):
            return {"success": True, "quotes": list(self.quotes)}
        if url.endswith("/api/v1/agent/status"):
            return dict(self.status_answer)
        raise AssertionError(f"unexpected read {url}")

    def send(self, method, url, body, timeout):
        assert url.endswith("/api/v1/agent/swap"), url
        self.settles.append(dict(body))
        step = self.settle_script.pop(0) if self.settle_script else None
        if isinstance(step, BaseException):
            raise step
        if step is not None:
            return step
        if body.get("dry_run"):
            return 200, {"success": True, "dry_run": True,
                         "result": {"transaction_id": TXID, "cost": 900_000_000}}
        return 202, {"success": True, "pending": True, "transaction_id": TXID,
                     "watch": {"launcher_ids": [POOL], "spent_coin_ids": ["ee" * 32]}}


class _ExpiringFake(_OfferFake):
    def make_offer(self, offered, requested, fee_mojos=0, receive_address=None,
                   expires_at_second=None):
        self.last_make = {"receive_address": receive_address,
                          "expires_at_second": expires_at_second}
        return super().make_offer(offered, requested, fee_mojos,
                                  receive_address, expires_at_second)


@pytest.fixture
def forge_daemon(tmp_path, monkeypatch):
    d, _ = _offer_daemon(tmp_path, monkeypatch)
    fake = _ExpiringFake("x")
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    router = _Router()
    monkeypatch.setattr(forge_mod, "_read", router.read)
    monkeypatch.setattr(forge_mod, "_send", router.send)
    return d, fake, router


def _swap(**over):
    p = {"intent": "forge_swap", "chain": "chia-testnet", "asset_in": "native",
         "asset_out": CAT, "amount_in_mojos": 2_000_000,
         "min_amount_out_mojos": 550, "fee_mojos": FEE, "purpose": "test"}
    p.update(over)
    return p


def _queued(d, router, **over):
    resp = d.rt_forge_swap(_swap(**over), "muse")
    assert resp["ok"] is True and resp["decision"] == "queued", resp
    assert router.settles == [], "nothing settles before approval"
    return resp["queue_id"]


# ------------------------------------------------------------- the client

def test_router_comes_from_config_https_only():
    assert forge_mod.responder_for("testnet11", {}) == TESTNET_ROUTER
    assert forge_mod.responder_for("mainnet", None) == forge_mod.DEFAULT_RESPONDERS["mainnet"]
    cfg = {"forge_responders": {"testnet11": "https://router.example/"}}
    assert forge_mod.responder_for("testnet11", cfg) == "https://router.example"
    assert forge_mod.responder_for(
        "testnet11", {"forge_responders": {"testnet11": "http://127.0.0.1:8787"}}
    ) == "http://127.0.0.1:8787"
    for bad in ("http://router.example", "https://router.example/api",
                "https://router.example/?x=1", "ftp://router.example"):
        with pytest.raises(forge_mod.ForgeError):
            forge_mod.responder_for("testnet11", {"forge_responders": {"testnet11": bad}})
    with pytest.raises(forge_mod.ForgeError):
        forge_mod.responder_for("simnet", {})


def test_pick_quote_takes_only_an_exact_executable_forge_route():
    answer = {"quotes": [
        _quote(executable=False, amount_out=999),
        _quote(amount_in=1_999_999, amount_out=998),             # sells another amount
        _quote(amount_out=996, take=NATIVE),                     # wrong asset out
        _quote(amount_out=600),
        # The router's own "offer" is dropped with every other non-lane key;
        # the daemon adds its wallet's offer. The best payer wins.
        _quote(amount_out=700, body={"launcher_id": POOL, "offer": "x"}),
        _quote(amount_out=650),
    ]}
    pick = forge_mod.pick_quote(answer, NATIVE, CAT, 2_000_000)
    assert pick["amount_out"] == 700
    assert pick["settlement_body"] == {"launcher_id": POOL}
    assert forge_mod.pick_quote({"quotes": []}, NATIVE, CAT, 1) is None


def test_settle_is_sent_once_and_classified_by_its_answer():
    def run(answer, dry=False):
        calls = []

        def send(method, url, body, timeout):
            calls.append(body)
            if isinstance(answer, BaseException):
                raise answer
            return answer
        try:
            out = forge_mod.settle("https://r", {"launcher_id": POOL, "offer": "o"},
                                   dry_run=dry, send=send)
        except forge_mod.ForgeError as e:
            out = e
        assert len(calls) == 1, "a settle is never retried"
        assert calls[0]["dry_run"] is dry, "dry_run is always set by the daemon"
        return out

    assert run((202, {"success": True, "transaction_id": TXID}))["transaction_id"] == TXID
    refused = run((409, {"success": False, "error": "pool pays 5, trader asks 6"}))
    assert type(refused) is forge_mod.ForgeError
    pending = run((503, {"success": False, "ambiguous": True, "code": "FORGE_PUSH_PENDING",
                         "transaction_id": TXID, "watch": {"launcher_ids": [POOL]}}))
    assert isinstance(pending, forge_mod.ForgeAmbiguous)
    assert pending.transaction_id == TXID and pending.watch == {"launcher_ids": [POOL]}
    assert isinstance(run((502, None)), forge_mod.ForgeAmbiguous), "a live 5xx may have pushed"
    assert isinstance(run(TimeoutError("read timed out")), forge_mod.ForgeAmbiguous)
    assert isinstance(run((302, None)), forge_mod.ForgeAmbiguous), "a redirect is not a refusal"
    # "Success" without a pushed transaction is not a settle (review finding 2).
    assert isinstance(run((200, {"success": True, "dry_run": True, "transaction_id": TXID})),
                      forge_mod.ForgeAmbiguous)
    assert isinstance(run((202, {"success": True})), forge_mod.ForgeAmbiguous)
    # A rehearsal pushes nothing: its failures are plain refusals.
    assert type(run(TimeoutError("x"), dry=True)) is forge_mod.ForgeError
    assert type(run((500, None), dry=True)) is forge_mod.ForgeError


def test_only_lane_keys_reach_the_settle_body():
    answer = {"quotes": [_quote(body={"launcher_id": POOL, "dry_run": True,
                                      "display_on_dexie": True, "offer": "x"})]}
    assert forge_mod.pick_quote(answer, NATIVE, CAT, 2_000_000)["settlement_body"] == {
        "launcher_id": POOL}
    assert forge_mod.pick_quote({"quotes": [_quote(body={"x": 1})]}, NATIVE, CAT, 2_000_000) is None


def test_pick_quote_survives_malformed_router_json():
    for answer in ({"quotes": "x"}, {"quotes": [{"executable": True, "settlement": "x",
                                                 "intent": "y"}]},
                   {"quotes": [dict(_quote(), intent={"offer": "x", "request": []})]},
                   {"quotes": [dict(_quote(), executable="yes")]}, [], None):
        assert forge_mod.pick_quote(answer, NATIVE, CAT, 2_000_000) is None
    huge = _quote(amount_out=str(2 ** 64))
    assert forge_mod.pick_quote({"quotes": [huge]}, NATIVE, CAT, 2_000_000) is None


def test_redirects_are_answers_not_followed():
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    try:
        status, payload = forge_mod._send(
            "GET", f"http://127.0.0.1:{srv.server_port}/api/v1/agent/markets", None, 5)
    finally:
        srv.server_close()
    assert status == 302 and payload is None


def test_reads_retry_gateway_errors_but_not_refusals(monkeypatch):
    answers = [(503, None), (200, {"success": True, "network": "testnet11"})]
    calls = []
    monkeypatch.setattr(forge_mod, "_send",
                        lambda m, u, b, t: calls.append(u) or answers.pop(0))
    out = forge_mod._read("GET", "https://r/api/v1/agent/markets", sleep=lambda s: None)
    assert out["network"] == "testnet11" and len(calls) == 2
    calls.clear()
    monkeypatch.setattr(forge_mod, "_send",
                        lambda m, u, b, t: calls.append(u) or (400, {"success": False, "error": "bad"}))
    with pytest.raises(forge_mod.ForgeError, match="bad"):
        forge_mod._read("POST", "https://r/api/v1/agent/quote", {}, sleep=lambda s: None)
    assert len(calls) == 1


def test_status_reports_tips_not_confirmation():
    def read(method, url, body=None):
        assert body == {"launcher_ids": [POOL], "spent_coin_ids": []}
        return {"success": True, "confirmed": True, "proof": "indexed tips exist",
                "detail": [{"launcher_id": POOL}]}
    out = forge_mod.status("https://r", {"launcher_ids": [POOL, "junk"]}, read=read)
    assert out["tips_spent"] is False and out["detail"] == [{"launcher_id": POOL}]
    with pytest.raises(forge_mod.ForgeError):
        forge_mod.status("https://r", {"launcher_ids": "x"}, read=read)


# ---------------------------------------------------------------- request

def test_bounds_only_schema(forge_daemon):
    d, _, router = forge_daemon
    for extra in ({"route": []}, {"responder": "https://evil"}, {"offer": "x"},
                  {"receive_address": "txch1x"}, {"settlement": {}}):
        assert d.rt_forge_swap(_swap(**extra), "m")["ok"] is False, extra
    for missing in ("asset_in", "min_amount_out_mojos", "fee_mojos"):
        p = _swap()
        del p[missing]
        assert d.rt_forge_swap(p, "m")["ok"] is False, missing
    assert d.rt_forge_swap(_swap(fee_mojos=0), "m")["ok"] is False
    assert d.rt_forge_swap(_swap(asset_out="native"), "m")["ok"] is False
    assert d.rt_forge_swap(_swap(asset_out="nft:" + "ab" * 32), "m")["ok"] is False
    assert d.rt_forge_swap(_swap(asset_out=NATIVE), "m")["ok"] is False
    assert d.rt_forge_swap(_swap(amount_in_mojos="2000000"), "m")["ok"] is False
    assert d.rt_forge_swap(_swap(chain="evm-8453"), "m")["ok"] is False
    assert d.queue == {} and router.settles == []


def test_fee_capped_by_the_forge_cap_not_the_offer_cap(forge_daemon):
    d, _, router = forge_daemon
    # 6e9 is far over the plain-offer cap (5e7) and under the Forge cap (1e10).
    _queued(d, router)
    out = d.rt_forge_swap(_swap(fee_mojos=10_000_000_001), "m")
    assert out["ok"] is False and "forge_max_fee_mojos" in out["error"]


def test_always_queued_even_under_auto_approve(forge_daemon):
    d, fake, router = forge_daemon
    d.policy = Policy(auto_approve_below={("chia-testnet", "native"): 10**15,
                                          ("chia-testnet", CAT): 10**15})
    qid = _queued(d, router)
    assert fake.made == []
    item = next(q for q in d._decoded_queue() if q["queue_id"] == qid)
    assert item["kind"] == "forge_swap"
    assert item["give"] == [{"asset": "native", "amount_mojos": 2_000_000}]
    assert item["take_at_least"] == [{"asset": CAT, "amount_mojos": 550}]
    assert item["router"] == TESTNET_ROUTER and item["network"] == "testnet11"
    assert item["expected_out_mojos"] == 600 and item["price_impact_bps"] == 14
    assert item["receive_address"]


def test_denied_by_cap_counts_the_fee(forge_daemon):
    d, _, router = forge_daemon
    d.policy = Policy(per_spend_cap={("chia-testnet", "native"): FEE})
    out = d.rt_forge_swap(_swap(), "m")
    assert out["decision"] == "denied", "2_000_000 given + the fee is over the cap"


def test_wrong_network_router_is_refused(forge_daemon):
    d, _, router = forge_daemon
    router.network = "mainnet"
    out = d.rt_forge_swap(_swap(), "m")
    assert out["ok"] is False and "serves 'mainnet'" in out["error"]


def test_not_queued_when_the_route_pays_below_the_minimum(forge_daemon):
    d, _, router = forge_daemon
    out = d.rt_forge_swap(_swap(min_amount_out_mojos=601), "m")
    assert out["ok"] is False and "below min_amount_out_mojos" in out["error"]
    assert d.queue == {}


def test_mainnet_needs_the_separate_flag(forge_daemon):
    d, _, router = forge_daemon
    out = d.rt_forge_swap(_swap(chain="chia-mainnet"), "m")
    assert out["ok"] is False and "mainnet_submit_enabled" in out["error"]
    assert router.reads == []


# -------------------------------------------------------------- execution

def test_approve_makes_the_offer_rehearses_and_settles_once(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    approved = d.queue[qid]["params"]["receive_address"]
    router.quotes = [_quote(amount_out=640)]       # the fresh quote pays more
    before = int(time.time())
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["ok"] is True, out
    offered, requested, fee = fake.made[0]
    assert offered == [{"asset": "native", "amount_mojos": 2_000_000}]
    assert requested == [{"asset": CAT, "amount_mojos": 640}], "asks the fresh quote"
    assert fee == FEE
    assert fake.last_make["receive_address"] == approved, "pays this wallet"
    expires = fake.last_make["expires_at_second"]
    assert before + 120 <= expires <= int(time.time()) + 600
    assert [s["dry_run"] for s in router.settles] == [True, False]
    assert all(s == {"launcher_id": POOL, "offer": "OFFERoid1", "dry_run": s["dry_run"]}
               for s in router.settles)
    assert out["tx_hash"] == TXID and out["offer_id"] == "oid1"
    assert out["watch"]["spent_coin_ids"] == ["ee" * 32]
    assert d.spent_last_24h("chia-testnet", "native") == 2_000_000 + FEE


def test_execution_refuses_below_the_approved_minimum(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    router.quotes = [_quote(amount_out=549)]
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["ok"] is False and "below the approved minimum" in out["error"]
    assert fake.made == [] and router.settles == []
    assert d._forge_open_offers() == {}


def test_execution_refuses_a_router_changed_since_approval(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    d.chia_cfg = dict(d.chia_cfg, forge_responders={"testnet11": "https://other.example"})
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["ok"] is False and "re-request" in out["error"]
    assert fake.made == [] and router.settles == []


def _assert_left_open(d, router, out, settles):
    """Review finding 1: once the offer has left, any outcome short of a
    proven settle is unknown, counted, and blocks a second swap of the pair."""
    assert out["decision"] == "approved-submit-unknown", out
    assert "oid1" in out["note"] and "offer_cancel" in out["note"]
    assert len(router.settles) == settles
    assert d.spent_last_24h("chia-testnet", "native") == 2_000_000 + FEE
    assert "oid1" in d._forge_open_offers()
    again = d.rt_forge_swap(_swap(), "muse")
    assert again["ok"] is False and "oid1" in again["error"]


def test_refused_rehearsal_leaves_the_offer_open(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    router.settle_script = [(409, {"success": False, "error": "pool pays 5, trader asks 6"})]
    _assert_left_open(d, router, d.rt_queue_approve({"queue_id": qid}, "human"), 1)


def test_fee_under_the_node_floor_never_goes_live(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    router.settle_script = [(200, {"success": True, "dry_run": True,
                                   "result": {"cost": 2_000_000_000}})]
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert "floor" in out["note"]
    _assert_left_open(d, router, out, 1)


def test_malformed_rehearsal_is_unknown_not_a_crash(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    router.settle_script = [(200, {"success": True, "result": "ok"}),
                            (202, "not json")]
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    _assert_left_open(d, router, out, 2)


def test_ambiguous_settle_is_unknown_with_its_watch_and_not_resent(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    watch = {"launcher_ids": [POOL], "spent_coin_ids": ["ee" * 32]}
    router.settle_script = [None, (503, {"success": False, "ambiguous": True,
                                         "code": "FORGE_PUSH_PENDING",
                                         "transaction_id": TXID, "watch": watch})]
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["tx_hash"] == TXID and out["watch"] == watch
    _assert_left_open(d, router, out, 2)
    assert d.rt_queue_approve({"queue_id": qid}, "human")["ok"] is False


def test_live_refusal_leaves_the_offer_open(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    router.settle_script = [None, (409, {"success": False, "error": "pool pays 5, trader asks 6"})]
    _assert_left_open(d, router, d.rt_queue_approve({"queue_id": qid}, "human"), 2)


def test_open_offer_expires_and_frees_the_pair(forge_daemon, monkeypatch):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    router.settle_script = [None, (409, {"success": False, "error": "refused"})]
    d.rt_queue_approve({"queue_id": qid}, "human")
    later = time.time() + 3601
    monkeypatch.setattr(time, "time", lambda: later)
    assert d._forge_open_offers() == {}
    assert d.rt_forge_swap(_swap(), "muse")["decision"] == "queued"


def test_forge_status_needs_the_wallets_own_offer_completed(forge_daemon):
    d, fake, router = forge_daemon
    qid = _queued(d, router)
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    st = {"chain": "chia-testnet", "offer_id": out["offer_id"], "watch": out["watch"]}
    # Pool tips spent, but the wallet's own offer not completed: another
    # trader's swap could have spent them (review finding 4).
    res = d.rt_forge_status(st, "m")
    assert res["pool_tips_spent"] is True and res["confirmed"] is False
    fake.records["oid1"]["status"] = "completed"
    res = d.rt_forge_status(st, "m")
    assert res["confirmed"] is True and res["offer_status"] == "completed"
    router.status_answer = {"success": True, "confirmed": True, "proof": "indexed tips exist"}
    assert d.rt_forge_status(st, "m")["confirmed"] is False
    assert d.rt_forge_status({"chain": "chia-testnet", "watch": out["watch"]}, "m")["ok"] is False
    assert d.rt_forge_status(dict(st, x=1), "m")["ok"] is False


def test_approval_card_fields_are_typed(forge_daemon):
    d, fake, router = forge_daemon
    q = _quote()
    q["intent"].update(price_impact_bps="0 (trust me)", total_fee_bps=10**20,
                       route=[{"pool": "<b>", "in": NATIVE, "out": CAT}, "x"] * 10)
    router.quotes = [q]
    qid = _queued(d, router)
    item = next(i for i in d._decoded_queue() if i["queue_id"] == qid)
    assert item["price_impact_bps"] is None and item["total_fee_bps"] is None
    assert len(item["route"]) <= 8
    assert all(set(h) <= {"pool", "in", "out"} and "pool" not in h for h in item["route"])

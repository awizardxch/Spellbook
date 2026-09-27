"""Tests for the Cast venue (dex.CastClient) — fixture payloads through a
monkeypatched _http_json; nothing here touches a live API, signs, or
broadcasts."""

import pytest

from spellbook import dex
from spellbook.dex import CastClient, DexError, normalize_venue, venue_serves_chain

TAKER = "0xc63fd4d246967347e9e9db12f748103c093ce463"
TOKEN = "0x21BEd5462749227F1b83f654DaeB6E44D5ea1Cd6"
WETH = "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73"
HOLDER = "0x0000000000001fF3684f28c67538d4D072C22734"
CALLDATA = "0x2213bc0b" + "00" * 64


def _quote_payload(sell=dex.NATIVE_SENTINEL, buy=TOKEN, **over):
    p = {
        "kind": "quote", "chainId": 4663, "network": "Robinhood Chain",
        "sellToken": sell, "buyToken": buy,
        "sellAmount": "1000", "buyAmount": "5000", "minBuyAmount": "4950",
        "allowanceTarget": None if sell == dex.NATIVE_SENTINEL else HOLDER,
        "approval": None,
        "transaction": {"chainId": 4663, "to": HOLDER, "data": CALLDATA,
                        "value": "1000" if sell == dex.NATIVE_SENTINEL else "0",
                        "gas": "210000", "gasPrice": "1000"},
    }
    p.update(over)
    return p


class _Calls(list):
    """Requests seen by the fake _http_json; .reply() queues its answers."""

    def __init__(self):
        super().__init__()
        self.replies = []

    def reply(self, payload):
        self.replies.append(payload)


@pytest.fixture
def calls(monkeypatch):
    seen = _Calls()

    def fake_http(method, url, headers, body=None, timeout=25):
        seen.append({"method": method, "url": url, "headers": headers, "body": body})
        return seen.replies.pop(0)

    monkeypatch.setattr(dex, "_http_json", fake_http)
    return seen


def test_cast_is_a_known_venue():
    assert normalize_venue("cast") == "cast"
    assert normalize_venue(" Cast ") == "cast"
    assert venue_serves_chain("cast", 4663)
    assert venue_serves_chain("cast", 8453)
    assert not venue_serves_chain("cast", 1)
    assert "cast" in dex.VENUES_KEY_OPTIONAL
    # Defaults unchanged: Cast is opt-in via dex.recommended_venues.
    assert "cast" not in dex.DEFAULT_RECOMMENDED_VENUES


def test_quote_posts_to_agent_api_without_key(calls):
    calls.reply(_quote_payload())
    q = CastClient().quote(4663, dex.NATIVE_SENTINEL, TOKEN, 1000, TAKER,
                           slippage_bps=100)
    c = calls[0]
    assert c["method"] == "POST"
    assert c["url"] == f"{dex.CAST_BASE}/api/agent/quote"
    assert "Authorization" not in c["headers"]
    assert c["body"] == {"chainId": 4663, "sellToken": dex.NATIVE_SENTINEL,
                         "buyToken": TOKEN, "sellAmount": "1000",
                         "taker": TAKER, "slippageBps": 100}
    assert q["venue"] == "cast"
    assert q["tx"] == {"to": HOLDER, "data": CALLDATA, "value": "1000",
                       "gas": "210000", "gas_price": "1000"}
    assert q["allowance_target"] is None
    assert (q["sell_amount"], q["buy_amount"], q["min_buy_amount"]) == ("1000", "5000", "4950")


def test_quote_sends_key_when_configured(calls):
    calls.reply(_quote_payload())
    CastClient("k1").quote(4663, dex.NATIVE_SENTINEL, TOKEN, 1000, TAKER)
    assert calls[0]["headers"]["Authorization"] == "Bearer k1"


def test_token_sell_uses_allowance_target_even_when_no_approval_needed(calls):
    calls.reply(_quote_payload(sell=TOKEN, buy=dex.NATIVE_SENTINEL))
    q = CastClient().quote(4663, TOKEN, dex.NATIVE_SENTINEL, 1000, TAKER)
    assert q["allowance_target"] == HOLDER
    plan = dex.validate_swap_intent_against_quote(
        {"chain_id": 4663, "sell_token": TOKEN, "buy_token": dex.NATIVE_SENTINEL,
         "sell_amount_wei": 1000, "min_buy_amount_wei": 4900,
         "max_slippage_bps": 100}, q)
    assert plan["needs_approval"] and plan["allowance_target"] == HOLDER


def test_token_sell_falls_back_to_approval_spender(calls):
    calls.reply(_quote_payload(sell=TOKEN, buy=WETH, allowanceTarget=None,
                               approval={"spender": HOLDER, "amount": "1000"}))
    q = CastClient().quote(4663, TOKEN, WETH, 1000, TAKER)
    assert q["allowance_target"] == HOLDER


def test_token_sell_without_spender_fails_validation(calls):
    calls.reply(_quote_payload(sell=TOKEN, buy=WETH, allowanceTarget=None))
    q = CastClient().quote(4663, TOKEN, WETH, 1000, TAKER)
    with pytest.raises(DexError, match="allowance_target"):
        dex.validate_swap_intent_against_quote(
            {"chain_id": 4663, "sell_token": TOKEN, "buy_token": WETH,
             "sell_amount_wei": 1000, "min_buy_amount_wei": 1,
             "max_slippage_bps": 100}, q)


def test_conflicting_spenders_are_refused(calls):
    calls.reply(_quote_payload(sell=TOKEN, buy=WETH,
                               approval={"spender": "0x" + "9" * 40}))
    with pytest.raises(DexError, match="two different spenders"):
        CastClient().quote(4663, TOKEN, WETH, 1000, TAKER)


@pytest.mark.parametrize("field,value,match", [
    ("chainId", 8453, "answered for chain"),
    ("buyToken", WETH, "buyToken"),
])
def test_answer_for_another_request_is_refused(calls, field, value, match):
    calls.reply(_quote_payload(**{field: value}))
    with pytest.raises(DexError, match=match):
        CastClient().quote(4663, dex.NATIVE_SENTINEL, TOKEN, 1000, TAKER)


def test_quote_sell_amount_is_casts_echo(calls):
    # Validation must compare what Cast will actually execute, not our request.
    calls.reply(_quote_payload(sellAmount="999"))
    q = CastClient().quote(4663, dex.NATIVE_SENTINEL, TOKEN, 1000, TAKER)
    with pytest.raises(DexError, match="exact amount"):
        dex.validate_swap_intent_against_quote(
            {"chain_id": 4663, "sell_token": dex.NATIVE_SENTINEL,
             "buy_token": TOKEN, "sell_amount_wei": 1000,
             "min_buy_amount_wei": 1, "max_slippage_bps": 100}, q)


def test_quote_without_transaction_is_refused(calls):
    calls.reply(_quote_payload(transaction=None))
    with pytest.raises(DexError, match="missing executable transaction"):
        CastClient().quote(4663, dex.NATIVE_SENTINEL, TOKEN, 1000, TAKER)


def test_rejects_bad_inputs_before_calling(calls):
    c = CastClient()
    with pytest.raises(DexError, match="does not serve chain 1"):
        c.quote(1, dex.NATIVE_SENTINEL, TOKEN, 1000, TAKER)
    with pytest.raises(DexError, match="slippage_bps"):
        c.quote(4663, dex.NATIVE_SENTINEL, TOKEN, 1000, TAKER, slippage_bps=900)
    with pytest.raises(DexError, match="taker"):
        c.quote(4663, dex.NATIVE_SENTINEL, TOKEN, 1000, "nope")
    assert calls == []


def test_price_is_indicative(calls):
    calls.reply({"kind": "price", "chainId": 8453, "sellToken": dex.NATIVE_SENTINEL,
                 "buyToken": TOKEN, "sellAmount": "1000", "buyAmount": "7",
                 "transaction": None})
    q = CastClient().price(8453, dex.NATIVE_SENTINEL, TOKEN, 1000)
    assert calls[0]["url"].endswith("/api/agent/price")
    assert "taker" not in calls[0]["body"]
    assert q["tx"] is None and q["buy_amount"] == "7" and q["chain_id"] == 8453


def test_read_only_endpoints(calls):
    c = CastClient()
    calls.reply({"networks": []})
    assert c.networks() == {"networks": []}
    assert calls[-1]["url"] == f"{dex.CAST_BASE}/api/agent/networks"

    calls.reply({"records": {}})
    c.tokens(4663, "blockscout")
    assert calls[-1]["url"] == f"{dex.CAST_BASE}/api/wizardswap/tokens?chainId=4663&source=blockscout"

    calls.reply({"symbol": "MUSE"})
    c.token_lookup(4663, TOKEN)
    assert calls[-1]["url"] == f"{dex.CAST_BASE}/api/token-lookup?chainId=4663&address={TOKEN}"

    calls.reply({"prices": {TOKEN.lower(): 0.5}})
    assert c.token_prices(4663, [TOKEN, WETH], [18, 18]) == {TOKEN.lower(): 0.5}
    assert calls[-1]["url"] == (f"{dex.CAST_BASE}/api/token-prices?chainId=4663"
                                f"&addresses={TOKEN}%2C{WETH}&decimals=18%2C18")
    assert all(x["method"] == "GET" for x in calls)

    with pytest.raises(DexError):
        c.token_lookup(4663, "0x123")
    with pytest.raises(DexError, match="one-to-one"):
        c.token_prices(4663, [TOKEN], [18, 6])


def test_daemon_swaps_through_cast_without_a_key(monkeypatch):
    """The daemon fetches the firm quote from Cast with no CAST_API_KEY set
    and validates it; here the chain is a stub that stops at the nonce."""
    from spellbook import daemon as daemon_mod

    monkeypatch.delenv("CAST_API_KEY", raising=False)
    fetched = []

    def quote(self, *a, **kw):
        fetched.append((self.api_key, a, kw))
        return {**_norm(), "sell_token": dex.NATIVE_SENTINEL, "buy_token": TOKEN}

    def _norm():
        return dex._norm_quote(
            venue="cast", chain_id=4663, sell_token=dex.NATIVE_SENTINEL,
            buy_token=TOKEN, sell_amount=1000, buy_amount=5000,
            min_buy_amount=4950, price_impact_bps=None, gas_estimate=None,
            tx={"to": HOLDER, "data": CALLDATA, "value": "1000"},
            allowance_target=None, raw={})

    monkeypatch.setattr(dex.CastClient, "quote", quote)

    class Stop(Exception):
        pass

    class Rpc:
        def nonce(self, _):
            raise Stop

    fake = type("D", (), {})()
    fake._evm_dex_guards = lambda params: ({"chain_id": 4663}, Rpc(), b"\x01" * 32, TAKER)
    with pytest.raises(Stop):  # quote fetched + validated, then on to the chain
        daemon_mod.Daemon._execute_evm_swap(fake, {
            "venue": "cast", "sell_token": dex.NATIVE_SENTINEL, "buy_token": TOKEN,
            "sell_amount_wei": 1000, "min_buy_amount_wei": 4900,
            "max_slippage_bps": 100, "deadline_sec": None})
    assert fetched and fetched[0][0] is None
    assert fetched[0][2] == {"slippage_bps": 100}


@pytest.mark.parametrize("venue,relay,ok", [
    ("cast", False, True),      # Cast's key is optional
    ("matcha", True, True),     # relay (ZEROX_BASE_URL) holds the 0x key
    ("matcha", False, True),    # operator relay holds the 0x key
    ("uniswap", True, False),   # the relay only stands in for 0x
])
def test_daemon_blank_key_rules(monkeypatch, venue, relay, ok):
    from spellbook import daemon as daemon_mod, evm

    for k in ("CAST_API_KEY", "ZERO_EX_API_KEY", "UNISWAP_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    if relay:
        monkeypatch.setenv("ZEROX_BASE_URL", "http://127.0.0.1:8899")
    else:
        monkeypatch.delenv("ZEROX_BASE_URL", raising=False)

    class Fetched(Exception):
        pass

    def stop(*a, **kw):
        raise Fetched

    monkeypatch.setattr(dex.CastClient, "quote", stop)
    monkeypatch.setattr(dex.ZeroExClient, "quote", stop)
    monkeypatch.setattr(dex.UniswapClient, "quote", stop)
    fake = type("D", (), {})()
    fake._evm_dex_guards = lambda params: ({"chain_id": 4663}, None, b"\x01" * 32, TAKER)
    params = {"venue": venue, "sell_token": dex.NATIVE_SENTINEL, "buy_token": TOKEN,
              "sell_amount_wei": 1000, "min_buy_amount_wei": 1,
              "max_slippage_bps": 100, "deadline_sec": None}
    if ok:
        with pytest.raises(Fetched):  # got past the key gate to the quote
            daemon_mod.Daemon._execute_evm_swap(fake, params)
    else:
        with pytest.raises(evm.EvmError, match="not in the daemon environment"):
            daemon_mod.Daemon._execute_evm_swap(fake, params)


def test_uniswap_swap_without_key_is_refused_at_request_time(tmp_path, monkeypatch):
    """Uniswap has no server-side key: refuse the request before a human
    spends an approval on a swap that could never fetch its quote."""
    from spellbook import evm
    from test_dex import _daemon

    monkeypatch.delenv("UNISWAP_API_KEY", raising=False)
    d = _daemon(tmp_path, {"recommended_venues": ["matcha", "uniswap", "cast"]})
    base = {"intent": "dex_swap", "chain": "evm-4663",
            "sell_token": dex.NATIVE_SENTINEL, "buy_token": TOKEN,
            "sell_amount_wei": 1000, "min_buy_amount_wei": 1,
            "max_slippage_bps": 100}
    with pytest.raises(evm.EvmError, match="needs UNISWAP_API_KEY"):
        d._validate_dex_swap({**base, "venue": "uniswap"})
    for venue in ("matcha", "cast"):  # keyless venues pass
        assert d._validate_dex_swap({**base, "venue": venue})["venue"] == venue
    monkeypatch.setenv("UNISWAP_API_KEY", "k")
    assert d._validate_dex_swap({**base, "venue": "uniswap"})["venue"] == "uniswap"

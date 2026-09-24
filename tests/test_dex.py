"""Tests for src/spellbook/dex.py — pure functions only, no network.

Quote-client HTTP paths are exercised against fixture payloads via
monkeypatched _http_json; nothing here touches a live API, signs, or
broadcasts.
"""

import json
import secrets

import pytest

from spellbook import dex
from spellbook.dex import (
    DexError,
    ZeroExClient,
    UniswapClient,
    build_approve_calldata,
    build_allowance_calldata,
    decode_allowance,
    build_v2_swap_calldata,
    build_v2_add_liquidity_calldata,
    build_v3_exact_input_single_calldata,
    build_v3_mint_calldata,
    compare_quotes,
    normalize_venue,
    venue_serves_chain,
)

A = "0x1111111111111111111111111111111111111111"
B = "0x2222222222222222222222222222222222222222"
C = "0x3333333333333333333333333333333333333333"


def _payload(hexdata: str) -> bytes:
    assert hexdata.startswith("0x")
    return bytes.fromhex(hexdata[10:])  # strip 0x + 4-byte selector


def _word(payload: bytes, i: int) -> int:
    return int.from_bytes(payload[i * 32:(i + 1) * 32], "big")


# --------------------------------------------------------------------------
# ERC-20
# --------------------------------------------------------------------------

def test_approve_selector_and_layout():
    cd = build_approve_calldata(B, 1000)
    assert cd.startswith("0x095ea7b3")
    p = _payload(cd)
    assert len(p) == 64
    assert p[12:32] == bytes.fromhex(B[2:])   # address, left-padded
    assert _word(p, 1) == 1000


def test_approve_rejects_bad_inputs():
    with pytest.raises(DexError):
        build_approve_calldata("not-an-address", 1000)
    with pytest.raises(DexError):
        build_approve_calldata(B, 0)
    with pytest.raises(DexError):
        build_approve_calldata(B, -5)


def test_allowance_round_trip():
    cd = build_allowance_calldata(A, B)
    assert cd.startswith("0xdd62ed3e")
    assert len(_payload(cd)) == 64
    assert decode_allowance("0x" + "0" * 62 + "ff") == 255
    with pytest.raises(DexError):
        decode_allowance("0x1234")


# --------------------------------------------------------------------------
# Uniswap v2
# --------------------------------------------------------------------------

def test_v2_swap_layout():
    cd = build_v2_swap_calldata(10**18, 990 * 10**15, [A, B], C, 1_800_000_000)
    assert cd.startswith("0x38ed1739")
    p = _payload(cd)
    # 5 head slots + tail(len + 2 addrs)
    assert len(p) == 5 * 32 + 3 * 32
    assert _word(p, 0) == 10**18
    assert _word(p, 1) == 990 * 10**15
    assert _word(p, 2) == 5 * 32            # offset to path array
    assert p[3 * 32 + 12:4 * 32] == bytes.fromhex(C[2:])
    assert _word(p, 4) == 1_800_000_000
    # tail
    assert _word(p, 5) == 2                 # array length
    assert p[6 * 32 + 12:7 * 32] == bytes.fromhex(A[2:])
    assert p[7 * 32 + 12:8 * 32] == bytes.fromhex(B[2:])


def test_v2_swap_rejects_short_path():
    with pytest.raises(DexError):
        build_v2_swap_calldata(100, 90, [A], C, 99)


def test_v2_add_liquidity_layout():
    cd = build_v2_add_liquidity_calldata(A, B, 100, 200, 90, 180, C, 99)
    assert cd.startswith("0xe8e33700")
    p = _payload(cd)
    assert len(p) == 8 * 32
    assert p[12:32] == bytes.fromhex(A[2:])
    assert p[32 + 12:64] == bytes.fromhex(B[2:])
    assert _word(p, 2) == 100
    assert _word(p, 5) == 180
    assert _word(p, 7) == 99


# --------------------------------------------------------------------------
# Uniswap v3
# --------------------------------------------------------------------------

def test_v3_exact_input_single_layout():
    cd = build_v3_exact_input_single_calldata(A, B, 3000, C, 10**18, 997 * 10**15)
    assert cd.startswith("0x414bf389")
    p = _payload(cd)
    assert len(p) == 7 * 32  # single tuple param, all static
    assert p[12:32] == bytes.fromhex(A[2:])
    assert p[32 + 12:64] == bytes.fromhex(B[2:])
    assert _word(p, 2) == 3000
    assert p[3 * 32 + 12:4 * 32] == bytes.fromhex(C[2:])
    assert _word(p, 4) == 10**18
    assert _word(p, 5) == 997 * 10**15
    assert _word(p, 6) == 0  # no price limit


def test_v3_exact_input_single_rejects_bad_fee():
    with pytest.raises(DexError):
        build_v3_exact_input_single_calldata(A, B, 1234, C, 100, 90)


def test_v3_mint_layout_and_sort_guard():
    cd = build_v3_mint_calldata(A, B, 500, -100, 100, 1000, 2000, 900, 1800,
                                C, 99)
    assert cd.startswith("0x88316456")
    p = _payload(cd)
    assert len(p) == 11 * 32
    assert _word(p, 2) == 500
    # int24 negative tick encodes two's complement
    assert _word(p, 3) == 2**256 - 100
    assert _word(p, 4) == 100
    assert _word(p, 10) == 99
    # token0 must sort below token1
    with pytest.raises(DexError):
        build_v3_mint_calldata(B, A, 500, -100, 100, 1, 1, 0, 0, C, 99)
    with pytest.raises(DexError):
        build_v3_mint_calldata(A, B, 500, 100, 100, 1, 1, 0, 0, C, 99)


# --------------------------------------------------------------------------
# Quote comparison
# --------------------------------------------------------------------------

def _q(venue, sell, buy):
    return {"venue": venue, "sell_amount": str(sell), "buy_amount": str(buy),
            "chain_id": 8453}


def test_compare_quotes_ranks_best_output():
    out = compare_quotes([_q("0x", 1000, 900), _q("uniswap", 1000, 950)])
    assert out["best"]["venue"] == "uniswap"
    assert out["ranked"][0]["venue"] == "uniswap"
    assert "uniswap" in out["note"]


def test_compare_quotes_empty():
    with pytest.raises(DexError):
        compare_quotes([])


# --------------------------------------------------------------------------
# Clients — fixture-driven, no network
# --------------------------------------------------------------------------

def _zerox_quote_fixture():
    return {
        "buyAmount": "950000",
        "minBuyAmount": "940000",
        "allowanceTarget": C,
        "transaction": {
            "to": B,
            "data": "0x1234",
            "value": "0",
            "gas": "250000",
        },
    }


def test_zerox_quote_parses(monkeypatch):
    seen = {}

    def fake_http(method, url, headers, body=None, timeout=25):
        seen["url"] = url
        seen["headers"] = headers
        assert method == "GET"
        assert "0x-api-key" in headers and headers["0x-version"] == "v2"
        return _zerox_quote_fixture()

    monkeypatch.setattr(dex, "_http_json", fake_http)
    c = ZeroExClient("key123")
    q = c.quote(8453, A, B, 10**18, C, slippage_bps=50)
    assert q["venue"] == "matcha"  # canonical venue name ("0x" is an alias)
    assert q["buy_amount"] == "950000"
    assert q["min_buy_amount"] == "940000"
    assert q["allowance_target"] == C
    assert q["tx"]["to"] == B and q["tx"]["data"] == "0x1234"
    assert "slippageBps=50" in seen["url"]
    assert "taker=" in seen["url"]


def test_zerox_refuses_unknown_chain():
    c = ZeroExClient("key123")
    with pytest.raises(DexError):
        c.quote(46630, A, B, 100, C)  # Robinhood Chain testnet not served by 0x


def test_zerox_without_key_uses_operator_relay(monkeypatch):
    # The operator's relay holds the 0x key server-side: agents are not
    # asked for one, and no empty key header is sent.
    monkeypatch.delenv("ZEROX_BASE_URL", raising=False)
    seen = {}

    def fake_http(method, url, headers, body=None, timeout=25):
        seen["url"], seen["headers"] = url, headers
        return _zerox_quote_fixture()

    monkeypatch.setattr(dex, "_http_json", fake_http)
    for key in ("", None):
        c = ZeroExClient(key)
        assert c.base == dex.SPELLBOOK_QUOTE_RELAY
        c.quote(8453, A, B, 10**18, C)
        assert seen["url"].startswith(
            f"{dex.SPELLBOOK_QUOTE_RELAY}/swap/allowance-holder/quote?")
        assert "0x-api-key" not in seen["headers"]
        assert seen["headers"]["0x-version"] == "v2"
    assert ZeroExClient().base == dex.SPELLBOOK_QUOTE_RELAY


def test_zerox_own_key_goes_direct(monkeypatch):
    monkeypatch.delenv("ZEROX_BASE_URL", raising=False)
    c = ZeroExClient("mykey")
    assert c.base == dex.ZEROX_DIRECT == "https://api.0x.org"
    assert c._headers()["0x-api-key"] == "mykey"


def test_zerox_blank_key_allowed_in_relay_mode(monkeypatch):
    # Cast site (via the shim) holds the API key server-side — the local
    # key is ignored, so blank is fine when ZEROX_BASE_URL is overridden.
    monkeypatch.setenv("ZEROX_BASE_URL", "http://127.0.0.1:8899")
    assert dex.relay_mode() is True
    c = ZeroExClient("")
    assert c.api_key == ""


def test_zerox_base_url_override_wins(monkeypatch):
    # ZEROX_BASE_URL (e.g. a local shim) beats both defaults, key or not.
    monkeypatch.setenv("ZEROX_BASE_URL", "http://127.0.0.1:8899/")
    assert ZeroExClient("").base == "http://127.0.0.1:8899"
    assert ZeroExClient("mykey").base == "http://127.0.0.1:8899"
    monkeypatch.delenv("ZEROX_BASE_URL")
    assert dex.relay_mode() is False


def test_uniswap_flow(monkeypatch):
    calls = []
    bodies = {}

    def fake_http(method, url, headers, body=None, timeout=25):
        calls.append(url)
        assert headers["x-api-key"] == "ukey"
        assert headers["X-Agent-Info"] == dex.AGENT_INFO
        # X-Agent-Info must be the JSON object Uniswap's
        # agent-attribution docs specify (a plain string is dropped
        # as malformed by their parser).
        info = json.loads(headers["X-Agent-Info"])
        assert info["decision_origin"] == "human_mediated"
        assert info["integration_name"] == "spellbook"
        if url.endswith("/check_approval"):
            bodies["check_approval"] = body
            return {"approval": None}
        if url.endswith("/quote"):
            return {"routing": "CLASSIC",
                    "quote": {"input": {"amount": "1000"},
                              "output": {"amount": "950"}}}
        if url.endswith("/swap"):
            bodies["swap"] = body
            assert body["routing"] == "CLASSIC"
            assert "permitData" not in body  # explicit nulls are stripped
            return {"swap": {"to": B, "from": C, "data": "0xabcd",
                             "value": "0", "gasLimit": "200000"}}
        raise AssertionError(url)

    monkeypatch.setattr(dex, "_http_json", fake_http)
    c = UniswapClient("ukey")
    ap = c.check_approval(8453, A, 1000, C)
    assert ap == {"approval_needed": False, "tx": None, "raw": {"approval": None}}
    # the ApprovalRequest schema names the wallet field "walletAddress"
    assert bodies["check_approval"]["walletAddress"] == C
    assert "wallet" not in bodies["check_approval"]
    q = c.quote(8453, A, B, 1000, C)
    assert q["venue"] == "uniswap" and q["buy_amount"] == "950"
    # null-stripping: permitData null must not reach /swap
    raw = {"routing": "CLASSIC", "permitData": None,
           "quote": {"input": {"amount": "1000"}, "output": {"amount": "950"}}}
    s = c.swap(raw, 8453, A, B, 1000, C)
    assert s["tx"]["to"] == B and s["tx"]["data"] == "0xabcd"
    # the /swap body is the /quote response itself, per the guide —
    # no top-level token/amount fields are invented onto it
    assert "tokenIn" not in bodies["swap"]
    assert "swapper" not in bodies["swap"]
    assert "amount" not in bodies["swap"]


def test_uniswap_swap_requires_permit_signature(monkeypatch):
    def fake_http(method, url, headers, body=None, timeout=25):
        raise AssertionError("must refuse before any HTTP call")

    monkeypatch.setattr(dex, "_http_json", fake_http)
    c = UniswapClient("ukey")
    raw = {"routing": "CLASSIC",
           "permitData": {"permit": {"domain": {}}},
           "quote": {"input": {"amount": "1000"},
                     "output": {"amount": "950"}}}
    with pytest.raises(DexError, match="EIP-712"):
        c.swap(raw, 8453, A, B, 1000, C)


def test_uniswap_swap_passes_permit_signature(monkeypatch):
    seen = {}

    def fake_http(method, url, headers, body=None, timeout=25):
        if url.endswith("/swap"):
            seen.update(body)
            return {"swap": {"to": B, "from": C, "data": "0xabcd",
                             "value": "0", "gasLimit": "200000"}}
        raise AssertionError(url)

    monkeypatch.setattr(dex, "_http_json", fake_http)
    c = UniswapClient("ukey")
    raw = {"routing": "CLASSIC",
           "permitData": {"permit": {"domain": {}}},
           "quote": {"input": {"amount": "1000"},
                     "output": {"amount": "950"}}}
    s = c.swap(raw, 8453, A, B, 1000, C, permit_signature="0xsig")
    assert seen["signature"] == "0xsig"
    assert s["tx"]["to"] == B


def test_uniswap_refuses_chained_routing(monkeypatch):
    monkeypatch.setattr(dex, "_http_json",
                        lambda *a, **k: {"routing": "DUTCH_V2"})
    c = UniswapClient("ukey")
    with pytest.raises(DexError):
        c.swap({"routing": "DUTCH_V2"}, 8453, A, B, 1000, C)
    # CHAINED routings go to /plan, not /order, per the guide's table
    with pytest.raises(DexError, match="plan"):
        c.swap({"routing": "CHAINED",
                "quote": {"input": {}, "output": {}}},
               8453, A, B, 1000, C)


def test_uniswap_requires_key():
    with pytest.raises(DexError):
        UniswapClient("")

# --------------------------------------------------------------------------
# validate_swap_intent_against_quote
# --------------------------------------------------------------------------

from spellbook.dex import (
    NATIVE_SENTINEL,
    validate_swap_intent_against_quote,
)

SELL = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
BUY = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
SPENDER = "0xcccccccccccccccccccccccccccccccccccccccc"


def _intent(**kw):
    base = {"chain_id": 8453, "sell_token": SELL, "buy_token": BUY,
            "sell_amount_wei": 10**18, "min_buy_amount_wei": 3000 * 10**6,
            "max_slippage_bps": 50}
    base.update(kw)
    return base


def _quote(**kw):
    base = {"venue": "0x", "chain_id": 8453, "sell_token": SELL,
            "buy_token": BUY, "sell_amount": str(10**18),
            "buy_amount": str(3100 * 10**6),
            "allowance_target": SPENDER,
            "tx": {"to": "0xdef1c0ded9bec7f1a1670819833240f027b25eff",
                   "data": "0x1234567890abcdef",
                   "value": "0"}}
    base.update(kw)
    return base


def test_validate_swap_happy_path():
    plan = validate_swap_intent_against_quote(_intent(), _quote())
    assert plan["to"] == "0xdef1c0ded9bec7f1a1670819833240f027b25eff"
    assert plan["data"] == "0x1234567890abcdef"
    assert plan["value_wei"] == 0
    assert plan["needs_approval"] is True
    assert plan["allowance_target"] == SPENDER
    assert plan["buy_amount_wei"] == 3100 * 10**6


def test_validate_swap_chain_mismatch():
    with pytest.raises(DexError, match="chain"):
        validate_swap_intent_against_quote(_intent(), _quote(chain_id=1))


def test_validate_swap_token_mismatch():
    with pytest.raises(DexError, match="buy_token"):
        validate_swap_intent_against_quote(
            _intent(), _quote(buy_token="0xdddddddddddddddddddddddddddddddddddddddd"))


def test_validate_swap_sell_amount_must_be_exact():
    with pytest.raises(DexError, match="exact amount"):
        validate_swap_intent_against_quote(
            _intent(), _quote(sell_amount=str(10**18 - 1)))


def test_validate_swap_buy_below_minimum():
    with pytest.raises(DexError, match="minimum"):
        validate_swap_intent_against_quote(
            _intent(), _quote(buy_amount=str(2999 * 10**6)))


def test_validate_swap_missing_tx():
    with pytest.raises(DexError, match="no executable transaction"):
        validate_swap_intent_against_quote(_intent(), _quote(tx=None))


def test_validate_swap_no_allowance_target_for_token_sell():
    with pytest.raises(DexError, match="allowance_target"):
        validate_swap_intent_against_quote(
            _intent(), _quote(allowance_target=None))


def test_validate_swap_token_sell_must_have_zero_value():
    with pytest.raises(DexError, match="must be 0"):
        validate_swap_intent_against_quote(_intent(), _quote(
            tx={"to": "0xdef1c0ded9bec7f1a1670819833240f027b25eff",
                "data": "0x1234567890abcdef", "value": "100"}))


def test_validate_swap_native_sell():
    intent = _intent(sell_token=NATIVE_SENTINEL)
    q = _quote(sell_token=NATIVE_SENTINEL, allowance_target=None,
               tx={"to": "0xdef1c0ded9bec7f1a1670819833240f027b25eff",
                   "data": "0x1234567890abcdef", "value": str(10**18)})
    plan = validate_swap_intent_against_quote(intent, q)
    assert plan["value_wei"] == 10**18
    assert plan["needs_approval"] is False


def test_validate_swap_native_value_mismatch():
    intent = _intent(sell_token=NATIVE_SENTINEL)
    q = _quote(sell_token=NATIVE_SENTINEL, allowance_target=None,
               tx={"to": "0xdef1c0ded9bec7f1a1670819833240f027b25eff",
                   "data": "0x1234567890abcdef", "value": str(10**18 - 1)})
    with pytest.raises(DexError, match="tx value"):
        validate_swap_intent_against_quote(intent, q)


def test_validate_swap_native_sell_zero_address():
    # Uniswap's native representation is the zero address (their docs),
    # not the 0x sentinel — the validator must accept both.
    from spellbook.dex import NATIVE_ZERO
    intent = _intent(sell_token=NATIVE_ZERO)
    q = _quote(sell_token=NATIVE_ZERO, allowance_target=None,
               tx={"to": "0xdef1c0ded9bec7f1a1670819833240f027b25eff",
                   "data": "0x1234567890abcdef", "value": str(10**18)})
    plan = validate_swap_intent_against_quote(intent, q)
    assert plan["value_wei"] == 10**18
    assert plan["needs_approval"] is False


# --------------------------------------------------------------------------
# Venue registry + user allowlist
# --------------------------------------------------------------------------

def test_normalize_venue_canonical_and_alias():
    assert normalize_venue("matcha") == "matcha"
    assert normalize_venue("0x") == "matcha"      # the API brand is an alias
    assert normalize_venue("uniswap") == "uniswap"
    assert normalize_venue(" Matcha ") == "matcha"  # tolerant input
    assert normalize_venue("UNISWAP") == "uniswap"


def test_normalize_venue_rejects_unknown():
    for bad in ("sushiswap", "", "   ", None, 123, "0xx"):
        with pytest.raises(DexError, match="unknown DEX venue"):
            normalize_venue(bad)


def test_venue_serves_chain():
    assert venue_serves_chain("matcha", 8453)
    assert venue_serves_chain("matcha", 1)
    assert venue_serves_chain("uniswap", 1)
    assert venue_serves_chain("uniswap", 8453)
    # Both aggregators serve Robinhood Chain mainnet (per their official
    # supported-chains docs, 2026-09-23); the testnet is refused, never guessed.
    assert venue_serves_chain("matcha", 4663)
    assert venue_serves_chain("uniswap", 4663)
    assert not venue_serves_chain("matcha", 46630)
    assert not venue_serves_chain("uniswap", 46630)
    # Unknown venue -> False (fail closed).
    assert not venue_serves_chain("sushiswap", 1)


def test_chain_lists_mirror_official_docs():
    # The chain lists are snapshots of the venues' official
    # supported-chains pages (the docs are the authority). If a venue
    # adds/removes a chain, update the list AND this snapshot together.
    from spellbook.dex import ZEROX_CHAINS, UNISWAP_CHAINS
    assert ZEROX_CHAINS == frozenset({
        1, 2741, 42161, 5042, 43114, 8453, 80094, 56, 999, 57073,
        59144, 5000, 143, 10, 9745, 137, 4663, 534352, 146, 4217,
        130, 480,
    })  # https://docs.0x.org/docs/introduction/supported-chains
    assert UNISWAP_CHAINS == frozenset({
        1, 10, 56, 130, 137, 143, 196, 324, 480, 1868, 4217, 4326,
        4663, 5042, 8453, 42161, 42220, 43114, 57073, 59144,
        7777777, 1301, 84532, 11155111,
    })  # https://developers.uniswap.org/docs/trading/swapping-api/supported-chains


# --------------------------------------------------------------------------
# Daemon allowlist enforcement (in-process Daemon, tmp config dir — no
# socket, no network, no signing)
# --------------------------------------------------------------------------

_MISSING = object()  # sentinel: "dex" key absent from spellbook.json


def _daemon(tmp_path, dex_cfg=_MISSING):
    """Minimal config dir: spellbook.json + policy.json + both tokens.

    dex_cfg is the value of the "dex" key; omitted -> key absent (default
    allowlist)."""
    from spellbook.daemon import Daemon
    cfg = {"labels": ["default"]}
    if dex_cfg is not _MISSING:
        cfg["dex"] = dex_cfg
    for name, data in (
            ("spellbook.json", json.dumps(cfg)),
            ("policy.json", json.dumps({})),
            ("request.token", secrets.token_hex(32)),
            ("approve.token", secrets.token_hex(32))):
        p = tmp_path / name
        p.write_text(data)
        p.chmod(0o600)
    return Daemon(str(tmp_path))


def _base_chain(monkeypatch):
    """evm.CHAINS on this branch is Robinhood-only; add Base so the
    venue/chain checks have a served chain to exercise (test-only)."""
    from spellbook import evm
    monkeypatch.setitem(evm.CHAINS, "evm-8453",
                        {"chain_id": 8453, "testnet": False, "name": "Base"})


def _swap_params(**over):
    p = {"intent": "dex_swap", "chain": "evm-8453", "venue": "matcha",
         "sell_token": A, "buy_token": B,
         "sell_amount_wei": 10**18, "min_buy_amount_wei": 9 * 10**17,
         "max_slippage_bps": 50, "purpose": "test"}
    p.update(over)
    return p


def test_daemon_default_recommended_venues(tmp_path):
    d = _daemon(tmp_path)
    assert d.dex_recommended_venues == ["matcha", "uniswap"]


def test_daemon_custom_recommended_venues(tmp_path):
    d = _daemon(tmp_path, {"recommended_venues": ["uniswap"]})
    assert d.dex_recommended_venues == ["uniswap"]


def test_daemon_normalizes_0x_alias_in_config(tmp_path):
    d = _daemon(tmp_path, {"recommended_venues": ["0x"]})
    assert d.dex_recommended_venues == ["matcha"]


def test_daemon_rejects_unknown_venue_in_config(tmp_path):
    with pytest.raises(ValueError, match="bad dex.recommended_venues"):
        _daemon(tmp_path, {"recommended_venues": ["sushiswap"]})


def test_daemon_rejects_empty_recommended_list(tmp_path):
    with pytest.raises(ValueError, match="non-empty list"):
        _daemon(tmp_path, {"recommended_venues": []})


def test_validate_swap_recommended_venue_has_no_warning(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    intent = d._validate_dex_swap(_swap_params())
    assert intent["venue"] == "matcha"
    assert intent["chain_id"] == 8453
    assert intent["venue_warning"] is None


def test_validate_swap_alias_0x_normalized(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    intent = d._validate_dex_swap(_swap_params(venue="0x"))
    assert intent["venue"] == "matcha"


def test_validate_swap_warns_on_non_recommended_venue(tmp_path, monkeypatch):
    # The recommendation list is advisory, not a gate: a venue outside
    # it is queued WITH a warning, and the human's approval authorizes
    # the venue — it is never refused for this reason.
    _base_chain(monkeypatch)
    d = _daemon(tmp_path, {"recommended_venues": ["uniswap"]})
    intent = d._validate_dex_swap(_swap_params(venue="matcha"))
    assert intent["venue"] == "matcha"
    assert intent["venue_warning"] is not None
    assert "not on your recommended venue list" in intent["venue_warning"]
    assert "approving this swap authorizes the venue" in intent["venue_warning"]


def test_validate_swap_rejects_unknown_venue(tmp_path, monkeypatch):
    from spellbook.evm import EvmError
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="unknown DEX venue"):
        d._validate_dex_swap(_swap_params(venue="sushiswap"))


def test_validate_swap_rejects_unserved_chain_at_request_time(tmp_path):
    # Robinhood Chain testnet (46630) is in evm.CHAINS but served by
    # neither venue: the refusal happens at request time with a clear
    # reason, not as a confusing failure at execution.
    from spellbook.evm import EvmError
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="does not serve"):
        d._validate_dex_swap(_swap_params(chain="evm-46630"))


def test_rt_dex_venues(tmp_path):
    d = _daemon(tmp_path, {"recommended_venues": ["matcha"]})
    out = d.rt_dex_venues({}, "muse-test")
    assert out["recommended_venues"] == ["matcha"]
    assert "not a gate" in out["note"]
    assert out["known_venues"]["matcha"]["env_key"] == "ZERO_EX_API_KEY"
    assert out["known_venues"]["uniswap"]["env_key"] == "UNISWAP_API_KEY"
    assert 8453 in out["known_venues"]["matcha"]["chain_ids"]
    assert 4663 in out["known_venues"]["matcha"]["chain_ids"]
    assert 46630 not in out["known_venues"]["matcha"]["chain_ids"]

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
    build_v2_remove_liquidity_calldata,
    build_v3_exact_input_single_calldata,
    build_v3_mint_calldata,
    build_v3_decrease_liquidity_calldata,
    build_v3_collect_calldata,
    build_v3_multicall_calldata,
    build_v3_remove_and_collect_calldata,
    V4_ACTIONS,
    V4_NATIVE_CURRENCY,
    build_v4_pool_key,
    v4_pool_id,
    build_v4_modify_liquidities_calldata,
    build_v4_mint_params,
    build_v4_decrease_params,
    build_v4_settle_pair_params,
    build_v4_take_pair_params,
    build_v4_burn_params,
    build_v4_lp_add_calldata,
    build_v4_lp_remove_calldata,
    build_v4_lp_claim_calldata,
    build_permit2_allowance_calldata,
    decode_permit2_allowance,
    build_permit2_approve_calldata,
    build_erc721_owner_of_calldata,
    decode_erc721_owner_of,
    build_posm_pool_manager_calldata,
    decode_address_return,
    build_pool_manager_get_slot0_calldata,
    decode_slot0_sqrt_price_x96,
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
    cd = build_v3_exact_input_single_calldata(
        A, B, 3000, C, 10**18, 997 * 10**15, 1800000000)
    assert cd.startswith("0x414bf389")
    p = _payload(cd)
    assert len(p) == 8 * 32  # single tuple param, all static
    assert p[12:32] == bytes.fromhex(A[2:])
    assert p[32 + 12:64] == bytes.fromhex(B[2:])
    assert _word(p, 2) == 3000
    assert p[3 * 32 + 12:4 * 32] == bytes.fromhex(C[2:])
    assert _word(p, 4) == 1800000000  # deadline sits before amountIn
    assert _word(p, 5) == 10**18
    assert _word(p, 6) == 997 * 10**15
    assert _word(p, 7) == 0  # no price limit


def test_v3_exact_input_single_requires_deadline():
    with pytest.raises(TypeError):
        # deadline is positional-required: no accidental zero-deadline swaps
        build_v3_exact_input_single_calldata(A, B, 3000, C, 100, 90)


def test_v3_exact_input_single_rejects_bad_fee():
    with pytest.raises(DexError):
        build_v3_exact_input_single_calldata(A, B, 1234, C, 100, 90,
                                             1800000000)


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
# LP remove / claim builders (v2, v3, v4) + Permit2
# --------------------------------------------------------------------------

DEADLINE = 1800000000


def test_v2_remove_liquidity_layout():
    cd = build_v2_remove_liquidity_calldata(A, B, 1234, 500, 600, C,
                                            DEADLINE)
    assert cd.startswith("0xbaa2abde")
    p = _payload(cd)
    assert len(p) == 7 * 32
    assert p[12:32] == bytes.fromhex(A[2:])
    assert p[32 + 12:64] == bytes.fromhex(B[2:])
    assert _word(p, 2) == 1234
    assert _word(p, 3) == 500
    assert _word(p, 4) == 600
    assert p[5 * 32 + 12:6 * 32] == bytes.fromhex(C[2:])
    assert _word(p, 6) == DEADLINE
    with pytest.raises(DexError):
        build_v2_remove_liquidity_calldata(A, B, 0, 0, 0, C, DEADLINE)


def test_v3_decrease_liquidity_layout():
    cd = build_v3_decrease_liquidity_calldata(42, 1000, 900, 800, DEADLINE)
    assert cd.startswith("0x0c49ccbe")
    p = _payload(cd)
    assert len(p) == 5 * 32
    assert _word(p, 0) == 42
    assert _word(p, 1) == 1000
    assert _word(p, 2) == 900
    assert _word(p, 3) == 800
    assert _word(p, 4) == DEADLINE
    with pytest.raises(DexError):
        build_v3_decrease_liquidity_calldata(0, 1000, 0, 0, DEADLINE)


def test_v3_collect_layout_defaults_to_max():
    cd = build_v3_collect_calldata(42, C)
    assert cd.startswith("0xfc6f7865")
    p = _payload(cd)
    assert len(p) == 4 * 32
    assert _word(p, 0) == 42
    assert p[32 + 12:64] == bytes.fromhex(C[2:])
    assert _word(p, 2) == 2 ** 128 - 1  # type(uint128).max — claim all
    assert _word(p, 3) == 2 ** 128 - 1


def test_v3_multicall_nests_decrease_and_collect():
    dec = build_v3_decrease_liquidity_calldata(42, 1000, 900, 800, DEADLINE)
    col = build_v3_collect_calldata(42, C)
    cd = build_v3_multicall_calldata([dec, col])
    assert cd.startswith("0xac9650d8")
    assert cd.count("0c49ccbe") == 1  # the inner calls ride along verbatim
    assert cd.count("fc6f7865") == 1
    with pytest.raises(DexError):
        build_v3_multicall_calldata([])


def test_v3_remove_and_collect_combines_both():
    cd = build_v3_remove_and_collect_calldata(42, 1000, 900, 800, C,
                                              DEADLINE)
    assert cd.startswith("0xac9650d8")
    assert cd.count("0c49ccbe") == 1
    assert cd.count("fc6f7865") == 1


def _v4_pool_args():
    return dict(currency0=A, currency1=B, fee=3000, tick_spacing=60,
                hooks="0x0000000000000000000000000000000000000000")


def test_v4_pool_key_layout_and_id():
    key = build_v4_pool_key(**_v4_pool_args())
    assert len(key) == 5 * 32
    assert key[12:32] == bytes.fromhex(A[2:])
    assert key[32 + 12:64] == bytes.fromhex(B[2:])
    assert int.from_bytes(key[64:96], "big") == 3000
    assert int.from_bytes(key[96:128], "big", signed=True) == 60
    assert key[128 + 12:160] == bytes(20)
    pool_id = v4_pool_id(**_v4_pool_args())
    assert pool_id.startswith("0x") and len(pool_id) == 66
    # currency sort guard
    with pytest.raises(DexError):
        build_v4_pool_key(currency0=B, currency1=A, fee=3000,
                          tick_spacing=60,
                          hooks="0x0000000000000000000000000000000000000000")
    # tick alignment guard lives on the mint path (5 not divisible by 60)
    with pytest.raises(DexError):
        build_v4_mint_params(tick_lower=5, tick_upper=120, liquidity=1,
                             amount0_max=1, amount1_max=1, owner=C,
                             **_v4_pool_args())
    # native currency refused
    with pytest.raises(DexError):
        build_v4_pool_key(currency0=V4_NATIVE_CURRENCY, currency1=B,
                          fee=3000, tick_spacing=60,
                          hooks="0x" + "00" * 20)


def test_v4_actions_match_official_constants():
    assert V4_ACTIONS["INCREASE_LIQUIDITY"] == 0x00
    assert V4_ACTIONS["DECREASE_LIQUIDITY"] == 0x01
    assert V4_ACTIONS["MINT_POSITION"] == 0x02
    assert V4_ACTIONS["BURN_POSITION"] == 0x03
    assert V4_ACTIONS["SETTLE_PAIR"] == 0x0D
    assert V4_ACTIONS["TAKE_PAIR"] == 0x11
    assert V4_ACTIONS["CLOSE_CURRENCY"] == 0x12
    assert V4_ACTIONS["SWEEP"] == 0x14


def _unlock_actions(p: bytes):
    """From a modifyLiquidities payload, return (actions_bytes,
    params_list_of_bytes). Asserts the trailing deadline."""
    unlock_off = _word(p, 0)
    assert _word(p, 1) == DEADLINE
    u = p[unlock_off:]
    act_off = _word(u, 0)
    par_off = _word(u, 1)
    act_len = _word(u, act_off // 32)
    actions = u[act_off + 32:act_off + 32 + act_len]
    arr = u[par_off:]  # bytes[] encoding: length word, then offset heads
    data = arr[32:]    # element offsets are relative to here
    n = _word(arr, 0)
    params = []
    for i in range(n):
        off = int.from_bytes(data[i * 32:(i + 1) * 32], "big")
        ln = int.from_bytes(data[off:off + 32], "big")
        params.append(data[off + 32:off + 32 + ln])
    return actions, params


def test_v4_modify_liquidities_layout():
    mint = build_v4_mint_params(tick_lower=-120, tick_upper=120,
                                liquidity=1000, amount0_max=900,
                                amount1_max=800, owner=C, **_v4_pool_args())
    settle = build_v4_settle_pair_params(A, B)
    cd = build_v4_modify_liquidities_calldata(
        bytes([V4_ACTIONS["MINT_POSITION"], V4_ACTIONS["SETTLE_PAIR"]]),
        [mint, settle], DEADLINE)
    assert cd.startswith("0xdd46508f")
    p = _payload(cd)
    actions, params = _unlock_actions(p)
    assert actions == bytes([0x02, 0x0D])
    assert len(params) == 2
    assert params[1] == settle  # settle pair is static: (c0, c1)
    # mint params: pool key first (5 words), then ticks
    assert params[0][5 * 32:6 * 32] == (-120).to_bytes(32, "big",
                                                      signed=True)
    assert params[0][6 * 32:7 * 32] == (120).to_bytes(32, "big")
    with pytest.raises(DexError):
        build_v4_modify_liquidities_calldata(b"", [], DEADLINE)
    with pytest.raises(DexError):
        build_v4_modify_liquidities_calldata(b"\x99", [mint], DEADLINE)
    with pytest.raises(DexError):
        build_v4_modify_liquidities_calldata(b"\x02", [mint, settle],
                                             DEADLINE)


def test_v4_mint_params_layout():
    m = build_v4_mint_params(tick_lower=-120, tick_upper=120,
                             liquidity=1000, amount0_max=900,
                             amount1_max=800, owner=C, **_v4_pool_args())
    # head: poolKey(5w) tickL tickU liq a0Max a1Max owner hookData(offset)
    assert int.from_bytes(m[5 * 32:6 * 32], "big", signed=True) == -120
    assert int.from_bytes(m[6 * 32:7 * 32], "big", signed=True) == 120
    assert int.from_bytes(m[7 * 32:8 * 32], "big") == 1000
    assert int.from_bytes(m[8 * 32:9 * 32], "big") == 900
    assert int.from_bytes(m[9 * 32:10 * 32], "big") == 800
    assert m[10 * 32 + 12:11 * 32] == bytes.fromhex(C[2:])
    assert int.from_bytes(m[11 * 32:12 * 32], "big") == 12 * 32  # hookData off


def test_v4_decrease_params_claim_zero_is_allowed():
    d = build_v4_decrease_params(7, 0, 0, 0)  # zero-liquidity = fee claim
    assert int.from_bytes(d[0:32], "big") == 7
    assert int.from_bytes(d[32:64], "big") == 0
    with pytest.raises(DexError):
        build_v4_decrease_params(7, -1, 0, 0)


def test_v4_lp_add_remove_claim_action_bytes():
    add = build_v4_lp_add_calldata(tick_lower=-120, tick_upper=120,
                                   liquidity=1000, amount0_max=900,
                                   amount1_max=800, recipient=C,
                                   deadline=DEADLINE, **_v4_pool_args())
    actions, params = _unlock_actions(_payload(add))
    assert actions == bytes([0x02, 0x0D])  # MINT_POSITION, SETTLE_PAIR
    assert len(params) == 2

    rem = build_v4_lp_remove_calldata(7, 1000, 900, 800, A, B, C, DEADLINE)
    actions, params = _unlock_actions(_payload(rem))
    assert actions == bytes([0x01, 0x11])  # DECREASE, TAKE_PAIR
    assert len(params) == 2

    rem_burn = build_v4_lp_remove_calldata(7, 1000, 900, 800, A, B, C,
                                           DEADLINE, burn_nft=True)
    actions, params = _unlock_actions(_payload(rem_burn))
    assert actions == bytes([0x01, 0x11, 0x03])  # + BURN_POSITION
    assert len(params) == 3

    claim = build_v4_lp_claim_calldata(7, A, B, C, DEADLINE)
    actions, params = _unlock_actions(_payload(claim))
    assert actions == bytes([0x01, 0x11])  # zero-liquidity DECREASE + TAKE
    assert len(params) == 2
    assert int.from_bytes(params[0][32:64], "big") == 0  # liquidity == 0

    with pytest.raises(DexError):
        build_v4_lp_remove_calldata(7, 0, 0, 0, A, B, C, DEADLINE)


def test_permit2_builders():
    al = build_permit2_allowance_calldata(A, B, C)
    assert al.startswith("0x927da105")
    p = _payload(al)
    assert len(p) == 3 * 32
    assert p[12:32] == bytes.fromhex(A[2:])
    ap = build_permit2_approve_calldata(B, C, 1000, DEADLINE)
    assert ap.startswith("0x87517c45")
    p = _payload(ap)
    assert len(p) == 4 * 32
    assert _word(p, 2) == 1000
    assert _word(p, 3) == DEADLINE
    with pytest.raises(DexError):
        build_permit2_approve_calldata(B, C, 0, DEADLINE)
    # allowance decode round-trip
    ret = "0x" + (1000).to_bytes(32, "big").hex() \
        + DEADLINE.to_bytes(32, "big").hex() \
        + (5).to_bytes(32, "big").hex()
    assert decode_permit2_allowance(ret) == (1000, DEADLINE, 5)


def test_owner_of_and_read_helpers():
    cd = build_erc721_owner_of_calldata(42)
    assert cd.startswith("0x6352211e")
    p = _payload(cd)
    assert _word(p, 0) == 42
    ret = "0x" + bytes(12).hex() + C[2:]
    assert decode_erc721_owner_of(ret) == C.lower()
    assert decode_address_return(ret) == C.lower()
    assert build_posm_pool_manager_calldata() == "0xdc4c90d3"
    pid = v4_pool_id(**_v4_pool_args())
    sc = build_pool_manager_get_slot0_calldata(pid)
    assert sc.startswith("0xc815641c")
    sq = "0x" + (2 ** 160).to_bytes(32, "big").hex()
    assert decode_slot0_sqrt_price_x96(sq) == 2 ** 160
    zero = "0x" + bytes(32).hex()
    assert decode_slot0_sqrt_price_x96(zero) == 0


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


def test_zerox_quote_with_null_allowance_issue(monkeypatch):
    # 0x sends issues.allowance = null when no approval is needed (native
    # sell, or allowance already enough). That must parse, not crash.
    raw = _zerox_quote_fixture()
    raw.pop("allowanceTarget", None)
    raw["issues"] = {"allowance": None, "balance": None}
    monkeypatch.setattr(dex, "_http_json", lambda *a, **k: raw)
    q = ZeroExClient("k").quote(8453, dex.NATIVE_SENTINEL, B, 10**18, C)
    assert q["allowance_target"] is None


def test_zerox_without_key_uses_operator_relay(monkeypatch):
    # Cast (the operator's relay) holds the 0x key server-side: agents are not
    # asked for one, and no empty key header is sent.
    monkeypatch.delenv("ZEROX_BASE_URL", raising=False)
    seen = {}

    def fake_http(method, url, headers, body=None, timeout=25):
        seen["url"], seen["headers"] = url, headers
        return _zerox_quote_fixture()

    monkeypatch.setattr(dex, "_http_json", fake_http)
    for key in ("", None):
        c = ZeroExClient(key)
        assert c.base == dex.OPERATOR_QUOTE_RELAY == "https://cast.awizard.dev"
        c.quote(8453, A, B, 10**18, C)
        assert seen["url"].startswith(
            f"{dex.OPERATOR_QUOTE_RELAY}/swap/allowance-holder/quote?")
        assert "0x-api-key" not in seen["headers"]
        assert seen["headers"]["0x-version"] == "v2"
    assert ZeroExClient().base == dex.OPERATOR_QUOTE_RELAY


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


# ---------------------------------------------------------------------------
# LP add v4 / LP remove / LP claim intent validation + queue flow
# ---------------------------------------------------------------------------

POSM = "0x3333333333333333333333333333333333333333"
PERMIT2 = "0x4444444444444444444444444444444444444444"
PAIR = "0x5555555555555555555555555555555555555555"
NPM = "0x6666666666666666666666666666666666666666"
HOOKLESS = "0x0000000000000000000000000000000000000000"


def _v4_add_params(**over):
    p = {"intent": "dex_lp_add", "chain": "evm-8453", "protocol": "v4",
         "position_manager": POSM, "permit2": PERMIT2,
         "token_a": A, "token_b": B,
         "amount_a_wei": 10**18, "amount_b_wei": 2 * 10**18,
         "liquidity": 10**15, "fee": 3000, "tick_spacing": 60,
         "hooks": HOOKLESS, "tick_lower": -600, "tick_upper": 600,
         "purpose": "test"}
    p.update(over)
    return p


def _remove_params(**over):
    p = {"intent": "dex_lp_remove", "chain": "evm-8453", "protocol": "v3",
         "router": NPM, "token_a": A, "token_b": B, "token_id": 7,
         "liquidity": 10**15, "amount_a_min_wei": 1, "amount_b_min_wei": 2,
         "purpose": "test"}
    p.update(over)
    return p


def _claim_params(**over):
    p = {"intent": "dex_lp_claim", "chain": "evm-8453", "protocol": "v3",
         "router": NPM, "token_a": A, "token_b": B, "token_id": 7,
         "purpose": "test"}
    p.update(over)
    return p


def test_validate_lp_add_v4_happy(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_add(_v4_add_params())
    assert intent["protocol"] == "v4"
    assert intent["position_manager"] == POSM
    assert intent["liquidity"] == 10**15
    assert intent["chain_id"] == 8453


def test_validate_lp_add_v4_rejects_router(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="v2/v3-only"):
        d._validate_dex_lp_add(_v4_add_params(router=NPM))


def test_validate_lp_add_v4_rejects_hooked_pool(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="hook"):
        d._validate_dex_lp_add(_v4_add_params(
            hooks="0x7777777777777777777777777777777777777777"))


def test_validate_lp_add_v4_rejects_misaligned_ticks(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="align"):
        d._validate_dex_lp_add(_v4_add_params(tick_lower=-601))


def test_validate_lp_add_v4_rejects_min_fields(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="v2/v3-only"):
        d._validate_dex_lp_add(_v4_add_params(amount_a_min_wei=5))


def test_validate_lp_add_v4_rejects_bad_fee(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="uint24"):
        d._validate_dex_lp_add(_v4_add_params(fee=2**24))


def test_validate_lp_add_v4_rejects_native(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="wrap to WETH"):
        d._validate_dex_lp_add(_v4_add_params(token_a=HOOKLESS))


def test_validate_lp_add_v4_rejects_unknown_field(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="schema violation"):
        d._validate_dex_lp_add(_v4_add_params(evil_calldata="0xdead"))


def test_validate_lp_remove_v2_happy(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_remove(
        _remove_params(protocol="v2", router="0x8888888888888888888888888888888888888888",
                       pair=PAIR, token_id=None))
    assert intent["pair"] == PAIR
    assert intent["token_id"] is None


def test_validate_lp_remove_v2_requires_pair(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="pair"):
        d._validate_dex_lp_remove(
            _remove_params(protocol="v2",
                           router="0x8888888888888888888888888888888888888888",
                           pair=None, token_id=None))


def test_validate_lp_remove_v3_requires_token_id(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="token_id"):
        d._validate_dex_lp_remove(_remove_params(token_id=None))


def test_validate_lp_remove_v4_happy(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_remove(
        _remove_params(protocol="v4", position_manager=POSM, router=None,
                       burn_nft=True))
    assert intent["position_manager"] == POSM
    assert intent["burn_nft"] is True


def test_validate_lp_remove_rejects_burn_on_v3(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="v4-only"):
        d._validate_dex_lp_remove(_remove_params(burn_nft=True))


def test_validate_lp_remove_rejects_unknown_field(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="schema violation"):
        d._validate_dex_lp_remove(_remove_params(opaque="0x1234"))


def test_validate_lp_claim_v3_happy(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_claim(_claim_params())
    assert intent["protocol"] == "v3"
    assert intent["token_id"] == 7


def test_validate_lp_claim_rejects_v2(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    with pytest.raises(Exception, match="dex_lp_remove"):
        d._validate_dex_lp_claim(_claim_params(protocol="v2"))


def test_validate_lp_claim_v4_happy(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_claim(
        _claim_params(protocol="v4", position_manager=POSM, router=None))
    assert intent["position_manager"] == POSM


def test_velocity_entries_remove_claim_empty(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    assert d._velocity_entries(_remove_params()) == []
    assert d._velocity_entries(_claim_params()) == []


def test_velocity_entries_lp_add_v4_uses_max_spends(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    entries = d._velocity_entries(_v4_add_params())
    assert entries == [("evm-8453", A.lower(), 10**18),
                       ("evm-8453", B.lower(), 2 * 10**18)]


def test_rt_lp_remove_always_queues(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    out = d.rt_dex_lp_remove(_remove_params(), "muse-test")
    assert out["decision"] == "queued"


def test_rt_lp_claim_always_queues(tmp_path, monkeypatch):
    _base_chain(monkeypatch)
    d = _daemon(tmp_path)
    out = d.rt_dex_lp_claim(_claim_params(), "muse-test")
    assert out["decision"] == "queued"

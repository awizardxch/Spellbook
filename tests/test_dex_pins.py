"""Official contract pins (Robinhood Chain 4663 and Base 8453) and the
routes they re-enable: Uniswap swaps through the Universal Router (v2, v3
and v4 pools), 0x/matcha/cast on Base, and v2/v3 LP. Every route still
passes the S-20/S-21 decode-before-sign checks; calldata is hand-built
with eth_abi. Nothing here touches a network, signs or broadcasts."""

import json
import pathlib

import pytest

from spellbook import dex
from spellbook.dex import (DexError, NATIVE_SENTINEL,
                           validate_swap_intent_against_quote)

import _dex_calldata as cd

FIXTURE = (pathlib.Path(__file__).parent / "fixtures"
           / "uniswap_deployments_4663_8453.json")


# -- the pins themselves -------------------------------------------------------

def _feed():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_fixture_is_the_cited_feed():
    feed = _feed()
    assert feed["version"] == "1.0.0"
    assert feed["generatedAt"] == "2026-09-22T20:38:17.000Z"
    assert feed["source"] == {
        "repo": "https://github.com/Uniswap/contracts",
        "commit": "a677c0d4b5fb6e3357cf6d0f0315bcb135a1e1ee"}
    assert "a677c0d" in dex.SOURCE_UNISWAP and "2026-09-22" in dex.SOURCE_UNISWAP


def _uniswap_pins():
    """(chain, role, address, source) for every built-in Uniswap pin."""
    out = []
    for cid, roles in dex.PINNED_CONTRACTS.items():
        for role, addr in roles.items():
            if role != dex.PIN_ALLOWANCE_HOLDER:
                out.append((cid, role, addr, dex.PINNED_SOURCES[(cid, role)]))
    for (cid, role), alts in dex.PINNED_ALTERNATES.items():
        for addr, src in alts.items():
            out.append((cid, role, addr, src))
    return out


def test_every_uniswap_pin_is_a_record_of_the_feed():
    records = _feed()["records"]
    pins = _uniswap_pins()
    assert len(pins) == len(records) == 20
    for cid, role, addr, src in pins:
        protocol, contract = dex.UNISWAP_ROLE_CONTRACTS[role]
        match = [r for r in records if r["chainId"] == cid
                 and r["address"].lower() == addr]
        assert len(match) == 1, (cid, role, addr)
        rec = match[0]
        assert rec["protocol"] == protocol
        assert rec["contract"].split("#")[0] == contract
        assert rec["status"] == "active" and rec["env"] == "mainnet"
        assert src.startswith(dex.SOURCE_UNISWAP)
        # The source names the exact record (version suffix included).
        assert src.endswith(": " + rec["contract"])


def test_pins_are_lowercase_addresses():
    for cid, roles in dex.PINNED_CONTRACTS.items():
        for role, addr in roles.items():
            assert addr == addr.lower() and dex._is_address(addr)
    for alts in dex.PINNED_ALTERNATES.values():
        for addr in alts:
            assert addr == addr.lower() and dex._is_address(addr)


def test_allowance_holder_comes_from_the_0x_settler_readme():
    for cid in (4663, 8453):
        assert dex.PINNED_CONTRACTS[cid][dex.PIN_ALLOWANCE_HOLDER] == cd.HOLDER
        assert dex.pin_source(cid, dex.PIN_ALLOWANCE_HOLDER).startswith(
            "0x-settler README")


def test_settler_is_not_pinned_but_its_registry_is_recorded():
    assert dex.SETTLER_REGISTRY == "0x00000000000004533fe15556b1e086bb1a72ceae"
    assert dex.SETTLER_FEATURE_TAKER_SUBMITTED == 2
    assert "settler" not in dex.PIN_ROLES


def test_state_view_table_mirrors_the_pins():
    for cid, sv in dex.V4_STATE_VIEW_ADDRESSES.items():
        assert dex.PINNED_CONTRACTS[cid][dex.PIN_V4_STATE_VIEW] == sv


def test_both_router_versions_are_accepted_and_an_override_replaces_them():
    assert set(dex.pinned_set(4663, dex.PIN_UNIVERSAL_ROUTER)) == {
        cd.UR_4663, cd.UR_4663_V212}
    assert cd.UR_8453_V12 not in dex.pinned_set(8453, dex.PIN_UNIVERSAL_ROUTER)
    over = {4663: {dex.PIN_UNIVERSAL_ROUTER: cd.UR}}
    assert dex.pinned_set(4663, dex.PIN_UNIVERSAL_ROUTER, over) == {
        cd.UR: dex.OVERRIDE_SOURCE}


# -- Uniswap swaps through the pinned Universal Router -------------------------

def _uni(data, *, chain=4663, to=cd.UR_4663, value="0", sell=cd.SELL,
         buy=cd.BUY, min_buy=cd.MIN_BUY):
    q = {"venue": "uniswap", "chain_id": chain, "sell_token": sell,
         "buy_token": buy, "sell_amount": str(cd.SELL_AMOUNT),
         "buy_amount": str(3100 * 10**6), "allowance_target": None,
         "tx": {"to": to, "data": data, "value": value}}
    intent = cd.swap_intent(venue="uniswap", chain_id=chain, sell_token=sell,
                            buy_token=buy, min_buy_amount_wei=min_buy)
    return validate_swap_intent_against_quote(intent, q)


def _ur(*cmds, deadline=1_900_000_000):
    return cd.ur_execute(bytes(c for c, _ in cmds), [i for _, i in cmds],
                         deadline=deadline)


@pytest.mark.parametrize("chain,router", [
    (4663, cd.UR_4663), (4663, cd.UR_4663_V212),
    (8453, cd.UR_8453), (8453, cd.UR_8453_V212)])
def test_uniswap_token_sell_v3_is_accepted(chain, router):
    plan = _uni(_ur((0x00, cd.ur_v3_in())), chain=chain, to=router)
    d = plan["decoded"]
    assert plan["to"] == router and d["target"] == router
    assert d["target_source"].startswith(dex.SOURCE_UNISWAP)
    assert d["commands"] == ["V3_SWAP_EXACT_IN"] and d["recipient"] == cd.WALLET
    # Approve the sell token to Permit2, then Permit2 -> this router.
    assert plan["allowance_target"] == cd.PERMIT2
    assert plan["permit2_spender"] == router
    assert plan["approve_amount_wei"] == cd.SELL_AMOUNT


def test_uniswap_token_sell_v2_path_is_accepted_on_base():
    plan = _uni(_ur((0x08, cd.ur_v2_in())), chain=8453, to=cd.UR_8453)
    assert plan["decoded"]["commands"] == ["V2_SWAP_EXACT_IN"]


def test_uniswap_native_sell_is_accepted_on_base():
    plan = _uni(_ur((0x0B, cd.ur_wrap()), (0x00, cd.ur_v3_in(payer_user=False))),
                chain=8453, to=cd.UR_8453, value=str(cd.SELL_AMOUNT),
                sell=NATIVE_SENTINEL)
    assert plan["needs_approval"] is False and plan["permit2_spender"] is None
    assert plan["value_wei"] == cd.SELL_AMOUNT


def test_uniswap_unpinned_router_version_is_refused():
    with pytest.raises(DexError, match="not the pinned universal_router"):
        _uni(_ur((0x00, cd.ur_v3_in())), chain=8453, to=cd.UR_8453_V12)


def test_uniswap_router_of_the_other_chain_is_refused():
    with pytest.raises(DexError, match="not the pinned universal_router"):
        _uni(_ur((0x00, cd.ur_v3_in())), chain=8453, to=cd.UR_4663)


def test_uniswap_quote_naming_another_spender_is_refused():
    q = {"venue": "uniswap", "chain_id": 4663, "sell_token": cd.SELL,
         "buy_token": cd.BUY, "sell_amount": str(cd.SELL_AMOUNT),
         "buy_amount": str(3100 * 10**6), "allowance_target": cd.UR_4663,
         "tx": {"to": cd.UR_4663, "data": _ur((0x00, cd.ur_v3_in())),
                "value": "0"}}
    with pytest.raises(DexError, match="not the pinned permit2"):
        validate_swap_intent_against_quote(
            cd.swap_intent(venue="uniswap"), q)


def test_permit2_approval_is_bound_to_a_pinned_router_and_exact():
    ok = dict(chain_id=4663, token=cd.SELL, spender=cd.UR_4663_V212,
              amount=cd.SELL_AMOUNT, sell_token=cd.SELL,
              sell_amount=cd.SELL_AMOUNT)
    assert dex.check_permit2_approval(**ok) == cd.UR_4663_V212
    with pytest.raises(DexError, match="not a pinned universal_router"):
        dex.check_permit2_approval(**{**ok, "spender": cd.ATTACKER})
    with pytest.raises(DexError, match="exceeds the sell amount"):
        dex.check_permit2_approval(**{**ok, "amount": cd.SELL_AMOUNT + 1})
    with pytest.raises(DexError, match="approved sell"):
        dex.check_permit2_approval(**{**ok, "token": cd.BUY})


# -- V4_SWAP -------------------------------------------------------------------

def _v4(actions, params):
    return (0x10, cd.ur_v4_swap(bytes(actions), params))


def _v4_token_sell(min_out=cd.MIN_BUY, settle=None, take=None,
                   swap=None):
    swap = swap or cd.v4_exact_in_single(cd.SELL, cd.BUY, True,
                                         min_out=min_out)
    settle = settle or (0x0C, cd.v4_settle_all(cd.SELL))
    take = take or (0x0F, cd.v4_take_all(cd.BUY, 0))
    return _ur(_v4([0x06, settle[0], take[0]], [swap, settle[1], take[1]]))


def test_v4_single_token_sell_is_accepted():
    plan = _uni(_v4_token_sell())
    d = plan["decoded"]
    assert d["commands"] == ["V4_SWAP"]
    assert d["v4_actions"] == [["SWAP_EXACT_IN_SINGLE", "SETTLE_ALL",
                                "TAKE_ALL"]]
    assert d["min_buy_amount_wei"] == cd.MIN_BUY
    assert plan["permit2_spender"] == cd.UR_4663


def test_v4_settle_and_take_to_the_wallet_are_accepted():
    data = _v4_token_sell(settle=(0x0B, cd.v4_settle(cd.SELL, 0, True)),
                          take=(0x0E, cd.v4_take(cd.BUY, cd.WALLET)))
    assert _uni(data)["decoded"]["recipient"] == cd.WALLET


def test_v4_native_sell_is_accepted_on_base():
    swap = cd.v4_exact_in_single(cd.NATIVE_ZERO, cd.BUY, True)
    data = _ur(_v4([0x06, 0x0B, 0x0E],
                   [swap, cd.v4_settle(cd.NATIVE_ZERO, 0, True),
                    cd.v4_take(cd.BUY)]))
    plan = _uni(data, chain=8453, to=cd.UR_8453_V212,
                value=str(cd.SELL_AMOUNT), sell=NATIVE_SENTINEL)
    assert plan["value_wei"] == cd.SELL_AMOUNT and not plan["needs_approval"]


def test_v4_native_buy_is_accepted():
    swap = cd.v4_exact_in_single(cd.NATIVE_ZERO, cd.SELL, False)
    data = _ur(_v4([0x06, 0x0C, 0x0E],
                   [swap, cd.v4_settle_all(cd.SELL),
                    cd.v4_take(cd.NATIVE_ZERO)]))
    plan = _uni(data, buy=NATIVE_SENTINEL)
    assert plan["decoded"]["min_buy_amount_wei"] == cd.MIN_BUY


def test_v4_multi_hop_is_accepted():
    mid = "0x5555555555555555555555555555555555555555"
    swap = cd.v4_exact_in(cd.SELL, [mid, cd.BUY])
    data = _ur(_v4([0x07, 0x0C, 0x0F],
                   [swap, cd.v4_settle_all(cd.SELL),
                    cd.v4_take_all(cd.BUY, cd.MIN_BUY)]))
    assert _uni(data)["decoded"]["v4_actions"] == [
        ["SWAP_EXACT_IN", "SETTLE_ALL", "TAKE_ALL"]]


def test_v4_take_to_someone_else_is_refused():
    with pytest.raises(DexError, match="TAKE pays recipient"):
        _uni(_v4_token_sell(take=(0x0E, cd.v4_take(cd.BUY, cd.ATTACKER))))


def test_v4_min_out_below_the_intent_is_refused():
    with pytest.raises(DexError, match="guaranteed out"):
        _uni(_v4_token_sell(min_out=cd.MIN_BUY - 1))


def test_v4_sell_amount_larger_is_refused():
    swap = cd.v4_exact_in_single(cd.SELL, cd.BUY, True,
                                 amount_in=cd.SELL_AMOUNT + 1)
    with pytest.raises(DexError, match="pulls"):
        _uni(_v4_token_sell(swap=swap))


def test_v4_other_pair_is_refused():
    swap = cd.v4_exact_in_single(cd.SELL, cd.ATTACKER, True)
    with pytest.raises(DexError, match="approved"):
        _uni(_v4_token_sell(swap=swap))


def test_v4_take_of_another_currency_is_refused():
    with pytest.raises(DexError, match="TAKE_ALL of"):
        _uni(_v4_token_sell(take=(0x0F, cd.v4_take_all(cd.ATTACKER, 0))))


def test_v4_settle_from_the_router_on_a_token_sell_is_refused():
    with pytest.raises(DexError, match="paid by the router"):
        _uni(_v4_token_sell(settle=(0x0B, cd.v4_settle(cd.SELL, 0, False))))


def test_v4_partial_take_is_refused():
    with pytest.raises(DexError, match="partial TAKE"):
        _uni(_v4_token_sell(take=(0x0E, cd.v4_take(cd.BUY, cd.WALLET, 5))))


@pytest.mark.parametrize("extra", [0x10, 0x14, 0x08])  # TAKE_PORTION, SWEEP, EXACT_OUT
def test_v4_other_actions_are_refused(extra):
    swap = cd.v4_exact_in_single(cd.SELL, cd.BUY, True)
    data = _ur(_v4([0x06, 0x0C, 0x0F, extra],
                   [swap, cd.v4_settle_all(cd.SELL),
                    cd.v4_take_all(cd.BUY, cd.MIN_BUY), b""]))
    with pytest.raises(DexError, match="cannot be bounded"):
        _uni(data)


def test_v4_params_in_another_layout_are_refused():
    """A struct with an extra field puts other values where the decoder
    reads amountOutMinimum and the hookData offset. Here a naive read
    would see a huge minimum and a valid offset; the canonical re-encode
    refuses it instead of misreading it."""
    from eth_abi import encode
    key = (cd.SELL, cd.BUY, 3000, 60, cd.NATIVE_ZERO)
    swap = encode(
        ["((address,address,uint24,int24,address),bool,uint128,uint128,"
         "uint256,bytes)"],
        [(key, True, cd.SELL_AMOUNT, 10**30, 0x140, b"")])
    with pytest.raises(DexError, match="not the expected layout"):
        _uni(_v4_token_sell(swap=swap))
    swap = encode(
        ["((address,address,uint24,int24,address),bool,uint128,uint128,"
         "uint256,bytes)"],
        [(key, True, cd.SELL_AMOUNT, cd.MIN_BUY, 0, b"")])
    with pytest.raises(DexError, match="bad bytes field"):
        _uni(_v4_token_sell(swap=swap))


def test_v3_multicall_builder_matches_eth_abi():
    """The daemon's v3 remove calldata is the standard multicall(bytes[])
    encoding (it lacked the argument's offset word before this change)."""
    built = dex.build_v3_remove_and_collect_calldata(7, 10**15, 1, 2,
                                                     cd.WALLET, 1_900_000_000)
    assert built == cd.v3_multicall([cd.v3_decrease(), cd.v3_collect()])


# -- 0x / matcha / cast on Base ------------------------------------------------

@pytest.mark.parametrize("venue", ["matcha", "cast"])
def test_zerox_on_base_is_accepted(venue):
    q = cd.zerox_quote(venue=venue)
    q["chain_id"] = 8453
    plan = validate_swap_intent_against_quote(
        cd.swap_intent(chain_id=8453, venue=venue), q)
    assert plan["to"] == cd.HOLDER and plan["allowance_target"] == cd.HOLDER
    assert plan["permit2_spender"] is None


# -- v2 / v3 / v4 LP decoders --------------------------------------------------

def test_v2_add_decodes_and_binds():
    kw = dict(token_a=cd.SELL, token_b=cd.BUY, amount_a_cap=10**18,
              amount_b_cap=2 * 10**18, amount_a_min=0, amount_b_min=0,
              wallet=cd.WALLET)
    d = dex.decode_v2_add_liquidity_calldata(cd.v2_add(), **kw)
    assert d["recipient"] == cd.WALLET and d["amount_b_max_wei"] == 2 * 10**18
    with pytest.raises(DexError, match="not this wallet"):
        dex.decode_v2_add_liquidity_calldata(cd.v2_add(to=cd.ATTACKER), **kw)
    with pytest.raises(DexError, match="exceeds the approved cap"):
        dex.decode_v2_add_liquidity_calldata(cd.v2_add(a=10**18 + 1), **kw)
    with pytest.raises(DexError, match="tokens differ"):
        dex.decode_v2_add_liquidity_calldata(
            cd.v2_add(token_b=cd.ATTACKER), **kw)
    with pytest.raises(DexError, match="ERC-20s only"):
        dex.decode_v2_add_liquidity_calldata(
            cd.v2_add(), **{**kw, "token_a": cd.NATIVE_ZERO})


def test_v3_mint_decodes_and_binds():
    kw = dict(token0=cd.SELL, token1=cd.BUY, amount0_cap=10**18,
              amount1_cap=2 * 10**18, amount0_min=0, amount1_min=0, fee=3000,
              tick_lower=-600, tick_upper=600, wallet=cd.WALLET)
    d = dex.decode_v3_mint_calldata(cd.v3_mint(), **kw)
    assert d["recipient"] == cd.WALLET and d["tick_lower"] == -600
    with pytest.raises(DexError, match="not this wallet"):
        dex.decode_v3_mint_calldata(cd.v3_mint(recipient=cd.ATTACKER), **kw)
    with pytest.raises(DexError, match="exceeds the approved cap"):
        dex.decode_v3_mint_calldata(cd.v3_mint(a1=2 * 10**18 + 1), **kw)
    with pytest.raises(DexError, match="fee/ticks differ"):
        dex.decode_v3_mint_calldata(cd.v3_mint(fee=500), **kw)


def test_v2_remove_decodes_and_binds():
    kw = dict(token_a=cd.SELL, token_b=cd.BUY, liquidity=10**15,
              amount_a_min=1, amount_b_min=2, wallet=cd.WALLET)
    assert dex.decode_v2_remove_liquidity_calldata(
        cd.v2_remove(), **kw)["recipient"] == cd.WALLET
    with pytest.raises(DexError, match="not this wallet"):
        dex.decode_v2_remove_liquidity_calldata(
            cd.v2_remove(to=cd.ATTACKER), **kw)
    with pytest.raises(DexError, match="minimum below"):
        dex.decode_v2_remove_liquidity_calldata(cd.v2_remove(a_min=0), **kw)


def test_v3_remove_and_claim_decode_and_bind():
    kw = dict(token_id=7, liquidity=10**15, amount0_min=1, amount1_min=2,
              wallet=cd.WALLET)
    ok = cd.v3_multicall([cd.v3_decrease(), cd.v3_collect()])
    assert dex.decode_v3_remove_calldata(ok, **kw)["recipient"] == cd.WALLET
    with pytest.raises(DexError, match="not this wallet"):
        dex.decode_v3_remove_calldata(cd.v3_multicall(
            [cd.v3_decrease(), cd.v3_collect(recipient=cd.ATTACKER)]), **kw)
    with pytest.raises(DexError, match="carries 3 calls"):
        dex.decode_v3_remove_calldata(cd.v3_multicall(
            [cd.v3_decrease(), cd.v3_collect(), cd.v3_collect()]), **kw)
    claim = "0x" + cd.v3_collect().hex()
    assert dex.decode_v3_collect_calldata(
        claim, token_id=7, wallet=cd.WALLET)["recipient"] == cd.WALLET
    with pytest.raises(DexError, match="collects position 8"):
        dex.decode_v3_collect_calldata(
            "0x" + cd.v3_collect(token_id=8).hex(), token_id=7,
            wallet=cd.WALLET)


def test_v4_remove_and_claim_decode_and_bind():
    kw = dict(token_id=7, liquidity=10**15, amount0_min=1, amount1_min=2,
              currency0=cd.NATIVE_ZERO, currency1=cd.BUY, wallet=cd.WALLET)
    ok = cd.v4_modify(bytes([0x01, 0x11]), [cd.v4_decrease(),
                                            cd.v4_take_pair()])
    assert dex.decode_v4_lp_take_calldata(ok, **kw)["recipient"] == cd.WALLET
    burn = cd.v4_modify(bytes([0x01, 0x11, 0x03]),
                        [cd.v4_decrease(), cd.v4_take_pair(), cd.v4_burn()])
    assert dex.decode_v4_lp_take_calldata(burn, **kw, burn_nft=True)[
        "actions"] == ["DECREASE_LIQUIDITY", "TAKE_PAIR", "BURN_POSITION"]
    with pytest.raises(DexError, match="not the approved"):
        dex.decode_v4_lp_take_calldata(burn, **kw)
    with pytest.raises(DexError, match="not this wallet"):
        dex.decode_v4_lp_take_calldata(cd.v4_modify(
            bytes([0x01, 0x11]),
            [cd.v4_decrease(), cd.v4_take_pair(recipient=cd.ATTACKER)]), **kw)
    claim = cd.v4_modify(bytes([0x01, 0x11]),
                         [cd.v4_decrease(liquidity=0, m0=0, m1=0),
                          cd.v4_take_pair()])
    assert dex.decode_v4_lp_take_calldata(
        claim, **{**kw, "liquidity": 0, "amount0_min": 0,
                  "amount1_min": 0})["liquidity"] == 0


def test_daemon_builders_pass_their_own_decoders():
    """What the daemon builds and then decodes before signing agrees."""
    w, dl = cd.WALLET, 1_900_000_000
    dex.decode_v2_add_liquidity_calldata(
        dex.build_v2_add_liquidity_calldata(cd.SELL, cd.BUY, 5, 6, 1, 2, w,
                                            dl),
        token_a=cd.SELL, token_b=cd.BUY, amount_a_cap=5, amount_b_cap=6,
        amount_a_min=1, amount_b_min=2, wallet=w)
    dex.decode_v3_mint_calldata(
        dex.build_v3_mint_calldata(cd.SELL, cd.BUY, 3000, -600, 600, 5, 6, 1,
                                   2, w, dl),
        token0=cd.SELL, token1=cd.BUY, amount0_cap=5, amount1_cap=6,
        amount0_min=1, amount1_min=2, fee=3000, tick_lower=-600,
        tick_upper=600, wallet=w)
    dex.decode_v2_remove_liquidity_calldata(
        dex.build_v2_remove_liquidity_calldata(cd.SELL, cd.BUY, 9, 1, 2, w,
                                               dl),
        token_a=cd.SELL, token_b=cd.BUY, liquidity=9, amount_a_min=1,
        amount_b_min=2, wallet=w)
    dex.decode_v3_remove_calldata(
        dex.build_v3_remove_and_collect_calldata(7, 9, 1, 2, w, dl),
        token_id=7, liquidity=9, amount0_min=1, amount1_min=2, wallet=w)
    dex.decode_v3_collect_calldata(dex.build_v3_collect_calldata(7, w),
                                   token_id=7, wallet=w)
    dex.decode_v4_lp_take_calldata(
        dex.build_v4_lp_remove_calldata(7, 9, 1, 2, cd.SELL, cd.BUY, w, dl,
                                        burn_nft=True),
        token_id=7, liquidity=9, amount0_min=1, amount1_min=2,
        currency0=cd.SELL, currency1=cd.BUY, wallet=w, burn_nft=True)
    dex.decode_v4_lp_take_calldata(
        dex.build_v4_lp_claim_calldata(7, cd.SELL, cd.BUY, w, dl),
        token_id=7, liquidity=0, amount0_min=0, amount1_min=0,
        currency0=cd.SELL, currency1=cd.BUY, wallet=w)


# -- daemon: request and execution ---------------------------------------------

def test_lp_requests_on_both_chains_use_the_pins(tmp_path):
    from test_dex import _daemon
    d = _daemon(tmp_path)
    for chain, cid in (("evm-4663", 4663), ("evm-8453", 8453)):
        pins = dex.PINNED_CONTRACTS[cid]
        v2 = d._validate_dex_lp_add({
            "intent": "dex_lp_add", "chain": chain, "protocol": "v2",
            "token_a": cd.SELL, "token_b": cd.BUY, "amount_a_wei": 5,
            "amount_b_wei": 6, "amount_a_min_wei": 1, "amount_b_min_wei": 2})
        assert v2["router"] == pins[dex.PIN_V2_ROUTER]
        v3 = d._validate_dex_lp_remove({
            "intent": "dex_lp_remove", "chain": chain, "protocol": "v3",
            "token_a": cd.SELL, "token_b": cd.BUY, "token_id": 7,
            "liquidity": 9, "amount_a_min_wei": 0, "amount_b_min_wei": 0})
        assert v3["router"] == pins[dex.PIN_V3_POSITION_MANAGER]
        claim = d._validate_dex_lp_claim({
            "intent": "dex_lp_claim", "chain": chain, "protocol": "v3",
            "token_a": cd.SELL, "token_b": cd.BUY, "token_id": 7})
        assert claim["router"] == pins[dex.PIN_V3_POSITION_MANAGER]
        v4 = d._validate_dex_lp_add({
            "intent": "dex_lp_add", "chain": chain, "protocol": "v4",
            "token_a": cd.NATIVE_ZERO, "token_b": cd.BUY,
            "amount_a_wei": 10**18, "amount_b_wei": 10**18,
            "liquidity": 10**15, "fee": 3000, "tick_spacing": 60,
            "hooks": cd.NATIVE_ZERO, "tick_lower": -600, "tick_upper": 600})
        assert v4["position_manager"] == pins[dex.PIN_V4_POSITION_MANAGER]


def test_v2_v3_lp_native_leg_is_refused(tmp_path):
    from spellbook.evm import EvmError
    from test_dex import _daemon
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="ERC-20s only"):
        d._validate_dex_lp_add({
            "intent": "dex_lp_add", "chain": "evm-8453", "protocol": "v2",
            "token_a": cd.NATIVE_ZERO, "token_b": cd.BUY, "amount_a_wei": 5,
            "amount_b_wei": 6, "amount_a_min_wei": 1, "amount_b_min_wei": 2})


def test_uniswap_request_on_both_chains_is_accepted(tmp_path, monkeypatch):
    from test_dex import _daemon, _swap_params
    monkeypatch.setenv("UNISWAP_API_KEY", "k")
    d = _daemon(tmp_path)
    for chain in ("evm-4663", "evm-8453"):
        intent = d._validate_dex_swap(_swap_params(chain=chain,
                                                   venue="uniswap"))
        assert intent["venue"] == "uniswap"
        d.queue["1"] = {"params": _swap_params(chain=chain, venue="uniswap"),
                        "muse_id": "m", "queued_at": 0}
        checks = d._decoded_queue()[0]["swap_checks"]
        assert checks["refused"] is None
        assert checks["spender"] == cd.PERMIT2
        assert len(checks["accepted_targets"]) >= 2
        assert checks["permit2_spender"] == sorted(checks["accepted_targets"])


class _Recorder:
    def __init__(self):
        self.calls = []


def _fake_exec_daemon(tmp_path, monkeypatch, chain_id, rpc):
    from spellbook import daemon as daemon_mod
    from test_dex import _daemon
    d = _daemon(tmp_path)
    rec = _Recorder()
    d._evm_dex_guards = lambda params: (
        {"chain_id": chain_id}, rpc, b"\x01" * 32, cd.WALLET)

    def ensure_allowance(rpc_, priv, cid, sender, nonce, token, spender,
                         amount, gas):
        rec.calls.append(("approve", token, spender, amount))
        return "0xa1", nonce + 1

    def ensure_permit2(rpc_, priv, cid, sender, nonce, token, permit2,
                       spender, amount, expiration, gas):
        rec.calls.append(("permit2", token, permit2, spender, amount))
        return "0xa2", nonce + 1

    def send_call(rpc_, priv, cid, sender, nonce, to, value, data, gas, what,
                  gas_limit=None):
        rec.calls.append(("send", to, value, data, what))
        return "0xbeef", nonce + 1, 1

    d._evm_ensure_allowance = ensure_allowance
    d._evm_ensure_permit2_allowance = ensure_permit2
    d._evm_send_call = send_call
    monkeypatch.setattr(daemon_mod, "_evm_gas_price", lambda rpc_: 1)
    return d, rec


class _NonceRpc:
    def nonce(self, _):
        return 5


def test_uniswap_token_sell_executes_through_permit2(tmp_path, monkeypatch):
    seen = {}
    data = _v4_token_sell()

    def quote(self, chain_id, sell, buy, amount, swapper, slippage_pct=0.5,
              exact_output=False, permit_as_transaction=False):
        seen["permit_as_transaction"] = permit_as_transaction
        return {"raw": {"quote": {}}}

    def swap(self, raw, chain_id, sell, buy, amount, swapper, **kw):
        return dex._norm_quote(
            venue="uniswap", chain_id=chain_id, sell_token=sell,
            buy_token=buy, sell_amount=amount, buy_amount=3100 * 10**6,
            min_buy_amount=None, price_impact_bps=None, gas_estimate=None,
            tx={"to": cd.UR_8453_V212, "data": data, "value": "0"},
            allowance_target=None, raw={})

    monkeypatch.setattr(dex.UniswapClient, "quote", quote)
    monkeypatch.setattr(dex.UniswapClient, "swap", swap)
    monkeypatch.setenv("UNISWAP_API_KEY", "k")
    d, rec = _fake_exec_daemon(tmp_path, monkeypatch, 8453, _NonceRpc())
    out = d._execute_evm_swap({
        "venue": "uniswap", "sell_token": cd.SELL, "buy_token": cd.BUY,
        "sell_amount_wei": cd.SELL_AMOUNT, "min_buy_amount_wei": cd.MIN_BUY,
        "max_slippage_bps": 50, "deadline_sec": None})
    assert seen["permit_as_transaction"] is True
    assert rec.calls[0] == ("approve", cd.SELL, cd.PERMIT2, cd.SELL_AMOUNT)
    assert rec.calls[1] == ("permit2", cd.SELL, cd.PERMIT2, cd.UR_8453_V212,
                            cd.SELL_AMOUNT)
    assert rec.calls[2][:3] == ("send", cd.UR_8453_V212, 0)
    assert out["permit2_approve_tx_hash"] == "0xa2"
    assert out["decoded"]["target_source"].endswith("UniversalRouter#v2.1.2")


class _LpRpc:
    def __init__(self, owner=cd.WALLET):
        self.owner = owner

    def nonce(self, _):
        return 5

    def eth_call(self, to, data, sender):
        assert data.startswith("0x6352211e")  # ownerOf: the only read
        return "0x" + "00" * 12 + self.owner[2:]


@pytest.mark.parametrize("chain,cid", [("evm-4663", 4663), ("evm-8453", 8453)])
def test_v2_add_executes_against_the_pinned_router(tmp_path, monkeypatch,
                                                   chain, cid):
    d, rec = _fake_exec_daemon(tmp_path, monkeypatch, cid, _LpRpc())
    intent = d._validate_dex_lp_add({
        "intent": "dex_lp_add", "chain": chain, "protocol": "v2",
        "token_a": cd.SELL, "token_b": cd.BUY, "amount_a_wei": 5,
        "amount_b_wei": 6, "amount_a_min_wei": 1, "amount_b_min_wei": 2})
    out = d._execute_evm_lp_add(intent)
    router = dex.PINNED_CONTRACTS[cid][dex.PIN_V2_ROUTER]
    assert [c[2] for c in rec.calls[:2]] == [router, router]
    assert rec.calls[2][:2] == ("send", router)
    assert out["decoded"]["recipient"] == cd.WALLET
    assert out["decoded"]["target"] == router


def test_v3_remove_and_claim_execute_against_the_pinned_npm(tmp_path,
                                                           monkeypatch):
    d, rec = _fake_exec_daemon(tmp_path, monkeypatch, 8453, _LpRpc())
    npm = dex.PINNED_CONTRACTS[8453][dex.PIN_V3_POSITION_MANAGER]
    rm = d._validate_dex_lp_remove({
        "intent": "dex_lp_remove", "chain": "evm-8453", "protocol": "v3",
        "token_a": cd.SELL, "token_b": cd.BUY, "token_id": 7,
        "liquidity": 9, "amount_a_min_wei": 1, "amount_b_min_wei": 2})
    out = d._execute_evm_lp_remove(rm)
    assert rec.calls[-1][:2] == ("send", npm)
    assert out["decoded"]["calls"] == ["decreaseLiquidity", "collect"]
    cl = d._validate_dex_lp_claim({
        "intent": "dex_lp_claim", "chain": "evm-8453", "protocol": "v3",
        "token_a": cd.SELL, "token_b": cd.BUY, "token_id": 7})
    out = d._execute_evm_lp_claim(cl)
    assert out["decoded"]["recipient"] == cd.WALLET


def test_v4_native_remove_and_claim_execute_decoded(tmp_path, monkeypatch):
    d, rec = _fake_exec_daemon(tmp_path, monkeypatch, 4663, _LpRpc())
    posm = dex.PINNED_CONTRACTS[4663][dex.PIN_V4_POSITION_MANAGER]
    base = {"chain": "evm-4663", "protocol": "v4", "token_a": cd.NATIVE_ZERO,
            "token_b": cd.BUY, "token_id": 7}
    out = d._execute_evm_lp_remove(d._validate_dex_lp_remove({
        **base, "intent": "dex_lp_remove", "liquidity": 9,
        "amount_a_min_wei": 1, "amount_b_min_wei": 2, "burn_nft": True}))
    assert rec.calls[-1][:2] == ("send", posm)
    assert out["decoded"]["actions"][-1] == "BURN_POSITION"
    out = d._execute_evm_lp_claim(d._validate_dex_lp_claim({
        **base, "intent": "dex_lp_claim"}))
    assert out["decoded"]["liquidity"] == 0
    assert out["decoded"]["recipient"] == cd.WALLET


def test_v4_add_refuses_a_position_manager_reporting_another_pool_manager(
        tmp_path):
    from spellbook.evm import EvmError
    from test_dex import _daemon
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_add({
        "intent": "dex_lp_add", "chain": "evm-8453", "protocol": "v4",
        "token_a": cd.NATIVE_ZERO, "token_b": cd.BUY,
        "amount_a_wei": 10**18, "amount_b_wei": 10**18,
        "liquidity": 10**15, "fee": 3000, "tick_spacing": 60,
        "hooks": cd.NATIVE_ZERO, "tick_lower": -600, "tick_upper": 600})

    class Rpc:
        def eth_call(self, to, data, sender):
            assert data == dex.build_posm_pool_manager_calldata()
            return "0x" + "00" * 12 + cd.ATTACKER[2:]

    with pytest.raises(EvmError, match="not the pinned"):
        d._execute_evm_lp_add_v4(intent, {"chain_id": 8453}, Rpc(),
                                 b"\x01" * 32, cd.WALLET, 1_900_000_000)

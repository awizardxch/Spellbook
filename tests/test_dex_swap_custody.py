"""S-20: swap transactions are decoded and bound to the intent before
signing — pinned target and spender, known selector, sell token and
amount, recipient = the wallet, minimum out, value. Calldata is hand-built
with eth_abi; nothing here touches a network, signs or broadcasts."""

import pytest

from spellbook import dex
from spellbook.dex import DexError, NATIVE_SENTINEL, validate_swap_intent_against_quote

import _dex_calldata as cd

UNLIMITED = 2**256 - 1


def _check(quote, **intent):
    return validate_swap_intent_against_quote(cd.swap_intent(**intent), quote)


# -- accepted --------------------------------------------------------------

def test_well_formed_token_sell_to_pinned_holder_is_accepted():
    plan = _check(cd.zerox_quote())
    d = plan["decoded"]
    assert plan["to"] == cd.HOLDER and d["target"] == cd.HOLDER
    assert d["target_role"] == "allowance_holder"
    assert d["selector"] == "0x2213bc0b"
    assert d["selector_name"].startswith("AllowanceHolder.exec")
    assert d["inner_selector"] == "0x1fff991f"
    assert d["recipient"] == cd.WALLET
    assert d["sell_token"] == cd.SELL and d["sell_amount_wei"] == cd.SELL_AMOUNT
    assert d["buy_token"] == cd.BUY and d["min_buy_amount_wei"] == cd.MIN_BUY
    assert d["settler"] == cd.SETTLER
    assert plan["allowance_target"] == cd.HOLDER
    assert plan["approve_amount_wei"] == cd.SELL_AMOUNT


def test_well_formed_native_sell_is_accepted():
    q = cd.zerox_quote(cd.ah_exec(token=NATIVE_SENTINEL), sell=NATIVE_SENTINEL,
                       value=str(cd.SELL_AMOUNT), spender=None)
    plan = _check(q, sell_token=NATIVE_SENTINEL)
    assert plan["value_wei"] == cd.SELL_AMOUNT
    assert plan["needs_approval"] is False and plan["approve_amount_wei"] == 0
    assert plan["decoded"]["recipient"] == cd.WALLET


def test_cast_venue_uses_the_same_pinned_holder():
    plan = _check(cd.zerox_quote(venue="cast"), venue="cast")
    assert plan["decoded"]["venue"] == "cast"


# -- refused: target / spender / approval --------------------------------

def test_to_off_list_is_refused():
    with pytest.raises(DexError, match="not the pinned allowance_holder"):
        _check(cd.zerox_quote(to=cd.ATTACKER))


def test_to_a_token_with_transfer_calldata_is_refused():
    transfer = ("0xa9059cbb" + "00" * 12 + cd.ATTACKER[2:]
                + (10**30).to_bytes(32, "big").hex())
    with pytest.raises(DexError, match="not the pinned"):
        _check(cd.zerox_quote(transfer, to=cd.SELL))


def test_spender_off_list_is_refused():
    with pytest.raises(DexError, match="spender .* is not the pinned"):
        _check(cd.zerox_quote(spender=cd.ATTACKER))


def test_unlimited_exec_allowance_is_refused():
    with pytest.raises(DexError, match="exec amount"):
        _check(cd.zerox_quote(cd.ah_exec(amount=UNLIMITED)))


def test_unlimited_approve_is_refused():
    with pytest.raises(DexError, match="exceeds the sell amount"):
        dex.check_swap_approval(
            chain_id=cd.CHAIN, venue="matcha", token=cd.SELL,
            spender=cd.HOLDER, amount=UNLIMITED, sell_token=cd.SELL,
            sell_amount=cd.SELL_AMOUNT)


def test_approve_to_another_spender_is_refused():
    with pytest.raises(DexError, match="not the pinned"):
        dex.check_swap_approval(
            chain_id=cd.CHAIN, venue="matcha", token=cd.SELL,
            spender=cd.ATTACKER, amount=cd.SELL_AMOUNT, sell_token=cd.SELL,
            sell_amount=cd.SELL_AMOUNT)


def test_exact_approve_is_accepted():
    dex.check_swap_approval(
        chain_id=cd.CHAIN, venue="cast", token=cd.SELL, spender=cd.HOLDER,
        amount=cd.SELL_AMOUNT, sell_token=cd.SELL, sell_amount=cd.SELL_AMOUNT)


# -- refused: decoded fields ------------------------------------------------

def test_wrong_recipient_is_refused():
    inner = cd.settler_execute(recipient=cd.ATTACKER)
    with pytest.raises(DexError, match="recipient .* is not this wallet"):
        _check(cd.zerox_quote(cd.ah_exec(inner=inner)))


def test_sell_amount_larger_than_intent_is_refused():
    with pytest.raises(DexError, match="exec amount"):
        _check(cd.zerox_quote(cd.ah_exec(amount=cd.SELL_AMOUNT + 1)))


def test_other_sell_token_is_refused():
    with pytest.raises(DexError, match="exec sells token"):
        _check(cd.zerox_quote(cd.ah_exec(token=cd.ATTACKER)))


def test_min_buy_lower_than_intent_is_refused():
    inner = cd.settler_execute(min_out=cd.MIN_BUY - 1)
    with pytest.raises(DexError, match="minimum out"):
        _check(cd.zerox_quote(cd.ah_exec(inner=inner)))


def test_other_buy_token_is_refused():
    inner = cd.settler_execute(buy=cd.ATTACKER)
    with pytest.raises(DexError, match="swap buys"):
        _check(cd.zerox_quote(cd.ah_exec(inner=inner)))


def test_unknown_selector_is_refused():
    data = cd.ah_exec(selector="a9059cbb")
    with pytest.raises(DexError, match="selector 0xa9059cbb is not a known"):
        _check(cd.zerox_quote(data))


def test_unknown_inner_selector_is_refused():
    inner = bytes.fromhex("deadbeef") + cd.settler_execute()[4:]
    with pytest.raises(DexError, match="0xdeadbeef .* cannot decode"):
        _check(cd.zerox_quote(cd.ah_exec(inner=inner)))


def test_undecodable_calldata_is_refused():
    with pytest.raises(DexError, match="AllowanceHolder.exec: calldata does "
                                       "not decode"):
        _check(cd.zerox_quote("0x2213bc0b" + "00" * 40))


def test_nonzero_value_on_erc20_sell_is_refused():
    # Checked by the decoder itself (it binds value to the decoded call),
    # not only by the quote-level validation that predates it.
    tx = {"to": cd.HOLDER, "data": cd.ah_exec(), "value": "1"}
    with pytest.raises(DexError, match="must be 0"):
        dex.decode_swap_tx(
            venue="matcha", chain_id=cd.CHAIN, tx=tx, wallet=cd.WALLET,
            sell_token=cd.SELL, buy_token=cd.BUY, sell_amount=cd.SELL_AMOUNT,
            min_buy=cd.MIN_BUY)
    with pytest.raises(DexError, match="must be 0"):
        _check(cd.zerox_quote(value="1"))


def test_native_sell_granting_a_token_is_refused():
    q = cd.zerox_quote(cd.ah_exec(token=cd.SELL), sell=NATIVE_SENTINEL,
                       value=str(cd.SELL_AMOUNT), spender=None)
    with pytest.raises(DexError, match="native sell, but exec grants"):
        _check(q, sell_token=NATIVE_SENTINEL)


def test_exec_target_that_is_a_token_is_refused():
    data = cd.ah_exec(operator=cd.BUY, target=cd.BUY)
    with pytest.raises(DexError, match="is a token"):
        _check(cd.zerox_quote(data))


def test_unpinned_chain_is_refused():
    q = cd.zerox_quote()
    q["chain_id"] = 1
    with pytest.raises(DexError, match="no pinned allowance_holder for chain 1"):
        _check(q, chain_id=1)


def test_base_uses_the_same_pinned_holder():
    q = cd.zerox_quote()
    q["chain_id"] = 8453
    plan = _check(q, chain_id=8453)
    assert plan["to"] == cd.HOLDER and plan["allowance_target"] == cd.HOLDER
    assert plan["decoded"]["target_source"].startswith("0x-settler README")


# -- Universal Router (operator pin) --------------------------------------

UR_PINS = {cd.CHAIN: {"universal_router": cd.UR}}


def _ur_quote(data, value="0", sell=cd.SELL):
    return {"venue": "uniswap", "chain_id": cd.CHAIN, "sell_token": sell,
            "buy_token": cd.BUY, "sell_amount": str(cd.SELL_AMOUNT),
            "buy_amount": str(3100 * 10**6), "allowance_target": None,
            "tx": {"to": cd.UR, "data": data, "value": value}}


def _ur_check(data, value="0", sell=cd.SELL, pins=UR_PINS):
    intent = cd.swap_intent(venue="uniswap", sell_token=sell,
                            pin_overrides=pins)
    return validate_swap_intent_against_quote(intent,
                                              _ur_quote(data, value, sell))


def _ur_native(*cmds):
    return cd.ur_execute(bytes(c for c, _ in cmds), [i for _, i in cmds],
                         deadline=1_900_000_000)


def test_uniswap_router_off_the_pin_list_is_refused():
    # Without the operator pin, cd.UR is not one of the built-in routers.
    data = _ur_native((0x0B, cd.ur_wrap()), (0x00, cd.ur_v3_in(payer_user=False)))
    with pytest.raises(DexError, match="not the pinned universal_router"):
        _ur_check(data, str(cd.SELL_AMOUNT), NATIVE_SENTINEL, pins=None)


def test_uniswap_is_refused_on_a_chain_without_a_pinned_router():
    data = _ur_native((0x0B, cd.ur_wrap()), (0x00, cd.ur_v3_in(payer_user=False)))
    q = _ur_quote(data, str(cd.SELL_AMOUNT), NATIVE_SENTINEL)
    q["chain_id"] = 1
    with pytest.raises(DexError, match="no pinned universal_router for chain 1"):
        validate_swap_intent_against_quote(cd.swap_intent(
            venue="uniswap", sell_token=NATIVE_SENTINEL, chain_id=1), q)


def test_universal_router_native_sell_is_accepted_with_a_pin():
    data = _ur_native((0x0B, cd.ur_wrap()), (0x00, cd.ur_v3_in(payer_user=False)))
    plan = _ur_check(data, str(cd.SELL_AMOUNT), NATIVE_SENTINEL)
    d = plan["decoded"]
    assert d["selector"] == "0x3593564c"
    assert d["commands"] == ["WRAP_ETH", "V3_SWAP_EXACT_IN"]
    assert d["recipient"] == cd.WALLET
    assert d["target_source"].startswith("operator override")


def test_universal_router_token_sell_with_sweep_decodes():
    # Decoder only: a Uniswap token sell still has no approval path (the
    # Trading API names no spender), so the full validation refuses it.
    data = cd.ur_execute(bytes([0x00, 0x04]), [
        cd.ur_v3_in(recipient=cd.UR_ADDRESS_THIS), cd.ur_sweep()])
    d = dex.decode_swap_tx(
        venue="uniswap", chain_id=cd.CHAIN,
        tx={"to": cd.UR, "data": data, "value": "0"}, wallet=cd.WALLET,
        sell_token=cd.SELL, buy_token=cd.BUY, sell_amount=cd.SELL_AMOUNT,
        min_buy=cd.MIN_BUY, pin_overrides=UR_PINS)
    assert d["min_buy_amount_wei"] == cd.MIN_BUY
    assert d["commands"] == ["V3_SWAP_EXACT_IN", "SWEEP"]


def test_universal_router_wrong_recipient_is_refused():
    data = _ur_native((0x0B, cd.ur_wrap()),
                      (0x00, cd.ur_v3_in(recipient=cd.ATTACKER, payer_user=False)))
    with pytest.raises(DexError, match="not this wallet"):
        _ur_check(data, str(cd.SELL_AMOUNT), NATIVE_SENTINEL)


def test_universal_router_min_buy_lower_is_refused():
    data = cd.ur_execute(bytes([0x00]), [cd.ur_v3_in(amount_min=cd.MIN_BUY - 1)])
    with pytest.raises(DexError, match="guaranteed out"):
        _ur_check(data)


def test_universal_router_sell_amount_larger_is_refused():
    data = cd.ur_execute(bytes([0x00]), [cd.ur_v3_in(amount_in=cd.SELL_AMOUNT + 1)])
    with pytest.raises(DexError, match="pulls"):
        _ur_check(data)


@pytest.mark.parametrize("cmd,name", [(0x05, "TRANSFER"), (0x06, "PAY_PORTION"),
                                      (0x0A, "PERMIT2_PERMIT"),
                                      (0x01, "V3_SWAP_EXACT_OUT")])
def test_universal_router_unbounded_commands_are_refused(cmd, name):
    data = cd.ur_execute(bytes([0x00, cmd]),
                         [cd.ur_v3_in(), cd.ur_sweep(recipient=cd.ATTACKER)])
    with pytest.raises(DexError, match=f"command {name} cannot be bounded"):
        _ur_check(data)


# -- daemon: request time, overrides, execution ---------------------------

def test_request_for_unpinned_chain_is_refused(tmp_path):
    from spellbook.evm import EvmError
    from test_dex import _daemon, _swap_params
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="no pinned allowance_holder for chain 1"):
        d._validate_dex_swap(_swap_params(chain="evm-1"))


def test_request_on_base_is_accepted(tmp_path):
    from test_dex import _daemon, _swap_params
    d = _daemon(tmp_path)
    for venue in ("matcha", "cast"):
        intent = d._validate_dex_swap(_swap_params(chain="evm-8453",
                                                   venue=venue))
        assert intent["chain_id"] == 8453


def test_operator_override_pins_a_chain_and_is_logged(tmp_path, monkeypatch, capsys):
    from test_dex import _base_chain, _daemon, _swap_params
    _base_chain(monkeypatch)
    d = _daemon(tmp_path, {"pinned_contracts": {"8453": {
        "allowance_holder": cd.HOLDER}}})
    assert "OPERATOR OVERRIDE" in capsys.readouterr().err
    assert d._validate_dex_swap(_swap_params(chain="evm-8453"))["chain_id"] == 8453
    pins = d.rt_dex_venues({}, "m")["pinned_contracts"]
    assert pins["8453"]["allowance_holder"]["source"].startswith("operator override")
    assert pins["4663"]["allowance_holder"]["address"] == cd.HOLDER


@pytest.mark.parametrize("bad", [
    {"8453": {"router_of_my_choice": cd.HOLDER}},
    {"8453": {"allowance_holder": "0x1234"}},
    {"base": {"allowance_holder": cd.HOLDER}},
    ["allowance_holder"],
])
def test_bad_override_refuses_to_start(tmp_path, bad):
    from test_dex import _daemon
    with pytest.raises(ValueError, match="dex.pinned_contracts"):
        _daemon(tmp_path, {"pinned_contracts": bad})


def test_queue_entry_shows_the_swap_checks(tmp_path):
    from test_dex import _daemon, _swap_params
    d = _daemon(tmp_path)
    d.queue["1"] = {"params": _swap_params(), "muse_id": "m", "queued_at": 0}
    entry = d._decoded_queue()[0]
    checks = entry["swap_checks"]
    assert checks["target"] == cd.HOLDER and checks["spender"] == cd.HOLDER
    assert checks["target_role"] == "allowance_holder"
    assert checks["refused"] is None
    assert any("AllowanceHolder.exec" in s for s in checks["selectors"])


def test_execution_refuses_a_hostile_quote_before_the_chain(monkeypatch):
    """A venue answer that pays someone else never reaches the nonce."""
    from spellbook import daemon as daemon_mod

    inner = cd.settler_execute(recipient=cd.ATTACKER)

    def quote(self, *a, **kw):
        return dex._norm_quote(
            venue="matcha", chain_id=cd.CHAIN, sell_token=cd.SELL,
            buy_token=cd.BUY, sell_amount=cd.SELL_AMOUNT,
            buy_amount=3100 * 10**6, min_buy_amount=None,
            price_impact_bps=None, gas_estimate=None,
            tx={"to": cd.HOLDER, "data": cd.ah_exec(inner=inner), "value": "0"},
            allowance_target=cd.HOLDER, raw={})

    monkeypatch.setattr(dex.ZeroExClient, "quote", quote)

    class Rpc:
        def nonce(self, _):
            raise AssertionError("must refuse before touching the chain")

    fake = type("D", (), {})()
    fake._evm_dex_guards = lambda params: (
        {"chain_id": cd.CHAIN}, Rpc(), b"\x01" * 32, cd.WALLET)
    with pytest.raises(DexError, match="not this wallet"):
        daemon_mod.Daemon._execute_evm_swap(fake, {
            "venue": "matcha", "sell_token": cd.SELL, "buy_token": cd.BUY,
            "sell_amount_wei": cd.SELL_AMOUNT,
            "min_buy_amount_wei": cd.MIN_BUY, "max_slippage_bps": 50,
            "deadline_sec": None})

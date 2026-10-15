"""S-21: an LP add's native leg is one policy key ("native") for policy
and velocity alike; the router, PositionManager and Permit2 come from the
pin table, never the agent's params; the v4 mint is decoded so both legs
are bounded by their caps and the position goes to the wallet. Nothing
here touches a network, signs or broadcasts."""

import pytest

from spellbook import dex
from spellbook.dex import DexError
from spellbook.evm import EvmError

from test_dex import _daemon

CHAIN = "evm-4663"
POSM = "0x58daec3116aae6d93017baaea7749052e8a04fa7"     # pinned for 4663
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"  # pinned for 4663
NATIVE = "0x0000000000000000000000000000000000000000"
TOKEN = "0x2222222222222222222222222222222222222222"
ATTACKER = "0x9999999999999999999999999999999999999999"
WALLET = "0xc63fd4d246967347e9e9db12f748103c093ce463"


def _v4_native_add(**over):
    p = {"intent": "dex_lp_add", "chain": CHAIN, "protocol": "v4",
         "token_a": NATIVE, "token_b": TOKEN,
         "amount_a_wei": 10**18, "amount_b_wei": 5 * 10**18,
         "liquidity": 10**15, "fee": 3000, "tick_spacing": 60,
         "hooks": NATIVE, "tick_lower": -600, "tick_upper": 600,
         "purpose": "test"}
    p.update(over)
    return p


# -- one key for policy and velocity ----------------------------------------

def test_native_leg_counts_under_native_for_velocity(tmp_path):
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_add(_v4_native_add())
    assert d._velocity_entries(intent) == [
        (CHAIN, "native", 10**18), (CHAIN, TOKEN, 5 * 10**18)]
    d._record_velocity_entries(intent)
    assert d.spent_last_24h(CHAIN, "native") == 10**18


def test_policy_and_velocity_use_the_same_keys(tmp_path):
    d = _daemon(tmp_path)
    seen = {}

    def capture(intent, muse_id, entries, kind, **kw):
        seen["policy"] = [(c, a, m) for c, a, m in entries]
        seen["intent"] = intent
        return {"ok": True}

    d._run_fund_intent = capture
    d.rt_dex_lp_add(_v4_native_add(), "muse-test")
    assert seen["policy"] == d._velocity_entries(seen["intent"])
    assert seen["policy"][0][1] == "native"


@pytest.mark.parametrize("sell", [
    NATIVE, dex.NATIVE_SENTINEL.upper().replace("0X", "0x"),
])
def test_swap_native_sell_is_one_key(tmp_path, sell):
    d = _daemon(tmp_path)
    seen = {}

    def capture(intent, muse_id, entries, kind, **kw):
        seen["policy"], seen["intent"] = entries, intent
        return {"ok": True}

    d._run_fund_intent = capture
    d.rt_dex_swap({"intent": "dex_swap", "chain": CHAIN, "venue": "cast",
                   "sell_token": sell, "buy_token": TOKEN,
                   "sell_amount_wei": 7, "min_buy_amount_wei": 1,
                   "max_slippage_bps": 50}, "muse-test")
    assert seen["policy"] == [(CHAIN, "native", 7)]
    assert d._velocity_entries(seen["intent"]) == [(CHAIN, "native", 7)]


# -- contracts from the pin table, never from params -------------------------

def test_position_manager_and_permit2_come_from_the_pin_table(tmp_path):
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_add(_v4_native_add())
    assert intent["position_manager"] == POSM
    assert intent["permit2"] == PERMIT2


def test_pinned_values_supplied_explicitly_are_accepted(tmp_path):
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_add(_v4_native_add(
        position_manager=POSM.upper().replace("0X", "0x"), permit2=PERMIT2))
    assert intent["position_manager"] == POSM


def test_position_manager_from_params_is_refused(tmp_path):
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="not the pinned v4_position_manager"):
        d._validate_dex_lp_add(_v4_native_add(position_manager=ATTACKER))


def test_permit2_from_params_is_refused(tmp_path):
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="not the pinned permit2"):
        d._validate_dex_lp_add(_v4_native_add(permit2=ATTACKER))


def test_unpinned_chain_lp_add_is_refused(tmp_path):
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="no pinned v4_position_manager for "
                                       "chain 1"):
        d._validate_dex_lp_add(_v4_native_add(chain="evm-1"))


def _v2_add(**over):
    p = {"intent": "dex_lp_add", "chain": CHAIN, "protocol": "v2",
         "token_a": TOKEN, "token_b": ATTACKER,
         "amount_a_wei": 1, "amount_b_wei": 1, "amount_a_min_wei": 0,
         "amount_b_min_wei": 0}
    p.update(over)
    return p


def test_v2_router_is_refused_without_a_pin(tmp_path):
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="no pinned v2_router"):
        d._validate_dex_lp_add(_v2_add(chain="evm-1"))


def test_v2_router_from_params_is_refused(tmp_path):
    d = _daemon(tmp_path)
    with pytest.raises(EvmError, match="not the pinned v2_router"):
        d._validate_dex_lp_add(_v2_add(router=ATTACKER))


def test_remove_and_claim_position_manager_from_params_is_refused(tmp_path):
    d = _daemon(tmp_path)
    base = {"chain": CHAIN, "protocol": "v4", "position_manager": ATTACKER,
            "token_a": NATIVE, "token_b": TOKEN, "token_id": 7}
    with pytest.raises(EvmError, match="not the pinned"):
        d._validate_dex_lp_remove({**base, "intent": "dex_lp_remove",
                                   "liquidity": 1, "amount_a_min_wei": 0,
                                   "amount_b_min_wei": 0})
    with pytest.raises(EvmError, match="not the pinned"):
        d._validate_dex_lp_claim({**base, "intent": "dex_lp_claim"})


def test_tampered_queue_entry_is_refused_at_execution(tmp_path):
    """A queued v4 add whose position manager is not the pin never reaches
    the chain: execution re-resolves the pin before any RPC."""
    d = _daemon(tmp_path)
    params = {**_v4_native_add(), "position_manager": ATTACKER,
              "permit2": PERMIT2}

    class Rpc:
        def __getattr__(self, name):
            raise AssertionError("must refuse before touching the chain")

    with pytest.raises(EvmError, match="not the pinned"):
        d._execute_evm_lp_add_v4(params, {"chain_id": 4663}, Rpc(),
                                 b"\x01" * 32, WALLET, 1_900_000_000)


# -- v4 mint decoded and bounded ---------------------------------------------

def _mint(owner=WALLET, a0=10**18, a1=5 * 10**18):
    return dex.build_v4_lp_add_calldata(
        NATIVE, TOKEN, 3000, 60, NATIVE, -600, 600, 10**15, a0, a1, owner,
        1_900_000_000, allow_native=True)


def _decode(data, value=10**18, cap0=10**18, cap1=5 * 10**18):
    return dex.decode_v4_lp_add_calldata(
        data, value_wei=value, currency0=NATIVE, currency1=TOKEN,
        amount0_cap=cap0, amount1_cap=cap1, wallet=WALLET)


def test_well_formed_v4_mint_decodes():
    d = _decode(_mint())
    assert d["recipient"] == WALLET
    assert d["amount0_max_wei"] == 10**18 and d["amount1_max_wei"] == 5 * 10**18
    assert d["actions"] == ["MINT_POSITION", "SETTLE_PAIR"]
    assert d["selector_name"].startswith("PositionManager.modifyLiquidities")


def test_v4_mint_recipient_not_the_wallet_is_refused():
    with pytest.raises(DexError, match="recipient .* is not this wallet"):
        _decode(_mint(owner=ATTACKER))


def test_v4_mint_token_leg_over_cap_is_refused():
    with pytest.raises(DexError, match="exceeds the approved cap"):
        _decode(_mint(a1=5 * 10**18 + 1))


def test_v4_mint_native_value_over_cap_is_refused():
    with pytest.raises(DexError, match="native value"):
        _decode(_mint(), value=10**18 + 1)


def test_v4_mint_other_pool_is_refused():
    other = dex.build_v4_lp_add_calldata(
        NATIVE, ATTACKER, 3000, 60, NATIVE, -600, 600, 10**15, 1, 1, WALLET,
        1_900_000_000, allow_native=True)
    with pytest.raises(DexError, match="currencies differ"):
        _decode(other)


def test_v4_other_actions_are_refused():
    data = dex.build_v4_lp_claim_calldata(7, NATIVE, TOKEN, ATTACKER,
                                          1_900_000_000, allow_native=True)
    with pytest.raises(DexError, match="are not \\[MINT_POSITION"):
        _decode(data)


# -- what the human sees -------------------------------------------------------

def test_queue_entry_shows_the_lp_checks(tmp_path):
    d = _daemon(tmp_path)
    intent = d._validate_dex_lp_add(_v4_native_add())
    d.queue["1"] = {"params": intent, "muse_id": "m", "queued_at": 0}
    checks = d._decoded_queue()[0]["lp_checks"]
    assert checks["contracts"]["v4_position_manager"]["address"] == POSM
    assert checks["contracts"]["permit2"]["address"] == PERMIT2
    assert checks["contracts"]["v4_position_manager"]["source"] == (
        "uniswap deployments.json a677c0d (2026-09-22): PositionManager")
    assert checks["legs"][0] == {"token": NATIVE, "policy_key": "native",
                                 "max_wei": 10**18}
    assert checks["refused"] is None

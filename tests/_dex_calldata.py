"""Hand-built venue calldata for the DEX custody tests (S-20/S-21).

Encoded with eth_abi (an independent encoder, test-only), never with the
daemon's own builders, so the decoder is checked against a second
implementation of the ABI.
"""

from eth_abi import encode

CHAIN = 4663
#: The built-in pin for 4663 (dex.PINNED_CONTRACTS), spelled out so these
#: helpers import on code that predates the table.
HOLDER = "0x0000000000001ff3684f28c67538d4d072c22734"
UR_ADDRESS_THIS = "0x0000000000000000000000000000000000000002"
WALLET = "0xc63fd4d246967347e9e9db12f748103c093ce463"
SETTLER = "0x7777777777777777777777777777777777777777"
ATTACKER = "0x9999999999999999999999999999999999999999"
SELL = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
BUY = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
UR = "0x6666666666666666666666666666666666666666"
SELL_AMOUNT = 10**18
MIN_BUY = 3000 * 10**6


def settler_execute(recipient=WALLET, buy=BUY, min_out=MIN_BUY) -> bytes:
    return bytes.fromhex("1fff991f") + encode(
        ["(address,address,uint256)", "bytes[]", "bytes32"],
        [(recipient, buy, min_out), [b"\x01\x02\x03"], b"\x00" * 32])


def ah_exec(token=SELL, amount=SELL_AMOUNT, operator=SETTLER, target=SETTLER,
            inner=None, selector="2213bc0b") -> str:
    inner = settler_execute() if inner is None else inner
    return "0x" + selector + encode(
        ["address", "address", "uint256", "address", "bytes"],
        [operator, token, amount, target, inner]).hex()


def ur_execute(commands: bytes, inputs: list, deadline=None) -> str:
    if deadline is None:
        return "0x24856bc3" + encode(["bytes", "bytes[]"],
                                     [commands, inputs]).hex()
    return "0x3593564c" + encode(["bytes", "bytes[]", "uint256"],
                                 [commands, inputs, deadline]).hex()


def ur_wrap(recipient=UR_ADDRESS_THIS, amount=SELL_AMOUNT) -> bytes:
    return encode(["address", "uint256"], [recipient, amount])


def ur_v3_in(recipient=WALLET, amount_in=SELL_AMOUNT, amount_min=MIN_BUY,
             token_in=SELL, token_out=BUY, payer_user=True) -> bytes:
    path = (bytes.fromhex(token_in[2:]) + (3000).to_bytes(3, "big")
            + bytes.fromhex(token_out[2:]))
    return encode(["address", "uint256", "uint256", "bytes", "bool"],
                  [recipient, amount_in, amount_min, path, payer_user])


def ur_sweep(token=BUY, recipient=WALLET, amount=MIN_BUY) -> bytes:
    return encode(["address", "address", "uint256"], [token, recipient, amount])


def zerox_quote(data=None, *, to=HOLDER, value="0", sell=SELL, buy=BUY,
                spender=HOLDER, venue="matcha", buy_amount=3100 * 10**6):
    return {"venue": venue, "chain_id": CHAIN, "sell_token": sell,
            "buy_token": buy, "sell_amount": str(SELL_AMOUNT),
            "buy_amount": str(buy_amount), "allowance_target": spender,
            "tx": {"to": to, "data": ah_exec() if data is None else data,
                   "value": value}}


def swap_intent(**kw):
    base = {"chain_id": CHAIN, "venue": "matcha", "wallet": WALLET,
            "sell_token": SELL, "buy_token": BUY,
            "sell_amount_wei": SELL_AMOUNT, "min_buy_amount_wei": MIN_BUY,
            "max_slippage_bps": 50}
    base.update(kw)
    return base


# -- built-in pins (dex.PINNED_CONTRACTS), spelled out ----------------------

PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
UR_4663 = "0x06afba43fd06227fa663b0daecf536f6eaa6bf99"
UR_4663_V212 = "0x204faca1764b154221e35c0d20abb3c525710498"
UR_8453 = "0x6ff5693b99212da76ad316178a184ab56d299b43"
UR_8453_V212 = "0xd6145b2d3f379919e8cdeda7b97e37c4b2ca9c40"
#: Base's UniversalRouter#v1.2: in the feed, deliberately not pinned.
UR_8453_V12 = "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad"
UR_MSG_SENDER = "0x0000000000000000000000000000000000000001"
NATIVE_ZERO = "0x0000000000000000000000000000000000000000"


def ur_v2_in(recipient=WALLET, amount_in=SELL_AMOUNT, amount_min=MIN_BUY,
             path=(SELL, BUY), payer_user=True) -> bytes:
    return encode(["address", "uint256", "uint256", "address[]", "bool"],
                  [recipient, amount_in, amount_min, list(path), payer_user])


# -- Universal Router V4_SWAP (v4-periphery V4Router params) ----------------

def v4_exact_in_single(c0, c1, zero_for_one, amount_in=SELL_AMOUNT,
                       min_out=MIN_BUY, fee=3000, tick_spacing=60,
                       hooks=NATIVE_ZERO, hook_data=b"") -> bytes:
    return encode(
        ["((address,address,uint24,int24,address),bool,uint128,uint128,bytes)"],
        [((c0, c1, fee, tick_spacing, hooks), zero_for_one, amount_in,
          min_out, hook_data)])


def v4_exact_in(currency_in, hops, amount_in=SELL_AMOUNT,
                min_out=MIN_BUY) -> bytes:
    """hops: [intermediateCurrency, ...] (fee 3000, spacing 60, no hooks)."""
    path = [(c, 3000, 60, NATIVE_ZERO, b"") for c in hops]
    return encode(["(address,(address,uint24,int24,address,bytes)[],"
                   "uint128,uint128)"],
                  [(currency_in, path, amount_in, min_out)])


def v4_settle(currency, amount=0, payer_user=True) -> bytes:
    return encode(["address", "uint256", "bool"], [currency, amount, payer_user])


def v4_settle_all(currency, max_amount=SELL_AMOUNT) -> bytes:
    return encode(["address", "uint256"], [currency, max_amount])


def v4_take(currency, recipient=UR_MSG_SENDER, amount=0) -> bytes:
    return encode(["address", "address", "uint256"],
                  [currency, recipient, amount])


def v4_take_all(currency, min_amount=MIN_BUY) -> bytes:
    return encode(["address", "uint256"], [currency, min_amount])


def ur_v4_swap(actions: bytes, params: list) -> bytes:
    return encode(["bytes", "bytes[]"], [actions, params])


# -- LP calldata (v2 Router02, v3 NonfungiblePositionManager, v4 POSM) ------

def v2_add(token_a=SELL, token_b=BUY, a=10**18, b=2 * 10**18, a_min=0,
           b_min=0, to=WALLET, deadline=1_900_000_000) -> str:
    return "0xe8e33700" + encode(
        ["address", "address", "uint256", "uint256", "uint256", "uint256",
         "address", "uint256"],
        [token_a, token_b, a, b, a_min, b_min, to, deadline]).hex()


def v2_remove(token_a=SELL, token_b=BUY, liquidity=10**15, a_min=1, b_min=2,
              to=WALLET, deadline=1_900_000_000) -> str:
    return "0xbaa2abde" + encode(
        ["address", "address", "uint256", "uint256", "uint256", "address",
         "uint256"],
        [token_a, token_b, liquidity, a_min, b_min, to, deadline]).hex()


def v3_mint(t0=SELL, t1=BUY, fee=3000, tl=-600, tu=600, a0=10**18,
            a1=2 * 10**18, m0=0, m1=0, recipient=WALLET,
            deadline=1_900_000_000) -> str:
    return "0x88316456" + encode(
        ["(address,address,uint24,int24,int24,uint256,uint256,uint256,"
         "uint256,address,uint256)"],
        [(t0, t1, fee, tl, tu, a0, a1, m0, m1, recipient, deadline)]).hex()


def v3_decrease(token_id=7, liquidity=10**15, m0=1, m1=2,
                deadline=1_900_000_000) -> bytes:
    return bytes.fromhex("0c49ccbe") + encode(
        ["(uint256,uint128,uint256,uint256,uint256)"],
        [(token_id, liquidity, m0, m1, deadline)])


def v3_collect(token_id=7, recipient=WALLET) -> bytes:
    return bytes.fromhex("fc6f7865") + encode(
        ["(uint256,address,uint128,uint128)"],
        [(token_id, recipient, 2**128 - 1, 2**128 - 1)])


def v3_multicall(calls: list) -> str:
    return "0xac9650d8" + encode(["bytes[]"], [calls]).hex()


def v4_modify(actions: bytes, params: list, deadline=1_900_000_000) -> str:
    unlock = encode(["bytes", "bytes[]"], [actions, params])
    return "0xdd46508f" + encode(["bytes", "uint256"], [unlock, deadline]).hex()


def v4_decrease(token_id=7, liquidity=10**15, m0=1, m1=2) -> bytes:
    return encode(["uint256", "uint256", "uint128", "uint128", "bytes"],
                  [token_id, liquidity, m0, m1, b""])


def v4_take_pair(c0=NATIVE_ZERO, c1=BUY, recipient=WALLET) -> bytes:
    return encode(["address", "address", "address"], [c0, c1, recipient])


def v4_burn(token_id=7) -> bytes:
    return encode(["uint256", "uint128", "uint128", "bytes"],
                  [token_id, 0, 0, b""])

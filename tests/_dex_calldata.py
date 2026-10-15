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

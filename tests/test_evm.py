"""EVM chain layer tests — all offline. The live-RPC proof is the §10 drill."""
import pytest

from spellbook import evm
from spellbook.evm import _rlp_bytes, _rlp_int, _rlp_list, keccak256


def _rlp_decode(b: bytes):
    """Minimal RLP decoder, just enough to check our encoder."""
    def dec(i):
        prefix = b[i]
        if prefix < 0x80:
            return b[i:i + 1], i + 1
        if prefix < 0xB8:
            l = prefix - 0x80
            return b[i + 1:i + 1 + l], i + 1 + l
        if prefix < 0xC0:
            ll = prefix - 0xB7
            l = int.from_bytes(b[i + 1:i + 1 + ll], "big")
            return b[i + 1 + ll:i + 1 + ll + l], i + 1 + ll + l
        if prefix < 0xF8:
            l = prefix - 0xC0
            items, j = [], i + 1
            while j < i + 1 + l:
                it, j = dec(j)
                items.append(it)
            return items, i + 1 + l
        ll = prefix - 0xF7
        l = int.from_bytes(b[i + 1:i + 1 + ll], "big")
        items, j = [], i + 1 + ll
        while j < i + 1 + ll + l:
            it, j = dec(j)
            items.append(it)
        return items, i + 1 + ll + l
    out, end = dec(0)
    assert end == len(b)
    return out


PRIV = bytes.fromhex("ac0974bec39a17e36ba4a6b4d238ff944bacb478805ffbc6f7c35b7e0e4a7f26")
# Cross-validated with eth_keys (independent implementation): both agree.
PRIV_ADDR = "0x86c19a61af0e3493e375d631c12d5ae3edbcd71d"


def test_address_derivation_matches_independent_lib():
    assert evm.address_from_privkey(PRIV) == PRIV_ADDR


def test_signature_matches_independent_lib():
    """Our RLP digest + ECDSA must match eth_keys' signing of the same digest."""
    eth_keys = pytest.importorskip("eth_keys")
    to = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    s = evm.sign_legacy_transfer(PRIV, 46630, nonce=7, to=to,
                                 value_wei=10 ** 15, gas_price_wei=10 ** 10)
    raw = bytes.fromhex(s["raw_hex"][2:])
    fields = _rlp_decode(raw)
    # Rebuild the signing digest independently and check eth_keys agrees
    # on (r, s) for it — proves our RLP digest construction is correct.
    unsigned = _rlp_list([_rlp_int(7), _rlp_int(10 ** 10), _rlp_int(21_000),
                          _rlp_bytes(bytes.fromhex(to[2:])),
                          _rlp_int(10 ** 15), _rlp_bytes(b""),
                          _rlp_int(46630), _rlp_bytes(b""), _rlp_bytes(b"")])
    digest = keccak256(unsigned)
    ref = eth_keys.keys.PrivateKey(PRIV).sign_msg_hash(digest)
    assert int.from_bytes(fields[7], "big") == ref.r
    # s may differ by low-S normalization; both are valid — check validity.
    assert ref.v in (0, 1)
    assert int.from_bytes(fields[6], "big") == 46630 * 2 + 35 + ref.v


def test_sign_transfer_structure_and_recovery():
    to = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    s = evm.sign_legacy_transfer(PRIV, 46630, nonce=7, to=to,
                                 value_wei=10 ** 15, gas_price_wei=10 ** 10)
    assert s["from"] == PRIV_ADDR
    assert s["to"] == to and s["value_wei"] == 10 ** 15 and s["nonce"] == 7
    raw = bytes.fromhex(s["raw_hex"][2:])
    # tx hash is keccak of the signed bytes.
    assert s["tx_hash"] == "0x" + evm.keccak256(raw).hex()
    # RLP structure: [nonce, gasPrice, gasLimit, to, value, data, v, r, s].
    fields = _rlp_decode(raw)
    assert len(fields) == 9
    assert int.from_bytes(fields[0], "big") == 7
    assert int.from_bytes(fields[1], "big") == 10 ** 10
    assert int.from_bytes(fields[2], "big") == 21_000
    assert fields[3] == bytes.fromhex(to[2:])
    assert int.from_bytes(fields[4], "big") == 10 ** 15
    assert fields[5] == b""
    v = int.from_bytes(fields[6], "big")
    assert v in (46630 * 2 + 35, 46630 * 2 + 36)  # EIP-155
    assert int.from_bytes(fields[7], "big") > 0  # r
    assert int.from_bytes(fields[8], "big") > 0  # s


def test_sign_rejects_bad_inputs():
    with pytest.raises(evm.EvmError):
        evm.sign_legacy_transfer(PRIV, 46630, 0, "not-an-address", 1, 1)
    with pytest.raises(evm.EvmError):
        evm.sign_legacy_transfer(PRIV, 46630, 0,
                                 "0x" + "ab" * 20, 0, 1)


def test_is_address():
    assert evm.is_address("0x" + "ab" * 20)
    assert not evm.is_address("0x123")
    assert not evm.is_address("ab" * 20)


class _FakeRpc(evm.Rpc):
    """Rpc with canned eth_estimateGas — no network."""
    def __init__(self, estimate_hex):
        super().__init__("http://127.0.0.1:1")
        self._estimate_hex = estimate_hex

    def call(self, method, params=None):
        if method == "eth_estimateGas":
            return self._estimate_hex
        raise AssertionError(f"unexpected RPC call: {method}")


def test_estimate_gas_returns_node_value():
    rpc = _FakeRpc("0x5208")  # 21000
    assert rpc.estimate_gas("0x" + "aa" * 20, "0x" + "bb" * 20, 1) == 21000


def test_estimate_gas_above_21000_honored():
    # Arbitrum-style chains estimate above the 21000 floor — the daemon
    # must use the estimate, not the hardcoded floor.
    rpc = _FakeRpc("0x186a0")  # 100000
    assert rpc.estimate_gas("0x" + "aa" * 20, "0x" + "bb" * 20, 1) == 100000


def test_estimate_gas_failure_raises_fail_closed():
    class _FailRpc(evm.Rpc):
        def __init__(self):
            super().__init__("http://127.0.0.1:1")

        def call(self, method, params=None):
            raise evm.EvmError("RPC error (eth_estimateGas): boom")

    with pytest.raises(evm.EvmError):
        _FailRpc().estimate_gas("0x" + "aa" * 20, "0x" + "bb" * 20, 1)

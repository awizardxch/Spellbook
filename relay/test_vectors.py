"""Known-good Streamable encodings for the relay codec.

These vectors pin the wire format.  The message-envelope vectors were
verified empirically against chia-blockchain 2.7.4's own
``Message.__bytes__``/``from_bytes``; the handshake vector is hand-computed
from the Streamable field rules and cross-checked against
``chia.protocols.shared_protocol.Handshake`` field order.

Run: ``python test_vectors.py`` (no pytest needed) or ``pytest test_vectors.py``.
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from streamable import (
    Coin, CoinSpend, CoinState, Handshake, Message, SpendBundle,
    StreamableError,
    clvm_program_length,
    coin_id, dec_bytes_var, dec_coin_state, dec_handshake, dec_message,
    dec_new_peak_wallet, dec_program, dec_respond_to_coin_updates,
    dec_respond_to_ph_updates,
    dec_str, dec_transaction_ack, dec_u16, dec_u32, dec_u64, dec_u8,
    enc_bool, enc_bytes_fixed, enc_bytes_var, enc_coin, enc_coin_spend,
    enc_coin_state, enc_handshake, enc_list, enc_message, enc_program, enc_str,
    enc_u8, enc_u16, enc_u32, enc_u64, enc_u128,
    enc_register_for_coin_updates, enc_register_for_ph_updates,
    enc_send_transaction, enc_spend_bundle, int_to_bytes,
    make_outbound_handshake, parse_spend_bundle, spend_bundle_txid,
    PINNED_CAPABILITIES,
    _Reader,
)

FAILURES = []


def check(name, actual, expected):
    if actual != expected:
        FAILURES.append(name)
        print(f"FAIL {name}\n  expected: {expected}\n  actual:   {actual}")
    else:
        print(f"ok   {name}")


def check_raises(name, fn):
    try:
        fn()
    except StreamableError:
        print(f"ok   {name} (raised)")
        return
    except Exception as e:  # noqa: BLE001
        FAILURES.append(name)
        print(f"FAIL {name}: wrong exception {type(e).__name__}: {e}")
        return
    FAILURES.append(name)
    print(f"FAIL {name}: did not raise")


# ---------------------------------------------------------------------------
# 1. Integer primitives (big-endian, fixed width)
# ---------------------------------------------------------------------------

def test_primitives():
    check("u8(0)", enc_u8(0).hex(), "00")
    check("u8(255)", enc_u8(255).hex(), "ff")
    check("u16(0x0102)", enc_u16(0x0102).hex(), "0102")
    check("u32(0x01020304)", enc_u32(0x01020304).hex(), "01020304")
    check("u64(1)", enc_u64(1).hex(), "0000000000000001")
    check("u64(max)", enc_u64(2**64 - 1).hex(), "ffffffffffffffff")
    check("u128(1)", enc_u128(1).hex(), "00000000000000000000000000000001")
    check("bool true", enc_bool(True).hex(), "01")
    check("bool false", enc_bool(False).hex(), "00")
    check_raises("u8(256) rejects", lambda: enc_u8(256))
    check_raises("u8(-1) rejects", lambda: enc_u8(-1))
    check_raises("u32(2**32) rejects", lambda: enc_u32(2**32))

    check("dec u16", dec_u16(_Reader(bytes.fromhex("0102"))), 0x0102)
    check("dec u32", dec_u32(_Reader(bytes.fromhex("01020304"))), 0x01020304)
    check("dec u64", dec_u64(_Reader(bytes.fromhex("0000000000000001"))), 1)
    check_raises("truncated u32", lambda: dec_u32(_Reader(b"\x01\x02")))


# ---------------------------------------------------------------------------
# 2. str / bytes / list / optional
# ---------------------------------------------------------------------------

def test_containers():
    # "testnet11" = 74 65 73 74 6e 65 74 31 31
    check("str testnet11", enc_str("testnet11").hex(), "00000009746573746e65743131")
    check("str empty", enc_str("").hex(), "00000000")
    check("dec str", dec_str(_Reader(bytes.fromhex("00000009746573746e65743131"))), "testnet11")

    check("bytes var", enc_bytes_var(b"\x01\x02").hex(), "000000020102")
    check("dec bytes var", dec_bytes_var(_Reader(bytes.fromhex("000000020102"))), b"\x01\x02")

    check("list[u8]", enc_list([1, 2], enc_u8).hex(), "000000020102")
    check("list empty", enc_list([], enc_u8).hex(), "00000000")

    # Optional[uint32]: 0x00 absent, 0x01 + value present
    check("optional none", (b"\x00").hex(), "00")
    check("optional some", (b"\x01" + enc_u32(5)).hex(), "0100000005")


# ---------------------------------------------------------------------------
# 3. int_to_bytes (minimal BE, used inside coin_id)
# ---------------------------------------------------------------------------

def test_int_to_bytes():
    check("int_to_bytes(0)", int_to_bytes(0).hex(), "")
    check("int_to_bytes(1)", int_to_bytes(1).hex(), "01")
    check("int_to_bytes(0x7f)", int_to_bytes(0x7f).hex(), "7f")
    check("int_to_bytes(0x80)", int_to_bytes(0x80).hex(), "0080")
    check("int_to_bytes(255)", int_to_bytes(255).hex(), "00ff")
    check("int_to_bytes(0x1234)", int_to_bytes(0x1234).hex(), "1234")
    check("int_to_bytes(1000)", int_to_bytes(1000).hex(), "03e8")
    check("int_to_bytes(2**63)", int_to_bytes(2**63).hex(), "008000000000000000")


# ---------------------------------------------------------------------------
# 4. coin_id — consensus coin name
# ---------------------------------------------------------------------------

def test_coin_id():
    parent = bytes.fromhex("aa" * 32)
    ph = bytes.fromhex("bb" * 32)
    # sha256(aa*32 || bb*32 || 0x03e8), computed independently with hashlib
    expected = hashlib.sha256(parent + ph + b"\x03\xe8").hexdigest()
    check("coin_id vector", coin_id(parent, ph, 1000).hex(), expected)
    check("coin_id pinned", coin_id(parent, ph, 1000).hex(),
          "305057db732d14a534fced00451a4122aa2a788211bf7dfc190bc9b25ccee035")
    check("coin_id zero amount", coin_id(parent, ph, 0).hex(),
          hashlib.sha256(parent + ph).hexdigest())
    c = Coin(parent, ph, 1000)
    check("Coin.coin_id()", c.coin_id().hex(), expected)


# ---------------------------------------------------------------------------
# 5. Message envelope — verified against chia-blockchain 2.7.4 wire bytes
# ---------------------------------------------------------------------------

def test_message_envelope():
    # Handshake-style: type=1, no id, data=b"ABC"
    # chia wire: 01 | 00 | 00000003 | 414243
    m = Message(1, None, b"ABC")
    check("message no-id", enc_message(m).hex(), "010000000003414243")

    # Request-style: type=70 (0x46), id=7, data=b"ABC"
    # chia wire: 46 | 01 | 0007 | 00000003 | 414243
    m2 = Message(70, 7, b"ABC")
    check("message with-id", enc_message(m2).hex(), "4601000700000003414243")

    d1 = dec_message(bytes.fromhex("010000000003414243"))
    check("decode no-id", (d1.msg_type, d1.id, d1.data), (1, None, b"ABC"))
    d2 = dec_message(bytes.fromhex("4601000700000003414243"))
    check("decode with-id", (d2.msg_type, d2.id, d2.data), (70, 7, b"ABC"))

    check_raises("message trailing byte", lambda: dec_message(bytes.fromhex("01000000000341424300")))
    check_raises("message truncated", lambda: dec_message(bytes.fromhex("0100000000034142")))
    check_raises("message bad id flag", lambda: dec_message(bytes.fromhex("01ff00000003414243")))


# ---------------------------------------------------------------------------
# 6. Handshake — hand-computed from Streamable field rules
# ---------------------------------------------------------------------------

EXPECTED_HANDSHAKE_HEX = (
    "00000009" "746573746e65743131"      # network_id "testnet11"
    "00000006" "302e302e3337"            # protocol_version "0.0.37"
    "00000005" "302e302e30"              # software_version "0.0.0"
    "0000"                              # server_port 0
    "06"                                # node_type Wallet (6)
    "00000003"                          # 3 capabilities
    "0001" "00000001" "31"               # (1, "1")
    "0002" "00000001" "31"               # (2, "1")
    "0003" "00000001" "31"               # (3, "1")
)


def test_handshake():
    h = make_outbound_handshake("testnet11")
    check("outbound handshake", enc_handshake(h).hex(), EXPECTED_HANDSHAKE_HEX)
    check("pinned caps", list(PINNED_CAPABILITIES), [(1, "1"), (2, "1"), (3, "1")])

    back = dec_handshake(bytes.fromhex(EXPECTED_HANDSHAKE_HEX))
    check("handshake round-trip", back, h)
    check("handshake network", back.network_id, "testnet11")
    check("handshake node type", back.node_type, 6)

    check_raises("handshake trailing", lambda: dec_handshake(bytes.fromhex(EXPECTED_HANDSHAKE_HEX + "00")))
    check_raises("handshake truncated", lambda: dec_handshake(bytes.fromhex(EXPECTED_HANDSHAKE_HEX[:-2])))


# ---------------------------------------------------------------------------
# 7. Coin / CoinState
# ---------------------------------------------------------------------------

def test_coin():
    parent = bytes.fromhex("aa" * 32)
    ph = bytes.fromhex("bb" * 32)
    c = Coin(parent, ph, 1000)
    check("coin encoding", enc_coin(c).hex(), "aa" * 32 + "bb" * 32 + "00000000000003e8")

    cs = CoinState(c, None, 4714900)
    # spent None -> 00 ; created 4714900 = 0x47F194 -> 01 0047f194
    check("coin state", enc_coin_state(cs).hex(),
          "aa" * 32 + "bb" * 32 + "00000000000003e8" + "00" + "01" + "0047f194")
    r = _Reader(enc_coin_state(cs))
    check("coin state round-trip", dec_coin_state(r), cs)
    check("coin state eof", r.eof(), True)

    cs2 = CoinState(c, 4714905, 4714900)
    check("coin state spent", dec_coin_state(_Reader(enc_coin_state(cs2))), cs2)


# ---------------------------------------------------------------------------
# 8. SpendBundle structural validation
# ---------------------------------------------------------------------------

def _sample_bundle_bytes() -> bytes:
    parent = bytes.fromhex("aa" * 32)
    ph = bytes.fromhex("bb" * 32)
    coin = enc_coin(Coin(parent, ph, 1000))
    # Programs use consensus framing: bare CLVM, NO uint32 length prefix
    # (chia's Program::parse reads via serialized_length_from_bytes).
    reveal = b"\xff\x01\x80"   # cons(0x01, nil)
    solution = b"\x80"         # nil
    sig = bytes.fromhex("cc" * 96)
    return enc_u32(1) + coin + reveal + solution + sig


def test_spend_bundle():
    raw = _sample_bundle_bytes()
    sb = parse_spend_bundle(raw)
    check("bundle spends", len(sb.coin_spends), 1)
    check("bundle amount", sb.coin_spends[0].coin.amount, 1000)
    check("bundle sig", sb.aggregated_signature.hex(), "cc" * 96)
    check("bundle re-encode", enc_spend_bundle(sb).hex(), raw.hex())

    txid = spend_bundle_txid(raw)
    check("bundle txid", txid.hex(), hashlib.sha256(raw).hexdigest())

    check_raises("bundle empty", lambda: parse_spend_bundle(b""))
    check_raises("bundle zero spends", lambda: parse_spend_bundle(enc_u32(0) + bytes(96)))
    check_raises("bundle truncated", lambda: parse_spend_bundle(raw[:-10]))
    check_raises("bundle trailing byte", lambda: parse_spend_bundle(raw + b"\x00"))
    check_raises("bundle short sig", lambda: parse_spend_bundle(raw[:-1]))
    check_raises("bundle garbage", lambda: parse_spend_bundle(b"\xff" * 200))

    # The old (pre-fix) layout length-prefixed programs; the canonical gate
    # must reject it fail-closed instead of forwarding it to peers.
    parent = bytes.fromhex("aa" * 32)
    ph = bytes.fromhex("bb" * 32)
    legacy = (enc_u32(1) + enc_coin(Coin(parent, ph, 1000))
              + enc_bytes_var(b"\xff\x01\x80") + enc_bytes_var(b"\x80")
              + bytes.fromhex("cc" * 96))
    check_raises("bundle legacy length-prefixed programs rejected",
                 lambda: parse_spend_bundle(legacy))


def test_clvm_program_framing():
    # single-byte atoms / nil
    check("clvm len nil", clvm_program_length(b"\x80"), 1)
    check("clvm len small atom", clvm_program_length(b"\x05"), 1)
    check("clvm len 0x7f", clvm_program_length(b"\x7f"), 1)
    # size-prefixed atoms: 0x83 -> 3-byte blob; 0xc4 0x01 -> 0x101-byte blob
    check("clvm len sized atom", clvm_program_length(b"\x83abc"), 4)
    check("clvm len 2-byte size", clvm_program_length(b"\xc1\x01" + b"z" * 0x101), 2 + 0x101)
    # cons cells nest
    check("clvm len cons", clvm_program_length(b"\xff\x01\x80"), 3)
    check("clvm len nested", clvm_program_length(b"\xff\xff\x01\x80\x02"), 5)
    check("clvm len stops at program end",
          clvm_program_length(b"\x80\x80\x80"), 1)
    check_raises("clvm truncated cons", lambda: clvm_program_length(b"\xff\x01"))
    check_raises("clvm truncated atom", lambda: clvm_program_length(b"\x83ab"))
    check_raises("clvm backref rejected", lambda: clvm_program_length(b"\xfe\x00"))
    check_raises("clvm empty", lambda: clvm_program_length(b""))
    # enc/dec round-trip with consensus framing (no length prefix)
    prog = b"\xff\x02\xff\xff\x04\x80\x80"  # cons(0x02, cons(cons(0x04, nil), nil))
    check("program enc is verbatim", enc_program(prog), prog)
    check("program dec", dec_program(_Reader(prog + b"\x80")), prog)
    check_raises("program enc rejects trailing garbage",
                 lambda: enc_program(b"\x80\x80"))


# ---------------------------------------------------------------------------
# 9. Wallet protocol messages (round-trips + field order)
# ---------------------------------------------------------------------------

def test_wallet_protocol():
    ph1 = bytes.fromhex("11" * 32)
    ph2 = bytes.fromhex("22" * 32)

    enc = enc_register_for_ph_updates([ph1, ph2], 0)
    # u32 count=2, two bytes32, u32 min_height=0
    check("register ph updates", enc.hex(), "00000002" + "11" * 32 + "22" * 32 + "00000000")

    cid = bytes.fromhex("33" * 32)
    enc2 = enc_register_for_coin_updates([cid], 100)
    check("register coin updates", enc2.hex(), "00000001" + "33" * 32 + "00000064")

    # RespondToPhUpdates round-trip
    cs = CoinState(Coin(bytes.fromhex("aa" * 32), ph1, 1000), None, 4714900)
    payload = (enc_u32(1) + enc_bytes_fixed(ph1, 32) + enc_u32(0)
               + enc_u32(1) + enc_coin_state(cs))
    resp = dec_respond_to_ph_updates(payload)
    check("respond ph updates", (resp["min_height"], resp["coin_states"]), (0, [cs]))
    check("respond ph hashes", resp["puzzle_hashes"], [ph1])

    # RespondToCoinUpdates round-trip
    payload2 = (enc_u32(1) + enc_bytes_fixed(cid, 32) + enc_u32(0)
                + enc_u32(1) + enc_coin_state(cs))
    resp2 = dec_respond_to_coin_updates(payload2)
    check("respond coin updates", resp2["coin_states"], [cs])

    # SendTransaction embeds the bundle verbatim
    raw = _sample_bundle_bytes()
    check("send tx payload", enc_send_transaction(raw).hex(), raw.hex())

    # TransactionAck: txid(32) + status u8 + Optional[str] error
    ack = bytes.fromhex("44" * 32) + b"\x01" + b"\x00"
    a = dec_transaction_ack(ack)
    check("tx ack", (a["txid"].hex(), a["status"], a["error"]),
          ("44" * 32, 1, None))
    ack_err = bytes.fromhex("44" * 32) + b"\x03" + b"\x01" + enc_str("bad bundle")
    a2 = dec_transaction_ack(ack_err)
    check("tx ack failed", (a2["status"], a2["error"]), (3, "bad bundle"))

    # NewPeakWallet: header_hash(32) + height u32 + weight u128 + fork u32
    peak = bytes.fromhex("55" * 32) + enc_u32(4714900) + enc_u128(123456) + enc_u32(4714899)
    p = dec_new_peak_wallet(peak)
    check("new peak", (p["height"], p["weight"], p["fork_point_with_previous_peak"]),
          (4714900, 123456, 4714899))


# ---------------------------------------------------------------------------
# 10. CoinStateUpdate push (msg 69) decodes
# ---------------------------------------------------------------------------

def test_coin_state_update():
    from streamable import dec_coin_state_update
    ph1 = bytes.fromhex("11" * 32)
    cs = CoinState(Coin(bytes.fromhex("aa" * 32), ph1, 1000), 4714905, 4714900)
    payload = (enc_u32(4714905) + enc_u32(4714900) + bytes.fromhex("66" * 32)
               + enc_u32(1) + enc_coin_state(cs))
    u = dec_coin_state_update(payload)
    check("coin update", (u["height"], u["fork_height"], u["items"]), (4714905, 4714900, [cs]))


TESTS = [
    test_primitives,
    test_containers,
    test_int_to_bytes,
    test_coin_id,
    test_message_envelope,
    test_handshake,
    test_coin,
    test_spend_bundle,
    test_clvm_program_framing,
    test_wallet_protocol,
    test_coin_state_update,
]


def main() -> int:
    for t in TESTS:
        print(f"--- {t.__name__} ---")
        t()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILURES: {FAILURES}")
        return 1
    print("all vectors green")
    return 0


if __name__ == "__main__":
    sys.exit(main())

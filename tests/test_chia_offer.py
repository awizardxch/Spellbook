"""Native XCH offer protocol tests.

Every constructed spend is executed through the real compiled CLVM
puzzles (``chia_rs.run_chia_program``): the standard puzzle and the
Chia 2.5.2 settlement mod.  A test that passes means the spends are
consensus-valid by construction.

Scope is native XCH only: CAT / NFT / DID / unknown-driver legs must
fail closed (OfferError), never execute, and never be reinterpreted as
XCH.

Reference compatibility (verified byte-for-byte against
chia-blockchain 2.5.2 during development):

* ``OFFER_MOD`` bytes == ``settlement_payments.clsp.hex`` from the
  2.5.2 wheel; ``OFFER_MOD_HASH`` matches the reference.
* Compression zdict entries 1..6 identical to the reference
  ``puzzle_compression.ZDICT``; version-6 framing identical.
* ``offer_nonce`` == ``Program.to(sorted_coin_infos).get_tree_hash()``
  with coins sorted by ``Coin.name()`` (reference
  ``notarize_payments``).
* ``announcement_for_asset`` message ==
  ``Program.to((nonce, [as_condition_args() ...])).get_tree_hash()``
  (reference ``calculate_announcements``).
* ``offer_id_for_bundle`` == ``SpendBundle.name()`` (reference
  ``Offer.name()``).
* ``bech32m_encode`` output identical to the reference
  ``bech32_encode``.

The fixed vectors below pin those semantics: any change to the
construction alters them.
"""

import hashlib

import pytest
from blspy import AugSchemeMPL, G1Element

import spellbook.chia_offer as o
import spellbook.chia_sign as cs
from spellbook.chia_offer import (
    BuiltOffer,
    Coin,
    CoinSpend,
    OfferError,
    RequestedPayment,
    XchInput,
    cancel_offer,
    make_offer,
    parse_offer,
    summarize_offer,
    take_offer,
)

NETWORK = "testnet11"
MASTER = bytes([7]) * 32  # deterministic test key (never a real wallet)

# Fixed vectors (see module docstring for provenance). Re-pinned 2026-10-07
# with the S1 fix: the maker/receive/change puzzle hashes are now the
# STANDARD curry's (chia-blockchain's), so every vector that embeds a
# puzzle hash changed; the construction they pin did not.
FIXED_OFFER_ID = "33d25276a9eace69f9e99b6a3c6e7b307a7ceceb59dd1241be0b5592cc4bdec0"
FIXED_NONCE = "2223f7981f58c2ec7d8a0d29a8bc4785eafbd1ea27aaaaabf5f3860dea45cb72"
FIXED_ANN_MSG = "01292cbad313eca871f8beb55a3640fe0472b9b904d17b953a9db245cee6febe"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def std_index(index: int):
    """(reveal, puzzle_hash, synthetic_sk, synthetic_pk) for an index."""
    wsk = cs.wallet_sk(MASTER, index)
    wpk = cs.pk_bytes(wsk)
    ssk = cs.synthetic_sk(wsk)
    spk = cs.synthetic_pk(wpk)
    reveal = cs.standard_puzzle_reveal(spk)
    return reveal, cs.sha256tree(cs.deser(reveal)), ssk, spk


def run(spend: CoinSpend):
    """Execute a spend's puzzle+solution, return condition s-exprs."""
    from chia_rs import run_chia_program

    _cost, out = run_chia_program(
        spend.puzzle_reveal, spend.solution, 11_000_000_000, 0
    )
    return o._sexpr_as_list(o._lazy_to_sexpr(out))


def create_coins(conditions):
    out = []
    for cond in conditions:
        opcode, args = o._condition_args(cond)
        if opcode == 51 and len(args) >= 2:
            out.append((args[0], o._atom_int(args[1])))
    return out


def announcements(conditions):
    out = []
    for cond in conditions:
        opcode, args = o._condition_args(cond)
        if opcode == 63 and len(args) == 1:  # ASSERT_PUZZLE_ANNOUNCEMENT (announcement id)
            out.append(args[0])
    return out


def created_puzzle_announcements(conditions, coin_puzzle_hash):
    out = []
    for cond in conditions:
        opcode, args = o._condition_args(cond)
        if opcode == 62 and len(args) >= 1:  # CREATE_PUZZLE_ANNOUNCEMENT
            out.append((coin_puzzle_hash, args[0]))
    return out


def reserve_fee(conditions):
    total = 0
    for cond in conditions:
        opcode, args = o._condition_args(cond)
        if opcode == 52 and args:  # RESERVE_FEE
            total += o._atom_int(args[0])
    return total


def aggsig_messages(spends, network=NETWORK):
    """[(pk, message)] for every AGG_SIG_ME a spend's conditions demand."""
    pairs = []
    for spend in spends:
        conds = run(spend)
        for cond in conds:
            opcode, args = o._condition_args(cond)
            if opcode == 50 and len(args) >= 2:  # AGG_SIG_ME
                pk, msg_hash = args[0], args[1]
                cid = spend.coin.coin_id()
                pairs.append(
                    (pk, cs.aggsig_me_message(msg_hash, cid, network))
                )
    return pairs


def assert_bundle_sigs(spends, signature: bytes, network=NETWORK):
    pairs = aggsig_messages(spends, network)
    assert pairs, "no signed conditions found"
    pks = [G1Element.from_bytes(pk) for pk, _msg in pairs]
    msgs = [msg for _pk, msg in pairs]
    from blspy import G2Element

    assert AugSchemeMPL.aggregate_verify(
        pks, msgs, G2Element.from_bytes(signature)
    )


def xch_input(index: int, amount: int, parent: bytes = None) -> XchInput:
    _reveal, ph, _ssk, _spk = std_index(index)
    return XchInput(
        parent_coin_info=parent or hashlib.sha256(f"parent-{index}".encode()).digest(),
        puzzle_hash=ph,
        amount=amount,
        index=index,
    )


def make_basic_offer(**kw):
    """Deterministic 400k-XCH-for-400k-XCH offer used by many tests."""
    args = dict(
        master_sk=MASTER,
        network_id=NETWORK,
        offered=[("native", 400_000)],
        requested=[RequestedPayment("native", std_index(9)[1], 400_000)],
        xch_inputs=[xch_input(1, 1_000_000)],
        change_ph=std_index(2)[1],
    )
    args.update(kw)
    return make_offer(**args)


# ---------------------------------------------------------------------------
# constants / encoding / reference vectors
# ---------------------------------------------------------------------------


def test_settlement_mod_hash_is_stable():
    assert len(o.OFFER_MOD_HASH) == 32
    assert o.OFFER_MOD_HASH == cs.sha256tree(cs.deser(o.OFFER_MOD))


def test_bech32m_roundtrip():
    payload = hashlib.sha256(b"offer-payload").digest() * 3
    s = cs.bech32m_encode("offer", payload)
    assert s.startswith("offer1")
    hrp, back = cs.bech32m_decode(s)
    assert hrp == "offer" and back == payload


def test_bech32m_rejects_bad_checksum():
    s = cs.bech32m_encode("offer", b"hello world")
    bad = s[:-1] + ("q" if s[-1] != "q" else "p")
    with pytest.raises(Exception):
        cs.bech32m_decode(bad)


def test_compress_roundtrip():
    blob = bytes(range(256)) * 4
    assert o.decompress_offer(o.compress_offer(blob)) == blob
    assert o.compress_offer(blob)[:2] == (6).to_bytes(2, "big")


def test_fixed_offer_id_vector():
    """Pinned end-to-end vector: any construction change alters this."""
    built = make_basic_offer()
    assert built.offer_id == FIXED_OFFER_ID
    parsed = parse_offer(built.offer_str)
    assert parsed.offer_id == FIXED_OFFER_ID
    assert parsed.nonce == built.nonce


def test_fixed_nonce_vector():
    coins = [
        Coin(hashlib.sha256(f"parent-{i}".encode()).digest(), std_index(i)[1], 100_000 * (i + 1))
        for i in (1, 2)
    ]
    assert o.offer_nonce(coins).hex() == FIXED_NONCE


def test_fixed_announcement_vector():
    nonce = bytes([9]) * 32
    _ph, msg = o.announcement_for_asset(
        "native", nonce, [o.Payment(std_index(9)[1], 400_000, [])]
    )
    assert _ph == o.OFFER_MOD_HASH
    assert msg.hex() == FIXED_ANN_MSG


def test_offer_build_is_deterministic():
    a = make_basic_offer()
    b = make_basic_offer()
    assert a.offer_id == b.offer_id
    assert a.offer_str == b.offer_str


def test_offer_id_changes_with_inputs():
    a = make_basic_offer()
    b = make_basic_offer(offered=[("native", 400_001)])
    assert a.offer_id != b.offer_id


# ---------------------------------------------------------------------------
# strict (de)serialization
# ---------------------------------------------------------------------------


def test_decompress_rejects_truncated():
    blob = o.compress_offer(b"hello world, this is an offer")
    with pytest.raises(OfferError):
        o.decompress_offer(blob[:-3])


def test_decompress_rejects_trailing_bytes():
    blob = o.compress_offer(b"hello world, this is an offer")
    with pytest.raises(OfferError):
        o.decompress_offer(blob + b"\x00\x01\x02")


def test_decompress_rejects_bad_version():
    blob = o.compress_offer(b"hello")
    bad = (99).to_bytes(2, "big") + blob[2:]
    with pytest.raises(OfferError):
        o.decompress_offer(bad)


def test_decompress_rejects_oversized():
    big = bytes(7 * 1024 * 1024)  # 7 MiB of zeros compresses tiny
    blob = o.compress_offer(big)
    with pytest.raises(OfferError):
        o.decompress_offer(blob)


def test_bundle_rejects_reveal_mismatch():
    """A spend whose reveal doesn't hash to its coin record is refused."""
    built = make_basic_offer()
    spends, sig = o.parse_solutions_bundle(built.bundle_bytes)
    s = spends[-1]
    other_reveal, _, _, _ = std_index(77)
    tampered = CoinSpend(
        Coin(s.coin.parent_coin_info, s.coin.puzzle_hash, s.coin.amount),
        other_reveal,
        s.solution,
    )
    raw = o.serialize_bundle(
        spends[:-1] + [tampered], sig
    )
    with pytest.raises(OfferError):
        o.parse_solutions_bundle(raw)


def test_bundle_rejects_trailing_bytes():
    built = make_basic_offer()
    with pytest.raises(OfferError):
        o.parse_solutions_bundle(built.bundle_bytes + b"\x00")


def test_bundle_rejects_truncated_coin():
    built = make_basic_offer()
    with pytest.raises(OfferError):
        o.parse_solutions_bundle(built.bundle_bytes[:20])


# ---------------------------------------------------------------------------
# XCH make
# ---------------------------------------------------------------------------


def test_make_xch_offer_executes():
    built = make_basic_offer()
    assert isinstance(built, BuiltOffer)
    assert built.offered == [("native", 400_000)]
    assert built.requested == [("native", 400_000)]

    # Round-trip through the offer string.
    parsed = parse_offer(built.offer_str)
    assert parsed.offer_id == built.offer_id
    assert parsed.nonce == built.nonce
    legs = summarize_offer(parsed)
    assert legs["offered"] == [("native", 400_000)]
    assert legs["requested"] == [("native", 400_000)]

    # Execute the maker spend: settlement + change + announcement.
    (spend,) = parsed.spends
    conds = run(spend)
    coins = create_coins(conds)
    assert (o.OFFER_MOD_HASH, 400_000) in coins
    change = [c for c in coins if c[0] == std_index(2)[1]]
    assert change == [(std_index(2)[1], 600_000)]
    anns = announcements(conds)
    assert len(anns) == 1
    # The asserted announcement commits to our requested payment.
    expected_msg = cs.sha256tree(
        cs.deser(o.notarized_group(parsed.nonce, parsed.requested["native"]))
    )
    expected_id = hashlib.sha256(o.OFFER_MOD_HASH + expected_msg).digest()
    assert anns[0] == expected_id

    # Maker signature verifies against the spend's AGG_SIG_ME.
    spends, sig = o.parse_solutions_bundle(built.bundle_bytes)
    assert_bundle_sigs([s for s in spends if s.coin.parent_coin_info != bytes(32)], sig)


def test_make_xch_offer_multi_coin_fee_and_change():
    built = make_offer(
        MASTER,
        NETWORK,
        offered=[("native", 500_000)],
        requested=[RequestedPayment("native", std_index(9)[1], 700_000)],
        xch_inputs=[xch_input(1, 400_000), xch_input(2, 400_000)],
        change_ph=std_index(3)[1],
        fee=100_000,
    )
    parsed = parse_offer(built.offer_str)
    assert len(parsed.spends) == 2
    spends, sig = o.parse_solutions_bundle(built.bundle_bytes)
    maker = [s for s in spends if s.coin.parent_coin_info != bytes(32)]
    # Origin coin: settlement + change (800k - 500k - 100k = 200k) + fee.
    origin = run(maker[0])
    coins = create_coins(origin)
    assert (o.OFFER_MOD_HASH, 500_000) in coins
    assert (std_index(3)[1], 200_000) in coins
    assert reserve_fee(origin) == 100_000
    assert len(announcements(origin)) == 1
    # Consolidating coin: no outputs, still signed.
    assert create_coins(run(maker[1])) == []
    assert_bundle_sigs(maker, sig)


def test_make_offer_rejects_unfunded():
    with pytest.raises(OfferError):
        make_offer(
            MASTER, NETWORK,
            offered=[("native", 100)],
            requested=[RequestedPayment("native", std_index(9)[1], 100)],
            xch_inputs=[xch_input(1, 50)],
            change_ph=std_index(2)[1],
        )


def test_make_offer_rejects_fee_without_inputs():
    with pytest.raises(OfferError):
        make_offer(
            MASTER, NETWORK,
            offered=[("native", 100)],
            requested=[RequestedPayment("native", std_index(9)[1], 100)],
            xch_inputs=[],
            change_ph=std_index(2)[1], fee=100,
        )


def test_make_offer_rejects_wrong_index():
    bad = xch_input(1, 1_000_000)
    bad = XchInput(bad.parent_coin_info, bad.puzzle_hash, bad.amount, 999)
    with pytest.raises(OfferError):
        make_offer(
            MASTER, NETWORK,
            offered=[("native", 100)],
            requested=[RequestedPayment("native", std_index(9)[1], 100)],
            xch_inputs=[bad],
            change_ph=std_index(2)[1],
        )


def test_make_offer_rejects_missing_change():
    with pytest.raises(OfferError):
        make_offer(
            MASTER, NETWORK,
            offered=[("native", 100)],
            requested=[RequestedPayment("native", std_index(9)[1], 100)],
            xch_inputs=[xch_input(1, 1_000_000)],
            change_ph=None,
        )


# ---------------------------------------------------------------------------
# XCH take (full bundle executes, announcements cross-link)
# ---------------------------------------------------------------------------


def test_take_xch_offer_full_bundle_executes():
    built = make_offer(
        MASTER, NETWORK,
        offered=[("native", 400_000)],
        requested=[RequestedPayment("native", std_index(11)[1], 400_000)],
        xch_inputs=[xch_input(1, 1_000_000)],
        change_ph=std_index(2)[1],
    )
    parsed = parse_offer(built.offer_str)

    taker_recv_ph = std_index(12)[1]
    result = take_offer(
        MASTER, NETWORK, parsed,
        xch_inputs=[xch_input(4, 900_000)],
        receive=[RequestedPayment("native", taker_recv_ph, 400_000)],
        change_ph=std_index(5)[1],
    )
    assert result.offered == [("native", 400_000)]
    assert result.given == [("native", 400_000)]

    spends, sig = o.parse_solutions_bundle(result.bundle_bytes)
    # 1 completion (maker X) + 1 maker + 1 completion (taker X) + 1 taker
    assert len(spends) == 4

    created_anns = []  # (puzzle_hash, message) from CREATE_PUZZLE_ANNOUNCEMENT
    asserted_anns = []  # announcement ids from ASSERT_PUZZLE_ANNOUNCEMENT
    payments_out = []
    for spend in spends:
        conds = run(spend)
        created_anns.extend(created_puzzle_announcements(conds, spend.coin.puzzle_hash))
        for cond in conds:
            opcode, args = o._condition_args(cond)
            if opcode == 63 and len(args) == 1:
                asserted_anns.append(args[0])
            elif opcode == 51 and len(args) >= 2:
                payments_out.append((args[0], o._atom_int(args[1])))
    # Every asserted announcement was created somewhere in the bundle.
    assert asserted_anns, "no announcements asserted"
    created_ids = {hashlib.sha256(ph + msg).digest() for ph, msg in created_anns}
    for ann_id in asserted_anns:
        assert ann_id in created_ids, f"asserted {ann_id.hex()[:8]}… never created"
    # The taker got paid, the maker got paid.
    assert (taker_recv_ph, 400_000) in payments_out
    assert (std_index(11)[1], 400_000) in payments_out
    # Full aggregate signature verifies (maker sig + taker sigs).
    assert_bundle_sigs(spends, sig)
    assert result.bundle_txid == hashlib.sha256(result.bundle_bytes).hexdigest()


def test_take_rejects_amount_mismatch():
    built = make_basic_offer()
    parsed = parse_offer(built.offer_str)
    with pytest.raises(OfferError):
        take_offer(
            MASTER, NETWORK, parsed,
            xch_inputs=[xch_input(4, 900_000)],
            receive=[RequestedPayment("native", std_index(12)[1], 399_999)],
            change_ph=std_index(5)[1],
        )


def test_take_rejects_tampered_announcement():
    built = make_basic_offer()
    parsed = parse_offer(built.offer_str)
    # Tamper: flip a byte in the maker spend's solution (breaks announcement).
    spends = list(parsed.spends)
    s = spends[0]
    tampered_sol = bytearray(s.solution)
    tampered_sol[-10] ^= 0xFF
    spends[0] = CoinSpend(s.coin, s.puzzle_reveal, bytes(tampered_sol))
    tampered = o.ParsedOffer(
        requested=parsed.requested,
        requested_groups=parsed.requested_groups,
        nonce=parsed.nonce,
        spends=spends,
        signature=parsed.signature,
        bundle_bytes=parsed.bundle_bytes,
        offer_id=parsed.offer_id,
    )
    with pytest.raises(OfferError):
        take_offer(
            MASTER, NETWORK, tampered,
            xch_inputs=[xch_input(4, 900_000)],
            receive=[RequestedPayment("native", std_index(12)[1], 400_000)],
            change_ph=std_index(5)[1],
        )


def test_take_rejects_wrong_receive_asset():
    built = make_basic_offer()
    parsed = parse_offer(built.offer_str)
    with pytest.raises(OfferError):
        take_offer(
            MASTER, NETWORK, parsed,
            xch_inputs=[xch_input(4, 900_000)],
            receive=[RequestedPayment("ab" * 32, std_index(12)[1], 400_000)],
            change_ph=std_index(5)[1],
        )


# ---------------------------------------------------------------------------
# cancel
# ---------------------------------------------------------------------------


def test_cancel_xch_executes():
    coin = xch_input(1, 1_000_000).coin()
    bundle = cancel_offer(
        MASTER, NETWORK, coin, 1, std_index(2)[1], fee=1_000
    )
    spends, sig = o.parse_solutions_bundle(bundle)
    assert len(spends) == 1
    conds = run(spends[0])
    assert create_coins(conds) == [(std_index(2)[1], 999_000)]
    assert reserve_fee(conds) == 1_000
    assert_bundle_sigs(spends, sig)


def test_cancel_rejects_wrong_index():
    coin = xch_input(1, 1_000_000).coin()
    with pytest.raises(OfferError):
        cancel_offer(MASTER, NETWORK, coin, 999, std_index(2)[1])


def test_cancel_rejects_fee_over_amount():
    coin = xch_input(1, 1_000).coin()
    with pytest.raises(OfferError):
        cancel_offer(MASTER, NETWORK, coin, 1, std_index(2)[1], fee=1_000)


# ---------------------------------------------------------------------------
# non-XCH drivers fail closed (no CAT/NFT/DID execution, no reinterpretation)
# ---------------------------------------------------------------------------


def test_make_rejects_cat_offered_asset():
    with pytest.raises(OfferError):
        make_offer(
            MASTER, NETWORK,
            offered=[("ab" * 32, 600_000)],
            requested=[RequestedPayment("native", std_index(9)[1], 250_000)],
            xch_inputs=[xch_input(1, 1_000_000)],
            change_ph=std_index(2)[1],
        )


def test_make_rejects_cat_requested_asset():
    with pytest.raises(OfferError):
        make_offer(
            MASTER, NETWORK,
            offered=[("native", 400_000)],
            requested=[RequestedPayment("ab" * 32, std_index(9)[1], 250_000)],
            xch_inputs=[xch_input(1, 1_000_000)],
            change_ph=std_index(2)[1],
        )


def test_make_rejects_unknown_offered_asset():
    with pytest.raises(OfferError):
        make_offer(
            MASTER, NETWORK,
            offered=[("mystery", 1)],
            requested=[RequestedPayment("native", std_index(9)[1], 1)],
            xch_inputs=[xch_input(1, 1_000_000)],
            change_ph=std_index(2)[1],
        )


def test_parse_conditions_rejects_cat_shaped_solution():
    """A CAT-ring solution shape (7-list) is refused, not unwrapped."""
    inner = o._standard_solution(o._inner_create_coin(o.OFFER_MOD_HASH, 1))
    cat_shaped = cs.ser(
        cs._list(
            [
                cs.deser(inner),
                cs.deser(cs.ser(cs._list([b"lineage"]))),
                bytes(32),
                cs.deser(cs.ser(cs._list([b"myinfo"]))),
                cs.deser(cs.ser(cs._list([b"nextinfo"]))),
                cs.int_to_bytes(0),
                cs.int_to_bytes(0),
            ]
        )
    )
    with pytest.raises(OfferError):
        o.parse_conditions(cat_shaped)


def test_parse_conditions_rejects_singleton_shaped_solution():
    """An NFT/singleton-style solution (arbitrary non-standard list)."""
    weird = cs.ser(cs._list([cs.int_to_bytes(1), cs.int_to_bytes(2)]))
    with pytest.raises(OfferError):
        o.parse_conditions(weird)


def test_parse_offer_rejects_cat_dummy_puzzle():
    """A dummy spend whose puzzle isn't the settlement mod is refused."""
    built = make_basic_offer()
    spends, sig = o.parse_solutions_bundle(built.bundle_bytes)
    dummies = [s for s in spends if s.coin.parent_coin_info == bytes(32)]
    assert len(dummies) == 1
    fake_cat_puzzle = cs.ser(cs._list([cs.int_to_bytes(2), cs.deser(o.OFFER_MOD)]))
    fake_dummy = CoinSpend(
        Coin(bytes(32), cs.sha256tree(cs.deser(fake_cat_puzzle)), 0),
        fake_cat_puzzle,
        dummies[0].solution,
    )
    raw = o.serialize_bundle(
        [fake_dummy] + [s for s in spends if s.coin.parent_coin_info != bytes(32)],
        sig,
    )
    s = cs.bech32m_encode("offer", o.compress_offer(raw))
    with pytest.raises(OfferError):
        parse_offer(s)


def test_parse_offer_rejects_nonstandard_maker_solution():
    """A maker spend with a non-XCH solution shape fails closed at parse."""
    built = make_basic_offer()
    spends, sig = o.parse_solutions_bundle(built.bundle_bytes)
    maker = [s for s in spends if s.coin.parent_coin_info != bytes(32)]
    dummies = [s for s in spends if s.coin.parent_coin_info == bytes(32)]
    s = maker[0]
    weird_solution = cs.ser(cs._list([cs.int_to_bytes(9), cs.int_to_bytes(9)]))
    tampered = CoinSpend(s.coin, s.puzzle_reveal, weird_solution)
    raw = o.serialize_bundle(dummies + [tampered], sig)
    enc = cs.bech32m_encode("offer", o.compress_offer(raw))
    with pytest.raises(OfferError):
        parse_offer(enc)


def test_announcement_for_asset_rejects_cat():
    with pytest.raises(OfferError):
        o.announcement_for_asset("ab" * 32, bytes(32), [])


# ---------------------------------------------------------------------------
# malformed / hostile offers fail closed
# ---------------------------------------------------------------------------


def test_parse_rejects_garbage():
    with pytest.raises(OfferError):
        parse_offer("offer1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")


def test_parse_rejects_empty_string():
    with pytest.raises(OfferError):
        parse_offer("")


def test_parse_rejects_mixed_nonce():
    built = make_basic_offer()
    # Craft a bundle whose two dummy spends use different nonces.
    spends, sig = o.parse_solutions_bundle(built.bundle_bytes)
    dummies = [s for s in spends if s.coin.parent_coin_info == bytes(32)]
    assert len(dummies) == 1
    other_nonce = hashlib.sha256(b"other").digest()
    other_group = o.notarized_group(
        other_nonce, [o.Payment(std_index(12)[1], 1, [])]
    )
    other_dummy = CoinSpend(
        Coin(bytes(32), o.OFFER_MOD_HASH, 0), o.OFFER_MOD, cs.ser(cs._list([cs.deser(other_group)]))
    )
    raw = o.serialize_bundle(dummies + [other_dummy] + [s for s in spends if s.coin.parent_coin_info != bytes(32)], sig)
    s = cs.bech32m_encode("offer", o.compress_offer(raw))
    with pytest.raises(OfferError):
        parse_offer(s)


def test_parse_accepts_raw_uncompressed_bundle():
    """Reference try_offer_decompression falls back to raw bundle bytes."""
    built = make_basic_offer()
    enc = cs.bech32m_encode("offer", built.bundle_bytes)
    parsed = parse_offer(enc)
    assert parsed.offer_id == built.offer_id
    assert summarize_offer(parsed)["offered"] == [("native", 400_000)]


# ---------------------------------------------------------------------------
# Chialisp audit 2026-10-07: S3 (crafted offer must refuse, not raise),
# S7 (settlement reveal compared by tree hash), S1 (legacy inputs)
# ---------------------------------------------------------------------------


def _reencode_nonminimal(obj) -> bytes:
    """Serialize ``obj`` encoding every 1-byte atom < 0x80 as 0x81 || b.

    A legal, non-minimal CLVM encoding of the same program (same tree
    hash); chia's deserializer accepts it.
    """
    out = bytearray()
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, bytes):
            if len(node) == 1 and node[0] < 0x80:
                out += b"\x81" + node
            else:
                out += cs._ser_atom(node)
        else:
            first, rest = node
            out.append(0xFF)
            stack.append(rest)
            stack.append(first)
    return bytes(out)


def crafted_offer_without_settlement_output() -> str:
    """A well-formed offer whose (only) maker spend creates no settlement
    output: the maker's standard solution pays the whole coin to a
    change address instead of OFFER_MOD_HASH. parse_offer accepts it
    (the shape is standard XCH), summarize_offer must refuse it."""
    built = make_basic_offer()
    spends, signature = o.parse_solutions_bundle(built.bundle_bytes)
    out = []
    for sp in spends:
        if sp.coin.parent_coin_info == o._ZERO32:
            out.append(sp)
            continue
        conds = cs._list([o._inner_create_coin(std_index(2)[1], sp.coin.amount)])
        out.append(CoinSpend(sp.coin, sp.puzzle_reveal, o._standard_solution(conds)))
    bundle = o.serialize_bundle(out, signature)  # signature now stale — irrelevant to parsing
    return cs.bech32m_encode("offer", o.compress_offer(bundle))


def test_crafted_offer_without_settlement_refuses_cleanly():
    offer = crafted_offer_without_settlement_output()
    parsed = parse_offer(offer)  # parses: standard-shaped maker spend
    with pytest.raises(OfferError, match="no native settlement output"):
        summarize_offer(parsed)
    with pytest.raises(OfferError):
        take_offer(MASTER, NETWORK, parsed, [xch_input(3, 1_000_000)],
                   [RequestedPayment("native", std_index(4)[1], 400_000)],
                   std_index(4)[1])


def test_parse_offer_accepts_nonminimal_settlement_reveal():
    """S7: the dummy settlement spend's reveal is matched by tree hash,
    so a legal non-minimal encoding of OFFER_MOD is the same puzzle."""
    built = make_basic_offer()
    spends, signature = o.parse_solutions_bundle(built.bundle_bytes)
    out = []
    for sp in spends:
        if sp.coin.parent_coin_info == o._ZERO32:
            reveal = _reencode_nonminimal(cs.deser(o.OFFER_MOD))
            assert reveal != o.OFFER_MOD
            assert cs.sha256tree(cs.deser(reveal)) == o.OFFER_MOD_HASH
            sp = CoinSpend(sp.coin, reveal, sp.solution)
        out.append(sp)
    bundle = o.serialize_bundle(out, signature)
    parsed = parse_offer(cs.bech32m_encode("offer", o.compress_offer(bundle)))
    assert summarize_offer(parsed) == summarize_offer(parse_offer(built.offer_str))


def test_parse_offer_still_rejects_wrong_settlement_puzzle():
    built = make_basic_offer()
    spends, signature = o.parse_solutions_bundle(built.bundle_bytes)
    out = []
    for sp in spends:
        if sp.coin.parent_coin_info == o._ZERO32:
            # a different puzzle with the matching coin record
            reveal = std_index(5)[0]
            sp = CoinSpend(Coin(o._ZERO32, cs.sha256tree(cs.deser(reveal)), 0),
                           reveal, sp.solution)
        out.append(sp)
    bundle = o.serialize_bundle(out, signature)
    with pytest.raises(OfferError, match="unsupported driver"):
        parse_offer(cs.bech32m_encode("offer", o.compress_offer(bundle)))


def legacy_xch_input(index: int, amount: int) -> XchInput:
    wsk = cs.wallet_sk(MASTER, index)
    spk = cs.synthetic_pk(cs.pk_bytes(wsk))
    return XchInput(
        parent_coin_info=hashlib.sha256(f"legacy-parent-{index}".encode()).digest(),
        puzzle_hash=cs.legacy_puzzle_hash_for_synthetic_pk(spk),
        amount=amount, index=index,
    )


def test_make_offer_from_legacy_coin_executes():
    """S1: a coin at a pre-fix (legacy) address can still back an offer;
    its spend carries the legacy reveal (which hashes to the coin's
    puzzle hash) and the change goes to the standard address."""
    inp = legacy_xch_input(1, 1_000_000)
    built = make_basic_offer(xch_inputs=[inp])
    parsed = parse_offer(built.offer_str)
    spend = parsed.spends[0]
    assert spend.coin.puzzle_hash == inp.puzzle_hash
    assert spend.puzzle_reveal == cs.legacy_standard_puzzle_reveal(
        cs.synthetic_pk(cs.pk_bytes(cs.wallet_sk(MASTER, 1))))
    conds = run(spend)
    assert (o.OFFER_MOD_HASH, 400_000) in create_coins(conds)
    assert (std_index(2)[1], 600_000) in create_coins(conds)
    assert_bundle_sigs(parsed.spends, parsed.signature)


def test_cancel_legacy_coin_executes():
    inp = legacy_xch_input(1, 1_000_000)
    bundle = cancel_offer(MASTER, NETWORK, inp.coin(), 1, std_index(0)[1], fee=0)
    spends, sig = o.parse_solutions_bundle(bundle)
    assert spends[0].coin.puzzle_hash == inp.puzzle_hash
    assert create_coins(run(spends[0])) == [(std_index(0)[1], 1_000_000)]
    assert_bundle_sigs(spends, sig)


def test_wrong_index_rejected_for_legacy_coin_too():
    inp = legacy_xch_input(1, 1_000_000)
    bad = XchInput(inp.parent_coin_info, inp.puzzle_hash, inp.amount, 2)
    with pytest.raises(OfferError, match="not locked"):
        make_basic_offer(xch_inputs=[bad])

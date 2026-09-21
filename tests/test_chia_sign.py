"""Tests for src/spellbook/chia_sign.py — local Chia key derivation, puzzle
construction, and AGG_SIG_ME signing.

Vectors:
- Unhardened derivation: chia-bls 0.36.1 (4 vectors)
- Synthetic keys: chia-puzzle-types 0.36.1 (16 vectors)
- Standard module hash: e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52
- Testnet11 genesis: 37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from spellbook import chia_sign as cs
from spellbook.chia_sign import ChiaSignError

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "fixtures",
                           "synth_vectors.txt")


def _load_vectors():
    vec = {}
    arr0 = {}
    arr1 = {}
    with open(VECTORS_PATH) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if k.startswith("ARR0["):
                idx = int(k[5:-1])
                arr0[idx] = v
            elif k.startswith("ARR1["):
                idx = int(k[5:-1])
                arr1[idx] = v
            else:
                vec[k] = v
    vec["SYNTH_PK"] = arr0
    vec["SYNTH_SK"] = arr1
    return vec


VEC = _load_vectors()
MASTER_SK = bytes.fromhex(VEC["MASTER_SK"])
# Testnet11 genesis challenge (AGG_SIG_ME additional data) — verified from
# chia-puzzle-types / testnet11 config
TESTNET11_GENESIS = bytes.fromhex(
    "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615")


class TestUnhardenedDerivation:
    def test_deterministic(self):
        for i in range(4):
            assert cs.wallet_sk(MASTER_SK, i) == cs.wallet_sk(MASTER_SK, i)

    def test_distinct_per_index(self):
        keys = [cs.wallet_sk(MASTER_SK, i) for i in range(4)]
        assert len(set(keys)) == 4

    def test_wallet_pubkeys_match(self):
        for i in range(4):
            wsk = cs.wallet_sk(MASTER_SK, i)
            wpk = cs.pk_bytes(wsk)
            assert len(wpk) == 48
            # Synthetic key derived from this wpk must match vector
            assert cs.synthetic_pk(wpk) == bytes.fromhex(VEC["SYNTH_PK"][i])

    def test_bad_master_rejected(self):
        with pytest.raises(ChiaSignError):
            cs.wallet_sk(b"short", 0)
        with pytest.raises(ChiaSignError):
            cs.wallet_sk(MASTER_SK, -1)


class TestSyntheticKeys:
    def test_sixteen_secret_vectors(self):
        for i in range(16):
            ssk = cs.synthetic_sk(cs.wallet_sk(MASTER_SK, i))
            assert ssk == bytes.fromhex(VEC["SYNTH_SK"][i]), f"index {i}"

    def test_sixteen_public_vectors(self):
        for i in range(16):
            spk = cs.synthetic_pk(cs.pk_bytes(cs.wallet_sk(MASTER_SK, i)))
            assert spk == bytes.fromhex(VEC["SYNTH_PK"][i]), f"index {i}"

    def test_pk_of_synthetic_sk(self):
        # pk(synthetic_sk) == synthetic_pk for all 16
        for i in range(16):
            ssk = cs.synthetic_sk(cs.wallet_sk(MASTER_SK, i))
            assert cs.pk_bytes(ssk) == bytes.fromhex(VEC["SYNTH_PK"][i])

    def test_signed_mod_high_bit(self):
        # Regression: digest with high bit set must use SIGNED reduction.
        # Index 0 synthetic offset digest starts with 0x92 (high bit set).
        wpk0 = cs.pk_bytes(cs.wallet_sk(MASTER_SK, 0))
        offset = cs.synthetic_offset(wpk0)
        assert offset.hex() == \
            "068e26c5041afd4fe72b15433030260602e52bcfb7ec8ba69b3c028772ba7323"


class TestPuzzle:
    def test_module_hash(self):
        assert cs.sha256tree(cs.deser(
            cs.P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE)).hex() == \
            "e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52"

    def test_module_parses(self):
        mod = cs.deser(cs.P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE)
        assert cs.ser(mod) == cs.P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE

    def test_puzzle_hash_deterministic(self):
        spk = bytes.fromhex(VEC["SYNTH_PK"][0])
        assert cs.puzzle_hash_for_synthetic_pk(spk) == \
            cs.puzzle_hash_for_synthetic_pk(spk)

    def test_puzzle_hash_differs_per_key(self):
        assert cs.puzzle_hash_for_synthetic_pk(
            bytes.fromhex(VEC["SYNTH_PK"][0])) != \
            cs.puzzle_hash_for_synthetic_pk(bytes.fromhex(VEC["SYNTH_PK"][1]))

    def test_reveal_runs(self):
        # Curried reveal executes and emits AGG_SIG_ME + conditions
        from chia_rs import run_chia_program
        spk = bytes.fromhex(VEC["SYNTH_PK"][0])
        conds = cs._list([cs._list([b"\x01"])])
        sol = cs.ser(cs._list([cs.NIL, cs.quote(conds), cs.NIL]))
        reveal = cs.standard_puzzle_reveal(spk)
        cost, out = run_chia_program(reveal, sol, 11000000000, 0)

        def to_py(n):
            if n.atom is not None:
                return n.atom
            a, b = n.pair
            return (to_py(a), to_py(b))

        def as_list(t):
            items = []
            while isinstance(t, tuple):
                items.append(t[0])
                t = t[1]
            return items

        conditions = as_list(to_py(out))
        c0 = as_list(conditions[0])
        assert int.from_bytes(c0[0], "big") == 50  # AGG_SIG_ME
        assert c0[1] == spk
        assert c0[2] == cs.sha256tree(cs.quote(conds))

    def test_address_roundtrip(self):
        spk = bytes.fromhex(VEC["SYNTH_PK"][0])
        ph = cs.puzzle_hash_for_synthetic_pk(spk)
        addr = cs.address_for_puzzle_hash(ph, "txch")
        assert addr.startswith("txch1")
        assert cs.puzzle_hash_for_address(addr) == ph

    def test_bad_address_rejected(self):
        with pytest.raises(ChiaSignError):
            cs.puzzle_hash_for_address("txch1invalid")
        with pytest.raises(ChiaSignError):
            cs.address_for_puzzle_hash(b"short", "txch")


class TestCoinAndConditions:
    def test_coin_id(self):
        cid = cs.coin_id(bytes(32), bytes(32), 1000)
        assert len(cid) == 32
        assert cid != cs.coin_id(bytes(32), bytes(32), 1001)

    def test_coin_id_bad_inputs(self):
        with pytest.raises(ChiaSignError):
            cs.coin_id(b"short", bytes(32), 1)
        with pytest.raises(ChiaSignError):
            cs.coin_id(bytes(32), bytes(32), -1)

    def test_coin_id_uses_chia_int_to_bytes(self):
        # Regression: coin_id must use Chia's int_to_bytes (minimal signed
        # big-endian) for the amount, matching Coin.name(), NOT fixed 8-byte
        # big-endian. The wrong encoding produces a coin_id the network
        # rejects with BAD_AGGREGATE_SIGNATURE (2026-09-21).
        import hashlib
        parent = bytes([2]) * 32
        ph = bytes([3]) * 32
        # 1000000 = 0x0F4240 -> int_to_bytes gives 3 bytes, not 8
        assert cs.int_to_bytes(1000000) == bytes.fromhex("0f4240")
        expected = hashlib.sha256(parent + ph + bytes.fromhex("0f4240")).digest()
        assert cs.coin_id(parent, ph, 1000000) == expected
        # Wrong (old) encoding would be 8-byte; ensure we don't match it
        wrong = hashlib.sha256(parent + ph + (1000000).to_bytes(8, "big")).digest()
        assert cs.coin_id(parent, ph, 1000000) != wrong
        # Edge: 128 needs a leading zero byte in signed encoding
        assert cs.int_to_bytes(128) == bytes.fromhex("0080")
        assert cs.coin_id(parent, ph, 128) == hashlib.sha256(
            parent + ph + bytes.fromhex("0080")).digest()

    def test_create_coin_conditions(self):
        ph = bytes([1]) * 32
        conds = cs.conditions_from_outputs([(ph, 1000)])
        assert len(conds) == 1

    def test_negative_change_rejected(self):
        # build_standard_spend validates amounts; negative outputs rejected
        # at the conditions layer via amount checks
        with pytest.raises(ChiaSignError):
            cs.conditions_from_outputs([(bytes(32), -1)])


class TestSigning:
    def _spend(self, index=0):
        wsk = cs.wallet_sk(MASTER_SK, index)
        spk = cs.synthetic_pk(cs.pk_bytes(wsk))
        ph = cs.puzzle_hash_for_synthetic_pk(spk)
        coin = (bytes(32), ph, 1_000_000_000_000)
        outputs = [(ph, 999_999_999_000), (ph, 1_000)]
        return cs.build_standard_spend(MASTER_SK, index, coin, outputs,
                                       "testnet11"), spk, coin, outputs

    def test_build_and_self_verify(self):
        spend, spk, coin, outputs = self._spend()
        assert len(spend["signature"]) == 96
        assert len(spend["puzzle_reveal"]) > 200
        assert len(spend["solution"]) > 0

    def test_external_bls_verify(self):
        from blspy import AugSchemeMPL, G1Element, G2Element
        spend, spk, coin, outputs = self._spend()
        conds = cs._list(cs.conditions_from_outputs(outputs))
        cid = cs.coin_id(*coin)
        msg = cs.sha256tree(cs.quote(conds)) + cid + TESTNET11_GENESIS
        ok = AugSchemeMPL.verify(G1Element.from_bytes(spk), msg,
                                 G2Element.from_bytes(spend["signature"]))
        assert ok

    def test_wrong_key_fails(self):
        from blspy import AugSchemeMPL, G1Element, G2Element
        spend, spk, coin, outputs = self._spend(index=0)
        # Verify with a DIFFERENT key must fail
        other_spk = cs.synthetic_pk(
            cs.pk_bytes(cs.wallet_sk(MASTER_SK, 1)))
        conds = cs._list(cs.conditions_from_outputs(outputs))
        cid = cs.coin_id(*coin)
        msg = cs.sha256tree(cs.quote(conds)) + cid + TESTNET11_GENESIS
        ok = AugSchemeMPL.verify(G1Element.from_bytes(other_spk), msg,
                                 G2Element.from_bytes(spend["signature"]))
        assert not ok

    def test_wrong_network_fails(self):
        # Mainnet genesis must not verify a testnet11 signature
        from blspy import AugSchemeMPL, G1Element, G2Element
        spend, spk, coin, outputs = self._spend()
        conds = cs._list(cs.conditions_from_outputs(outputs))
        cid = cs.coin_id(*coin)
        mainnet_genesis = bytes(32)  # placeholder; must differ
        assert mainnet_genesis != TESTNET11_GENESIS
        msg = cs.sha256tree(cs.quote(conds)) + cid + mainnet_genesis
        ok = AugSchemeMPL.verify(G1Element.from_bytes(spk), msg,
                                 G2Element.from_bytes(spend["signature"]))
        assert not ok

    def test_coin_mismatch_rejected(self):
        wsk = cs.wallet_sk(MASTER_SK, 0)
        spk = cs.synthetic_pk(cs.pk_bytes(wsk))
        ph = cs.puzzle_hash_for_synthetic_pk(spk)
        bad_coin = (bytes(32), bytes(32), 1000)  # wrong puzzle hash
        with pytest.raises(ChiaSignError):
            cs.build_standard_spend(MASTER_SK, 0, bad_coin,
                                    [(ph, 1000)], "testnet11")

    def test_spend_bundle_serialization(self):
        spend, spk, coin, outputs = self._spend()
        bundle = cs.build_spend_bundle([spend])
        assert len(bundle) > 500
        # Must start with list length prefix (Streamable)
        assert bundle[:4] == (1).to_bytes(4, "big")


class TestStreamable:
    def test_coin_spend_roundtrip(self):
        coin = (bytes([2]) * 32, bytes([3]) * 32, 12345)
        reveal = b"reveal-bytes"
        solution = b"solution-bytes"
        raw = cs.coin_spend_bytes(coin, reveal, solution)
        assert len(raw) > 0

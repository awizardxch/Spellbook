"""The daemon as the THIRD KDF implementation (SPEC §10 step 2).

Reproduces every vector in vectors/vectors.json byte-for-byte from the
published test seed, using only the installed `spellbook` package.
Any mismatch fails — and blocks the install (install.sh runs this gate).
"""
import json
import os

import pytest

from spellbook import kdf
from spellbook.seed import entropy_from_mnemonic

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "vectors", "vectors.json")
VECTORS = json.load(open(VECTORS_PATH))["vectors"]
POSITIVE = [v for v in VECTORS if "expected_failure" not in v]
NEGATIVE = {v["vector_id"]: v for v in VECTORS if "expected_failure" in v}

TEST_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                          "101112131415161718191a1b1c1d1e1f")


def test_vector_set_shape():
    assert len(POSITIVE) == 6, f"expected 6 positive vectors, got {len(POSITIVE)}"
    assert len(NEGATIVE) == 4, f"expected 4 negative vectors, got {len(NEGATIVE)}"


@pytest.mark.parametrize("v", POSITIVE, ids=lambda v: v["vector_id"])
def test_positive_vector(v):
    seed = bytes.fromhex(v["test_seed_hex"])
    d = kdf.derive_labeled(seed, v["chain"], v["label"])
    assert d["domain_tag"] == v["domain_tag"]
    assert d["scalar_hex"] == v["expected_scalar_hex"]
    assert d["ctr_used"] == v["ctr_used"]
    assert d["resampled"] == v["resampled"]
    if v["chain"].startswith("evm-"):
        assert d["pubkey_hex"] == v["expected_pubkey_hex"]
        assert d["address"] == v["expected_address"]
    else:
        assert d["pubkey_hex"] == v["expected_master_pubkey_hex"]


def test_negative_short_seed():
    v = NEGATIVE["kdf-negative-short-seed"]
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        kdf.derive_scalar(bytes.fromhex(v["test_seed_hex"]), "evm-4663", "default")


def test_negative_secp256k1_scalar_at_order():
    # S12: a candidate equal to the curve order is REJECTED, never reduced.
    v = NEGATIVE["kdf-negative-secp256k1-scalar-at-order"]
    n = int(v["scalar_hex"], 16)
    assert n == kdf.SECP256K1_N
    with pytest.raises(ValueError, match="out of range"):
        kdf.secp256k1_pubkey_uncompressed(n)


def test_negative_bls_scalar_zero():
    with pytest.raises(ValueError, match="out of range"):
        kdf.bls_g1_pubkey(0)


def test_negative_bip39_checksum():
    v = NEGATIVE["kdf-negative-bip39-checksum"]
    with pytest.raises(ValueError, match="[Cc]hecksum"):
        entropy_from_mnemonic(v["mnemonic"])
    # Sanity: the canonical valid zero-entropy mnemonics decode cleanly.
    assert entropy_from_mnemonic("abandon " * 11 + "about") == bytes(16)
    assert entropy_from_mnemonic(
        ("abandon " * 23 + "art").strip()) == bytes(32)


def test_bip39_roundtrip():
    from spellbook.seed import mnemonic_from_entropy
    for n in (16, 24, 32):
        ent = bytes(range(n))
        assert entropy_from_mnemonic(mnemonic_from_entropy(ent)) == ent


def test_pubkey_address_consistency():
    # EVM address is always keccak256(pubkey)[-20:], recomputed independently.
    from Crypto.Hash import keccak
    d = kdf.derive_labeled(TEST_SEED, "evm-46630", "default")
    pub = bytes.fromhex(d["pubkey_hex"])
    expect = "0x" + keccak.new(digest_bits=256, data=pub).hexdigest()[-40:]
    assert d["address"] == expect

"""Tests for Solana key management — all offline.

Covers:
  - SLIP-0010 ed25519 official test vectors (satoshilabs/slips slip-0010.md,
    "Test vector 1" and "Test vector 2").
  - RFC 8032 ed25519 sign vectors (TEST 1/2/3: pubkey derivation,
    deterministic signature bytes, verification).
  - base58 round-trip, cross-checked against solders' own base58.
  - Custom-KDF determinism: same seed+label -> same keypair; different
    network/label -> different keypair.
  - One-seed -> three-chains: Solana + EVM + Chia addresses from one
    fixed 32-byte seed are deterministic and pairwise distinct.
  - Standard mnemonic -> m/44'/501'/0'/0' cross-checked between solders'
    from_seed_and_derivation_path and our manual SLIP-0010.

Only published test vectors and throwaway seeds are used here — no real
wallet material.
"""

import os

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from spellbook import chia_sign, evm, kdf, solana, stdkeys

_H = 0x80000000

# ---------------------------------------------------------------------------
# SLIP-0010 official ed25519 vectors (slip-0010.md)
# ---------------------------------------------------------------------------

SLIP10_V1_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
# (path, private_hex, chain_hex)
SLIP10_V1 = [
    ((),  # chain m
     "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
     "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
    (((_H + 0),),  # m/0H
     "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
     "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"),
    (((_H + 0), (_H + 1)),  # m/0H/1H
     "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
     "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"),
    (((_H + 0), (_H + 1), (_H + 2)),  # m/0H/1H/2H
     "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
     "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c"),
    (((_H + 0), (_H + 1), (_H + 2), (_H + 2)),  # m/0H/1H/2H/2H
     "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
     "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc"),
    (((_H + 0), (_H + 1), (_H + 2), (_H + 2), (_H + 1000000000)),  # +1000000000H
     "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
     "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"),
]

SLIP10_V2_SEED = bytes.fromhex(
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29"
    "f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
SLIP10_V2 = [
    ((),  # chain m
     "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
     "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b"),
    (((_H + 0), (_H + 2147483647)),  # m/0H/2147483647H
     "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
     "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f"),
]


def test_slip10_master_vector1():
    priv, chain = solana.slip10_master(SLIP10_V1_SEED)
    assert priv.hex() == SLIP10_V1[0][1]
    assert chain.hex() == SLIP10_V1[0][2]


@pytest.mark.parametrize("path,priv_hex,chain_hex", SLIP10_V1)
def test_slip10_vector1_paths(path, priv_hex, chain_hex):
    priv, chain = solana.slip10_derive_path(SLIP10_V1_SEED, path)
    assert priv.hex() == priv_hex
    assert chain.hex() == chain_hex


@pytest.mark.parametrize("path,priv_hex,chain_hex", SLIP10_V2)
def test_slip10_vector2_paths(path, priv_hex, chain_hex):
    priv, chain = solana.slip10_derive_path(SLIP10_V2_SEED, path)
    assert priv.hex() == priv_hex
    assert chain.hex() == chain_hex


def test_slip10_derived_priv_is_valid_ed25519_seed():
    # The vector-1 master private key must produce the spec's public key
    # (spec: 00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed;
    # the leading 00 is the SLIP-0010 serialization prefix).
    priv = bytes.fromhex(SLIP10_V1[0][1])
    kp = Keypair.from_seed(priv)
    assert bytes(kp.pubkey()).hex() == \
        "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"


def test_slip10_rejects_non_hardened():
    with pytest.raises(solana.SolanaError):
        solana.slip10_derive_child(bytes(32), bytes(32), 0)


def test_slip10_rejects_bad_seed_length():
    with pytest.raises(solana.SolanaError):
        solana.slip10_master(bytes(15))  # below the 128-bit SLIP-0010 minimum
    with pytest.raises(solana.SolanaError):
        solana.slip10_master(bytes(65))


# ---------------------------------------------------------------------------
# RFC 8032 ed25519 vectors
# ---------------------------------------------------------------------------

# (secret_seed_hex, pubkey_hex, message_hex, signature_hex)
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", RFC8032)
def test_rfc8032_pubkey_sign_verify(seed_hex, pub_hex, msg_hex, sig_hex):
    kp = Keypair.from_seed(bytes.fromhex(seed_hex))
    assert bytes(kp.pubkey()).hex() == pub_hex
    msg = bytes.fromhex(msg_hex)
    sig = kp.sign_message(msg)
    # Deterministic per RFC 8032: bytes must match the vector exactly.
    assert bytes(sig).hex() == sig_hex
    assert sig.verify(kp.pubkey(), msg)
    assert solana.signature_valid(bytes(kp.pubkey()), msg, bytes(sig))


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", RFC8032)
def test_rfc8032_tampered_message_fails(seed_hex, pub_hex, msg_hex, sig_hex):
    kp = Keypair.from_seed(bytes.fromhex(seed_hex))
    sig = bytes.fromhex(sig_hex)
    bad = bytearray(bytes.fromhex(msg_hex or "00"))
    bad[0] ^= 0x01
    assert not solana.signature_valid(bytes(kp.pubkey()), bytes(bad), sig)


# ---------------------------------------------------------------------------
# base58
# ---------------------------------------------------------------------------

def test_base58_round_trip():
    cases = [b"\x00", b"\x00\x00\x00", bytes(32), os.urandom(32),
             b"\x00\x01\x02" + os.urandom(29), bytes.fromhex("ff" * 32)]
    # Note: b"" is intentionally excluded — b58decode("") is fail-closed
    # (a Solana address/blockhash/signature is never empty).
    for raw in cases:
        assert solana.b58decode(solana.b58encode(raw)) == raw


def test_base58_matches_solders():
    # Cross-check our encoder against solders' own base58 (str(Pubkey)).
    for _ in range(8):
        raw = os.urandom(32)
        assert solana.b58encode(raw) == str(Pubkey.from_bytes(raw))
        assert solana.b58decode(str(Pubkey.from_bytes(raw))) == raw


def test_base58_known_values():
    assert solana.b58encode(bytes(32)) == "1" * 32
    assert solana.b58encode(b"\x00\x00abc") == "11" + solana.b58encode(b"abc")
    assert solana.b58decode("11111111111111111111111111111111") == bytes(32)


def test_base58_rejects_bad_input():
    with pytest.raises(solana.SolanaError):
        solana.b58decode("0OIl")  # not in the Bitcoin alphabet
    with pytest.raises(solana.SolanaError):
        solana.b58decode("")


# ---------------------------------------------------------------------------
# Custom-KDF mode
# ---------------------------------------------------------------------------

FIXED_SEED = bytes.fromhex("ab" * 32)


def test_custom_kdf_deterministic():
    a = solana.custom_keypair(FIXED_SEED, "solana-devnet", "default")
    b = solana.custom_keypair(FIXED_SEED, "solana-devnet", "default")
    assert solana.address_of_keypair(a) == solana.address_of_keypair(b)
    assert a.to_bytes() == b.to_bytes()


def test_custom_kdf_network_separation():
    dev = solana.custom_keypair(FIXED_SEED, "solana-devnet", "default")
    main = solana.custom_keypair(FIXED_SEED, "solana-mainnet", "default")
    assert solana.address_of_keypair(dev) != solana.address_of_keypair(main)


def test_custom_kdf_label_separation():
    a = solana.custom_keypair(FIXED_SEED, "solana-devnet", "default")
    b = solana.custom_keypair(FIXED_SEED, "solana-devnet", "vault")
    assert solana.address_of_keypair(a) != solana.address_of_keypair(b)


def test_custom_kdf_domain_tag_shape():
    # The KDF domain must reuse kdf's labeled info-string construction.
    seed = solana.custom_seed(FIXED_SEED, "solana-devnet", "default")
    assert len(seed) == 32
    assert seed != FIXED_SEED
    with pytest.raises(solana.SolanaError):
        solana.custom_seed(FIXED_SEED, "solana-bogus", "default")
    with pytest.raises(solana.SolanaError):
        solana.custom_seed(bytes(31), "solana-devnet", "default")


def test_phantom_backup_format():
    kp = solana.custom_keypair(FIXED_SEED, "solana-devnet", "default")
    secret = solana.phantom_backup_secret(kp)
    raw = solana.b58decode(secret)
    assert len(raw) == 64
    # Phantom format: 32-byte seed || 32-byte pubkey.
    assert raw[:32] == solana.custom_seed(FIXED_SEED, "solana-devnet", "default")
    assert raw[32:] == solana.pubkey_bytes(kp)
    assert solana.b58decode(solana.address_of_keypair(kp)) == solana.pubkey_bytes(kp)


# ---------------------------------------------------------------------------
# One seed -> three chains
# ---------------------------------------------------------------------------

def _three_chains(seed: bytes):
    sol = solana.address_of_keypair(
        solana.custom_keypair(seed, "solana-devnet", "default"))
    evm_addr = kdf.derive_labeled(seed, "evm-46630", "default")["address"]
    chia_master = bytes.fromhex(
        kdf.derive_labeled(seed, "chia-testnet", "default")["scalar_hex"])
    chia_addr = chia_sign.receive_address(chia_master, 0, "testnet11")
    return sol, evm_addr, chia_addr


def test_one_seed_three_chains_deterministic_and_distinct():
    a = _three_chains(FIXED_SEED)
    b = _three_chains(FIXED_SEED)
    assert a == b  # deterministic
    sol, evm_addr, chia_addr = a
    assert sol and evm_addr and chia_addr
    assert len({sol, evm_addr, chia_addr}) == 3  # pairwise distinct
    assert evm_addr.startswith("0x") and len(evm_addr) == 42
    assert chia_addr.startswith("txch1")
    assert len(solana.b58decode(sol)) == 32


def test_standard_mode_three_chains_deterministic():
    # The same 24-word mnemonic feeds EVM (BIP-32), Chia (BLS key_gen) and
    # Solana (SLIP-0010) — the standard-mode one-seed picture.
    words = " ".join(["abandon"] * 23 + ["art"])
    seed64 = stdkeys.mnemonic_to_seed(words, "")
    sol1 = solana.address_of_keypair(solana.standard_keypair(seed64))
    sol2 = solana.address_of_keypair(solana.standard_keypair(seed64))
    assert sol1 == sol2
    evm_addr = stdkeys.evm_address(stdkeys.evm_privkey(seed64))
    master = stdkeys.chia_master_sk(seed64)
    chia_addr = chia_sign.receive_address(master, 0, "testnet11")
    assert len({sol1, evm_addr, chia_addr}) == 3
    # And standard Solana differs from KDF Solana for the same install.
    kdf_sol = solana.address_of_keypair(
        solana.custom_keypair(bytes(32), "solana-devnet", "default"))
    assert sol1 != kdf_sol


# ---------------------------------------------------------------------------
# Standard mnemonic -> m/44'/501'/0'/0': solders vs manual SLIP-0010
# ---------------------------------------------------------------------------

def test_standard_path_matches_solders_derivation():
    words = " ".join(["abandon"] * 23 + ["art"])
    seed64 = stdkeys.mnemonic_to_seed(words, "")
    manual = solana.standard_ed25519_seed(seed64)
    via_solders = Keypair.from_seed_and_derivation_path(
        seed64, "m/44'/501'/0'/0'")
    assert via_solders.to_bytes()[:32] == manual
    assert (solana.address_of_keypair(solana.standard_keypair(seed64))
            == str(via_solders.pubkey()))


def test_standard_path_matches_solders_second_seed():
    words = "test test test test test test test test test test test junk"
    seed64 = stdkeys.mnemonic_to_seed(words, "")
    manual = solana.standard_ed25519_seed(seed64)
    via_solders = Keypair.from_seed_and_derivation_path(
        seed64, "m/44'/501'/0'/0'")
    assert via_solders.to_bytes()[:32] == manual

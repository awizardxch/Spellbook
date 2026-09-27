"""Tests for the standards-based recovery wallet (SPEC §2b).

Covers:
  - BIP-39 mnemonic validation + seed derivation against the published
    trezor/python-mnemonic vectors (24-word and 12-word).
  - BLS key_gen (blspy) against an independent hand-rolled implementation
    of the same KDF — the function Sage applies to an imported mnemonic.
  - BIP-32 m/44'/60'/0'/0/0 against bip32utils-verified values and the
    canonical Hardhat account #0 vector (mnemonic "test ... junk" ->
    0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266).
  - Daemon wiring: key_derivation=kdf (default, existing behavior
    untouched) vs key_derivation=standard (daemon derives + signs with the
    standard keys; refuses to start without std_seed_path).

Only published test vectors and throwaway keys are used here — no real
wallet material.
"""

import hashlib
import hmac
import json
import os
import tempfile

import pytest

from spellbook import chia_sign, kdf, stdkeys
from spellbook.daemon import Daemon
from spellbook.seed import mnemonic_from_entropy

# ---------------------------------------------------------------------------
# Published vectors
# ---------------------------------------------------------------------------

# trezor/python-mnemonic vectors.json (passphrase "TREZOR" throughout).
VEC24_WORDS = " ".join(["abandon"] * 23 + ["art"])
VEC24_ENTROPY = bytes(32)
VEC24_SEED = bytes.fromhex(
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
    "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8")
VEC12_WORDS = " ".join(["abandon"] * 11 + ["about"])
VEC12_ENTROPY = bytes(16)
# First 32 bytes of the published 64-byte seed (enough to pin the KDF input).
VEC12_SEED_PREFIX = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"

# Hardhat/Anvil default account #0: the canonical BIP-44 Ethereum vector.
HARDHAT_WORDS = "test test test test test test test test test test test junk"
HARDHAT_PRIV = ("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
HARDHAT_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
# Second seed, private key independently produced by bip32utils from the
# same BIP-39 seed (cross-implementation check, not self-derived).
VEC24_TREZOR_PRIV = ("f9399e5d4ddb63856a95268e2806def3ea55c1fcac22f90a5de3a72667a9408c")

BLS_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


def _bls_key_gen_reference(ikm: bytes) -> bytes:
    """Independent BLS KeyGen, hand-rolled (IETF CFRG draft, which blspy
    implements and Sage/chiapos uses for imported mnemonics).

    PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1));
    OKM = HKDF-Expand(PRK, I2OSP(48, 2), 48); SK = OS2IP(OKM) mod r.
    (No salt-evolution retry loop — matching blspy exactly.)
    """
    def i2osp(x, ln):
        return x.to_bytes(ln, "big")

    def hkdf_extract(salt, msg):
        return hmac.new(salt, msg, hashlib.sha256).digest()

    def hkdf_expand(prk, info, ln):
        okm, prev, ctr = b"", b"", 1
        while len(okm) < ln:
            prev = hmac.new(prk, prev + info + bytes([ctr]),
                            hashlib.sha256).digest()
            okm += prev
            ctr += 1
        return okm[:ln]

    prk = hkdf_extract(b"BLS-SIG-KEYGEN-SALT-", ikm + i2osp(0, 1))
    okm = hkdf_expand(prk, i2osp(48, 2), 48)
    sk = int.from_bytes(okm, "big") % BLS_ORDER
    assert sk != 0, "key_gen produced zero"
    return sk.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# BIP-39
# ---------------------------------------------------------------------------

def test_bip39_24word_vector():
    assert mnemonic_from_entropy(VEC24_ENTROPY) == VEC24_WORDS
    assert stdkeys.validate_mnemonic(VEC24_WORDS) == VEC24_ENTROPY
    assert stdkeys.mnemonic_to_seed(VEC24_WORDS, "TREZOR") == VEC24_SEED


def test_bip39_12word_vector():
    assert stdkeys.validate_mnemonic(VEC12_WORDS) == VEC12_ENTROPY
    seed = stdkeys.mnemonic_to_seed(VEC12_WORDS, "TREZOR")
    assert len(seed) == 64
    assert seed.hex().startswith(VEC12_SEED_PREFIX)


def test_bip39_rejects_bad_checksum():
    words = VEC24_WORDS.split()
    words[-1] = "zoo"  # valid word, wrong checksum
    with pytest.raises(stdkeys.StdKeysError):
        stdkeys.validate_mnemonic(" ".join(words))


def test_bip39_rejects_unknown_word():
    with pytest.raises(stdkeys.StdKeysError):
        stdkeys.validate_mnemonic(" ".join(["abandon"] * 23 + ["notaword"]))


def test_bip39_rejects_bad_length():
    with pytest.raises(stdkeys.StdKeysError):
        stdkeys.validate_mnemonic(" ".join(["abandon"] * 13))


def test_bip39_round_trip_random_entropy():
    entropy = os.urandom(32)
    words = mnemonic_from_entropy(entropy)
    assert stdkeys.validate_mnemonic(words) == entropy
    assert len(stdkeys.mnemonic_to_seed(words)) == 64


# ---------------------------------------------------------------------------
# BLS key_gen (Chia master key — what Sage derives from an imported mnemonic)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ikm", [
    bytes(64),
    bytes.fromhex("01" * 64),
    VEC24_SEED,                       # the published BIP-39 vector seed
    os.urandom(64),
])
def test_bls_key_gen_matches_reference(ikm):
    got = stdkeys.chia_master_sk(ikm)
    assert got == _bls_key_gen_reference(ikm)
    assert 0 < int.from_bytes(got, "big") < BLS_ORDER


def test_bls_key_gen_rejects_bad_seed_length():
    with pytest.raises(stdkeys.StdKeysError):
        stdkeys.chia_master_sk(bytes(32))


def test_chia_addresses_derive_through_standard_pipeline():
    # The master key feeds the daemon's existing, vector-tested wallet path
    # [12381, 8444, 2, index] + synthetic key — the same pipeline Sage uses.
    master = stdkeys.chia_master_sk(VEC24_SEED)
    txch = chia_sign.receive_address(master, 0, "testnet11")
    xch = chia_sign.receive_address(master, 0, "mainnet")
    assert txch.startswith("txch1") and xch.startswith("xch1")
    # Only the HRP differs between networks for one standard wallet.
    assert (chia_sign.puzzle_hash_for_address(txch)
            == chia_sign.puzzle_hash_for_address(xch))


# ---------------------------------------------------------------------------
# BIP-32 m/44'/60'/0'/0/0 (EVM — what MetaMask derives from a mnemonic)
# ---------------------------------------------------------------------------

def test_bip32_hardhat_vector():
    seed = stdkeys.mnemonic_to_seed(HARDHAT_WORDS, "")
    priv = stdkeys.evm_privkey(seed)
    assert priv.hex() == HARDHAT_PRIV
    assert stdkeys.evm_address(priv).lower() == HARDHAT_ADDR.lower()


def test_bip32_matches_independent_implementation():
    seed = stdkeys.mnemonic_to_seed(VEC24_WORDS, "TREZOR")
    assert stdkeys.evm_privkey(seed).hex() == VEC24_TREZOR_PRIV


def test_bip32_rejects_bad_seed_length():
    with pytest.raises(stdkeys.StdKeysError):
        stdkeys.evm_privkey(bytes(32))


# ---------------------------------------------------------------------------
# Daemon wiring: kdf (default) vs standard
# ---------------------------------------------------------------------------

def _write(path, data, mode=0o600):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)


def _config_dir(key_derivation=None, with_std_seed=True):
    tmp = tempfile.mkdtemp(prefix="spellbook-stdkeys-test-")
    seed_hex = "00" * 32
    _write(os.path.join(tmp, "seed.key"), seed_hex)
    cfg = {"seed_path": os.path.join(tmp, "seed.key"),
           "labels": ["default"]}
    if key_derivation is not None:
        cfg["key_derivation"] = key_derivation
    if with_std_seed:
        std_hex = stdkeys.mnemonic_to_seed(VEC24_WORDS, "").hex()
        _write(os.path.join(tmp, "std_seed.key"), std_hex)
        cfg["std_seed_path"] = os.path.join(tmp, "std_seed.key")
    _write(os.path.join(tmp, "spellbook.json"), json.dumps(cfg))
    _write(os.path.join(tmp, "policy.json"), json.dumps({}))
    _write(os.path.join(tmp, "ledger.jsonl"), "")
    _write(os.path.join(tmp, "request.token"), "11" * 32)
    _write(os.path.join(tmp, "approve.token"), "22" * 32)
    return tmp


def test_daemon_defaults_to_kdf():
    d = Daemon(_config_dir())
    assert d.key_derivation == "kdf"
    assert d.std_seed is None
    priv, addr = d._evm_key("evm-4663")
    exp = kdf.derive_labeled(bytes(32), "evm-4663", "default")
    assert priv == bytes.fromhex(exp["scalar_hex"])
    assert addr == exp["address"]
    msk = d._chia_master_sk("chia-testnet")
    exp_c = kdf.derive_labeled(bytes(32), "chia-testnet", "default")
    assert msk == bytes.fromhex(exp_c["scalar_hex"])


def test_daemon_standard_mode_uses_standard_keys():
    d = Daemon(_config_dir(key_derivation="standard"))
    assert d.key_derivation == "standard"
    seed64 = stdkeys.mnemonic_to_seed(VEC24_WORDS, "")
    priv, addr = d._evm_key("evm-4663")
    assert priv == stdkeys.evm_privkey(seed64)
    assert addr == stdkeys.evm_address(priv)
    # Same 0x address on every EVM chain, as with MetaMask.
    assert d._evm_key("evm-46630")[1] == addr
    msk = d._chia_master_sk("chia-testnet")
    assert msk == stdkeys.chia_master_sk(seed64)
    # One BLS master key for both Chia networks.
    assert d._chia_master_sk("chia-mainnet") == msk
    # Standard keys differ from the KDF keys for the same install.
    kdf_priv, _ = Daemon(_config_dir())._evm_key("evm-4663")
    assert priv != kdf_priv


def test_daemon_standard_mode_addresses():
    d = Daemon(_config_dir(key_derivation="standard"))
    out = d.rt_addresses({}, "muse_test")
    assert out["ok"]
    per = out["addresses"]["default"]
    seed64 = stdkeys.mnemonic_to_seed(VEC24_WORDS, "")
    evm_addr = stdkeys.evm_address(stdkeys.evm_privkey(seed64))
    master = stdkeys.chia_master_sk(seed64)
    assert per["evm-4663"] == evm_addr
    assert per["evm-46630"] == evm_addr
    assert per["chia-testnet"] == chia_sign.receive_address(master, 0, "testnet11")
    assert per["chia-mainnet"] == chia_sign.receive_address(master, 0, "mainnet")


def test_daemon_signing_seed_follows_mode():
    kdf_d = Daemon(_config_dir())
    assert kdf_d._signing_seed() == kdf_d.seed
    std_d = Daemon(_config_dir(key_derivation="standard"))
    assert std_d._signing_seed() == std_d.std_seed
    # Standard mode never draws keys from the KDF seed.
    assert std_d._evm_key("evm-4663")[0] != kdf_d._evm_key("evm-4663")[0]


def test_daemon_standard_mode_without_kdf_seed():
    # Standard mode works with only the BIP-39 seed present: the spend
    # guards check the active signing seed, not the KDF seed.
    tmp = _config_dir(key_derivation="standard")
    cfg_path = os.path.join(tmp, "spellbook.json")
    cfg = json.load(open(cfg_path))
    del cfg["seed_path"]
    os.remove(os.path.join(tmp, "seed.key"))
    json.dump(cfg, open(cfg_path, "w"))
    d = Daemon(tmp)
    assert d.seed is None
    assert d._signing_seed() == d.std_seed
    out = d.rt_addresses({}, "muse_test")
    assert out["ok"] and out["addresses"]["default"]["evm-4663"].startswith("0x")


def test_daemon_standard_mode_requires_std_seed_path():
    with pytest.raises(ValueError):
        Daemon(_config_dir(key_derivation="standard", with_std_seed=False))
    with pytest.raises(ValueError):
        Daemon(_config_dir(key_derivation="standard", with_std_seed=False))


def test_daemon_rejects_bad_key_derivation():
    with pytest.raises(ValueError):
        Daemon(_config_dir(key_derivation="bogus"))


def test_daemon_standard_mode_signs_chia_spend():
    # The standard master key flows through the real local signing
    # pipeline (build + self-verify), so it is a usable signing key, not
    # just an address generator.
    d = Daemon(_config_dir(key_derivation="standard"))
    master = d._chia_master_sk("chia-testnet")
    wsk = chia_sign.wallet_sk(master, 0)
    spk = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk))
    ph = chia_sign.puzzle_hash_for_synthetic_pk(spk)
    parent = bytes(32)
    coin = (parent, ph, 1_000_000)
    dest_ph = bytes.fromhex("11" * 32)
    spend = chia_sign.build_standard_spend(
        master, 0, coin, [(dest_ph, 999_000), (ph, 1_000)], "testnet11")
    assert len(spend["signature"]) == 96
    bundle = chia_sign.build_spend_bundle([spend])
    assert len(bundle) > 96

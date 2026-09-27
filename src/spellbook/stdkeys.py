"""Standards-based key derivation for the Spellbook daemon (SPEC §2b).

Alongside the daemon's custom labeled KDF (kdf.py), every install also
carries a *standard recovery* wallet: one BIP-39 24-word mnemonic whose
keys derive exactly the way stock wallets do, so the same words load
directly in Sage (Chia) and MetaMask (EVM):

  - Chia master BLS key: BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds,
    salt "mnemonic"+passphrase, empty passphrase at install) -> BLS
    ``key_gen`` (HKDF with salt "BLS-SIG-KEYGEN-SALT-", as implemented by
    blspy) — the exact function Sage/chiapos applies to an imported
    mnemonic. Wallet keys then follow the standard Chia path
    [12381, 8444, 2, index] + synthetic key (chia_sign.py) — the same
    pipeline Sage uses, so the first receive address matches what Sage
    shows.
  - EVM key: the same 64-byte BIP-39 seed -> BIP-32 master ->
    m/44'/60'/0'/0/0, the first account MetaMask derives when importing a
    mnemonic (and the same key a raw-private-key import yields).

The daemon selects this derivation when ``key_derivation: "standard"`` is
set in spellbook.json (new installs); ``"kdf"`` (default) keeps the
existing custom-KDF behavior byte-for-byte, so existing wallets are
untouched.

No key material is ever logged. Errors never carry secrets.
"""

import hashlib
import hmac
import unicodedata

from blspy import AugSchemeMPL
from coincurve import PrivateKey as SecpPrivateKey

from spellbook import evm
from spellbook.seed import bip39_wordlist

# secp256k1 group order (BIP-32 arithmetic).
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_WORD_INDEX = None


def _word_index() -> dict:
    global _WORD_INDEX
    if _WORD_INDEX is None:
        _WORD_INDEX = {w: i for i, w in enumerate(bip39_wordlist())}
    return _WORD_INDEX


class StdKeysError(Exception):
    """Any standards-derivation failure. Never carries key material."""


# ---------------------------------------------------------------------------
# BIP-39: mnemonic <-> entropy, mnemonic -> seed
# ---------------------------------------------------------------------------

def validate_mnemonic(mnemonic: str) -> bytes:
    """Checksum-validate a BIP-39 mnemonic; return the raw entropy bytes.

    Accepts 12/15/18/21/24 words. Fail-closed on unknown words, bad
    length, or a checksum mismatch.
    """
    words = mnemonic.strip().split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise StdKeysError("mnemonic must be 12/15/18/21/24 words")
    idx = _word_index()
    try:
        vals = [idx[w] for w in words]
    except KeyError:
        raise StdKeysError("mnemonic contains a word outside the BIP-39 list")
    total_bits = len(words) * 11
    cs_bits = total_bits // 33
    ent_bits = total_bits - cs_bits
    acc = 0
    for v in vals:
        acc = (acc << 11) | v
    entropy = (acc >> cs_bits).to_bytes(ent_bits // 8, "big")
    checksum = acc & ((1 << cs_bits) - 1)
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    if checksum != expected:
        raise StdKeysError("mnemonic checksum mismatch")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase).

    2048 rounds, 64 bytes out. The mnemonic is checksum-validated first.
    """
    validate_mnemonic(mnemonic)  # fail-closed before any key material exists
    mn = unicodedata.normalize("NFKD", " ".join(mnemonic.strip().split()))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac(
        "sha512", mn.encode("utf-8"), salt.encode("utf-8"), 2048, 64)


# ---------------------------------------------------------------------------
# Chia: BLS key_gen master key (what Sage derives from an imported mnemonic)
# ---------------------------------------------------------------------------

def chia_master_sk(seed64: bytes) -> bytes:
    """32-byte BLS master secret via BLS ``key_gen`` (blspy, audited).

    This is the exact function chiapos/Sage applies to the BIP-39 seed of
    an imported mnemonic (HKDF-Extract with salt "BLS-SIG-KEYGEN-SALT-",
    then HKDF-Expand to 48 bytes, mod r), so the returned key imported
    into Sage (raw BLS private key) yields the same wallet the daemon
    derives locally.
    """
    if len(seed64) != 64:
        raise StdKeysError("BIP-39 seed must be 64 bytes")
    sk = AugSchemeMPL.key_gen(seed64)
    out = bytes(sk)
    if len(out) != 32 or int.from_bytes(out, "big") == 0:
        raise StdKeysError("key_gen produced an invalid secret")
    return out


# ---------------------------------------------------------------------------
# EVM: BIP-32 m/44'/60'/0'/0/0 (what MetaMask derives from an imported mnemonic)
# ---------------------------------------------------------------------------

def _bip32_master(seed64: bytes) -> tuple:
    """BIP-32 master (priv_bytes, chain_code) from the 64-byte seed."""
    if len(seed64) != 64:
        raise StdKeysError("BIP-39 seed must be 64 bytes")
    i = hmac.new(b"Bitcoin seed", seed64, hashlib.sha512).digest()
    il, ir = i[:32], i[32:]
    k = int.from_bytes(il, "big")
    if k == 0 or k >= _SECP256K1_N:
        raise StdKeysError("BIP-32 master key out of range")
    return il, ir


def _bip32_ckd_priv(parent_priv: bytes, parent_chain: bytes, index: int) -> tuple:
    """One BIP-32 child: hardened if index >= 0x80000000. Returns (priv, chain)."""
    if not 0 <= index < 2**32:
        raise StdKeysError("BIP-32 index out of range")
    kp = int.from_bytes(parent_priv, "big")
    if not 0 < kp < _SECP256K1_N:
        raise StdKeysError("BIP-32 parent key out of range")
    if index >= 0x80000000:
        data = b"\x00" + parent_priv + index.to_bytes(4, "big")
    else:
        pub_compressed = SecpPrivateKey(parent_priv).public_key.format(compressed=True)
        data = pub_compressed + index.to_bytes(4, "big")
    i = hmac.new(parent_chain, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    if il >= _SECP256K1_N:
        raise StdKeysError("BIP-32 child key out of range")
    child = (il + kp) % _SECP256K1_N
    if child == 0:
        raise StdKeysError("BIP-32 derived the zero key")
    return child.to_bytes(32, "big"), i[32:]


# m / 44' / 60' / 0' / 0 / 0 — the first Ethereum account of a BIP-44 wallet.
EVM_PATH = (0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0)


def evm_privkey(seed64: bytes) -> bytes:
    """32-byte secp256k1 private key at m/44'/60'/0'/0/0.

    Importing this hex into MetaMask as a raw private key yields the same
    account as importing the mnemonic (MetaMask derives this exact path
    first).
    """
    priv, chain = _bip32_master(seed64)
    for index in EVM_PATH:
        priv, chain = _bip32_ckd_priv(priv, chain, index)
    return priv


def evm_address(priv: bytes) -> str:
    """0x address for a 32-byte secp256k1 private key (EIP-55-agnostic)."""
    if len(priv) != 32:
        raise StdKeysError("EVM private key must be 32 bytes")
    return evm.address_from_privkey(priv)

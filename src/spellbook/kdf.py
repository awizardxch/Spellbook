"""Spellbook §2 KDF — the daemon's key-derivation implementation.

HKDF-SHA256 (stdlib, RFC 5869) + reject/resample (S12: never reduce mod the
order) over labeled info strings, then audited curve libraries:

  - secp256k1 point multiply: coincurve (libsecp256k1 bindings)
  - BLS12-381 G1 multiply:    py_ecc
  - Keccak-256:               pycryptodome

This is the THIRD implementation of the KDF (after vectors/generate.mjs and
vectors/verify.py). It must reproduce vectors/vectors.json byte-for-byte —
see tests/test_kdf_vectors.py — before any real seed is derived
(SPEC §10 step 2).

No hand-rolled curve math lives here. Ever.
"""
import hmac
import hashlib

from coincurve import PrivateKey
from Crypto.Hash import keccak
from py_ecc.bls12_381 import G1, multiply as g1_multiply, curve_order as BLS_R

SALT = b"muse-wallet-v1"
INFO_PREFIX = "muse-wallet/v1/"

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# BLS12-381 G1 subgroup order (== BLS_R imported above).
BLS12_381_R = BLS_R

# Base field modulus, for G1 point compression (Zcash-style flags).
_FIELD_P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFE
_FIELD_P = (_FIELD_P << 96) | 0xB153FFFFB9FEFFFFFFFFAAAB

CHAINS = ("evm-4663", "evm-46630", "chia-mainnet", "chia-testnet")


def info_string(chain: str, label: str) -> str:
    if chain not in CHAINS:
        raise ValueError(f"unknown chain {chain!r}")
    if not label or "/" in label:
        raise ValueError(f"bad label {label!r}")
    return f"{INFO_PREFIX}{chain}/sign/{label}"


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, prev, ctr = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([ctr]), hashlib.sha256).digest()
        out += prev
        ctr += 1
    return out[:length]


def derive_scalar(seed: bytes, chain: str, label: str) -> tuple[int, int]:
    """Return (scalar, ctr_used). Reject/resample per S12: never reduce mod order."""
    if len(seed) != 32:
        raise ValueError("reject: seed must be exactly 32 bytes")
    order = SECP256K1_N if chain.startswith("evm-") else BLS12_381_R
    base = info_string(chain, label)
    ctr = 0
    while True:
        info = base if ctr == 0 else f"{base}/ctr/{ctr}"
        candidate = int.from_bytes(_hkdf(seed, SALT, info.encode(), 32), "big")
        if candidate != 0 and candidate < order:
            return candidate, ctr
        ctr += 1
        if ctr > 10_000:
            raise RuntimeError("resample loop did not terminate")


def secp256k1_pubkey_uncompressed(scalar: int) -> bytes:
    """64 bytes: x || y (no 0x04 prefix — matches the vector format)."""
    if not 0 < scalar < SECP256K1_N:
        raise ValueError("scalar out of range for secp256k1")
    return PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=False)[1:]


def evm_address(pubkey_uncompressed_64: bytes) -> str:
    """EIP-55-agnostic lowercase hex address (0x + 40 hex)."""
    if len(pubkey_uncompressed_64) != 64:
        raise ValueError("expected 64-byte uncompressed secp256k1 pubkey")
    digest = keccak.new(digest_bits=256, data=pubkey_uncompressed_64).digest()
    return "0x" + digest[-20:].hex()


def _g1_compress(pt) -> bytes:
    # Zcash-style compression: 0x80 | 0x20-parity(y) in the top bits of x.
    x, y = pt[0].n, pt[1].n
    if not (0 < x < _FIELD_P and 0 < y < _FIELD_P):
        raise ValueError("G1 point out of field range")
    flag = 0x80 | (0x20 if y > (_FIELD_P - 1) // 2 else 0x00)
    xb = x.to_bytes(48, "big")
    return bytes([xb[0] | flag]) + xb[1:]


def bls_g1_pubkey(scalar: int) -> bytes:
    """48-byte compressed G1 pubkey = scalar * G1 (Chia master pubkey)."""
    if not 0 < scalar < BLS12_381_R:
        raise ValueError("scalar out of range for BLS12-381")
    return _g1_compress(g1_multiply(G1, scalar))


def derive_labeled(seed: bytes, chain: str, label: str) -> dict:
    """Full labeled derivation for one (chain, label): scalar + pubkey material.

    Returns {chain, label, domain_tag, scalar_hex, ctr_used, resampled,
    pubkey_hex, address?}. `address` is present for EVM chains; Chia chains
    carry the 48-byte master pubkey hex instead (child/address derivation
    via Sage is a later step — SPEC §3).
    """
    scalar, ctr = derive_scalar(seed, chain, label)
    out = {
        "chain": chain,
        "label": label,
        "domain_tag": info_string(chain, label),
        "scalar_hex": format(scalar, "064x"),
        "ctr_used": ctr,
        "resampled": ctr > 0,
    }
    if chain.startswith("evm-"):
        pub = secp256k1_pubkey_uncompressed(scalar)
        out["pubkey_hex"] = pub.hex()
        out["address"] = evm_address(pub)
    else:
        out["pubkey_hex"] = bls_g1_pubkey(scalar).hex()
    return out

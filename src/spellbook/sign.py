"""Signing primitives — SPEC §4, §8 (P1).

Two fixed domain prefixes (P1): a Musebook signing string can never parse
as a directory entry, and the daemon never signs caller-supplied raw bytes.
The daemon builds every canonical string itself from typed fields.

Curves:
  - secp256k1 ECDSA over a 32-byte digest (EVM legacy/1559 sighash), RFC 6979,
    low-S normalized — via coincurve (libsecp256k1).
  - BLS (G2Basic ciphersuite) over arbitrary messages (Chia) — via py_ecc.

These primitives are exercised with test keys only. Wiring them to real
transaction submission is SPEC §10 phase 1, which needs its own authorization.
"""
import json

from coincurve import PrivateKey, PublicKey
from py_ecc.bls.ciphersuites import G2Basic as bls

from spellbook.kdf import SECP256K1_N, BLS12_381_R

MUSEBOOK_SIGN_PREFIX = "spellbook-musebook-request/v1/"
DIRECTORY_ENTRY_PREFIX = "spellbook-directory-entry/v1/"


def build_musebook_canonical(method: str, path: str, body: str) -> bytes:
    """The daemon builds the Musebook signing string itself (P1)."""
    if "\n" in method or "\n" in path:
        raise ValueError("method/path must not contain newlines")
    return (MUSEBOOK_SIGN_PREFIX + method + "\n" + path + "\n" + body).encode()


def build_directory_canonical(entry: dict) -> bytes:
    """Canonical directory-entry bytes (SPEC §8/O3). Distinct prefix (P1)."""
    if not isinstance(entry, dict):
        raise ValueError("entry must be an object")
    return (DIRECTORY_ENTRY_PREFIX
            + json.dumps(entry, sort_keys=True, separators=(",", ":"))).encode()


# ------------------------------------------------------- secp256k1 / EVM

def _check_secp_scalar(scalar: int):
    if not 0 < scalar < SECP256K1_N:
        raise ValueError("scalar out of range for secp256k1")


def _der_to_compact(der: bytes) -> bytes:
    """Strict minimal DER parse -> 64-byte r||s. Rejects anything exotic."""
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("bad DER signature")
    if der[2] != 0x02:
        raise ValueError("bad DER signature")
    rlen = der[3]
    r = der[4:4 + rlen]
    rest = der[4 + rlen:]
    if len(rest) < 2 or rest[0] != 0x02 or rest[1] != len(rest) - 2:
        raise ValueError("bad DER signature")
    s = rest[2:]
    if not 1 <= len(r) <= 33 or not 1 <= len(s) <= 33:
        raise ValueError("bad DER signature")
    return (int.from_bytes(r, "big").to_bytes(32, "big")
            + int.from_bytes(s, "big").to_bytes(32, "big"))


def _compact_to_der(sig64: bytes) -> bytes:
    def enc(x: bytes) -> bytes:
        x = x.lstrip(b"\x00") or b"\x00"
        if x[0] & 0x80:
            x = b"\x00" + x
        return b"\x02" + bytes([len(x)]) + x
    body = enc(sig64[:32]) + enc(sig64[32:])
    return b"\x30" + bytes([len(body)]) + body


def sign_secp256k1_digest(scalar: int, digest32: bytes) -> bytes:
    """Sign a 32-byte digest. Returns 64-byte compact r||s, low-S normalized."""
    _check_secp_scalar(scalar)
    if len(digest32) != 32:
        raise ValueError("digest must be 32 bytes")
    priv = PrivateKey(scalar.to_bytes(32, "big"))
    # hasher=None: digest32 is already the message hash (EVM sighash).
    # coincurve returns DER; normalize to compact and enforce low-S
    # (flipping s -> n-s keeps the signature valid).
    compact = _der_to_compact(priv.sign(digest32, hasher=None))
    r, s = int.from_bytes(compact[:32], "big"), int.from_bytes(compact[32:], "big")
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
        compact = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return compact


def verify_secp256k1_digest(pubkey_uncompressed_64: bytes, digest32: bytes,
                            sig64: bytes) -> bool:
    if len(pubkey_uncompressed_64) != 64 or len(sig64) != 64 or len(digest32) != 32:
        raise ValueError("bad lengths")
    pub = PublicKey(b"\x04" + pubkey_uncompressed_64)
    return pub.verify(_compact_to_der(sig64), digest32, hasher=None)


def is_low_s(sig64: bytes) -> bool:
    s = int.from_bytes(sig64[32:], "big")
    return s <= SECP256K1_N // 2


# ---------------------------------------------------------------- BLS / Chia

def _check_bls_scalar(scalar: int):
    if not 0 < scalar < BLS12_381_R:
        raise ValueError("scalar out of range for BLS12-381")


def bls_sign(scalar: int, message: bytes) -> bytes:
    """96-byte BLS signature (G2Basic)."""
    _check_bls_scalar(scalar)
    return bls.Sign(scalar, message)


def bls_verify(pubkey48: bytes, message: bytes, sig96: bytes) -> bool:
    if len(pubkey48) != 48 or len(sig96) != 96:
        raise ValueError("bad lengths")
    return bls.Verify(pubkey48, message, sig96)

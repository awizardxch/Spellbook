"""Signing primitives — verified by INDEPENDENT code paths.

secp256k1: signatures produced by coincurve (libsecp256k1) are verified by a
small pure-Python ECDSA verifier written for this test — no shared code with
sign.py. BLS: py_ecc's G2Basic ciphersuite cross-checked against the daemon's
manual G1 compression from kdf.py.
"""
import hashlib

import pytest

from spellbook import kdf
from spellbook import sign as spellsign

# ------------------------------------------------- pure-Python secp256k1 ECDSA verify
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a):
    return pow(a, P - 2, P)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    lam = ((y2 - y1) * _inv((x2 - x1) % P)) % P if p1 != p2 else \
        ((3 * x1 * x1) * _inv((2 * y1) % P)) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, pt=(Gx, Gy)):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def ecdsa_verify_independent(pub64: bytes, digest32: bytes, sig64: bytes) -> bool:
    """RFC 6979-independent ECDSA verification. Returns False, never raises,
    on bad signatures."""
    if len(pub64) != 64 or len(digest32) != 32 or len(sig64) != 64:
        return False
    x = int.from_bytes(pub64[:32], "big")
    y = int.from_bytes(pub64[32:], "big")
    if not (0 < x < P and 0 < y < P) or (y * y - (x * x * x + 7)) % P != 0:
        return False
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(digest32, "big")
    w = pow(s, N - 2, N)
    u1, u2 = (e * w) % N, (r * w) % N
    pt = _add(_mul(u1), _mul(u2, (x, y)))
    return pt is not None and pt[0] % N == r


SCALAR = int("9bf10efea92304c20034b09735b4f56f50976ee18d235e4bc529e8dac9bda8c7", 16)
DIGEST = hashlib.sha256(b"spellbook signing test").digest()


def test_ecdsa_signature_verifies_independently():
    pub = kdf.secp256k1_pubkey_uncompressed(SCALAR)
    sig = spellsign.sign_secp256k1_digest(SCALAR, DIGEST)
    assert len(sig) == 64
    assert spellsign.is_low_s(sig), "daemon must produce low-S signatures"
    assert spellsign.verify_secp256k1_digest(pub, DIGEST, sig)
    assert ecdsa_verify_independent(pub, DIGEST, sig)


def test_ecdsa_rejects_tampering():
    pub = kdf.secp256k1_pubkey_uncompressed(SCALAR)
    sig = spellsign.sign_secp256k1_digest(SCALAR, DIGEST)
    other_digest = hashlib.sha256(b"something else").digest()
    assert not ecdsa_verify_independent(pub, other_digest, sig)
    bad = bytearray(sig)
    bad[0] ^= 1
    assert not ecdsa_verify_independent(pub, DIGEST, bytes(bad))
    with pytest.raises(ValueError):
        spellsign.sign_secp256k1_digest(0, DIGEST)
    with pytest.raises(ValueError):
        spellsign.sign_secp256k1_digest(SCALAR, b"short")


def test_bls_sign_verify_roundtrip():
    from py_ecc.bls.ciphersuites import G2Basic as bls
    scalar = int("5f70b5c61e70ac0a93d5d46bc771f1f4246c2a37"
                 "00000000000000000000000000000001", 16) % kdf.BLS12_381_R
    assert scalar != 0
    msg = b"spellbook bls test"
    # The daemon's manual G1 compression must agree with py_ecc's SkToPk.
    assert kdf.bls_g1_pubkey(scalar) == bls.SkToPk(scalar)
    sig = spellsign.bls_sign(scalar, msg)
    assert len(sig) == 96
    assert spellsign.bls_verify(kdf.bls_g1_pubkey(scalar), msg, sig)
    assert not spellsign.bls_verify(kdf.bls_g1_pubkey(scalar), b"other", sig)
    with pytest.raises(ValueError):
        spellsign.bls_sign(0, msg)


def test_domain_prefix_separation():
    # P1: the two signing domains can never collide.
    a = spellsign.build_musebook_canonical("POST", "/api/post", "{}")
    b = spellsign.build_directory_canonical({"kind": "wallet", "body": "{}"})
    assert a != b
    assert a.startswith(spellsign.MUSEBOOK_SIGN_PREFIX.encode())
    assert b.startswith(spellsign.DIRECTORY_ENTRY_PREFIX.encode())
    # Same payload, different domain -> different signature.
    sig_a = spellsign.bls_sign(12345, a)
    sig_b = spellsign.bls_sign(12345, b)
    assert sig_a != sig_b

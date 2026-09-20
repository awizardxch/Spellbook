#!/usr/bin/env python3
"""
Spellbook KDF test-vector verifier — implementation #2 (Python, independent).

Re-derives every vector in vectors.json from scratch using a different
codebase than generate.mjs:
  - HKDF-SHA256: stdlib hmac/hashlib (RFC 5869, hand-rolled extract+expand)
  - secp256k1: pure-Python short-Weierstrass arithmetic (no noble, no libsecp)
  - keccak256: pycryptodome
  - BLS12-381 G1: py_ecc (scalar*G1, manual 48-byte compression)
  - BIP-39 checksum: real validation against bip39-english.txt

Usage: python3 verify.py [vectors.json]
Exit 0 = all vectors reproduce. Anything else = STOP (spec §2).
"""
import hmac, hashlib, json, sys

# ---------------------------------------------------------------- HKDF (RFC 5869)
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, L: int) -> bytes:
    out, t, ctr = b"", b"", 1
    while len(out) < L:
        t = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256).digest()
        out += t
        ctr += 1
    return out[:L]

def hkdf(ikm: bytes, salt: bytes, info: bytes, L: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, L)

# ---------------------------------------------------------------- secp256k1 (pure python)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0: return None
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def secp_mul(k: int):
    r, add = None, (Gx, Gy)
    while k:
        if k & 1: r = _add(r, add)
        add = _add(add, add)
        k >>= 1
    return r

# ---------------------------------------------------------------- BLS12-381 G1 (py_ecc)
from py_ecc.bls12_381 import G1, multiply, curve_order as BLS_R
FIELD_P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

def g1_compress(pt) -> bytes:
    x, y = pt[0].n, pt[1].n
    assert 0 < x < FIELD_P and 0 < y < FIELD_P
    flag = 0x80 | (0x20 if y > (FIELD_P - 1) // 2 else 0x00)
    xb = x.to_bytes(48, "big")
    return bytes([xb[0] | flag]) + xb[1:]

# ---------------------------------------------------------------- KDF per SPEC_V1.md §2
SALT = b"muse-wallet-v1"

def derive_scalar(seed: bytes, info: str, order: int):
    if len(seed) != 32:
        raise ValueError("reject: seed must be exactly 32 bytes")
    ctr = 0
    while True:
        tag = info if ctr == 0 else f"{info}/ctr/{ctr}"
        v = int.from_bytes(hkdf(seed, SALT, tag.encode(), 32), "big")
        if v != 0 and v < order:
            return v, ctr
        ctr += 1
        if ctr > 1000:
            raise AssertionError("resample loop exceeded 1000 tries")

# ---------------------------------------------------------------- BIP-39 checksum
WORDS = open("bip39-english.txt").read().split()
assert len(WORDS) == 2048

def bip39_valid(mnemonic: str) -> bool:
    w = mnemonic.split()
    if len(w) % 3 != 0:
        return False
    idx = [WORDS.index(x) for x in w]
    bits = "".join(f"{i:011b}" for i in idx)
    ent_len = len(bits) * 32 // 33
    entropy = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    checksum = bits[ent_len:]
    h = hashlib.sha256(entropy).digest()
    expect = "".join(f"{b:08b}" for b in h)[: len(bits) - ent_len]
    return checksum == expect

# ---------------------------------------------------------------- main
def main(path: str):
    doc = json.load(open(path))
    fails = []
    for v in doc["vectors"]:
        vid = v["vector_id"]
        try:
            if "expected_failure" in v:
                # negative vectors: the operation must fail the way the vector says
                if vid == "kdf-negative-short-seed":
                    try:
                        derive_scalar(bytes.fromhex(v["test_seed_hex"]), "x", N)
                        fails.append((vid, "short seed was NOT rejected"))
                    except ValueError as e:
                        assert "32 bytes" in str(e), str(e)
                elif vid == "kdf-negative-secp256k1-scalar-at-order":
                    s = int(v["scalar_hex"], 16)
                    assert not (s != 0 and s < N), "scalar == n was NOT rejected"
                elif vid == "kdf-negative-bls-scalar-zero":
                    s = int(v["scalar_hex"], 16)
                    assert not (s != 0 and s < BLS_R), "zero scalar was NOT rejected"
                elif vid == "kdf-negative-bip39-checksum":
                    assert not bip39_valid(v["mnemonic"]), "bad-checksum mnemonic was NOT rejected"
                    assert bip39_valid("abandon " * 11 + "about"), "sanity: valid mnemonic rejected!"
                else:
                    fails.append((vid, "unknown negative vector"))
                print(f"ok   {vid} (negative, failed as expected)")
                continue
            seed = bytes.fromhex(v["test_seed_hex"])
            info = v["domain_tag"]
            if vid.startswith("evm-"):
                from Crypto.Hash import keccak
                s, ctr = derive_scalar(seed, info, N)
                x, y = secp_mul(s)
                uncompressed = x.to_bytes(32, "big") + y.to_bytes(32, "big")
                addr = "0x" + keccak.new(digest_bits=256, data=uncompressed).hexdigest()[-40:]
                assert s.to_bytes(32, "big").hex() == v["expected_scalar_hex"], "scalar mismatch"
                assert uncompressed.hex() == v["expected_pubkey_hex"], "pubkey mismatch"
                assert addr == v["expected_address"], f"address mismatch: {addr}"
                assert v["resampled"] == (ctr > 0) and v["ctr_used"] == ctr
            elif vid.startswith("chia-"):
                s, ctr = derive_scalar(seed, info, BLS_R)
                pub = g1_compress(multiply(G1, s))
                assert s.to_bytes(32, "big").hex() == v["expected_scalar_hex"], "scalar mismatch"
                assert pub.hex() == v["expected_master_pubkey_hex"], "master pubkey mismatch"
                assert v["resampled"] == (ctr > 0) and v["ctr_used"] == ctr
            else:
                fails.append((vid, "unknown vector family"))
                continue
            print(f"ok   {vid}")
        except AssertionError as e:
            fails.append((vid, f"mismatch: {e}"))
            print(f"FAIL {vid}: {e}")
    # cross-family invariant from the spec (P9): testnet/mainnet keys differ
    by_id = {v["vector_id"]: v for v in doc["vectors"]}
    a = by_id["evm-4663-sign-default"]["expected_address"]
    b = by_id["evm-46630-sign-default"]["expected_address"]
    assert a != b, "testnet/mainnet addresses identical — P9 violated"
    print("ok   p9-invariant: evm-4663 != evm-46630")
    if fails:
        print(f"\n{fails.__len__()} FAILURES — STOP")
        sys.exit(1)
    print(f"\nall {len(doc['vectors'])} vectors + P9 invariant reproduce. green.")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "vectors.json")

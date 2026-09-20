"""Spellbook §2 KDF — HKDF-SHA256 + reject/resample (stdlib only).

Scalar extraction is real. Curve operations (secp256k1 point multiply,
BLS12-381 G1 multiply) are TODO(build): the daemon must reproduce
vectors/vectors.json byte-for-byte before any real key is derived
(SPEC §10 step 2). Do NOT hand-roll curve math here — vendor audited libs.
"""
import hmac
import hashlib

SALT = b"muse-wallet-v1"
INFO_PREFIX = "muse-wallet/v1/"

# Curve orders (constants only — no curve math in this file yet).
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BLS12_381_R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

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
        raise ValueError("seed must be exactly 32 bytes")
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


# TODO(build): secp256k1_private_to_uncompressed_pubkey(scalar) -> bytes[64]
# TODO(build): evm_address(uncompressed_pubkey) -> 20 bytes (keccak256, last 20)
# TODO(build): bls_secret_to_pubkey(scalar) -> bytes[48] (G1 compression)
# Each MUST reproduce vectors/vectors.json before mainnet is possible.

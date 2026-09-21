"""Seed handling — SPEC §2, §6.

The daemon's KDF input is always exactly 32 bytes:

  - Musebook muses: the existing 32-byte Ed25519 identity seed.
  - everyone else: 32 bytes of fresh entropy, generated once at install.

The paper backup (§6) is a BIP-39 mnemonic over that entropy. The daemon
never sees the mnemonic — it loads the 32-byte seed file (daemon-user-owned,
mode 0600) and nothing else.

Hard rules:
  - No seed material in logs, the ledger, error messages, or API responses.
  - The conversational agent must never inspect the seed file (it cannot —
    the file is owned by the daemon's OS user, mode 0600).
  - Real seeds are created only after the §10 phase-1 authorization.
    Everything built here is exercised with the published TEST seed only.
"""
import hashlib
import hmac
import os
from importlib.resources import files

_WORDLIST = None


def _wordlist() -> list[str]:
    global _WORDLIST
    if _WORDLIST is None:
        data = (files(__package__) / "bip39-english.txt").read_text()
        _WORDLIST = [w.strip() for w in data.splitlines() if w.strip()]
    assert len(_WORDLIST) == 2048, "bip39 wordlist must hold 2048 words"
    return _WORDLIST


def load_seed(path: str) -> bytes:
    """Load the 32-byte seed from a daemon-user-owned, mode-0600 file.

    The file holds 64 hex chars (whitespace tolerated). Fails closed on
    permissions, length, or encoding — a daemon that cannot prove its seed
    file is private refuses to start.
    """
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise PermissionError(f"seed file {path} is not 0600 — refusing to load")
    with open(path) as f:
        text = f.read().strip()
    try:
        seed = bytes.fromhex(text)
    except ValueError:
        raise ValueError("seed file is not hex")
    if len(seed) != 32:
        raise ValueError("reject: seed must be exactly 32 bytes")
    return seed


def generate_entropy() -> bytes:
    """32 bytes from the OS CSPRNG. Call once per wallet, at install time."""
    return os.urandom(32)


# ---------------------------------------------------------------- BIP-39
# Paper backup only. The daemon's own backup is 24 words over its 32-byte
# entropy; import accepts all standard lengths (12/15/18/21/24 words).
# The daemon's KDF input stays the raw entropy bytes, never the mnemonic.

def mnemonic_from_entropy(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("BIP-39 entropy must be 16/20/24/28/32 bytes")
    words = _wordlist()
    checksum_bits = len(entropy) * 8 // 32
    h = hashlib.sha256(entropy).digest()
    bits = (int.from_bytes(entropy, "big") << checksum_bits) | \
        (h[0] >> (8 - checksum_bits))
    total = (len(entropy) * 8 + checksum_bits)
    out = []
    for _ in range(total // 11):
        total -= 11
        out.append(words[(bits >> total) & 0x7FF])
    return " ".join(out)


def entropy_from_mnemonic(mnemonic: str) -> bytes:
    """Decode + checksum-verify a BIP-39 mnemonic back to entropy bytes."""
    words = _wordlist()
    idx = {w: i for i, w in enumerate(words)}
    parts = mnemonic.strip().split()
    if len(parts) not in (12, 15, 18, 21, 24):
        raise ValueError("mnemonic must hold 12/15/18/21/24 words")
    total_bits = len(parts) * 11
    checksum_bits = total_bits // 33
    entropy_bits = total_bits - checksum_bits
    bits = 0
    for w in parts:
        if w not in idx:
            raise ValueError(f"unknown word in mnemonic: {w!r}")
        bits = (bits << 11) | idx[w]
    entropy = (bits >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    checksum = bits & ((1 << checksum_bits) - 1)
    expected = int.from_bytes(hashlib.sha256(entropy).digest(), "big") >> (256 - checksum_bits)
    if checksum != expected:
        raise ValueError("mnemonic checksum failed — mis-copied word?")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP-39 seed (64 bytes). Informational: Spellbook's KDF input is the
    32-byte entropy, not this value. Provided for wallet interop."""
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.strip().encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"), 2048, 64)

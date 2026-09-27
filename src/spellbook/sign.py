"""Signing primitives — SPEC §4, §8 (P1).

Two fixed domain prefixes (P1): a Musebook signing string can never parse
as a directory entry, and the daemon never signs caller-supplied raw bytes.
The daemon builds every canonical string itself from typed fields.

Curves:
  - secp256k1 ECDSA over a 32-byte digest (EVM legacy/1559 sighash), RFC 6979,
    low-S normalized — via coincurve (libsecp256k1).
  - BLS (G2Basic ciphersuite) over arbitrary messages (Chia) — via py_ecc.

Off-chain message signatures (SPEC §10, wallet signatures on all chains):
  - EVM EIP-191 ``personal_sign``: the daemon builds the
    ``\\x19Ethereum Signed Message:\\n<len>`` preimage itself from the
    human-approved message string — never from caller-supplied raw bytes.
    Returns 65-byte r||s||v (v in {27,28}), low-S normalized.
  - EVM EIP-712 typed data: the daemon builds the ``\\x19\\x01`` digest
    itself from the approved typed-data envelope (full encodeType /
    encodeData implementation) and signs that.
  - Solana: plain ed25519 ``sign_message`` over the UTF-8 bytes (solders
    Keypair), 64-byte signature.

These primitives are exercised with test keys only. Wiring them to real
transaction submission is SPEC §10 phase 1, which needs its own authorization.
"""
import json
import re

from coincurve import PrivateKey, PublicKey
from Crypto.Hash import keccak
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


def secp256k1_pubkey_uncompressed_hex(privkey_bytes: bytes) -> str:
    """130-hex uncompressed public key (04 || x || y) for a 32-byte scalar."""
    if len(privkey_bytes) != 32:
        raise ValueError("privkey must be 32 bytes")
    _check_secp_scalar(int.from_bytes(privkey_bytes, "big"))
    return PrivateKey(privkey_bytes).public_key.format(
        compressed=False).hex()


# --------------------------------------- EVM off-chain message signatures

def _keccak256(b: bytes) -> bytes:
    return keccak.new(data=b, digest_bits=256).digest()


def evm_to_checksum_address(addr: str) -> str:
    """EIP-55 checksum encoding for a 0x-prefixed hex address."""
    if not isinstance(addr, str):
        raise ValueError("address must be a string")
    low = addr[2:] if addr[:2] in ("0x", "0X") else addr
    low = low.lower()
    if len(low) != 40 or not all(c in "0123456789abcdef" for c in low):
        raise ValueError("bad EVM address")
    digest = _keccak256(low.encode()).hex()
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c
                          for i, c in enumerate(low))


EIP191_PREFIX = b"\x19Ethereum Signed Message:\n"


def evm_personal_sign(privkey_bytes: bytes, message: str) -> bytes:
    """EIP-191 personal_sign. Returns 65-byte r||s||v, v in {27,28}.

    The EIP-191 preimage is built INSIDE this function from the message
    string (P1): the daemon never signs caller-supplied raw bytes. The
    signature is RFC 6979 + low-S normalized (the recovery id flips with
    the s-flip so recovery stays correct).
    """
    if len(privkey_bytes) != 32:
        raise ValueError("privkey must be 32 bytes")
    if not isinstance(message, str):
        raise ValueError("message must be a string")
    _check_secp_scalar(int.from_bytes(privkey_bytes, "big"))
    msg_bytes = message.encode("utf-8")
    preimage = (EIP191_PREFIX + str(len(msg_bytes)).encode() + msg_bytes)
    digest = _keccak256(preimage)
    rec = PrivateKey(privkey_bytes).sign_recoverable(digest, hasher=None)
    recid = rec[-1]
    r = int.from_bytes(rec[:32], "big")
    s = int.from_bytes(rec[32:64], "big")
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
        recid ^= 1  # s -> n-s flips the R point's y parity
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")
            + bytes([27 + recid]))


def evm_recover_personal_address(message: str, sig65: bytes) -> str:
    """Recover the EIP-55 checksum address for a personal_sign signature."""
    if not isinstance(message, str):
        raise ValueError("message must be a string")
    if len(sig65) != 65:
        raise ValueError("signature must be 65 bytes")
    v = sig65[64]
    if v not in (27, 28):
        raise ValueError("v must be 27 or 28")
    msg_bytes = message.encode("utf-8")
    preimage = (EIP191_PREFIX + str(len(msg_bytes)).encode() + msg_bytes)
    digest = _keccak256(preimage)
    rec = bytes(sig65[:64]) + bytes([v - 27])
    try:
        pub = PublicKey.from_signature_and_message(rec, digest, hasher=None)
    except Exception as e:
        raise ValueError(f"unrecoverable signature: {e}")
    return evm_to_checksum_address(
        "0x" + _keccak256(pub.format(compressed=False)[1:])[-20:].hex())


# ------------------------------------------------------------- EIP-712

_E712_INT_RE = re.compile(r"^(u?int)([0-9]+)$")
_E712_BYTESN_RE = re.compile(r"^bytes([0-9]{1,2})$")
_E712_ARRAY_RE = re.compile(r"^(.*)\[([0-9]*)\]$")


def _e712_dependencies(types: dict, name: str) -> list:
    """Custom types referenced by `name`, transitively (excluding itself)."""
    found = []

    def collect(t: str):
        if t in found or t not in types:
            return
        found.append(t)
        for f in types[t]:
            base = _E712_ARRAY_RE.sub(r"\1", f["type"])
            if base != t and base in types:
                collect(base)

    for f in types[name]:
        base = _E712_ARRAY_RE.sub(r"\1", f["type"])
        if base != name and base in types:
            collect(base)
    return found


def _e712_encode_type(types: dict, name: str) -> str:
    """encodeType: primary first, then referenced custom types sorted."""
    deps = sorted(set(_e712_dependencies(types, name)))
    order = [name] + [d for d in deps if d != name]
    parts = []
    for t in order:
        if t not in types or not isinstance(types[t], list):
            raise ValueError(f"unknown EIP-712 type {t!r}")
        fields = []
        for f in types[t]:
            if not isinstance(f, dict) or "name" not in f or "type" not in f:
                raise ValueError(f"bad field descriptor in {t!r}")
            fields.append(f"{f['type']} {f['name']}")
        parts.append(f"{t}({','.join(fields)})")
    return "".join(parts)


def _e712_type_hash(types: dict, name: str) -> bytes:
    return _keccak256(_e712_encode_type(types, name).encode())


def _e712_hex_bytes(val, what: str) -> bytes:
    if isinstance(val, str) and val[:2] in ("0x", "0X"):
        try:
            return bytes.fromhex(val[2:])
        except ValueError:
            raise ValueError(f"bad hex for {what}")
    if isinstance(val, (bytes, bytearray)):
        return bytes(val)
    raise ValueError(f"{what} needs 0x-hex or bytes")


def _e712_encode_atomic(ftype: str, val) -> bytes:
    if ftype == "address":
        if not isinstance(val, str):
            raise ValueError("address needs a hex string")
        low = val[2:] if val[:2] in ("0x", "0X") else val
        low = low.lower()
        if len(low) != 40 or not all(c in "0123456789abcdef" for c in low):
            raise ValueError("bad address value")
        return b"\x00" * 12 + bytes.fromhex(low)
    m = _E712_INT_RE.match(ftype)
    if m:
        signed = m.group(1) == "int"
        bits = int(m.group(2))
        if not 8 <= bits <= 256 or bits % 8:
            raise ValueError(f"bad int size in {ftype!r}")
        if isinstance(val, bool) or not isinstance(val, int):
            raise ValueError(f"{ftype} needs an integer")
        lo = -(1 << (bits - 1)) if signed else 0
        hi = (1 << (bits - 1)) if signed else (1 << bits)
        if not lo <= val < hi:
            raise ValueError(f"{ftype} value out of range")
        return val.to_bytes(32, "big", signed=signed)
    if ftype == "bool":
        if not isinstance(val, bool):
            raise ValueError("bool needs a boolean")
        return (1 if val else 0).to_bytes(32, "big")
    m = _E712_BYTESN_RE.match(ftype)
    if m:
        n = int(m.group(1))
        b = _e712_hex_bytes(val, ftype)
        if len(b) != n:
            raise ValueError(f"{ftype} needs exactly {n} bytes")
        return b.ljust(32, b"\x00")
    if ftype == "bytes":
        return _keccak256(_e712_hex_bytes(val, "bytes"))
    if ftype == "string":
        if not isinstance(val, str):
            raise ValueError("string needs a string")
        return _keccak256(val.encode("utf-8"))
    raise ValueError(f"unknown EIP-712 atomic type {ftype!r}")


def _e712_encode_value(types: dict, ftype: str, val) -> bytes:
    m = _E712_ARRAY_RE.match(ftype)
    if m:
        base, nstr = m.group(1), m.group(2)
        if not isinstance(val, list):
            raise ValueError(f"array {ftype!r} needs a list")
        if nstr and len(val) != int(nstr):
            raise ValueError(
                f"fixed array {ftype!r} needs {nstr} elements")
        if base in types:
            return _keccak256(b"".join(
                _e712_hash_struct(types, base, v) for v in val))
        return _keccak256(b"".join(
            _e712_encode_atomic(base, v) for v in val))
    if ftype in types:
        return _e712_hash_struct(types, ftype, val)
    return _e712_encode_atomic(ftype, val)


def _e712_encode_data(types: dict, name: str, data: dict) -> bytes:
    if not isinstance(data, dict):
        raise ValueError(f"EIP-712 struct {name!r} needs an object")
    out = [_e712_type_hash(types, name)]
    for f in types[name]:
        if f["name"] not in data:
            raise ValueError(
                f"EIP-712 struct {name!r} missing field {f['name']!r}")
        out.append(_e712_encode_value(types, f["type"], data[f["name"]]))
    return b"".join(out)


def _e712_hash_struct(types: dict, name: str, data: dict) -> bytes:
    return _keccak256(_e712_encode_data(types, name, data))


def eip712_digest(typed_data: dict) -> bytes:
    """Full EIP-712 digest for a typed-data envelope.

    typed_data has types / primaryType / domain / message. Returns
    keccak256(b"\\x19\\x01" + domainSeparator + hashStruct(message)).
    The digest is built entirely inside this function (P1): callers never
    pass a pre-computed hash.
    """
    if not isinstance(typed_data, dict):
        raise ValueError("typed_data must be an object")
    types = typed_data.get("types")
    primary = typed_data.get("primaryType")
    domain = typed_data.get("domain")
    message = typed_data.get("message")
    if not isinstance(types, dict) or not isinstance(primary, str):
        raise ValueError(
            "typed_data needs types (object) and primaryType (string)")
    if not isinstance(domain, dict) or not isinstance(message, dict):
        raise ValueError(
            "typed_data needs domain and message objects")
    if "EIP712Domain" not in types:
        raise ValueError("typed_data types must define EIP712Domain")
    if primary not in types:
        raise ValueError(f"primaryType {primary!r} not in types")
    if not isinstance(types["EIP712Domain"], list):
        raise ValueError("EIP712Domain must be a field list")
    return _keccak256(
        b"\x19\x01"
        + _e712_hash_struct(types, "EIP712Domain", domain)
        + _e712_hash_struct(types, primary, message))


def evm_sign_typed_data(privkey_bytes: bytes, typed_data: dict) -> bytes:
    """Sign EIP-712 typed data. Returns 65-byte r||s||v, v in {27,28}.

    The digest is built from the envelope by eip712_digest (P1) — never
    caller-supplied. Low-S normalized like evm_personal_sign.
    """
    if len(privkey_bytes) != 32:
        raise ValueError("privkey must be 32 bytes")
    _check_secp_scalar(int.from_bytes(privkey_bytes, "big"))
    digest = eip712_digest(typed_data)
    rec = PrivateKey(privkey_bytes).sign_recoverable(digest, hasher=None)
    recid = rec[-1]
    r = int.from_bytes(rec[:32], "big")
    s = int.from_bytes(rec[32:64], "big")
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
        recid ^= 1
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")
            + bytes([27 + recid]))


# --------------------------------------- Solana off-chain message signing

def solana_sign_message(keypair, message: bytes) -> bytes:
    """ed25519 sign_message with a solders Keypair (duck-typed).

    Solana has no EIP-191-style envelope for plain messages: the 64-byte
    signature covers the raw message bytes. Returns the 64-byte signature.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("message must be bytes")
    sig = keypair.sign_message(bytes(message))
    out = bytes(sig)
    if len(out) != 64:
        raise ValueError("bad ed25519 signature length")
    return out


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

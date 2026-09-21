"""Chia Streamable codec — minimal, dependency-free implementation.

Implements exactly the subset of Chia's ``Streamable`` binary format the
relay needs.  Encoding rules follow ``chia.util.streamable`` (verified
against chia-blockchain 2.7.4 and chia-protocol 0.36.1):

* integers: big-endian, fixed width (uint8/16/32/64/128)
* ``str``: u32-BE byte length followed by UTF-8 bytes
* ``bytes`` (variable): u32-BE length followed by raw bytes
* fixed-size bytes (bytes32, G2Element, ...): raw bytes, no prefix
* ``Optional[T]``: one byte 0x00 (absent) or 0x01 (present), then T
* ``List[T]``: u32-BE item count, then each item
* ``Tuple[A, B]``: A then B concatenated

Message envelope (``chia.protocols.outbound_message.Message``):

* uint8 ``msg_type``
* ``Optional[uint16] id`` — the 0x00/0x01 prefix byte is ALWAYS on the
  wire; the u16 follows only when the prefix is 0x01
* variable ``bytes`` data (u32-BE length + payload)

Known-good encodings live in ``test_vectors.py``.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class StreamableError(ValueError):
    """Raised when bytes do not form a valid Streamable value."""


# ---------------------------------------------------------------------------
# Low-level reader
# ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, n: int) -> bytes:
        if n < 0:
            raise StreamableError("negative read length")
        end = self._pos + n
        if end > len(self._data):
            raise StreamableError(
                f"truncated stream: need {n} bytes at offset {self._pos}, "
                f"only {len(self._data) - self._pos} remain"
            )
        out = self._data[self._pos:end]
        self._pos = end
        return out

    def eof(self) -> bool:
        return self._pos == len(self._data)

    def remaining(self) -> int:
        return len(self._data) - self._pos


# ---------------------------------------------------------------------------
# Integer primitives
# ---------------------------------------------------------------------------

def enc_u8(v: int) -> bytes:
    _check_range(v, 8)
    return struct.pack(">B", v)


def enc_u16(v: int) -> bytes:
    _check_range(v, 16)
    return struct.pack(">H", v)


def enc_u32(v: int) -> bytes:
    _check_range(v, 32)
    return struct.pack(">I", v)


def enc_u64(v: int) -> bytes:
    _check_range(v, 64)
    return struct.pack(">Q", v)


def enc_u128(v: int) -> bytes:
    _check_range(v, 128)
    return struct.pack(">QQ", (v >> 64) & 0xFFFFFFFFFFFFFFFF, v & 0xFFFFFFFFFFFFFFFF)


def _check_range(v: int, bits: int) -> None:
    if not isinstance(v, int) or isinstance(v, bool):
        raise StreamableError(f"expected int for uint{bits}, got {type(v).__name__}")
    if v < 0 or v >= (1 << bits):
        raise StreamableError(f"value {v} out of range for uint{bits}")


def dec_u8(r: _Reader) -> int:
    return struct.unpack(">B", r.read(1))[0]


def dec_u16(r: _Reader) -> int:
    return struct.unpack(">H", r.read(2))[0]


def dec_u32(r: _Reader) -> int:
    return struct.unpack(">I", r.read(4))[0]


def dec_u64(r: _Reader) -> int:
    return struct.unpack(">Q", r.read(8))[0]


def dec_u128(r: _Reader) -> int:
    hi, lo = struct.unpack(">QQ", r.read(16))
    return (hi << 64) | lo


def enc_bool(v: bool) -> bytes:
    if not isinstance(v, bool):
        raise StreamableError(f"expected bool, got {type(v).__name__}")
    return b"\x01" if v else b"\x00"


def dec_bool(r: _Reader) -> bool:
    b = r.read(1)
    if b == b"\x01":
        return True
    if b == b"\x00":
        return False
    raise StreamableError(f"invalid bool byte: {b.hex()}")


# ---------------------------------------------------------------------------
# CLVM programs — consensus framing (NO length prefix)
# ---------------------------------------------------------------------------
# Chia's Streamable encodes Program fields as bare, self-delimiting CLVM —
# there is no uint32 length prefix (this matches chia-blockchain's Python
# Streamable and the Rust chia-protocol/clvmr `Program::parse`, which reads
# via `serialized_length_from_bytes`).  A previous revision of this file
# wrongly length-prefixed programs; peers then misparsed the bundle and
# dropped the connection, so this framing is load-bearing.
#
# Atom encoding (mirrors clvmr serialized_length_from_bytes):
#   0xff         cons cell: 0xff <first> <rest>
#   0xfe         back-reference (with encoded path) — REJECTED by this gate;
#                our encoder never emits them and the relay fails closed on
#                exotic encodings rather than forwarding them.
#   0x80 |<=0x7f single-byte atom (0x80 is also nil)
#   else         size-prefixed atom: the leading 1-bits of the first byte
#                count the size-field bytes; the low bits plus following
#                bytes are the big-endian blob size.

def _clvm_atom_total(buf: bytes, pos: int) -> int:
    """Total bytes (size prefix + blob) of the atom starting at pos."""
    if pos >= len(buf):
        raise StreamableError("truncated CLVM program")
    b0 = buf[pos]
    if b0 == 0xFF:
        raise StreamableError("0xff starts a cons cell, not an atom")
    if b0 == 0xFE:
        raise StreamableError("CLVM back-references are not accepted")
    if b0 == 0x80 or b0 < 0x80:
        return 1
    n = 0
    b = b0
    while b & 0x80:
        n += 1
        b = (b << 1) & 0xFF
    if n > 8 or pos + n > len(buf):
        raise StreamableError("truncated CLVM atom size prefix")
    size = b0 & (0xFF >> n)
    for i in range(1, n):
        size = (size << 8) | buf[pos + i]
    total = n + size
    if pos + total > len(buf):
        raise StreamableError("truncated CLVM atom blob")
    return total


def clvm_program_length(buf: bytes, pos: int = 0) -> int:
    """Length in bytes of the one serialized CLVM program starting at pos."""
    start = pos
    pending = 1
    while pending > 0:
        if pos >= len(buf):
            raise StreamableError("truncated CLVM program")
        b0 = buf[pos]
        if b0 == 0xFF:
            pos += 1
            pending += 1  # two children replace the one expected sexp
        elif b0 == 0xFE:
            raise StreamableError("CLVM back-references are not accepted")
        elif b0 == 0x80 or b0 < 0x80:
            pos += 1
            pending -= 1
        else:
            pos += _clvm_atom_total(buf, pos)
            pending -= 1
    return pos - start


def enc_program(b: bytes) -> bytes:
    """Encode a Program with consensus framing: raw CLVM, no length prefix."""
    if not isinstance(b, (bytes, bytearray)):
        raise StreamableError(f"expected bytes, got {type(b).__name__}")
    raw = bytes(b)
    if clvm_program_length(raw, 0) != len(raw):
        raise StreamableError("program bytes contain trailing garbage")
    return raw


def dec_program(r: _Reader, max_len: int = 2**32 - 1) -> bytes:
    """Decode one Program with consensus framing (self-delimiting CLVM)."""
    length = clvm_program_length(r._data, r._pos)
    if length > max_len:
        raise StreamableError(f"CLVM program length {length} exceeds limit {max_len}")
    return r.read(length)


# ---------------------------------------------------------------------------
# str / bytes / fixed bytes
# ---------------------------------------------------------------------------

def enc_str(s: str) -> bytes:
    if not isinstance(s, str):
        raise StreamableError(f"expected str, got {type(s).__name__}")
    raw = s.encode("utf-8")
    return enc_u32(len(raw)) + raw


def dec_str(r: _Reader) -> str:
    n = dec_u32(r)
    raw = r.read(n)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise StreamableError(f"invalid utf-8 string: {e}") from e


def enc_bytes_var(b: bytes) -> bytes:
    if not isinstance(b, (bytes, bytearray)):
        raise StreamableError(f"expected bytes, got {type(b).__name__}")
    return enc_u32(len(b)) + bytes(b)


def dec_bytes_var(r: _Reader, max_len: int = 2**32 - 1) -> bytes:
    n = dec_u32(r)
    if n > max_len:
        raise StreamableError(f"byte string length {n} exceeds limit {max_len}")
    return r.read(n)


def enc_bytes_fixed(b: bytes, size: int) -> bytes:
    if not isinstance(b, (bytes, bytearray)) or len(b) != size:
        raise StreamableError(f"expected {size} bytes, got {len(b) if isinstance(b, (bytes, bytearray)) else type(b).__name__}")
    return bytes(b)


def dec_bytes_fixed(r: _Reader, size: int) -> bytes:
    return r.read(size)


# ---------------------------------------------------------------------------
# Optional / List / Tuple
# ---------------------------------------------------------------------------

def enc_optional(v, enc_item) -> bytes:
    if v is None:
        return b"\x00"
    return b"\x01" + enc_item(v)


def enc_list(items, enc_item) -> bytes:
    out = [enc_u32(len(items))]
    for it in items:
        out.append(enc_item(it))
    return b"".join(out)


def dec_list(r: _Reader, dec_item, max_items: int = 2**32 - 1, max_len: int = 2**32 - 1) -> list:
    n = dec_u32(r)
    if n > max_items:
        raise StreamableError(f"list length {n} exceeds limit {max_items}")
    return [dec_item(r) for _ in range(n)]


# ---------------------------------------------------------------------------
# Coins
# ---------------------------------------------------------------------------

def int_to_bytes(n: int) -> bytes:
    """Minimal big-endian encoding of a non-negative int (CLVM style).

    Used inside ``coin_id``: 0 -> b"", high bit set -> leading 0x00 byte.
    Matches ``Coin::coin_id`` in chia-protocol 0.36.1.
    """
    if n < 0:
        raise StreamableError("int_to_bytes needs a non-negative int")
    if n == 0:
        return b""
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def coin_id(parent_coin_info: bytes, puzzle_hash: bytes, amount: int) -> bytes:
    """Consensus coin id: sha256(parent || puzzle_hash || minimal amount)."""
    if len(parent_coin_info) != 32 or len(puzzle_hash) != 32:
        raise StreamableError("coin_id needs 32-byte parent and puzzle hash")
    h = hashlib.sha256()
    h.update(parent_coin_info)
    h.update(puzzle_hash)
    h.update(int_to_bytes(amount))
    return h.digest()


@dataclass(frozen=True)
class Coin:
    parent_coin_info: bytes  # bytes32
    puzzle_hash: bytes       # bytes32
    amount: int              # uint64

    def coin_id(self) -> bytes:
        return coin_id(self.parent_coin_info, self.puzzle_hash, self.amount)


def enc_coin(c: Coin) -> bytes:
    return enc_bytes_fixed(c.parent_coin_info, 32) + enc_bytes_fixed(c.puzzle_hash, 32) + enc_u64(c.amount)


def dec_coin(r: _Reader) -> Coin:
    return Coin(dec_bytes_fixed(r, 32), dec_bytes_fixed(r, 32), dec_u64(r))


@dataclass(frozen=True)
class CoinState:
    coin: Coin
    spent_height: Optional[int]   # Optional[uint32]
    created_height: Optional[int]  # Optional[uint32]


def enc_coin_state(cs: CoinState) -> bytes:
    out = enc_coin(cs.coin)
    out += b"\x00" if cs.spent_height is None else b"\x01" + enc_u32(cs.spent_height)
    out += b"\x00" if cs.created_height is None else b"\x01" + enc_u32(cs.created_height)
    return out


def dec_coin_state(r: _Reader) -> CoinState:
    coin = dec_coin(r)
    spent = dec_optional_u32(r)
    created = dec_optional_u32(r)
    return CoinState(coin, spent, created)


def dec_optional_u32(r: _Reader) -> Optional[int]:
    flag = r.read(1)
    if flag == b"\x00":
        return None
    if flag == b"\x01":
        return dec_u32(r)
    raise StreamableError(f"invalid optional flag: {flag.hex()}")


def dec_optional_str(r: _Reader) -> Optional[str]:
    flag = r.read(1)
    if flag == b"\x00":
        return None
    if flag == b"\x01":
        return dec_str(r)
    raise StreamableError(f"invalid optional flag: {flag.hex()}")


@dataclass(frozen=True)
class CoinSpend:
    coin: Coin
    puzzle_reveal: bytes  # Program, consensus framing (bare CLVM, NO length prefix)
    solution: bytes       # Program, consensus framing (bare CLVM, NO length prefix)


def enc_coin_spend(cs: CoinSpend) -> bytes:
    return enc_coin(cs.coin) + enc_program(cs.puzzle_reveal) + enc_program(cs.solution)


def dec_coin_spend(r: _Reader, max_program: int) -> CoinSpend:
    coin = dec_coin(r)
    reveal = dec_program(r, max_program)
    solution = dec_program(r, max_program)
    return CoinSpend(coin, reveal, solution)


@dataclass(frozen=True)
class SpendBundle:
    coin_spends: List[CoinSpend]
    aggregated_signature: bytes  # G2Element, 96 bytes


def enc_spend_bundle(sb: SpendBundle) -> bytes:
    return enc_u32(len(sb.coin_spends)) + b"".join(enc_coin_spend(c) for c in sb.coin_spends) + enc_bytes_fixed(sb.aggregated_signature, 96)


# ---------------------------------------------------------------------------
# SpendBundle structural validation (fail-closed, before broadcast)
# ---------------------------------------------------------------------------

# Hard caps for structural validation. The HTTP layer enforces the 5 MB
# bundle cap first; these bound individual fields so a corrupt length prefix
# cannot drive runaway allocation.
_MAX_COIN_SPENDS = 10_000
_MAX_PROGRAM_BYTES = 2 * 1024 * 1024  # 2 MB per puzzle reveal / solution


def parse_spend_bundle(data: bytes) -> SpendBundle:
    """Strictly parse a SpendBundle, rejecting malformed input.

    Raises StreamableError on: truncation, bad lengths, empty coin_spends,
    wrong signature size, or any trailing bytes.  This is the gate in front
    of /v1/broadcast — nothing unparseable here ever reaches a peer.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
        raise StreamableError("empty spend bundle")
    r = _Reader(bytes(data))
    n = dec_u32(r)
    if n == 0:
        raise StreamableError("spend bundle has no coin spends")
    if n > _MAX_COIN_SPENDS:
        raise StreamableError(f"too many coin spends: {n}")
    spends = [dec_coin_spend(r, _MAX_PROGRAM_BYTES) for _ in range(n)]
    sig = dec_bytes_fixed(r, 96)
    if not r.eof():
        raise StreamableError(f"trailing bytes after spend bundle: {r.remaining()}")
    return SpendBundle(spends, sig)


def spend_bundle_txid(bundle_bytes: bytes) -> bytes:
    """Expected txid for a bundle: sha256 of its canonical serialization."""
    return hashlib.sha256(bundle_bytes).digest()


# ---------------------------------------------------------------------------
# Message envelope
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Message:
    msg_type: int          # uint8
    id: Optional[int]      # Optional[uint16]
    data: bytes            # length-prefixed bytes


def enc_message(msg: Message) -> bytes:
    out = enc_u8(msg.msg_type)
    out += b"\x00" if msg.id is None else b"\x01" + enc_u16(msg.id)
    out += enc_bytes_var(msg.data)
    return out


def dec_message(data: bytes) -> Message:
    """Strictly decode one Message; the whole frame must be consumed."""
    r = _Reader(bytes(data))
    msg_type = dec_u8(r)
    flag = r.read(1)
    if flag == b"\x00":
        msg_id = None
    elif flag == b"\x01":
        msg_id = dec_u16(r)
    else:
        raise StreamableError(f"invalid message id flag: {flag.hex()}")
    payload = dec_bytes_var(r)
    if not r.eof():
        raise StreamableError(f"trailing bytes after message: {r.remaining()}")
    return Message(msg_type, msg_id, payload)


# ---------------------------------------------------------------------------
# Protocol constants (verified against chia-blockchain 2.7.4 /
# chia-protocol 0.36.1)
# ---------------------------------------------------------------------------

class MsgType:
    HANDSHAKE = 1
    REQUEST_PUZZLE_SOLUTION = 45
    RESPOND_PUZZLE_SOLUTION = 46
    REJECT_PUZZLE_SOLUTION = 47
    SEND_TRANSACTION = 48
    TRANSACTION_ACK = 49
    NEW_PEAK_WALLET = 50
    REQUEST_HEADER_BLOCKS = 60
    REJECT_HEADER_BLOCKS = 61
    RESPOND_HEADER_BLOCKS = 62
    COIN_STATE_UPDATE = 69
    REGISTER_FOR_PH_UPDATES = 70
    RESPOND_TO_PH_UPDATES = 71
    REGISTER_FOR_COIN_UPDATES = 72
    RESPOND_TO_COIN_UPDATES = 73


class NodeType:
    FULL_NODE = 1
    WALLET = 6


class MempoolStatus:
    SUCCESS = 1
    PENDING = 2
    FAILED = 3


MEMPOOL_STATUS_NAMES = {1: "SUCCESS", 2: "PENDING", 3: "FAILED"}


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Handshake:
    network_id: str          # e.g. "testnet11" (the selected_network string)
    protocol_version: str    # e.g. "0.0.37"
    software_version: str    # e.g. "0.0.0"
    server_port: int         # uint16
    node_type: int           # uint8
    capabilities: List[tuple]  # List[Tuple[uint16, str]]

    def __post_init__(self):
        # tuples from wire decode arrive as tuples; keep them hashable
        object.__setattr__(self, "capabilities", [(int(a), str(b)) for a, b in self.capabilities])


def enc_handshake(h: Handshake) -> bytes:
    out = enc_str(h.network_id)
    out += enc_str(h.protocol_version)
    out += enc_str(h.software_version)
    out += enc_u16(h.server_port)
    out += enc_u8(h.node_type)
    out += enc_u32(len(h.capabilities))
    for cap_id, cap_val in h.capabilities:
        out += enc_u16(cap_id) + enc_str(cap_val)
    return out


def dec_handshake(data: bytes) -> Handshake:
    r = _Reader(bytes(data))
    network_id = dec_str(r)
    protocol_version = dec_str(r)
    software_version = dec_str(r)
    server_port = dec_u16(r)
    node_type = dec_u8(r)
    n = dec_u32(r)
    if n > 64:
        raise StreamableError(f"too many capabilities: {n}")
    caps = [(dec_u16(r), dec_str(r)) for _ in range(n)]
    if not r.eof():
        raise StreamableError(f"trailing bytes after handshake: {r.remaining()}")
    return Handshake(network_id, protocol_version, software_version, server_port, node_type, caps)


# ---------------------------------------------------------------------------
# Wallet protocol messages
# ---------------------------------------------------------------------------

def enc_register_for_ph_updates(puzzle_hashes: List[bytes], min_height: int) -> bytes:
    for ph in puzzle_hashes:
        if len(ph) != 32:
            raise StreamableError("puzzle hash must be 32 bytes")
    return enc_u32(len(puzzle_hashes)) + b"".join(enc_bytes_fixed(ph, 32) for ph in puzzle_hashes) + enc_u32(min_height)


def dec_respond_to_ph_updates(data: bytes) -> dict:
    r = _Reader(bytes(data))
    n = dec_u32(r)
    if n > 100_000:
        raise StreamableError(f"absurd puzzle hash count: {n}")
    puzzle_hashes = [dec_bytes_fixed(r, 32) for _ in range(n)]
    min_height = dec_u32(r)
    m = dec_u32(r)
    if m > 1_000_000:
        raise StreamableError(f"absurd coin state count: {m}")
    coin_states = [dec_coin_state(r) for _ in range(m)]
    if not r.eof():
        raise StreamableError(f"trailing bytes after RespondToPhUpdates: {r.remaining()}")
    return {"puzzle_hashes": puzzle_hashes, "min_height": min_height, "coin_states": coin_states}


def enc_register_for_coin_updates(coin_ids: List[bytes], min_height: int) -> bytes:
    for cid in coin_ids:
        if len(cid) != 32:
            raise StreamableError("coin id must be 32 bytes")
    return enc_u32(len(coin_ids)) + b"".join(enc_bytes_fixed(c, 32) for c in coin_ids) + enc_u32(min_height)


def dec_respond_to_coin_updates(data: bytes) -> dict:
    r = _Reader(bytes(data))
    n = dec_u32(r)
    if n > 100_000:
        raise StreamableError(f"absurd coin id count: {n}")
    coin_ids = [dec_bytes_fixed(r, 32) for _ in range(n)]
    min_height = dec_u32(r)
    m = dec_u32(r)
    if m > 1_000_000:
        raise StreamableError(f"absurd coin state count: {m}")
    coin_states = [dec_coin_state(r) for _ in range(m)]
    if not r.eof():
        raise StreamableError(f"trailing bytes after RespondToCoinUpdates: {r.remaining()}")
    return {"coin_ids": coin_ids, "min_height": min_height, "coin_states": coin_states}


def dec_coin_state_update(data: bytes) -> dict:
    """Unsolicited push (msg 69) when subscribed coins change."""
    r = _Reader(bytes(data))
    height = dec_u32(r)
    fork_height = dec_u32(r)
    peak_hash = dec_bytes_fixed(r, 32)
    m = dec_u32(r)
    if m > 1_000_000:
        raise StreamableError(f"absurd coin state count: {m}")
    items = [dec_coin_state(r) for _ in range(m)]
    if not r.eof():
        raise StreamableError(f"trailing bytes after CoinStateUpdate: {r.remaining()}")
    return {"height": height, "fork_height": fork_height, "peak_hash": peak_hash, "items": items}


def enc_send_transaction(spend_bundle_bytes: bytes) -> bytes:
    # SendTransaction { transaction: SpendBundle } — the bundle is already
    # canonical bytes, embedded verbatim (no extra length prefix: it IS the
    # Streamable encoding of the SpendBundle struct).
    return bytes(spend_bundle_bytes)


def dec_transaction_ack(data: bytes) -> dict:
    r = _Reader(bytes(data))
    txid = dec_bytes_fixed(r, 32)
    status = dec_u8(r)
    error = dec_optional_str(r)
    if not r.eof():
        raise StreamableError(f"trailing bytes after TransactionAck: {r.remaining()}")
    return {"txid": txid, "status": status, "error": error}


def dec_new_peak_wallet(data: bytes) -> dict:
    r = _Reader(bytes(data))
    header_hash = dec_bytes_fixed(r, 32)
    height = dec_u32(r)
    weight = dec_u128(r)
    fork_point = dec_u32(r)
    if not r.eof():
        raise StreamableError(f"trailing bytes after NewPeakWallet: {r.remaining()}")
    return {"header_hash": header_hash, "height": height, "weight": weight,
            "fork_point_with_previous_peak": fork_point}


# ---------------------------------------------------------------------------
# Our pinned outbound handshake
# ---------------------------------------------------------------------------

PINNED_PROTOCOL_VERSION = "0.0.37"
PINNED_SOFTWARE_VERSION = "0.0.0"
PINNED_CAPABILITIES = [(1, "1"), (2, "1"), (3, "1")]  # BASE, BLOCK_HEADERS, RATE_LIMITS_V2


def make_outbound_handshake(network_id: str) -> Handshake:
    """The exact handshake a Chia wallet sends (verified against
    chia-blockchain 2.7.4's perform_handshake + default capabilities)."""
    return Handshake(
        network_id=network_id,
        protocol_version=PINNED_PROTOCOL_VERSION,
        software_version=PINNED_SOFTWARE_VERSION,
        server_port=0,
        node_type=NodeType.WALLET,
        capabilities=list(PINNED_CAPABILITIES),
    )

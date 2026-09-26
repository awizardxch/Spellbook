"""Minimal Ethereum ABI encoder/decoder for Spellbook contract intents.

Supports the elementary types and arrays needed for contract_deploy /
contract_call / contract_call_view: address, bool, uint<M>, int<M>,
bytes<M>, bytes, string, and (nested) static/dynamic arrays.

Tuples/structs are REFUSED — fail closed rather than half-encode a struct
layout the caller may have mis-specified. Fixed-point types (fixed/ufixed)
are refused for the same reason.

No third-party dependency: the codebase hand-rolls crypto already
(spellbook.evm), and the ABI codec stays small and auditable. The test
suite cross-checks vectors against eth_abi (test-only oracle, never
imported by src/).

Value coercion (JSON-friendly — everything crosses the daemon socket):
- uint<M>/int<M>: Python int, or a decimal string ("123"). bool is
  rejected explicitly (True == 1 in Python; silent coercion hides bugs).
- address: "0x" + 40 hex chars (any case; encoding is case-insensitive).
- bytes<M>: "0x" hex of exactly M bytes, or a bytes object.
- bytes: "0x" hex or bytes. string: str.
- arrays: list/tuple; static arrays must match the declared length.
"""

from Crypto.Hash import keccak


class AbiError(Exception):
    """Anything the v1 codec cannot encode or decode — fail closed."""


# ---------------------------------------------------------------- types

def _parse_type(t: str):
    """Split 'uint256[3][]' into (kind, size, dims).

    kind is one of address/bool/uint/int/bytesN/bytes/string, size is the
    bit/byte width (or None), dims is the array dimensions (None entry =
    dynamic dimension), outermost first.
    """
    if not isinstance(t, str) or not t:
        raise AbiError(f"bad ABI type: {t!r}")
    dims = []
    base = t
    while base.endswith("]"):
        open_br = base.rfind("[")
        if open_br == -1:
            raise AbiError(f"bad ABI type: {t!r}")
        dim = base[open_br + 1:-1]
        if dim == "":
            dims.append(None)
        elif dim.isdigit() and int(dim) > 0:
            dims.append(int(dim))
        else:
            raise AbiError(f"bad array dimension in ABI type: {t!r}")
        base = base[:open_br]
    # The rightmost bracket is the OUTERMOST dimension, and the loop
    # strips right-to-left, so dims is already outermost-first.
    if base == "address":
        kind, size = "address", None
    elif base == "bool":
        kind, size = "bool", None
    elif base == "string":
        kind, size = "string", None
    elif base == "bytes":
        kind, size = "bytes", None
    elif base == "uint":
        kind, size = "uint", 256
    elif base == "int":
        kind, size = "int", 256
    elif base.startswith("uint"):
        kind, size = "uint", _width(base, t, 8, 256, step=8)
    elif base.startswith("int"):
        kind, size = "int", _width(base, t, 8, 256, step=8)
    elif base.startswith("bytes"):
        kind, size = "bytesN", _width(base, t, 1, 32, step=1)
    else:
        raise AbiError(f"unsupported ABI type: {t!r} "
                       "(tuples/structs and fixed-point are not supported)")
    return kind, size, dims


def _width(base: str, full: str, lo: int, hi: int, step: int) -> int:
    # "uint" is 4 letters, "bytes" is 5, "int" is 3.
    if base.startswith("uint"):
        digits = base[4:]
    elif base.startswith("bytes"):
        digits = base[5:]
    else:
        digits = base[3:]
    if not digits.isdigit():
        raise AbiError(f"bad ABI type: {full!r}")
    n = int(digits)
    if not (lo <= n <= hi) or n % step:
        raise AbiError(f"bad ABI type: {full!r}")
    return n


def _is_dynamic(kind, size, dims) -> bool:
    if dims:
        # A static array is dynamic iff its element type is dynamic.
        return dims[0] is None or _is_dynamic(kind, size, dims[1:])
    return kind in ("bytes", "string")


# ---------------------------------------------------------------- encode

def _encode_uint(v, bits: int) -> bytes:
    if isinstance(v, bool):
        raise AbiError("bool is not a valid uint value")
    if isinstance(v, str):
        if not v.isdigit():
            raise AbiError(
                f"uint value must be a non-negative integer, got {v!r}")
        v = int(v)
    if not isinstance(v, int) or v < 0 or v >= 1 << bits:
        raise AbiError(f"uint{bits} value out of range: {v!r}")
    return v.to_bytes(32, "big")


def _encode_int(v, bits: int) -> bytes:
    if isinstance(v, bool):
        raise AbiError("bool is not a valid int value")
    if isinstance(v, str):
        s = v.strip()
        neg = s.startswith("-")
        if not s.lstrip("-").isdigit():
            raise AbiError(f"int value must be an integer, got {v!r}")
        v = -int(s[1:]) if neg else int(s)
    if not isinstance(v, int) or v < -(1 << (bits - 1)) or v >= 1 << (bits - 1):
        raise AbiError(f"int{bits} value out of range: {v!r}")
    return (v % (1 << 256)).to_bytes(32, "big")


def _encode_address(v) -> bytes:
    if not (isinstance(v, str) and len(v) == 42 and v.startswith("0x")):
        raise AbiError(f"address must be 0x + 40 hex chars, got {v!r}")
    try:
        raw = bytes.fromhex(v[2:])
    except ValueError:
        raise AbiError(f"address is not valid hex: {v!r}")
    return b"\x00" * 12 + raw


def _encode_bytes_n(v, n: int) -> bytes:
    raw = _coerce_bytes(v, f"bytes{n}")
    if len(raw) != n:
        raise AbiError(f"bytes{n} needs exactly {n} bytes, got {len(raw)}")
    return raw + b"\x00" * (32 - n)


def _coerce_bytes(v, what: str) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, str) and v.startswith("0x"):
        try:
            return bytes.fromhex(v[2:])
        except ValueError:
            raise AbiError(f"{what} is not valid hex: {v!r}")
    raise AbiError(f"{what} must be 0x-prefixed hex or bytes, got {v!r}")


def _encode_dynamic_bytes(raw: bytes) -> bytes:
    return (len(raw).to_bytes(32, "big") + raw
            + b"\x00" * ((32 - len(raw) % 32) % 32))


def _encode_value(kind, size, dims, v):
    """Encode one value (possibly an array) to its ABI bytes."""
    if dims:
        if not isinstance(v, (list, tuple)):
            raise AbiError(f"array value must be a list, got {v!r}")
        dim = dims[0]
        if dim is not None and len(v) != dim:
            raise AbiError(
                f"static array needs {dim} elements, got {len(v)}")
        sub_dyn = _is_dynamic(kind, size, dims[1:])
        elems = [_encode_value(kind, size, dims[1:], e) for e in v]
        if dim is None or sub_dyn:
            # Dynamic array, or static array of dynamic elements:
            # length word (dynamic only) then tuple-style head/tail.
            pairs = [(e, sub_dyn) for e in elems]
            head = _encode_sequence(pairs)
            if dim is None:
                return len(v).to_bytes(32, "big") + head
            return head
        return b"".join(elems)
    if kind == "uint":
        return _encode_uint(v, size)
    if kind == "int":
        return _encode_int(v, size)
    if kind == "address":
        return _encode_address(v)
    if kind == "bool":
        if not isinstance(v, bool):
            raise AbiError(f"bool value must be true/false, got {v!r}")
        return (1 if v else 0).to_bytes(32, "big")
    if kind == "bytesN":
        return _encode_bytes_n(v, size)
    if kind == "bytes":
        return _encode_dynamic_bytes(_coerce_bytes(v, "bytes"))
    if kind == "string":
        if not isinstance(v, str):
            raise AbiError(f"string value must be a string, got {v!r}")
        return _encode_dynamic_bytes(v.encode("utf-8"))
    raise AbiError(f"unreachable kind {kind!r}")  # pragma: no cover


def _encode_sequence(pairs: list) -> bytes:
    """Head/tail layout. pairs = [(encoded_bytes, is_dynamic), ...].

    Offsets are relative to the start of this sequence.
    """
    head, tail = b"", b""
    offset = 32 * len(pairs)
    for enc, dyn in pairs:
        if dyn:
            head += offset.to_bytes(32, "big")
            tail += enc
            offset += len(enc)
        else:
            head += enc
    return head + tail


def encode_args(types: list, values: list) -> bytes:
    """Encode a list of values against a list of ABI type strings."""
    if len(types) != len(values):
        raise AbiError(
            f"{len(values)} args for {len(types)} ABI inputs — refusing")
    pairs = []
    for t, v in zip(types, values):
        kind, size, dims = _parse_type(t)
        pairs.append((_encode_value(kind, size, dims, v),
                      _is_dynamic(kind, size, dims)))
    return _encode_sequence(pairs)


def encode_function_call(method_abi: dict, args) -> str:
    """Encode calldata for a contract method. Returns 0x-prefixed hex.

    method_abi is a standard ABI fragment: {"name": ..., "inputs":
    [{"name":..., "type":...}], ...}. The selector is keccak of the
    canonical signature.
    """
    name, inputs = _method_inputs(method_abi)
    types = [i["type"] for i in inputs]
    sig = f"{name}({','.join(types)})"
    selector = keccak.new(data=sig.encode(), digest_bits=256).digest()[:4]
    return "0x" + (selector + encode_args(types, list(args or []))).hex()


def encode_constructor(bytecode: str, constructor_abi, args) -> str:
    """Append encoded constructor args to init bytecode. 0x-prefixed hex.

    constructor_abi is {"inputs": [...]} or a bare list of inputs; None
    means the constructor takes no args (args must then be empty).
    """
    data = _coerce_bytes(bytecode, "bytecode")
    if not data:
        raise AbiError("bytecode is empty — nothing to deploy")
    if len(data) > 49152:
        raise AbiError(
            f"init bytecode {len(data)} bytes exceeds the EIP-3860 "
            "init-code limit (49152) — refusing")
    types = [i["type"] for i in _constructor_inputs(constructor_abi)]
    return "0x" + (data + encode_args(types, list(args or []))).hex()


def _method_inputs(method_abi: dict):
    if not isinstance(method_abi, dict):
        raise AbiError("method_abi must be an ABI JSON object")
    name = method_abi.get("name")
    inputs = method_abi.get("inputs", [])
    if not isinstance(name, str) or not name:
        raise AbiError("method_abi needs a non-empty name")
    _check_inputs(inputs, "method_abi")
    return name, inputs


def _constructor_inputs(constructor_abi):
    if constructor_abi is None:
        return []
    if isinstance(constructor_abi, dict):
        inputs = constructor_abi.get("inputs", [])
    elif isinstance(constructor_abi, list):
        inputs = constructor_abi
    else:
        raise AbiError("constructor_abi must be an object or a list")
    _check_inputs(inputs, "constructor_abi")
    return inputs


def _check_inputs(inputs, what: str):
    if not isinstance(inputs, list):
        raise AbiError(f"{what} inputs must be a list")
    for i in inputs:
        if not isinstance(i, dict) or "type" not in i:
            raise AbiError(f"{what} inputs need {{name, type}} entries")
        _parse_type(i["type"])  # fail closed on unsupported types now


# ---------------------------------------------------------------- decode

def decode_abi(types: list, data_hex: str) -> list:
    """Decode ABI-encoded return data against output type strings."""
    data = _coerce_bytes(data_hex, "return data")
    vals, _ = _decode_sequence(types, data, 0, 0)
    return vals


def _read_word(data: bytes, pos: int) -> bytes:
    w = data[pos:pos + 32]
    if len(w) < 32:
        raise AbiError("return data truncated")
    return w


def _decode_sequence(types: list, data: bytes, pos: int, base: int):
    """Decode a head/tail sequence. base = sequence start (offsets are
    relative to it). Returns (values, end_pos)."""
    parsed = [_parse_type(t) for t in types]
    values: list = [None] * len(parsed)
    deferred = []  # (index, offset) for dynamic values
    for i, (kind, size, dims) in enumerate(parsed):
        if _is_dynamic(kind, size, dims):
            off = int.from_bytes(_read_word(data, pos), "big")
            pos += 32
            deferred.append((i, off))
        elif dims:
            # Static array of static elements: inline at pos.
            v, pos = _decode_static_array(kind, size, dims, data, pos)
            values[i] = v
        else:
            values[i] = _decode_word(kind, size, _read_word(data, pos))
            pos += 32
    for i, off in deferred:
        kind, size, dims = parsed[i]
        v, _ = _decode_at(kind, size, dims, data, base + off, base)
        values[i] = v
    return values, pos


def _decode_static_array(kind, size, dims, data: bytes, pos: int):
    """Decode a static array whose elements are all static (inline)."""
    dim = dims[0]
    vals = []
    for _ in range(dim):
        v, pos = _decode_at(kind, size, dims[1:], data, pos, None)
        vals.append(v)
    return vals, pos


def _decode_at(kind, size, dims, data: bytes, pos: int, base):
    """Decode a value at absolute position pos.

    Handles: dynamic arrays, static arrays of dynamic elements (both via
    their head/tail sections), static arrays of static elements (inline),
    dynamic bytes/string, and simple static words.
    Returns (value, next_pos).
    """
    if dims:
        dim = dims[0]
        sub = (kind, size, dims[1:])
        if dim is None:
            # Dynamic array: length word, then the element section.
            ln = int.from_bytes(_read_word(data, pos), "big")
            seq = pos + 32
            if _is_dynamic(*sub):
                vals = _decode_dyn_elems(sub, data, seq, ln)
            else:
                # Dynamic array of static scalars: ln plain words.
                vals = [_decode_word(kind, size,
                                     _read_word(data, seq + 32 * i))
                        for i in range(ln)]
            return vals, pos + 32 + _array_span(sub, data, seq, ln)
        if _is_dynamic(*sub):
            # Static array of dynamic elements: head/tail at pos.
            return _decode_dyn_elems(sub, data, pos, dim), \
                pos + _array_span(sub, data, pos, dim)
        # Static array of static elements: inline.
        return _decode_static_array(kind, size, dims, data, pos)
    if kind in ("bytes", "string"):
        ln = int.from_bytes(_read_word(data, pos), "big")
        raw = data[pos + 32:pos + 32 + ln]
        if len(raw) < ln:
            raise AbiError("return data truncated")
        span = 32 + ((ln + 31) // 32) * 32
        if kind == "string":
            try:
                return raw.decode("utf-8"), pos + span
            except UnicodeDecodeError:
                raise AbiError("string is not valid UTF-8 in return data")
        return "0x" + raw.hex(), pos + span
    return _decode_word(kind, size, _read_word(data, pos)), pos + 32


def _decode_dyn_elems(sub, data: bytes, seq: int, ln: int):
    """Decode ln dynamic elements from a head/tail section at seq."""
    kind, size, dims = sub
    heads = [int.from_bytes(_read_word(data, seq + 32 * i), "big")
             for i in range(ln)]
    return [_decode_at(kind, size, dims, data, seq + off, seq)[0]
            for off in heads]


def _array_span(sub, data: bytes, seq: int, ln: int) -> int:
    """Byte span of an array's element section starting at seq."""
    kind, size, dims = sub
    if ln == 0:
        return 0
    if not _is_dynamic(kind, size, dims):
        return ln * 32
    end = ln * 32
    for i in range(ln):
        off = int.from_bytes(_read_word(data, seq + 32 * i), "big")
        end = max(end, off + _elem_span(kind, size, dims, data, seq + off))
    return end


def _elem_span(kind, size, dims, data: bytes, pos: int) -> int:
    """Byte span of one dynamic element's encoding at pos."""
    if dims:
        dim = dims[0]
        if dim is None:
            ln = int.from_bytes(_read_word(data, pos), "big")
            return 32 + _array_span((kind, size, dims[1:]), data,
                                    pos + 32, ln)
        return _array_span((kind, size, dims[1:]), data, pos, dim)
    if kind in ("bytes", "string"):
        ln = int.from_bytes(_read_word(data, pos), "big")
        return 32 + ((ln + 31) // 32) * 32
    return 32


def _decode_word(kind, size, word: bytes):
    if kind == "uint":
        v = int.from_bytes(word, "big")
        if v >= 1 << size:
            raise AbiError("uint value out of range in return data")
        return v
    if kind == "int":
        v = int.from_bytes(word, "big")
        return v - (1 << 256) if v >= 1 << (size - 1) else v
    if kind == "address":
        if word[:12] != b"\x00" * 12:
            raise AbiError("address has dirty high bits in return data")
        return "0x" + word[12:].hex()
    if kind == "bool":
        v = int.from_bytes(word, "big")
        if v not in (0, 1):
            raise AbiError("bool is not 0/1 in return data")
        return bool(v)
    if kind == "bytesN":
        return "0x" + word[:size].hex()
    raise AbiError(f"unreachable kind {kind!r}")  # pragma: no cover

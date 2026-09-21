"""Chia local signing for the Spellbook daemon (relay architecture).

Every secret stays on the daemon. This module:

  - derives wallet keys: master secret -> unhardened path [12381, 8444, 2, index]
  - derives synthetic keys against the default hidden puzzle
  - builds the standard-transaction puzzle reveal (curried
    p2_delegated_puzzle_or_hidden_puzzle) and its puzzle hash / address
  - builds standard solutions from condition lists
  - signs spends: AGG_SIG_ME preimage =
        sha256tree1((q . conditions)) || coin_id || genesis_challenge
    (AugSchemeMPL; signatures aggregated across the bundle)

Verified against the vendored chia-sdk sources the Sage build pulls in:
chia-bls 0.36.1 (derive_keys.rs: unhardened derivation, wallet path),
chia-puzzle-types 0.36.1 (derive_synthetic.rs: synthetic offset;
standard.rs: from_conditions), chia-sdk-signer 0.36.0
(required_signature.rs / required_bls_signature.rs: AGG_SIG_ME preimage =
condition message || coin_id || agg_sig_me_additional_data), chia-puzzles
0.20.3 (p2_delegated_puzzle_or_hidden_puzzle.clsp: the AGG_SIG_ME condition
message is sha256tree1 of the quoted delegated puzzle), and
chia-sdk-types 0.36.0 (constants.rs: testnet11 agg_sig_me_additional_data
== testnet11 genesis challenge).

Uses blspy (BLS12-381, audited) for all curve work plus hashlib for the
hashes. No key material is ever logged; errors never include secrets.

Test vectors: tests/test_chia_sign.py checks derivation against the Rust
SDK's own synthetic-key vectors and the puzzle pipeline against the real
CLVM (chia_rs).
"""

import hashlib

from blspy import AugSchemeMPL, G1Element, PrivateKey

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# BLS12-381 subgroup order (blspy enforces < order on PrivateKey.from_bytes).
BLS_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

# Default hidden puzzle `(=)` and its tree hash (chia-puzzle-types).
DEFAULT_HIDDEN_PUZZLE = bytes.fromhex("ff0980")
DEFAULT_HIDDEN_PUZZLE_HASH = bytes.fromhex(
    "711d6c4e32c92e53179b199484cf8c897542bc57f2b22582799f9d657eec4699"
)

# p2_delegated_puzzle_or_hidden_puzzle, compiled (chia-puzzles 0.20.3).
# Tree hash verified: e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52
P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE = bytes.fromhex(
    "ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02"
    "ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180"
    "ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff808080"
    "80ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff01"
    "02ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff80808080"
    "80ffff01ff0bffff0101ff058080ff0180ff018080"
)
P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE_HASH = bytes.fromhex(
    "e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52"
)

# Genesis challenges == agg_sig_me additional data per network
# (chia-sdk-types constants.rs: default_constants(genesis, genesis)).
TESTNET11_GENESIS_CHALLENGE = bytes.fromhex(
    "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
)
MAINNET_GENESIS_CHALLENGE = bytes.fromhex(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
)

GENESIS_CHALLENGE = {
    "testnet11": TESTNET11_GENESIS_CHALLENGE,
    "mainnet": MAINNET_GENESIS_CHALLENGE,
}

ADDRESS_PREFIX = {
    "testnet11": "txch",
    "mainnet": "xch",
}

# Condition opcodes (chia condition_opcodes.py).
AGG_SIG_ME = 50
CREATE_COIN = 51


class ChiaSignError(Exception):
    """Any local signing failure. Never carries key material."""


# ---------------------------------------------------------------------------
# CLVM serialization (atoms and pairs only — everything we build)
# ---------------------------------------------------------------------------

NIL = b""  # () serializes to 0x80


def _ser_atom(blob: bytes) -> bytes:
    n = len(blob)
    if n == 0:
        return b"\x80"
    if n == 1 and blob[0] < 0x80:
        return blob
    if n < 0x40:
        return bytes([0x80 | n]) + blob
    if n < 0x2000:
        return bytes([0xC0 | (n >> 8), n & 0xFF]) + blob
    raise ChiaSignError("atom too large to serialize")


def ser(obj) -> bytes:
    """Serialize a CLVM s-expression: bytes = atom, tuple(first, rest) = pair."""
    if isinstance(obj, bytes):
        return _ser_atom(obj)
    first, rest = obj
    return b"\xff" + ser(first) + ser(rest)


def sha256tree(obj) -> bytes:
    """sha256tree1: sha256(0x01 || atom) for atoms,
    sha256(0x02 || sha256tree(l) || sha256tree(r)) for pairs."""
    if isinstance(obj, bytes):
        return hashlib.sha256(b"\x01" + obj).digest()
    first, rest = obj
    return hashlib.sha256(b"\x02" + sha256tree(first) + sha256tree(rest)).digest()


def int_to_bytes(v: int) -> bytes:
    """Chia's int_to_bytes: minimal signed big-endian (for condition args)."""
    if v == 0:
        return b""
    if v < 0:
        raise ChiaSignError("negative ints not supported in conditions")
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def _cons(first, rest):
    return (first, rest)


def _list(items) -> bytes:
    """Build a CLVM list s-expression from Python items (bytes or nested)."""
    out = NIL
    for item in reversed(items):
        out = _cons(item, out)
    return out


def deser(data: bytes):
    """Deserialize CLVM bytes into s-expr (bytes atoms / tuple pairs)."""
    def go(pos):
        if pos >= len(data):
            raise ChiaSignError("truncated CLVM")
        b = data[pos]
        if b == 0xFF:
            first, pos = go(pos + 1)
            rest, pos = go(pos)
            return (first, rest), pos
        if b <= 0x7F:
            return bytes([b]), pos + 1
        if b <= 0xBF:
            n = b & 0x3F
            pos += 1
        elif b <= 0xDF:
            n = ((b & 0x1F) << 8) | data[pos + 1]
            pos += 2
        elif b <= 0xEF:
            n = ((b & 0x0F) << 16) | (data[pos + 1] << 8) | data[pos + 2]
            pos += 3
        elif b <= 0xF7:
            n = ((b & 0x07) << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
            pos += 4
        else:
            raise ChiaSignError("bad CLVM atom prefix")
        return data[pos:pos + n], pos + n
    obj, pos = go(0)
    if pos != len(data):
        raise ChiaSignError("trailing bytes in CLVM")
    return obj


def quote(obj):
    """(q . obj) — dotted quote. Valid when obj is a LIST (CLVM quote returns
    it unevaluated). Matches chia's clvm_quote! for the delegated puzzle."""
    return _cons(b"\x01", obj)


# (quote_atom removed — _unwrap_quote handles atoms via (f (q X)))


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _sk_to_int(sk: bytes) -> int:
    if len(sk) != 32:
        raise ChiaSignError("secret key must be 32 bytes")
    v = int.from_bytes(sk, "big")
    if not 0 < v < BLS_ORDER:
        raise ChiaSignError("secret scalar out of range")
    return v


def _sk_from_int(v: int) -> bytes:
    return (v % BLS_ORDER).to_bytes(32, "big")


def _g1(sk: bytes) -> G1Element:
    return AugSchemeMPL.sk_to_g1(PrivateKey.from_bytes(sk))


def pk_bytes(sk: bytes) -> bytes:
    """48-byte compressed G1 public key for a 32-byte secret."""
    return bytes(_g1(sk))


def derive_sk_unhardened(sk: bytes, index: int) -> bytes:
    """One unhardened child: offset = sha256(pk || index_be32); sk' = sk + offset.

    Matches chia-bls derive_keys.rs (DerivableKey::derive_unhardened).
    """
    if not 0 <= index < 2**32:
        raise ChiaSignError("derivation index out of range")
    digest = hashlib.sha256(pk_bytes(sk) + index.to_bytes(4, "big")).digest()
    return _sk_from_int(_sk_to_int(sk) + int.from_bytes(digest, "big"))


def wallet_sk(master_sk: bytes, index: int) -> bytes:
    """master -> [12381, 8444, 2, index], all unhardened (Sage/Chia wallet path)."""
    if len(master_sk) != 32:
        raise ChiaSignError("master secret key must be 32 bytes")
    if index < 0:
        raise ChiaSignError("index must be non-negative")
    sk = master_sk
    for level in (12381, 8444, 2, index):
        sk = derive_sk_unhardened(sk, level)
    return sk


def wallet_pk(master_sk: bytes, index: int) -> bytes:
    """48-byte wallet public key at `index`."""
    return pk_bytes(wallet_sk(master_sk, index))


def _mod_by_group_order_signed(digest: bytes) -> bytes:
    """chia-puzzle-types `mod_by_group_order`: BigInt::from_signed_bytes_be.

    The 32-byte digest is interpreted as a SIGNED big-endian integer
    (two's complement), then reduced mod n. This matters whenever the
    digest's high bit is set.
    """
    if len(digest) != 32:
        raise ChiaSignError("digest must be 32 bytes")
    v = int.from_bytes(digest, "big")
    if digest[0] & 0x80:
        v -= 1 << 256
    return (((v % BLS_ORDER) + BLS_ORDER) % BLS_ORDER).to_bytes(32, "big")


def synthetic_offset(wallet_pk_bytes: bytes,
                     hidden_puzzle_hash: bytes = DEFAULT_HIDDEN_PUZZLE_HASH) -> bytes:
    """sha256(wallet_pk || hidden_puzzle_hash), signed-mod-n, as 32-byte scalar.

    Matches chia-puzzle-types synthetic_offset (note the signed reduction).
    """
    if len(hidden_puzzle_hash) != 32 or len(wallet_pk_bytes) != 48:
        raise ChiaSignError("bad lengths for synthetic offset inputs")
    digest = hashlib.sha256(wallet_pk_bytes + hidden_puzzle_hash).digest()
    return _mod_by_group_order_signed(digest)


def synthetic_sk(wallet_sk_bytes: bytes,
                 hidden_puzzle_hash: bytes = DEFAULT_HIDDEN_PUZZLE_HASH) -> bytes:
    """Synthetic secret key = wallet_sk + offset (mod n)."""
    offset = synthetic_offset(pk_bytes(wallet_sk_bytes), hidden_puzzle_hash)
    return _sk_from_int(
        _sk_to_int(wallet_sk_bytes) + int.from_bytes(offset, "big"))


def synthetic_pk(wallet_pk_bytes: bytes,
                 hidden_puzzle_hash: bytes = DEFAULT_HIDDEN_PUZZLE_HASH) -> bytes:
    """Synthetic public key = wallet_pk + offset*G (no secret needed)."""
    offset = synthetic_offset(wallet_pk_bytes, hidden_puzzle_hash)
    offset_pt = _g1(offset)
    return bytes(G1Element.from_bytes(wallet_pk_bytes) + offset_pt)


# ---------------------------------------------------------------------------
# Puzzle, puzzle hash, address
# ---------------------------------------------------------------------------

def _unwrap_quote(sexpr):
    """(f (q X)) — CLVM's (q X) returns (X); f unwraps to X."""
    return (b"\x05", (_list([b"\x01", sexpr]), b""))


def standard_puzzle_reveal(synthetic_pk_bytes: bytes) -> bytes:
    """Curried p2_delegated_puzzle_or_hidden_puzzle.

    (a (f (q MOD)) (c (f (q pk)) 1)): CLVM (q X) evaluates to (X), so f
    unwraps to the program/atom. MOD is embedded as a parsed s-expression.
    When applied to a solution S the module receives (pk . S).
    """
    if len(synthetic_pk_bytes) != 48:
        raise ChiaSignError("synthetic public key must be 48 bytes")
    mod = deser(P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE)
    inner = _cons(b"\x04", _cons(_unwrap_quote(synthetic_pk_bytes),
                                 _cons(b"\x01", NIL)))
    curried = _cons(b"\x02", _cons(_unwrap_quote(mod), _cons(inner, NIL)))
    return ser(curried)


def puzzle_hash_for_synthetic_pk(synthetic_pk_bytes: bytes) -> bytes:
    """sha256tree of the curried standard puzzle."""
    if len(synthetic_pk_bytes) != 48:
        raise ChiaSignError("synthetic public key must be 48 bytes")
    mod = deser(P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE)
    inner = _cons(b"\x04", _cons(_unwrap_quote(synthetic_pk_bytes),
                                 _cons(b"\x01", NIL)))
    curried = _cons(b"\x02", _cons(_unwrap_quote(mod), _cons(inner, NIL)))
    return sha256tree(curried)


def _bech32_polymod(values) -> int:
    GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if (b >> i) & 1 else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ChiaSignError("bad bech32 padding")
    return out


_BECH32M_CONST = 0x2BC830A3
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def address_for_puzzle_hash(puzzle_hash: bytes, prefix: str) -> str:
    """bech32m encode (Chia address format)."""
    if len(puzzle_hash) != 32:
        raise ChiaSignError("puzzle hash must be 32 bytes")
    data = _convertbits(puzzle_hash, 8, 5)
    polymod = _bech32_polymod(_bech32_hrp_expand(prefix) + data + [0] * 6) ^ _BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return prefix + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def puzzle_hash_for_address(address: str) -> bytes:
    """bech32m decode; fail-closed on bad checksum / charset / prefix."""
    address = address.strip().lower()
    if "1" not in address:
        raise ChiaSignError("bad chia address: no separator")
    hrp, _, data_part = address.rpartition("1")
    if not hrp or len(data_part) < 6:
        raise ChiaSignError("bad chia address: malformed")
    try:
        data = [_BECH32_CHARSET.index(c) for c in data_part]
    except ValueError:
        raise ChiaSignError("bad chia address: bad charset")
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != _BECH32M_CONST:
        raise ChiaSignError("bad chia address: checksum")
    vals = data[:-6]
    acc = bits = 0
    out = bytearray()
    for v in vals:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if len(out) != 32:
        raise ChiaSignError("bad chia address: payload length")
    return bytes(out)


def receive_address(master_sk: bytes, index: int, network_id: str) -> str:
    """Standard receive address at derivation `index` for a network."""
    if network_id not in ADDRESS_PREFIX:
        raise ChiaSignError(f"unknown network {network_id!r}")
    wpk = wallet_pk(master_sk, index)
    spk = synthetic_pk(wpk)
    return address_for_puzzle_hash(puzzle_hash_for_synthetic_pk(spk),
                                   ADDRESS_PREFIX[network_id])


# ---------------------------------------------------------------------------
# Coins, conditions, solutions
# ---------------------------------------------------------------------------

def coin_id(parent_coin_id: bytes, puzzle_hash: bytes, amount: int) -> bytes:
    """sha256(parent || puzzle_hash || int_to_bytes(amount)).

    Chia's Coin.name() serializes the amount with int_to_bytes (minimal
    signed big-endian), NOT fixed 8-byte big-endian. Using the wrong
    encoding produces a coin_id the network rejects with
    BAD_AGGREGATE_SIGNATURE (the AGG_SIG_ME message commits to coin_id).
    """
    if len(parent_coin_id) != 32 or len(puzzle_hash) != 32 or amount < 0:
        raise ChiaSignError("bad coin fields")
    return hashlib.sha256(
        parent_coin_id + puzzle_hash + int_to_bytes(amount)).digest()


def create_coin_condition(puzzle_hash: bytes, amount: int):
    """One CREATE_COIN condition as an s-expression."""
    return _list([int_to_bytes(CREATE_COIN), puzzle_hash, int_to_bytes(amount)])


def standard_solution_sexpr(conditions_sexpr):
    """(None, (q . conditions), ()) — StandardSolution::from_conditions."""
    return _list([NIL, quote(conditions_sexpr), NIL])


def conditions_from_outputs(outputs) -> list:
    """outputs: [(puzzle_hash, amount_mojos)] -> condition s-expressions."""
    return [create_coin_condition(ph, amt) for ph, amt in outputs]


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def aggsig_me_message(condition_message: bytes, coin_id_bytes: bytes,
                      network_id: str) -> bytes:
    """The exact AGG_SIG_ME preimage consensus verifies:

        condition_message || coin_id || agg_sig_me_additional_data

    (chia-sdk-signer RequiredBlsSignature::message(); additional data is the
    network's genesis challenge — chia-sdk-types constants.rs.)
    """
    if network_id not in GENESIS_CHALLENGE:
        raise ChiaSignError(f"unknown network {network_id!r}")
    if len(coin_id_bytes) != 32:
        raise ChiaSignError("coin id must be 32 bytes")
    return condition_message + coin_id_bytes + GENESIS_CHALLENGE[network_id]


def sign_coin_spend(synthetic_sk_bytes: bytes, coin: tuple,
                    conditions_sexpr, network_id: str) -> bytes:
    """Sign one standard coin spend. Returns the 96-byte BLS signature.

    coin: (parent_coin_id, puzzle_hash, amount).
    The signed message is sha256tree1((q . conditions)) || coin_id ||
    genesis_challenge — the same message the puzzle's AGG_SIG_ME condition
    commits to (p2_delegated_puzzle_or_hidden_puzzle.clsp) and the same
    preimage consensus verifies (chia-sdk-signer).
    """
    parent, puzzle_hash, amount = coin
    cid = coin_id(parent, puzzle_hash, amount)
    condition_message = sha256tree(quote(conditions_sexpr))
    msg = aggsig_me_message(condition_message, cid, network_id)
    sk = PrivateKey.from_bytes(synthetic_sk_bytes)
    return bytes(AugSchemeMPL.sign(sk, msg))


def aggregate_signatures(sigs: list) -> bytes:
    """Aggregate 96-byte BLS signatures into one 96-byte SpendBundle signature."""
    if not sigs:
        raise ChiaSignError("nothing to aggregate")
    for s in sigs:
        if len(s) != 96:
            raise ChiaSignError("signature must be 96 bytes")
    from blspy import G2Element
    return bytes(AugSchemeMPL.aggregate([G2Element.from_bytes(s) for s in sigs]))


def verify_coin_spend_signature(synthetic_pk_bytes: bytes, coin: tuple,
                                conditions_sexpr, network_id: str,
                                signature: bytes) -> bool:
    """Local sanity check: AugSchemeMPL.verify over the consensus preimage."""
    parent, puzzle_hash, amount = coin
    cid = coin_id(parent, puzzle_hash, amount)
    condition_message = sha256tree(quote(conditions_sexpr))
    msg = aggsig_me_message(condition_message, cid, network_id)
    from blspy import G2Element
    return AugSchemeMPL.verify(G1Element.from_bytes(synthetic_pk_bytes), msg,
                               G2Element.from_bytes(signature))


# ---------------------------------------------------------------------------
# SpendBundle serialization (chia Streamable layout)
# ---------------------------------------------------------------------------

def _ser_u8(v: int) -> bytes:
    return v.to_bytes(1, "big")


def _ser_u16(v: int) -> bytes:
    return v.to_bytes(2, "big")


def _ser_u32(v: int) -> bytes:
    return v.to_bytes(4, "big")


def _ser_u64(v: int) -> bytes:
    return v.to_bytes(8, "big")


def _ser_bytes(b: bytes) -> bytes:
    return _ser_u32(len(b)) + b


def _ser_option(b: bytes | None) -> bytes:
    # Option<Bytes>: 0x00 = none, 0x01 + u32-len + bytes = some
    if b is None:
        return b"\x00"
    return b"\x01" + _ser_bytes(b)


def coin_spend_bytes(coin: tuple, puzzle_reveal: bytes, solution: bytes) -> bytes:
    """Streamable CoinSpend: coin(parent, puzzle_hash, amount) + puzzle_reveal + solution.

    Consensus framing: Program fields are BARE self-delimiting CLVM with NO
    length prefix (verified against chia-protocol's Program::parse). A u32
    prefix here makes peers fail parsing and kill the connection.
    """
    parent, puzzle_hash, amount = coin
    return (parent + puzzle_hash + _ser_u64(amount)
            + puzzle_reveal + solution)


def spend_bundle_bytes(coin_spends: list, aggregated_signature: bytes) -> bytes:
    """Streamable SpendBundle: Vec<CoinSpend> + 96-byte G2 signature."""
    if len(aggregated_signature) != 96:
        raise ChiaSignError("aggregated signature must be 96 bytes")
    out = _ser_u32(len(coin_spends))
    for cs in coin_spends:
        out += cs
    return out + aggregated_signature


def build_standard_spend(master_sk: bytes, index: int, coin: tuple,
                         outputs: list, network_id: str) -> dict:
    """Build + sign a standard spend of `coin` to `outputs`.

    Returns {"coin_spend": bytes, "signature": bytes(96),
             "puzzle_reveal": bytes, "solution": bytes,
             "synthetic_pk": bytes, "puzzle_hash": bytes}.
    coin: (parent_coin_id, puzzle_hash, amount). outputs: [(puzzle_hash, amount)].
    """
    wsk = wallet_sk(master_sk, index)
    wpk = pk_bytes(wsk)
    ssk = synthetic_sk(wsk)
    spk = synthetic_pk(wpk)
    ph = puzzle_hash_for_synthetic_pk(spk)
    if ph != coin[1]:
        raise ChiaSignError("coin puzzle hash does not match this key/index")
    conditions = _list(conditions_from_outputs(outputs))
    solution = ser(standard_solution_sexpr(conditions))
    reveal = standard_puzzle_reveal(spk)
    sig = sign_coin_spend(ssk, coin, conditions, network_id)
    if not verify_coin_spend_signature(spk, coin, conditions, network_id, sig):
        raise ChiaSignError("self-verification of coin signature failed")
    cs = coin_spend_bytes(coin, reveal, solution)
    return {
        "coin_spend": cs,
        "signature": sig,
        "puzzle_reveal": reveal,
        "solution": solution,
        "synthetic_pk": spk,
        "puzzle_hash": ph,
    }


def build_spend_bundle(spends: list) -> bytes:
    """Aggregate per-spend signatures into a serialized SpendBundle.

    spends: list of build_standard_spend() dicts.
    """
    sigs = [s["signature"] for s in spends]
    agg = aggregate_signatures(sigs)
    return spend_bundle_bytes([s["coin_spend"] for s in spends], agg)

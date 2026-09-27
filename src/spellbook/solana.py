"""Solana chain layer — testnet/devnet-first. SPEC §10 companion.

Mirrors evm.py: stdlib JSON-RPC (urllib) + hand-rolled derivation, with
signing done by solders (audited Rust Ed25519 via PyO3). The SLIP-0010
ed25519 derivation is implemented manually in this module — key math
never depends on a wallet library.

Derivation modes (same one-seed model as EVM/Chia):
  - "kdf" (default): the daemon's 32-byte seed -> custom labeled KDF ->
    32-byte ed25519 seed -> keypair. See custom_seed().
  - "standard": the install's 24-word BIP-39 mnemonic -> 64-byte seed
    (stdkeys.mnemonic_to_seed) -> SLIP-0010 m/44'/501'/0'/0' ->
    Phantom/Solflare-compatible keypair.

Deviation note (auditable): kdf.derive_labeled() cannot be used
literally here — its CHAINS gate rejects "solana-devnet"/"solana-mainnet"
and it reduces the HKDF output modulo the secp256k1/BLS group order,
which is invalid for ed25519 (an ed25519 seed is arbitrary 32 bytes;
no modular reduction applies). Instead custom_seed() reuses kdf's exact
domain-separation parameters (SALT, INFO_PREFIX, the
"muse-wallet/v1/<chain>/sign/<label>" info-string shape) so Solana keys
stay in the same labeled family as EVM/Chia, minus the group-order
step. No existing file was modified to do this.

Safety rails (same posture as evm.py):
- Only plain native SOL transfers. build_transfer constructs exactly one
  SystemProgram transfer instruction — no other program id, no extra
  accounts, no data-bearing instructions; there is no parameter that
  could express anything else.
- Mainnet submission is a daemon-level gate ("mainnet_submit_enabled",
  §10.14-17), exactly as for EVM: this module signs and submits on
  whichever network the SolanaRpc was pointed at, and the daemon must
  refuse to point it at solana-mainnet without that flag.
- Before a tx leaves the machine, build_transfer self-verifies: the
  signature must verify against the serialized message, the fee payer
  must be the keypair's address, and the single instruction must decode
  to SystemProgram transfer(from=key, to=intent, lamports=intent).
- The RPC's network is checked via getGenesisHash before any signing —
  a mispointed RPC cannot redirect funds (mirrors evm.py's chain_id
  check).
- A confirmation timeout is NOT a failure: wait_signature raises
  BroadcastUnknown (the tx left the machine, its fate is unknown) so no
  caller ever blind-retries into a double-spend.

Signing path decision (2026-09-21): solders 0.29.0 installed cleanly in
.venv via pip, so solders is the signing/keypair path. SLIP-0010 stays
manual per the task spec.

No key material is ever logged. Errors never carry secrets.
"""
import base64
import hashlib
import hmac
import json
import time
import urllib.request

from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import ID as SYSTEM_PROGRAM, TransferParams, transfer
from solders.transaction import Transaction

from spellbook import kdf as _kdf

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LAMPORTS_PER_SOL = 1_000_000_000

SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
assert str(SYSTEM_PROGRAM) == SYSTEM_PROGRAM_ID, "solders system program id drift"

# m/44'/501'/0'/0' — what Phantom/Solflare derive from an imported mnemonic.
_H = 0x80000000
SOLANA_PATH = (_H + 44, _H + 501, _H + 0, _H + 0)

# Chrome UA: this VM's egress proxy 403s Python-urllib's default UA
# (same lesson as ~/workspace/AGENTS.md for Robinhood Chain + Musebook).
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

NETWORKS = {
    "solana-devnet": {
        "url": "https://api.devnet.solana.com",
        "testnet": True,
        "name": "Solana devnet",
        # Verified live 2026-09-21 via getGenesisHash.
        "genesis_hash": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
    },
    "solana-mainnet": {
        "url": "https://api.mainnet-beta.solana.com",
        "testnet": False,
        "name": "Solana mainnet-beta",
        # Verified live 2026-09-21 via getGenesisHash.
        "genesis_hash": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
    },
}


class SolanaError(Exception):
    """Any Solana layer failure. Never carries key material."""


class BroadcastUnknown(SolanaError):
    """The signed tx was accepted by the node (a signature exists) but no
    confirmation arrived within the wait window — the spend left the
    machine and its fate is UNKNOWN. Callers must NOT retry blindly
    (that would double-spend); they ledger the signature as unresolved
    and let a human reconcile before any re-request."""

    def __init__(self, signature: str, note: str):
        super().__init__(note)
        self.signature = signature


# ---------------------------------------------------------------------------
# base58 (self-contained, Bitcoin alphabet — Solana addresses, blockhashes)
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def b58encode(b: bytes) -> str:
    """base58-encode bytes (Bitcoin alphabet)."""
    if not isinstance(b, (bytes, bytearray)):
        raise SolanaError("b58encode needs bytes")
    n = int.from_bytes(bytes(b), "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    # Leading zero bytes become leading '1's.
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out if out else "1" * pad


def b58decode(s: str) -> bytes:
    """base58-decode to bytes. Fail-closed on any out-of-alphabet char."""
    if not isinstance(s, str) or not s:
        raise SolanaError("b58decode needs a non-empty string")
    n = 0
    for c in s:
        if c not in _B58_INDEX:
            raise SolanaError("b58decode: character outside base58 alphabet")
        n = n * 58 + _B58_INDEX[c]
    raw = b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


# ---------------------------------------------------------------------------
# SLIP-0010 ed25519 (manual — no wallet-library derivation)
# ---------------------------------------------------------------------------

def slip10_master(seed: bytes) -> tuple:
    """SLIP-0010 master key: HMAC-SHA512(key="ed25519 seed", data=seed).

    Returns (private_key_32, chain_code_32). SLIP-0010 allows seeds of
    128-512 bits (16-64 bytes); standard mode uses the 64-byte BIP-39 seed.
    """
    if not 16 <= len(seed) <= 64:
        raise SolanaError("SLIP-0010 seed must be 16-64 bytes")
    i = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return i[:32], i[32:]


def slip10_derive_child(priv: bytes, chain: bytes, index: int) -> tuple:
    """One SLIP-0010 hardened child. ed25519 allows hardened only.

    Returns (child_private_32, child_chain_32).
    """
    if len(priv) != 32 or len(chain) != 32:
        raise SolanaError("SLIP-0010 child needs 32-byte key + chain code")
    if not 0x80000000 <= index < 2**32:
        raise SolanaError("SLIP-0010 ed25519 requires a hardened index")
    data = b"\x00" + priv + index.to_bytes(4, "big")
    i = hmac.new(chain, data, hashlib.sha512).digest()
    return i[:32], i[32:]


def slip10_derive_path(seed: bytes, path: tuple = SOLANA_PATH) -> tuple:
    """Walk a hardened path from the 64-byte seed. Default: m/44'/501'/0'/0'.

    Returns (private_key_32, chain_code_32) at the path.
    """
    priv, chain = slip10_master(seed)
    for index in path:
        priv, chain = slip10_derive_child(priv, chain, index)
    return priv, chain


def standard_ed25519_seed(seed64: bytes) -> bytes:
    """32-byte ed25519 seed at m/44'/501'/0'/0' from a 64-byte BIP-39 seed.

    The Phantom/Solflare-compatible standard-mode key.
    """
    priv, _chain = slip10_derive_path(seed64, SOLANA_PATH)
    return priv


# ---------------------------------------------------------------------------
# Custom-KDF mode: same labeled family as EVM/Chia
# ---------------------------------------------------------------------------

def custom_seed(seed32: bytes, network: str, label: str) -> bytes:
    """32-byte ed25519 seed from the daemon's 32-byte seed.

    HKDF-SHA256 with kdf's SALT and info-string shape
    ("muse-wallet/v1/<network>/sign/<label>"), network in
    {"solana-devnet", "solana-mainnet"}. The 32-byte output is used
    directly as the ed25519 seed — no modular reduction (see module
    docstring for why derive_labeled's scalar step does not apply).
    """
    if len(seed32) != 32:
        raise SolanaError("reject: seed must be exactly 32 bytes")
    if network not in NETWORKS:
        raise SolanaError(f"unknown Solana network {network!r}")
    if not label or "/" in label:
        raise SolanaError(f"bad label {label!r}")
    info = f"{_kdf.INFO_PREFIX}{network}/sign/{label}".encode()
    prk = hmac.new(_kdf.SALT, seed32, hashlib.sha256).digest()
    # 32 bytes needs exactly one HKDF-Expand block.
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Keypairs / addresses
# ---------------------------------------------------------------------------

def keypair_from_seed(seed32: bytes) -> Keypair:
    """solders Keypair from a 32-byte ed25519 seed."""
    if len(seed32) != 32:
        raise SolanaError("ed25519 seed must be 32 bytes")
    return Keypair.from_seed(bytes(seed32))


def custom_keypair(seed32: bytes, network: str, label: str) -> Keypair:
    """KDF-mode keypair: custom_seed(seed, network, label) -> Keypair."""
    return keypair_from_seed(custom_seed(seed32, network, label))


def standard_keypair(seed64: bytes) -> Keypair:
    """Standard-mode keypair: 64-byte BIP-39 seed -> m/44'/501'/0'/0'."""
    return keypair_from_seed(standard_ed25519_seed(seed64))


def pubkey_bytes(keypair: Keypair) -> bytes:
    """Raw 32-byte ed25519 public key."""
    return bytes(keypair.pubkey())


def address_from_pubkey(pubkey32: bytes) -> str:
    """Solana address = base58(32-byte pubkey)."""
    if len(pubkey32) != 32:
        raise SolanaError("pubkey must be 32 bytes")
    return b58encode(pubkey32)


def address_of_keypair(keypair: Keypair) -> str:
    """base58 address for a keypair."""
    return address_from_pubkey(pubkey_bytes(keypair))


def phantom_backup_secret(keypair: Keypair) -> str:
    """Phantom import format: base58 of the 64-byte secret (seed || pubkey).

    This is the raw backup secret — handle like a private key: never
    log it, never put it in an API response.
    """
    raw = keypair.to_bytes()
    if len(raw) != 64:
        raise SolanaError("keypair secret must be 64 bytes")
    return b58encode(raw)


def signature_valid(pubkey32: bytes, message: bytes, signature64: bytes) -> bool:
    """Verify an ed25519 signature with solders. Pure check, no secrets."""
    if len(pubkey32) != 32 or len(signature64) != 64:
        raise SolanaError("signature_valid needs 32-byte pubkey + 64-byte sig")
    return Signature.from_bytes(bytes(signature64)).verify(
        Pubkey.from_bytes(bytes(pubkey32)), bytes(message))


# ---------------------------------------------------------------------------
# JSON-RPC (stdlib urllib; respects proxy env vars; Chrome UA for egress)
# ---------------------------------------------------------------------------

class SolanaRpc:
    """HTTPS JSON-RPC client for the Solana endpoints."""

    def __init__(self, network: str, url: str | None = None, timeout: int = 20):
        if network not in NETWORKS:
            raise SolanaError(f"unknown Solana network {network!r}")
        self.network = network
        self.url = url or NETWORKS[network]["url"]
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params=None):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id,
                           "method": method, "params": params or []}).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": CHROME_UA})
        try:
            # urllib honors HTTP_PROXY/HTTPS_PROXY env vars via the
            # default opener — no custom proxy code needed.
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.load(r)
        except Exception as e:
            raise SolanaError(f"RPC unreachable ({method}): {e}")
        if "error" in resp:
            raise SolanaError(f"RPC error ({method}): {resp['error']}")
        return resp.get("result")

    # -- network guard (mirrors evm.py's chain_id check) -------------------

    def get_genesis_hash(self) -> str:
        return self.call("getGenesisHash")

    def check_network(self) -> None:
        """Fail closed if the RPC is not the network we think it is.

        Call before any signing — a mispointed RPC cannot redirect funds.
        """
        expected = NETWORKS[self.network]["genesis_hash"]
        got = self.get_genesis_hash()
        if got != expected:
            raise SolanaError(
                f"RPC genesis hash {got!r} != expected {expected!r} for "
                f"{self.network} — refusing to sign")

    # -- reads -------------------------------------------------------------

    def get_latest_blockhash(self, commitment: str = "finalized") -> str:
        res = self.call("getLatestBlockhash", [{"commitment": commitment}])
        try:
            return res["value"]["blockhash"]
        except (TypeError, KeyError):
            raise SolanaError(f"getLatestBlockhash bad shape: {res!r}")

    def get_balance_lamports(self, address: str) -> int:
        res = self.call("getBalance", [address])
        try:
            return int(res["value"])
        except (TypeError, KeyError, ValueError):
            raise SolanaError(f"getBalance bad shape: {res!r}")

    def request_airdrop(self, address: str, lamports: int) -> str:
        """Devnet/testnet faucet. Returns the airdrop transaction signature."""
        if lamports <= 0:
            raise SolanaError("airdrop lamports must be positive")
        return self.call("requestAirdrop", [address, lamports])

    # -- submit + confirm --------------------------------------------------

    def send_transaction(self, raw_b64: str) -> str:
        """Broadcast a base64-encoded signed transaction. Returns signature."""
        if not raw_b64:
            raise SolanaError("send_transaction needs a non-empty payload")
        return self.call("sendTransaction",
                         [raw_b64, {"encoding": "base64",
                                    "preflightCommitment": "confirmed"}])

    def get_signature_statuses(self, signatures: list) -> list:
        res = self.call("getSignatureStatuses",
                        [signatures, {"searchTransactionHistory": False}])
        try:
            return res["value"]
        except (TypeError, KeyError):
            raise SolanaError(f"getSignatureStatuses bad shape: {res!r}")

    def get_transaction(self, signature: str):
        res = self.call("getTransaction",
                        [signature, {"encoding": "json",
                                    "maxSupportedTransactionVersion": 0}])
        return res  # None when the node does not know the signature yet

    def wait_signature(self, signature: str, timeout: int = 90,
                       poll: float = 2.0) -> dict:
        """Poll getSignatureStatuses until confirmed/finalized or timeout.

        Returns the status dict. A status with err set raises SolanaError
        (the tx definitively FAILED — not unknown). On timeout raises
        BroadcastUnknown: the tx left the machine, its fate is unknown —
        do not retry blindly.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            statuses = self.get_signature_statuses([signature])
            st = statuses[0] if statuses else None
            if st is not None:
                if st.get("err") is not None:
                    raise SolanaError(
                        f"tx {signature} failed on-chain: {st['err']!r}")
                if st.get("confirmationStatus") in ("confirmed", "finalized"):
                    return st
            time.sleep(poll)
        raise BroadcastUnknown(
            signature,
            f"tx {signature} submitted but not confirmed within {timeout}s "
            "— confirmation UNKNOWN. Do not re-request blindly; reconcile "
            "the signature on-chain first.")


# ---------------------------------------------------------------------------
# Transfer build + sign (offline; self-verified before broadcast)
# ---------------------------------------------------------------------------

def _check_blockhash(b58: str) -> bytes:
    try:
        raw = b58decode(b58)
    except SolanaError:
        raise SolanaError("recent blockhash is not valid base58")
    if len(raw) != 32:
        raise SolanaError("recent blockhash must decode to 32 bytes")
    return raw


def _check_address(addr: str) -> Pubkey:
    """Validate a base58 Solana address -> solders Pubkey (fail-closed)."""
    try:
        raw = b58decode(addr)
    except SolanaError:
        raise SolanaError(f"bad destination address: {addr!r}")
    if len(raw) != 32:
        raise SolanaError(f"bad destination address: {addr!r}")
    return Pubkey.from_bytes(raw)


def build_transfer(keypair: Keypair, to_address: str, lamports: int,
                   recent_blockhash: str) -> dict:
    """Build + sign a native SOL transfer, self-verified before return.

    The tx carries exactly one instruction: SystemProgram transfer from
    the keypair's address to to_address for lamports. Returns a dict with
    the wire payload and the decoded intent:

      {"raw_b64", "signature", "from", "to", "lamports",
       "recent_blockhash"}

    Pre-broadcast verification (mirrors evm.py): the signature must
    verify against the serialized message; the fee payer must be the
    keypair's address; the single instruction must decode to
    transfer(from=key, to=to_address, lamports=lamports). Anything else
    raises and nothing is broadcast.
    """
    if not isinstance(lamports, int) or lamports <= 0:
        raise SolanaError("lamports must be a positive int")
    to_pubkey = _check_address(to_address)
    from_pubkey = keypair.pubkey()
    _check_blockhash(recent_blockhash)  # validates shape; solders parses it
    blockhash = Hash.from_string(recent_blockhash)

    ix = transfer(TransferParams(from_pubkey=from_pubkey,
                                 to_pubkey=to_pubkey,
                                 lamports=lamports))
    tx = Transaction.new_signed_with_payer([ix], from_pubkey,
                                           [keypair], blockhash)

    # --- pre-broadcast self-verification ---
    try:
        tx.verify()
    except Exception as e:
        raise SolanaError(f"signed tx failed verification: {e}")
    msg: Message = tx.message
    # Fee payer is account 0 of a legacy message.
    if not msg.account_keys or msg.account_keys[0] != from_pubkey:
        raise SolanaError("fee payer mismatch — refusing to broadcast")
    if len(msg.instructions) != 1:
        raise SolanaError("expected exactly one instruction")
    ins = msg.instructions[0]
    prog = msg.account_keys[ins.program_id_index]
    if prog != SYSTEM_PROGRAM:
        raise SolanaError("instruction is not a SystemProgram transfer")
    acct_idx = bytes(ins.accounts)
    if len(acct_idx) != 2:
        raise SolanaError("transfer instruction must reference 2 accounts")
    if msg.account_keys[acct_idx[0]] != from_pubkey:
        raise SolanaError("transfer source mismatch — refusing to broadcast")
    if msg.account_keys[acct_idx[1]] != to_pubkey:
        raise SolanaError("transfer destination mismatch — refusing")
    # SystemProgram transfer layout: u32LE discriminator 2 || u64LE lamports.
    if bytes(ins.data) != b"\x02\x00\x00\x00" + lamports.to_bytes(8, "little"):
        raise SolanaError("transfer data mismatch — refusing to broadcast")

    wire = bytes(tx)
    sig = tx.signatures[0]
    return {
        "raw_b64": base64.b64encode(wire).decode(),
        "signature": str(sig),
        "from": str(from_pubkey),
        "to": to_address,
        "lamports": lamports,
        "recent_blockhash": recent_blockhash,
    }


def sign_transfer(keypair: Keypair, to_address: str, lamports: int,
                  rpc: SolanaRpc) -> dict:
    """Network-aware transfer: check_network + fresh blockhash + build.

    The RPC's genesis hash is verified before any signing happens.
    """
    rpc.check_network()
    blockhash = rpc.get_latest_blockhash()
    return build_transfer(keypair, to_address, lamports, blockhash)

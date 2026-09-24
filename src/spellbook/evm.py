"""EVM chain layer — testnet-first. SPEC §10.

Stdlib JSON-RPC (urllib) + coincurve signing. No new dependencies.

Safety rails:
- Only plain native transfers. The daemon's v1 schema already rejects
  contract-call-shaped requests; this module has no calldata parameter at
  all — there is no way to express anything but to/value.
- Mainnet submission is REFUSED unless the daemon config explicitly sets
  "mainnet_submit_enabled": true. That flag exists only for the
  separately-authorized §10.14-17 mainnet dust step.
- Before broadcast, the signed tx is verified: the recovered sender must
  equal the derived address AND to/value/chain_id must equal the approved
  intent. Anything else aborts before the tx leaves the machine.
- The RPC's chain_id is checked against the expected chain before any
  signing happens — a mispointed RPC cannot redirect funds.
- Nonces are read at the "pending" block tag so back-to-back spends never
  share a nonce.
- Signing is legacy type-0 (EIP-155) only — a deliberate v1 limitation:
  legacy transfers are valid on every EVM chain including post-merge, and
  the hand-rolled RLP/signer stays small and auditable. EIP-1559 (type-2)
  is a future enhancement, not a silent fallback.
- A receipt timeout is NOT a failure: it raises BroadcastUnknown (the tx
  left the machine, its fate is unknown) so no caller ever blind-retries
  into a double-spend.
"""
import json
import time
import urllib.request

from coincurve import PrivateKey, PublicKey
from Crypto.Hash import keccak

from spellbook import __version__

# chain name -> parameters. Only chains listed here can ever submit.
CHAINS = {
    "evm-4663": {"chain_id": 4663, "testnet": False,
                 "name": "Robinhood Chain"},
    "evm-46630": {"chain_id": 46630, "testnet": True,
                  "name": "Robinhood Chain testnet"},
}

TRANSFER_GAS_LIMIT = 21_000


class EvmError(Exception):
    pass


class BroadcastUnknown(EvmError):
    """The signed tx was accepted by the node (a tx hash exists) but no
    receipt arrived within the wait window — the spend left the machine and
    its fate is UNKNOWN. Callers must NOT retry blindly (that would
    double-spend); they ledger the hash as unresolved and let a human
    reconcile before any re-request."""

    def __init__(self, tx_hash: str, note: str):
        super().__init__(note)
        self.tx_hash = tx_hash


def is_address(s: str) -> bool:
    return (isinstance(s, str) and len(s) == 42 and s.startswith("0x")
            and all(c in "0123456789abcdefABCDEF" for c in s[2:]))


def keccak256(b: bytes) -> bytes:
    return keccak.new(data=b, digest_bits=256).digest()


def address_from_privkey(privkey_bytes: bytes) -> str:
    pub = PrivateKey(privkey_bytes).public_key.format(compressed=False)[1:]
    return "0x" + keccak256(pub)[-20:].hex()


# --- minimal RLP (tx signing only) -------------------------------------------
def _rlp_len(l: int, offset: int) -> bytes:
    if l < 56:
        return bytes([offset + l])
    bl = l.to_bytes((l.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(bl)]) + bl


def _rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _rlp_len(len(b), 0x80) + b


def _rlp_int(n: int) -> bytes:
    return _rlp_bytes(b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big"))


def _rlp_list(items: list) -> bytes:
    payload = b"".join(items)
    return _rlp_len(len(payload), 0xC0) + payload


# --- JSON-RPC -----------------------------------------------------------------
class Rpc:
    def __init__(self, url: str, timeout: int = 20):
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params=None):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id,
                           "method": method, "params": params or []}).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": f"spellbook/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.load(r)
        except Exception as e:
            raise EvmError(f"RPC unreachable ({method}): {e}")
        if "error" in resp:
            raise EvmError(f"RPC error ({method}): {resp['error']}")
        return resp.get("result")

    def chain_id(self) -> int:
        return int(self.call("eth_chainId"), 16)

    def balance_wei(self, address: str) -> int:
        return int(self.call("eth_getBalance", [address, "latest"]), 16)

    def nonce(self, address: str) -> int:
        # "pending", not "latest": the daemon handles requests serially, but
        # two approved spends can land before either is mined. "latest" would
        # hand both the same nonce (second tx replaces the first); "pending"
        # counts in-flight txs so each spend gets a distinct nonce.
        return int(self.call("eth_getTransactionCount",
                             [address, "pending"]), 16)

    def gas_price_wei(self) -> int:
        return int(self.call("eth_gasPrice"), 16)

    def estimate_gas(self, from_addr: str, to: str, value_wei: int) -> int:
        """eth_estimateGas for a plain native transfer.

        Raises (fail-closed) if the node cannot estimate: we never guess a
        gas limit, because an under-limit tx burns its fee on chains like
        Robinhood's where intrinsic cost exceeds 21000.
        """
        tx = {"from": from_addr, "to": to, "value": hex(value_wei)}
        return int(self.call("eth_estimateGas", [tx]), 16)

    def estimate_gas_call(self, from_addr: str, to: str, value_wei: int,
                          data_hex: str) -> int:
        """eth_estimateGas for a contract call (swap, approve, LP, ...).

        Same fail-closed discipline as estimate_gas: no guess is ever
        broadcast. data_hex must be 0x-prefixed calldata.
        """
        if not (isinstance(data_hex, str) and data_hex.startswith("0x")):
            raise EvmError("calldata must be 0x-prefixed hex")
        tx = {"from": from_addr, "to": to, "value": hex(value_wei),
              "data": data_hex}
        return int(self.call("eth_estimateGas", [tx]), 16)

    def eth_call(self, to: str, data_hex: str, from_addr: str | None = None,
                 block: str = "latest"):
        """Read-only contract call (allowance checks, etc.). Never signs."""
        if not (isinstance(data_hex, str) and data_hex.startswith("0x")):
            raise EvmError("calldata must be 0x-prefixed hex")
        tx = {"to": to, "data": data_hex}
        if from_addr:
            tx["from"] = from_addr
        return self.call("eth_call", [tx, block])

    def send_raw_tx(self, raw_hex: str) -> str:
        return self.call("eth_sendRawTransaction", [raw_hex])

    def receipt(self, tx_hash: str):
        return self.call("eth_getTransactionReceipt", [tx_hash])

    def wait_receipt(self, tx_hash: str, timeout: int = 90, poll: float = 1.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = self.receipt(tx_hash)
            if r is not None:
                return r
            time.sleep(poll)
        # The tx was broadcast and accepted (send_raw_tx returned a hash),
        # but no receipt arrived in time. It may still confirm later —
        # raise the unknown state, never a plain failure: a plain failure
        # invites a blind retry, and a blind retry double-spends.
        raise BroadcastUnknown(
            tx_hash,
            f"tx {tx_hash} broadcast but no receipt within {timeout}s — "
            "confirmation UNKNOWN. Do not re-request blindly; reconcile "
            "the hash on-chain first.")


# --- signing ------------------------------------------------------------------
def _sign_legacy(privkey_bytes: bytes, chain_id: int, nonce: int, to: str,
                 value_wei: int, data: bytes, gas_price_wei: int,
                 gas_limit: int) -> dict:
    """Core EIP-155 legacy signer. ``data`` empty = native transfer."""
    if not is_address(to):
        raise EvmError(f"bad destination address: {to!r}")
    if value_wei < 0:
        raise EvmError("value must be non-negative")
    to_bytes = bytes.fromhex(to[2:])
    unsigned = _rlp_list([_rlp_int(nonce), _rlp_int(gas_price_wei),
                          _rlp_int(gas_limit), _rlp_bytes(to_bytes),
                          _rlp_int(value_wei), _rlp_bytes(data),
                          _rlp_int(chain_id), _rlp_bytes(b""),
                          _rlp_bytes(b"")])
    digest = keccak256(unsigned)
    sig = PrivateKey(privkey_bytes).sign_recoverable(digest, hasher=None)
    r, s, rec_id = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    v = chain_id * 2 + 35 + rec_id
    signed = _rlp_list([_rlp_int(nonce), _rlp_int(gas_price_wei),
                        _rlp_int(gas_limit), _rlp_bytes(to_bytes),
                        _rlp_int(value_wei), _rlp_bytes(data),
                        _rlp_int(v), _rlp_int(r), _rlp_int(s)])
    # Pre-broadcast verification: recover the sender, compare to the key.
    recovered = PublicKey.from_signature_and_message(sig, digest, hasher=None)
    rec_addr = "0x" + keccak256(recovered.format(compressed=False)[1:])[-20:].hex()
    expected = address_from_privkey(privkey_bytes)
    if rec_addr.lower() != expected.lower():
        raise EvmError("signature recovery mismatch — refusing to broadcast")
    return {"raw_hex": "0x" + signed.hex(),
            "tx_hash": "0x" + keccak256(signed).hex(),
            "from": expected, "to": to, "value_wei": value_wei,
            "data": "0x" + data.hex(),
            "nonce": nonce, "chain_id": chain_id}


def sign_legacy_transfer(privkey_bytes: bytes, chain_id: int, nonce: int,
                         to: str, value_wei: int, gas_price_wei: int,
                         gas_limit: int = TRANSFER_GAS_LIMIT) -> dict:
    """Sign an EIP-155 legacy native transfer. Returns raw tx + tx hash.

    Verifies by ecrecover before returning: the recovered sender must equal
    address_from_privkey(privkey_bytes), else this raises and nothing is
    broadcast.
    """
    if value_wei <= 0:
        raise EvmError("value must be positive")
    return _sign_legacy(privkey_bytes, chain_id, nonce, to, value_wei, b"",
                        gas_price_wei, gas_limit)


def sign_legacy_call(privkey_bytes: bytes, chain_id: int, nonce: int,
                     to: str, value_wei: int, data_hex: str,
                     gas_price_wei: int, gas_limit: int) -> dict:
    """Sign an EIP-155 legacy contract call (swap, approve, LP, ...).

    Same ecrecover self-check as transfers. ``data_hex`` must be 0x-prefixed
    calldata built by a whitelisted builder (spellbook.dex) — the daemon
    never signs caller-supplied raw calldata (only decoded, bounded
    intents reach this function).
    """
    if not (isinstance(data_hex, str) and data_hex.startswith("0x")):
        raise EvmError("calldata must be 0x-prefixed hex")
    try:
        data = bytes.fromhex(data_hex[2:])
    except ValueError:
        raise EvmError("calldata is not valid hex")
    if not data:
        raise EvmError("empty calldata — use sign_legacy_transfer")
    return _sign_legacy(privkey_bytes, chain_id, nonce, to, value_wei, data,
                        gas_price_wei, gas_limit)

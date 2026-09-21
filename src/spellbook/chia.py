"""Chia/Sage path for the Spellbook daemon (SPEC §10 phase 1, O10).

The daemon is the sole talker to Sage RPC. This module is a small,
stdlib-only mTLS client for the Sage RPC server (`sage rpc start`):

  - mTLS with the Sage data dir's own ssl/wallet.crt + ssl/wallet.key.
    Sage requires the client to present exactly the wallet cert; the
    server cert is the same self-signed cert. Trust here comes from file
    ownership (the data dir is daemon-owned, mode 700), not from a CA —
    hostname checking and CA verification are off because there is no CA.
  - Fail-closed: any transport error, non-2xx status, or RPC-side error
    raises SageError. Sage returns errors as plain text on non-2xx, so
    we surface that text instead of trying to parse JSON.

Verified against the pinned sage source (v0.13.1, f2ec89d...): routes are
POST /{endpoint} with a JSON body. The endpoints used here:

  POST /set_network        {"name": "testnet11"}
  POST /get_keys           {}                      -> {"keys": [{"fingerprint": ...}]}
  POST /import_key         {"name","key","derivation_index"} -> {"fingerprint": n}
  POST /login              {"fingerprint": n}
  POST /get_sync_status    {} -> {"selectable_balance","receive_address",...}
  POST /get_wallet_address {"fingerprint": n, "network_id": "testnet11"}
  POST /send_xch           {"address","amount","fee","memos","auto_submit": true}
  POST /get_transactions   {"offset":0,"limit":5,"ascending":false}

Amounts in Sage's API are untagged string-or-number ("Amount"); we send
plain JSON integers for mojos and accept either form back.

Nothing in this module ever logs key material. The private key is passed
to Sage's /import_key once per (chain, label) — Sage needs the secret to
sign — over the local mTLS channel only.
"""

import http.client
import json
import os
import ssl
import time

# Spellbook chain id -> Sage network name (from sage-config/src/network.rs).
NETWORKS = {
    "chia-testnet": "testnet11",
    "chia-mainnet": "mainnet",
}

# Address prefix per Sage network (bech32m). Used only as a fail-fast
# sanity check before asking Sage to build the spend.
PREFIXES = {
    "testnet11": "txch1",
    "mainnet": "xch1",
}


class SageError(Exception):
    """Any Sage RPC failure — transport, protocol, or RPC-side."""


class BroadcastUnknown(SageError):
    """The spend was submitted (send_xch accepted it) but no matching
    on-chain record appeared within the wait window — it left the machine
    and its fate is UNKNOWN. Callers must NOT retry blindly (that would
    double-spend); they ledger the reference as unresolved and let a human
    reconcile before any re-request."""

    def __init__(self, reference: str, note: str):
        super().__init__(note)
        self.reference = reference


def amount_to_int(v) -> int:
    """Parse Sage's untagged Amount (string or number) into mojos."""
    if isinstance(v, bool):
        raise SageError(f"bad amount from Sage: {v!r}")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s, 10)
    raise SageError(f"bad amount from Sage: {v!r}")


def chia_fingerprint(master_pubkey_hex: str) -> int:
    """Chia key fingerprint: first 4 bytes of sha256(master pubkey), big-endian."""
    import hashlib
    digest = hashlib.sha256(bytes.fromhex(master_pubkey_hex)).digest()
    return int.from_bytes(digest[:4], "big")


class SageRpc:
    """Minimal mTLS client for the Sage RPC server on localhost."""

    def __init__(self, data_dir: str, host: str = "127.0.0.1",
                 port: int = 9257, timeout: int = 60):
        ssl_dir = os.path.join(data_dir, "ssl")
        crt = os.path.join(ssl_dir, "wallet.crt")
        key = os.path.join(ssl_dir, "wallet.key")
        for p in (crt, key):
            if not os.path.isfile(p):
                raise SageError(
                    f"Sage ssl material not found at {p} — is `sage rpc start` "
                    f"running with this data dir?")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        # Self-signed cert shared between client and server; trust is the
        # daemon-owned data dir, not a CA. No hostname to check on loopback.
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.load_cert_chain(certfile=crt, keyfile=key)
        except Exception as e:
            raise SageError(f"could not load Sage client cert: {e}") from e
        self._host = host
        self._port = port
        self._timeout = timeout
        self._ctx = ctx

    def call(self, endpoint: str, body: dict | None = None) -> dict:
        """POST /{endpoint} with a JSON body; returns the parsed JSON response."""
        payload = json.dumps(body or {}).encode()
        conn = http.client.HTTPSConnection(
            self._host, self._port, timeout=self._timeout, context=self._ctx)
        try:
            conn.request("POST", "/" + endpoint.lstrip("/"), body=payload,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read()
        except Exception as e:
            raise SageError(f"Sage RPC transport failure on /{endpoint}: {e}") from e
        finally:
            conn.close()
        if resp.status < 200 or resp.status >= 300:
            # Sage returns errors as plain text, not JSON.
            raise SageError(f"Sage /{endpoint} -> HTTP {resp.status}: "
                            f"{raw.decode(errors='replace')[:500]}")
        try:
            return json.loads(raw.decode())
        except Exception as e:
            raise SageError(f"Sage /{endpoint} returned non-JSON: {e}") from e

    # ---- convenience wrappers ----

    def set_network(self, name: str) -> None:
        self.call("set_network", {"name": name})

    def get_keys(self) -> list:
        return self.call("get_keys").get("keys", [])

    def import_key(self, name: str, key_hex: str) -> int:
        """Import a raw 32-byte hex private key; returns its fingerprint."""
        out = self.call("import_key", {"name": name, "key": key_hex,
                                      "derivation_index": 0})
        try:
            return int(out["fingerprint"])
        except (KeyError, TypeError, ValueError) as e:
            raise SageError(f"/import_key gave no fingerprint: {out!r}") from e

    def login(self, fingerprint: int) -> None:
        self.call("login", {"fingerprint": fingerprint})

    def sync_status(self) -> dict:
        return self.call("get_sync_status", {})

    def wallet_address(self, fingerprint: int, network_id: str) -> str:
        out = self.call("get_wallet_address",
                        {"fingerprint": fingerprint, "network_id": network_id})
        addr = out.get("address")
        if not addr:
            raise SageError(f"/get_wallet_address gave no address: {out!r}")
        return addr

    def send_xch(self, address: str, amount_mojos: int, fee_mojos: int = 0,
                 memos: list | None = None) -> dict:
        return self.call("send_xch", {
            "address": address,
            "amount": amount_mojos,
            "fee": fee_mojos,
            "memos": memos or [],
            "auto_submit": True,
        })

    def recent_transactions(self, limit: int = 5) -> list:
        return self.call("get_transactions",
                         {"offset": 0, "limit": limit,
                          "ascending": False}).get("transactions", [])


def wait_for_outgoing(rpc: SageRpc, destination: str, amount_mojos: int,
                      since_ts: float, timeout_s: int = 180,
                      poll_s: int = 5) -> dict:
    """Poll /get_transactions until our outgoing spend shows up.

    Matches the first transaction created after `since_ts` whose created
    coins include `destination` (case-insensitive). Fail-closed on timeout:
    the spend may still confirm later, so the caller must treat this as
    "broadcast, confirmation unknown" rather than as a failure.
    """
    dest = destination.lower()
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for tx in rpc.recent_transactions(limit=10):
            ts = tx.get("timestamp") or 0
            if ts < since_ts - 60:
                continue
            for coin in tx.get("created", []):
                addr = (coin.get("address") or "").lower()
                try:
                    amt = amount_to_int(coin.get("amount"))
                except SageError:
                    continue
                if addr == dest and amt == amount_mojos:
                    return tx
        time.sleep(poll_s)
    raise BroadcastUnknown(
        "",
        "spend was submitted but no matching transaction appeared in "
        f"/get_transactions within {timeout_s}s — broadcast, confirmation "
        "unknown; do not retry blindly")

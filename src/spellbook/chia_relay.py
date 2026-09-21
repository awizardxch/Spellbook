"""Chia relay transport for the Spellbook daemon (SPEC §10, O10).

`RelayRpc` is the HTTPS client for the `spellbook-chia-relay` service
(Railway). It mirrors the fail-closed posture of `SageRpc` in chia.py
but talks to the relay's v1 API instead of Sage's local mTLS RPC.

The daemon keeps keys and BLS signing local (see chia_sign.py). The
relay only ever sees:
  - puzzle hashes (public)
  - signed spend bundles (public once broadcast)
  - the bearer token

It NEVER receives seeds, private keys, or mnemonics.

API (from docs/chia-relay.md):
  GET  /v1/status              -> {ok, network, peak_height, peers, ...}
  POST /v1/coins               {puzzle_hashes: [hex...]} -> {coins: [...]}
  POST /v1/broadcast           {spend_bundle_hex} -> {ok, txid, status}
  GET  /v1/coin/{coin_id}      -> {coin_id, spent_height, created_height}

Fail-closed: any transport error, non-2xx status, or schema mismatch
raises RelayError. Nothing is retried blindly.
"""

import http.client
import json
import ssl
import time
import urllib.parse


class RelayError(Exception):
    """Any relay API failure — transport, auth, protocol, or relay-side."""


class BroadcastUnknown(RelayError):
    """The bundle was submitted but confirmation is unknown.

    Same semantics as chia.BroadcastUnknown: it left the machine and its
    fate is UNKNOWN. Callers must NOT retry blindly (double-spend risk);
    ledger as unresolved and let a human reconcile.
    """

    def __init__(self, reference: str, note: str):
        super().__init__(note)
        self.reference = reference


# MempoolInclusionStatus from Chia (mempool_inclusion_status.py)
MEMPOOL_STATUS = {
    1: "SUCCESS",
    2: "PENDING",
    3: "FAILED",
}


class RelayRpc:
    """HTTPS client for the spellbook-chia-relay v1 API."""

    def __init__(self, relay_url: str, token: str, timeout: int = 60):
        if not relay_url or not relay_url.startswith(("https://", "http://")):
            raise RelayError(f"bad relay_url: {relay_url!r}")
        if not token or len(token) < 16:
            raise RelayError("relay token missing or too short")
        # Never log the token; store it for the Authorization header only.
        self._url = relay_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        parsed = urllib.parse.urlparse(self._url)
        self._host = parsed.hostname
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._secure = parsed.scheme == "https"
        self._ctx = None
        if self._secure:
            self._ctx = ssl.create_default_context()

    def _request(self, method: str, path: str,
                 body: dict | None = None) -> dict:
        payload = json.dumps(body or {}).encode() if body is not None else None
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        if self._secure:
            conn = http.client.HTTPSConnection(
                self._host, self._port, timeout=self._timeout,
                context=self._ctx)
        else:
            conn = http.client.HTTPConnection(
                self._host, self._port, timeout=self._timeout)
        try:
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except Exception as e:
            raise RelayError(
                f"relay transport failure on {method} {path}: {e}") from e
        finally:
            conn.close()
        if resp.status < 200 or resp.status >= 300:
            # Don't leak the token in error messages; raw may contain
            # relay-side error text which is safe to surface.
            raise RelayError(
                f"relay {method} {path} -> HTTP {resp.status}: "
                f"{raw.decode(errors='replace')[:500]}")
        try:
            return json.loads(raw.decode())
        except Exception as e:
            raise RelayError(
                f"relay {method} {path} returned non-JSON: {e}") from e

    # ---- API methods ----

    def status(self) -> dict:
        """GET /v1/status — relay health, network, peer count, height."""
        out = self._request("GET", "/v1/status")
        for field in ("ok", "network", "peak_height", "peers"):
            if field not in out:
                raise RelayError(
                    f"/v1/status missing field {field!r}: {out!r}")
        return out

    def coins(self, puzzle_hashes: list) -> list:
        """POST /v1/coins — CoinStates for the given puzzle hashes.

        puzzle_hashes: list of 32-byte hex strings (≤ 50 per the relay).
        Returns the list of coin dicts; empty list means no coins (not an
        error).
        """
        if not isinstance(puzzle_hashes, list):
            raise RelayError("puzzle_hashes must be a list")
        if len(puzzle_hashes) > 50:
            raise RelayError(
                f"too many puzzle hashes ({len(puzzle_hashes)} > 50)")
        for ph in puzzle_hashes:
            if not isinstance(ph, str) or len(ph) != 64:
                raise RelayError(f"bad puzzle hash: {ph!r}")
            try:
                bytes.fromhex(ph)
            except ValueError:
                raise RelayError(f"bad puzzle hash hex: {ph!r}")
        out = self._request("POST", "/v1/coins",
                            {"puzzle_hashes": puzzle_hashes})
        coins = out.get("coins")
        if not isinstance(coins, list):
            raise RelayError(f"/v1/coins gave no coins list: {out!r}")
        return coins

    def broadcast(self, spend_bundle_hex: str) -> dict:
        """POST /v1/broadcast — submit a signed spend bundle.

        spend_bundle_hex: hex of the serialized SpendBundle (built and
        signed locally via chia_sign.py).
        Returns {ok, txid, status} where status is the mempool inclusion
        string (SUCCESS/PENDING/FAILED).
        """
        if not isinstance(spend_bundle_hex, str) or not spend_bundle_hex:
            raise RelayError("spend_bundle_hex must be a non-empty hex string")
        try:
            raw = bytes.fromhex(spend_bundle_hex)
        except ValueError:
            raise RelayError("spend_bundle_hex is not valid hex")
        if len(raw) > 5 * 1024 * 1024:
            raise RelayError(
                f"spend bundle too large ({len(raw)} > 5MB)")
        # Fail fast on obvious key-material smuggling: the relay also
        # rejects, but we never even send.
        out = self._request("POST", "/v1/broadcast",
                            {"spend_bundle_hex": spend_bundle_hex})
        if "txid" not in out:
            raise RelayError(f"/v1/broadcast gave no txid: {out!r}")
        return out

    def coin(self, coin_id_hex: str) -> dict:
        """GET /v1/coin/{coin_id} — poll a coin's spent/created heights."""
        if not isinstance(coin_id_hex, str) or len(coin_id_hex) != 64:
            raise RelayError(f"bad coin id: {coin_id_hex!r}")
        try:
            bytes.fromhex(coin_id_hex)
        except ValueError:
            raise RelayError(f"bad coin id hex: {coin_id_hex!r}")
        return self._request("GET", f"/v1/coin/{coin_id_hex}")


def wait_for_confirmation(rpc: RelayRpc, coin_id_hex: str,
                          timeout_s: int = 180,
                          poll_s: int = 5) -> dict:
    """Poll /v1/coin/{coin_id} until spent_height is set.

    Used to track change coins after a broadcast. Fail-closed on timeout:
    raises BroadcastUnknown (the spend left the machine; do not retry).
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        info = rpc.coin(coin_id_hex)
        if info.get("spent_height") is not None:
            return info
        time.sleep(poll_s)
    raise BroadcastUnknown(
        coin_id_hex,
        f"broadcast accepted but coin {coin_id_hex[:16]}… not spent within "
        f"{timeout_s}s — confirmation unknown; do not retry blindly")

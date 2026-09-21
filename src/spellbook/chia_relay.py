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
  POST /v1/coin_ids            {coin_ids: [hex...]}
                               -> {ok, coins: [...], not_found: [hex...]}
  POST /v1/broadcast           {spend_bundle: hex}
                               -> {ok, txid, expected_txid, status,
                                   status_name, error}
  GET  /v1/coin/{coin_id}      -> {ok, coin: {coin_id, spent_height,
                                             created_height, ...}}
                               (HTTP 404 {"ok": False, "error": ...} when the
                               coin is not known yet)
  GET  /v1/broadcasts          -> {ok, broadcasts: [...]}
  GET  /v1/broadcasts/{txid}   -> {ok, broadcast: {txid, status,
                                                   status_name, error, ...}}
                               (HTTP 404 when the relay never saw the txid)

Mempool status is the Chia mempool-inclusion int (1=SUCCESS, 2=PENDING,
3=FAILED); status_name is its string form. `expected_txid` is the
relay-computed sha256 of the bundle bytes it received — the daemon
compares it against its own locally computed bundle txid and fails
closed on any mismatch.

Fail-closed: any transport error, non-2xx status, or schema mismatch
raises RelayError. Nothing is retried blindly.
"""

import base64
import http.client
import json
import os
import ssl
import time
import urllib.parse
from typing import Callable


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

    def __init__(self, relay_url: str, token: str = "",
                 token_provider: Callable[[str], str] | None = None,
                 timeout: int = 60):
        if not relay_url or not relay_url.startswith(("https://", "http://")):
            raise RelayError(f"bad relay_url: {relay_url!r}")
        if token_provider is not None:
            # Connector-backed credential (e.g. Secure Vault): a fresh
            # surrogate is resolved per request; the raw token never lives
            # in this process. The provider receives the relay base URL so
            # it can enforce its own host allowlist.
            if not callable(token_provider):
                raise RelayError("token_provider must be callable")
            self._token = ""
            self._token_provider = token_provider
        else:
            if not token or len(token) < 16:
                raise RelayError("relay token missing or too short")
            # Never log the token; store it for the Authorization header only.
            self._token = token
            self._token_provider = None
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

    def _proxy_bypassed(self) -> bool:
        """True when no_proxy/NO_PROXY covers this relay host."""
        no_proxy = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
        host = (self._host or "").lower()
        for entry in no_proxy.split(","):
            entry = entry.strip().lower().strip("[]")
            if not entry:
                continue
            if entry == "*" or host == entry or host.endswith("." + entry.lstrip(".")):
                return True
        return False

    def _connection(self):
        """Build the HTTP(S) connection, tunneling through the egress
        proxy when one is configured (https_proxy/HTTPS_PROXY/all_proxy)
        and the relay host is not in no_proxy.

        Agents and daemons often run behind a mandatory egress proxy;
        without this, remote relay hosts are unreachable while the
        local relay (127.0.0.1, covered by no_proxy) keeps working.
        """
        if not self._proxy_bypassed():
            proxy = (os.environ.get("https_proxy")
                     or os.environ.get("HTTPS_PROXY")
                     or os.environ.get("all_proxy")
                     or os.environ.get("ALL_PROXY"))
        else:
            proxy = None
        if not proxy:
            if self._secure:
                return http.client.HTTPSConnection(
                    self._host, self._port, timeout=self._timeout,
                    context=self._ctx)
            return http.client.HTTPConnection(
                self._host, self._port, timeout=self._timeout)
        p = urllib.parse.urlparse(proxy)
        tunnel_headers = {}
        if p.username:
            creds = (urllib.parse.unquote(p.username) + ":"
                     + urllib.parse.unquote(p.password or ""))
            tunnel_headers["Proxy-Authorization"] = (
                "Basic " + base64.b64encode(creds.encode()).decode())
        if self._secure:
            conn = http.client.HTTPSConnection(
                p.hostname, p.port or 3128, timeout=self._timeout,
                context=self._ctx)
        else:
            conn = http.client.HTTPConnection(
                p.hostname, p.port or 3128, timeout=self._timeout)
        conn.set_tunnel(self._host, self._port,
                        tunnel_headers or None)
        return conn

    def _bearer(self) -> str:
        """Bearer value for the Authorization header (never logged)."""
        if self._token_provider is not None:
            try:
                return self._token_provider(self._url)
            except Exception as e:
                raise RelayError(
                    f"relay credential provider failed: {e}") from e
        return self._token

    def _request(self, method: str, path: str,
                 body: dict | None = None) -> dict:
        payload = json.dumps(body or {}).encode() if body is not None else None
        headers = {
            "Authorization": f"Bearer {self._bearer()}",
            "Content-Type": "application/json",
        }
        conn = self._connection()
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

    def broadcast(self, spend_bundle: str) -> dict:
        """POST /v1/broadcast — submit a signed spend bundle.

        spend_bundle: hex of the serialized SpendBundle (built and
        signed locally via chia_sign.py). Sent as {"spend_bundle": hex}
        per the documented contract.
        Returns {ok, txid, expected_txid, status, status_name, error}
        where status is the mempool inclusion int (1=SUCCESS, 2=PENDING,
        3=FAILED) and status_name is its string form. `expected_txid` is
        the relay's sha256 of the bundle bytes it received.
        """
        if not isinstance(spend_bundle, str) or not spend_bundle:
            raise RelayError("spend_bundle must be a non-empty hex string")
        try:
            raw = bytes.fromhex(spend_bundle)
        except ValueError:
            raise RelayError("spend_bundle is not valid hex")
        if len(raw) > 5 * 1024 * 1024:
            raise RelayError(
                f"spend bundle too large ({len(raw)} > 5MB)")
        # Fail fast on obvious key-material smuggling: the relay also
        # rejects, but we never even send.
        # Documented field name is `spend_bundle`; the relay tolerates the
        # legacy `spend_bundle_hex` alias but we send the documented shape.
        out = self._request("POST", "/v1/broadcast",
                            {"spend_bundle": spend_bundle})
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

    def coin_ids(self, coin_id_hexes: list) -> dict:
        """POST /v1/coin_ids — batch coin-state lookup (Sage get_coins_by_ids).

        Returns {"coins": [...], "not_found": [hex...]}. Coins come back
        in request order; unknown ids land in "not_found" (not an error).
        """
        if not isinstance(coin_id_hexes, list):
            raise RelayError("coin_ids must be a list")
        if not (1 <= len(coin_id_hexes) <= 50):
            raise RelayError(
                f"coin_ids must be a list of 1..50 items "
                f"(got {len(coin_id_hexes)})")
        for cid in coin_id_hexes:
            if not isinstance(cid, str) or len(cid) != 64:
                raise RelayError(f"bad coin id: {cid!r}")
            try:
                bytes.fromhex(cid)
            except ValueError:
                raise RelayError(f"bad coin id hex: {cid!r}")
        out = self._request("POST", "/v1/coin_ids",
                            {"coin_ids": coin_id_hexes})
        coins = out.get("coins")
        not_found = out.get("not_found")
        if not isinstance(coins, list) or not isinstance(not_found, list):
            raise RelayError(f"/v1/coin_ids gave bad shape: {out!r}")
        return {"coins": coins, "not_found": not_found}

    def broadcast_status(self, txid_hex: str) -> dict:
        """GET /v1/broadcasts/{txid} — what did the relay see for this txid?

        Returns the broadcast record {txid, status, status_name, error,
        coin_spends, time}. Raises RelayError (with HTTP 404) when the
        relay has never seen the txid — meaning it was NOT submitted
        through this relay instance.
        """
        if not isinstance(txid_hex, str) or len(txid_hex) != 64:
            raise RelayError(f"bad txid: {txid_hex!r}")
        try:
            txid_hex = txid_hex.strip().lower()
            bytes.fromhex(txid_hex)
        except ValueError:
            raise RelayError(f"bad txid hex: {txid_hex!r}")
        out = self._request("GET", f"/v1/broadcasts/{txid_hex}")
        record = out.get("broadcast")
        if not isinstance(record, dict):
            raise RelayError(
                f"/v1/broadcasts/{txid_hex[:16]}… gave bad shape: {out!r}")
        return record


def wait_for_confirmation(rpc: RelayRpc, coin_id_hex: str,
                          timeout_s: int = 180,
                          poll_s: int = 5,
                          created: bool = False) -> dict:
    """Poll /v1/coin/{coin_id} until the spend is confirmed on-chain.

    The relay returns {ok, coin: {...}} (HTTP 404 while the coin is not
    known yet — e.g. a change coin whose creating spend has not been
    included; tolerated during polling).

    Confirmation semantics:
      - created=False (default): the coin is one we SPENT; confirmed when
        spent_height becomes non-None.
      - created=True: the coin is one we CREATED (destination/change);
        confirmed when the relay knows it at all (created_height set).

    Returns the coin dict. Fail-closed on timeout: raises BroadcastUnknown
    (the spend left the machine; do not retry blindly). Non-404 relay
    errors raise immediately.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            info = rpc.coin(coin_id_hex)
        except RelayError as e:
            if "HTTP 404" not in str(e):
                raise
            # Coin not known yet — the spend may not be included. Keep
            # polling; the timeout stays the fail-closed backstop.
            time.sleep(poll_s)
            continue
        # Tolerate a legacy flat shape; the documented one nests under
        # "coin".
        coin = info.get("coin", info)
        if not isinstance(coin, dict):
            raise RelayError(
                f"/v1/coin/{coin_id_hex[:16]}… bad coin shape: {info!r}")
        if created:
            if coin.get("created_height") is not None:
                return coin
        elif coin.get("spent_height") is not None:
            return coin
        time.sleep(poll_s)
    raise BroadcastUnknown(
        coin_id_hex,
        f"broadcast accepted but coin {coin_id_hex[:16]}… not confirmed "
        f"within {timeout_s}s — confirmation unknown; do not retry blindly")

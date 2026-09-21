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
                          derivation_index > 0 (default 100): initial address
                          pool, derived synchronously. With 0, /get_sync_status
                          fails with "Insufficient derivations".
  POST /login              {"fingerprint": n}
  POST /get_sync_status    {} -> {"selectable_balance","receive_address",...}
  POST /get_wallet_address {"fingerprint": n, "network_id": "testnet11"}
  POST /send_xch           {"address","amount","fee","memos","auto_submit": true}
  POST /get_transactions   {"offset":0,"limit":5,"ascending":false}
  POST /send_cat            {"asset_id","address","amount","fee","memos","auto_submit": true}
  POST /get_cats            {} -> {"cats": [{"asset_id","balance",...}]}
  POST /transfer_nfts       {"nft_ids","address","fee","auto_submit": true}

Amounts in Sage's API are untagged string-or-number ("Amount"); we send
plain JSON integers for mojos and accept either form back.

Nothing in this module ever logs key material. The private key is passed
to Sage's /import_key once per (chain, label) — Sage needs the secret to
sign — over the local mTLS channel only.
"""

import http.client
import json
import os
import re
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

_HEX64_OFFER = re.compile(r"[0-9a-fA-F]{64}")


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

    def import_key(self, name: str, key_hex: str,
                   derivation_count: int = 100) -> int:
        """Import a raw 32-byte hex private key; returns its fingerprint.

        derivation_count is the initial address-pool size Sage derives
        synchronously at import (0..derivation_count). It must be > 0:
        with zero derivations Sage's /get_sync_status fails with
        "Insufficient derivations" and the wallet cannot report a balance
        or receive address until the sync worker derives a batch (which
        needs peer connectivity). Importing the pool up front makes the
        wallet usable immediately and deterministically.
        """
        out = self.call("import_key", {"name": name, "key": key_hex,
                                      "derivation_index": derivation_count})
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

    def send_cat(self, asset_id: str, address: str, amount_mojos: int,
                 fee_mojos: int = 0, memos: list | None = None) -> dict:
        """POST /send_cat — send CAT tokens of `asset_id` to `address`.

        `asset_id` is the 64-hex tree hash of the curried TAIL.
        """
        return self.call("send_cat", {
            "asset_id": asset_id,
            "address": address,
            "amount": amount_mojos,
            "fee": fee_mojos,
            "memos": memos or [],
            "auto_submit": True,
        })

    def get_cats(self) -> list:
        """POST /get_cats — list CATs in the logged-in wallet."""
        return self.call("get_cats", {}).get("cats", [])

    def transfer_nfts(self, nft_ids: list, address: str,
                      fee_mojos: int = 0) -> dict:
        """POST /transfer_nfts — move NFT(s) to a new owner `address`.

        `nft_ids` are the wallet's NFT identifiers (nft1… ids accepted).
        """
        return self.call("transfer_nfts", {
            "nft_ids": list(nft_ids),
            "address": address,
            "fee": fee_mojos,
            "auto_submit": True,
        })

    def recent_transactions(self, limit: int = 5) -> list:
        return self.call("get_transactions",
                         {"offset": 0, "limit": limit,
                          "ascending": False}).get("transactions", [])

    # ---- offers (full lifecycle; wallet-local construction + signing) ----

    @staticmethod
    def _offer_amounts(items: list) -> list:
        """Normalize [{asset, amount_mojos}] into Sage OfferAmount dicts.

        asset "native" (or None) -> XCH (asset_id omitted); otherwise a
        64-hex CAT asset id. NFT offers are not supported here — the
        daemon's NFT path is transfer-only.
        """
        out = []
        for it in items:
            asset = it.get("asset", "native")
            amount = it.get("amount_mojos")
            if not isinstance(amount, int) or amount <= 0:
                raise SageError(
                    "offer amounts must be positive integer mojos")
            if asset in (None, "native"):
                out.append({"amount": amount})
            elif isinstance(asset, str) and _HEX64_OFFER.fullmatch(asset):
                out.append({"asset_id": asset.lower(), "amount": amount})
            else:
                raise SageError(
                    f"bad offer asset {asset!r}: expected 'native' or a "
                    "64-hex CAT asset id")
        return out

    def make_offer(self, offered: list, requested: list, fee_mojos: int = 0,
                   receive_address: str | None = None,
                   expires_at_second: int | None = None,
                   auto_import: bool = True) -> dict:
        """POST /make_offer — build (off-chain) an offer giving `offered`
        for `requested`. Each side is [{asset, amount_mojos}].
        Returns {"offer": <bech32 string>, "offer_id": <hex>}."""
        if not offered or not requested:
            raise SageError("make_offer needs at least one offered and one "
                            "requested asset")
        body = {
            "offered_assets": self._offer_amounts(offered),
            "requested_assets": self._offer_amounts(requested),
            "fee": fee_mojos,
            "auto_import": auto_import,
        }
        if receive_address:
            body["receive_address"] = receive_address
        if expires_at_second:
            body["expires_at_second"] = expires_at_second
        out = self.call("make_offer", body)
        if not out.get("offer") or not out.get("offer_id"):
            raise SageError(f"/make_offer gave no offer: {out!r}")
        return out

    def take_offer(self, offer: str, fee_mojos: int = 0,
                   auto_submit: bool = True) -> dict:
        """POST /take_offer — accept someone else's offer (on-chain spend
        of the requested side). Returns the transaction summary."""
        return self.call("take_offer", {
            "offer": offer,
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def cancel_offer(self, offer_id: str, fee_mojos: int = 0,
                     auto_submit: bool = True) -> dict:
        """POST /cancel_offer — cancel one of our offers by spending the
        offered coins on-chain (double-spend invalidates the offer)."""
        return self.call("cancel_offer", {
            "offer_id": offer_id,
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def cancel_offers(self, offer_ids: list, fee_mojos: int = 0,
                      auto_submit: bool = True) -> dict:
        """POST /cancel_offers — cancel several of our offers in one tx."""
        return self.call("cancel_offers", {
            "offer_ids": list(offer_ids),
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def get_offers(self) -> list:
        """POST /get_offers — our offer records (any status)."""
        return self.call("get_offers", {}).get("offers", [])

    def get_offer(self, offer_id: str) -> dict:
        """POST /get_offer — one offer record by id."""
        return self.call("get_offer", {"offer_id": offer_id}).get("offer", {})

    def get_offers_for_asset(self, asset_id: str) -> list:
        """POST /get_offers_for_asset — offers involving a CAT asset."""
        return self.call("get_offers_for_asset",
                         {"asset_id": asset_id}).get("offers", [])

    def view_offer(self, offer: str) -> dict:
        """POST /view_offer — decode an offer string without accepting it.
        Returns {"offer": <summary>, "status": <record status>}."""
        return self.call("view_offer", {"offer": offer})

    def import_offer(self, offer: str) -> str:
        """POST /import_offer — store someone else's offer string locally."""
        out = self.call("import_offer", {"offer": offer})
        if not out.get("offer_id"):
            raise SageError(f"/import_offer gave no offer_id: {out!r}")
        return out["offer_id"]

    def delete_offer(self, offer_id: str) -> None:
        """POST /delete_offer — drop an offer record locally (NOT an
        on-chain cancel; use cancel_offer for that)."""
        self.call("delete_offer", {"offer_id": offer_id})

    def combine_offers(self, offers: list) -> str:
        """POST /combine_offers — merge offer strings into one (local)."""
        out = self.call("combine_offers", {"offers": list(offers)})
        if not out.get("offer"):
            raise SageError(f"/combine_offers gave no offer: {out!r}")
        return out["offer"]

    # ---- coins ----

    def get_coins(self, asset_id: str | None = None, offset: int = 0,
                  limit: int = 50) -> list:
        """POST /get_coins — wallet coin records, optional CAT filter."""
        body = {"offset": offset, "limit": limit}
        if asset_id:
            body["asset_id"] = asset_id
        return self.call("get_coins", body).get("coins", [])

    def get_coins_by_ids(self, coin_ids: list) -> list:
        """POST /get_coins_by_ids — coin records for exact coin ids."""
        return self.call("get_coins_by_ids",
                         {"coin_ids": list(coin_ids)}).get("coins", [])

    def get_are_coins_spendable(self, coin_ids: list) -> bool:
        """POST /get_are_coins_spendable — all listed coins spendable?"""
        return bool(self.call("get_are_coins_spendable",
                              {"coin_ids": list(coin_ids)}).get("spendable"))

    def get_spendable_coin_count(self, asset_id: str | None = None) -> int:
        """POST /get_spendable_coin_count — count (None asset = XCH)."""
        body = {}
        if asset_id:
            body["asset_id"] = asset_id
        return int(self.call("get_spendable_coin_count", body).get("count", 0))

    # ---- transactions ----

    def get_transaction(self, transaction_id: str) -> dict:
        """POST /get_transaction — one transaction record by id."""
        return self.call("get_transaction",
                         {"transaction_id": transaction_id})

    def get_pending_transactions(self) -> list:
        """POST /get_pending_transactions — unconfirmed wallet txs."""
        return self.call("get_pending_transactions", {}).get("transactions", [])

    # ---- asset reads ----

    def get_all_cats(self) -> list:
        """POST /get_all_cats — every known CAT (not just in-wallet)."""
        return self.call("get_all_cats", {}).get("cats", [])

    def get_nfts(self, offset: int = 0, limit: int = 50,
                 collection_id: str | None = None,
                 name: str | None = None) -> list:
        """POST /get_nfts — wallet NFTs, paginated with optional filters."""
        body = {"offset": offset, "limit": limit}
        if collection_id:
            body["collection_id"] = collection_id
        if name:
            body["name"] = name
        return self.call("get_nfts", body).get("nfts", [])

    def get_nft(self, nft_id: str) -> dict:
        """POST /get_nft — one NFT record."""
        return self.call("get_nft", {"nft_id": nft_id}).get("nft", {})

    def get_nft_data(self, nft_id: str) -> dict:
        """POST /get_nft_data — an NFT's data URIs/content hashes."""
        return self.call("get_nft_data", {"nft_id": nft_id})

    def get_dids(self) -> list:
        """POST /get_dids — DIDs in the wallet."""
        return self.call("get_dids", {}).get("dids", [])

    def get_minter_did_ids(self) -> list:
        """POST /get_minter_did_ids — minter DID ids known to the wallet."""
        return self.call("get_minter_did_ids", {}).get("minter_did_ids", [])

    def is_asset_owned(self, asset_id: str) -> bool:
        """POST /is_asset_owned — do we own any of this CAT/NFT asset?"""
        return bool(self.call("is_asset_owned",
                              {"asset_id": asset_id}).get("owned"))

    def get_options(self, offset: int = 0, limit: int = 50) -> list:
        """POST /get_options — option contracts in the wallet."""
        return self.call("get_options",
                         {"offset": offset, "limit": limit}).get("options", [])

    def get_option(self, option_id: str) -> dict:
        """POST /get_option — one option record."""
        return self.call("get_option", {"option_id": option_id}).get("option", {})

    # ---- system / network reads ----

    def get_version(self) -> str:
        """POST /get_version — the Sage build's version string."""
        return self.call("get_version", {}).get("version", "")

    def get_network(self) -> dict:
        """POST /get_network — current network name/kind."""
        return self.call("get_network", {})

    def get_networks(self) -> list:
        """POST /get_networks — networks Sage knows."""
        out = self.call("get_networks", {})
        return out.get("networks", out)

    def get_peers(self) -> list:
        """POST /get_peers — connected full-node peers."""
        return self.call("get_peers", {}).get("peers", [])

    def get_xch_usd_price(self) -> float:
        """POST /get_xch_usd_price — oracle USD price (display only)."""
        return float(self.call("get_xch_usd_price", {}).get("usd", 0.0))

    def check_address(self, address: str) -> bool:
        """POST /check_address — valid and belongs to this wallet?"""
        return bool(self.call("check_address",
                              {"address": address}).get("valid"))

    def get_derivations(self, offset: int = 0, limit: int = 50,
                        hardened: bool = False) -> dict:
        """POST /get_derivations — address derivation records."""
        return self.call("get_derivations", {"offset": offset,
                                             "limit": limit,
                                             "hardened": hardened})

    def get_database_stats(self) -> dict:
        """POST /get_database_stats — wallet DB size/sync stats."""
        return self.call("get_database_stats", {})


def cat_balance(rpc: SageRpc, asset_id: str) -> int:
    """Spendable balance (CAT mojos) of `asset_id` in the logged-in wallet.

    Raises SageError when the CAT is not in the wallet — sending a CAT we
    don't hold must fail closed before /send_cat is ever called.
    """
    want = asset_id.lower()
    for cat in rpc.get_cats():
        if (cat.get("asset_id") or "").lower() == want:
            return amount_to_int(cat.get("balance", 0))
    raise SageError(f"CAT {asset_id[:16]}… not in wallet — refusing")


def wait_for_outgoing(rpc: SageRpc, destination: str, amount_mojos: int,
                      since_ts: float, timeout_s: int = 180,
                      poll_s: int = 5, asset_ref: str | None = None) -> dict:
    """Poll /get_transactions until our outgoing spend shows up.

    Matches the first transaction created after `since_ts` whose created
    coins include `destination` (case-insensitive) with `amount_mojos`.
    When `asset_ref` is given (a CAT asset id), the created coin must also
    carry that reference in one of its asset/nft/coin id fields — Sage's
    tx records must echo the asset or verification fails closed.
    Fail-closed on timeout: the spend may still confirm later, so the
    caller must treat this as "broadcast, confirmation unknown" rather
    than as a failure.
    """
    dest = destination.lower()
    ref = asset_ref.lower() if asset_ref else None
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
                if addr != dest or amt != amount_mojos:
                    continue
                if ref is not None:
                    fields = (coin.get("asset_id"), coin.get("nft_id"),
                              coin.get("coin_id"))
                    if not any(isinstance(f, str) and f.lower() == ref
                               for f in fields):
                        continue
                return tx
        time.sleep(poll_s)
    raise BroadcastUnknown(
        "",
        "spend was submitted but no matching transaction appeared in "
        f"/get_transactions within {timeout_s}s — broadcast, confirmation "
        "unknown; do not retry blindly")


def wait_for_nft_transfer(rpc: SageRpc, nft_ref: str, destination: str,
                          since_ts: float, timeout_s: int = 180,
                          poll_s: int = 5) -> dict:
    """Poll /get_transactions until the approved NFT move shows up.

    An NFT transfer consumes the exact NFT coin (`nft_ref` — coin id or
    nft1 id) and creates a coin to the new owner. Matches the first
    transaction created after `since_ts` where a *spent* coin references
    the NFT and a *created* coin goes to `destination`. Fail-closed on
    timeout, same as wait_for_outgoing.
    """
    dest = destination.lower()
    ref = nft_ref.lower()
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for tx in rpc.recent_transactions(limit=10):
            ts = tx.get("timestamp") or 0
            if ts < since_ts - 60:
                continue
            spent_ids = set()
            for coin in tx.get("spent", []):
                for f in (coin.get("coin_id"), coin.get("nft_id")):
                    if isinstance(f, str):
                        spent_ids.add(f.lower())
            if ref not in spent_ids:
                continue
            for coin in tx.get("created", []):
                if (coin.get("address") or "").lower() == dest:
                    return tx
        time.sleep(poll_s)
    raise BroadcastUnknown(
        "",
        "NFT transfer was submitted but no matching transaction appeared "
        f"in /get_transactions within {timeout_s}s — broadcast, "
        "confirmation unknown; do not retry blindly")

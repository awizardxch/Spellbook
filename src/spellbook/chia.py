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

        asset "native" (or None) -> XCH (asset_id omitted); a 64-hex CAT
        asset id -> {"asset_id": ...}; "nft:<launcher-id>" -> {"asset_id":
        <launcher-id>} — Sage resolves the id to an NFT leg when it matches
        a wallet NFT (OfferAmount.asset_id carries XCH/CAT/NFT alike; the
        wallet distinguishes by lookup). NFT legs must be owned by the
        wallet — the daemon checks that before calling.
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
                continue
            ref = asset
            if isinstance(asset, str) and asset.startswith("nft:"):
                ref = asset[4:]
                if amount != 1:
                    raise SageError(
                        "NFT offer legs must have amount_mojos 1 "
                        "(the NFT is a singleton)")
            if isinstance(ref, str) and _HEX64_OFFER.fullmatch(ref):
                out.append({"asset_id": ref.lower(), "amount": amount})
            else:
                raise SageError(
                    f"bad offer asset {asset!r}: expected 'native', a "
                    "64-hex CAT id, or 'nft:<64-hex launcher id>'")
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

    def get_transaction(self, height: int) -> dict:
        """POST /get_transaction — one transaction record by height."""
        if not isinstance(height, int) or height < 0:
            raise SageError("get_transaction needs a non-negative height")
        return self.call("get_transaction", {"height": height})

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

    # ---- more reads (full Sage surface) ----

    def get_transactions(self, offset: int = 0, limit: int = 50,
                         ascending: bool = False,
                         find_value: str | None = None) -> list:
        """POST /get_transactions — paginated wallet transactions."""
        body = {"offset": offset, "limit": limit, "ascending": ascending}
        if find_value:
            body["find_value"] = find_value
        return self.call("get_transactions", body).get("transactions", [])

    def get_nft_collections(self, offset: int = 0, limit: int = 50,
                            include_hidden: bool = False) -> list:
        """POST /get_nft_collections — NFT collections, paginated."""
        return self.call("get_nft_collections",
                         {"offset": offset, "limit": limit,
                          "include_hidden": include_hidden}
                         ).get("collections", [])

    def get_nft_collection(self, collection_id: str | None = None) -> dict:
        """POST /get_nft_collection — one collection (None = uncollected)."""
        body = {}
        if collection_id:
            body["collection_id"] = collection_id
        return self.call("get_nft_collection", body).get("collection", {})

    def get_nft_icon(self, nft_id: str) -> str:
        """POST /get_nft_icon — base64-encoded icon image."""
        return self.call("get_nft_icon",
                         {"nft_id": nft_id}).get("icon", "")

    def get_nft_thumbnail(self, nft_id: str) -> str:
        """POST /get_nft_thumbnail — base64-encoded thumbnail image."""
        return self.call("get_nft_thumbnail",
                         {"nft_id": nft_id}).get("thumbnail", "")

    def get_token(self, asset_id: str | None = None) -> dict:
        """POST /get_token — one CAT token record (None = XCH)."""
        body = {}
        if asset_id:
            body["asset_id"] = asset_id
        return self.call("get_token", body).get("token", {})

    def filter_unlocked_coins(self, coin_ids: list) -> list:
        """POST /filter_unlocked_coins — keep only unlocked coin ids."""
        return self.call("filter_unlocked_coins",
                         {"coin_ids": list(coin_ids)}).get("coin_ids", [])

    def get_asset_coins(self, kind: str | None = None,
                        asset_id: str | None = None,
                        included_locked: bool | None = None,
                        offset: int | None = None,
                        limit: int | None = None) -> list:
        """POST /get_asset_coins — spendable coins for an asset type.

        kind is one of "cat" | "did" | "nft" (None = any). Note the
        endpoint uses camelCase keys.
        """
        body = {}
        if kind:
            body["type"] = kind
        if asset_id:
            body["assetId"] = asset_id
        if included_locked is not None:
            body["includedLocked"] = included_locked
        if offset is not None:
            body["offset"] = offset
        if limit is not None:
            body["limit"] = limit
        return self.call("get_asset_coins", body).get("coins", [])

    # ---- issuance / minting (fund-moving; daemon queues these) ----

    def create_did(self, name: str, fee_mojos: int = 0,
                   auto_submit: bool = True) -> dict:
        """POST /create_did — create a new DID. TransactionResponse."""
        return self.call("create_did", {
            "name": name,
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def bulk_mint_nfts(self, mints: list, did_id: str,
                       fee_mojos: int = 0, auto_submit: bool = True) -> dict:
        """POST /bulk_mint_nfts — mint 1..n NFTs in one transaction.

        Each mint: {address?, edition_number?, edition_total?,
        data_hash?, data_uris[], metadata_hash?, metadata_uris[],
        license_hash?, license_uris[], royalty_address?,
        royalty_ten_thousandths?}. Returns {nft_ids, summary, coin_spends}.
        """
        return self.call("bulk_mint_nfts", {
            "mints": list(mints),
            "did_id": did_id,
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def mint_option(self, expiration_seconds: int, underlying: dict,
                    strike: dict, fee_mojos: int = 0,
                    auto_submit: bool = True) -> dict:
        """POST /mint_option — mint an option contract.

        underlying/strike: {"asset_id": <64-hex or None>, "amount": int}.
        TransactionResponse.
        """
        for leg in (underlying, strike):
            if not isinstance(leg.get("amount"), int) or leg["amount"] <= 0:
                raise SageError("option legs need a positive integer amount")
        return self.call("mint_option", {
            "expiration_seconds": expiration_seconds,
            "underlying": {"asset_id": underlying.get("asset_id"),
                           "amount": underlying["amount"]},
            "strike": {"asset_id": strike.get("asset_id"),
                       "amount": strike["amount"]},
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def issue_cat(self, name: str, ticker: str, amount_mojos: int,
                  revocable: bool = False, fee_mojos: int = 0,
                  auto_submit: bool = True) -> dict:
        """POST /issue_cat — issue a new CAT. TransactionResponse.

        This is token issuance: the daemon treats it as a queued fund
        intent, and the standing token-launch gate still applies — the
        human's approval is the authorization.
        """
        if not name or not ticker:
            raise SageError("issue_cat needs a name and a ticker")
        if not isinstance(amount_mojos, int) or amount_mojos <= 0:
            raise SageError("issue_cat amount must be a positive integer")
        return self.call("issue_cat", {
            "name": name,
            "ticker": ticker,
            "amount": amount_mojos,
            "revocable": revocable,
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    # ---- DID / option transfers (fund-moving; daemon queues these) ----

    def transfer_dids(self, did_ids: list, address: str,
                      fee_mojos: int = 0, clawback: int | None = None,
                      auto_submit: bool = True) -> dict:
        """POST /transfer_dids — transfer DIDs. TransactionResponse."""
        body = {"did_ids": list(did_ids), "address": address,
                "fee": fee_mojos, "auto_submit": auto_submit}
        if clawback is not None:
            body["clawback"] = clawback
        return self.call("transfer_dids", body)

    def transfer_options(self, option_ids: list, address: str,
                         fee_mojos: int = 0, clawback: int | None = None,
                         auto_submit: bool = True) -> dict:
        """POST /transfer_options — transfer options. TransactionResponse."""
        body = {"option_ids": list(option_ids), "address": address,
                "fee": fee_mojos, "auto_submit": auto_submit}
        if clawback is not None:
            body["clawback"] = clawback
        return self.call("transfer_options", body)

    def exercise_options(self, option_ids: list, fee_mojos: int = 0,
                         auto_submit: bool = True) -> dict:
        """POST /exercise_options — exercise options. TransactionResponse."""
        return self.call("exercise_options", {
            "option_ids": list(option_ids),
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def assign_nfts_to_did(self, nft_ids: list, did_id: str | None,
                           fee_mojos: int = 0,
                           auto_submit: bool = True) -> dict:
        """POST /assign_nfts_to_did — assign NFTs to a DID profile
        (did_id None unassigns). TransactionResponse."""
        return self.call("assign_nfts_to_did", {
            "nft_ids": list(nft_ids),
            "did_id": did_id,
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def normalize_dids(self, did_ids: list, fee_mojos: int = 0,
                       auto_submit: bool = True) -> dict:
        """POST /normalize_dids — normalize DID coins. TransactionResponse."""
        return self.call("normalize_dids", {
            "did_ids": list(did_ids),
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def finalize_clawback(self, coin_ids: list, fee_mojos: int = 0,
                          auto_submit: bool = True) -> dict:
        """POST /finalize_clawback — reclaim clawback coins.
        TransactionResponse."""
        return self.call("finalize_clawback", {
            "coin_ids": list(coin_ids),
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    # ---- coin management (fund-moving; daemon queues these) ----

    def combine(self, coin_ids: list, fee_mojos: int = 0,
                auto_submit: bool = True) -> dict:
        """POST /combine — combine coins into fewer. TransactionResponse."""
        return self.call("combine", {
            "coin_ids": list(coin_ids),
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def split(self, coin_ids: list, output_count: int, fee_mojos: int = 0,
              auto_submit: bool = True) -> dict:
        """POST /split — split coins into output_count coins.
        TransactionResponse."""
        if not isinstance(output_count, int) or output_count < 2:
            raise SageError("split needs output_count >= 2")
        return self.call("split", {
            "coin_ids": list(coin_ids),
            "output_count": output_count,
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    def auto_combine_xch(self, max_coins: int,
                         max_coin_amount: int | None = None,
                         fee_mojos: int = 0,
                         auto_submit: bool = True) -> dict:
        """POST /auto_combine_xch — auto-combine small XCH coins."""
        body = {"max_coins": max_coins, "fee": fee_mojos,
                "auto_submit": auto_submit}
        if max_coin_amount is not None:
            body["max_coin_amount"] = max_coin_amount
        return self.call("auto_combine_xch", body)

    def auto_combine_cat(self, asset_id: str, max_coins: int,
                         max_coin_amount: int | None = None,
                         fee_mojos: int = 0,
                         auto_submit: bool = True) -> dict:
        """POST /auto_combine_cat — auto-combine small CAT coins."""
        if not _HEX64_OFFER.fullmatch(asset_id or ""):
            raise SageError("auto_combine_cat needs a 64-hex asset id")
        body = {"asset_id": asset_id.lower(), "max_coins": max_coins,
                "fee": fee_mojos, "auto_submit": auto_submit}
        if max_coin_amount is not None:
            body["max_coin_amount"] = max_coin_amount
        return self.call("auto_combine_cat", body)

    # ---- bulk sends (fund-moving; daemon queues these) ----

    def bulk_send_xch(self, addresses: list, amount_mojos: int,
                      fee_mojos: int = 0, memos: list | None = None,
                      auto_submit: bool = True) -> dict:
        """POST /bulk_send_xch — same amount to many addresses."""
        return self.call("bulk_send_xch", {
            "addresses": list(addresses),
            "amount": amount_mojos,
            "fee": fee_mojos,
            "memos": memos or [],
            "auto_submit": auto_submit,
        })

    def bulk_send_cat(self, asset_id: str, addresses: list,
                      amount_mojos: int, fee_mojos: int = 0,
                      memos: list | None = None, include_hint: bool = True,
                      auto_submit: bool = True) -> dict:
        """POST /bulk_send_cat — same CAT amount to many addresses."""
        if not _HEX64_OFFER.fullmatch(asset_id or ""):
            raise SageError("bulk_send_cat needs a 64-hex asset id")
        return self.call("bulk_send_cat", {
            "asset_id": asset_id.lower(),
            "addresses": list(addresses),
            "amount": amount_mojos,
            "fee": fee_mojos,
            "memos": memos or [],
            "include_hint": include_hint,
            "auto_submit": auto_submit,
        })

    def multi_send(self, payments: list, fee_mojos: int = 0,
                   auto_submit: bool = True) -> dict:
        """POST /multi_send — mixed-asset payments in one transaction.

        payments: [{"asset_id": <64-hex or None>, "address": ...,
                    "amount": int, "memos": [...]}].
        """
        norm = []
        for pay in payments:
            amt = pay.get("amount")
            if not isinstance(amt, int) or amt <= 0:
                raise SageError("multi_send payments need positive amounts")
            aid = pay.get("asset_id")
            if aid is not None and not _HEX64_OFFER.fullmatch(aid):
                raise SageError(f"bad multi_send asset_id {aid!r}")
            norm.append({"asset_id": aid.lower() if aid else None,
                         "address": pay.get("address"),
                         "amount": amt,
                         "memos": pay.get("memos") or []})
        return self.call("multi_send", {
            "payments": norm,
            "fee": fee_mojos,
            "auto_submit": auto_submit,
        })

    # ---- message signing (capability; daemon always queues) ----

    def sign_message_by_address(self, address: str, message: str) -> dict:
        """POST /sign_message_by_address — sign a message with the key
        behind an address. No funds move; the daemon still queues it so a
        human sees exactly what is being signed."""
        return self.call("sign_message_by_address",
                         {"address": address, "message": message})

    def sign_message_with_public_key(self, public_key: str,
                                     message: str) -> dict:
        """POST /sign_message_with_public_key — sign with a public key.
        Queued like sign_message_by_address.

        Note: Sage's WalletConnect request struct uses camelCase, so the
        key goes out as "publicKey"."""
        return self.call("sign_message_with_public_key",
                         {"publicKey": public_key, "message": message})

    # ---- wallet-local metadata (no chain, no funds) ----

    def update_cat(self, record: dict) -> None:
        """POST /update_cat — update a CAT token record (local only)."""
        self.call("update_cat", {"record": record})

    def update_did(self, did_id: str, name: str | None = None,
                   visible: bool = True) -> None:
        """POST /update_did — rename / show-hide a DID (local only)."""
        body = {"did_id": did_id, "visible": visible}
        if name is not None:
            body["name"] = name
        self.call("update_did", body)

    def update_nft(self, nft_id: str, visible: bool = True) -> None:
        """POST /update_nft — show/hide an NFT (local only)."""
        self.call("update_nft", {"nft_id": nft_id, "visible": visible})

    def update_option(self, option_id: str, visible: bool = True) -> None:
        """POST /update_option — show/hide an option (local only)."""
        self.call("update_option",
                  {"option_id": option_id, "visible": visible})

    def update_nft_collection(self, collection_id: str,
                              visible: bool = True) -> None:
        """POST /update_nft_collection — show/hide a collection (local)."""
        self.call("update_nft_collection",
                  {"collection_id": collection_id, "visible": visible})

    def redownload_nft(self, nft_id: str) -> None:
        """POST /redownload_nft — re-fetch an NFT's data/metadata (local)."""
        self.call("redownload_nft", {"nft_id": nft_id})


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


def wait_for_tx_by_inputs(rpc: SageRpc, input_coin_ids: list,
                          since_ts: float, timeout_s: int = 180,
                          poll_s: int = 5) -> dict:
    """Poll /get_transactions until a tx spending one of `input_coin_ids`
    shows up (created after `since_ts`).

    Used to verify auto_submit writes (mints, combines, DID/option moves)
    where there is no single external destination to match on. The inputs
    come from the RPC's own TransactionResponse summary, so a match proves
    the exact submitted transaction landed in the wallet. Fail-closed on
    timeout, same BroadcastUnknown discipline as wait_for_outgoing.
    """
    wanted = {str(c).lower() for c in input_coin_ids if c}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for tx in rpc.recent_transactions(limit=10):
            ts = tx.get("timestamp") or 0
            if ts < since_ts - 60:
                continue
            spent = {str(c.get("coin_id") or "").lower()
                     for c in tx.get("spent", [])}
            if wanted & spent:
                return tx
        time.sleep(poll_s)
    raise BroadcastUnknown(
        "",
        "transaction was submitted but no transaction spending its inputs "
        f"appeared in /get_transactions within {timeout_s}s — broadcast, "
        "confirmation unknown; do not retry blindly")


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

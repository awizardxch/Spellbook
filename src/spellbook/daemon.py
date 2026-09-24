#!/usr/bin/env python3
"""spellbookd — the Spellbook policy daemon. SPEC §4, O10.

Listens on a Unix domain socket (peer-credential checks). Localhost HTTP
is the specified fallback; this build implements the socket path.

Protocol: newline-delimited JSON per connection.
  request:  {"token": "<hex>", "route": "<name>", "params": {...}}
  response: {"ok": true, ...} | {"ok": false, "error": "..."}

Real in this build: token auth, per-role peer-UID enforcement (when
configured), routing, policy evaluation, the decision ledger, a persistent
spend queue, 24h velocity accounting rebuilt from disk, the §2 KDF
(third implementation — reproduces vectors/vectors.json), labeled
addresses, EVM testnet submission (build/sign/broadcast with pre-broadcast
verification; mainnet refuses without explicit config), live EVM balances,
Chia/XCH submission via Sage RPC (daemon-spawned `sage rpc start`, local
mTLS, key import with local fingerprint verification, testnet11;
chia-mainnet refuses without the explicit flag), live XCH balances, and
Ed25519 identity signing behind the S1 gate (Option B adopted).

Nothing here touches mainnet without the explicit mainnet_submit_enabled flag.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

from spellbook import chia, chia_relay, evm, kdf, sign as spellsign
from spellbook import chia_sign
from spellbook import doctor as doctor_mod
from spellbook import solana as solana_mod
from spellbook import version as version_mod
from spellbook.config import load_config, load_policy
from spellbook.ledger import Ledger
from spellbook.policy import evaluate
from spellbook.seed import load_seed
from spellbook import tokens as token_auth
from spellbook import dex as dex_mod

REQUEST_ROUTES = {
    "request_spend", "queue_read", "status", "addresses", "doctor",
    "ledger_read", "sign_musebook_request", "chia_read",
    "offer_make", "offer_take", "offer_cancel",
    "offer_import", "offer_delete", "offer_combine",
    "nft_mint", "nft_update", "nft_collection_update", "nft_redownload",
    "nft_assign_did",
    "did_create", "did_update", "did_transfer", "did_normalize",
    "option_mint", "option_update", "option_transfer", "option_exercise",
    "cat_issue", "cat_update",
    "clawback_finalize",
    "coin_combine", "coin_split", "coin_autocombine",
    "bulk_send", "multi_send",
    "message_sign",
    "dex_swap", "dex_lp_add", "dex_venues",
}
APPROVE_ROUTES = {
    "queue_approve", "queue_reject", "publish_directory_entry",
}

# v1 transfer schema — plain transfers only (S13). Unknown fields are
# rejected; anything shaped like a contract call is denied, not coerced.
SPEND_FIELDS = {"chain", "destination", "asset", "purpose"}
AMOUNT_FIELDS = {"amount_mojos", "amount_wei", "amount_lamports"}

# Offer intent schemas. make/take/cancel move or encumber funds, so they
# travel the same queue/approval/ledger/velocity path as transfers, with
# an explicit "intent" discriminator (S13: unknown shapes are rejected,
# never coerced into transfers).
OFFER_MAKE_FIELDS = {"intent", "chain", "offered", "requested", "fee_mojos",
                     "purpose", "expires_at_second", "receive_address"}
OFFER_TAKE_FIELDS = {"intent", "chain", "offer", "fee_mojos", "purpose",
                     "_give"}
OFFER_CANCEL_FIELDS = {"intent", "chain", "offer_id", "offer_ids",
                       "fee_mojos", "purpose", "_offered"}

# Full Sage wallet surface: every fund-moving Sage endpoint is a queued
# intent with an explicit schema (S13: unknown shapes are rejected, never
# coerced). Local-only metadata ops are direct routes, not queue items.
NFT_MINT_FIELDS = {"intent", "chain", "mints", "did_id", "fee_mojos",
                   "purpose"}
DID_CREATE_FIELDS = {"intent", "chain", "name", "fee_mojos", "purpose"}
DID_TRANSFER_FIELDS = {"intent", "chain", "did_ids", "destination",
                       "fee_mojos", "purpose", "clawback_at"}
DID_NORMALIZE_FIELDS = {"intent", "chain", "did_ids", "fee_mojos", "purpose"}
OPTION_MINT_FIELDS = {"intent", "chain", "expiration_seconds", "underlying",
                      "strike", "fee_mojos", "purpose"}
OPTION_TRANSFER_FIELDS = {"intent", "chain", "option_ids", "destination",
                          "fee_mojos", "purpose", "clawback_at"}
OPTION_EXERCISE_FIELDS = {"intent", "chain", "option_ids", "fee_mojos",
                          "purpose"}
CAT_ISSUE_FIELDS = {"intent", "chain", "name", "ticker", "amount_mojos",
                    "revocable", "fee_mojos", "purpose"}
NFT_ASSIGN_DID_FIELDS = {"intent", "chain", "nft_ids", "did_id",
                         "fee_mojos", "purpose"}
CLAWBACK_FIELDS = {"intent", "chain", "coin_ids", "fee_mojos", "purpose"}
COIN_COMBINE_FIELDS = {"intent", "chain", "coin_ids", "fee_mojos", "purpose"}
COIN_SPLIT_FIELDS = {"intent", "chain", "coin_ids", "output_count",
                     "fee_mojos", "purpose"}
COIN_AUTOCOMBINE_FIELDS = {"intent", "chain", "asset", "max_coins",
                           "max_coin_amount", "fee_mojos", "purpose"}
BULK_SEND_FIELDS = {"intent", "chain", "asset", "addresses", "amount_mojos",
                    "fee_mojos", "purpose", "memos"}
MULTI_SEND_FIELDS = {"intent", "chain", "payments", "fee_mojos", "purpose"}
MESSAGE_SIGN_FIELDS = {"intent", "chain", "address", "public_key",
                       "message", "purpose", "sign_type",
                       "human_approval_ref"}

# DEX intents (SPEC §10 v2 — approved by Speechless 2026-09-23): bounded
# swap / LP-add requests. The queue holds BOUNDS (tokens, exact sell
# amounts, minimum buy, slippage, deadline) — never raw calldata. The
# daemon fetches the firm venue quote at execution time and refuses to
# sign unless it fits the approved bounds. Unknown shapes are rejected
# (S13), never coerced.
SWAP_FIELDS = {"intent", "chain", "venue", "sell_token", "buy_token",
               "sell_amount_wei", "min_buy_amount_wei", "max_slippage_bps",
               "purpose", "deadline_sec"}
LP_ADD_FIELDS = {"intent", "chain", "protocol", "router", "token_a", "token_b",
                 "amount_a_wei", "amount_b_wei", "amount_a_min_wei",
                 "amount_b_min_wei", "fee", "tick_lower", "tick_upper",
                 "purpose", "deadline_sec"}

# EVM gas-price headroom, in basis points over the node's quoted price.
# Signing is legacy type-0 (see evm.py): on EIP-1559 chains the node reads
# the legacy gasPrice as maxFeePerGas and rejects the submission when the
# block base fee lands above it ("max fee per gas less than block base
# fee"). A quote taken seconds before submission can already be stale, so
# every EVM submission goes through _evm_gas_price() below. 25% headroom
# absorbs normal base-fee movement. Note the cost is real: a legacy tx on
# a 1559 chain pays its full gasPrice (base fee + the rest as tip to the
# block producer), so the bump is kept modest on purpose.
EVM_GAS_PRICE_BUMP_BPS = 2500


def _evm_gas_price(rpc) -> int:
    """Node gas price plus headroom — the single choke point for EVM submissions."""
    return rpc.gas_price_wei() * (10_000 + EVM_GAS_PRICE_BUMP_BPS) // 10_000

# Wallet-local metadata routes: direct (no queue, no chain, no funds).
# Each has an explicit schema — S13 rejects anything else.
OFFER_IMPORT_FIELDS = {"intent", "chain", "offer"}
OFFER_DELETE_FIELDS = {"intent", "chain", "offer_id"}
OFFER_COMBINE_FIELDS = {"intent", "chain", "offers"}
CAT_UPDATE_FIELDS = {"intent", "chain", "record"}
DID_UPDATE_FIELDS = {"intent", "chain", "did_id", "name", "visible"}
NFT_UPDATE_FIELDS = {"intent", "chain", "nft_id", "visible"}
NFT_COLLECTION_UPDATE_FIELDS = {"intent", "chain", "collection_id",
                                "visible"}
NFT_REDOWNLOAD_FIELDS = {"intent", "chain", "nft_id"}
OPTION_UPDATE_FIELDS = {"intent", "chain", "option_id", "visible"}

# chia_read op allowlist: strictly read-only. Each entry is (rpc_method,
# [param names]). Anything not listed here is rejected by rt_chia_read, so
# the route can never become a generic RPC passthrough (no spends, no
# signing, no key material, no issuance, no local-record mutation —
# import/delete/combine live behind their own explicit routes).
_CHIA_READ_OPS = {
    # offers (local records / decode only — NOT take/cancel)
    "get_offers": ("get_offers", []),
    "get_offer": ("get_offer", ["offer_id"]),
    "get_offers_for_asset": ("get_offers_for_asset", ["asset_id"]),
    "view_offer": ("view_offer", ["offer"]),
    # coins
    "get_coins": ("get_coins", ["asset_id", "offset", "limit"]),
    "get_coins_by_ids": ("get_coins_by_ids", ["coin_ids"]),
    "get_are_coins_spendable": ("get_are_coins_spendable", ["coin_ids"]),
    "get_spendable_coin_count": ("get_spendable_coin_count", ["asset_id"]),
    "get_asset_coins": ("get_asset_coins",
                        ["kind", "asset_id", "included_locked",
                         "offset", "limit"]),
    "filter_unlocked_coins": ("filter_unlocked_coins", ["coin_ids"]),
    # transactions
    "get_transaction": ("get_transaction", ["height"]),
    "get_transactions": ("get_transactions",
                         ["offset", "limit", "ascending", "find_value"]),
    "get_pending_transactions": ("get_pending_transactions", []),
    "recent_transactions": ("recent_transactions", ["limit"]),
    # assets
    "get_cats": ("get_cats", []),
    "get_all_cats": ("get_all_cats", []),
    "get_token": ("get_token", ["asset_id"]),
    "get_nfts": ("get_nfts", ["offset", "limit", "collection_id", "name"]),
    "get_nft": ("get_nft", ["nft_id"]),
    "get_nft_data": ("get_nft_data", ["nft_id"]),
    "get_nft_icon": ("get_nft_icon", ["nft_id"]),
    "get_nft_thumbnail": ("get_nft_thumbnail", ["nft_id"]),
    "get_nft_collections": ("get_nft_collections",
                            ["offset", "limit", "include_hidden"]),
    "get_nft_collection": ("get_nft_collection", ["collection_id"]),
    "get_dids": ("get_dids", []),
    "get_minter_did_ids": ("get_minter_did_ids", []),
    "is_asset_owned": ("is_asset_owned", ["asset_id"]),
    "get_options": ("get_options", ["offset", "limit"]),
    "get_option": ("get_option", ["option_id"]),
    # system / network
    "get_version": ("get_version", []),
    "get_network": ("get_network", []),
    "get_networks": ("get_networks", []),
    "get_peers": ("get_peers", []),
    "get_xch_usd_price": ("get_xch_usd_price", []),
    "check_address": ("check_address", ["address"]),
    "get_derivations": ("get_derivations", ["offset", "limit", "hardened"]),
    "get_database_stats": ("get_database_stats", []),
    "sync_status": ("sync_status", []),
}


def _run_chia_read_op(daemon, rpc, op: str, p: dict):
    """Dispatch one allowlisted chia_read op against the Sage RPC."""
    method_name, param_names = _CHIA_READ_OPS[op]
    method = getattr(rpc, method_name)
    kwargs = {}
    for name in param_names:
        if name in p and p[name] is not None:
            kwargs[name] = p[name]
    return method(**kwargs)

VELOCITY_WINDOW_S = 24 * 3600

# Chia asset model (SPEC §3b): the `asset` field on a Chia-chain request
# is a real routing signal, not a label.
#   "native"           -> native XCH (Sage or relay transport)
#   64-hex             -> CAT asset id = tree hash of the curried TAIL
#                          (Sage transport only — /send_cat)
#   "nft:<id>"         -> NFT transfer; <id> is the NFT's coin id (64-hex)
#                          or nft1 id. Amount must be 1 (the NFT is a
#                          singleton). (Sage transport only — /transfer_nfts)
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")


def chia_asset_kind(asset: str) -> tuple:
    """Split a Chia asset field into (kind, ref).

    kind is "native" | "cat" | "nft"; ref is the CAT asset id (lowercased
    hex) or the NFT id, None for native. Raises chia.SageError on any
    malformed value so bad assets fail closed at request time.
    """
    if asset == "native":
        return ("native", None)
    if isinstance(asset, str) and _HEX64.fullmatch(asset):
        return ("cat", asset.lower())
    if isinstance(asset, str) and asset.startswith("nft:"):
        ref = asset[4:]
        if ref and (_HEX64.fullmatch(ref) or ref.startswith("nft1")):
            return ("nft", ref)
    raise chia.SageError(
        f"bad chia asset {asset!r}: expected 'native', a 64-hex CAT asset "
        "id, or 'nft:<id>'")


def _validate_offer_legs(items, side: str) -> list:
    """Validate one side of an offer intent: [{asset, amount_mojos}].

    Returns [(asset, amount)] with the asset in daemon form ("native",
    64-hex CAT id, or "nft:<ref>" where ref is a 64-hex coin/launcher id
    or nft1 id). NFT legs keep the "nft:" prefix here — the daemon
    resolves them to launcher ids (and checks ownership) via
    _resolve_offer_nft_legs before building the intent. Raises
    chia.SageError on any malformed leg so bad offers fail closed at
    request time.
    """
    if not isinstance(items, list) or not items:
        raise chia.SageError(f"offer {side} must be a non-empty list")
    out = []
    for it in items:
        if not isinstance(it, dict):
            raise chia.SageError(f"offer {side} leg must be an object")
        asset = it.get("asset", "native")
        amount = it.get("amount_mojos")
        try:
            kind, ref = chia_asset_kind(asset)
        except chia.SageError as e:
            raise chia.SageError(f"offer {side}: {e}") from e
        if not isinstance(amount, int) or amount <= 0:
            raise chia.SageError(
                f"offer {side}: amount_mojos must be a positive integer")
        if kind == "nft":
            if amount != 1:
                raise chia.SageError(
                    f"offer {side}: NFT legs must have amount_mojos 1")
            out.append((f"nft:{ref}", amount))
        else:
            out.append((asset if kind == "native" else ref, amount))
    return out


def _resolve_offer_nft_legs(rpc, legs: list, side: str) -> list:
    """Resolve "nft:<ref>" legs to "nft:<launcher-id>", checking ownership.

    Sage's /make_offer takes the NFT's launcher id as the leg's asset_id;
    the daemon accepts a coin id, launcher id, or nft1 id and resolves it
    here. Raises chia.SageError when the NFT is not in this wallet —
    offering someone else's NFT fails closed.
    """
    out = []
    for asset, amount in legs:
        if not asset.startswith("nft:"):
            out.append((asset, amount))
            continue
        launcher = _resolve_nft_launcher(rpc, asset[4:])
        if not launcher:
            raise chia.SageError(
                f"offer {side}: NFT {asset[4:][:16]}… is not in this "
                "wallet — refusing")
        out.append((f"nft:{launcher}", amount))
    return out


def _resolve_nft_launcher(rpc, ref: str) -> str | None:
    """Launcher id (lowercase hex) for an NFT ref, or None if not owned.

    ref may be a 64-hex coin id, a 64-hex launcher id, or an nft1 id.
    """
    r = (ref or "").strip()
    if r.startswith("nft1"):
        rec = rpc.get_nft(r) or {}
        lid = rec.get("launcher_id")
        return str(lid).lower() if lid else None
    if not _HEX64.fullmatch(r):
        return None
    rl = r.lower()
    for nft in rpc.get_nfts(offset=0, limit=1000):
        if not isinstance(nft, dict):
            continue
        lid = str(nft.get("launcher_id") or "").lower()
        cid = str(nft.get("coin_id") or "").lower()
        if rl in (lid, cid) and lid:
            return lid
    return None


def _summary_legs(summary: dict, side: str) -> list:
    """Convert a Sage OfferSummary's maker/taker legs to [(asset, amount)].

    Sage's summary uses {"asset": {"asset_id": <hex>|null,
    "kind": "token"|"nft"|...}, "amount": ...}; asset_id null means XCH.
    NFT legs come back as "nft:<launcher-id>". DID/option legs raise —
    offers only carry fungible and NFT legs.
    """
    legs = summary.get(side)
    if not isinstance(legs, list):
        raise chia.SageError(f"offer summary has no {side!r} legs: "
                             f"{str(summary)[:200]}")
    out = []
    for leg in legs:
        a = (leg or {}).get("asset") or {}
        kind = (a.get("kind") or "token")
        asset_id = a.get("asset_id")
        if kind == "nft":
            if not asset_id or not _HEX64.fullmatch(str(asset_id)):
                raise chia.SageError(
                    f"bad NFT offer leg asset id {asset_id!r}")
            asset = f"nft:{str(asset_id).lower()}"
        elif kind == "token":
            asset = "native" if not asset_id else str(asset_id).lower()
            if asset != "native" and not _HEX64.fullmatch(asset):
                raise chia.SageError(f"bad offer leg asset id {asset_id!r}")
        else:
            raise chia.SageError(
                f"offer leg kind {kind!r} not supported")
        try:
            amount = chia.amount_to_int(leg.get("amount"))
        except chia.SageError as e:
            raise chia.SageError(f"bad offer leg amount: {e}") from e
        if amount <= 0:
            raise chia.SageError("offer leg amount must be positive")
        out.append((asset, amount))
    return out


def _redacted(req: dict) -> str:
    """Ledger-safe request summary: the bearer token is never written to disk."""
    return json.dumps({"route": req.get("route"), "muse_id": req.get("muse_id"),
                       "params_keys": sorted((req.get("params") or {}).keys())})


def _atomic_write_json(path: str, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.rename(tmp, path)


class Daemon:
    def __init__(self, config_dir):
        self.config_dir = config_dir
        self.cfg = load_config(config_dir)
        self.policy = load_policy(config_dir)
        self.request_token = token_auth.load_token(os.path.join(config_dir, "request.token"))
        self.approve_token = token_auth.load_token(os.path.join(config_dir, "approve.token"))
        self.ledger = Ledger(os.path.join(config_dir, "ledger.jsonl"))
        self.queue_path = os.path.join(config_dir, "queue.json")
        self.velocity_path = os.path.join(config_dir, "velocity.jsonl")
        # Mint/issuance gate (six-gate rule): mint_gate.json is written by
        # the human's own tooling, never by the agent and never by any
        # daemon route. It must name the exact canonical digests of the
        # queued intents it authorizes (one-shot: each digest is consumed
        # on first use), bind the network, carry an expiry, and attest all
        # six launch requirements. Read fresh at every execution.
        self.mint_gate_path = os.path.join(config_dir, "mint_gate.json")
        # One-shot consumption record: digests the gate has already
        # authorized. Written by the daemon (mode 600, atomic) — the only
        # daemon-side write in the gate protocol. A digest listed here can
        # never authorize another execution, even if mint_gate.json still
        # names it.
        self.mint_gate_consumed_path = os.path.join(
            config_dir, "mint_gate_consumed.json")
        self._load_queue()
        self._load_velocity()
        # The seed is loaded only to derive addresses/signing keys in-process.
        # It is never logged, never returned by any route, never leaves this
        # process. Real seeds enter only after the §10 phase-1 authorization.
        seed_path = self.cfg.get("seed_path")
        self.seed = load_seed(seed_path) if seed_path else None
        # Standard-recovery wallet (SPEC §2b): the 64-byte BIP-39 seed whose
        # keys derive the way stock wallets do (Sage / MetaMask). Required
        # exactly when key_derivation == "standard" — the daemon refuses to
        # start in standard mode without it, so a spend can never silently
        # fall back to KDF keys.
        self.key_derivation = self.cfg.get("key_derivation", "kdf")
        if self.key_derivation not in ("kdf", "standard"):
            raise ValueError("key_derivation must be 'kdf' or 'standard'")
        self.std_seed = None
        if self.key_derivation == "standard":
            std_seed_path = self.cfg.get("std_seed_path")
            if not std_seed_path:
                raise ValueError(
                    "key_derivation=standard requires std_seed_path")
            from spellbook.seed import load_std_seed
            self.std_seed = load_std_seed(std_seed_path)
        if self.seed and self.cfg.get("musebook_signing_mode") == "daemon":
            from nacl.signing import SigningKey
            self._identity_key = SigningKey(self.seed)
        else:
            self._identity_key = None
        # EVM chain wiring (SPEC §10): {"chains": {chain: {"rpc_url": str,
        # "enabled": bool}}, "mainnet_submit_enabled": bool}. No chains
        # configured -> approved spends do not submit (honest note, no-op).
        self.evm_cfg = self.cfg.get("evm", {})
        # Chia wiring (SPEC §10 phase 1): {"sage_data_dir": str, "rpc_port": int,
        # "fee_mojos": int, "mainnet_submit_enabled": bool}. The daemon is the
        # sole talker to Sage RPC; `sage rpc start` must be running against
        # the same data dir (the installer/drill starts it).
        self.chia_cfg = self.cfg.get("chia", {})
        # Solana wiring (SPEC §10 Solana): {"network": "devnet" |
        # "mainnet-beta" (default "devnet"), "rpc_url": str (optional —
        # defaults to the network's public endpoint),
        # "mainnet_submit_enabled": bool (default false)}. Direct HTTPS
        # JSON-RPC to a public node — no relay to deploy; the endpoint sees
        # public addresses, balances, and already-signed transactions only.
        self.solana_cfg = self.cfg.get("solana", {})
        # DEX venue recommendations (SPEC §10 v2): the user's recommended
        # swap venues. spellbook.json may carry {"dex":
        # {"recommended_venues": ["matcha", "uniswap"]}} — default is
        # both. This list is ADVISORY, not a gate: a dex_swap naming
        # another venue is queued with a prominent warning, and the
        # human's per-transaction approval is what authorizes the venue.
        # Unknown names still fail the daemon at startup (fail closed on
        # typos, not on policy).
        dex_cfg = self.cfg.get("dex", {})
        if not isinstance(dex_cfg, dict):
            raise ValueError("dex must be an object")
        raw_venues = dex_cfg.get("recommended_venues",
                                 list(dex_mod.DEFAULT_RECOMMENDED_VENUES))
        if (not isinstance(raw_venues, list) or not raw_venues
                or any(not isinstance(v, str) for v in raw_venues)):
            raise ValueError(
                "dex.recommended_venues must be a non-empty list of venue "
                "names")
        try:
            self.dex_recommended_venues = [dex_mod.normalize_venue(v)
                                           for v in raw_venues]
        except dex_mod.DexError as e:
            raise ValueError(f"bad dex.recommended_venues: {e}")
        self._dex_recommended_set = frozenset(self.dex_recommended_venues)
        # The Sage RPC child process, if we started one. The daemon owns the
        # whole Chia execution path (O10): it spawns `sage rpc start` against
        # the configured data home and talks to it over local mTLS. If Sage
        # is down, Chia spends fail closed in _execute_chia_spend.
        self._sage_proc = None

    # ------------------------------------------------------------ state
    def _load_queue(self):
        if os.path.exists(self.queue_path):
            with open(self.queue_path) as f:
                data = json.load(f)
            self.queue = data.get("items", {})
            self.next_qid = data.get("next_qid", 1)
        else:
            self.queue = {}
            self.next_qid = 1

    def _save_queue(self):
        _atomic_write_json(self.queue_path,
                           {"next_qid": self.next_qid, "items": self.queue})

    def _load_velocity(self):
        """Rebuild the 24h spend window from the sidecar (SPEC §10 step 11).

        The decision ledger itself carries only digests (P6), so executed/
        approved amounts live in this daemon-local sidecar — never in the API.
        """
        self.velocity = []  # [(ts, chain, asset, amount)]
        if os.path.exists(self.velocity_path):
            with open(self.velocity_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        r = json.loads(line)
                        self.velocity.append((r["ts"], r["chain"], r["asset"], r["amount"]))
        self._prune_velocity()

    def _prune_velocity(self):
        cutoff = time.time() - VELOCITY_WINDOW_S
        kept = [row for row in self.velocity if row[0] >= cutoff]
        if len(kept) != len(self.velocity):
            self.velocity = kept
            with open(self.velocity_path, "w") as f:
                for ts, chain, asset, amount in kept:
                    f.write(json.dumps({"ts": ts, "chain": chain, "asset": asset,
                                        "amount": amount}, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())

    def _record_velocity(self, chain: str, asset: str, amount: int):
        self.velocity.append((time.time(), chain, asset, amount))
        with open(self.velocity_path, "a") as f:
            f.write(json.dumps({"ts": time.time(), "chain": chain, "asset": asset,
                                "amount": amount}, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def spent_last_24h(self, chain: str, asset: str) -> int:
        cutoff = time.time() - VELOCITY_WINDOW_S
        return sum(a for ts, c, at, a in self.velocity
                   if c == chain and at == asset and ts >= cutoff)

    # ------------------------------------------------------------ auth
    def _auth(self, presented_hex: str):
        try:
            presented = bytes.fromhex(presented_hex)
        except ValueError:
            return None
        if token_auth.check(presented, self.request_token):
            return "request"
        if token_auth.check(presented, self.approve_token):
            return "approve"
        return None

    # ------------------------------------------------------------ routes
    def handle(self, req: dict, peer_uid: int) -> dict:
        role = self._auth(req.get("token", ""))
        if role is None:
            return {"ok": False, "error": "bad token"}
        # Peer-UID enforcement (S2): when the config names the UIDs allowed
        # per role, the kernel's credential is ENFORCED — a stolen token from
        # the wrong OS user is denied and the attempt is ledgered.
        allowed_key = ("allowed_request_uids" if role == "request"
                       else "allowed_approve_uids")
        allowed = self.cfg.get(allowed_key)
        if allowed is not None and peer_uid not in allowed:
            self.ledger.append(req.get("muse_id", "?"),
                               _redacted(req).encode(),
                               None, "denied:uid-not-allowed")
            return {"ok": False, "error": "peer UID not allowed for this role"}
        route = req.get("route")
        params = req.get("params", {}) or {}

        if route in APPROVE_ROUTES and role != "approve":
            # S7: an approval the requester can grant is not an approval.
            self.ledger.append(req.get("muse_id", "?"), _redacted(req).encode(),
                               None, "denied:privilege-escalation-attempt")
            return {"ok": False, "error": "approve token required"}
        if route not in REQUEST_ROUTES and route not in APPROVE_ROUTES:
            return {"ok": False, "error": f"unknown route {route!r}"}

        handler = getattr(self, "rt_" + route, None)
        if handler is None:
            return {"ok": False, "error": "not implemented"}
        try:
            return handler(params, req.get("muse_id", "?"))
        except (evm.EvmError, chia.SageError, chia_relay.RelayError,
                solana_mod.SolanaError, dex_mod.DexError) as e:
            # A request handler must never let a validation/broadcast
            # error escape as a dropped connection: return a structured
            # failure instead (e.g. an invalid fee_mojos raised from
            # _fee_of outside a handler-local try/except).
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------ chain execution
    def _signing_seed(self):
        """The seed that actually signs under the configured derivation.

        Standard mode signs with the BIP-39 seed only; KDF mode signs with
        the daemon seed only. A spend can never draw keys from the other
        wallet set, and a missing active seed fails closed even when the
        other set is present.
        """
        return self.std_seed if self.key_derivation == "standard" else self.seed

    def _evm_key(self, chain):
        """(priv_bytes, address) for an EVM chain under the configured derivation.

        KDF mode: the labeled secp256k1 scalar (existing behavior).
        Standard mode: BIP-32 m/44'/60'/0'/0/0 of the BIP-39 seed — the key
        MetaMask derives from the same mnemonic.
        """
        if self.key_derivation == "standard":
            from spellbook import stdkeys
            priv = stdkeys.evm_privkey(self.std_seed)
            return priv, stdkeys.evm_address(priv)
        d = kdf.derive_labeled(self.seed, chain, "default")
        return bytes.fromhex(d["scalar_hex"]), d["address"]

    def _chia_master_sk(self, chain):
        """32-byte Chia master secret for `chain` under the configured derivation.

        KDF mode: the per-chain labeled BLS scalar (existing behavior).
        Standard mode: the BLS key_gen master key of the BIP-39 seed — the
        same key Sage derives from the same mnemonic (one key; only the
        bech32m HRP differs between testnet11 and mainnet).
        """
        if self.key_derivation == "standard":
            from spellbook import stdkeys
            return stdkeys.chia_master_sk(self.std_seed)
        d = kdf.derive_labeled(self.seed, chain, "default")
        return bytes.fromhex(d["scalar_hex"])

    def _solana_keypair(self, chain):
        """solders Keypair for a Solana chain under the configured derivation.

        KDF mode: the custom labeled seed (32 bytes from the daemon seed via
        solana.custom_seed — same domain-separation family as §2, no
        modular reduction since ed25519 seeds are arbitrary bytes).
        Standard mode: SLIP-0010 m/44'/501'/0'/0' of the BIP-39 seed — the
        key Phantom/Solflare derives from the same mnemonic.
        Spends use the active signing seed only: in standard mode the 64-byte
        BIP-39 seed, in KDF mode the 32-byte daemon seed — never the other
        wallet set, and a missing active seed fails closed even when the
        other set is present (via _signing_seed).
        """
        seed = self._signing_seed()
        if seed is None:
            raise solana_mod.SolanaError("no seed configured — cannot sign")
        if self.key_derivation == "standard":
            return solana_mod.standard_keypair(seed)
        return solana_mod.custom_keypair(seed, chain, "default")

    def _active_solana_chain(self) -> str:
        """The chain id the configured Solana network maps to.

        solana.network defaults to "devnet"; "mainnet-beta" is the only
        other accepted value. Anything else is a config error and fails
        closed here rather than pointing at an unintended network.
        """
        net = self.solana_cfg.get("network", "devnet")
        if net == "devnet":
            return "solana-devnet"
        if net == "mainnet-beta":
            return "solana-mainnet"
        raise solana_mod.SolanaError(
            f"bad solana.network {net!r} — expected 'devnet' or 'mainnet-beta'")

    def _execute_solana_spend(self, params: dict) -> dict:
        """Build, sign, and broadcast an approved native SOL transfer (§10 Solana).

        Flow: network-mismatch check against the configured active network
        (fail closed), mainnet gate (§10.14-17), active-seed key derivation,
        genesis-hash check on the RPC (a mispointed RPC cannot redirect
        funds), fresh blockhash, local sign with pre-broadcast
        self-verification, sendTransaction, and confirmation tracking.

        Returns {"submitted": True, "tx_hash": <signature>, "slot": ...}.
        Raises solana_mod.SolanaError on any failure — a spend that never
        left the machine records nothing and consumes no velocity; a
        confirmation timeout raises BroadcastUnknown (fate unknown — the
        human reconciles the signature on-chain before any re-request).
        Spends use the "default" label's key (v1).
        """
        chain = params["chain"]
        if chain not in solana_mod.NETWORKS:
            raise solana_mod.SolanaError(f"unknown Solana chain {chain!r}")
        active = self._active_solana_chain()
        if chain != active:
            raise solana_mod.SolanaError(
                f"network mismatch: daemon is configured for {active}, "
                f"spend requested {chain} — refusing")
        info = solana_mod.NETWORKS[chain]
        if not info["testnet"] and not self.solana_cfg.get("mainnet_submit_enabled"):
            raise solana_mod.SolanaError(
                "mainnet submission refused for solana-mainnet — needs the "
                "separately-authorized mainnet_submit_enabled flag (§10.14-17)")
        if params.get("amount_wei") is not None or params.get("amount_mojos") is not None:
            raise solana_mod.SolanaError(
                "wei/mojos on a Solana chain — schema misuse, refusing")
        dest = params.get("destination", "")
        amount = params["amount_lamports"]
        kp = self._solana_keypair(chain)
        rpc = solana_mod.SolanaRpc(
            chain, url=self.solana_cfg.get("rpc_url") or info["url"])
        built = solana_mod.sign_transfer(kp, dest, amount, rpc)
        # The approved intent, re-checked against the built tx's decoded
        # fields. Explicit checks, not assert: fail-closed under -O too.
        if (built["from"] != solana_mod.address_of_keypair(kp)
                or built["to"] != dest
                or built["lamports"] != amount):
            raise solana_mod.SolanaError(
                "signed tx intent mismatch — approved intent violated, "
                "refusing to broadcast")
        sig = rpc.send_transaction(built["raw_b64"])
        st = rpc.wait_signature(sig)
        return {"submitted": True, "tx_hash": sig,
                "slot": st.get("slot"), "from": built["from"]}

    def _execute_spend(self, params: dict) -> dict:
        """Build, sign, and broadcast an approved transfer (SPEC §10).

        Returns {"submitted": True, "tx_hash": ..., "block": ...} on success,
        {"submitted": False, "note": ...} when no chain is configured, and
        raises evm.EvmError on any failure — a spend that never left the
        machine records nothing and consumes no velocity. Spends use the
        "default" label's key (v1).
        """
        chain = params["chain"]
        # Single dispatch point for off-chain message signing (SPEC §10):
        # Chia signs via Sage RPC; EVM and Solana sign locally with the
        # daemon's own keys. message_sign never reaches a spend path.
        if params.get("intent") == "message_sign":
            return self._execute_message_sign(params)
        if chain in chia.NETWORKS:
            return self._execute_chia_spend(params)
        if chain in solana_mod.NETWORKS:
            return self._execute_solana_spend(params)
        if chain not in evm.CHAINS:
            return {"submitted": False,
                    "note": f"chain submission not configured for {chain}"}
        # DEX intents (SPEC §10 v2): bounded swap / LP-add. The queue held
        # bounds; execution fetches the firm quote now and refuses to sign
        # unless it fits inside the approved bounds.
        intent = params.get("intent")
        if intent == "dex_swap":
            return self._execute_evm_swap(params)
        if intent == "dex_lp_add":
            return self._execute_evm_lp_add(params)
        entry = (self.evm_cfg.get("chains") or {}).get(chain) or {}
        if not entry.get("enabled") or not entry.get("rpc_url"):
            return {"submitted": False,
                    "note": f"chain submission not configured for {chain}"}
        info = evm.CHAINS[chain]
        if not info["testnet"] and not self.evm_cfg.get("mainnet_submit_enabled"):
            raise evm.EvmError(
                f"mainnet submission refused for {chain} — needs the "
                "separately-authorized mainnet_submit_enabled flag (§10.14-17)")
        if self._signing_seed() is None:
            raise evm.EvmError("no seed configured — cannot sign")
        if params.get("amount_mojos") is not None or params.get("amount_lamports") is not None:
            raise evm.EvmError("mojos/lamports on an EVM chain — schema misuse, refusing")
        dest = params.get("destination", "")
        if not evm.is_address(dest):
            raise evm.EvmError(f"bad destination address: {dest!r}")
        amount = params["amount_wei"]
        priv, sender = self._evm_key(chain)
        rpc = evm.Rpc(entry["rpc_url"])
        if rpc.chain_id() != info["chain_id"]:
            raise evm.EvmError(
                f"RPC reports a different chain id than {chain} — aborting")
        # Gas limit comes from the node, never hardcoded: on Robinhood Chain
        # (Arbitrum-style) the intrinsic cost of a transfer exceeds 21000,
        # so a hardcoded limit dies with "intrinsic gas too low". estimate
        # fails closed — no guess is ever broadcast.
        gas_limit = max(rpc.estimate_gas(sender, dest, amount),
                        evm.TRANSFER_GAS_LIMIT)
        signed = evm.sign_legacy_transfer(priv, info["chain_id"],
                                          rpc.nonce(sender), dest, amount,
                                          _evm_gas_price(rpc), gas_limit)
        # The approved intent, re-checked against the signed tx's fields.
        # Explicit checks, not assert: this module must stay fail-closed
        # even under `python -O` (which strips assert statements).
        for name, got, want in (
                ("from", signed["from"].lower(), sender.lower()),
                ("to", signed["to"].lower(), dest.lower()),
                ("value_wei", signed["value_wei"], amount),
                ("chain_id", signed["chain_id"], info["chain_id"])):
            if got != want:
                raise evm.EvmError(
                    f"signed tx {name} mismatch ({got!r} != {want!r}) — "
                    "approved intent violated, refusing to broadcast")
        tx_hash = rpc.send_raw_tx(signed["raw_hex"])
        rcpt = rpc.wait_receipt(tx_hash)
        if int(rcpt.get("status", "0x0"), 16) != 1:
            raise evm.EvmError(f"tx {tx_hash} reverted on-chain")
        return {"submitted": True, "tx_hash": tx_hash,
                "block": int(rcpt.get("blockNumber", "0x0"), 16), "from": sender}

    # ------------------------------------------------------------ DEX execution
    def _evm_dex_guards(self, params: dict):
        """Chain-config gates shared by swap and LP execution. Returns
        (info, rpc, priv, sender). Raises evm.EvmError fail-closed."""
        chain = params["chain"]
        entry = (self.evm_cfg.get("chains") or {}).get(chain) or {}
        if not entry.get("enabled") or not entry.get("rpc_url"):
            raise evm.EvmError(f"chain submission not configured for {chain}")
        info = evm.CHAINS[chain]
        if not info["testnet"] and not self.evm_cfg.get("mainnet_submit_enabled"):
            raise evm.EvmError(
                f"mainnet submission refused for {chain} — needs the "
                "separately-authorized mainnet_submit_enabled flag (§10.14-17)")
        if self._signing_seed() is None:
            raise evm.EvmError("no seed configured — cannot sign")
        rpc = evm.Rpc(entry["rpc_url"])
        if rpc.chain_id() != info["chain_id"]:
            raise evm.EvmError(
                f"RPC reports a different chain id than {chain} — aborting")
        priv, sender = self._evm_key(chain)
        return info, rpc, priv, sender

    def _evm_send_call(self, rpc, priv: bytes, chain_id: int, sender: str,
                       nonce: int, to: str, value_wei: int, data_hex: str,
                       gas_price_wei: int, what: str) -> tuple:
        """Estimate, sign, verify, broadcast one contract call; wait for the
        receipt and require success. Returns (tx_hash, next_nonce).

        The signed tx's fields are re-checked against the plan (explicit
        checks, not assert — fail-closed under python -O). A revert or a
        missing receipt raises; a broadcast with no receipt in time raises
        BroadcastUnknown (never a plain failure — no blind retries).
        """
        gas_limit = rpc.estimate_gas_call(sender, to, value_wei, data_hex)
        signed = evm.sign_legacy_call(priv, chain_id, nonce, to, value_wei,
                                      data_hex, gas_price_wei, gas_limit)
        for name, got, want in (
                ("from", signed["from"].lower(), sender.lower()),
                ("to", signed["to"].lower(), to.lower()),
                ("data", signed["data"].lower(), data_hex.lower()),
                ("value_wei", signed["value_wei"], value_wei),
                ("chain_id", signed["chain_id"], chain_id)):
            if got != want:
                raise evm.EvmError(
                    f"{what}: signed tx {name} mismatch — approved intent "
                    "violated, refusing to broadcast")
        tx_hash = rpc.send_raw_tx(signed["raw_hex"])
        rcpt = rpc.wait_receipt(tx_hash)
        if int(rcpt.get("status", "0x0"), 16) != 1:
            raise evm.EvmError(f"{what} tx {tx_hash} reverted on-chain")
        return tx_hash, nonce + 1, int(rcpt.get("blockNumber", "0x0"), 16)

    def _evm_ensure_allowance(self, rpc, priv: bytes, chain_id: int,
                              sender: str, nonce: int, token: str,
                              spender: str, amount_wei: int,
                              gas_price_wei: int) -> tuple:
        """Exact-amount ERC-20 approval if on-chain allowance is short.

        Approves the EXACT amount the trade needs — never unlimited.
        Returns (approve_tx_hash | None, next_nonce).
        """
        raw = rpc.eth_call(token,
                           dex_mod.build_allowance_calldata(sender, spender),
                           sender)
        if dex_mod.decode_allowance(raw) >= amount_wei:
            return None, nonce
        data = dex_mod.build_approve_calldata(spender, amount_wei)
        tx_hash, next_nonce, _block = self._evm_send_call(
            rpc, priv, chain_id, sender, nonce, token, 0, data,
            gas_price_wei, "approve")
        return tx_hash, next_nonce

    def _execute_evm_swap(self, params: dict) -> dict:
        """Execute an approved dex_swap intent.

        One approval = one execution attempt: the approve (exact amount,
        only if allowance is short) and the swap are the single execution
        of this intent. The firm quote is fetched NOW and validated
        against the approved bounds before anything is signed.
        """
        import os
        info, rpc, priv, sender = self._evm_dex_guards(params)
        dl = params.get("deadline_sec")
        if dl is not None and time.time() > dl:
            raise evm.EvmError("swap intent expired — refusing")
        # Venue checks at execution time. The recommended-venue list is
        # advisory (the human's approval already authorized this swap),
        # so only hard facts are re-checked here: the venue name must be
        # known and it must serve the chain. A venue that cannot route
        # the chain is refused — executing would be a guaranteed failure.
        try:
            venue = dex_mod.normalize_venue(params["venue"])
        except dex_mod.DexError as e:
            raise evm.EvmError(f"schema violation: {e}")
        if not dex_mod.venue_serves_chain(venue, info["chain_id"]):
            raise evm.EvmError(
                f"venue {venue!r} does not serve chain id "
                f"{info['chain_id']} — refusing")
        env_key = dex_mod.VENUE_ENV_KEYS[venue]
        api_key = os.environ.get(env_key)
        if not api_key:
            raise evm.EvmError(
                f"{env_key} not in the daemon environment — cannot fetch "
                "a firm quote, refusing")
        sell, buy = params["sell_token"], params["buy_token"]
        amount = params["sell_amount_wei"]
        # Firm quote, fetched at execution time (quotes live ~30s).
        if venue == dex_mod.VENUE_MATCHA:
            quote = dex_mod.ZeroExClient(api_key).quote(
                info["chain_id"], sell, buy, amount, sender,
                slippage_bps=params["max_slippage_bps"])
        else:
            uni = dex_mod.UniswapClient(api_key)
            zero = "0x0000000000000000000000000000000000000000"
            sell_q = zero if sell == dex_mod.NATIVE_SENTINEL else sell
            buy_q = zero if buy == dex_mod.NATIVE_SENTINEL else buy
            q = uni.quote(info["chain_id"], sell_q, buy_q, amount, sender,
                          slippage_pct=params["max_slippage_bps"] / 100)
            quote = uni.swap(q["raw"], info["chain_id"], sell_q, buy_q,
                             amount, sender,
                             slippage_pct=params["max_slippage_bps"] / 100)
            # Normalize back to the intent's token representation for the
            # bounds check below.
            quote["sell_token"], quote["buy_token"] = sell, buy
        plan = dex_mod.validate_swap_intent_against_quote(
            {"chain_id": info["chain_id"], "sell_token": sell,
             "buy_token": buy, "sell_amount_wei": amount,
             "min_buy_amount_wei": params["min_buy_amount_wei"],
             "max_slippage_bps": params["max_slippage_bps"]},
            quote)
        nonce = rpc.nonce(sender)
        gas_price = _evm_gas_price(rpc)
        approve_tx = None
        if plan["needs_approval"]:
            approve_tx, nonce = self._evm_ensure_allowance(
                rpc, priv, info["chain_id"], sender, nonce, sell,
                plan["allowance_target"], amount, gas_price)
        tx_hash, _, block = self._evm_send_call(
            rpc, priv, info["chain_id"], sender, nonce,
            plan["to"], plan["value_wei"], plan["data"], gas_price, "swap")
        out = {"submitted": True, "tx_hash": tx_hash, "block": block,
               "from": sender, "buy_amount_wei": plan["buy_amount_wei"]}
        if approve_tx:
            out["approve_tx_hash"] = approve_tx
        return out

    def _execute_evm_lp_add(self, params: dict) -> dict:
        """Execute an approved dex_lp_add intent.

        Calldata is built locally from the approved bounds via the
        whitelisted dex builders — the daemon never signs opaque
        caller-supplied calldata. Both tokens get exact-amount approvals
        (only where allowance is short), then the LP call.
        """
        info, rpc, priv, sender = self._evm_dex_guards(params)
        dl = params.get("deadline_sec")
        if dl is not None and time.time() > dl:
            raise evm.EvmError("LP intent expired — refusing")
        call_deadline = dl or int(time.time()) + 600
        if call_deadline <= time.time() + 60:
            raise evm.EvmError(
                "LP deadline too close — calldata would revert on-chain")
        protocol = params["protocol"]
        tok_a, tok_b = params["token_a"], params["token_b"]
        amt_a, amt_b = params["amount_a_wei"], params["amount_b_wei"]
        if protocol == "v2":
            data = dex_mod.build_v2_add_liquidity_calldata(
                tok_a, tok_b, amt_a, amt_b,
                params["amount_a_min_wei"], params["amount_b_min_wei"],
                sender, call_deadline)
        else:
            t0, t1 = (tok_a, tok_b) if tok_a.lower() < tok_b.lower() \
                else (tok_b, tok_a)
            a0, a1 = (amt_a, amt_b) if tok_a.lower() < tok_b.lower() \
                else (amt_b, amt_a)
            m0, m1 = (params["amount_a_min_wei"], params["amount_b_min_wei"]) \
                if tok_a.lower() < tok_b.lower() \
                else (params["amount_b_min_wei"], params["amount_a_min_wei"])
            data = dex_mod.build_v3_mint_calldata(
                t0, t1, params["fee"], params["tick_lower"],
                params["tick_upper"], a0, a1, m0, m1, sender, call_deadline)
        nonce = rpc.nonce(sender)
        gas_price = _evm_gas_price(rpc)
        approve_txs = []
        for tok, amt in ((tok_a, amt_a), (tok_b, amt_b)):
            ah, nonce = self._evm_ensure_allowance(
                rpc, priv, info["chain_id"], sender, nonce, tok,
                params["router"], amt, gas_price)
            if ah:
                approve_txs.append(ah)
        tx_hash, _, block = self._evm_send_call(
            rpc, priv, info["chain_id"], sender, nonce,
            params["router"], 0, data, gas_price, "lp_add")
        out = {"submitted": True, "tx_hash": tx_hash, "block": block,
               "from": sender}
        if approve_txs:
            out["approve_tx_hashes"] = approve_txs
        return out

    def _sage_rpc_ready(self) -> bool:
        """True if something answers on the Sage RPC port (TCP only)."""
        port = int(self.chia_cfg.get("rpc_port", 9257))
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.close()
            return True
        except OSError:
            return False

    def _ensure_sage_rpc(self) -> None:
        """Start `sage rpc start` if nothing answers on the RPC port.

        Idempotent and crash-tolerant: if the port already answers (e.g. an
        orphaned Sage from a previous daemon run using the same data dir),
        we just use it — the mTLS certs on disk decide trust, not the pid.
        Raises chia.SageError if Sage cannot be brought up.
        """
        if not self.cfg.get("chia_enabled", True):
            raise chia.SageError("chia is not enabled in this install")
        if self._sage_rpc_ready():
            return
        if self._sage_proc is not None and self._sage_proc.poll() is None:
            # We started one and it's still alive but not answering yet —
            # give it a moment rather than spawning a second.
            pass
        else:
            sage_bin = self.chia_cfg.get("sage_bin")
            data_home = self.chia_cfg.get("sage_data_home")
            if not sage_bin or not os.access(sage_bin, os.X_OK):
                raise chia.SageError(
                    "no usable sage_bin configured — cannot start Sage RPC")
            if not data_home:
                raise chia.SageError(
                    "no chia.sage_data_home configured — cannot start Sage RPC")
            os.makedirs(data_home, mode=0o700, exist_ok=True)
            env = dict(os.environ)
            env["XDG_DATA_HOME"] = data_home  # sage-cli: data_dir()/com.rigidnetwork.sage
            log_path = os.path.join(self.config_dir, "sage-rpc.log")
            try:
                logf = open(log_path, "a")
                self._sage_proc = subprocess.Popen(
                    [sage_bin, "rpc", "start"], env=env,
                    stdout=logf, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=True)
            except Exception as e:
                raise chia.SageError(f"could not start sage rpc: {e}") from e
        deadline = time.time() + 45
        while time.time() < deadline:
            if self._sage_rpc_ready():
                return
            if self._sage_proc is not None and self._sage_proc.poll() is not None:
                raise chia.SageError(
                    f"sage rpc exited with code {self._sage_proc.returncode} "
                    "— see sage-rpc.log")
            time.sleep(1)
        raise chia.SageError(
            "sage rpc did not answer on its port within 45s — see sage-rpc.log")

    def _chia_wallet(self, rpc, chain):
        """Select the daemon-owned wallet for `chain` on Sage.

        Switches Sage to the chain's network, imports the daemon's BLS
        master key when missing (verifying the fingerprint locally — never
        trusting the RPC's word for which key it imported), and logs in.
        Returns (fingerprint, address).

        In standard mode the imported key is the BLS key_gen master key, so
        Sage operates the exact wallet the mnemonic opens in stock Sage —
        the daemon and Sage agree on every address.

        Every balance read goes through here. Sage's /get_sync_status
        reports whichever wallet was logged in last, so a foreign wallet
        left selected by earlier tooling (e.g. a drill script that logged
        into the destination wallet to derive its address) would otherwise
        make status report someone else's balance as the agent's. O10
        requires the agent to surface its own balance/address, so status
        selects — and if needed imports — the daemon's own wallet first.
        """
        network = chia.NETWORKS[chain]
        rpc.set_network(network)
        master_sk = self._chia_master_sk(chain)
        from spellbook import chia_sign
        expected_fp = chia.chia_fingerprint(chia_sign.pk_bytes(master_sk).hex())
        have = set()
        for k in rpc.get_keys():
            try:
                have.add(int(k.get("fingerprint")))
            except (TypeError, ValueError):
                continue
        if expected_fp not in have:
            got = rpc.import_key("spellbook-default", master_sk.hex())
            if got != expected_fp:
                raise chia.SageError(
                    f"imported fingerprint {got} != derived {expected_fp} "
                    "— refusing to use an unexpected key")
        rpc.login(expected_fp)
        return expected_fp, rpc.wallet_address(expected_fp, network)

    # The six standing requirements for any token launch, mint, or
    # issuance. mint_gate.json must attest ALL of them, name the EXACT
    # canonical digests of the queued intents it authorizes, bind the
    # network, and carry an expiry. The human writes that file with their
    # own tooling — the agent has no route that writes it, so queue
    # approval alone can never open it.
    #
    # Gate schema (strict — unknown keys are refused):
    #   {
    #     "attestations": {
    #       "receive_95_percent_supply": true,
    #       "majority_holder": true,
    #       "hold_at_least_1_percent": true,
    #       "articles_of_description": true,
    #       "metadata_set": true,
    #       "website_exists": true
    #     },
    #     "granted_by": "<human identifier>",
    #     "digests": ["<64-hex sha256 of the canonical queued params>"],
    #     "network": "testnet11",
    #     "expires_at": <epoch seconds>
    #   }
    # The digest is sha256(json.dumps(params, sort_keys=True)) over the
    # exact stored queue params — the same bytes the ledger's canon_digest
    # covers. The human reads it from the decoded queue listing
    # ("canon_digest") before writing the gate file. Each digest is
    # one-shot: the first execution attempt consumes it, and a consumed
    # digest never authorizes again.
    _MINT_GATE_INTENTS = {"cat_issue", "nft_mint", "option_mint"}
    _MINT_GATE_ATTESTATIONS = (
        "receive_95_percent_supply",
        "majority_holder",
        "hold_at_least_1_percent",
        "articles_of_description",
        "metadata_set",
        "website_exists",
    )
    _MINT_GATE_TOP_KEYS = frozenset(
        {"attestations", "granted_by", "digests", "network", "expires_at"})

    @staticmethod
    def _mint_intent_digest(params: dict) -> str:
        """Canonical digest of the exact queued params the gate authorizes."""
        return hashlib.sha256(
            json.dumps(params, sort_keys=True).encode()).hexdigest()

    def _mint_consumed_digests(self) -> set:
        """Digests already consumed by the one-shot gate. Fail closed: an
        unreadable consumption record refuses every mint."""
        try:
            with open(self.mint_gate_consumed_path) as f:
                data = json.load(f)
        except OSError:
            return set()
        except ValueError:
            raise chia.SageError(
                "consumed-digest store is corrupt — refusing every mint "
                "until the human repairs or removes "
                "mint_gate_consumed.json")
        if not isinstance(data, dict) or not isinstance(
                data.get("digests"), list):
            raise chia.SageError(
                "consumed-digest store has a bad shape — refusing every "
                "mint until the human repairs or removes "
                "mint_gate_consumed.json")
        return {d for d in data["digests"] if isinstance(d, str)}

    def _mint_consume_digest(self, digest: str) -> None:
        consumed = self._mint_consumed_digests()
        consumed.add(digest)
        _atomic_write_json(self.mint_gate_consumed_path,
                           {"digests": sorted(consumed)})

    def _check_mint_gate(self, params: dict) -> None:
        """Refuse mint/issuance execution unless the human's mint gate is
        open for the EXACT canonical digest of these params, on this
        network, before expiry, with all six attestations. Read fresh every
        time — no caching, no bypass.

        One-shot: a passing check consumes the digest BEFORE execution
        proceeds, so the grant authorizes exactly one execution attempt
        even if the daemon crashes mid-flight. A failed check consumes
        nothing and triggers no RPC attempt."""
        intent = params.get("intent")
        if intent not in self._MINT_GATE_INTENTS:
            raise chia.SageError(
                f"mint gate invoked for non-mint intent {intent!r} — "
                "refusing")
        canon = json.dumps(params, sort_keys=True).encode()
        digest = hashlib.sha256(canon).hexdigest()
        problems = []

        gate = None
        try:
            with open(self.mint_gate_path) as f:
                gate = json.load(f)
        except (OSError, ValueError):
            gate = None
        if not isinstance(gate, dict):
            problems.append("mint_gate.json is missing or not a JSON object")
        else:
            unknown = set(gate) - self._MINT_GATE_TOP_KEYS
            if unknown:
                problems.append(
                    "unknown top-level keys: " + ", ".join(sorted(unknown)))
            atts = gate.get("attestations")
            if not isinstance(atts, dict):
                problems.append("attestations is not an object")
            else:
                unknown_atts = set(atts) - set(self._MINT_GATE_ATTESTATIONS)
                if unknown_atts:
                    problems.append("unknown attestations: " +
                                    ", ".join(sorted(unknown_atts)))
                missing = [a for a in self._MINT_GATE_ATTESTATIONS
                           if atts.get(a) is not True]
                if missing:
                    problems.append("missing attestations: " +
                                    ", ".join(missing))
            granted_by = gate.get("granted_by")
            if not isinstance(granted_by, str) or not granted_by.strip():
                problems.append("granted_by is not set")
            digests = gate.get("digests")
            if (not isinstance(digests, list) or not digests or not all(
                    isinstance(d, str) and len(d) == 64 and
                    all(c in "0123456789abcdef" for c in d.lower())
                    for d in digests)):
                problems.append(
                    "digests must be a non-empty list of 64-hex digests")
            network = gate.get("network")
            if not isinstance(network, str) or not network:
                problems.append("network is not set")
            elif network not in set(chia.NETWORKS.values()):
                problems.append(f"unknown network {network!r}")
            expires_at = gate.get("expires_at")
            if (isinstance(expires_at, bool) or
                    not isinstance(expires_at, (int, float)) or
                    expires_at <= 0):
                problems.append("expires_at must be a positive epoch time")
            # Cross-checks against this execution (only meaningful when the
            # shape above parsed; each appends rather than short-circuits so
            # the refusal reason lists everything wrong at once).
            if not problems:
                try:
                    consumed = self._mint_consumed_digests()
                except chia.SageError as e:
                    problems.append(str(e))
                else:
                    if digest in consumed:
                        problems.append(
                            "this grant was already consumed (one-shot) — "
                            "the human must open a fresh gate for another "
                            "attempt")
                if digest not in [d.lower() for d in digests]:
                    problems.append(
                        f"digest {digest} is not authorized by the gate")
                want_network = chia.NETWORKS.get(params.get("chain"))
                if network != want_network:
                    problems.append(
                        f"gate is for network {network!r}, this execution "
                        f"is on {want_network!r}")
                if time.time() > expires_at:
                    problems.append("gate has expired")

        if problems:
            self.ledger.append("mint-gate", canon, None,
                               "mint-gate-refused:" + "; ".join(problems))
            raise chia.SageError(
                "mint/issuance gate is closed: " + "; ".join(problems) +
                ". The human opens it with their own tooling via "
                "mint_gate.json (six attestations + granted_by + exact "
                "intent digests + network + expires_at); queue approval "
                "alone never opens it.")
        # Open: consume the digest first (one-shot), then let execution
        # proceed. A crash between here and the RPC still burns the grant —
        # that is the point: one grant, one attempt, never a replay.
        self._mint_consume_digest(digest)
        self.ledger.append("mint-gate", canon, None,
                           f"mint-gate-open:{intent}:{digest}")

    def _execute_chia_spend(self, params: dict) -> dict:
        """Dispatch to the Sage or relay Chia spend path.

        The relay path is selected when EITHER the per-network
        `chia.relay_urls` map (new installs) or the legacy flat
        `chia.relay_url` (single-network installs) is set. Precedence
        inside the relay path: relay_urls[<network>] wins over the flat
        relay_url. Otherwise the Sage RPC path is used (default, unchanged).

        CAT and NFT assets always take the Sage path — the HTTPS relay is
        native-XCH only (it builds standard-puzzle spends via chia_sign).
        The asset was validated at request time; re-validating here is the
        execute-time second layer.

        Offer intents always take the Sage path — offer construction,
        taking, and cancellation are wallet-local Sage operations the
        relay deliberately does not expose.
        """
        intent = params.get("intent")
        if intent in self._MINT_GATE_INTENTS:
            # Six-gate rule: token launches, mints, and issuance execute
            # only when the human has separately opened the mint gate for
            # the exact canonical digest of these params. Queue approval
            # is not enough.
            self._check_mint_gate(params)
        if intent == "offer_make":
            if params.get("transport") == "native":
                return self._execute_offer_make_native(params)
            return self._execute_offer_make_via_sage(params)
        if intent == "offer_take":
            if params.get("transport") == "native":
                return self._execute_offer_take_native(params)
            return self._execute_offer_take_via_sage(params)
        if intent == "offer_cancel":
            if params.get("transport") == "native":
                return self._execute_offer_cancel_native(params)
            return self._execute_offer_cancel_via_sage(params)
        if intent == "nft_mint":
            return self._execute_nft_mint_via_sage(params)
        if intent == "nft_assign_did":
            return self._execute_nft_assign_did_via_sage(params)
        if intent == "did_create":
            return self._execute_did_create_via_sage(params)
        if intent == "did_transfer":
            return self._execute_did_transfer_via_sage(params)
        if intent == "did_normalize":
            return self._execute_did_normalize_via_sage(params)
        if intent == "option_mint":
            return self._execute_option_mint_via_sage(params)
        if intent == "option_transfer":
            return self._execute_option_transfer_via_sage(params)
        if intent == "option_exercise":
            return self._execute_option_exercise_via_sage(params)
        if intent == "cat_issue":
            return self._execute_cat_issue_via_sage(params)
        if intent == "clawback_finalize":
            return self._execute_clawback_finalize_via_sage(params)
        if intent == "coin_combine":
            return self._execute_coin_combine_via_sage(params)
        if intent == "coin_split":
            return self._execute_coin_split_via_sage(params)
        if intent == "coin_autocombine":
            return self._execute_coin_autocombine_via_sage(params)
        if intent == "bulk_send":
            return self._execute_bulk_send_via_sage(params)
        if intent == "multi_send":
            return self._execute_multi_send_via_sage(params)
        kind, _ = chia_asset_kind(params.get("asset", "native"))
        if kind != "native":
            return self._execute_chia_spend_via_sage(params)
        if self.chia_cfg.get("relay_urls") or self.chia_cfg.get("relay_url"):
            return self._execute_chia_spend_via_relay(params)
        return self._execute_chia_spend_via_sage(params)

    def _chia_relay_rpc(self, network: str):
        """Build the relay client for a Chia network (SPEC §10).

        Token sources for ``chia.relay_token`` (checked in order):
          - ``"env:VAR"`` — value from the process environment.
          - ``"connector:<id>"`` — fresh authd surrogate per request;
            the raw token never lives in this process (connectors.py).
          - literal token (>= 16 chars) — legacy.
        """
        relay_urls = self.chia_cfg.get("relay_urls", {})
        relay_url = relay_urls.get(network) or self.chia_cfg.get("relay_url")
        if not relay_url:
            raise chia_relay.RelayError(
                f"no relay configured for {network} — refusing")
        token = self.chia_cfg.get("relay_token") or os.environ.get(
            "SPELLBOOK_RELAY_TOKEN", "")
        if token.startswith("env:"):
            token = os.environ.get(token[4:], "")
        token_provider = None
        if token.startswith("connector:"):
            # Connector-backed credential (Secure Vault): the raw token is
            # never in this process — a fresh surrogate is resolved from
            # authd for every relay request and swapped for the real
            # credential by the egress layer.
            from . import connectors
            host = urllib.parse.urlparse(relay_url).hostname or ""
            token_provider = connectors.connector_token_provider(
                token[len("connector:"):], allowed_hosts=(host,))
            token = ""
        rpc = chia_relay.RelayRpc(relay_url, token,
                                  token_provider=token_provider)
        return rpc

    def _execute_chia_spend_via_relay(self, params: dict) -> dict:
        """Build, sign (locally), and broadcast an approved XCH transfer
        via the spellbook-chia-relay.

        Flow: derive the KDF wallet key locally, compute our puzzle hashes
        (indices 0..N), fetch coins from the relay, select coins covering
        amount+fee, build + sign the spend bundle with chia_sign.py (keys
        never leave this machine), broadcast via the relay, and return the
        created coin id as the ledger reference.

        Returns {"submitted": True, "tx_hash": <coin id>, ...}.
        Raises chia_relay.RelayError on any failure — a spend that never
        left the machine records nothing and consumes no velocity.
        """
        from spellbook import chia_relay, chia_sign
        kind, _ = chia_asset_kind(params.get("asset", "native"))
        if kind != "native":
            raise chia_relay.RelayError(
                "relay path is native-XCH only — CAT/NFT spends go through "
                "Sage RPC (/send_cat, /transfer_nfts)")
        chain = params["chain"]
        network = chia.NETWORKS[chain]
        if chain == "chia-mainnet" and not self.chia_cfg.get(
                "mainnet_submit_enabled"):
            raise chia_relay.RelayError(
                "mainnet submission refused for chia-mainnet — needs the "
                "separately-authorized mainnet_submit_enabled flag (§10.14-17)")
        if self._signing_seed() is None:
            raise chia_relay.RelayError("no seed configured — cannot sign")
        if params.get("amount_wei") is not None or params.get("amount_lamports") is not None:
            raise chia_relay.RelayError(
                "wei/lamports on a Chia chain — schema misuse, refusing")
        dest = params.get("destination", "")
        prefix = chia.PREFIXES[network]
        if not isinstance(dest, str) or not dest.startswith(prefix):
            raise chia_relay.RelayError(
                f"bad destination for {chain}: expected a {prefix}... address")
        amount = params["amount_mojos"]
        fee = int(self.chia_cfg.get("fee_mojos", 0))

        # Dual-network wallets: one seed serves testnet11 and mainnet (the
        # KDF derives per-chain keys; only the bech32m HRP differs). Relays
        # are per-network — a testnet relay must never see a mainnet bundle.
        # `relay_urls` maps network name -> URL; the legacy flat `relay_url`
        # is kept as a fallback for single-network installs.
        rpc = self._chia_relay_rpc(network)

        # Verify the relay is on the expected network before touching keys.
        st = rpc.status()
        if st.get("network") != network:
            raise chia_relay.RelayError(
                f"relay network {st.get('network')!r} != expected {network!r} "
                "— refusing")

        # Derive our wallet master key locally. In KDF mode the label matches
        # the Sage path ("default") so both transports use the same wallet;
        # in standard mode it is the BLS key_gen master key (same for both
        # networks — only the bech32m HRP differs).
        master_sk = self._chia_master_sk(chain)
        # Scan the first N derivation indices for coins.
        scan_n = int(self.chia_cfg.get("relay_scan_indices", 10))
        puzzle_hashes = []
        index_for_ph = {}
        for i in range(scan_n):
            wsk = chia_sign.wallet_sk(master_sk, i)
            spk = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk))
            ph = chia_sign.puzzle_hash_for_synthetic_pk(spk)
            puzzle_hashes.append(ph.hex())
            index_for_ph[ph.hex()] = i

        coins = rpc.coins(puzzle_hashes)
        unspent = [c for c in coins if c.get("spent_height") is None]
        # Sort by amount descending for simple largest-first selection.
        unspent.sort(key=lambda c: int(c.get("amount_mojos", 0)),
                     reverse=True)
        need = amount + fee
        # Never spend a coin committed to an open offer — it is
        # encumbered until the offer is taken, cancelled, or expires.
        encumbered = self._open_offer_coin_ids()
        selected = []
        total = 0
        for c in unspent:
            if c.get("coin_id") in encumbered:
                continue
            selected.append(c)
            total += int(c["amount_mojos"])
            if total >= need:
                break
        if total < need:
            raise chia_relay.RelayError(
                f"insufficient balance via relay: have {total} mojos, "
                f"need {need}")

        # Build outputs: destination + change back to our first address.
        change_ph_hex = puzzle_hashes[0]
        change = total - amount - fee
        dest_ph = chia_sign.puzzle_hash_for_address(dest)
        outputs = [(dest_ph, amount)]
        if change > 0:
            outputs.append((bytes.fromhex(change_ph_hex), change))
        elif change < 0:
            raise chia_relay.RelayError("negative change — refusing")

        # Build and sign one spend per selected coin (keys stay local).
        spends = []
        for c in selected:
            ph_hex = c["puzzle_hash"]
            idx = index_for_ph.get(ph_hex)
            if idx is None:
                raise chia_relay.RelayError(
                    f"coin puzzle hash {ph_hex[:16]}… not in our key set "
                    "— refusing")
            coin = (bytes.fromhex(c["parent_coin_info"]),
                    bytes.fromhex(ph_hex),
                    int(c["amount_mojos"]))
            # Split outputs across spends: first spend pays dest+change,
            # subsequent spends just consolidate to our change address.
            # (Simple single-spend path: use the first coin if it covers.)
            spends.append(chia_sign.build_standard_spend(
                master_sk, idx, coin, outputs, network))
            # For now only single-coin spends are supported; multi-coin
            # needs output splitting across spends.
            break
        if len(selected) > 1:
            raise chia_relay.RelayError(
                "multi-coin selection not yet supported via relay — "
                "fund a single coin covering the amount")

        bundle_hex = chia_sign.build_spend_bundle(spends).hex()
        res = rpc.broadcast(bundle_hex)
        # The relay returns mempool status as an int (1=SUCCESS, 2=PENDING,
        # 3=FAILED) plus a status_name string.  Check the name — comparing
        # the int to "FAILED" would never match and a failed broadcast
        # would be recorded as submitted.
        status = res.get("status", "")
        status_name = res.get("status_name", "")
        if status_name == "FAILED" or status == 3:
            raise chia_relay.RelayError(
                f"relay broadcast FAILED: {res.get('error', res)!r}")
        # Fail closed on bundle-identity mismatch. The bundle's txid is
        # deterministically sha256 of its serialized bytes — we compute it
        # locally and require BOTH the relay's expected_txid (sha256 of the
        # bytes the relay received) and the peer mempool ack txid to equal
        # it. A missing expected_txid/txid is a contract violation and a
        # refusal (RelayError — nothing is recorded, no velocity consumed).
        # A MISMATCH is different: the bundle left the machine but the
        # pipeline saw different bytes than the ones we signed, so the
        # spend's fate is UNKNOWN. Per Speechless (2026-09-21) a mismatch is
        # never safe-to-retry — raise BroadcastUnknown so the daemon's
        # unknown-spend path ledgers approved-submit-unknown and consumes
        # velocity fail-closed (assume it lands; a cap that undercounts is
        # a broken cap). The human reconciles the txid on-chain before any
        # re-request; a blind retry could double-spend.
        local_txid = hashlib.sha256(bytes.fromhex(bundle_hex)).hexdigest()
        expected_txid = res.get("expected_txid")
        if not expected_txid:
            raise chia_relay.RelayError(
                "relay broadcast returned no expected_txid — refusing "
                "(contract violation; bundle identity unverified)")
        if expected_txid != local_txid:
            raise chia_relay.BroadcastUnknown(
                local_txid,
                f"relay expected_txid {expected_txid!r} != locally computed "
                f"bundle txid {local_txid[:16]}… — fate unknown, do not retry")
        txid = res.get("txid")
        if not txid:
            raise chia_relay.RelayError(
                "relay broadcast returned no txid — refusing "
                "(contract violation; bundle identity unverified)")
        if txid != local_txid:
            raise chia_relay.BroadcastUnknown(
                local_txid,
                f"relay peer-ack txid {txid!r} != locally computed "
                f"bundle txid {local_txid[:16]}… — fate unknown, do not retry")
        # txid here is the mempool ack; the stable ledger reference is the
        # created coin id (first CREATE_COIN output).
        coin_id = None
        spent_coin_id = selected[0]["coin_id"]
        for c in selected[:1]:
            # Recompute the expected created coin id for the destination
            # output: sha256(parent || puzzle_hash || amount), where the
            # parent is the SPENT coin's own id (c["coin_id"]) — not the
            # spent coin's parent_coin_info.
            cid = chia_sign.coin_id(
                bytes.fromhex(c["coin_id"]),
                dest_ph, amount)
            coin_id = cid.hex()
            break
        # "from" is the bech32m address of our change/index-0 puzzle hash
        # (txch1… on testnet11, xch1… on mainnet) — not raw puzzle-hash hex.
        hrp = prefix[:-1] if prefix.endswith("1") else prefix
        from_addr = chia_sign.address_for_puzzle_hash(
            bytes.fromhex(puzzle_hashes[0]), hrp)
        out = {"submitted": True, "tx_hash": res.get("txid"),
               "coin_id": coin_id, "from": from_addr,
               "mempool_status": status_name or status}
        # Opt-in on-chain confirmation (chia.confirm_spends): poll the
        # spent coin until spent_height is set. Default off — the mempool
        # ack above is the recorded result; confirmation is a stronger
        # claim that blocks up to the relay timeout.
        if self.chia_cfg.get("confirm_spends"):
            conf = chia_relay.wait_for_confirmation(rpc, spent_coin_id)
            out["confirmed_height"] = conf.get("spent_height")
        return out

    def _chia_sage_rpc(self, chain: str):
        """Start/connect Sage RPC and select the daemon's wallet for `chain`.

        Shared setup for all Sage-path Chia spends (XCH, CAT, NFT): ensures
        `sage rpc start` answers, switches to the chain's network, and
        imports + logs in the daemon's KDF-derived BLS key. Returns
        (rpc, fingerprint, sender_address).
        """
        self._ensure_sage_rpc()
        data_home = self.chia_cfg.get("sage_data_home")
        data_dir = os.path.join(data_home, "com.rigidnetwork.sage")
        if not os.path.isdir(data_dir):
            raise chia.SageError(
                f"Sage data dir {data_dir} missing after startup — refusing")
        rpc = chia.SageRpc(data_dir,
                           port=int(self.chia_cfg.get("rpc_port", 9257)))
        expected_fp, sender = self._chia_wallet(rpc, chain)
        return rpc, expected_fp, sender

    def _chia_sage_guards(self, params: dict, chain: str) -> tuple:
        """Fail-fast checks shared by every Sage-path Chia spend.

        Returns (network, destination, amount_mojos). Raises chia.SageError
        on mainnet-without-flag, missing seed, wrong amount field, or a
        destination with the wrong address prefix.
        """
        network = chia.NETWORKS[chain]
        if chain == "chia-mainnet" and not self.chia_cfg.get(
                "mainnet_submit_enabled"):
            raise chia.SageError(
                "mainnet submission refused for chia-mainnet — needs the "
                "separately-authorized mainnet_submit_enabled flag (§10.14-17)")
        if self._signing_seed() is None:
            raise chia.SageError("no seed configured — cannot sign")
        if params.get("amount_wei") is not None or params.get(
                "amount_lamports") is not None:
            raise chia.SageError(
                "wei/lamports on a Chia chain — schema misuse, refusing")
        dest = params.get("destination", "")
        prefix = chia.PREFIXES[network]
        if not isinstance(dest, str) or not dest.startswith(prefix):
            raise chia.SageError(
                f"bad destination for {chain}: expected a {prefix}... address")
        amount = params["amount_mojos"]
        return network, dest, amount

    def _execute_chia_cat_spend_via_sage(self, params: dict,
                                         asset_id: str) -> dict:
        """Build, sign, and submit an approved CAT transfer via Sage RPC.

        Flow mirrors the XCH Sage path: guards, wallet selection, balance
        check against /get_cats, /send_cat with auto_submit, then
        verification — the outgoing transaction must appear in
        /get_transactions carrying a created CAT coin to the approved
        destination with the approved amount and the CAT asset id echoed
        on the coin record. The created CAT coin id is the ledger
        reference. Raises chia.SageError on any failure, and
        chia.BroadcastUnknown when the send may have broadcast but the
        matching transaction never appeared (the caller's unknown-fate
        rule applies: never retry, never reuse the queue id).
        """
        chain = params["chain"]
        network, dest, amount = self._chia_sage_guards(params, chain)
        rpc, _, sender = self._chia_sage_rpc(chain)
        fee = int(self.chia_cfg.get("fee_mojos", 0))
        cat_bal = chia.cat_balance(rpc, asset_id)
        if cat_bal < amount:
            raise chia.SageError(
                f"insufficient CAT balance: have {cat_bal} mojos of "
                f"{asset_id[:16]}…, need {amount}")
        xch_bal = chia.amount_to_int(rpc.sync_status()["selectable_balance"])
        if xch_bal < fee:
            raise chia.SageError(
                f"insufficient XCH for fee: have {xch_bal} mojos, "
                f"need {fee}")
        t0 = time.time()
        rpc.send_cat(asset_id, dest, amount, fee,
                     memos=[str(params.get("purpose", ""))[:64]])
        # The approved intent, re-checked against the on-wallet transaction
        # record: destination, amount, AND asset id must all match.
        tx = chia.wait_for_outgoing(rpc, dest, amount, t0,
                                    asset_ref=asset_id,
                                    timeout_s=self._sage_wait_timeout_s())
        coin_id = None
        for coin in tx.get("created", []):
            if ((coin.get("address") or "").lower() == dest.lower()
                    and chia.amount_to_int(coin.get("amount")) == amount
                    and isinstance(coin.get("asset_id"), str)
                    and coin["asset_id"].lower() == asset_id.lower()):
                coin_id = coin.get("coin_id")
                break
        if not coin_id:
            raise chia.SageError(
                "outgoing transaction found but no created coin matches the "
                "approved destination+amount+asset — refusing to report "
                "success")
        return {"submitted": True, "tx_hash": coin_id,
                "coin_id": coin_id, "from": sender,
                "tx_height": tx.get("height"), "asset_id": asset_id}

    def _execute_chia_nft_spend_via_sage(self, params: dict,
                                         nft_ref: str) -> dict:
        """Transfer an approved NFT to a new owner via Sage RPC.

        The NFT is a singleton: amount is 1 (validated at request time and
        re-checked here). Flow: guards, wallet selection, XCH fee-balance
        check, /transfer_nfts with auto_submit, then verification — the
        exact approved NFT coin must be consumed and a coin created to the
        approved destination. The new coin id is the ledger reference.
        Raises chia.SageError on any failure, and chia.BroadcastUnknown on
        unknown fate (same no-retry rule as every other spend).
        """
        chain = params["chain"]
        network, dest, amount = self._chia_sage_guards(params, chain)
        if amount != 1:
            raise chia.SageError(
                "NFT transfer amount must be 1 — refusing schema misuse")
        rpc, _, sender = self._chia_sage_rpc(chain)
        fee = int(self.chia_cfg.get("fee_mojos", 0))
        xch_bal = chia.amount_to_int(rpc.sync_status()["selectable_balance"])
        if xch_bal < fee:
            raise chia.SageError(
                f"insufficient XCH for fee: have {xch_bal} mojos, "
                f"need {fee}")
        t0 = time.time()
        rpc.transfer_nfts([nft_ref], dest, fee)
        tx = chia.wait_for_nft_transfer(rpc, nft_ref, dest, t0,
                                        timeout_s=self._sage_wait_timeout_s())
        coin_id = None
        for coin in tx.get("created", []):
            if (coin.get("address") or "").lower() == dest.lower():
                coin_id = coin.get("coin_id")
                break
        if not coin_id:
            raise chia.SageError(
                "NFT transfer transaction found but no created coin pays "
                "the approved destination — refusing to report success")
        return {"submitted": True, "tx_hash": coin_id,
                "coin_id": coin_id, "from": sender,
                "tx_height": tx.get("height"), "nft_id": nft_ref}

    def _execute_offer_make_via_sage(self, params: dict) -> dict:
        """Create an approved offer via Sage RPC (off-chain — no broadcast).

        Flow: guards, wallet selection, re-validation of the queued legs
        (never trust the queue entry shape blindly), balance check for the
        offered side, /make_offer, then verification — the offer record
        must exist via /get_offer with an open status. Returns
        {"submitted": False, "offer_id", "offer", ...}: nothing left the
        machine, so velocity counts the encumbered legs and the ledger
        records the offer_id as the reference. Raises chia.SageError on
        any failure — a make that never completed records nothing.
        """
        chain = params["chain"]
        self._chia_offer_guards(params, chain)
        offered = _validate_offer_legs(params["offered"], "offered")
        requested = _validate_offer_legs(params["requested"], "requested")
        rpc, _, _ = self._chia_sage_rpc(chain)
        fee = params.get("fee_mojos", 0)
        self._check_offer_balances(rpc, offered, fee)
        res = rpc.make_offer(
            [{"asset": a, "amount_mojos": m} for a, m in offered],
            [{"asset": a, "amount_mojos": m} for a, m in requested],
            fee_mojos=fee,
            receive_address=params.get("receive_address"),
            expires_at_second=params.get("expires_at_second"))
        offer_id = res["offer_id"]
        rec = rpc.get_offer(offer_id)
        if rec.get("status") not in ("pending", "active"):
            raise chia.SageError(
                f"offer {offer_id[:16]}… created but status is "
                f"{rec.get('status')!r} — human must reconcile")
        return {"submitted": False, "offer_id": offer_id,
                "offer": res["offer"],
                "note": f"offer {offer_id} created off-chain "
                        f"(status {rec.get('status')})"}

    def _execute_offer_take_via_sage(self, params: dict) -> dict:
        """Take an approved offer via Sage RPC (on-chain spend of our side).

        Flow: guards, wallet selection, re-view of the offer — it must
        still be open AND its legs must equal the request-time terms (the
        offer string is immutable, so this is belt-and-braces),
        balance check for what we give, /take_offer with auto_submit,
        then verification — the transaction must appear in Sage's pending
        transactions. Raises chia.SageError on any failure, and
        chia.BroadcastUnknown when the take may have broadcast but never
        appeared (never retry, never reuse).
        """
        chain = params["chain"]
        self._chia_offer_guards(params, chain)
        offer = params["offer"]
        rpc, _, _ = self._chia_sage_rpc(chain)
        seen = rpc.view_offer(offer)
        if seen.get("status") not in ("pending", "active"):
            raise chia.SageError(
                "offer is no longer takeable "
                f"(status {seen.get('status')!r}) — refusing")
        summary = seen.get("offer") or {}
        give = _summary_legs(summary, "taker")
        get = _summary_legs(summary, "maker")
        want_give = [(it["asset"], it["amount_mojos"])
                     for it in params["_give"]]
        want_get = [(it["asset"], it["amount_mojos"])
                    for it in params["_get"]]
        if give != want_give or get != want_get:
            raise chia.SageError(
                "offer terms changed since approval — refusing to take")
        fee = params.get("fee_mojos", 0)
        self._check_offer_balances(rpc, give, fee)
        res = rpc.take_offer(offer, fee_mojos=fee, auto_submit=True)
        tx_id = res.get("transaction_id")
        if not tx_id:
            raise chia.SageError(
                f"/take_offer gave no transaction_id: {str(res)[:200]}")
        if not self._wait_pending_tx(rpc, tx_id,
                                     timeout_s=self._sage_wait_timeout_s()):
            raise chia.BroadcastUnknown(
                tx_id, "take_offer submitted but the transaction never "
                "appeared in pending transactions — broadcast, confirmation "
                "unknown; do not retry blindly")
        return {"submitted": True, "tx_hash": tx_id,
                "give": params["_give"], "get": params["_get"]}

    def _execute_offer_cancel_via_sage(self, params: dict) -> dict:
        """Cancel approved offer(s) via Sage RPC (on-chain coin spends).

        Flow: guards, wallet selection, re-verification that every offer
        is still open, /cancel_offer(s) with auto_submit, then
        verification — each offer record must flip to "cancelled". The
        first spent input coin id is the ledger reference. Raises
        chia.SageError on any failure, and chia.BroadcastUnknown when the
        cancel may have broadcast but the records never flipped (never
        retry, never reuse).
        """
        chain = params["chain"]
        self._chia_offer_guards(params, chain)
        ids = list(params["offer_ids"])
        rpc, _, _ = self._chia_sage_rpc(chain)
        for oid in ids:
            rec = rpc.get_offer(oid)
            if rec.get("status") not in ("pending", "active"):
                raise chia.SageError(
                    f"offer {oid[:16]}… is not open "
                    f"(status {rec.get('status')!r}) — refusing")
        fee = params.get("fee_mojos", 0)
        if len(ids) == 1:
            res = rpc.cancel_offer(ids[0], fee_mojos=fee, auto_submit=True)
        else:
            res = rpc.cancel_offers(ids, fee_mojos=fee, auto_submit=True)
        inputs = ((res.get("summary") or {}).get("inputs") or [])
        ref = inputs[0].get("coin_id") if inputs else ""
        deadline = time.time() + self._sage_wait_timeout_s()
        while time.time() < deadline:
            if all((rpc.get_offer(oid) or {}).get("status") == "cancelled"
                   for oid in ids):
                break
            time.sleep(5)
        if not all((rpc.get_offer(oid) or {}).get("status") == "cancelled"
                   for oid in ids):
            raise chia.BroadcastUnknown(
                ref, "cancel submitted but offer record(s) never flipped "
                "to cancelled — broadcast, confirmation unknown; do not "
                "retry blindly")
        return {"submitted": True, "tx_hash": ref or ids[0],
                "offer_ids": ids}

    # ---- native XCH offer path (chia_offer.py + relay, no Sage) ----

    def _offer_native_route(self, chain: str) -> bool:
        """True when the native offer path can serve this chain.

        The native route never calls _chia_sage_rpc: chain data comes
        from the relay and signing is local via chia_offer.py. Legs must
        all be native XCH (checked by the caller); the relay must be
        configured for the chain's network.
        """
        network = chia.NETWORKS.get(chain)
        if not network:
            return False
        urls = self.chia_cfg.get("relay_urls", {}) or {}
        return bool(urls.get(network) or self.chia_cfg.get("relay_url"))

    # -- atomic mode-600 offer storage under config_dir/offers --

    def _offer_store_dir(self) -> str:
        d = os.path.join(self.config_dir, "offers")
        os.makedirs(d, mode=0o700, exist_ok=True)
        return d

    def _offer_store(self, record: dict) -> None:
        """Persist an offer record atomically with mode 600.

        Writes to a temp file (mode 600 from creation — never
        world-readable) then os.replace, so a crash cannot leave a
        half-written record and the plaintext offer string is never
        exposed by file permissions.
        """
        d = self._offer_store_dir()
        path = os.path.join(d, record["offer_id"] + ".json")
        tmp = path + ".tmp"
        data = json.dumps(record, indent=2).encode()
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)

    def _offer_load(self, offer_id: str):
        """Load a stored native offer record, or None."""
        path = os.path.join(self._offer_store_dir(), offer_id + ".json")
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def _offer_mark(self, offer_id: str, status: str,
                    extra: dict | None = None) -> None:
        rec = self._offer_load(offer_id)
        if rec is None:
            raise chia_relay.RelayError(
                f"offer {offer_id[:16]}… not in the local offer store — refusing")
        rec["status"] = status
        if extra:
            rec.update(extra)
        self._offer_store(rec)

    def _offer_list_local(self) -> list:
        """All stored native offer records (newest first)."""
        out = []
        try:
            names = os.listdir(self._offer_store_dir())
        except FileNotFoundError:
            return []
        for name in sorted(names):
            if not name.endswith(".json") or name.endswith(".tmp"):
                continue
            try:
                with open(os.path.join(self._offer_store_dir(), name)) as f:
                    out.append(json.load(f))
            except (OSError, ValueError):
                continue
        out.sort(key=lambda r: r.get("created_at", 0), reverse=True)
        return out

    # -- relay chain access: fresh read on every call --

    def _native_relay_coins(self, chain: str):
        """(rpc, network, master_sk, unspent, index_for_ph, puzzle_hashes).

        Fetches coins fresh from the relay on every call — the
        execute-time unspent-input recheck happens immediately before
        approved signing. Raises chia_relay.RelayError on any problem.
        """
        from spellbook import chia_relay, chia_sign
        network = chia.NETWORKS[chain]
        rpc = self._chia_relay_rpc(network)
        st = rpc.status()
        if st.get("network") != network:
            raise chia_relay.RelayError(
                f"relay network {st.get('network')!r} != expected "
                f"{network!r} — refusing")
        master_sk = self._chia_master_sk(chain)
        scan_n = int(self.chia_cfg.get("relay_scan_indices", 10))
        puzzle_hashes = []
        index_for_ph = {}
        for i in range(scan_n):
            wsk = chia_sign.wallet_sk(master_sk, i)
            spk = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk))
            ph = chia_sign.puzzle_hash_for_synthetic_pk(spk)
            puzzle_hashes.append(ph.hex())
            index_for_ph[ph.hex()] = i
        coins = rpc.coins(puzzle_hashes)
        unspent = [c for c in coins if c.get("spent_height") is None]
        return rpc, network, master_sk, unspent, index_for_ph, puzzle_hashes

    def _open_offer_coin_ids(self) -> set:
        """Coin ids encumbered by locally-stored open native offers.

        A coin committed as a maker input to an open offer must not be
        selected for any other spend (regular transfer, another offer's
        make, or a take — including a self-take of that same offer,
        whose maker coins are spent by the offer's own spends inside the
        take bundle). Without this, the same coin can be selected twice
        and the bundle is rejected as a double-spend.
        """
        encumbered = set()
        for rec in self._offer_list_local():
            if rec.get("status") != "open":
                continue
            for mc in rec.get("maker_coins") or []:
                cid = mc.get("coin_id")
                if cid:
                    encumbered.add(cid)
        return encumbered

    def _native_select(self, unspent: list, index_for_ph: dict, need: int,
                       exclude: set | None = None):
        """Largest-first XCH input selection; returns ([XchInput], total).

        ``exclude``: coin ids to skip (encumbered by open offers).
        """
        from spellbook import chia_offer, chia_relay
        excluded = exclude or set()
        ordered = sorted(unspent,
                         key=lambda c: int(c.get("amount_mojos", 0)),
                         reverse=True)
        selected = []
        total = 0
        skipped = 0
        for c in ordered:
            if c.get("coin_id") in excluded:
                skipped += 1
                continue
            ph_hex = c["puzzle_hash"]
            idx = index_for_ph.get(ph_hex)
            if idx is None:
                raise chia_relay.RelayError(
                    f"coin puzzle hash {ph_hex[:16]}… not in our key set "
                    "— refusing")
            selected.append(chia_offer.XchInput(
                bytes.fromhex(c["parent_coin_info"]),
                bytes.fromhex(ph_hex),
                int(c["amount_mojos"]), idx))
            total += int(c["amount_mojos"])
            if total >= need:
                break
        if total < need:
            raise chia_relay.RelayError(
                f"insufficient XCH via relay: have {total} mojos, need {need}"
                + (f" ({skipped} coins encumbered by open offers)"
                   if skipped else ""))
        return selected, total

    def _relay_broadcast_strict(self, rpc, bundle_bytes: bytes) -> str:
        """Broadcast with strict local/relay/peer txid identity.

        The bundle txid is deterministically sha256 of its serialized
        bytes — computed locally and required to equal BOTH the relay's
        expected_txid and the peer mempool ack txid. Raises RelayError
        on contract violations (nothing recorded, no velocity consumed)
        and BroadcastUnknown on any identity mismatch (fate unknown —
        never retry; the caller ledgers approved-submit-unknown and
        consumes velocity fail-closed).
        """
        from spellbook import chia_relay
        res = rpc.broadcast(bundle_bytes.hex())
        status_name = res.get("status_name", "")
        if status_name == "FAILED" or res.get("status") == 3:
            raise chia_relay.RelayError(
                f"relay broadcast FAILED: {res.get('error', res)!r}")
        local_txid = hashlib.sha256(bundle_bytes).hexdigest()
        expected_txid = res.get("expected_txid")
        if not expected_txid:
            raise chia_relay.RelayError(
                "relay broadcast returned no expected_txid — refusing "
                "(contract violation; bundle identity unverified)")
        if expected_txid != local_txid:
            raise chia_relay.BroadcastUnknown(
                local_txid,
                f"relay expected_txid {expected_txid!r} != locally computed "
                f"bundle txid {local_txid[:16]}… — fate unknown, do not retry")
        txid = res.get("txid")
        if not txid:
            raise chia_relay.RelayError(
                "relay broadcast returned no txid — refusing "
                "(contract violation; bundle identity unverified)")
        if txid != local_txid:
            raise chia_relay.BroadcastUnknown(
                local_txid,
                f"relay peer-ack txid {txid!r} != locally computed bundle "
                f"txid {local_txid[:16]}… — fate unknown, do not retry")
        return txid

    # -- native make / take / cancel (approved execution) --

    def _execute_offer_make_native(self, params: dict) -> dict:
        """Create an approved native-XCH offer (off-chain — no broadcast).

        Guards, leg re-validation (all-native or refuse), fresh relay
        coin scan, local build+sign via chia_offer, atomic mode-600
        storage of the offer record. Returns {"submitted": False,
        "offer_id", "offer"} — nothing left the machine, so velocity
        counts the encumbered legs and the ledger records the offer_id.
        """
        from spellbook import chia_offer, chia_relay
        chain = params["chain"]
        self._chia_offer_guards(params, chain)
        offered = _validate_offer_legs(params["offered"], "offered")
        requested = _validate_offer_legs(params["requested"], "requested")
        if any(a != "native" for a, _ in offered + requested):
            raise chia_relay.RelayError(
                "native offer path is XCH-only — non-native legs go through Sage")
        fee = params.get("fee_mojos", 0)
        receive_ph = bytes.fromhex(params["_receive_ph"])
        (rpc, network, master_sk, unspent, index_for_ph,
         puzzle_hashes) = self._native_relay_coins(chain)
        need = sum(m for _, m in offered) + fee
        # Coins committed to other open offers are encumbered — a coin
        # can back only one open offer at a time.
        inputs, _total = self._native_select(
            unspent, index_for_ph, need,
            exclude=self._open_offer_coin_ids())
        change_ph = bytes.fromhex(puzzle_hashes[0])
        built = chia_offer.make_offer(
            master_sk, network,
            offered=[("native", m) for _, m in offered],
            requested=[chia_offer.RequestedPayment("native", receive_ph, m)
                       for _, m in requested],
            xch_inputs=inputs,
            change_ph=change_ph,
            fee=fee,
        )
        self._offer_store({
            "offer_id": built.offer_id,
            "offer": built.offer_str,
            "bundle_hex": built.bundle_bytes.hex(),
            "maker_coins": built.maker_coins,
            "offered": [[a, m] for a, m in built.offered],
            "requested": [[a, m] for a, m in built.requested],
            "nonce": built.nonce.hex(),
            "status": "open",
            "chain": chain,
            "network": network,
            "transport": "native",
            "created_at": time.time(),
        })
        return {"submitted": False, "offer_id": built.offer_id,
                "offer": built.offer_str,
                "note": f"native XCH offer {built.offer_id[:16]}… created "
                        f"off-chain (stored open; nothing broadcast)"}

    def _execute_offer_take_native(self, params: dict) -> dict:
        """Take an approved native-XCH offer (on-chain spend of our side).

        Re-parses the offer (the string is immutable — belt-and-braces),
        re-verifies terms against the approval, rechecks unspent inputs
        via the relay, builds and signs our side locally, completes
        settlement, and broadcasts with strict txid identity. Raises
        chia_relay.RelayError on any failure and BroadcastUnknown when
        the take may have broadcast but identity could not be verified
        (never retry, never reuse).
        """
        from spellbook import chia_offer, chia_relay
        chain = params["chain"]
        self._chia_offer_guards(params, chain)
        try:
            parsed = chia_offer.parse_offer(params["offer"])
        except chia_offer.OfferError as e:
            raise chia_relay.RelayError(
                f"offer failed native parse: {e}") from e
        legs = chia_offer.summarize_offer(parsed)
        give = legs["requested"]  # what we must pay (maker's requested)
        get = legs["offered"]     # what we receive (maker's offered)
        want_give = [(it["asset"], it["amount_mojos"])
                     for it in params["_give"]]
        want_get = [(it["asset"], it["amount_mojos"])
                    for it in params["_get"]]
        if give != want_give or get != want_get:
            raise chia_relay.RelayError(
                "offer terms changed since approval — refusing to take")
        fee = params.get("fee_mojos", 0)
        (rpc, network, master_sk, unspent, index_for_ph,
         puzzle_hashes) = self._native_relay_coins(chain)
        need = sum(m for _, m in give) + fee
        # The offer's own maker coins are spent by the offer's spends
        # inside the take bundle, and other open offers encumber their
        # coins too — exclude all of them so the taker side can never
        # re-select the same coin (double-spend inside the bundle).
        inputs, _total = self._native_select(
            unspent, index_for_ph, need,
            exclude=self._open_offer_coin_ids())
        recv_ph = bytes.fromhex(puzzle_hashes[0])
        result = chia_offer.take_offer(
            master_sk, network, parsed,
            xch_inputs=inputs,
            receive=[chia_offer.RequestedPayment(a, recv_ph, m)
                     for a, m in get],
            change_ph=recv_ph,
            fee=fee,
        )
        txid = self._relay_broadcast_strict(rpc, result.bundle_bytes)
        if self._offer_load(parsed.offer_id) is not None:
            self._offer_mark(parsed.offer_id, "taken", {"take_txid": txid})
        return {"submitted": True, "tx_hash": txid,
                "give": params["_give"], "get": params["_get"]}

    def _execute_offer_cancel_native(self, params: dict) -> dict:
        """Cancel approved native-XCH offer(s) (on-chain coin spends).

        Each offer must be in the local store and open; at least one
        maker coin must still be unspent on the relay (immediate
        recheck). Spends the first live maker coin back to our change
        address and broadcasts with strict txid identity. Raises
        chia_relay.RelayError on any failure and BroadcastUnknown when
        a cancel may have broadcast but identity could not be verified
        (never retry, never reuse).
        """
        from spellbook import chia_offer, chia_relay
        chain = params["chain"]
        self._chia_offer_guards(params, chain)
        ids = list(params["offer_ids"])
        fee = params.get("fee_mojos", 0)
        (rpc, network, master_sk, unspent, index_for_ph,
         puzzle_hashes) = self._native_relay_coins(chain)
        unspent_ids = {c.get("coin_id") for c in unspent}
        change_ph = bytes.fromhex(puzzle_hashes[0])
        results = []
        for oid in ids:
            rec = self._offer_load(oid)
            if rec is None:
                raise chia_relay.RelayError(
                    f"offer {oid[:16]}… not in the local offer store — refusing")
            if rec.get("status") != "open":
                raise chia_relay.RelayError(
                    f"offer {oid[:16]}… is not open "
                    f"(status {rec.get('status')!r}) — refusing")
            if rec.get("chain") != chain:
                raise chia_relay.RelayError(
                    f"offer {oid[:16]}… belongs to {rec.get('chain')} — refusing")
            maker_coins = rec.get("maker_coins") or []
            live = [mc for mc in maker_coins
                    if mc.get("coin_id") in unspent_ids]
            if not live:
                raise chia_relay.RelayError(
                    f"offer {oid[:16]}… maker coins already spent — "
                    "nothing to cancel")
            mc = live[0]
            idx = index_for_ph.get(mc["puzzle_hash"])
            if idx is None:
                raise chia_relay.RelayError(
                    "maker coin puzzle hash not in our key set — refusing")
            coin = chia_offer.Coin(bytes.fromhex(mc["parent"]),
                                   bytes.fromhex(mc["puzzle_hash"]),
                                   mc["amount"])
            bundle = chia_offer.cancel_offer(master_sk, network, coin, idx,
                                             change_ph, fee=fee)
            txid = self._relay_broadcast_strict(rpc, bundle)
            self._offer_mark(oid, "cancelled", {"cancel_txid": txid})
            results.append({"offer_id": oid, "tx_hash": txid})
        out = {"submitted": True, "tx_hash": results[0]["tx_hash"],
               "offer_ids": ids}
        if len(results) > 1:
            out["cancels"] = results
        return out

    # -- native request-time validation (no Sage at request time either) --

    def _rt_offer_make_native(self, p: dict, chain: str, offered: list,
                              requested: list, muse_id: str) -> dict:
        """Queue a native-XCH offer_make intent.

        All-native legs are already validated; the receive address
        decodes to a puzzle hash locally and the funding check reads
        the relay — Sage is never consulted on this path.
        """
        from spellbook import chia_relay, chia_sign
        recv = p.get("receive_address")
        if not isinstance(recv, str) or not recv:
            return {"ok": False,
                    "error": "native offer_make needs receive_address "
                             "(requested XCH needs a puzzle hash)"}
        network = chia.NETWORKS[chain]
        prefix = chia.PREFIXES[network]
        if not recv.startswith(prefix):
            return {"ok": False,
                    "error": f"bad receive_address for {chain}: expected a "
                             f"{prefix}… address"}
        if not self._offer_native_route(chain):
            return {"ok": False,
                    "error": "native XCH offers need a configured Chia relay "
                             f"(chia.relay_urls[{network}]) — refusing"}
        try:
            receive_ph = chia_sign.puzzle_hash_for_address(recv)
            (_rpc, _net, _master, unspent, _idx,
             _phs) = self._native_relay_coins(chain)
            have = sum(int(c.get("amount_mojos", 0)) for c in unspent)
            need = sum(m for _, m in offered) + p.get("fee_mojos", 0)
            if have < need:
                raise chia_relay.RelayError(
                    f"insufficient XCH via relay: have {have} mojos, "
                    f"need {need}")
        except (chia_relay.RelayError, ValueError) as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "offer_make", "chain": chain,
                  "transport": "native",
                  "offered": [{"asset": a, "amount_mojos": m}
                              for a, m in offered],
                  "requested": [{"asset": a, "amount_mojos": m}
                                for a, m in requested],
                  "fee_mojos": p.get("fee_mojos", 0),
                  "purpose": p.get("purpose", ""),
                  "_receive_ph": receive_ph.hex()}
        if p.get("expires_at_second") is not None:
            params["expires_at_second"] = p["expires_at_second"]
        entries = [(chain, a, m) for a, m in offered]
        return self._run_fund_intent(params, muse_id, entries, "offer_make")

    def _rt_offer_take_native(self, p: dict, chain: str, muse_id: str) -> dict:
        """Queue a native-XCH offer_take intent.

        The offer string decodes locally (exact legs for the policy
        engine and the human — never an opaque string); the funding
        check reads the relay. Falls back to the Sage path only when
        the offer is not native-parseable (e.g. CAT legs).
        """
        from spellbook import chia_offer, chia_relay
        try:
            parsed = chia_offer.parse_offer(p["offer"])
        except chia_offer.OfferError:
            return None  # not native-parseable: caller tries Sage
        legs = chia_offer.summarize_offer(parsed)
        give = legs["requested"]
        get = legs["offered"]
        if not self._offer_native_route(chain):
            return {"ok": False,
                    "error": "native XCH offers need a configured Chia relay "
                             f"(chia.relay_urls[{chia.NETWORKS[chain]}]) — refusing"}
        try:
            (_rpc, _net, _master, unspent, _idx,
             _phs) = self._native_relay_coins(chain)
            have = sum(int(c.get("amount_mojos", 0)) for c in unspent)
            need = sum(m for _, m in give) + p.get("fee_mojos", 0)
            if have < need:
                raise chia_relay.RelayError(
                    f"insufficient XCH via relay: have {have} mojos, "
                    f"need {need}")
        except chia_relay.RelayError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "offer_take", "chain": chain,
                  "transport": "native",
                  "offer": p["offer"],
                  "fee_mojos": p.get("fee_mojos", 0),
                  "purpose": p.get("purpose", ""),
                  "_give": [{"asset": a, "amount_mojos": m} for a, m in give],
                  "_get": [{"asset": a, "amount_mojos": m} for a, m in get]}
        entries = [(chain, a, m) for a, m in give]
        return self._run_fund_intent(params, muse_id, entries, "offer_take")

    def _rt_offer_cancel_native(self, p: dict, chain: str, ids: list,
                                muse_id: str) -> dict:
        """Queue a native-XCH offer_cancel intent.

        Every offer must be ours: present in the local store and open.
        Cancellation always queues for a human — no amount policy.
        """
        offered_all = []
        for oid in ids:
            rec = self._offer_load(oid)
            if rec is None or rec.get("transport") != "native":
                return None  # not ours: caller tries Sage
            if rec.get("status") != "open":
                return {"ok": False,
                        "error": f"offer {oid[:16]}… is not open "
                                 f"(status {rec.get('status')!r}) — refusing"}
            if rec.get("chain") != chain:
                return {"ok": False,
                        "error": f"offer {oid[:16]}… belongs to "
                                 f"{rec.get('chain')} — refusing"}
            offered_all.append({"offer_id": oid, "offered": [
                {"asset": a, "amount_mojos": m}
                for a, m in rec.get("offered", [])]})
        params = {"intent": "offer_cancel", "chain": chain,
                  "transport": "native",
                  "offer_ids": list(ids),
                  "fee_mojos": p.get("fee_mojos", 0),
                  "purpose": p.get("purpose", ""),
                  "_offered": offered_all}
        canon = json.dumps(params, sort_keys=True).encode()
        qid = str(self.next_qid)
        self.next_qid += 1
        self.queue[qid] = {"params": params, "muse_id": muse_id,
                           "queued_at": time.time()}
        self._save_queue()
        self.ledger.append(muse_id, canon, None, f"queued:{qid}")
        return {"ok": True, "decision": "queued", "queue_id": qid,
                "reason": "offer cancellation always requires human approval"}

    # ---- full Sage wallet surface: mints, DID/option/CAT, coin ops ----

    def _submit_sage_tx(self, rpc, res: dict, t0: float,
                        describe: str) -> dict:
        """Verify a Sage TransactionResponse and return the spend record.

        Extracts the input coin ids from the response's summary, then
        waits for a wallet transaction spending one of them (created after
        t0, the pre-call timestamp). The first matched input coin id is
        the stable ledger reference — Sage's transaction records carry
        height/timestamp, not a bundle hash. Raises chia.SageError when
        the response has no inputs, and chia.BroadcastUnknown when no
        transaction appears: the broadcast happened or it didn't, so it
        is never retried and velocity is consumed fail-closed by the
        caller.
        """
        inputs = [str(i.get("coin_id") or "") for i in
                  ((res or {}).get("summary") or {}).get("inputs") or []]
        inputs = [i for i in inputs if i]
        if not inputs:
            raise chia.SageError(
                f"{describe}: Sage returned a transaction with no inputs "
                "— refusing to report success")
        tx = chia.wait_for_tx_by_inputs(
            rpc, inputs, t0, timeout_s=self._sage_wait_timeout_s())
        return {"submitted": True, "tx_hash": inputs[0],
                "input_coin_ids": inputs,
                "tx_height": tx.get("height"),
                "note": f"{describe} submitted (in wallet tx at height "
                        f"{tx.get('height')})"}

    def _tx_intent_rpc(self, params: dict):
        """Common entry for approved Sage-transaction intents: guards +
        wallet selection. Returns (rpc, fee)."""
        chain = params["chain"]
        self._chia_offer_guards(params, chain)
        rpc, _, _ = self._chia_sage_rpc(chain)
        return rpc, params.get("fee_mojos", 0)

    def _execute_nft_mint_via_sage(self, params: dict) -> dict:
        """Mint approved NFTs via Sage RPC (on-chain).

        Re-validates the queued mints at execution; the approved
        did_id must still be a minter DID we own. The mint gate
        (_check_mint_gate) runs before this is reached — execution
        requires the human's separately-opened gate, not just queue
        approval. Returns the TransactionResponse-verified spend record.
        """
        rpc, fee = self._tx_intent_rpc(params)
        mints = params.get("mints") or []
        if not isinstance(mints, list) or not mints:
            raise chia.SageError("nft_mint needs a non-empty mints list")
        for m in mints:
            self._validate_nft_mint(m)
        did_id = params.get("did_id")
        # DidRecord.address is the did:chia:1… address the request names.
        owned = {str(d.get("address") or "") for d in rpc.get_dids()}
        if did_id not in owned:
            raise chia.SageError(
                f"minter DID {str(did_id)[:16]}… is not in this wallet — "
                "refusing")
        t0 = time.time()
        res = rpc.bulk_mint_nfts(list(mints), did_id, fee_mojos=fee,
                                 auto_submit=True)
        out = self._submit_sage_tx(
            rpc, res, t0, f"minted {len(mints)} NFT(s)")
        out["nft_ids"] = res.get("nft_ids", [])
        return out

    # Sage's NftMint descriptor fields — anything else is rejected (S13:
    # unknown shapes never reach the RPC).
    _NFT_MINT_KEYS = {"address", "edition_number", "edition_total",
                      "data_uris", "data_hash", "metadata_uris",
                      "metadata_hash", "license_uris", "license_hash",
                      "royalty_address", "royalty_ten_thousandths"}

    @staticmethod
    def _validate_nft_mint(m: dict) -> None:
        """Fail-closed validation of one NFT mint descriptor."""
        if not isinstance(m, dict):
            raise chia.SageError("each NFT mint must be an object")
        unknown = set(m) - Daemon._NFT_MINT_KEYS
        if unknown:
            raise chia.SageError(
                f"unknown NFT mint fields: {sorted(unknown)}")
        for key in ("data_uris", "metadata_uris", "license_uris"):
            v = m.get(key)
            if v is not None and not isinstance(v, list):
                raise chia.SageError(f"NFT mint {key} must be a list")
        roy = m.get("royalty_ten_thousandths")
        if roy is not None and (
                not isinstance(roy, int) or not 0 <= roy <= 10000):
            raise chia.SageError(
                "royalty_ten_thousandths must be 0-10000")
        if m.get("royalty_address") and not isinstance(
                m["royalty_address"], str):
            raise chia.SageError("royalty_address must be a string")

    def _execute_nft_assign_did_via_sage(self, params: dict) -> dict:
        """Assign approved NFTs to a DID profile via Sage RPC (on-chain).

        Every NFT id must still be in this wallet at execution; the RPC
        takes nft1 bech32 ids, so refs are resolved to launcher ids and
        re-encoded here (chia_sign.address_for_puzzle_hash). did_id None
        unassigns; otherwise it must be a did:chia: id we own.
        """
        rpc, fee = self._tx_intent_rpc(params)
        ids = params.get("nft_ids") or []
        if not isinstance(ids, list) or not all(
                isinstance(i, str) and i for i in ids):
            raise chia.SageError("nft_ids must be a non-empty string list")
        nft1_ids = []
        for i in ids:
            lid = _resolve_nft_launcher(rpc, i)
            if not lid:
                raise chia.SageError(
                    f"NFT {i[:16]}… is not in this wallet — refusing")
            nft1_ids.append(chia_sign.address_for_puzzle_hash(
                bytes.fromhex(lid), "nft"))
        did_id = params.get("did_id")
        if did_id is not None:
            if not (isinstance(did_id, str)
                    and did_id.startswith("did:chia:1")):
                raise chia.SageError(
                    "did_id must be a did:chia:1… address or null")
            # DidRecord.address is the did:chia:1… address form.
            owned_dids = {str(d.get("address") or "")
                          for d in rpc.get_dids()}
            if did_id not in owned_dids:
                raise chia.SageError(
                    f"DID {did_id[:20]}… is not in this wallet — refusing")
        t0 = time.time()
        res = rpc.assign_nfts_to_did(nft1_ids, did_id,
                                     fee_mojos=fee, auto_submit=True)
        return self._submit_sage_tx(
            rpc, res, t0,
            f"assigned {len(ids)} NFT(s) to DID")

    def _execute_did_create_via_sage(self, params: dict) -> dict:
        """Create an approved DID via Sage RPC (on-chain)."""
        rpc, fee = self._tx_intent_rpc(params)
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise chia.SageError("did_create needs a non-empty name")
        t0 = time.time()
        res = rpc.create_did(name, fee_mojos=fee, auto_submit=True)
        return self._submit_sage_tx(rpc, res, t0,
                                    f"created DID {name!r}")

    @staticmethod
    def _validated_did_ids(params: dict) -> list:
        """did:chia:1… ids, the wallet's canonical DID form (what
        /get_dids returns as launcher_id and /transfer_dids accepts)."""
        ids = params.get("did_ids") or []
        if not isinstance(ids, list) or not ids or not all(
                isinstance(i, str) and i.startswith("did:chia:1")
                for i in ids):
            raise chia.SageError(
                "did_ids must be a non-empty list of did:chia:1… ids")
        return list(ids)

    @staticmethod
    def _owned_did_ids(rpc) -> set:
        return {str(d.get("launcher_id") or "") for d in rpc.get_dids()}

    @staticmethod
    def _validated_option_ids(params: dict) -> list:
        """option1… ids, the wallet's canonical option form."""
        ids = params.get("option_ids") or []
        if not isinstance(ids, list) or not ids or not all(
                isinstance(i, str) and i.startswith("option1")
                for i in ids):
            raise chia.SageError(
                "option_ids must be a non-empty list of option1… ids")
        return list(ids)

    @staticmethod
    def _owned_option_ids(rpc) -> set:
        # OptionRecord.launcher_id is the canonical option id field.
        return {str(o.get("launcher_id") or "")
                for o in rpc.get_options(offset=0, limit=1000)}

    def _execute_did_transfer_via_sage(self, params: dict) -> dict:
        """Transfer approved DIDs via Sage RPC (on-chain).

        Every DID must still be in this wallet; the destination is the
        exact approved one (re-checked here, not trusted from the queue).
        """
        rpc, fee = self._tx_intent_rpc(params)
        ids = self._validated_did_ids(params)
        dest = params.get("destination")
        if not isinstance(dest, str) or not dest:
            raise chia.SageError("destination must be a non-empty string")
        owned = self._owned_did_ids(rpc)
        for i in ids:
            if i not in owned:
                raise chia.SageError(
                    f"DID {i[:20]}… is not in this wallet — refusing")
        t0 = time.time()
        res = rpc.transfer_dids(ids, dest, fee_mojos=fee,
                                clawback=params.get("clawback_at"),
                                auto_submit=True)
        out = self._submit_sage_tx(
            rpc, res, t0, f"transferred {len(ids)} DID(s) to {dest}")
        out["destination"] = dest
        return out

    def _execute_did_normalize_via_sage(self, params: dict) -> dict:
        """Normalize approved DID coins via Sage RPC (on-chain)."""
        rpc, fee = self._tx_intent_rpc(params)
        ids = self._validated_did_ids(params)
        owned = self._owned_did_ids(rpc)
        for i in ids:
            if i not in owned:
                raise chia.SageError(
                    f"DID {i[:20]}… is not in this wallet — refusing")
        t0 = time.time()
        res = rpc.normalize_dids(ids, fee_mojos=fee, auto_submit=True)
        return self._submit_sage_tx(
            rpc, res, t0, f"normalized {len(ids)} DID(s)")

    def _execute_option_mint_via_sage(self, params: dict) -> dict:
        """Mint an approved option contract via Sage RPC (on-chain).

        The underlying/strike legs are re-validated at execution; both
        assets must be native or 64-hex CAT ids. The mint gate
        (_check_mint_gate) runs before this is reached — execution
        requires the human's separately-opened gate, not just queue
        approval.
        """
        rpc, fee = self._tx_intent_rpc(params)
        for key in ("underlying", "strike"):
            leg = params.get(key) or {}
            aid = leg.get("asset_id")
            amt = leg.get("amount")
            if aid is not None and not _HEX64.fullmatch(str(aid)):
                raise chia.SageError(
                    f"option {key} asset_id must be a 64-hex CAT id")
            if not isinstance(amt, int) or amt <= 0:
                raise chia.SageError(
                    f"option {key} amount must be a positive integer")
        exp = params.get("expiration_seconds")
        if not isinstance(exp, int) or exp <= 0:
            raise chia.SageError(
                "expiration_seconds must be a positive unix timestamp")
        t0 = time.time()
        res = rpc.mint_option(exp, params["underlying"], params["strike"],
                              fee_mojos=fee, auto_submit=True)
        return self._submit_sage_tx(rpc, res, t0, "minted option contract")

    def _execute_option_transfer_via_sage(self, params: dict) -> dict:
        """Transfer approved options via Sage RPC (on-chain).

        Every option must still be in this wallet; the destination is
        the exact approved one.
        """
        rpc, fee = self._tx_intent_rpc(params)
        ids = self._validated_option_ids(params)
        dest = params.get("destination")
        if not isinstance(dest, str) or not dest:
            raise chia.SageError("destination must be a non-empty string")
        owned = self._owned_option_ids(rpc)
        for i in ids:
            if i not in owned:
                raise chia.SageError(
                    f"option {i[:16]}… is not in this wallet — refusing")
        t0 = time.time()
        res = rpc.transfer_options(ids, dest, fee_mojos=fee,
                                   clawback=params.get("clawback_at"),
                                   auto_submit=True)
        out = self._submit_sage_tx(
            rpc, res, t0, f"transferred {len(ids)} option(s) to {dest}")
        out["destination"] = dest
        return out

    def _execute_option_exercise_via_sage(self, params: dict) -> dict:
        """Exercise approved options via Sage RPC (on-chain)."""
        rpc, fee = self._tx_intent_rpc(params)
        ids = self._validated_option_ids(params)
        owned = self._owned_option_ids(rpc)
        for i in ids:
            if i not in owned:
                raise chia.SageError(
                    f"option {i[:16]}… is not in this wallet — refusing")
        t0 = time.time()
        res = rpc.exercise_options(ids, fee_mojos=fee,
                                   auto_submit=True)
        return self._submit_sage_tx(
            rpc, res, t0, f"exercised {len(ids)} option(s)")

    def _execute_cat_issue_via_sage(self, params: dict) -> dict:
        """Issue an approved CAT via Sage RPC (on-chain).

        This is token issuance. The six-gate rule is enforced by
        _check_mint_gate before this is reached: queue approval alone
        never authorizes issuance — the human must separately open the
        mint gate (mint_gate.json) with all six attestations. The daemon
        records the name, ticker, and amount in the ledger for the
        human to see.
        """
        rpc, fee = self._tx_intent_rpc(params)
        name = params.get("name")
        ticker = params.get("ticker")
        amount = params.get("amount_mojos")
        if not isinstance(name, str) or not name:
            raise chia.SageError("cat_issue needs a non-empty name")
        if not isinstance(ticker, str) or not ticker:
            raise chia.SageError("cat_issue needs a non-empty ticker")
        if not isinstance(amount, int) or amount <= 0:
            raise chia.SageError("amount_mojos must be a positive integer")
        t0 = time.time()
        res = rpc.issue_cat(name, ticker, amount,
                            revocable=bool(params.get("revocable", False)),
                            fee_mojos=fee, auto_submit=True)
        out = self._submit_sage_tx(
            rpc, res, t0,
            f"issued CAT {ticker} ({amount} mojos)")
        out["name"] = name
        out["ticker"] = ticker
        return out

    def _execute_clawback_finalize_via_sage(self, params: dict) -> dict:
        """Finalize an approved clawback via Sage RPC (on-chain)."""
        rpc, fee = self._tx_intent_rpc(params)
        ids = params.get("coin_ids") or []
        if not isinstance(ids, list) or not all(
                isinstance(i, str) and i for i in ids):
            raise chia.SageError("coin_ids must be a non-empty string list")
        t0 = time.time()
        res = rpc.finalize_clawback(list(ids), fee_mojos=fee,
                                    auto_submit=True)
        return self._submit_sage_tx(
            rpc, res, t0, f"finalized clawback of {len(ids)} coin(s)")

    def _execute_coin_combine_via_sage(self, params: dict) -> dict:
        """Combine approved coins via Sage RPC (on-chain)."""
        rpc, fee = self._tx_intent_rpc(params)
        ids = self._validated_coin_ids(params)
        t0 = time.time()
        res = rpc.combine(list(ids), fee_mojos=fee, auto_submit=True)
        return self._submit_sage_tx(
            rpc, res, t0, f"combined {len(ids)} coin(s)")

    def _execute_coin_split_via_sage(self, params: dict) -> dict:
        """Split approved coins via Sage RPC (on-chain)."""
        rpc, fee = self._tx_intent_rpc(params)
        ids = self._validated_coin_ids(params)
        n = params.get("output_count")
        if not isinstance(n, int) or n < 2:
            raise chia.SageError("output_count must be an integer >= 2")
        t0 = time.time()
        res = rpc.split(list(ids), n, fee_mojos=fee, auto_submit=True)
        return self._submit_sage_tx(
            rpc, res, t0, f"split {len(ids)} coin(s) into {n}")

    def _execute_coin_autocombine_via_sage(self, params: dict) -> dict:
        """Auto-combine approved small coins via Sage RPC (on-chain)."""
        rpc, fee = self._tx_intent_rpc(params)
        asset = params.get("asset", "native")
        max_coins = params.get("max_coins")
        if asset not in ("native",) and not _HEX64.fullmatch(
                str(asset or "")):
            raise chia.SageError(
                "coin_autocombine asset must be 'native' or a 64-hex CAT id")
        if not isinstance(max_coins, int) or max_coins < 2:
            raise chia.SageError("max_coins must be an integer >= 2")
        t0 = time.time()
        if asset == "native":
            res = rpc.auto_combine_xch(
                max_coins,
                max_coin_amount=params.get("max_coin_amount"),
                fee_mojos=fee, auto_submit=True)
        else:
            res = rpc.auto_combine_cat(
                str(asset).lower(), max_coins,
                max_coin_amount=params.get("max_coin_amount"),
                fee_mojos=fee, auto_submit=True)
        return self._submit_sage_tx(
            rpc, res, t0, f"auto-combined {asset} coins")

    @staticmethod
    def _validated_coin_ids(params: dict) -> list:
        ids = params.get("coin_ids") or []
        if not isinstance(ids, list) or not ids or not all(
                isinstance(i, str) and _HEX64.fullmatch(i) for i in ids):
            raise chia.SageError(
                "coin_ids must be a non-empty list of 64-hex coin ids")
        return [i.lower() for i in ids]

    def _execute_bulk_send_via_sage(self, params: dict) -> dict:
        """Bulk-send an approved batch via Sage RPC (on-chain).

        Re-validates every address and the exact amount at execution —
        the queue entry is never trusted blindly.
        """
        rpc, fee = self._tx_intent_rpc(params)
        kind, ref = chia_asset_kind(params.get("asset", "native"))
        if kind == "nft":
            raise chia.SageError("bulk_send does not support NFT assets")
        addrs = params.get("addresses") or []
        amount = params.get("amount_mojos")
        if not isinstance(addrs, list) or not addrs or not all(
                isinstance(a, str) and a for a in addrs):
            raise chia.SageError(
                "addresses must be a non-empty list of address strings")
        if not isinstance(amount, int) or amount <= 0:
            raise chia.SageError("amount_mojos must be a positive integer")
        memos = params.get("memos") or []
        if not isinstance(memos, list):
            raise chia.SageError("memos must be a list")
        t0 = time.time()
        if kind == "native":
            res = rpc.bulk_send_xch(list(addrs), amount, fee_mojos=fee,
                                    memos=memos, auto_submit=True)
        else:
            res = rpc.bulk_send_cat(ref, list(addrs), amount,
                                    fee_mojos=fee, memos=memos,
                                    auto_submit=True)
        out = self._submit_sage_tx(
            rpc, res, t0,
            f"bulk-sent {amount} mojos to {len(addrs)} address(es)")
        out["addresses"] = list(addrs)
        return out

    def _execute_multi_send_via_sage(self, params: dict) -> dict:
        """Multi-send approved mixed-asset payments via Sage RPC (on-chain).

        Every payment's asset/address/amount is re-validated at
        execution against the queued intent.
        """
        rpc, fee = self._tx_intent_rpc(params)
        pays = params.get("payments") or []
        if not isinstance(pays, list) or not pays:
            raise chia.SageError("payments must be a non-empty list")
        norm = []
        for pay in pays:
            if not isinstance(pay, dict):
                raise chia.SageError("each payment must be an object")
            aid = pay.get("asset_id")
            amt = pay.get("amount")
            addr = pay.get("address")
            if aid is not None and not _HEX64.fullmatch(str(aid)):
                raise chia.SageError(f"bad payment asset_id {aid!r}")
            if not isinstance(amt, int) or amt <= 0:
                raise chia.SageError(
                    "each payment amount must be a positive integer")
            if not isinstance(addr, str) or not addr:
                raise chia.SageError(
                    "each payment needs a non-empty address")
            memos = pay.get("memos") or []
            if not isinstance(memos, list):
                raise chia.SageError("payment memos must be a list")
            norm.append({"asset_id": str(aid).lower() if aid else None,
                         "address": addr, "amount": amt, "memos": memos})
        t0 = time.time()
        res = rpc.multi_send(norm, fee_mojos=fee, auto_submit=True)
        out = self._submit_sage_tx(
            rpc, res, t0, f"multi-sent {len(norm)} payment(s)")
        out["payments"] = norm
        return out

    def _execute_message_sign_via_sage(self, params: dict) -> dict:
        """Sign an approved message via Sage RPC (off-chain).

        No funds move, but the signature is a capability: the message
        and the signing identity are exactly what the human approved,
        verified here before signing. Returns the signature — never the
        key. Nothing is broadcast, so submitted=False and no velocity is
        recorded.
        """
        chain = params["chain"]
        self._chia_offer_guards(params, chain)
        rpc, _, _ = self._chia_sage_rpc(chain)
        message = params.get("message")
        if not isinstance(message, str) or not message:
            raise chia.SageError("message_sign needs a non-empty message")
        addr = params.get("address")
        pkey = params.get("public_key")
        if addr and pkey:
            raise chia.SageError(
                "message_sign takes address OR public_key, not both")
        if addr:
            res = rpc.sign_message_by_address(addr, message)
            who = addr
        elif pkey:
            res = rpc.sign_message_with_public_key(pkey, message)
            who = pkey
        else:
            raise chia.SageError(
                "message_sign needs address or public_key")
        sig = (res or {}).get("signature")
        if not sig:
            raise chia.SageError("Sage returned no signature")
        return {"submitted": False, "signature": sig, "signed_by": who,
                "note": f"signed message as {who[:24]}…"}

    def _execute_message_sign(self, params: dict) -> dict:
        """Single dispatch point for off-chain message signing (SPEC §10).

        Chain family decides the signer: Chia signs via Sage RPC (the only
        path that touches a live wallet), EVM and Solana sign locally with
        the daemon's own derived keys. The request-time chain/sign_type
        gating is the first layer; membership checks here are the second.
        Nothing is broadcast: every path returns submitted=False and no
        velocity is recorded. Raises on any failure — a refused signature
        records nothing.
        """
        chain = params.get("chain", "")
        if chain in chia.NETWORKS:
            return self._execute_message_sign_via_sage(params)
        if chain in solana_mod.NETWORKS:
            return self._execute_message_sign_solana(params)
        if chain in evm.CHAINS:
            return self._execute_message_sign_evm(params)
        return {"submitted": False,
                "note": f"message signing not configured for {chain!r}"}

    @staticmethod
    def _verify_sign_identity_evm(params: dict, priv: bytes,
                                  addr: str) -> str:
        """Re-verify the approved signing identity against the daemon's key.

        The human approved a specific identity; execution refuses unless the
        requested address (case-insensitive) or public key (uncompressed
        secp256k1 hex, 04 prefix optional, 0x prefix optional) matches the
        key being signed with. Returns the canonical identity string.
        """
        req_addr = params.get("address")
        req_pk = params.get("public_key")
        if req_addr and req_pk:
            raise evm.EvmError(
                "message_sign takes address OR public_key, not both")
        if req_addr:
            if not isinstance(req_addr, str) or req_addr.lower() != addr.lower():
                raise evm.EvmError(
                    "requested signing address does not match the daemon's "
                    "EVM key for this chain — refusing")
            return addr
        if req_pk:
            if not isinstance(req_pk, str):
                raise evm.EvmError("public_key must be a string")
            norm = req_pk.lower().removeprefix("0x")
            if len(norm) == 128:  # 04 prefix omitted
                norm = "04" + norm
            derived = spellsign.secp256k1_pubkey_uncompressed_hex(priv)
            if norm != derived:
                raise evm.EvmError(
                    "requested signing public key does not match the "
                    "daemon's EVM key for this chain — refusing")
            return addr
        raise evm.EvmError("message_sign needs address or public_key")

    def _execute_message_sign_evm(self, params: dict) -> dict:
        """Sign an approved message with the daemon's EVM key (off-chain).

        sign_type is personal (EIP-191) or typed_data (EIP-712). The
        preimage/digest is built from the approved message inside sign.py
        (P1) — never from caller-supplied raw bytes. For typed_data the
        envelope's domain.chainId must equal the signing chain's id, or the
        signature is refused: the human approved signing for THIS chain.
        """
        chain = params["chain"]
        if chain not in evm.CHAINS:
            raise evm.EvmError(f"unknown EVM chain: {chain!r}")
        sign_type = params.get("sign_type", "plain")
        if sign_type not in ("personal", "typed_data"):
            raise evm.EvmError(
                f"sign_type {sign_type!r} not supported for EVM chains")
        priv, addr = self._evm_key(chain)
        who = self._verify_sign_identity_evm(params, priv, addr)
        message = params.get("message")
        if not isinstance(message, str) or not message:
            raise evm.EvmError("message_sign needs a non-empty message")
        if sign_type == "personal":
            sig65 = spellsign.evm_personal_sign(priv, message)
        else:
            try:
                typed = json.loads(message)
            except (json.JSONDecodeError, TypeError) as e:
                raise evm.EvmError(
                    f"typed_data message is not valid JSON: {e}")
            if not isinstance(typed, dict):
                raise evm.EvmError(
                    "typed_data message must be a JSON object")
            try:
                domain_chain_id = int((typed.get("domain") or {}).get(
                    "chainId"))
            except (TypeError, ValueError):
                raise evm.EvmError(
                    "typed_data domain.chainId must be an integer")
            expected = int(chain.split("-", 1)[1])
            if domain_chain_id != expected:
                raise evm.EvmError(
                    f"typed_data domain chainId {domain_chain_id} does not "
                    f"match signing chain {chain} — refusing")
            try:
                sig65 = spellsign.evm_sign_typed_data(priv, typed)
            except ValueError as e:
                raise evm.EvmError(f"bad typed_data envelope: {e}")
        return {"submitted": False, "signature": "0x" + sig65.hex(),
                "signed_by": who, "sign_type": sign_type,
                "note": f"signed {sign_type} message as {who[:10]}…"}

    @staticmethod
    def _verify_sign_identity_solana(params: dict, kp) -> str:
        """Re-verify the approved signing identity against the keypair.

        The human approved a specific identity; execution refuses unless the
        requested address equals the keypair's address, or the requested
        public key (base58 or hex) equals the keypair's public key.
        """
        req_addr = params.get("address")
        req_pk = params.get("public_key")
        if req_addr and req_pk:
            raise solana_mod.SolanaError(
                "message_sign takes address OR public_key, not both")
        expected = solana_mod.address_of_keypair(kp)
        if req_addr:
            if not isinstance(req_addr, str) or req_addr != expected:
                raise solana_mod.SolanaError(
                    "requested signing address does not match the daemon's "
                    "Solana keypair for this chain — refusing")
            return expected
        if req_pk:
            if not isinstance(req_pk, str):
                raise solana_mod.SolanaError("public_key must be a string")
            pub32 = solana_mod.pubkey_bytes(kp)
            if req_pk != solana_mod.b58encode(pub32) \
                    and req_pk.lower() != pub32.hex():
                raise solana_mod.SolanaError(
                    "requested signing public key does not match the "
                    "daemon's Solana keypair for this chain — refusing")
            return expected
        raise solana_mod.SolanaError("message_sign needs address or public_key")

    def _execute_message_sign_solana(self, params: dict) -> dict:
        """Sign an approved message with the daemon's Solana keypair.

        Solana plain messages have no envelope: the 64-byte ed25519
        signature covers the raw UTF-8 message bytes (base58 in the
        response). The signing identity is re-verified before signing.
        """
        chain = params["chain"]
        if chain not in solana_mod.NETWORKS:
            raise solana_mod.SolanaError(f"unknown Solana chain: {chain!r}")
        if params.get("sign_type", "plain") != "plain":
            raise solana_mod.SolanaError(
                f"sign_type {params.get('sign_type')!r} not supported for "
                "Solana chains")
        kp = self._solana_keypair(chain)
        who = self._verify_sign_identity_solana(params, kp)
        message = params.get("message")
        if not isinstance(message, str) or not message:
            raise solana_mod.SolanaError(
                "message_sign needs a non-empty message")
        sig64 = spellsign.solana_sign_message(kp, message.encode("utf-8"))
        return {"submitted": False,
                "signature": solana_mod.b58encode(sig64),
                "signed_by": who, "sign_type": "plain",
                "note": f"signed message as {who[:10]}…"}

    def _wait_pending_tx(self, rpc, tx_id: str, timeout_s: int) -> bool:
        """True when tx_id shows up in Sage's pending transactions."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            for tx in rpc.get_pending_transactions():
                if str(tx.get("transaction_id") or tx.get("id")) == tx_id:
                    return True
            time.sleep(5)
        return False

    def _sage_wait_timeout_s(self) -> int:
        """Seconds to wait for the outgoing transaction to appear in
        Sage's /get_transactions after a send. Configurable via
        ``chia.sage_wait_timeout_s`` (default 180). After the window the
        spend is recorded as approved-submit-unknown — never retried."""
        try:
            return int(self.chia_cfg.get("sage_wait_timeout_s", 180))
        except (TypeError, ValueError):
            return 180

    def _execute_chia_spend_via_sage(self, params: dict) -> dict:
        """Build, sign, and submit an approved XCH transfer via Sage RPC.

        Flow: switch Sage to the right network, ensure the KDF-derived BLS
        key is imported (verifying the fingerprint locally — never trusting
        the RPC's word for which key it imported), log in, send via
        /send_xch with auto_submit, then confirm the outgoing transaction
        appears in /get_transactions paying our destination our amount.

        Returns {"submitted": True, "tx_hash": <created coin id>, ...} where
        the coin id is the stable ledger reference (Sage's transaction
        records carry height/timestamp, not a bundle hash). Raises
        chia.SageError on any failure — a spend that never left the machine
        records nothing and consumes no velocity.
        """
        kind, ref = chia_asset_kind(params.get("asset", "native"))
        if kind == "cat":
            return self._execute_chia_cat_spend_via_sage(params, ref)
        if kind == "nft":
            return self._execute_chia_nft_spend_via_sage(params, ref)
        chain = params["chain"]
        network, dest, amount = self._chia_sage_guards(params, chain)
        rpc, _, sender = self._chia_sage_rpc(chain)
        fee = int(self.chia_cfg.get("fee_mojos", 0))
        bal = chia.amount_to_int(rpc.sync_status()["selectable_balance"])
        if bal < amount + fee:
            raise chia.SageError(
                f"insufficient selectable balance: have {bal} mojos, "
                f"need {amount + fee}")
        t0 = time.time()
        rpc.send_xch(dest, amount, fee,
                     memos=[str(params.get("purpose", ""))[:64]])
        # The approved intent, re-checked against the on-wallet transaction
        # record: destination and amount must match what was approved.
        tx = chia.wait_for_outgoing(rpc, dest, amount, t0,
                                    timeout_s=self._sage_wait_timeout_s())
        coin_id = None
        for coin in tx.get("created", []):
            if ((coin.get("address") or "").lower() == dest.lower()
                    and chia.amount_to_int(coin.get("amount")) == amount):
                coin_id = coin.get("coin_id")
                break
        if not coin_id:
            raise chia.SageError(
                "outgoing transaction found but no created coin matches the "
                "approved destination+amount — refusing to report success")
        return {"submitted": True, "tx_hash": coin_id,
                "coin_id": coin_id, "from": sender,
                "tx_height": tx.get("height")}

    def rt_request_spend(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        amounts = fields & AMOUNT_FIELDS
        if (not fields.issubset(SPEND_FIELDS | AMOUNT_FIELDS)
                or "chain" not in p or len(amounts) != 1):
            return {"ok": False, "error": "schema violation: v1 is plain transfers only"}
        # Solana network-mismatch is a hard error at request time: a
        # devnet-configured daemon asked to touch mainnet-beta (or vice
        # versa) refuses before any policy evaluation or queueing. The
        # execute-time check in _execute_solana_spend is the second layer
        # (it also guards the queue-approve path if config changed
        # between queueing and approval).
        if p["chain"] in solana_mod.NETWORKS:
            try:
                active = self._active_solana_chain()
            except solana_mod.SolanaError as e:
                return {"ok": False, "error": str(e)}
            if p["chain"] != active:
                return {"ok": False, "error":
                        f"network mismatch: daemon is configured for {active}, "
                        f"refusing {p['chain']}"}
        amount = p.get("amount_mojos", p.get("amount_wei", p.get("amount_lamports")))
        if not isinstance(amount, int) or amount <= 0:
            return {"ok": False, "error": "amount must be a positive integer in base units"}
        # Note: contract-call-shaped requests never reach here — "calldata"/"data"
        # are not in the v1 schema, so they fail the subset check above (S13).
        asset = p.get("asset", "native")
        if p["chain"] in chia.NETWORKS:
            # Chia asset model (SPEC §3b): the asset field is a routing signal.
            # Malformed assets fail closed here; NFT transfers carry amount 1
            # (the NFT is a singleton — anything else is schema misuse).
            try:
                kind, _ = chia_asset_kind(asset)
            except chia.SageError as e:
                return {"ok": False, "error": str(e)}
            if kind == "nft" and p.get("amount_mojos") != 1:
                return {"ok": False, "error":
                        "NFT transfer amount must be 1 (singleton asset)"}
        d = evaluate(self.policy, p["chain"], asset,
                     amount, p.get("destination", ""),
                     self.spent_last_24h(p["chain"], asset))
        canon = json.dumps(p, sort_keys=True).encode()
        if d.verdict == "queued":
            qid = str(self.next_qid); self.next_qid += 1
            self.queue[qid] = {"params": p, "muse_id": muse_id,
                               "queued_at": time.time()}
            self._save_queue()
            self.ledger.append(muse_id, canon, None, f"queued:{qid}")
            return {"ok": True, "decision": "queued", "queue_id": qid,
                    "reason": d.reason}
        if d.verdict == "denied":
            self.ledger.append(muse_id, canon, None, "denied:" + d.reason)
            return {"ok": True, "decision": "denied", "reason": d.reason}
        # Pre-execution intent line: if the process dies between here and the
        # outcome line below, the ledger still records that this spend was
        # executing. The human reconciles by canon_digest before any
        # re-request (a blind retry could double-spend).
        self.ledger.append(muse_id, canon, None, "executing")
        try:
            ex = self._execute_spend(p)
        except (evm.BroadcastUnknown, chia.BroadcastUnknown,
                chia_relay.BroadcastUnknown, solana_mod.BroadcastUnknown) as e:
            # The spend left the machine; its fate is unknown. Ledger the
            # reference as unresolved and consume velocity fail-closed
            # (assume it lands — a cap that undercounts is a broken cap).
            # The human reconciles the hash on-chain before re-requesting.
            # Solana's BroadcastUnknown carries .signature instead of
            # .tx_hash — check both before the generic .reference.
            ref = (getattr(e, "tx_hash", None) or getattr(e, "signature", None)
                   or getattr(e, "reference", None))
            self._record_velocity_entries(p)
            self.ledger.append(muse_id, canon, ref,
                               "approved-submit-unknown:" + str(e))
            return {"ok": True, "decision": "approved-submit-unknown",
                    "tx_hash": ref, "note": str(e)}
        except (evm.EvmError, chia.SageError, chia_relay.RelayError,
                solana_mod.SolanaError, dex_mod.DexError) as e:
            self.ledger.append(muse_id, canon, None,
                               "approved-submit-failed:" + str(e))
            return {"ok": False, "decision": "approved-submit-failed",
                    "error": str(e)}
        self._record_velocity_entries(p)
        if ex["submitted"]:
            self.ledger.append(muse_id, canon, ex["tx_hash"], "approved")
            return {"ok": True, "decision": "approved",
                    "tx_hash": ex["tx_hash"],
                    "block": ex.get("block", ex.get("tx_height", ex.get("slot")))}
        self.ledger.append(muse_id, canon, None, "approved")
        return {"ok": True, "decision": "approved", "note": ex["note"]}

    # ------------------------------------------------------------ DEX intents
    def _validate_dex_swap(self, p: dict) -> dict:
        """Schema + bounds validation for a dex_swap intent. Returns the
        normalized intent or raises evm.EvmError (fail closed)."""
        fields = set(p)
        if not fields.issubset(SWAP_FIELDS) or "intent" not in p:
            raise evm.EvmError(
                "schema violation: unknown dex_swap fields rejected")
        if p.get("intent") != "dex_swap":
            raise evm.EvmError("schema violation: intent != dex_swap")
        chain = p.get("chain")
        if chain not in evm.CHAINS:
            raise evm.EvmError(f"unknown EVM chain: {chain!r}")
        venue = p.get("venue")
        try:
            venue = dex_mod.normalize_venue(venue)
        except dex_mod.DexError as e:
            raise evm.EvmError(f"schema violation: {e}")
        # The recommended-venue list is advisory, not a gate: a venue
        # outside it is queued with a prominent warning, and the human's
        # per-transaction approval is what authorizes the venue. Every
        # agent's human approves their own venues.
        venue_warning = None
        if venue not in self._dex_recommended_set:
            venue_warning = (
                f"venue {venue!r} is not on your recommended venue list "
                f"({', '.join(self.dex_recommended_venues)}). It is not "
                "blocked: approving this swap authorizes the venue for "
                "this transaction. To stop seeing this warning, add it to "
                "dex.recommended_venues in spellbook.json and restart the "
                "daemon.")
        chain_id = evm.CHAINS[chain]["chain_id"]
        if not dex_mod.venue_serves_chain(venue, chain_id):
            raise evm.EvmError(
                f"venue {venue!r} does not serve {chain} "
                f"(chain id {chain_id}) — refusing")
        sell = p.get("sell_token", "")
        buy = p.get("buy_token", "")
        for tok, what in ((sell, "sell_token"), (buy, "buy_token")):
            if tok != dex_mod.NATIVE_SENTINEL and not evm.is_address(tok):
                raise evm.EvmError(f"bad {what} address: {tok!r}")
        if sell.lower() == buy.lower():
            raise evm.EvmError("sell_token == buy_token — refusing")
        for k in ("sell_amount_wei", "min_buy_amount_wei"):
            v = p.get(k)
            if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                raise evm.EvmError(f"{k} must be a positive int in base units")
        sl = p.get("max_slippage_bps")
        if isinstance(sl, bool) or not isinstance(sl, int) \
                or not (1 <= sl <= 500):
            raise evm.EvmError("max_slippage_bps must be an int 1..500")
        dl = p.get("deadline_sec")
        if dl is not None and (not isinstance(dl, int) or dl <= 0):
            raise evm.EvmError("deadline_sec must be a positive unix timestamp")
        return {"intent": "dex_swap", "chain": chain, "venue": venue,
                "venue_warning": venue_warning,
                "sell_token": sell, "buy_token": buy,
                "sell_amount_wei": p["sell_amount_wei"],
                "min_buy_amount_wei": p["min_buy_amount_wei"],
                "max_slippage_bps": sl, "purpose": p.get("purpose", ""),
                "deadline_sec": dl,
                "chain_id": chain_id}

    def _validate_dex_lp_add(self, p: dict) -> dict:
        """Schema + bounds validation for a dex_lp_add intent."""
        fields = set(p)
        if not fields.issubset(LP_ADD_FIELDS) or "intent" not in p:
            raise evm.EvmError(
                "schema violation: unknown dex_lp_add fields rejected")
        if p.get("intent") != "dex_lp_add":
            raise evm.EvmError("schema violation: intent != dex_lp_add")
        chain = p.get("chain")
        if chain not in evm.CHAINS:
            raise evm.EvmError(f"unknown EVM chain: {chain!r}")
        protocol = p.get("protocol")
        if protocol not in ("v2", "v3"):
            raise evm.EvmError(
                f"protocol must be 'v2' or 'v3', got {protocol!r}")
        router = p.get("router", "")
        if not evm.is_address(router):
            raise evm.EvmError(f"bad router address: {router!r}")
        tok_a, tok_b = p.get("token_a", ""), p.get("token_b", "")
        for tok, what in ((tok_a, "token_a"), (tok_b, "token_b")):
            if not evm.is_address(tok):
                raise evm.EvmError(f"bad {what} address: {tok!r}")
        if tok_a.lower() == tok_b.lower():
            raise evm.EvmError("token_a == token_b — refusing")
        for k in ("amount_a_wei", "amount_b_wei"):
            v = p.get(k)
            if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                raise evm.EvmError(f"{k} must be a positive int in base units")
        for k in ("amount_a_min_wei", "amount_b_min_wei"):
            v = p.get(k)
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise evm.EvmError(f"{k} must be a non-negative int")
        if p["amount_a_min_wei"] > p["amount_a_wei"] or \
                p["amount_b_min_wei"] > p["amount_b_wei"]:
            raise evm.EvmError("min amounts exceed desired amounts — refusing")
        fee, tl, tu = p.get("fee"), p.get("tick_lower"), p.get("tick_upper")
        if protocol == "v3":
            if fee not in (100, 500, 3000, 10000):
                raise evm.EvmError("v3 fee must be one of 100/500/3000/10000")
            if not isinstance(tl, int) or not isinstance(tu, int) or tl >= tu:
                raise evm.EvmError("tick_lower must be < tick_upper")
        elif fee is not None or tl is not None or tu is not None:
            raise evm.EvmError("fee/ticks are v3-only fields")
        dl = p.get("deadline_sec")
        if dl is not None and (not isinstance(dl, int) or dl <= 0):
            raise evm.EvmError("deadline_sec must be a positive unix timestamp")
        return {"intent": "dex_lp_add", "chain": chain,
                "protocol": protocol, "router": router,
                "token_a": tok_a, "token_b": tok_b,
                "amount_a_wei": p["amount_a_wei"],
                "amount_b_wei": p["amount_b_wei"],
                "amount_a_min_wei": p["amount_a_min_wei"],
                "amount_b_min_wei": p["amount_b_min_wei"],
                "fee": fee, "tick_lower": tl, "tick_upper": tu,
                "purpose": p.get("purpose", ""), "deadline_sec": dl,
                "chain_id": evm.CHAINS[chain]["chain_id"]}

    def rt_dex_swap(self, p: dict, muse_id: str) -> dict:
        """Queue/approve/deny/execute path for a bounded swap intent."""
        intent = self._validate_dex_swap(p)
        asset = ("native" if intent["sell_token"] == dex_mod.NATIVE_SENTINEL
                 else intent["sell_token"].lower())
        entries = [(intent["chain"], asset, intent["sell_amount_wei"])]
        return self._run_fund_intent(intent, muse_id, entries, "dex_swap")

    def rt_dex_lp_add(self, p: dict, muse_id: str) -> dict:
        """Queue/approve/deny/execute path for a bounded LP-add intent."""
        intent = self._validate_dex_lp_add(p)
        entries = [(intent["chain"], intent["token_a"].lower(),
                    intent["amount_a_wei"]),
                   (intent["chain"], intent["token_b"].lower(),
                    intent["amount_b_wei"])]
        return self._run_fund_intent(intent, muse_id, entries, "dex_lp_add")

    def rt_dex_venues(self, p: dict, muse_id: str) -> dict:
        """Read-only: the user's recommended swap venues (SPEC §10 v2).

        No funds move; this reports the venue recommendation list. The
        list is advisory — a dex_swap naming another venue is queued
        with a warning, and the human's per-transaction approval is what
        authorizes the venue. The list comes from dex.recommended_venues
        in spellbook.json (default: matcha + uniswap) and takes effect
        on daemon restart.
        """
        return {
            "recommended_venues": list(self.dex_recommended_venues),
            "known_venues": {
                v: {"env_key": dex_mod.VENUE_ENV_KEYS[v],
                    "chain_ids": sorted(dex_mod.VENUE_CHAINS[v])}
                for v in dex_mod.KNOWN_VENUES
            },
            "note": ("the list is a recommendation, not a gate: other "
                     "venues trigger a warning on the queued intent and "
                     "your approval authorizes them. To change the list, "
                     "set dex.recommended_venues in spellbook.json (0600, "
                     "daemon-user-owned) and restart the daemon"),
        }

    # ------------------------------------------------------------ offer intents
    def _chia_offer_guards(self, params: dict, chain: str) -> None:
        """Fail-fast checks shared by every offer intent.

        Mainnet-without-flag and missing-seed refuse exactly like the
        transfer path. There is no destination to prefix-check — offers
        name assets, not addresses.
        """
        if chain == "chia-mainnet" and not self.chia_cfg.get(
                "mainnet_submit_enabled"):
            raise chia.SageError(
                "mainnet submission refused for chia-mainnet — needs the "
                "separately-authorized mainnet_submit_enabled flag (§10.14-17)")
        if self._signing_seed() is None:
            raise chia.SageError("no seed configured — cannot sign")
        fee = params.get("fee_mojos", 0)
        if not isinstance(fee, int) or fee < 0:
            raise chia.SageError("fee_mojos must be a non-negative integer")

    def _check_offer_balances(self, rpc, legs: list, fee_mojos: int) -> None:
        """Fail closed when the wallet cannot fund the offer's give side.

        legs are (asset, amount) with asset "native", 64-hex CAT, or
        "nft:<launcher-id>". NFT legs are verified by ownership (the NFT
        must still be in the wallet), not by a fungible balance.
        """
        xch_need = fee_mojos
        nft_launchers = [a[4:] for a, _ in legs if a.startswith("nft:")]
        if nft_launchers:
            owned = {str(n.get("launcher_id") or "").lower()
                     for n in rpc.get_nfts(offset=0, limit=1000)}
            for lid in nft_launchers:
                if lid.lower() not in owned:
                    raise chia.SageError(
                        f"offered NFT {lid[:16]}… is no longer in this "
                        "wallet — refusing")
        for asset, amount in legs:
            if asset == "native":
                xch_need += amount
            elif asset.startswith("nft:"):
                continue
            else:
                bal = chia.cat_balance(rpc, asset)
                if bal < amount:
                    raise chia.SageError(
                        f"insufficient CAT balance: have {bal} mojos of "
                        f"{asset[:16]}…, need {amount}")
        if xch_need:
            bal = chia.amount_to_int(rpc.sync_status()["selectable_balance"])
            if bal < xch_need:
                raise chia.SageError(
                    f"insufficient XCH balance: have {bal} mojos, need "
                    f"{xch_need}")

    def _decide_fund_intent(self, entries: list) -> tuple:
        """Policy over each (chain, asset, amount) leg of a fund-moving intent.

        Any denied leg denies the intent; any queued leg queues it; all
        approved executes. Destination is "" — offers name no destination,
        so a configured destination allowlist denies them fail-closed.
        """
        queued_reasons = []
        for (chain, asset, amount) in entries:
            d = evaluate(self.policy, chain, asset, amount, "",
                         self.spent_last_24h(chain, asset))
            if d.verdict == "denied":
                return ("denied", d.reason)
            if d.verdict == "queued":
                queued_reasons.append(f"{asset}: {d.reason}")
        if queued_reasons:
            return ("queued", "; ".join(queued_reasons))
        return ("approved", "within policy")

    def _velocity_entries(self, params: dict) -> list:
        """(chain, asset, amount) legs whose movement counts toward velocity.

        Transfers keep today's single-leg shape. offer_make counts the
        encumbered offered legs; offer_take counts what we give (the
        request-time _give legs, re-verified at execution); offer_cancel
        counts nothing — the coins return to the wallet and the make
        already counted them. Mint/DID/option/coin-op intents count the
        fee leg (native) plus any asset the wallet gives up: option_mint
        counts the underlying leg, bulk_send and multi_send count every
        payment leg. message_sign moves nothing and counts nothing.
        """
        intent = params.get("intent")
        chain = params["chain"]
        if intent == "offer_make":
            return [(chain, it["asset"], it["amount_mojos"])
                    for it in params["offered"]]
        if intent == "offer_take":
            return [(chain, it["asset"], it["amount_mojos"])
                    for it in params["_give"]]
        if intent in ("offer_cancel", "message_sign"):
            return []
        if intent == "dex_swap":
            asset = params.get("sell_token", "")
            a = "native" if asset == dex_mod.NATIVE_SENTINEL else asset.lower()
            return [(chain, a, params["sell_amount_wei"])]
        if intent == "dex_lp_add":
            return [(chain, params["token_a"].lower(), params["amount_a_wei"]),
                    (chain, params["token_b"].lower(), params["amount_b_wei"])]
        fee = params.get("fee_mojos", 0)
        if intent == "option_mint":
            leg = params.get("underlying") or {}
            aid = leg.get("asset_id")
            a = aid.lower() if aid else "native"
            amt = leg.get("amount", 0)
            if a == "native":
                return [(chain, "native", fee + amt)]
            return [(chain, "native", fee), (chain, a, amt)]
        if intent == "bulk_send":
            asset = params.get("asset", "native")
            kind, ref = chia_asset_kind(asset)
            a = "native" if kind == "native" else ref
            total = len(params.get("addresses") or []) * params.get(
                "amount_mojos", 0)
            if a == "native":
                # One merged native entry — evaluate() is per-entry, so
                # separate amount and fee entries would under-count.
                return [(chain, "native", total + fee)]
            return [(chain, a, total), (chain, "native", fee)]
        if intent == "multi_send":
            # Merge per asset (same reason as bulk_send) so a mixed batch
            # is evaluated at its true total per asset.
            totals: dict = {}
            for pay in params.get("payments") or []:
                aid = pay.get("asset_id")
                a = aid.lower() if aid else "native"
                totals[a] = totals.get(a, 0) + pay.get("amount", 0)
            totals["native"] = totals.get("native", 0) + fee
            return [(chain, a, t) for a, t in totals.items()]
        asset = params.get("asset", "native")
        amount = params.get("amount_mojos", params.get("amount_wei",
                            params.get("amount_lamports")))
        if intent in ("nft_mint", "nft_assign_did", "did_create",
                      "did_transfer", "did_normalize", "option_transfer",
                      "option_exercise", "cat_issue", "clawback_finalize",
                      "coin_combine", "coin_split", "coin_autocombine"):
            return [(chain, "native", fee)]
        return [(chain, asset, amount)]

    def _record_velocity_entries(self, params: dict) -> None:
        for (chain, asset, amount) in self._velocity_entries(params):
            self._record_velocity(chain, asset, amount)

    def _run_fund_intent(self, params: dict, muse_id: str, entries: list,
                         kind: str) -> dict:
        """Shared queue/approve/deny/execute path for fund-moving intents.

        Mirrors rt_request_spend's ledger discipline: queued/denied lines,
        the pre-execution "executing" line, unknown-fate handling that
        consumes velocity fail-closed, and per-leg velocity on success.
        """
        canon = json.dumps(params, sort_keys=True).encode()
        verdict, reason = self._decide_fund_intent(entries)
        if verdict == "queued":
            qid = str(self.next_qid); self.next_qid += 1
            self.queue[qid] = {"params": params, "muse_id": muse_id,
                               "queued_at": time.time()}
            self._save_queue()
            self.ledger.append(muse_id, canon, None, f"queued:{qid}")
            return {"ok": True, "decision": "queued", "queue_id": qid,
                    "reason": reason}
        if verdict == "denied":
            self.ledger.append(muse_id, canon, None, "denied:" + reason)
            return {"ok": True, "decision": "denied", "reason": reason}
        self.ledger.append(muse_id, canon, None, "executing")
        try:
            ex = self._execute_spend(params)
        except (evm.BroadcastUnknown, chia.BroadcastUnknown,
                chia_relay.BroadcastUnknown, solana_mod.BroadcastUnknown) as e:
            ref = (getattr(e, "tx_hash", None) or getattr(e, "signature", None)
                   or getattr(e, "reference", None))
            self._record_velocity_entries(params)
            self.ledger.append(muse_id, canon, ref,
                               "approved-submit-unknown:" + str(e))
            return {"ok": True, "decision": "approved-submit-unknown",
                    "tx_hash": ref, "note": str(e)}
        except (evm.EvmError, chia.SageError, chia_relay.RelayError,
                solana_mod.SolanaError, dex_mod.DexError) as e:
            self.ledger.append(muse_id, canon, None,
                               "approved-submit-failed:" + str(e))
            return {"ok": False, "decision": "approved-submit-failed",
                    "error": str(e)}
        self._record_velocity_entries(params)
        if ex.get("submitted"):
            self.ledger.append(muse_id, canon, ex["tx_hash"], "approved")
            out = {"ok": True, "decision": "approved",
                   "tx_hash": ex["tx_hash"],
                   "block": ex.get("block", ex.get("tx_height", ex.get("slot")))}
            # DEX executions may include exact-amount approval txs as part
            # of the single approved execution — surface them for audit.
            if ex.get("approve_tx_hash"):
                out["approve_tx_hash"] = ex["approve_tx_hash"]
            if ex.get("approve_tx_hashes"):
                out["approve_tx_hashes"] = ex["approve_tx_hashes"]
            if ex.get("buy_amount_wei") is not None:
                out["buy_amount_wei"] = ex["buy_amount_wei"]
            return out
        self.ledger.append(muse_id, canon, ex.get("offer_id"), "approved")
        out = {"ok": True, "decision": "approved", "note": ex.get("note", "")}
        if ex.get("offer_id"):
            out["offer_id"] = ex["offer_id"]
        if ex.get("offer"):
            out["offer"] = ex["offer"]
        return out

    def rt_offer_make(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(OFFER_MAKE_FIELDS) or "chain" not in p
                or "offered" not in p or "requested" not in p):
            return {"ok": False,
                    "error": "schema violation: offer_make needs chain, "
                             "offered[], requested[]"}
        chain = p["chain"]
        if chain not in chia.NETWORKS:
            return {"ok": False,
                    "error": f"offer_make is Chia-only, got {chain!r}"}
        try:
            self._chia_offer_guards(p, chain)
            offered = _validate_offer_legs(p["offered"], "offered")
            requested = _validate_offer_legs(p["requested"], "requested")
            expires = p.get("expires_at_second")
            if expires is not None and (
                    not isinstance(expires, int) or expires <= 0):
                raise chia.SageError(
                    "expires_at_second must be a positive unix timestamp")
            recv = p.get("receive_address")
            if recv is not None and not isinstance(recv, str):
                raise chia.SageError("receive_address must be a string")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        # All-native-XCH legs take the native offer path (local build,
        # relay chain data — Sage is never consulted). Anything else
        # keeps the existing Sage flow.
        if all(a == "native" for a, _ in offered + requested):
            return self._rt_offer_make_native(p, chain, offered, requested,
                                              muse_id)
        try:
            # NFT legs resolve to launcher ids now, so the queued intent
            # the human approves names the exact NFT (and fails fast when
            # the NFT is not in this wallet).
            rpc, _, _ = self._chia_sage_rpc(chain)
            offered = _resolve_offer_nft_legs(rpc, offered, "offered")
            requested = _resolve_offer_nft_legs(rpc, requested, "requested")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "offer_make", "chain": chain,
                  "offered": [{"asset": a, "amount_mojos": m}
                              for a, m in offered],
                  "requested": [{"asset": a, "amount_mojos": m}
                                for a, m in requested],
                  "fee_mojos": p.get("fee_mojos", 0),
                  "purpose": p.get("purpose", "")}
        if expires is not None:
            params["expires_at_second"] = expires
        if recv:
            params["receive_address"] = recv
        entries = [(chain, a, m) for a, m in offered]
        return self._run_fund_intent(params, muse_id, entries, "offer_make")

    def rt_offer_take(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(OFFER_TAKE_FIELDS) or "chain" not in p
                or not p.get("offer")):
            return {"ok": False,
                    "error": "schema violation: offer_take needs chain, offer"}
        chain = p["chain"]
        if chain not in chia.NETWORKS:
            return {"ok": False,
                    "error": f"offer_take is Chia-only, got {chain!r}"}
        if not isinstance(p["offer"], str):
            return {"ok": False, "error": "offer must be the offer string"}
        try:
            self._chia_offer_guards(p, chain)
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        # Native-parseable (XCH-only) offers take the native path — the
        # offer string decodes locally, funding is checked via the relay,
        # and Sage is never consulted. Anything else keeps the Sage flow.
        native = self._rt_offer_take_native(p, chain, muse_id)
        if native is not None:
            return native
        try:
            # Decode the offer now so policy sees real legs and the human
            # sees real terms in the queue — never an opaque string alone.
            rpc, _, _ = self._chia_sage_rpc(chain)
            seen = rpc.view_offer(p["offer"])
            if seen.get("status") not in ("pending", "active"):
                raise chia.SageError(
                    "offer is not takeable "
                    f"(status {seen.get('status')!r})")
            summary = seen.get("offer") or {}
            give = _summary_legs(summary, "taker")
            get = _summary_legs(summary, "maker")
            self._check_offer_balances(
                rpc, give, p.get("fee_mojos", 0))
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "offer_take", "chain": chain,
                  "offer": p["offer"],
                  "fee_mojos": p.get("fee_mojos", 0),
                  "purpose": p.get("purpose", ""),
                  "_give": [{"asset": a, "amount_mojos": m} for a, m in give],
                  "_get": [{"asset": a, "amount_mojos": m} for a, m in get]}
        entries = [(chain, a, m) for a, m in give]
        return self._run_fund_intent(params, muse_id, entries, "offer_take")

    def rt_offer_cancel(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(OFFER_CANCEL_FIELDS) or "chain" not in p
                or ("offer_id" not in p and "offer_ids" not in p)):
            return {"ok": False,
                    "error": "schema violation: offer_cancel needs chain and "
                             "offer_id or offer_ids"}
        chain = p["chain"]
        if chain not in chia.NETWORKS:
            return {"ok": False,
                    "error": f"offer_cancel is Chia-only, got {chain!r}"}
        ids = p.get("offer_ids") or [p.get("offer_id")]
        if (not isinstance(ids, list) or not ids
                or not all(isinstance(i, str) and i for i in ids)):
            return {"ok": False, "error": "offer_id(s) must be non-empty strings"}
        try:
            self._chia_offer_guards(p, chain)
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        # Offers made on the native path cancel on the native path — the
        # local store (not Sage) is the source of truth for our offers.
        # Anything else keeps the Sage flow.
        native = self._rt_offer_cancel_native(p, chain, ids, muse_id)
        if native is not None:
            return native
        try:
            # Confirm each offer is ours and still open, so the human
            # approves a real cancellation with real terms attached.
            rpc, _, _ = self._chia_sage_rpc(chain)
            offered_all = []
            for oid in ids:
                rec = rpc.get_offer(oid)
                if not rec or rec.get("status") not in ("pending", "active"):
                    raise chia.SageError(
                        f"offer {oid[:16]}… is not open "
                        f"(status {(rec or {}).get('status')!r}) — refusing")
                legs = _summary_legs(rec.get("summary") or {}, "maker")
                offered_all.append({"offer_id": oid, "offered": [
                    {"asset": a, "amount_mojos": m} for a, m in legs]})
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "offer_cancel", "chain": chain,
                  "offer_ids": list(ids),
                  "fee_mojos": p.get("fee_mojos", 0),
                  "purpose": p.get("purpose", ""),
                  "_offered": offered_all}
        # Cancel is fund-preserving (coins return to the wallet) but
        # irreversible UX — it always queues for a human, no amount policy.
        canon = json.dumps(params, sort_keys=True).encode()
        qid = str(self.next_qid); self.next_qid += 1
        self.queue[qid] = {"params": params, "muse_id": muse_id,
                           "queued_at": time.time()}
        self._save_queue()
        self.ledger.append(muse_id, canon, None, f"queued:{qid}")
        return {"ok": True, "decision": "queued", "queue_id": qid,
                "reason": "offer cancellation always requires human approval"}

    # --------------------------------- full Sage wallet surface: intents

    def _req_tx_guards(self, p: dict, chain: str):
        """Request-time guards shared by every Sage-transaction intent.

        Returns None on success, or an error dict. Mainnet-without-flag
        and missing-seed refuse exactly like the transfer/offer paths;
        fee_mojos must be a non-negative integer.
        """
        if chain not in chia.NETWORKS:
            return {"ok": False,
                    "error": f"Chia-only intent, got chain {chain!r}"}
        try:
            self._chia_offer_guards(p, chain)
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        return None

    def _queue_tx_intent(self, params: dict, muse_id: str, intent: str):
        """Queue-or-execute a validated Sage-transaction intent.

        Velocity legs come from _velocity_entries(params) — one source of
        truth shared with the post-execution recording.
        """
        return self._run_fund_intent(params, muse_id,
                                     self._velocity_entries(params), intent)

    @staticmethod
    def _fee_of(p: dict) -> int:
        fee = p.get("fee_mojos", 0)
        if not isinstance(fee, int) or fee < 0:
            raise chia.SageError("fee_mojos must be a non-negative integer")
        return fee

    def rt_nft_mint(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(NFT_MINT_FIELDS) or "chain" not in p
                or "mints" not in p or "did_id" not in p):
            return {"ok": False,
                    "error": "schema violation: nft_mint needs chain, "
                             "mints[], did_id"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            mints = p["mints"]
            if not isinstance(mints, list) or not mints:
                raise chia.SageError("mints must be a non-empty list")
            for m in mints:
                self._validate_nft_mint(m)
            did_id = p["did_id"]
            if not (isinstance(did_id, str)
                    and did_id.startswith("did:chia:1")):
                raise chia.SageError(
                    "did_id must be a did:chia:1… minter DID id")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "nft_mint", "chain": p["chain"],
                  "mints": mints, "did_id": did_id,
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "nft_mint")

    def rt_nft_assign_did(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(NFT_ASSIGN_DID_FIELDS) or "chain" not in p
                or "nft_ids" not in p):
            return {"ok": False,
                    "error": "schema violation: nft_assign_did needs chain, "
                             "nft_ids[]"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            ids = p["nft_ids"]
            if not isinstance(ids, list) or not ids or not all(
                    isinstance(i, str) and (
                        i.startswith("nft1") or _HEX64.fullmatch(i))
                    for i in ids):
                raise chia.SageError(
                    "nft_ids must be a non-empty list of nft1 or 64-hex ids")
            did_id = p.get("did_id")
            if did_id is not None and not (
                    isinstance(did_id, str)
                    and did_id.startswith("did:chia:1")):
                raise chia.SageError(
                    "did_id must be a did:chia:1… address or null "
                    "(null unassigns)")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "nft_assign_did", "chain": p["chain"],
                  "nft_ids": list(ids), "did_id": did_id,
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "nft_assign_did")

    def rt_did_create(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(DID_CREATE_FIELDS) or "chain" not in p
                or "name" not in p):
            return {"ok": False,
                    "error": "schema violation: did_create needs chain, name"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            name = p["name"]
            if not isinstance(name, str) or not name:
                raise chia.SageError("name must be a non-empty string")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "did_create", "chain": p["chain"], "name": name,
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "did_create")

    def rt_did_transfer(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(DID_TRANSFER_FIELDS) or "chain" not in p
                or "did_ids" not in p or "destination" not in p):
            return {"ok": False,
                    "error": "schema violation: did_transfer needs chain, "
                             "did_ids[], destination"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            ids = self._validated_did_ids(p)
            dest = p["destination"]
            if not isinstance(dest, str) or not dest:
                raise chia.SageError(
                    "destination must be a non-empty string")
            claw = p.get("clawback_at")
            if claw is not None and (
                    not isinstance(claw, int) or claw <= 0):
                raise chia.SageError(
                    "clawback_at must be a positive unix timestamp")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "did_transfer", "chain": p["chain"],
                  "did_ids": ids, "destination": dest,
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        if claw is not None:
            params["clawback_at"] = claw
        return self._queue_tx_intent(params, muse_id, "did_transfer")

    def rt_did_normalize(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(DID_NORMALIZE_FIELDS) or "chain" not in p
                or "did_ids" not in p):
            return {"ok": False,
                    "error": "schema violation: did_normalize needs chain, "
                             "did_ids[]"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            ids = self._validated_did_ids(p)
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "did_normalize", "chain": p["chain"],
                  "did_ids": ids, "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "did_normalize")

    def rt_option_mint(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(OPTION_MINT_FIELDS) or "chain" not in p
                or "expiration_seconds" not in p or "underlying" not in p
                or "strike" not in p):
            return {"ok": False,
                    "error": "schema violation: option_mint needs chain, "
                             "expiration_seconds, underlying, strike"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            exp = p["expiration_seconds"]
            if not isinstance(exp, int) or exp <= 0:
                raise chia.SageError(
                    "expiration_seconds must be a positive unix timestamp")
            legs = {}
            for key in ("underlying", "strike"):
                leg = p[key]
                if not isinstance(leg, dict):
                    raise chia.SageError(f"{key} must be an object")
                aid = leg.get("asset_id")
                amt = leg.get("amount")
                if aid is not None and not _HEX64.fullmatch(str(aid)):
                    raise chia.SageError(
                        f"{key}.asset_id must be a 64-hex CAT id or null "
                        "(null = XCH)")
                if not isinstance(amt, int) or amt <= 0:
                    raise chia.SageError(
                        f"{key}.amount must be a positive integer")
                legs[key] = {"asset_id": str(aid).lower() if aid else None,
                             "amount": amt}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "option_mint", "chain": p["chain"],
                  "expiration_seconds": exp,
                  "underlying": legs["underlying"],
                  "strike": legs["strike"],
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "option_mint")

    def rt_option_transfer(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(OPTION_TRANSFER_FIELDS) or "chain" not in p
                or "option_ids" not in p or "destination" not in p):
            return {"ok": False,
                    "error": "schema violation: option_transfer needs chain, "
                             "option_ids[], destination"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            ids = self._validated_option_ids(p)
            dest = p["destination"]
            if not isinstance(dest, str) or not dest:
                raise chia.SageError(
                    "destination must be a non-empty string")
            claw = p.get("clawback_at")
            if claw is not None and (
                    not isinstance(claw, int) or claw <= 0):
                raise chia.SageError(
                    "clawback_at must be a positive unix timestamp")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "option_transfer", "chain": p["chain"],
                  "option_ids": ids, "destination": dest,
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        if claw is not None:
            params["clawback_at"] = claw
        return self._queue_tx_intent(params, muse_id, "option_transfer")

    def rt_option_exercise(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(OPTION_EXERCISE_FIELDS) or "chain" not in p
                or "option_ids" not in p):
            return {"ok": False,
                    "error": "schema violation: option_exercise needs chain, "
                             "option_ids[]"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            ids = self._validated_option_ids(p)
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "option_exercise", "chain": p["chain"],
                  "option_ids": ids, "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "option_exercise")

    def rt_cat_issue(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(CAT_ISSUE_FIELDS) or "chain" not in p
                or "name" not in p or "ticker" not in p
                or "amount_mojos" not in p):
            return {"ok": False,
                    "error": "schema violation: cat_issue needs chain, name, "
                             "ticker, amount_mojos"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            name, ticker = p["name"], p["ticker"]
            amount = p["amount_mojos"]
            if not isinstance(name, str) or not name:
                raise chia.SageError("name must be a non-empty string")
            if not isinstance(ticker, str) or not ticker:
                raise chia.SageError("ticker must be a non-empty string")
            if not isinstance(amount, int) or amount <= 0:
                raise chia.SageError(
                    "amount_mojos must be a positive integer")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        # Token issuance: the six-gate rule applies. The queued intent
        # carries the full terms (name/ticker/amount) for the human, and
        # nothing executes without BOTH their queue approval AND the
        # separately-opened mint gate (mint_gate.json, six attestations).
        params = {"intent": "cat_issue", "chain": p["chain"],
                  "name": name, "ticker": ticker,
                  "amount_mojos": amount,
                  "revocable": bool(p.get("revocable", False)),
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "cat_issue")

    def rt_clawback_finalize(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(CLAWBACK_FIELDS) or "chain" not in p
                or "coin_ids" not in p):
            return {"ok": False,
                    "error": "schema violation: clawback_finalize needs "
                             "chain, coin_ids[]"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            ids = self._validated_coin_ids(p)
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "clawback_finalize", "chain": p["chain"],
                  "coin_ids": ids, "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "clawback_finalize")

    def rt_coin_combine(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(COIN_COMBINE_FIELDS) or "chain" not in p
                or "coin_ids" not in p):
            return {"ok": False,
                    "error": "schema violation: coin_combine needs chain, "
                             "coin_ids[]"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            ids = self._validated_coin_ids(p)
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "coin_combine", "chain": p["chain"],
                  "coin_ids": ids, "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "coin_combine")

    def rt_coin_split(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(COIN_SPLIT_FIELDS) or "chain" not in p
                or "coin_ids" not in p or "output_count" not in p):
            return {"ok": False,
                    "error": "schema violation: coin_split needs chain, "
                             "coin_ids[], output_count"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            ids = self._validated_coin_ids(p)
            n = p["output_count"]
            if not isinstance(n, int) or n < 2:
                raise chia.SageError("output_count must be an integer >= 2")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "coin_split", "chain": p["chain"],
                  "coin_ids": ids, "output_count": n,
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "coin_split")

    def rt_coin_autocombine(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(COIN_AUTOCOMBINE_FIELDS) or "chain" not in p
                or "max_coins" not in p):
            return {"ok": False,
                    "error": "schema violation: coin_autocombine needs chain, "
                             "max_coins"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            asset = p.get("asset", "native")
            if asset != "native" and not _HEX64.fullmatch(str(asset or "")):
                raise chia.SageError(
                    "asset must be 'native' or a 64-hex CAT id")
            max_coins = p["max_coins"]
            if not isinstance(max_coins, int) or max_coins < 2:
                raise chia.SageError("max_coins must be an integer >= 2")
            mca = p.get("max_coin_amount")
            if mca is not None and (
                    not isinstance(mca, int) or mca <= 0):
                raise chia.SageError(
                    "max_coin_amount must be a positive integer")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "coin_autocombine", "chain": p["chain"],
                  "asset": asset if asset == "native" else str(asset).lower(),
                  "max_coins": max_coins,
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        if mca is not None:
            params["max_coin_amount"] = mca
        return self._queue_tx_intent(params, muse_id, "coin_autocombine")

    def rt_bulk_send(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(BULK_SEND_FIELDS) or "chain" not in p
                or "addresses" not in p or "amount_mojos" not in p):
            return {"ok": False,
                    "error": "schema violation: bulk_send needs chain, "
                             "addresses[], amount_mojos"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            kind, ref = chia_asset_kind(p.get("asset", "native"))
            if kind == "nft":
                raise chia.SageError(
                    "bulk_send does not support NFT assets")
            addrs = p["addresses"]
            amount = p["amount_mojos"]
            if not isinstance(addrs, list) or not addrs or not all(
                    isinstance(a, str) and a for a in addrs):
                raise chia.SageError(
                    "addresses must be a non-empty list of address strings")
            if not isinstance(amount, int) or amount <= 0:
                raise chia.SageError(
                    "amount_mojos must be a positive integer")
            memos = p.get("memos") or []
            if not isinstance(memos, list):
                raise chia.SageError("memos must be a list")
            asset = "native" if kind == "native" else ref
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "bulk_send", "chain": p["chain"],
                  "asset": asset, "addresses": list(addrs),
                  "amount_mojos": amount, "memos": list(memos),
                  "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "bulk_send")

    def rt_multi_send(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(MULTI_SEND_FIELDS) or "chain" not in p
                or "payments" not in p):
            return {"ok": False,
                    "error": "schema violation: multi_send needs chain, "
                             "payments[]"}
        err = self._req_tx_guards(p, p["chain"])
        if err:
            return err
        try:
            pays = p["payments"]
            if not isinstance(pays, list) or not pays:
                raise chia.SageError("payments must be a non-empty list")
            norm = []
            for pay in pays:
                if not isinstance(pay, dict):
                    raise chia.SageError("each payment must be an object")
                aid = pay.get("asset_id")
                amt = pay.get("amount")
                addr = pay.get("address")
                if aid is not None and not _HEX64.fullmatch(str(aid)):
                    raise chia.SageError(
                        f"bad payment asset_id {aid!r}: 64-hex or null")
                if not isinstance(amt, int) or amt <= 0:
                    raise chia.SageError(
                        "each payment amount must be a positive integer")
                if not isinstance(addr, str) or not addr:
                    raise chia.SageError(
                        "each payment needs a non-empty address")
                memos = pay.get("memos") or []
                if not isinstance(memos, list):
                    raise chia.SageError("payment memos must be a list")
                norm.append({"asset_id": str(aid).lower() if aid else None,
                             "address": addr, "amount": amt,
                             "memos": list(memos)})
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        params = {"intent": "multi_send", "chain": p["chain"],
                  "payments": norm, "fee_mojos": self._fee_of(p),
                  "purpose": p.get("purpose", "")}
        return self._queue_tx_intent(params, muse_id, "multi_send")

    def rt_message_sign(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        if (not fields.issubset(MESSAGE_SIGN_FIELDS) or "chain" not in p
                or "message" not in p):
            return {"ok": False,
                    "error": "schema violation: message_sign needs chain, "
                             "message, and address or public_key"}
        chain = p["chain"]
        # Chain-family gating for sign_type (first layer; execution
        # re-checks membership): EVM signs personal (EIP-191) or typed_data
        # (EIP-712); Chia and Solana sign plain messages. Unknown families
        # and unknown chains fail closed here.
        if chain.startswith("evm-"):
            if chain not in evm.CHAINS:
                return {"ok": False, "error":
                        f"schema violation: unknown EVM chain {chain!r}"}
            allowed = {"personal", "typed_data"}
        elif chain.startswith("solana-"):
            if chain not in solana_mod.NETWORKS:
                return {"ok": False, "error":
                        f"schema violation: unknown Solana chain {chain!r}"}
            allowed = {"plain"}
            # Same network-mismatch rule as the spend path: a devnet-
            # configured daemon asked to sign for mainnet-beta (or vice
            # versa) refuses — the KDF label (and keypair) is per-chain.
            try:
                active = self._active_solana_chain()
            except solana_mod.SolanaError as e:
                return {"ok": False, "error": str(e)}
            if chain != active:
                return {"ok": False, "error":
                        f"network mismatch: daemon is configured for "
                        f"{active}, refusing {chain!r}"}
        elif chain.startswith("chia-"):
            if chain not in chia.NETWORKS:
                return {"ok": False, "error":
                        f"schema violation: unknown Chia chain {chain!r}"}
            allowed = {"plain"}
        else:
            return {"ok": False, "error":
                    "schema violation: message_sign needs a chia-*, evm-*, "
                    f"or solana-* chain, got {chain!r}"}
        # Absent sign_type keeps the v1 default (plain) for backward
        # compatibility; a present-but-invalid value is a schema violation.
        sign_type = p.get("sign_type", "plain")
        if sign_type not in allowed:
            return {"ok": False, "error":
                    f"schema violation: sign_type {sign_type!r} not allowed "
                    f"for chain {chain!r}"}
        try:
            message = p["message"]
            addr = p.get("address")
            pkey = p.get("public_key")
            if not isinstance(message, str) or not message:
                raise chia.SageError("message must be a non-empty string")
            if sign_type == "typed_data":
                # Request-time shape check: the message must parse as a JSON
                # object carrying the EIP-712 envelope keys. Full envelope
                # validation happens again at execution (eip712_digest is
                # the second layer).
                try:
                    typed = json.loads(message)
                except (json.JSONDecodeError, TypeError):
                    raise chia.SageError(
                        "typed_data message must be a JSON string")
                if not isinstance(typed, dict) or not all(
                        k in typed for k in ("types", "primaryType",
                                            "domain", "message")):
                    raise chia.SageError(
                        "typed_data message must be a JSON object with "
                        "types/primaryType/domain/message")
            if addr and pkey:
                raise chia.SageError(
                    "message_sign takes address OR public_key, not both")
            if addr is not None and not isinstance(addr, str):
                raise chia.SageError("address must be a string")
            if pkey is not None and not isinstance(pkey, str):
                raise chia.SageError("public_key must be a string")
            if not addr and not pkey:
                raise chia.SageError(
                    "message_sign needs address or public_key")
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}
        # Chia request-time guards (mainnet flag, seed, fee) — unchanged.
        if chain in chia.NETWORKS:
            err = self._req_tx_guards(p, p["chain"])
            if err:
                return err
        params = {"intent": "message_sign", "chain": p["chain"],
                  "message": message, "sign_type": sign_type,
                  "purpose": p.get("purpose", "")}
        if addr:
            params["address"] = addr
        if pkey:
            params["public_key"] = pkey
        # A signature is a capability even though no funds move: it always
        # queues for a human, no amount policy. The approved message and
        # signing identity are re-verified at execution.
        # Exception: if the agent provides a human_approval_ref (documenting
        # that the human approved in chat/conversation), execute immediately.
        # The ref is logged for audit. This supports the agent-as-delegate
        # model where chat approval is the human's authorization.
        approval_ref = p.get("human_approval_ref")
        if approval_ref and isinstance(approval_ref, str) and approval_ref.strip():
            params["human_approval_ref"] = approval_ref.strip()
            try:
                result = self._execute_message_sign(params)
            except Exception as e:
                return {"ok": False, "error": f"message_sign execution failed: {e}"}
            # Log the chat-approved execution for audit
            canon = json.dumps(params, sort_keys=True).encode()
            self.ledger.append(muse_id, canon, None,
                               f"chat-approved:{approval_ref.strip()}")
            result["human_approval_ref"] = approval_ref.strip()
            result["note"] = (result.get("note", "") +
                              f" [human approved via chat: {approval_ref.strip()}]")
            return {"ok": True, "decision": "executed", **result}
        canon = json.dumps(params, sort_keys=True).encode()
        qid = str(self.next_qid); self.next_qid += 1
        self.queue[qid] = {"params": params, "muse_id": muse_id,
                           "queued_at": time.time()}
        self._save_queue()
        self.ledger.append(muse_id, canon, None, f"queued:{qid}")
        return {"ok": True, "decision": "queued", "queue_id": qid,
                "reason": "message signing always requires human approval"}

    # ----------------------- wallet-local metadata (direct, no queue)

    def _local_chia_rpc(self, p: dict):
        """Guards + wallet selection for local-metadata routes.

        Returns (rpc, None) or (None, error_dict). No seed is required —
        nothing is signed — but the chain must be a Chia network.
        """
        chain = p.get("chain")
        if chain not in chia.NETWORKS:
            return None, {"ok": False,
                          "error": f"Chia-only route, got chain {chain!r}"}
        try:
            rpc, _, _ = self._chia_sage_rpc(chain)
        except chia.SageError as e:
            return None, {"ok": False, "error": str(e)}
        return rpc, None

    def rt_offer_import(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(OFFER_IMPORT_FIELDS)
                or "chain" not in p or "offer" not in p
                or not isinstance(p["offer"], str)):
            return {"ok": False,
                    "error": "schema violation: offer_import needs chain, "
                             "offer (string)"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            rpc.import_offer(p["offer"])
            return {"ok": True, "imported": True}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    def rt_offer_delete(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(OFFER_DELETE_FIELDS)
                or "chain" not in p or not p.get("offer_id")):
            return {"ok": False,
                    "error": "schema violation: offer_delete needs chain, "
                             "offer_id"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            rpc.delete_offer(p["offer_id"])
            return {"ok": True, "deleted": True}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    def rt_offer_combine(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(OFFER_COMBINE_FIELDS)
                or "chain" not in p or "offers" not in p
                or not isinstance(p["offers"], list) or not p["offers"]):
            return {"ok": False,
                    "error": "schema violation: offer_combine needs chain, "
                             "offers[] (non-empty)"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            res = rpc.combine_offers(list(p["offers"]))
            return {"ok": True, "result": res}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    def rt_cat_update(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(CAT_UPDATE_FIELDS)
                or "chain" not in p or "record" not in p
                or not isinstance(p["record"], dict)):
            return {"ok": False,
                    "error": "schema violation: cat_update needs chain, "
                             "record (object)"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            rpc.update_cat(p["record"])
            return {"ok": True, "updated": True}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    def rt_did_update(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(DID_UPDATE_FIELDS)
                or "chain" not in p or "did_id" not in p):
            return {"ok": False,
                    "error": "schema violation: did_update needs chain, "
                             "did_id"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            rpc.update_did(p["did_id"], name=p.get("name"),
                           visible=bool(p.get("visible", True)))
            return {"ok": True, "updated": True}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    def rt_nft_update(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(NFT_UPDATE_FIELDS)
                or "chain" not in p or "nft_id" not in p):
            return {"ok": False,
                    "error": "schema violation: nft_update needs chain, "
                             "nft_id"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            rpc.update_nft(p["nft_id"],
                           visible=bool(p.get("visible", True)))
            return {"ok": True, "updated": True}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    def rt_nft_collection_update(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(NFT_COLLECTION_UPDATE_FIELDS)
                or "chain" not in p or "collection_id" not in p):
            return {"ok": False,
                    "error": "schema violation: nft_collection_update needs "
                             "chain, collection_id"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            rpc.update_nft_collection(
                p["collection_id"], visible=bool(p.get("visible", True)))
            return {"ok": True, "updated": True}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    def rt_nft_redownload(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(NFT_REDOWNLOAD_FIELDS)
                or "chain" not in p or "nft_id" not in p):
            return {"ok": False,
                    "error": "schema violation: nft_redownload needs chain, "
                             "nft_id"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            rpc.redownload_nft(p["nft_id"])
            return {"ok": True, "redownloaded": True}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    def rt_option_update(self, p: dict, muse_id: str) -> dict:
        if (not set(p).issubset(OPTION_UPDATE_FIELDS)
                or "chain" not in p or "option_id" not in p):
            return {"ok": False,
                    "error": "schema violation: option_update needs chain, "
                             "option_id"}
        rpc, err = self._local_chia_rpc(p)
        if err:
            return err
        try:
            rpc.update_option(p["option_id"],
                              visible=bool(p.get("visible", True)))
            return {"ok": True, "updated": True}
        except chia.SageError as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------ chia reads
    def rt_chia_read(self, p: dict, muse_id: str) -> dict:
        """Read-only (or wallet-local) Chia queries — never a spend.

        {"chain": "chia-testnet", "op": "<op>", ...op args}. The op
        allowlist below is the whole surface: anything else is rejected,
        so this route cannot become a generic RPC passthrough.
        """
        chain = p.get("chain")
        if chain not in chia.NETWORKS:
            return {"ok": False,
                    "error": f"chia_read is Chia-only, got {chain!r}"}
        op = p.get("op")
        if op not in _CHIA_READ_OPS:
            return {"ok": False,
                    "error": f"unknown chia_read op {op!r}"}
        # Native-path offers live in the local store, not in Sage: serve
        # our own records directly so reads work when Sage is down.
        if op == "get_offer" and p.get("offer_id"):
            rec = self._offer_load(p["offer_id"])
            if rec is not None:
                return {"ok": True, "result": rec}
        try:
            rpc, _, _ = self._chia_sage_rpc(chain)
            return {"ok": True, "result": _run_chia_read_op(self, rpc, op, p)}
        except chia.SageError as e:
            if op == "get_offers":
                local = self._offer_list_local()
                if local:
                    return {"ok": True, "result": local,
                            "note": "Sage unavailable; local native offers only"}
            return {"ok": False, "error": str(e)}

    def _decoded_queue(self):
        # Full decoded intent (to/value/chain/asset), never just a hash.
        out = []
        for qid, item in sorted(self.queue.items(), key=lambda kv: int(kv[0])):
            p = item["params"]
            entry = {
                "queue_id": qid,
                "chain": p.get("chain"),
                "destination": p.get("destination"),
                "asset": p.get("asset", "native"),
                "amount": p.get("amount_mojos",
                                p.get("amount_wei", p.get("amount_lamports"))),
                "purpose": p.get("purpose", ""),
                "muse_id": item.get("muse_id"),
                "queued_at": item.get("queued_at"),
                # The exact digest the mint gate authorizes for mint
                # intents (sha256 of the canonical params — the same bytes
                # the ledger's canon_digest covers). Shown alongside the
                # full decoded intent, never instead of it.
                "canon_digest": self._mint_intent_digest(p),
            }
            # Offer intents carry no single destination/asset/amount — the
            # human must see the decoded legs, never an opaque hash.
            intent = p.get("intent")
            if intent == "offer_make":
                entry.update({
                    "kind": "offer_make",
                    "offered": p.get("offered"),
                    "requested": p.get("requested"),
                    "fee_mojos": p.get("fee_mojos", 0),
                    "expires_at_second": p.get("expires_at_second"),
                    "destination": None, "asset": "offer", "amount": None,
                })
            elif intent == "offer_take":
                entry.update({
                    "kind": "offer_take",
                    "give": p.get("_give"),
                    "get": p.get("_get"),
                    "fee_mojos": p.get("fee_mojos", 0),
                    "destination": None, "asset": "offer", "amount": None,
                })
            elif intent == "dex_swap":
                # The human approves BOUNDS, not calldata: exact sell,
                # minimum buy, max slippage. The firm quote is fetched at
                # execution and must fit inside these bounds.
                entry.update({
                    "kind": "dex_swap",
                    "venue": p.get("venue"),
                    "sell_token": p.get("sell_token"),
                    "buy_token": p.get("buy_token"),
                    "sell_amount_wei": p.get("sell_amount_wei"),
                    "min_buy_amount_wei": p.get("min_buy_amount_wei"),
                    "max_slippage_bps": p.get("max_slippage_bps"),
                    "deadline_sec": p.get("deadline_sec"),
                    "destination": None, "asset": "dex_swap", "amount": None,
                })
            elif intent == "dex_lp_add":
                entry.update({
                    "kind": "dex_lp_add",
                    "protocol": p.get("protocol"),
                    "router": p.get("router"),
                    "token_a": p.get("token_a"),
                    "token_b": p.get("token_b"),
                    "amount_a_wei": p.get("amount_a_wei"),
                    "amount_b_wei": p.get("amount_b_wei"),
                    "amount_a_min_wei": p.get("amount_a_min_wei"),
                    "amount_b_min_wei": p.get("amount_b_min_wei"),
                    "fee": p.get("fee"),
                    "tick_lower": p.get("tick_lower"),
                    "tick_upper": p.get("tick_upper"),
                    "deadline_sec": p.get("deadline_sec"),
                    "destination": None, "asset": "dex_lp_add", "amount": None,
                })
            elif intent == "offer_cancel":
                entry.update({
                    "kind": "offer_cancel",
                    "offer_ids": p.get("offer_ids"),
                    "offered": p.get("_offered"),
                    "fee_mojos": p.get("fee_mojos", 0),
                    "destination": None, "asset": "offer", "amount": None,
                })
            elif intent in ("nft_mint", "nft_assign_did", "did_create",
                            "did_transfer", "did_normalize", "option_mint",
                            "option_transfer", "option_exercise",
                            "cat_issue", "clawback_finalize",
                            "coin_combine", "coin_split",
                            "coin_autocombine", "bulk_send", "multi_send",
                            "message_sign"):
                # Full Sage wallet surface: the human sees the whole
                # intent, never an opaque hash. "destination"/"asset"/
                # "amount" stay None — these intents name ids and lists,
                # not a single transfer.
                detail = {
                    "kind": intent,
                    "fee_mojos": p.get("fee_mojos", 0),
                    "destination": None, "asset": None, "amount": None,
                }
                for key in ("mints", "did_id", "did_ids", "name",
                            "option_ids", "expiration_seconds",
                            "underlying", "strike", "ticker",
                            "amount_mojos", "revocable", "nft_ids",
                            "coin_ids", "output_count", "max_coins",
                            "max_coin_amount", "addresses", "payments",
                            "address", "public_key", "message", "sign_type"):
                    if p.get(key) is not None:
                        detail[key] = p[key]
                entry.update(detail)
            out.append(entry)
        return out

    def rt_queue_read(self, p: dict, muse_id: str) -> dict:
        return {"ok": True, "queue": self._decoded_queue()}

    def rt_queue_approve(self, p: dict, muse_id: str) -> dict:
        qid = p.get("queue_id")
        if qid not in self.queue:
            return {"ok": False, "error": "unknown queue_id"}
        item = self.queue.pop(qid)
        self._save_queue()
        params = item["params"]
        canon = json.dumps(params, sort_keys=True).encode()
        # Same pre-execution intent line as the auto-approve path: the queue
        # item is already popped (one approval = one execution attempt), so
        # the ledger is the crash record for the in-flight window.
        self.ledger.append(muse_id, canon, None, "executing")
        try:
            ex = self._execute_spend(params)
        except (evm.BroadcastUnknown, chia.BroadcastUnknown,
                chia_relay.BroadcastUnknown, solana_mod.BroadcastUnknown) as e:
            ref = (getattr(e, "tx_hash", None) or getattr(e, "signature", None)
                   or getattr(e, "reference", None))
            self._record_velocity_entries(params)
            self.ledger.append(muse_id, canon, ref,
                               "approved-submit-unknown:" + str(e))
            return {"ok": True, "queue_id": qid, "tx_hash": ref,
                    "decision": "approved-submit-unknown",
                    "note": str(e)}
        except (evm.EvmError, chia.SageError, chia_relay.RelayError,
                solana_mod.SolanaError, dex_mod.DexError) as e:
            # Approved but never executed: the human's approval is consumed,
            # the failure is ledgered, nothing is recorded as spent. The
            # agent reports it; the human re-requests if they still want it.
            self.ledger.append(muse_id, canon, None,
                               "approved-submit-failed:" + str(e))
            return {"ok": False, "queue_id": qid, "error": str(e)}
        self._record_velocity_entries(params)
        if ex["submitted"]:
            self.ledger.append(muse_id, canon, ex["tx_hash"], "approved-by-human")
            return {"ok": True, "queue_id": qid,
                    "tx_hash": ex["tx_hash"],
                    "block": ex.get("block", ex.get("tx_height", ex.get("slot")))}
        self.ledger.append(muse_id, canon, ex.get("offer_id"),
                           "approved-by-human")
        out = {"ok": True, "queue_id": qid, "note": ex.get("note", "")}
        if ex.get("offer_id"):
            out["offer_id"] = ex["offer_id"]
        if ex.get("offer"):
            out["offer"] = ex["offer"]
        return out

    def rt_queue_reject(self, p: dict, muse_id: str) -> dict:
        qid = p.get("queue_id")
        if qid not in self.queue:
            return {"ok": False, "error": "unknown queue_id"}
        item = self.queue.pop(qid)
        self._save_queue()
        self.ledger.append(muse_id, json.dumps(item["params"], sort_keys=True).encode(),
                           None, "rejected-by-human")
        return {"ok": True, "queue_id": qid}

    # Resolved outcomes for an "executing" ledger line. Anything else with
    # the same canon_digest leaves the execution unresolved — the human
    # must reconcile the chain before re-requesting.
    _RESOLVED_EXECUTIONS = frozenset({
        "approved", "approved-by-human",
        "approved-submit-failed", "approved-submit-unknown",
    })

    def unresolved_executions(self) -> list[dict]:
        """Ledger rows marked 'executing' with no later resolution row.

        This is the crash/ambiguity record: a daemon killed mid-execution
        (or a broadcast whose receipt never arrived and was never
        reconciled) leaves an 'executing' line with no outcome. Matching is
        by canon_digest, so it is a heuristic when two identical requests
        exist — err on the side of showing, not hiding.
        """
        rows = self.ledger.read_all()
        resolved: set[str] = set()
        executing: list[dict] = []
        for row in rows:
            digest = row.get("canon_digest")
            decision = (row.get("decision") or "")
            base = decision.split(":", 1)[0]
            if base == "executing":
                executing.append(row)
            elif base in self._RESOLVED_EXECUTIONS:
                resolved.add(digest)
        return [{"canon_digest": r["canon_digest"], "ts": r["ts"],
                 "requester_muse": r["requester_muse"]}
                for r in executing if r["canon_digest"] not in resolved]

    def rt_status(self, p: dict, muse_id: str) -> dict:
        out = {"ok": True, "queue_depth": len(self.queue),
               "spellbook_version": version_mod.local_version(self.config_dir),
               "seed_loaded": self.seed is not None,
               "std_seed_loaded": self.std_seed is not None,
               "key_derivation": self.key_derivation,
               "unresolved_executions": self.unresolved_executions()}
        balances = {}
        signing_seed = (self.std_seed if self.key_derivation == "standard"
                        else self.seed)
        if signing_seed is not None:
            for chain, entry in (self.evm_cfg.get("chains") or {}).items():
                if not entry.get("enabled") or not entry.get("rpc_url"):
                    continue
                try:
                    addr = self._evm_key(chain)[1]
                    balances[chain] = {
                        "address": addr,
                        "balance_wei": evm.Rpc(entry["rpc_url"]).balance_wei(addr),
                    }
                except Exception as e:  # best effort — a down RPC is not a daemon failure
                    balances[chain] = {"error": str(e)}
        if (signing_seed is not None and self.cfg.get("chia_enabled", True)
                and self.chia_cfg.get("sage_data_home")):
            try:
                data_dir = os.path.join(self.chia_cfg["sage_data_home"],
                                        "com.rigidnetwork.sage")
                rpc = chia.SageRpc(
                    data_dir, port=int(self.chia_cfg.get("rpc_port", 9257)))
                # Select the daemon's own wallet first: Sage reports the
                # *selected* wallet, which may be a foreign one left logged
                # in by earlier tooling. Never report another wallet's
                # balance/address as the agent's (O10).
                _, addr = self._chia_wallet(rpc, "chia-testnet")
                st = rpc.sync_status()
                balances["chia-testnet"] = {
                    "address": addr,
                    "balance_mojos": chia.amount_to_int(
                        st.get("selectable_balance", 0)),
                }
            except Exception as e:  # best effort — Sage down is not a daemon failure
                balances["chia-testnet"] = {"error": str(e)}
        if signing_seed is not None:
            # Solana: direct HTTPS JSON-RPC (no relay, no Sage). Devnet is
            # the default active network; mainnet-beta requires the
            # explicit flag (the gate is enforced at spend time — balances
            # simply read the configured active network).
            try:
                active = self._active_solana_chain()
            except Exception:
                active = None
            if active is not None:
                try:
                    info = solana_mod.NETWORKS[active]
                    kp = self._solana_keypair(active)
                    addr = solana_mod.address_of_keypair(kp)
                    rpc = solana_mod.SolanaRpc(
                        active, url=self.solana_cfg.get("rpc_url") or info["url"])
                    balances[active] = {
                        "address": addr,
                        "balance_lamports": rpc.get_balance_lamports(addr),
                    }
                except Exception as e:  # best effort — a down RPC is not a daemon failure
                    balances[active] = {"error": str(e)}
        out["balances"] = balances
        return out

    def rt_doctor(self, p: dict, muse_id: str) -> dict:
        """Read-only install health (SPEC §12b item 4).

        Presence/permissions/shape only — never key contents. The agent
        calls this instead of stat-ing the prefix itself (it cannot traverse
        /opt/spellbook). Failures map to repair actions via
        spellbook.doctor.repair_plan; only CODE problems are self-repairable,
        state problems (keys/tokens/config/ledger) fail closed.
        """
        checks = doctor_mod.run_checks(prefix=self.config_dir)
        return {"ok": True, **doctor_mod.summary(checks)}

    def rt_addresses(self, p: dict, muse_id: str) -> dict:
        signing_seed = (self.std_seed if self.key_derivation == "standard"
                        else self.seed)
        if signing_seed is None:
            return {"ok": True, "addresses": {},
                    "note": "no seed configured — daemon serves policy/queue/ledger only"}
        if self.key_derivation == "standard":
            # One standard wallet: a single EVM account (same 0x address on
            # every EVM chain, as with MetaMask) and one BLS master key whose
            # testnet11/mainnet addresses differ only by bech32m HRP.
            from spellbook import chia_sign, stdkeys
            master_sk = stdkeys.chia_master_sk(self.std_seed)
            evm_addr = stdkeys.evm_address(stdkeys.evm_privkey(self.std_seed))
            per_label = {}
            for chain in kdf.CHAINS:
                if chain.startswith("chia-") and not self.cfg.get("chia_enabled", True):
                    continue
                if chain.startswith("evm-"):
                    per_label[chain] = evm_addr
                elif chain == "chia-testnet":
                    per_label[chain] = chia_sign.receive_address(
                        master_sk, 0, "testnet11")
                elif chain == "chia-mainnet":
                    per_label[chain] = chia_sign.receive_address(
                        master_sk, 0, "mainnet")
            # Solana standard path: SLIP-0010 m/44'/501'/0'/0' — the address
            # Phantom/Solflare show on mnemonic import. Solana addresses
            # are network-agnostic (base58 pubkey), so devnet and
            # mainnet-beta share one address in standard mode.
            sol_kp = solana_mod.standard_keypair(self.std_seed)
            sol_addr = solana_mod.address_of_keypair(sol_kp)
            per_label["solana-devnet"] = sol_addr
            per_label["solana-mainnet"] = sol_addr
            return {"ok": True, "addresses": {"default": per_label}}
        out = {}
        for label in self.cfg.get("labels", ["default"]):
            per_label = {}
            for chain in kdf.CHAINS:
                if chain.startswith("chia-") and not self.cfg.get("chia_enabled", True):
                    continue
                d = kdf.derive_labeled(self.seed, chain, label)
                per_label[chain] = d.get("address", d["pubkey_hex"])
            # Solana is not in kdf.CHAINS (derive_labeled reduces mod a
            # group order, which is invalid for ed25519) — derive
            # per-network keys via the Solana module instead. Devnet and
            # mainnet-beta keys differ by design (P9).
            for schain in ("solana-devnet", "solana-mainnet"):
                per_label[schain] = solana_mod.address_of_keypair(
                    solana_mod.custom_keypair(self.seed, schain, label))
            out[label] = per_label
        return {"ok": True, "addresses": out}

    def rt_ledger_read(self, p: dict, muse_id: str) -> dict:
        # P6: the ledger is read through the API, never the file.
        return {"ok": True, "rows": self.ledger.read_all()}

    def rt_sign_musebook_request(self, p: dict, muse_id: str) -> dict:
        # S1: Option B (fleet) adopted 2026-09-20 — each muse's own daemon may
        # sign for that muse when its config enables it; otherwise inert.
        if self._identity_key is None:
            return {"ok": False,
                    "error": "daemon-side Musebook signing is disabled pending the S1 decision"}
        for f in ("method", "path", "body"):
            if f not in p:
                return {"ok": False, "error": f"missing field {f}"}
        # The daemon builds the canonical string itself — it never signs
        # caller-supplied raw bytes (P1).
        canonical = spellsign.build_musebook_canonical(p["method"], p["path"], p["body"])
        signed = self._identity_key.sign(canonical)
        self.ledger.append(muse_id, canonical, None, "musebook-sign")
        return {"ok": True, "signature_hex": signed.signature.hex()}

    def rt_publish_directory_entry(self, p: dict, muse_id: str) -> dict:
        # Approve token only (checked in handle()). Distinct prefix (P1).
        if self._identity_key is None:
            return {"ok": False,
                    "error": "identity signing is disabled pending the S1 decision"}
        canonical = spellsign.build_directory_canonical(p.get("entry"))
        signed = self._identity_key.sign(canonical)
        self.ledger.append(muse_id, canonical, None, "directory-entry")
        # TODO(phase-1): publish per §8/O3.
        return {"ok": True, "signature_hex": signed.signature.hex(),
                "note": "TODO(phase-1): directory publication not yet implemented"}


def peer_uid(conn: socket.socket) -> int:
    # SO_PEERCRED: the kernel tells us who is on the other end of the socket.
    try:
        data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", data)
        return uid
    except OSError:
        return -1


def serve(sock_path: str, daemon: Daemon):
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    # S2: the agent runs as its own OS user, not the daemon's. When the
    # config names a socket group, group members may connect (the token is
    # still the authentication; peer-UID allowlists are the authorization).
    group = daemon.cfg.get("socket_group")
    if group:
        import shutil
        shutil.chown(sock_path, group=group)
        os.chmod(sock_path, 0o770)
    else:
        os.chmod(sock_path, 0o700)
    srv.listen(16)
    print(f"spellbookd listening on {sock_path}", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            uid = peer_uid(conn)
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            try:
                req = json.loads(buf.decode())
            except (ValueError, UnicodeDecodeError):
                conn.sendall(b'{"ok": false, "error": "bad json"}\n')
                continue
            resp = daemon.handle(req, uid)
            conn.sendall((json.dumps(resp) + "\n").encode())
        except OSError:
            # The client went away mid-request (RST, EPIPE on send). Drop
            # the request; the daemon must not crash with it.
            pass
        finally:
            conn.close()


def main():
    ap = argparse.ArgumentParser(prog="spellbookd")
    ap.add_argument("--socket", required=True)
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    daemon = Daemon(args.config)
    serve(args.socket, daemon)


if __name__ == "__main__":
    main()

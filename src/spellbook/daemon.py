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
from spellbook import solana as solana_mod
from spellbook.config import load_config, load_policy
from spellbook.ledger import Ledger
from spellbook.policy import evaluate
from spellbook.seed import load_seed
from spellbook import tokens as token_auth

REQUEST_ROUTES = {
    "request_spend", "queue_read", "status", "addresses",
    "ledger_read", "sign_musebook_request", "chia_read",
    "offer_make", "offer_take", "offer_cancel",
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

# chia_read op allowlist: read-only or wallet-local offer ops only. Each
# entry is (rpc_method, [param names]). Anything not listed here is
# rejected by rt_chia_read, so the route can never become a generic RPC
# passthrough (no spends, no signing, no key material, no issuance).
_CHIA_READ_OPS = {
    # offers (local records / decode only — NOT take/cancel)
    "get_offers": ("get_offers", []),
    "get_offer": ("get_offer", ["offer_id"]),
    "get_offers_for_asset": ("get_offers_for_asset", ["asset_id"]),
    "view_offer": ("view_offer", ["offer"]),
    "import_offer": ("import_offer", ["offer"]),
    "delete_offer": ("delete_offer", ["offer_id"]),
    "combine_offers": ("combine_offers", ["offers"]),
    # coins
    "get_coins": ("get_coins", ["asset_id", "offset", "limit"]),
    "get_coins_by_ids": ("get_coins_by_ids", ["coin_ids"]),
    "get_are_coins_spendable": ("get_are_coins_spendable", ["coin_ids"]),
    "get_spendable_coin_count": ("get_spendable_coin_count", ["asset_id"]),
    # transactions
    "get_transaction": ("get_transaction", ["transaction_id"]),
    "get_pending_transactions": ("get_pending_transactions", []),
    "recent_transactions": ("recent_transactions", ["limit"]),
    # assets
    "get_cats": ("get_cats", []),
    "get_all_cats": ("get_all_cats", []),
    "get_nfts": ("get_nfts", ["offset", "limit", "collection_id", "name"]),
    "get_nft": ("get_nft", ["nft_id"]),
    "get_nft_data": ("get_nft_data", ["nft_id"]),
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

    Returns [(asset, amount)] with the asset in daemon form ("native" or
    64-hex CAT). NFTs are rejected — the daemon's NFT path is
    transfer-only. Raises chia.SageError on any malformed leg so bad
    offers fail closed at request time.
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
        if kind == "nft":
            raise chia.SageError(
                f"offer {side}: NFTs not supported in offers")
        if not isinstance(amount, int) or amount <= 0:
            raise chia.SageError(
                f"offer {side}: amount_mojos must be a positive integer")
        out.append((asset if kind == "native" else ref, amount))
    return out


def _summary_legs(summary: dict, side: str) -> list:
    """Convert a Sage OfferSummary's maker/taker legs to [(asset, amount)].

    Sage's summary uses {"asset": {"asset_id": <hex>|null, "kind": ...},
    "amount": ...}; asset_id null means XCH. NFT/DID/option legs raise —
    the daemon only handles fungible legs.
    """
    legs = summary.get(side)
    if not isinstance(legs, list):
        raise chia.SageError(f"offer summary has no {side!r} legs: "
                             f"{str(summary)[:200]}")
    out = []
    for leg in legs:
        a = (leg or {}).get("asset") or {}
        kind = (a.get("kind") or "token")
        if kind != "token":
            raise chia.SageError(
                f"offer leg kind {kind!r} not supported (fungible only)")
        asset_id = a.get("asset_id")
        asset = "native" if not asset_id else str(asset_id).lower()
        if asset != "native" and not _HEX64.fullmatch(asset):
            raise chia.SageError(f"bad offer leg asset id {asset_id!r}")
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
        return handler(params, req.get("muse_id", "?"))

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
        if chain in chia.NETWORKS:
            return self._execute_chia_spend(params)
        if chain in solana_mod.NETWORKS:
            return self._execute_solana_spend(params)
        if chain not in evm.CHAINS:
            return {"submitted": False,
                    "note": f"chain submission not configured for {chain}"}
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
                                          rpc.gas_price_wei(), gas_limit)
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
        if intent == "offer_make":
            return self._execute_offer_make_via_sage(params)
        if intent == "offer_take":
            return self._execute_offer_take_via_sage(params)
        if intent == "offer_cancel":
            return self._execute_offer_cancel_via_sage(params)
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
        selected = []
        total = 0
        for c in unspent:
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
                solana_mod.SolanaError) as e:
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

        legs are (asset, amount) with asset "native" or 64-hex CAT.
        """
        xch_need = fee_mojos
        for asset, amount in legs:
            if asset == "native":
                xch_need += amount
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
        already counted them.
        """
        intent = params.get("intent")
        chain = params["chain"]
        if intent == "offer_make":
            return [(chain, it["asset"], it["amount_mojos"])
                    for it in params["offered"]]
        if intent == "offer_take":
            return [(chain, it["asset"], it["amount_mojos"])
                    for it in params["_give"]]
        if intent == "offer_cancel":
            return []
        asset = params.get("asset", "native")
        amount = params.get("amount_mojos", params.get("amount_wei",
                            params.get("amount_lamports")))
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
                solana_mod.SolanaError) as e:
            self.ledger.append(muse_id, canon, None,
                               "approved-submit-failed:" + str(e))
            return {"ok": False, "decision": "approved-submit-failed",
                    "error": str(e)}
        self._record_velocity_entries(params)
        if ex.get("submitted"):
            self.ledger.append(muse_id, canon, ex["tx_hash"], "approved")
            return {"ok": True, "decision": "approved",
                    "tx_hash": ex["tx_hash"],
                    "block": ex.get("block", ex.get("tx_height", ex.get("slot")))}
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
        try:
            rpc, _, _ = self._chia_sage_rpc(chain)
            return {"ok": True, "result": _run_chia_read_op(self, rpc, op, p)}
        except chia.SageError as e:
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
            elif intent == "offer_cancel":
                entry.update({
                    "kind": "offer_cancel",
                    "offer_ids": p.get("offer_ids"),
                    "offered": p.get("_offered"),
                    "fee_mojos": p.get("fee_mojos", 0),
                    "destination": None, "asset": "offer", "amount": None,
                })
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
                solana_mod.SolanaError) as e:
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

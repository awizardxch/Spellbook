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
import socket
import struct
import subprocess
import sys
import time

from spellbook import chia, evm, kdf, sign as spellsign
from spellbook.config import load_config, load_policy
from spellbook.ledger import Ledger
from spellbook.policy import evaluate
from spellbook.seed import load_seed
from spellbook import tokens as token_auth

REQUEST_ROUTES = {
    "request_spend", "queue_read", "status", "addresses",
    "ledger_read", "sign_musebook_request",
}
APPROVE_ROUTES = {
    "queue_approve", "queue_reject", "publish_directory_entry",
}

# v1 transfer schema — plain transfers only (S13). Unknown fields are
# rejected; anything shaped like a contract call is denied, not coerced.
SPEND_FIELDS = {"chain", "destination", "asset", "purpose"}
AMOUNT_FIELDS = {"amount_mojos", "amount_wei"}

VELOCITY_WINDOW_S = 24 * 3600


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

    def _execute_spend(self, params: dict) -> dict:
        """Build, sign, and broadcast an approved EVM transfer (SPEC §10).

        Returns {"submitted": True, "tx_hash": ..., "block": ...} on success,
        {"submitted": False, "note": ...} when no chain is configured, and
        raises evm.EvmError on any failure — a spend that never left the
        machine records nothing and consumes no velocity. Spends use the
        "default" label's key (v1).
        """
        chain = params["chain"]
        if chain in chia.NETWORKS:
            return self._execute_chia_spend(params)
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
        if params.get("amount_mojos") is not None:
            raise evm.EvmError("mojos on an EVM chain — schema misuse, refusing")
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
        """
        if self.chia_cfg.get("relay_urls") or self.chia_cfg.get("relay_url"):
            return self._execute_chia_spend_via_relay(params)
        return self._execute_chia_spend_via_sage(params)

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
        chain = params["chain"]
        network = chia.NETWORKS[chain]
        if chain == "chia-mainnet" and not self.chia_cfg.get(
                "mainnet_submit_enabled"):
            raise chia_relay.RelayError(
                "mainnet submission refused for chia-mainnet — needs the "
                "separately-authorized mainnet_submit_enabled flag (§10.14-17)")
        if self._signing_seed() is None:
            raise chia_relay.RelayError("no seed configured — cannot sign")
        if params.get("amount_wei") is not None:
            raise chia_relay.RelayError(
                "wei on a Chia chain — schema misuse, refusing")
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
        relay_urls = self.chia_cfg.get("relay_urls", {})
        relay_url = relay_urls.get(network) or self.chia_cfg.get("relay_url")
        if not relay_url:
            raise chia_relay.RelayError(
                f"no relay configured for {network} — refusing")
        token = self.chia_cfg.get("relay_token") or os.environ.get(
            "SPELLBOOK_RELAY_TOKEN", "")
        if token.startswith("env:"):
            token = os.environ.get(token[4:], "")
        rpc = chia_relay.RelayRpc(relay_url, token)

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
        # it. Any divergence means the pipeline saw a different bundle
        # than the one we signed; recording success would be wrong, so we
        # raise before anything is recorded or any velocity consumed.
        # A missing expected_txid is also a refusal: the documented
        # contract always returns it.
        local_txid = hashlib.sha256(bytes.fromhex(bundle_hex)).hexdigest()
        expected_txid = res.get("expected_txid")
        if not expected_txid or expected_txid != local_txid:
            raise chia_relay.RelayError(
                f"relay expected_txid {expected_txid!r} != locally computed "
                f"bundle txid {local_txid[:16]}… — refusing")
        if res.get("txid") != local_txid:
            raise chia_relay.RelayError(
                f"relay peer-ack txid {res.get('txid')!r} != locally computed "
                f"bundle txid {local_txid[:16]}… — refusing")
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
        chain = params["chain"]
        network = chia.NETWORKS[chain]
        if chain == "chia-mainnet" and not self.chia_cfg.get("mainnet_submit_enabled"):
            raise chia.SageError(
                "mainnet submission refused for chia-mainnet — needs the "
                "separately-authorized mainnet_submit_enabled flag (§10.14-17)")
        if self._signing_seed() is None:
            raise chia.SageError("no seed configured — cannot sign")
        if params.get("amount_wei") is not None:
            raise chia.SageError("wei on a Chia chain — schema misuse, refusing")
        dest = params.get("destination", "")
        prefix = chia.PREFIXES[network]
        if not isinstance(dest, str) or not dest.startswith(prefix):
            raise chia.SageError(
                f"bad destination for {chain}: expected a {prefix}... address")
        amount = params["amount_mojos"]
        self._ensure_sage_rpc()
        data_home = self.chia_cfg.get("sage_data_home")
        data_dir = os.path.join(data_home, "com.rigidnetwork.sage")
        if not os.path.isdir(data_dir):
            raise chia.SageError(
                f"Sage data dir {data_dir} missing after startup — refusing")
        rpc = chia.SageRpc(data_dir,
                           port=int(self.chia_cfg.get("rpc_port", 9257)))
        expected_fp, sender = self._chia_wallet(rpc, chain)
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
        tx = chia.wait_for_outgoing(rpc, dest, amount, t0)
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
        amount = p.get("amount_mojos", p.get("amount_wei"))
        if not isinstance(amount, int) or amount <= 0:
            return {"ok": False, "error": "amount must be a positive integer in base units"}
        # Note: contract-call-shaped requests never reach here — "calldata"/"data"
        # are not in the v1 schema, so they fail the subset check above (S13).
        asset = p.get("asset", "native")
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
        except (evm.BroadcastUnknown, chia.BroadcastUnknown) as e:
            # The spend left the machine; its fate is unknown. Ledger the
            # reference as unresolved and consume velocity fail-closed
            # (assume it lands — a cap that undercounts is a broken cap).
            # The human reconciles the hash on-chain before re-requesting.
            ref = getattr(e, "tx_hash", None) or getattr(e, "reference", None)
            self._record_velocity(p["chain"], asset, amount)
            self.ledger.append(muse_id, canon, ref,
                               "approved-submit-unknown:" + str(e))
            return {"ok": True, "decision": "approved-submit-unknown",
                    "tx_hash": ref, "note": str(e)}
        except (evm.EvmError, chia.SageError) as e:
            self.ledger.append(muse_id, canon, None,
                               "approved-submit-failed:" + str(e))
            return {"ok": False, "decision": "approved-submit-failed",
                    "error": str(e)}
        self._record_velocity(p["chain"], asset, amount)
        if ex["submitted"]:
            self.ledger.append(muse_id, canon, ex["tx_hash"], "approved")
            return {"ok": True, "decision": "approved",
                    "tx_hash": ex["tx_hash"],
                    "block": ex.get("block", ex.get("tx_height"))}
        self.ledger.append(muse_id, canon, None, "approved")
        return {"ok": True, "decision": "approved", "note": ex["note"]}

    def _decoded_queue(self):
        # Full decoded intent (to/value/chain/asset), never just a hash.
        out = []
        for qid, item in sorted(self.queue.items(), key=lambda kv: int(kv[0])):
            p = item["params"]
            out.append({
                "queue_id": qid,
                "chain": p.get("chain"),
                "destination": p.get("destination"),
                "asset": p.get("asset", "native"),
                "amount": p.get("amount_mojos", p.get("amount_wei")),
                "purpose": p.get("purpose", ""),
                "muse_id": item.get("muse_id"),
                "queued_at": item.get("queued_at"),
            })
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
        asset = params.get("asset", "native")
        amount = params.get("amount_mojos", params.get("amount_wei"))
        canon = json.dumps(params, sort_keys=True).encode()
        # Same pre-execution intent line as the auto-approve path: the queue
        # item is already popped (one approval = one execution attempt), so
        # the ledger is the crash record for the in-flight window.
        self.ledger.append(muse_id, canon, None, "executing")
        try:
            ex = self._execute_spend(params)
        except (evm.BroadcastUnknown, chia.BroadcastUnknown) as e:
            ref = getattr(e, "tx_hash", None) or getattr(e, "reference", None)
            self._record_velocity(params["chain"], asset, amount)
            self.ledger.append(muse_id, canon, ref,
                               "approved-submit-unknown:" + str(e))
            return {"ok": True, "queue_id": qid, "tx_hash": ref,
                    "decision": "approved-submit-unknown",
                    "note": str(e)}
        except (evm.EvmError, chia.SageError) as e:
            # Approved but never executed: the human's approval is consumed,
            # the failure is ledgered, nothing is recorded as spent. The
            # agent reports it; the human re-requests if they still want it.
            self.ledger.append(muse_id, canon, None,
                               "approved-submit-failed:" + str(e))
            return {"ok": False, "queue_id": qid, "error": str(e)}
        self._record_velocity(params["chain"], asset, amount)
        if ex["submitted"]:
            self.ledger.append(muse_id, canon, ex["tx_hash"], "approved-by-human")
            return {"ok": True, "queue_id": qid,
                    "tx_hash": ex["tx_hash"],
                    "block": ex.get("block", ex.get("tx_height"))}
        self.ledger.append(muse_id, canon, None, "approved-by-human")
        return {"ok": True, "queue_id": qid, "note": ex["note"]}

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
            return {"ok": True, "addresses": {"default": per_label}}
        out = {}
        for label in self.cfg.get("labels", ["default"]):
            per_label = {}
            for chain in kdf.CHAINS:
                if chain.startswith("chia-") and not self.cfg.get("chia_enabled", True):
                    continue
                d = kdf.derive_labeled(self.seed, chain, label)
                per_label[chain] = d.get("address", d["pubkey_hex"])
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

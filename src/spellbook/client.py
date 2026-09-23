"""The agent-facing package: how an agent (and its human) talk to spellbookd.

Two clients, two tokens (SPEC §4 S7) — the split is structural, not advisory:

  AgentClient  — holds the REQUEST token (lives in the agent's environment).
                 Can request spends and read queue/status/addresses/ledger.
                 Has NO approve method; the daemon would reject it anyway.

  HumanClient  — holds the APPROVE token (the human's own tooling, ideally a
                 separate device per O5). Approves/rejects queued spends and
                 publishes directory entries.

The conversational agent surfaces decoded intent from `queue()` / `status()`
(O10) and relays the human's decision — it never approves.
"""
import json
import socket

DEFAULT_TIMEOUT = 10


class SpellbookError(Exception):
    """The daemon said no, or the transport failed."""


class _BaseClient:
    def __init__(self, socket_path: str, token_hex: str,
                 timeout: float = DEFAULT_TIMEOUT, muse_id: str = "agent"):
        self.socket_path = socket_path
        self.token_hex = token_hex.strip()
        self.timeout = timeout
        self.muse_id = muse_id

    def _call(self, route: str, params: dict | None = None) -> dict:
        req = {"token": self.token_hex, "route": route,
               "params": params or {}, "muse_id": self.muse_id}
        try:
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.settimeout(self.timeout)
            c.connect(self.socket_path)
            c.sendall((json.dumps(req) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except (OSError, socket.timeout) as e:
            raise SpellbookError(f"cannot reach spellbookd at {self.socket_path}: {e}")
        finally:
            try:
                c.close()
            except Exception:
                pass
        try:
            resp = json.loads(buf.decode())
        except (ValueError, UnicodeDecodeError):
            raise SpellbookError("daemon returned malformed JSON")
        if not resp.get("ok"):
            raise SpellbookError(resp.get("error", "unknown daemon error"))
        return resp


class AgentClient(_BaseClient):
    """The agent's client. Request token only — no approve surface exists."""

    def request_spend(self, *, chain: str, destination: str, asset: str = "native",
                      amount_wei: int | None = None,
                      amount_mojos: int | None = None,
                      amount_lamports: int | None = None,
                      purpose: str = "") -> dict:
        """Ask the daemon for a plain-transfer spend.

        Returns the daemon's decision: {"decision": "approved"|"queued"|"denied",
        ...}. "queued" includes a queue_id for the human to review; "denied"
        includes a reason. v1 is plain transfers only — no contract calls.

        Exactly one amount kwarg: amount_wei (EVM), amount_mojos (Chia), or
        amount_lamports (Solana).
        """
        params: dict = {"chain": chain, "destination": destination,
                        "asset": asset, "purpose": purpose}
        amounts = sum(x is not None for x in
                      (amount_wei, amount_mojos, amount_lamports))
        if amounts != 1:
            raise ValueError(
                "pass exactly one of amount_wei / amount_mojos / amount_lamports")
        if amount_wei is not None:
            params["amount_wei"] = amount_wei
        elif amount_mojos is not None:
            params["amount_mojos"] = amount_mojos
        else:
            params["amount_lamports"] = amount_lamports
        return self._call("request_spend", params)

    def queue(self) -> list[dict]:
        """Queued spends as decoded intent (O10): chain, destination, asset,
        amount, purpose, muse, queued_at — never just a hash."""
        return self._call("queue_read")["queue"]

    def dex_swap(self, *, chain: str, venue: str, sell_token: str,
                 buy_token: str, sell_amount_wei: int,
                 min_buy_amount_wei: int, max_slippage_bps: int,
                 purpose: str = "", deadline_sec: int | None = None) -> dict:
        """Request a bounded swap. The queue holds bounds — exact sell
        amount, minimum buy, max slippage — never calldata. The daemon
        fetches the firm venue quote at execution time and refuses to
        sign unless it fits inside the approved bounds.

        ``venue`` is "matcha" (0x API; "0x" also accepted) or "uniswap".
        The user's dex.recommended_venues list (default: both) is
        advisory, not a gate: a swap naming another venue is queued with
        a prominent warning, and the human's per-transaction approval is
        what authorizes the venue. The venue must still serve the chain
        (neither serves Robinhood Chain) — that is a capability fact.

        Use the 0xeeee...eeee sentinel for a native sell or buy side.
        Returns the daemon's decision: approved | queued | denied.
        """
        params = {"intent": "dex_swap", "chain": chain, "venue": venue,
                  "sell_token": sell_token, "buy_token": buy_token,
                  "sell_amount_wei": sell_amount_wei,
                  "min_buy_amount_wei": min_buy_amount_wei,
                  "max_slippage_bps": max_slippage_bps, "purpose": purpose,
                  "deadline_sec": deadline_sec}
        return self._call("dex_swap", params)

    def dex_venues(self) -> dict:
        """Read-only: the user's recommended swap venues and every known
        venue (API-key env var + served chain ids). The list is a
        recommendation, not a gate — set via dex.recommended_venues in
        spellbook.json, takes effect on daemon restart."""
        return self._call("dex_venues")

    def dex_lp_add(self, *, chain: str, protocol: str, router: str,
                   token_a: str, token_b: str, amount_a_wei: int,
                   amount_b_wei: int, amount_a_min_wei: int = 0,
                   amount_b_min_wei: int = 0, fee: int | None = None,
                   tick_lower: int | None = None,
                   tick_upper: int | None = None,
                   purpose: str = "", deadline_sec: int | None = None) -> dict:
        """Request a bounded LP add (v2 addLiquidity or v3 mint).

        ``router`` is the v2 router or v3 NonfungiblePositionManager
        address — supplied by the agent, shown to the human, never
        guessed by the daemon. fee/ticks are v3-only (100/500/3000/10000).
        """
        params = {"intent": "dex_lp_add", "chain": chain, "protocol": protocol,
                  "router": router, "token_a": token_a, "token_b": token_b,
                  "amount_a_wei": amount_a_wei, "amount_b_wei": amount_b_wei,
                  "amount_a_min_wei": amount_a_min_wei,
                  "amount_b_min_wei": amount_b_min_wei, "fee": fee,
                  "tick_lower": tick_lower, "tick_upper": tick_upper,
                  "purpose": purpose, "deadline_sec": deadline_sec}
        return self._call("dex_lp_add", params)

    def status(self) -> dict:
        return self._call("status")

    def doctor(self) -> dict:
        """Read-only install health, computed daemon-side (SPEC §12b item 4).

        Presence/permissions/shape only — never key contents. The agent
        calls this instead of stat-ing the prefix itself.
        """
        return self._call("doctor")

    def addresses(self) -> dict:
        """{label: {chain: address}} — read-only, derived by the daemon."""
        return self._call("addresses")["addresses"]

    def ledger(self) -> list[dict]:
        """Decision ledger rows (P6): read through the API, never the file."""
        return self._call("ledger_read")["rows"]

    def chia_read(self, *, chain: str, op: str, **kwargs) -> dict:
        """Read-only Chia query (the daemon allowlists `op`; anything else
        is rejected server-side). Ops: get_offers, get_offer, view_offer,
        get_coins, get_pending_transactions, sync_status, ..."""
        params = {"chain": chain, "op": op}
        params.update({k: v for k, v in kwargs.items() if v is not None})
        return self._call("chia_read", params)["result"]

    def offer_make(self, *, chain: str, offered: list, requested: list,
                   fee_mojos: int = 0, purpose: str = "",
                   expires_at_second: int | None = None,
                   receive_address: str | None = None) -> dict:
        """Request an offer intent: [{asset, amount_mojos}] on each side.

        Asset is "native" (XCH) or a 64-hex CAT asset id. The daemon
        validates, runs per-leg policy, and queues for human approval
        (or executes immediately only when policy auto-approves).
        """
        params: dict = {"chain": chain, "offered": offered,
                        "requested": requested, "fee_mojos": fee_mojos,
                        "purpose": purpose}
        if expires_at_second is not None:
            params["expires_at_second"] = expires_at_second
        if receive_address:
            params["receive_address"] = receive_address
        return self._call("offer_make", params)

    def offer_take(self, *, chain: str, offer: str, fee_mojos: int = 0,
                   purpose: str = "") -> dict:
        """Request taking an offer string. The daemon decodes the offer at
        request time so policy and the queue show real legs (give/get),
        re-verifies terms at execution, and requires human approval."""
        return self._call("offer_take", {"chain": chain, "offer": offer,
                                         "fee_mojos": fee_mojos,
                                         "purpose": purpose})

    def offer_cancel(self, *, chain: str, offer_id: str | None = None,
                     offer_ids: list | None = None, fee_mojos: int = 0,
                     purpose: str = "") -> dict:
        """Request on-chain cancellation of offer(s). Always queues for
        human approval — the coins return to the wallet."""
        params: dict = {"chain": chain, "fee_mojos": fee_mojos,
                        "purpose": purpose}
        if offer_ids:
            params["offer_ids"] = offer_ids
        elif offer_id:
            params["offer_id"] = offer_id
        else:
            raise ValueError("pass offer_id or offer_ids")
        return self._call("offer_cancel", params)

    # ---- full Sage wallet surface ----
    # Every method below builds a queued, human-approved intent. Nothing
    # executes without the human's approval (policy auto-approve only
    # where the daemon's policy explicitly allows it; message_sign and
    # offer_cancel always queue).

    def _tx(self, route: str, params: dict) -> dict:
        """Call a queued Sage-transaction route (params already shaped)."""
        return self._call(route, params)

    @staticmethod
    def _tx_params(chain: str, fee_mojos: int, purpose: str, **kw) -> dict:
        p: dict = {"chain": chain, "fee_mojos": fee_mojos,
                   "purpose": purpose}
        p.update({k: v for k, v in kw.items() if v is not None})
        return p

    def nft_mint(self, *, chain: str, mints: list, did_id: str,
                 fee_mojos: int = 0, purpose: str = "") -> dict:
        """Queue minting NFTs (on-chain). Each mint is a Sage NftMint
        descriptor; did_id is the minter DID (did:chia:1…).

        Execution also requires the human's separate six-gate
        mint/issuance authorization (mint_gate.json) — queue approval
        alone does not authorize minting. The gate names the exact
        canonical digest of the queued intent (visible as canon_digest in
        the queue listing) and each grant is one-shot: it authorizes a
        single execution attempt."""
        return self._tx("nft_mint", self._tx_params(
            chain, fee_mojos, purpose, mints=mints, did_id=did_id))

    def nft_assign_did(self, *, chain: str, nft_ids: list,
                       did_id: str | None = None, fee_mojos: int = 0,
                       purpose: str = "") -> dict:
        """Queue assigning NFTs to a DID profile (did_id None unassigns)."""
        return self._tx("nft_assign_did", self._tx_params(
            chain, fee_mojos, purpose, nft_ids=nft_ids, did_id=did_id))

    def did_create(self, *, chain: str, name: str, fee_mojos: int = 0,
                   purpose: str = "") -> dict:
        """Queue creating a DID (on-chain)."""
        return self._tx("did_create", self._tx_params(
            chain, fee_mojos, purpose, name=name))

    def did_transfer(self, *, chain: str, did_ids: list, destination: str,
                     fee_mojos: int = 0, purpose: str = "",
                     clawback_at: int | None = None) -> dict:
        """Queue transferring DIDs (on-chain)."""
        return self._tx("did_transfer", self._tx_params(
            chain, fee_mojos, purpose, did_ids=did_ids,
            destination=destination, clawback_at=clawback_at))

    def did_normalize(self, *, chain: str, did_ids: list,
                      fee_mojos: int = 0, purpose: str = "") -> dict:
        """Queue normalizing DID coins (on-chain)."""
        return self._tx("did_normalize", self._tx_params(
            chain, fee_mojos, purpose, did_ids=did_ids))

    def option_mint(self, *, chain: str, expiration_seconds: int,
                    underlying: dict, strike: dict, fee_mojos: int = 0,
                    purpose: str = "") -> dict:
        """Queue minting an option contract (on-chain). Legs are
        {asset_id (64-hex or None for XCH), amount}.

        Execution also requires the human's separate six-gate
        mint/issuance authorization (mint_gate.json) — queue approval
        alone does not authorize minting. The gate names the exact
        canonical digest of the queued intent (visible as canon_digest in
        the queue listing) and each grant is one-shot: it authorizes a
        single execution attempt."""
        return self._tx("option_mint", self._tx_params(
            chain, fee_mojos, purpose, expiration_seconds=expiration_seconds,
            underlying=underlying, strike=strike))

    def option_transfer(self, *, chain: str, option_ids: list,
                        destination: str, fee_mojos: int = 0,
                        purpose: str = "",
                        clawback_at: int | None = None) -> dict:
        """Queue transferring options (on-chain)."""
        return self._tx("option_transfer", self._tx_params(
            chain, fee_mojos, purpose, option_ids=option_ids,
            destination=destination, clawback_at=clawback_at))

    def option_exercise(self, *, chain: str, option_ids: list,
                        fee_mojos: int = 0, purpose: str = "") -> dict:
        """Queue exercising options (on-chain)."""
        return self._tx("option_exercise", self._tx_params(
            chain, fee_mojos, purpose, option_ids=option_ids))

    def cat_issue(self, *, chain: str, name: str, ticker: str,
                  amount_mojos: int, revocable: bool = False,
                  fee_mojos: int = 0, purpose: str = "") -> dict:
        """Queue issuing a new CAT (on-chain token issuance).

        Execution also requires the human's separate six-gate
        mint/issuance authorization (mint_gate.json): receive 95% of
        supply, be the majority holder, hold at least 1%, articles of
        description exist, metadata is set, and a website exists. Queue
        approval alone does NOT satisfy the gate. The gate names the exact
        canonical digest of the queued intent (visible as canon_digest in
        the queue listing), binds the network, carries an expiry, and each
        grant is one-shot: a single execution attempt."""
        return self._tx("cat_issue", self._tx_params(
            chain, fee_mojos, purpose, name=name, ticker=ticker,
            amount_mojos=amount_mojos,
            revocable=revocable or None))

    def clawback_finalize(self, *, chain: str, coin_ids: list,
                          fee_mojos: int = 0, purpose: str = "") -> dict:
        """Queue finalizing a clawback (on-chain)."""
        return self._tx("clawback_finalize", self._tx_params(
            chain, fee_mojos, purpose, coin_ids=coin_ids))

    def coin_combine(self, *, chain: str, coin_ids: list,
                     fee_mojos: int = 0, purpose: str = "") -> dict:
        """Queue combining coins (on-chain)."""
        return self._tx("coin_combine", self._tx_params(
            chain, fee_mojos, purpose, coin_ids=coin_ids))

    def coin_split(self, *, chain: str, coin_ids: list, output_count: int,
                   fee_mojos: int = 0, purpose: str = "") -> dict:
        """Queue splitting coins (on-chain)."""
        return self._tx("coin_split", self._tx_params(
            chain, fee_mojos, purpose, coin_ids=coin_ids,
            output_count=output_count))

    def coin_autocombine(self, *, chain: str, max_coins: int,
                         asset: str = "native",
                         max_coin_amount: int | None = None,
                         fee_mojos: int = 0, purpose: str = "") -> dict:
        """Queue auto-combining small coins (on-chain)."""
        return self._tx("coin_autocombine", self._tx_params(
            chain, fee_mojos, purpose, asset=asset, max_coins=max_coins,
            max_coin_amount=max_coin_amount))

    def bulk_send(self, *, chain: str, addresses: list, amount_mojos: int,
                  asset: str = "native", fee_mojos: int = 0,
                  purpose: str = "", memos: list | None = None) -> dict:
        """Queue bulk-sending one amount to many addresses (on-chain)."""
        return self._tx("bulk_send", self._tx_params(
            chain, fee_mojos, purpose, asset=asset, addresses=addresses,
            amount_mojos=amount_mojos, memos=memos))

    def multi_send(self, *, chain: str, payments: list, fee_mojos: int = 0,
                   purpose: str = "") -> dict:
        """Queue a mixed-asset multi-payment (on-chain). Payments are
        {asset_id (64-hex or None), address, amount, memos}."""
        return self._tx("multi_send", self._tx_params(
            chain, fee_mojos, purpose, payments=payments))

    def message_sign(self, *, chain: str, message: str, address: str = "",
                     public_key: str = "", purpose: str = "") -> dict:
        """Queue signing a message (off-chain). Always requires human
        approval — a signature is a capability even with no funds moving.
        Pass address OR public_key."""
        params = self._tx_params(chain, 0, purpose, message=message)
        if address:
            params["address"] = address
        if public_key:
            params["public_key"] = public_key
        return self._tx("message_sign", params)

    # ---- wallet-local metadata (direct, no queue, no chain, no funds)

    def offer_import(self, *, chain: str, offer: str) -> dict:
        """Import an offer string into the wallet's local offer book."""
        return self._call("offer_import", {"chain": chain, "offer": offer})

    def offer_delete(self, *, chain: str, offer_id: str) -> dict:
        """Delete an offer from the wallet's local offer book."""
        return self._call("offer_delete",
                          {"chain": chain, "offer_id": offer_id})

    def offer_combine(self, *, chain: str, offers: list) -> dict:
        """Combine offer strings into one (local, off-chain)."""
        return self._call("offer_combine",
                          {"chain": chain, "offers": offers})

    def cat_update(self, *, chain: str, record: dict) -> dict:
        """Update a CAT token record (wallet-local display metadata)."""
        return self._call("cat_update", {"chain": chain, "record": record})

    def did_update(self, *, chain: str, did_id: str, name: str | None = None,
                   visible: bool = True) -> dict:
        """Rename / show-hide a DID (wallet-local)."""
        return self._call("did_update",
                          {"chain": chain, "did_id": did_id, "name": name,
                           "visible": visible})

    def nft_update(self, *, chain: str, nft_id: str,
                   visible: bool = True) -> dict:
        """Show/hide an NFT (wallet-local)."""
        return self._call("nft_update",
                          {"chain": chain, "nft_id": nft_id,
                           "visible": visible})

    def nft_collection_update(self, *, chain: str, collection_id: str,
                              visible: bool = True) -> dict:
        """Show/hide an NFT collection (wallet-local)."""
        return self._call("nft_collection_update",
                          {"chain": chain, "collection_id": collection_id,
                           "visible": visible})

    def nft_redownload(self, *, chain: str, nft_id: str) -> dict:
        """Re-fetch an NFT's data/metadata (wallet-local)."""
        return self._call("nft_redownload",
                          {"chain": chain, "nft_id": nft_id})

    def option_update(self, *, chain: str, option_id: str,
                      visible: bool = True) -> dict:
        """Show/hide an option (wallet-local)."""
        return self._call("option_update",
                          {"chain": chain, "option_id": option_id,
                           "visible": visible})


class HumanClient(_BaseClient):
    """The human's client. Approve token only — separate tooling (O5)."""

    def approve(self, queue_id: str) -> dict:
        return self._call("queue_approve", {"queue_id": queue_id})

    def reject(self, queue_id: str) -> dict:
        return self._call("queue_reject", {"queue_id": queue_id})

    def publish_directory_entry(self, entry: dict) -> dict:
        return self._call("publish_directory_entry", {"entry": entry})

    # Read-only surface, same as the agent's (the human sees what the agent sees).
    def queue(self) -> list[dict]:
        return self._call("queue_read")["queue"]

    def status(self) -> dict:
        return self._call("status")

    def addresses(self) -> dict:
        return self._call("addresses")["addresses"]

    def ledger(self) -> list[dict]:
        return self._call("ledger_read")["rows"]

    def chia_read(self, *, chain: str, op: str, **kwargs) -> dict:
        params = {"chain": chain, "op": op}
        params.update({k: v for k, v in kwargs.items() if v is not None})
        return self._call("chia_read", params)["result"]

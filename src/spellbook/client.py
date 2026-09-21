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

    def status(self) -> dict:
        return self._call("status")

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

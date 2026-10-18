"""The Forge (a Chia AMM at forge.awizard.dev) — the client behind ``forge_swap``.

The Forge settles a Chia offer against its pools in one transaction. A swap through it
is: ask the network's router for a quote, have the wallet make an offer that gives
``intent.offer`` and asks for ``intent.request``, post that offer to the router's settle
lane (``dry_run`` first), and watch the pool coins it spent. The contract is the Forge's
``docs/FORGE_AGENT_API.md``, served by each router at ``/docs/FORGE_AGENT_API.md``.

What this module will and will not do, because it sits next to custody:

- **The router URL comes from the daemon's configuration**, never from a request:
  ``chia.forge_responders`` per network, defaulting to the Forge's own routers.
  ``markets`` answers with the network it serves, and the caller checks it.
- **It never signs.** Sage builds and signs the offer (the existing ``offer_make``
  path); this module only moves the finished ``offer1…`` string. An offer cannot release
  a coin unless its requested payment is made, so nothing the router sends back can
  widen what the human approved. (An earlier design had the daemon sign the unsigned
  ``coin_spends`` the router's ``build`` returns, after matching them to the quote's
  ``intent`` — both come from the router, so the match proves nothing.)
- **Reads may be retried; a settle never is.** A quote, the market list and a status
  poll are read-only and retried on a dropped connection or a gateway error. The settle
  POST is sent once: an answer the router could not finish (503 ``FORGE_PUSH_PENDING``,
  ``ambiguous: true``, any 5xx, a dropped connection) means the bundle may land, and is
  reported as ambiguous so the caller watches it instead of sending it again (rules
  R5, R6, R9 in docs/FORGE_SWAP.md).
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spellbook import __version__

#: The Forge's own routers. A daemon may point a network elsewhere in its config
#: (``chia.forge_responders``) — the operator's file, never the requester's call.
DEFAULT_RESPONDERS = {
    "mainnet": "https://forge-ui-production.up.railway.app",
    "testnet11": "https://forge-responder.up.railway.app",
}
NATIVE_ID = "0" * 64
USER_AGENT = f"spellbook/{__version__} (+https://github.com/awizardxch/Spellbook)"
READ_RETRY_DELAYS_SEC = (1, 3, 6)
_GATEWAY = frozenset({502, 503, 504})


class ForgeError(Exception):
    """A definite failure: nothing was settled (a refused quote, a refused rehearsal,
    a refused settle, a responder serving the wrong network)."""


class ForgeAmbiguous(ForgeError):
    """The settle POST left the machine and its outcome is unknown. Never resend the
    offer: poll status with ``watch`` until the pre-trade tips are spent."""

    def __init__(self, message: str, transaction_id: str | None, watch: dict | None):
        super().__init__(message)
        self.transaction_id = transaction_id
        self.watch = watch


def responder_for(network: str, chia_cfg: dict | None) -> str:
    """The router base URL for a network: the daemon's configuration, else the default.
    https only; plain http only to a loopback host (a local router under test)."""
    configured = ((chia_cfg or {}).get("forge_responders") or {}).get(network)
    url = (configured or DEFAULT_RESPONDERS.get(network) or "").strip().rstrip("/")
    if not url:
        raise ForgeError(f"no Forge router configured for {network}")
    parsed = urllib.parse.urlparse(url)
    loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ForgeError(f"Forge router for {network} must be https: {url!r}")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ForgeError(f"Forge router for {network} must be a bare origin: {url!r}")
    return url


def _send(method: str, url: str, body: dict | None, timeout: int) -> tuple[int, dict | None]:
    """One request. Returns (status, parsed JSON or None) for ANY HTTP answer; raises
    the transport error when no answer came back."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        payload = json.loads(raw.decode() or "null")
    except (ValueError, UnicodeDecodeError):
        payload = None
    return status, payload if isinstance(payload, dict) else None


def _transient(e: BaseException) -> bool:
    if isinstance(e, urllib.error.URLError):
        e = e.reason if isinstance(e.reason, BaseException) else e
    return isinstance(e, (http.client.HTTPException, ConnectionError, TimeoutError, OSError))


def _read(method: str, url: str, body: dict | None = None, timeout: int = 30,
          sleep=time.sleep) -> dict:
    """A read-only call, retried only when no answer or a gateway error came back."""
    last = None
    for attempt in range(len(READ_RETRY_DELAYS_SEC) + 1):
        try:
            status, payload = _send(method, url, body, timeout)
        except Exception as e:  # noqa: BLE001 — classified just below
            if not _transient(e):
                raise ForgeError(f"Forge router unreachable ({url}): {e}") from e
            last = f"no answer: {e}"
        else:
            if status in _GATEWAY:
                last = f"HTTP {status}"
            elif 200 <= status < 300 and payload is not None and payload.get("success") is not False:
                return payload
            else:
                detail = (payload or {}).get("error") or f"HTTP {status}"
                raise ForgeError(f"Forge router refused ({url}): {detail}")
        if attempt < len(READ_RETRY_DELAYS_SEC):
            sleep(READ_RETRY_DELAYS_SEC[attempt])
    raise ForgeError(f"Forge router unavailable ({url}): {last}")


def check_network(base: str, network: str, read=None) -> dict:
    """The router's market list, refused unless it serves ``network``."""
    markets = (read or _read)("GET", f"{base}/api/v1/agent/markets")
    served = markets.get("network")
    if served != network:
        raise ForgeError(f"the Forge router at {base} serves {served!r}, not {network!r}")
    return markets


def quote(base: str, asset_in: str, asset_out: str, amount_in: int, read=None) -> dict:
    return (read or _read)("POST", f"{base}/api/v1/agent/quote",
                {"asset_in": asset_in, "asset_out": asset_out, "amount_in": str(amount_in)})


def _amount(value) -> int | None:
    try:
        n = int(str(value))
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _sides(intent: dict) -> tuple[list, list]:
    def legs(items):
        out = []
        for it in items or []:
            asset = str((it or {}).get("asset_id") or "").lower().removeprefix("0x")
            out.append((asset, _amount((it or {}).get("amount"))))
        return out
    return legs((intent or {}).get("offer")), legs((intent or {}).get("request"))


def pick_quote(answer: dict, asset_in: str, asset_out: str, amount_in: int) -> dict | None:
    """The best executable Forge quote that gives EXACTLY ``amount_in`` of ``asset_in``
    and asks for one positive amount of ``asset_out``; None when there is none.
    Returns {"amount_out", "settlement_body", "intent", "quote"}."""
    for q in answer.get("quotes") or []:
        if not isinstance(q, dict) or not q.get("executable"):
            continue
        body = (q.get("settlement") or {}).get("body")
        if not isinstance(body, dict) or "offer" in body:
            continue
        offered, requested = _sides(q.get("intent") or {})
        if offered != [(asset_in, amount_in)]:
            continue
        if len(requested) != 1 or requested[0][0] != asset_out or requested[0][1] is None:
            continue
        return {"amount_out": requested[0][1], "settlement_body": body,
                "intent": q.get("intent"), "quote": q}
    return None


def settle(base: str, body: dict, timeout: int = 120, send=None) -> dict:
    """POST the offer to the settle lane ONCE. A dry run answers or raises ForgeError;
    a live settle answers, raises ForgeError (a definite refusal: nothing was pushed),
    or raises ForgeAmbiguous (it may land: watch it, never resend)."""
    dry = body.get("dry_run") is True
    url = f"{base}/api/v1/agent/swap"
    try:
        status, payload = (send or _send)("POST", url, body, timeout)
    except Exception as e:  # noqa: BLE001 — a live POST that got no answer is ambiguous
        if dry:
            raise ForgeError(f"Forge rehearsal got no answer: {e}") from e
        raise ForgeAmbiguous(f"Forge settle got no answer ({e}); it may still land",
                             None, None) from e
    payload = payload or {}
    if payload.get("success") is True and 200 <= status < 300:
        return payload
    detail = payload.get("error") or payload.get("code") or f"HTTP {status}"
    if dry:
        raise ForgeError(f"Forge rehearsal refused: {detail}")
    if payload.get("ambiguous") is True or payload.get("code") == "FORGE_PUSH_PENDING" or status >= 500:
        raise ForgeAmbiguous(f"Forge settle outcome unknown: {detail}",
                             payload.get("transaction_id"), payload.get("watch"))
    raise ForgeError(f"Forge settle refused: {detail}")


def status(base: str, watch: dict, read=None) -> dict:
    """Has it landed? ``confirmed`` is true only with ``proof: "pre-trade tips spent"``
    (R8); "indexed tips exist" is true the moment a push is accepted."""
    watch = watch or {}
    body = {"launcher_ids": list(watch.get("launcher_ids") or []),
            "spent_coin_ids": list(watch.get("spent_coin_ids") or [])}
    answer = (read or _read)("POST", f"{base}/api/v1/agent/status", body)
    confirmed = answer.get("confirmed") is True and answer.get("proof") == "pre-trade tips spent"
    return {**answer, "confirmed": confirmed}

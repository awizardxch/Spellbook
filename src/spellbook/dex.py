"""DEX aggregation for the Spellbook wallet — quotes, calldata builders,
and execution-time validation.

Two quote venues (both free API keys, see docs/AGENT_ONBOARDING.md):

- **matcha** — the 0x Swap API v2, the engine behind matcha.xyz.
  ``https://api.0x.org``. ``GET /swap/allowance-holder/quote`` and
  ``/swap/permit2/quote`` return firm quotes with ready-to-sign calldata.
  Header ``0x-api-key`` + ``0x-version: v2``. Chain via ``chainId`` query
  param.
- **Uniswap** — ``https://trade-api.gateway.uniswap.org/v1``.
  Flow: ``POST /check_approval`` -> ``POST /quote`` -> ``POST /swap``
  (unsigned tx). Header ``x-api-key``. ``X-Agent-Info`` attribution is
  sent on every call.

- **cast** — Cast (``https://cast.awizard.dev``), aWizard's swap router
  over the 0x Swap API on Base and Robinhood Chain. No API key. Its
  agent API (``/api/agent/quote``) returns allowance-holder calldata plus
  the spender, and it also serves token lists, token lookup and USD
  prices. Cast takes its platform fee inside the quoted swap.

Plus pure-Python calldata builders for direct pool interaction (no API
key needed — useful on chains neither aggregator covers, e.g. the
Uniswap-v2-style pools on Robinhood Chain):

- ERC-20 ``approve`` / ``allowance``
- Uniswap v2 ``swapExactTokensForTokens`` / ``addLiquidity``
- Uniswap v3 ``exactInputSingle`` (SwapRouter) / ``mint``
  (NonfungiblePositionManager)

VENUE RECOMMENDATIONS + EXECUTION (SPEC §10 v2): the user keeps a
recommended-venue list via ``dex.recommended_venues`` in spellbook.json
(default: matcha + uniswap; ``normalize_venue`` maps the "0x" alias to
"matcha"). The list is advisory, not a gate: a swap naming another
venue carries a prominent warning on the queued intent, and the human's
per-transaction approval is what authorizes the venue. Nothing in this
module signs or broadcasts. Quotes are fetched and normalized here; at
execution time the daemon fetches the firm quote again and validates it
field-by-field against the human-approved bounds
(``validate_swap_intent_against_quote``) before anything is signed. A
venue that doesn't serve the intent's chain is refused — that is a
capability fact, not a policy choice.

All amounts are integers in base units (wei etc.). All addresses are
checksummed-or-lowercase hex; they are validated, never assumed.
"""

import http.client
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from spellbook import __version__

# ---------------------------------------------------------------------------
# errors + venue metadata
# ---------------------------------------------------------------------------


class DexError(Exception):
    """Anything the DEX layer refuses to do or cannot complete."""


#: 0x Swap API v2 base URL.
#:
#: Override with the ZEROX_BASE_URL environment variable to point at a
#: Spellbook quote relay (e.g. https://spellbook.awizard.dev) instead of
#: calling 0x directly. The relay holds the operator's 0x API key
#: server-side and returns 0x-compatible quotes; the daemon still signs
#: with its own seed — the relay never holds funds or signs.
import os as _os


def relay_mode() -> bool:
    """Quote traffic is routed to a quote relay (e.g. the Cast site via the
    local shim) instead of api.0x.org directly. The relay holds the API key
    server-side, so the local key may be blank — it is ignored."""
    return bool(_os.environ.get("ZEROX_BASE_URL"))

ZEROX_BASE = _os.environ.get("ZEROX_BASE_URL", "https://api.0x.org")

#: Uniswap Trading API base URL.
UNISWAP_BASE = "https://trade-api.gateway.uniswap.org/v1"

#: Cast base URL (override with CAST_BASE_URL, e.g. for a preview deploy).
CAST_BASE = _os.environ.get("CAST_BASE_URL", "https://cast.awizard.dev").rstrip("/")

#: Chains the 0x Swap API v2 serves, mirrored from 0x's official
#: supported-chains documentation — the docs are the authority; this
#: list is re-checked against them, never hand-maintained:
#: https://docs.0x.org/docs/introduction/supported-chains
ZEROX_CHAINS = frozenset({
    1,       # Ethereum
    2741,    # Abstract
    42161,   # Arbitrum
    5042,    # Arc
    43114,   # Avalanche
    8453,    # Base
    80094,   # Berachain
    56,      # BNB Chain
    999,     # HyperEVM
    57073,   # Ink
    59144,   # Linea
    5000,    # Mantle
    143,     # Monad
    10,      # Optimism
    9745,    # Plasma
    137,     # Polygon
    4663,    # Robinhood Chain mainnet
    534352,  # Scroll
    146,     # Sonic
    4217,    # Tempo
    130,     # Unichain
    480,     # World Chain
})

#: Chains the Uniswap Trading API serves for swapping, mirrored from
#: Uniswap's official supported-chains documentation — the docs are the
#: authority; this list is re-checked against them, never hand-maintained:
#: https://developers.uniswap.org/docs/trading/swapping-api/supported-chains
UNISWAP_CHAINS = frozenset({
    1,        # Ethereum
    10,       # OP Mainnet
    56,       # BNB Smart Chain
    130,      # Unichain
    137,      # Polygon
    143,      # Monad
    196,      # X Layer
    324,      # zkSync
    480,      # World Chain
    1868,     # Soneium
    4217,     # Tempo
    4326,     # MegaETH
    4663,     # Robinhood Chain mainnet
    5042,     # Arc
    8453,     # Base
    42161,    # Arbitrum
    42220,    # Celo
    43114,    # Avalanche
    57073,    # Ink
    59144,    # Linea
    7777777,  # Zora
    1301,     # Unichain Sepolia (testnet)
    84532,    # Base Sepolia (testnet)
    11155111, # Ethereum Sepolia (testnet)
})

#: Chains Cast serves, mirrored from its GET /api/agent/networks.
CAST_CHAINS = frozenset({
    8453,    # Base
    4663,    # Robinhood Chain mainnet
})

#: 0x's sentinel for the native currency (per the 0x docs, native is
#: represented as 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE).
NATIVE_SENTINEL = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

#: Uniswap's native-currency representation (per the Uniswap
#: supported-chains docs: "To swap native tokens, use the address
#: 0x0000000000000000000000000000000000000000").
NATIVE_ZERO = "0x0000000000000000000000000000000000000000"


def _is_native_token(token: str) -> bool:
    """True for either venue's native-currency representation."""
    return (token or "").lower() in (NATIVE_SENTINEL, NATIVE_ZERO)


#: Attribution header Uniswap asks AI-agent integrations to send. Per
#: Uniswap's agent-attribution docs, X-Agent-Info is optional and
#: analytics-only, and when sent its value must be a JSON object with a
#: required ``decision_origin`` (exactly "autonomous" or
#: "human_mediated", case-sensitive) plus optional ``integration_name``
#: and ``version`` — a plain string is dropped as malformed:
#: https://developers.uniswap.org/docs/trading/swapping-api/start-building/agent-attribution
#: Spellbook swaps always carry the human's per-transaction approval, so
#: the origin is "human_mediated".
AGENT_INFO = json.dumps({
    "decision_origin": "human_mediated",
    "integration_name": "spellbook",
})


# ---------------------------------------------------------------------------
# Venue registry — canonical names, aliases, and the user's recommended
# venue list (advisory; the human's approval authorizes the venue).
# ---------------------------------------------------------------------------

#: Canonical venue name for the 0x Swap API v2 (the engine behind matcha.xyz).
VENUE_MATCHA = "matcha"

#: Canonical venue name for the Uniswap Trading API.
VENUE_UNISWAP = "uniswap"

#: Canonical venue name for Cast (cast.awizard.dev).
VENUE_CAST = "cast"

#: Every venue the DEX layer knows how to talk to.
KNOWN_VENUES = (VENUE_MATCHA, VENUE_UNISWAP, VENUE_CAST)

#: User-facing spellings -> canonical names. "0x" is the API brand behind
#: matcha; both spellings are accepted wherever a venue is named.
VENUE_ALIASES = {
    "0x": VENUE_MATCHA,
    "matcha": VENUE_MATCHA,
    "uniswap": VENUE_UNISWAP,
    "cast": VENUE_CAST,
}

#: Which chains each venue's API serves. Conservative subsets — unknown
#: chains are refused, never guessed.
VENUE_CHAINS = {
    VENUE_MATCHA: ZEROX_CHAINS,
    VENUE_UNISWAP: UNISWAP_CHAINS,
    VENUE_CAST: CAST_CHAINS,
}

#: API-key env var per venue (keys live in the daemon's environment,
#: never in the repo).
VENUE_ENV_KEYS = {
    VENUE_MATCHA: "ZERO_EX_API_KEY",
    VENUE_UNISWAP: "UNISWAP_API_KEY",
    VENUE_CAST: "CAST_API_KEY",
}

#: Venues whose API key is optional — the call works without one. Cast's
#: agent API is open; CAST_API_KEY is only sent if the operator set one.
VENUES_KEY_OPTIONAL = frozenset({VENUE_CAST})

#: Recommended venues used when spellbook.json names no
#: dex.recommended_venues. Advisory only — the human's per-transaction
#: approval is the actual authorization; other venues trigger a warning.
DEFAULT_RECOMMENDED_VENUES = (VENUE_MATCHA, VENUE_UNISWAP)


def normalize_venue(name) -> str:
    """Map a user-supplied venue name to its canonical form.

    Accepts the canonical names plus the "0x" alias (case- and
    whitespace-tolerant). Unknown names raise DexError — the venue set
    is closed.
    """
    if isinstance(name, str):
        canon = VENUE_ALIASES.get(name.strip().lower())
        if canon is not None:
            return canon
    raise DexError(
        f"unknown DEX venue {name!r} — known venues: "
        f"{', '.join(KNOWN_VENUES)}")


def venue_serves_chain(venue: str, chain_id: int) -> bool:
    """True if the venue's API serves chain_id. Unknown venues and
    unlisted chains are refused (False), never guessed."""
    return chain_id in VENUE_CHAINS.get(venue, frozenset())


def _is_address(s) -> bool:
    return (
        isinstance(s, str)
        and len(s) == 42
        and s.startswith("0x")
        and all(c in "0123456789abcdefABCDEF" for c in s[2:])
    )


def _require_address(s: str, what: str) -> str:
    if not _is_address(s):
        raise DexError(f"bad {what} address: {s!r}")
    return s


def _require_positive_int(n, what: str) -> int:
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        raise DexError(f"{what} must be a positive integer in base units, got {n!r}")
    return n


#: Sent on every DEX call. Python's default "Python-urllib/3.x" is refused
#: or throttled by some edges, and a named client is easier to find in a
#: venue's logs.
USER_AGENT = f"spellbook/{__version__} (+https://github.com/awizardxch/Spellbook)"

#: Backoff between attempts when a DEX call fails before the venue answered
#: (connection reset, empty reply, timeout) or with a gateway error. Every
#: DEX call in this module is read-only — quotes, prices, unsigned-tx
#: building — so retrying one never signs, broadcasts or moves funds, and
#: the quote that finally arrives is the one validated before signing.
#: Spread over ~40s rather than a burst: drops tend to come in bursts on
#: flaky egress, and a quick burst of retries all lands inside one.
RETRY_DELAYS_SEC = (2, 5, 10, 20)

#: Wall-clock cap across all attempts, so a dead venue fails in bounded time.
RETRY_BUDGET_SEC = 90

#: Gateway statuses: the venue's own upstream failed, the request was fine.
_RETRYABLE_HTTP = frozenset({502, 503, 504})


def _is_transient(e: BaseException) -> bool:
    """True when the request or its response never completed — the venue
    never gave an answer, so asking again is the only way to get one."""
    if isinstance(e, urllib.error.HTTPError):
        return e.code in _RETRYABLE_HTTP
    if isinstance(e, urllib.error.URLError):
        if not isinstance(e.reason, BaseException):
            return False  # e.g. a malformed URL — config, not network
        e = e.reason
    if isinstance(e, ssl.SSLCertVerificationError):
        return False  # a bad certificate is not a blip
    return isinstance(e, (http.client.RemoteDisconnected,
                          http.client.IncompleteRead,
                          http.client.BadStatusLine,
                          ConnectionError, TimeoutError, OSError))


def _http_json(method: str, url: str, headers: dict, body: dict | None = None,
               timeout: int = 25) -> dict:
    """One DEX API call, retried only on connection-level/gateway failures.

    Each attempt carries ``X-Request-Id: <id>-<attempt>`` so a failure can
    be matched against the venue's logs; the id is in every error message.
    A definite answer from the venue (4xx, other 5xx, a parsed body) is
    never retried.
    """
    data = None
    base_headers = dict(headers, **{"User-Agent": USER_AGENT})
    if body is not None:
        data = json.dumps(body).encode()
        base_headers["Content-Type"] = "application/json"
    request_id = uuid.uuid4().hex[:16]
    started = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        rid = f"{request_id}-{attempt}"
        req = urllib.request.Request(
            url, data=data, headers=dict(base_headers, **{"X-Request-Id": rid}),
            method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:
            delays = RETRY_DELAYS_SEC
            if attempt <= len(delays) and _is_transient(e):
                delay = delays[attempt - 1]
                if time.monotonic() - started + delay < RETRY_BUDGET_SEC:
                    time.sleep(delay)
                    continue
            if isinstance(e, urllib.error.HTTPError):
                try:
                    detail = e.read().decode()[:500]
                except Exception:
                    detail = ""
                raise DexError(f"DEX API HTTP {e.code} (request id {rid}, "
                               f"attempt {attempt}): {detail}")
            raise DexError(f"DEX API unreachable ({method} {url}; request id "
                           f"{rid}, attempt {attempt}): {e}")


def _norm_quote(venue: str, chain_id: int, sell_token: str, buy_token: str,
                sell_amount: int, buy_amount: int, min_buy_amount: int | None,
                price_impact_bps: int | None, gas_estimate: int | None,
                tx: dict | None, allowance_target: str | None,
                raw: dict) -> dict:
    """Common quote shape across venues. ``tx`` is unsigned calldata
    (``to``/``data``/``value``/``gas``) or None for indicative prices."""
    return {
        "venue": venue,
        "chain_id": chain_id,
        "sell_token": sell_token,
        "buy_token": buy_token,
        "sell_amount": str(sell_amount),
        "buy_amount": str(buy_amount),
        "min_buy_amount": str(min_buy_amount) if min_buy_amount is not None else None,
        "price_impact_bps": price_impact_bps,
        "gas_estimate": gas_estimate,
        "tx": tx,
        "allowance_target": allowance_target,
        "fetched_at": int(time.time()),
        "raw": raw,
    }

# ---------------------------------------------------------------------------
# 0x Swap API v2 (the matcha.xyz engine)
# ---------------------------------------------------------------------------


class ZeroExClient:
    """Thin client for the 0x Swap API v2.

    ``price`` is indicative (no calldata). ``quote`` returns firm,
    executable calldata — it is short-lived (tens of seconds) and must be
    re-fetched at execution time, never stored and replayed.
    """

    def __init__(self, api_key: str):
        if not api_key and not relay_mode():
            raise DexError("0x API key required (dashboard.0x.org, free)")
        # In relay mode the key value is ignored — the relay (Cast site)
        # holds the real key server-side — so a blank key is fine.
        self.api_key = api_key or ""

    def _headers(self) -> dict:
        return {"0x-api-key": self.api_key, "0x-version": "v2"}

    def _get(self, path: str, params: dict) -> dict:
        qs = urllib.parse.urlencode(params)
        return _http_json("GET", f"{ZEROX_BASE}{path}?{qs}", self._headers())

    def _check_chain(self, chain_id: int) -> int:
        if chain_id not in ZEROX_CHAINS:
            raise DexError(
                f"matcha (0x API) does not serve chain {chain_id} "
                f"(known: {sorted(ZEROX_CHAINS)})")
        return chain_id

    def price(self, chain_id: int, sell_token: str, buy_token: str,
              sell_amount: int, taker: str | None = None) -> dict:
        """Indicative price — no calldata, safe to poll for display."""
        self._check_chain(chain_id)
        params = {
            "chainId": chain_id,
            "sellToken": _require_address(sell_token, "sell token"),
            "buyToken": _require_address(buy_token, "buy token"),
            "sellAmount": str(_require_positive_int(sell_amount, "sell amount")),
        }
        if taker:
            params["taker"] = _require_address(taker, "taker")
        raw = self._get("/swap/allowance-holder/price", params)
        buy = raw.get("buyAmount")
        if buy is None:
            raise DexError(f"0x price response missing buyAmount: {raw!r}"[:300])
        return _norm_quote(
            venue="matcha", chain_id=chain_id,
            sell_token=sell_token, buy_token=buy_token,
            sell_amount=sell_amount, buy_amount=int(buy),
            min_buy_amount=int(raw["minBuyAmount"]) if raw.get("minBuyAmount") else None,
            price_impact_bps=None, gas_estimate=None,
            tx=None, allowance_target=None, raw=raw)

    def quote(self, chain_id: int, sell_token: str, buy_token: str,
              sell_amount: int, taker: str,
              slippage_bps: int = 50, use_permit2: bool = False) -> dict:
        """Firm quote with executable calldata.

        ``slippage_bps`` bounds the worst acceptable output (50 = 0.5%).
        The returned calldata expires quickly — validate every field again
        at execution time and never replay a stale quote.
        """
        self._check_chain(chain_id)
        _require_address(taker, "taker")
        if not (0 < slippage_bps <= 500):
            raise DexError("slippage_bps must be 1..500 (0.01%..5%)")
        path = "/swap/permit2/quote" if use_permit2 else "/swap/allowance-holder/quote"
        raw = self._get(path, {
            "chainId": chain_id,
            "sellToken": _require_address(sell_token, "sell token"),
            "buyToken": _require_address(buy_token, "buy token"),
            "sellAmount": str(_require_positive_int(sell_amount, "sell amount")),
            "taker": taker,
            "slippageBps": str(slippage_bps),
        })
        txn = raw.get("transaction") or {}
        to = txn.get("to")
        data = txn.get("data")
        if not to or not data:
            raise DexError(f"0x quote missing executable transaction: {raw!r}"[:300])
        # Allowance target: NEVER hardcode. Read it from the quote.
        allowance_target = (
            raw.get("allowanceTarget")
            or (raw.get("issues") or {}).get("allowance", {}).get("spender")
        )
        if allowance_target and not _is_address(allowance_target):
            raise DexError(f"0x returned bad allowanceTarget: {allowance_target!r}")
        tx = {
            "to": to,
            "data": data,
            "value": str(txn.get("value", "0")),
            "gas": txn.get("gas"),
            "gas_price": txn.get("gasPrice"),
        }
        buy_amount = int(raw.get("buyAmount", "0"))
        min_buy = raw.get("minBuyAmount")
        return _norm_quote(
            venue="matcha", chain_id=chain_id,
            sell_token=sell_token, buy_token=buy_token,
            sell_amount=sell_amount, buy_amount=buy_amount,
            min_buy_amount=int(min_buy) if min_buy else None,
            price_impact_bps=None, gas_estimate=txn.get("gas"),
            tx=tx, allowance_target=allowance_target, raw=raw)


# ---------------------------------------------------------------------------
# Cast (cast.awizard.dev)
# ---------------------------------------------------------------------------


class CastClient:
    """Client for Cast's API — the agent swap endpoints plus its read-only
    token and price endpoints. Docs: https://cast.awizard.dev/agents

    Quotes are 0x allowance-holder quotes with Cast's platform fee taken
    inside the swap. As with every venue, only ``tx`` and
    ``allowance_target`` are used: the daemon builds its own exact-amount
    approval and never signs Cast's ``approval`` calldata.
    """

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key or None
        self.base = (base_url or CAST_BASE).rstrip("/")

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _get(self, path: str, params: dict | None = None) -> dict:
        qs = f"?{urllib.parse.urlencode(params)}" if params else ""
        return _http_json("GET", f"{self.base}{path}{qs}", self._headers())

    def _post(self, path: str, body: dict) -> dict:
        return _http_json("POST", f"{self.base}{path}", self._headers(), body)

    @staticmethod
    def _check_chain(chain_id: int) -> int:
        if chain_id not in CAST_CHAINS:
            raise DexError(
                f"cast does not serve chain {chain_id} "
                f"(known: {sorted(CAST_CHAINS)})")
        return chain_id

    # -- read-only info ----------------------------------------------------

    def networks(self) -> dict:
        """Supported chains, common + wizard tokens, fee recipient, flow."""
        return self._get("/api/agent/networks")

    def tokens(self, chain_id: int, source: str | None = None) -> dict:
        """A token list for the chain: ``{"records": {address: {symbol,
        name, decimals, logoURI}}}``. Source keys per chain are listed by
        ``networks()``; omitted, Cast uses the chain's primary list."""
        self._check_chain(chain_id)
        params = {"chainId": chain_id}
        if source:
            params["source"] = source
        return self._get("/api/wizardswap/tokens", params)

    def token_lookup(self, chain_id: int, address: str) -> dict:
        """Symbol, name and decimals for any token address on the chain."""
        self._check_chain(chain_id)
        return self._get("/api/token-lookup", {
            "chainId": chain_id,
            "address": _require_address(address, "token")})

    def token_prices(self, chain_id: int, addresses: list,
                     decimals: list | None = None) -> dict:
        """USD prices: ``{address_lower: price}`` for the ones Cast could
        price. Display only — never used to bound a swap."""
        self._check_chain(chain_id)
        addrs = [_require_address(a, "token") for a in addresses]
        if not addrs:
            return {}
        params = {"chainId": chain_id, "addresses": ",".join(addrs)}
        if decimals:
            if len(decimals) != len(addrs):
                raise DexError("decimals must match addresses one-to-one")
            params["decimals"] = ",".join(str(int(d)) for d in decimals)
        return self._get("/api/token-prices", params).get("prices", {})

    # -- swaps -------------------------------------------------------------

    def _swap_body(self, chain_id, sell_token, buy_token, sell_amount,
                   taker, slippage_bps) -> dict:
        self._check_chain(chain_id)
        body = {
            "chainId": chain_id,
            "sellToken": _require_address(sell_token, "sell token"),
            "buyToken": _require_address(buy_token, "buy token"),
            "sellAmount": str(_require_positive_int(sell_amount, "sell amount")),
        }
        if taker:
            body["taker"] = _require_address(taker, "taker")
        if slippage_bps is not None:
            if not (0 < slippage_bps <= 500):
                raise DexError("slippage_bps must be 1..500 (0.01%..5%)")
            body["slippageBps"] = slippage_bps
        return body

    def _check_echo(self, raw: dict, chain_id: int, body: dict) -> None:
        """Cast echoes the request; a mismatch means the answer is not for
        this request, so refuse it rather than trust it."""
        if raw.get("chainId") != chain_id:
            raise DexError(f"cast answered for chain {raw.get('chainId')}, "
                           f"asked {chain_id} — refusing")
        for k in ("sellToken", "buyToken"):
            if str(raw.get(k, "")).lower() != body[k].lower():
                raise DexError(f"cast answered {k} {raw.get(k)!r}, asked "
                               f"{body[k]!r} — refusing")

    def price(self, chain_id: int, sell_token: str, buy_token: str,
              sell_amount: int, taker: str | None = None) -> dict:
        """Indicative price — no calldata, safe to poll for display."""
        body = self._swap_body(chain_id, sell_token, buy_token, sell_amount,
                               taker, None)
        raw = self._post("/api/agent/price", body)
        self._check_echo(raw, chain_id, body)
        if raw.get("buyAmount") is None:
            raise DexError(f"cast price response missing buyAmount: {raw!r}"[:300])
        return _norm_quote(
            venue=VENUE_CAST, chain_id=chain_id,
            sell_token=raw["sellToken"], buy_token=raw["buyToken"],
            sell_amount=int(raw.get("sellAmount") or sell_amount),
            buy_amount=int(raw["buyAmount"]),
            min_buy_amount=int(raw["minBuyAmount"]) if raw.get("minBuyAmount") else None,
            price_impact_bps=None, gas_estimate=None,
            tx=None, allowance_target=None, raw=raw)

    def quote(self, chain_id: int, sell_token: str, buy_token: str,
              sell_amount: int, taker: str, slippage_bps: int = 50) -> dict:
        """Firm quote with executable calldata (allowance-holder).

        The returned sell amount is Cast's echo, not the request, so
        ``validate_swap_intent_against_quote`` really compares it against
        the approved amount. Expires in seconds — never store or replay.
        """
        _require_address(taker, "taker")
        body = self._swap_body(chain_id, sell_token, buy_token, sell_amount,
                               taker, slippage_bps)
        raw = self._post("/api/agent/quote", body)
        self._check_echo(raw, chain_id, body)
        txn = raw.get("transaction") or {}
        to, data = txn.get("to"), txn.get("data")
        if not to or not data:
            raise DexError(f"cast quote missing executable transaction: {raw!r}"[:300])
        if txn.get("chainId") not in (None, chain_id):
            raise DexError("cast quote transaction is for another chain — refusing")
        # Spender: from the quote, never hardcoded or inferred from tx.to.
        allowance_target = raw.get("allowanceTarget")
        approval_spender = (raw.get("approval") or {}).get("spender")
        if not allowance_target:
            allowance_target = approval_spender
        elif approval_spender and approval_spender.lower() != allowance_target.lower():
            raise DexError("cast quote names two different spenders — refusing")
        if allowance_target and not _is_address(allowance_target):
            raise DexError(f"cast returned bad allowanceTarget: {allowance_target!r}")
        tx = {
            "to": to,
            "data": data,
            "value": str(txn.get("value", "0")),
            "gas": txn.get("gas"),
            "gas_price": txn.get("gasPrice"),
        }
        min_buy = raw.get("minBuyAmount")
        return _norm_quote(
            venue=VENUE_CAST, chain_id=chain_id,
            sell_token=raw["sellToken"], buy_token=raw["buyToken"],
            sell_amount=int(raw.get("sellAmount") or 0),
            buy_amount=int(raw.get("buyAmount") or 0),
            min_buy_amount=int(min_buy) if min_buy else None,
            price_impact_bps=None, gas_estimate=txn.get("gas"),
            tx=tx, allowance_target=allowance_target, raw=raw)


# ---------------------------------------------------------------------------
# Uniswap Trading API
# ---------------------------------------------------------------------------


class UniswapClient:
    """Client for the Uniswap Trading API (classic + UniswapX routing).

    Canonical flow: ``check_approval`` -> ``quote`` -> ``swap``.
    ``quote`` is indicative; ``swap`` converts it to an unsigned tx.
    """

    def __init__(self, api_key: str):
        if not api_key:
            raise DexError(
                "Uniswap API key required (developers.uniswap.org/dashboard)")
        self.api_key = api_key

    def _headers(self) -> dict:
        return {"x-api-key": self.api_key,
                "Accept": "application/json",
                "X-Agent-Info": AGENT_INFO}

    def _post(self, path: str, body: dict) -> dict:
        return _http_json("POST", f"{UNISWAP_BASE}{path}", self._headers(), body)

    def _check_chain(self, chain_id: int) -> int:
        if chain_id not in UNISWAP_CHAINS:
            raise DexError(
                f"Uniswap API: refusing unknown chain {chain_id} "
                f"(known: {sorted(UNISWAP_CHAINS)})")
        return chain_id

    def check_approval(self, chain_id: int, token: str, amount: int,
                       wallet: str) -> dict:
        """Returns ``{"approval_needed": bool, "tx": {...} | None}``.

        If an approval is needed, the API returns the unsigned approval
        transaction to sign (Permit2 flow). Per Uniswap's docs the
        approval's allowance depends on the API's ``permitAmount``
        (FULL = max uint256, one approval forever; EXACT = this amount)
        — review the returned ``tx`` rather than assuming an
        exact-amount allowance. Confirm the approval on-chain before
        the swap.
        """
        self._check_chain(chain_id)
        raw = self._post("/check_approval", {
            "chainId": chain_id,
            "token": _require_address(token, "token"),
            "amount": str(_require_positive_int(amount, "amount")),
            "walletAddress": _require_address(wallet, "wallet"),
        })
        approval = raw.get("approval")
        return {"approval_needed": bool(approval), "tx": approval, "raw": raw}

    def quote(self, chain_id: int, token_in: str, token_out: str,
              amount: int, swapper: str, slippage_pct: float = 0.5,
              exact_output: bool = False) -> dict:
        """Indicative quote with routing info."""
        self._check_chain(chain_id)
        if not (0 < slippage_pct <= 5):
            raise DexError("slippage_pct must be in (0, 5]")
        raw = self._post("/quote", {
            "type": "EXACT_OUTPUT" if exact_output else "EXACT_INPUT",
            "tokenIn": _require_address(token_in, "token in"),
            "tokenOut": _require_address(token_out, "token out"),
            "tokenInChainId": chain_id,
            "tokenOutChainId": chain_id,
            "amount": str(_require_positive_int(amount, "amount")),
            "swapper": _require_address(swapper, "swapper"),
            "slippageTolerance": slippage_pct,
        })
        q = raw.get("quote") or {}
        inp = q.get("input") or {}
        outp = q.get("output") or {}
        buy_amount = int(outp.get("amount", "0") or 0)
        return _norm_quote(
            venue="uniswap", chain_id=chain_id,
            sell_token=token_in, buy_token=token_out,
            sell_amount=int(inp.get("amount", amount) or amount),
            buy_amount=buy_amount,
            min_buy_amount=None,
            price_impact_bps=None, gas_estimate=None,
            tx=None, allowance_target=None, raw=raw)

    def swap(self, quote_raw: dict, chain_id: int, token_in: str,
             token_out: str, amount: int, swapper: str,
             slippage_pct: float = 0.5,
             permit_signature: str | None = None) -> dict:
        """Convert a ``quote`` response into an unsigned transaction.

        Per Uniswap's integration guide, the /swap request body IS the
        /quote response object itself (the guide's curl passes it
        verbatim; the API reference documents the accepted fields as
        ``quote``, ``signature``, ``permitData``, ``safetyMode``,
        ``deadline`` and friends — see
        https://developers.uniswap.org/docs/api-reference/create_swap_transaction).
        Only CLASSIC/WRAP/UNWRAP/BRIDGE routings are supported here —
        per the guide's endpoint table, DUTCH_V2/DUTCH_V3/PRIORITY/
        LIMIT_ORDER quotes go to /order and CHAINED quotes go to /plan,
        so those are refused rather than half-built.

        If the quote returned non-null ``permitData``, the human's
        EIP-712 signature over it is required — pass it as
        ``permit_signature`` (it is sent in the ``signature`` field, per
        the guide). Without it this raises instead of silently dropping
        the permit: an unsigned permit is not a valid authorization.
        """
        self._check_chain(chain_id)
        routing = (quote_raw.get("routing") or "CLASSIC").upper()
        if routing not in ("CLASSIC", "WRAP", "UNWRAP", "BRIDGE"):
            raise DexError(
                f"Uniswap routing {routing!r} is not buildable via /swap: "
                "the Uniswap integration guide sends DUTCH_V2/DUTCH_V3/"
                "PRIORITY/LIMIT_ORDER quotes to /order and CHAINED quotes "
                "to /plan — refused; re-quote or pick another venue")
        if quote_raw.get("permitData") and not permit_signature:
            raise DexError(
                "Uniswap quote returned permitData: a Permit2 EIP-712 "
                "signature from the human's wallet is required (pass "
                "permit_signature); per the Uniswap docs /swap needs it "
                "in the 'signature' field")
        if not quote_raw.get("quote"):
            raise DexError("Uniswap /swap needs the /quote response object "
                           "(missing nested 'quote')")
        body = dict(quote_raw)  # the guide passes the quote response itself
        if permit_signature:
            body["signature"] = permit_signature
        # The API chokes on explicit nulls — strip them.
        body = {k: v for k, v in body.items() if v is not None}
        raw = self._post("/swap", body)
        # Documented shape is CreateSwapResponse: {"swap": {to, from,
        # data, value, gasLimit, ...}, ...} — fall back defensively.
        tx = raw.get("swap") or raw.get("transaction") or raw
        to, data = tx.get("to"), tx.get("data")
        if not to or not data:
            raise DexError(f"Uniswap /swap returned no executable tx: {raw!r}"[:300])
        unsigned = {
            "to": to,
            "from": tx.get("from", swapper),
            "data": data,
            "value": str(tx.get("value", "0")),
            "gas": tx.get("gasLimit", tx.get("gas")),
        }
        q = (quote_raw.get("quote") or {})
        outp = q.get("output") or {}
        return _norm_quote(
            venue="uniswap", chain_id=chain_id,
            sell_token=token_in, buy_token=token_out,
            sell_amount=amount, buy_amount=int(outp.get("amount", "0") or 0),
            min_buy_amount=None, price_impact_bps=None,
            gas_estimate=tx.get("gasLimit", tx.get("gas")),
            tx=unsigned, allowance_target=None, raw=raw)

# ---------------------------------------------------------------------------
# Minimal ABI encoder (static types + address[]/bytes dynamics — enough for
# the builders below; NOT a general encoder)
# ---------------------------------------------------------------------------


def _u256(n: int) -> bytes:
    if not isinstance(n, int) or n < 0 or n >= 2 ** 256:
        raise DexError(f"uint256 out of range: {n!r}")
    return n.to_bytes(32, "big")


def _addr(a: str) -> bytes:
    _require_address(a, "address")
    return bytes(32 - 20) + bytes.fromhex(a[2:])


def _u24(n: int) -> bytes:
    return _u256(n)


def _i24(n: int) -> bytes:
    if not isinstance(n, int) or n < -(2 ** 23) or n >= 2 ** 23:
        raise DexError(f"int24 out of range: {n!r}")
    return (n % 2 ** 256).to_bytes(32, "big")


def _enc_tuple(items: list[bytes]) -> bytes:
    """Encode a tuple of already-encoded static params."""
    return b"".join(items)


def _enc_addr_array(addrs: list[str]) -> bytes:
    body = _u256(len(addrs)) + b"".join(_addr(a) for a in addrs)
    return body


def _head_tail(head: list, tails: list[bytes]) -> bytes:
    """head entries are static encodings, or None for a dynamic slot whose
    encoding is the next entry of tails. Dynamic slots become offset
    pointers; tails are appended after the head block in order."""
    out = b""
    off = 32 * len(head)
    tail_iter = iter(tails)
    enc_tails = []
    for h in head:
        if h is None:  # dynamic slot -> offset pointer
            t = next(tail_iter)
            out += _u256(off)
            enc_tails.append(t)
            off += len(t)
        else:
            out += h
    for t in enc_tails:
        out += t
    return out


# Function selectors below are pinned constants (verified against the
ERC20_APPROVE_SELECTOR = "095ea7b3"      # approve(address,uint256)
ERC20_ALLOWANCE_SELECTOR = "dd62ed3e"    # allowance(address,address)
V2_SWAP_SELECTOR = "38ed1739"            # swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
V2_ADD_LIQ_SELECTOR = "e8e33700"         # addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)
V3_EXACT_INPUT_SINGLE_SELECTOR = "414bf389"  # exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
V3_MINT_SELECTOR = "88316456"            # mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))


def _calldata(selector_hex: str, payload: bytes) -> str:
    return "0x" + selector_hex + payload.hex()


# ---------------------------------------------------------------------------
# ERC-20 helpers
# ---------------------------------------------------------------------------


def build_approve_calldata(spender: str, amount: int) -> str:
    """approve(spender, amount) calldata. Amount should be the EXACT trade
    amount — never type(uint256).max unless the human explicitly asked."""
    _require_address(spender, "spender")
    _require_positive_int(amount, "approve amount")
    return _calldata(ERC20_APPROVE_SELECTOR, _addr(spender) + _u256(amount))


def build_allowance_calldata(owner: str, spender: str) -> str:
    """allowance(owner, spender) eth_call payload (read-only)."""
    _require_address(owner, "owner")
    _require_address(spender, "spender")
    return _calldata(ERC20_ALLOWANCE_SELECTOR, _addr(owner) + _addr(spender))


def decode_allowance(result_hex: str) -> int:
    """Decode the uint256 returned by an allowance eth_call."""
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    if len(h) != 64:
        raise DexError(f"bad allowance return data: {result_hex!r}")
    return int(h, 16)


# ---------------------------------------------------------------------------
# Uniswap v2 (and v2-style forks, e.g. on Robinhood Chain)
# ---------------------------------------------------------------------------


def build_v2_swap_calldata(amount_in: int, amount_out_min: int,
                           path: list[str], to: str, deadline: int) -> str:
    """swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)."""
    _require_positive_int(amount_in, "amount_in")
    if not isinstance(amount_out_min, int) or amount_out_min < 0:
        raise DexError("amount_out_min must be a non-negative int")
    if not isinstance(path, list) or len(path) < 2:
        raise DexError("v2 swap path needs at least 2 token addresses")
    for p in path:
        _require_address(p, "path token")
    _require_address(to, "recipient")
    _require_positive_int(deadline, "deadline")
    head = [_u256(amount_in), _u256(amount_out_min), None, _addr(to),
            _u256(deadline)]
    tails = [_enc_addr_array(path)]
    return _calldata(V2_SWAP_SELECTOR, _head_tail(head, tails))


def build_v2_add_liquidity_calldata(token_a: str, token_b: str,
                                    amount_a_desired: int, amount_b_desired: int,
                                    amount_a_min: int, amount_b_min: int,
                                    to: str, deadline: int) -> str:
    """addLiquidity(tokenA, tokenB, amountADesired, amountBDesired,
    amountAMin, amountBMin, to, deadline). All static params."""
    for t, w in ((token_a, "token A"), (token_b, "token B")):
        _require_address(t, w)
    _require_address(to, "recipient")
    for n, w in ((amount_a_desired, "amount A desired"),
                 (amount_b_desired, "amount B desired")):
        _require_positive_int(n, w)
    for n, w in ((amount_a_min, "amount A min"),
                 (amount_b_min, "amount B min")):
        if not isinstance(n, int) or n < 0:
            raise DexError(f"{w} must be a non-negative int")
    _require_positive_int(deadline, "deadline")
    return _calldata(V2_ADD_LIQ_SELECTOR, _enc_tuple([
        _addr(token_a), _addr(token_b),
        _u256(amount_a_desired), _u256(amount_b_desired),
        _u256(amount_a_min), _u256(amount_b_min),
        _addr(to), _u256(deadline),
    ]))


# ---------------------------------------------------------------------------
# Uniswap v3
# ---------------------------------------------------------------------------


def build_v3_exact_input_single_calldata(token_in: str, token_out: str,
                                         fee: int, recipient: str,
                                         amount_in: int, amount_out_min: int,
                                         sqrt_price_limit_x96: int = 0) -> str:
    """SwapRouter.exactInputSingle(params) — single-hop v3 swap."""
    _require_address(token_in, "token in")
    _require_address(token_out, "token out")
    _require_address(recipient, "recipient")
    if fee not in (100, 500, 3000, 10000):
        raise DexError(f"v3 fee must be one of 100/500/3000/10000, got {fee}")
    _require_positive_int(amount_in, "amount_in")
    if not isinstance(amount_out_min, int) or amount_out_min < 0:
        raise DexError("amount_out_min must be a non-negative int")
    if not isinstance(sqrt_price_limit_x96, int) or sqrt_price_limit_x96 < 0:
        raise DexError("sqrt_price_limit_x96 must be a non-negative int")
    return _calldata(V3_EXACT_INPUT_SINGLE_SELECTOR, _enc_tuple([
        _addr(token_in), _addr(token_out), _u24(fee), _addr(recipient),
        _u256(amount_in), _u256(amount_out_min),
        _u256(sqrt_price_limit_x96),
    ]))


def build_v3_mint_calldata(token0: str, token1: str, fee: int,
                           tick_lower: int, tick_upper: int,
                           amount0_desired: int, amount1_desired: int,
                           amount0_min: int, amount1_min: int,
                           recipient: str, deadline: int) -> str:
    """NonfungiblePositionManager.mint(params) — open a v3 LP position."""
    _require_address(token0, "token0")
    _require_address(token1, "token1")
    if token0.lower() >= token1.lower():
        raise DexError("v3 mint requires token0 < token1 (sort order)")
    _require_address(recipient, "recipient")
    if fee not in (100, 500, 3000, 10000):
        raise DexError(f"v3 fee must be one of 100/500/3000/10000, got {fee}")
    if not isinstance(tick_lower, int) or not isinstance(tick_upper, int) \
            or tick_lower >= tick_upper:
        raise DexError("tick_lower must be < tick_upper")
    for n, w in ((amount0_desired, "amount0 desired"),
                 (amount1_desired, "amount1 desired")):
        _require_positive_int(n, w)
    for n, w in ((amount0_min, "amount0 min"), (amount1_min, "amount1 min")):
        if not isinstance(n, int) or n < 0:
            raise DexError(f"{w} must be a non-negative int")
    _require_positive_int(deadline, "deadline")
    return _calldata(V3_MINT_SELECTOR, _enc_tuple([
        _addr(token0), _addr(token1), _u24(fee),
        _i24(tick_lower), _i24(tick_upper),
        _u256(amount0_desired), _u256(amount1_desired),
        _u256(amount0_min), _u256(amount1_min),
        _addr(recipient), _u256(deadline),
    ]))


# ---------------------------------------------------------------------------
# Quote comparison helper (agent-facing)
# ---------------------------------------------------------------------------


def compare_quotes(quotes: list[dict]) -> dict:
    """Rank normalized quotes by output-per-input. Pure function — no I/O.

    Returns {"best": <quote>, "ranked": [<quote>, ...], "note": ...}.
    Quotes with no buy_amount (failed/indicative) sort last.
    """
    if not quotes:
        raise DexError("no quotes to compare")
    for q in quotes:
        for k in ("venue", "sell_amount", "buy_amount"):
            if k not in q:
                raise DexError(f"quote missing {k!r}")

    def _eff(q):
        sell = int(q["sell_amount"])
        buy = int(q["buy_amount"])
        return (buy / sell) if sell > 0 and buy > 0 else -1.0

    ranked = sorted(quotes, key=_eff, reverse=True)
    best = ranked[0]
    note = (f"best output from {best['venue']}: "
            f"{best['buy_amount']} per {best['sell_amount']} in")
    if _eff(best) < 0:
        note = "no venue returned a usable quote"
    return {"best": best, "ranked": ranked, "note": note}


__all__ = [
    "DexError",
    "ZEROX_BASE", "UNISWAP_BASE", "CAST_BASE",
    "ZEROX_CHAINS", "UNISWAP_CHAINS", "CAST_CHAINS",
    "NATIVE_SENTINEL", "NATIVE_ZERO",
    "VENUE_MATCHA", "VENUE_UNISWAP", "VENUE_CAST", "KNOWN_VENUES",
    "VENUE_ALIASES", "VENUE_CHAINS", "VENUE_ENV_KEYS", "VENUES_KEY_OPTIONAL",
    "DEFAULT_RECOMMENDED_VENUES",
    "normalize_venue", "venue_serves_chain", "relay_mode",
    "ZeroExClient", "UniswapClient", "CastClient",
    "build_approve_calldata", "build_allowance_calldata", "decode_allowance",
    "build_v2_swap_calldata", "build_v2_add_liquidity_calldata",
    "build_v3_exact_input_single_calldata", "build_v3_mint_calldata",
    "compare_quotes",
]

# ---------------------------------------------------------------------------
# Execution-time validation (pure — the daemon calls this on every firm
# quote before signing anything)
# ---------------------------------------------------------------------------


def validate_swap_intent_against_quote(intent: dict, quote: dict) -> dict:
    """Check a firm venue quote against the approved swap intent bounds.

    The human approved *bounds* (tokens, exact sell amount, minimum buy,
    max slippage, deadline) — not calldata. The daemon re-fetches the
    firm quote at execution time and this function enforces that the
    quote fits inside the approved bounds. Anything off -> DexError ->
    fail closed, no signature, no broadcast.

    Returns a normalized execution plan:
    {"to", "data", "value_wei", "allowance_target" | None,
     "buy_amount_wei", "needs_approval": bool}
    """
    for k in ("chain_id", "sell_token", "buy_token", "sell_amount_wei",
              "min_buy_amount_wei", "max_slippage_bps"):
        if k not in intent:
            raise DexError(f"swap intent missing {k!r}")
    chain_id = intent["chain_id"]
    if quote.get("chain_id") != chain_id:
        raise DexError(
            f"quote chain {quote.get('chain_id')} != intent chain {chain_id}")
    for side in ("sell_token", "buy_token"):
        want = intent[side]
        got = quote.get(side)
        if not (isinstance(got, str) and got.lower() == want.lower()):
            raise DexError(
                f"quote {side} {got!r} != approved {want!r} — refusing")
    sell_amount = intent["sell_amount_wei"]
    if str(quote.get("sell_amount")) != str(sell_amount):
        raise DexError(
            f"quote sell_amount {quote.get('sell_amount')} != approved "
            f"{sell_amount} — exact amount only, no partial fills")
    buy_amount = int(quote.get("buy_amount") or 0)
    min_buy = intent["min_buy_amount_wei"]
    if buy_amount < min_buy:
        raise DexError(
            f"quote buy_amount {buy_amount} < approved minimum {min_buy} "
            "— market moved past the bound, refusing")
    tx = quote.get("tx") or {}
    to, data = tx.get("to"), tx.get("data")
    if not to or not data:
        raise DexError("firm quote carries no executable transaction")
    if not _is_address(to):
        raise DexError(f"quote tx target is not an address: {to!r}")
    if not (isinstance(data, str) and data.startswith("0x") and len(data) > 10):
        raise DexError("quote tx data is malformed")
    try:
        value_wei = int(str(tx.get("value", "0")), 0)
    except ValueError:
        raise DexError(f"quote tx value malformed: {tx.get('value')!r}")
    if value_wei < 0:
        raise DexError("quote tx value negative")
    native_sell = _is_native_token(intent["sell_token"])
    if native_sell and value_wei != sell_amount:
        raise DexError(
            f"native sell: tx value {value_wei} != sell_amount {sell_amount}")
    if not native_sell and value_wei != 0:
        raise DexError(
            f"token sell: tx value must be 0, got {value_wei}")
    allowance_target = quote.get("allowance_target")
    needs_approval = False
    if not native_sell:
        # Token swaps need an ERC-20 approval to the quote's spender —
        # which must come from the quote, never hardcoded.
        if not allowance_target or not _is_address(allowance_target):
            raise DexError(
                "token swap quote names no valid allowance_target — refusing")
        needs_approval = True  # daemon checks on-chain allowance; may skip
    return {
        "to": to,
        "data": data,
        "value_wei": value_wei,
        "allowance_target": allowance_target,
        "buy_amount_wei": buy_amount,
        "needs_approval": needs_approval,
    }

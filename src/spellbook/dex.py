"""DEX aggregation for the Spellbook wallet — quotes, calldata builders,
and execution-time validation.

Three quote venues (see docs/AGENT_ONBOARDING.md). Agents need no API
key for matcha or cast — keys are held server-side — and bring their own
only if they choose to:

- **matcha** — the 0x Swap API v2, the engine behind matcha.xyz.
  ``GET /swap/allowance-holder/quote`` and ``/swap/permit2/quote`` return
  firm quotes with ready-to-sign calldata. Without a key of the agent's
  own, quotes go through Cast's 0x-compatible routes
  (``OPERATOR_QUOTE_RELAY``), which hold the key server-side; with
  ``ZERO_EX_API_KEY`` set they go to ``https://api.0x.org`` directly.
  Chain via ``chainId`` query param.
- **Uniswap** — ``https://trade-api.gateway.uniswap.org/v1``.
  Flow: ``POST /check_approval`` -> ``POST /quote`` -> ``POST /swap``
  (unsigned tx). Header ``x-api-key``. ``X-Agent-Info`` attribution is
  sent on every call. No server-side key: needs ``UNISWAP_API_KEY``.
- **cast** — Cast (``https://cast.awizard.dev``), aWizard's swap router
  over the 0x Swap API on Base and Robinhood Chain. No API key. Its
  agent API (``/api/agent/quote``) returns allowance-holder calldata plus
  the spender, and it also serves token lists, token lookup and USD
  prices. Cast takes its platform fee inside the quoted swap.

Plus pure-Python calldata builders for direct pool interaction (no API
key needed — useful on chains neither aggregator covers, e.g. the
Uniswap-v2-style pools on Robinhood Chain):

- ERC-20 ``approve`` / ``allowance``
- Uniswap v2 ``swapExactTokensForTokens`` / ``addLiquidity`` /
  ``removeLiquidity``
- Uniswap v3 ``exactInputSingle`` (SwapRouter) / ``mint`` /
  ``decreaseLiquidity`` / ``collect`` / ``multicall``
  (NonfungiblePositionManager)
- Uniswap v4 ``modifyLiquidities`` (PositionManager): mint / decrease /
  fee-claim command batches, plus the two-stage Permit2 approval path
  and read helpers (position ownership, pool initialization)

VENUE RECOMMENDATIONS + EXECUTION (SPEC §10 v2): the user keeps a
recommended-venue list via ``dex.recommended_venues`` in spellbook.json
(default: matcha + uniswap; ``normalize_venue`` maps the "0x" alias to
"matcha"). The list is advisory, not a gate: a swap naming another
venue carries a prominent warning on the queued intent, and the human's
per-transaction approval is what authorizes the venue. Nothing in this
module signs or broadcasts. Quotes are fetched and normalized here; at
execution time the daemon fetches the firm quote again and DECODES its
transaction against the human-approved bounds and the pinned contract
table (``validate_swap_intent_against_quote`` / ``decode_swap_tx``,
``PINNED_CONTRACTS``) before anything is signed. A
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


import os as _os

#: 0x Swap API v2, called directly when the agent brings its own key.
ZEROX_DIRECT = "https://api.0x.org"

#: The operator's 0x-compatible quote relay: Cast's
#: /swap/allowance-holder/{price,quote}, the 0x Swap API v2 shape. Cast
#: holds the 0x API key server-side and adds its platform fee inside the
#: quote (so the quoted buyAmount — what the human's bounds are checked
#: against — is already net of it). matcha quotes go here when the agent has no key of
#: its own — agents are never asked for a key they don't want to manage.
#: The daemon still signs with its own seed; the relay never holds funds
#: or signs.
OPERATOR_QUOTE_RELAY = "https://cast.awizard.dev"


def zerox_base(api_key: str | None = None) -> str:
    """Where matcha quotes go: ZEROX_BASE_URL if set (e.g. a local shim or
    another relay); else api.0x.org with the agent's own key; else the
    operator's relay (Cast), which holds the key server-side."""
    override = _os.environ.get("ZEROX_BASE_URL")
    if override:
        return override.rstrip("/")
    return ZEROX_DIRECT if api_key else OPERATOR_QUOTE_RELAY


def relay_mode() -> bool:
    """ZEROX_BASE_URL points quote traffic at a relay instead of 0x."""
    return bool(_os.environ.get("ZEROX_BASE_URL"))


#: Default 0x base for display/back-compat; ZeroExClient resolves its own
#: per key via zerox_base().
ZEROX_BASE = _os.environ.get("ZEROX_BASE_URL", ZEROX_DIRECT)

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
#: never in the repo). Only Uniswap needs one; for the others it is the
#: agent's choice to bring its own.
VENUE_ENV_KEYS = {
    VENUE_MATCHA: "ZERO_EX_API_KEY",
    VENUE_UNISWAP: "UNISWAP_API_KEY",
    VENUE_CAST: "CAST_API_KEY",
}

#: Venues whose API key is optional — the call works without one:
#: matcha falls back to the operator's quote relay (key held server-side),
#: and Cast's agent API is open (CAST_API_KEY only sent if set). Uniswap
#: has no server-side key, so it still needs the agent's own.
VENUES_KEY_OPTIONAL = frozenset({VENUE_MATCHA, VENUE_CAST})

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

    def __init__(self, api_key: str | None = None):
        # No key is fine: quotes then go to the operator's relay (Cast), which
        # holds the key server-side. A key of the agent's own goes direct.
        self.api_key = api_key or ""
        self.base = zerox_base(self.api_key)

    def _headers(self) -> dict:
        h = {"0x-version": "v2"}
        if self.api_key:
            h["0x-api-key"] = self.api_key
        return h

    def _get(self, path: str, params: dict) -> dict:
        qs = urllib.parse.urlencode(params)
        return _http_json("GET", f"{self.base}{path}?{qs}", self._headers())

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
            # issues.allowance is null when no approval is needed (native
            # sell, or allowance already enough) — not a missing key
            or ((raw.get("issues") or {}).get("allowance") or {}).get("spender")
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
              exact_output: bool = False,
              permit_as_transaction: bool = False) -> dict:
        """Indicative quote with routing info.

        ``permit_as_transaction`` asks the API for the Permit2 allowance as
        an on-chain transaction instead of an EIP-712 permit to sign
        (``generatePermitAsTransaction``). The daemon sets it: it never
        signs typed data for a swap, and issues its own exact-amount
        Permit2.approve to the pinned router instead of the API's."""
        self._check_chain(chain_id)
        if not (0 < slippage_pct <= 5):
            raise DexError("slippage_pct must be in (0, 5]")
        body = {
            "type": "EXACT_OUTPUT" if exact_output else "EXACT_INPUT",
            "tokenIn": _require_address(token_in, "token in"),
            "tokenOut": _require_address(token_out, "token out"),
            "tokenInChainId": chain_id,
            "tokenOutChainId": chain_id,
            "amount": str(_require_positive_int(amount, "amount")),
            "swapper": _require_address(swapper, "swapper"),
            "slippageTolerance": slippage_pct,
        }
        if permit_as_transaction:
            body["generatePermitAsTransaction"] = True
        raw = self._post("/quote", body)
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


def _u128(n: int) -> bytes:
    if not isinstance(n, int) or n < 0 or n >= 2 ** 128:
        raise DexError(f"uint128 out of range: {n!r}")
    return n.to_bytes(32, "big")


def _u160(n: int) -> bytes:
    if not isinstance(n, int) or n < 0 or n >= 2 ** 160:
        raise DexError(f"uint160 out of range: {n!r}")
    return n.to_bytes(32, "big")


def _u48(n: int) -> bytes:
    if not isinstance(n, int) or n < 0 or n >= 2 ** 48:
        raise DexError(f"uint48 out of range: {n!r}")
    return n.to_bytes(32, "big")


def _i24(n: int) -> bytes:
    if not isinstance(n, int) or n < -(2 ** 23) or n >= 2 ** 23:
        raise DexError(f"int24 out of range: {n!r}")
    return (n % 2 ** 256).to_bytes(32, "big")


def _enc_bytes(b: bytes) -> bytes:
    """ABI-encode dynamic bytes: length word + right-padded data."""
    if not isinstance(b, (bytes, bytearray)):
        raise DexError("bytes payload must be bytes")
    b = bytes(b)
    return _u256(len(b)) + b + bytes(-len(b) % 32)


def _enc_bytes_array(items: list[bytes]) -> bytes:
    """ABI-encode bytes[]: length + offsets + elements (strict layout)."""
    n = len(items)
    for it in items:
        if not isinstance(it, (bytes, bytearray)):
            raise DexError("bytes[] elements must be bytes")
    head_len = 32 * n
    out = _u256(n)
    off = head_len
    tails = []
    for it in items:
        out += _u256(off)
        enc = _enc_bytes(bytes(it))
        tails.append(enc)
        off += len(enc)
    for t in tails:
        out += t
    return out


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
    # Offset base is the real head byte length: a head entry may span
    # several words (e.g. a v4 PoolKey), and a None slot costs 32 bytes.
    off = sum(32 if h is None else len(h) for h in head)
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
# canonical signatures with keccak-256 on 2026-09-25 — see the selector
# check in the PR notes; never hand-transcribe a new one).
ERC20_APPROVE_SELECTOR = "095ea7b3"      # approve(address,uint256)
ERC20_ALLOWANCE_SELECTOR = "dd62ed3e"    # allowance(address,address)
V2_SWAP_SELECTOR = "38ed1739"            # swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
V2_ADD_LIQ_SELECTOR = "e8e33700"         # addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)
V2_REMOVE_LIQ_SELECTOR = "baa2abde"      # removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)
V3_EXACT_INPUT_SINGLE_SELECTOR = "414bf389"  # exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))
V3_MINT_SELECTOR = "88316456"            # mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))
V3_DECREASE_LIQUIDITY_SELECTOR = "0c49ccbe"  # decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))
V3_COLLECT_SELECTOR = "fc6f7865"         # collect((uint256,address,uint128,uint128))
V3_MULTICALL_SELECTOR = "ac9650d8"       # multicall(bytes[])
ERC721_OWNER_OF_SELECTOR = "6352211e"    # ownerOf(uint256)
V4_MODIFY_LIQUIDITIES_SELECTOR = "dd46508f"  # modifyLiquidities(bytes,uint256)
PERMIT2_APPROVE_SELECTOR = "87517c45"    # approve(address,address,uint160,uint48)
PERMIT2_ALLOWANCE_SELECTOR = "927da105"  # allowance(address,address,address)
POSM_POOL_MANAGER_SELECTOR = "dc4c90d3"  # poolManager()
POOL_MANAGER_GET_SLOT0_SELECTOR = "c815641c"  # getSlot0(bytes32)

#: Uniswap v4 PositionManager action ids — official v4-periphery
#: src/libraries/Actions.sol (verified 2026-09-25).
V4_ACTIONS = {
    "INCREASE_LIQUIDITY": 0x00,
    "DECREASE_LIQUIDITY": 0x01,
    "MINT_POSITION": 0x02,
    "BURN_POSITION": 0x03,
    "SETTLE_PAIR": 0x0D,
    "TAKE_PAIR": 0x11,
    "CLOSE_CURRENCY": 0x12,
    "CLEAR_OR_TAKE": 0x13,
    "SWEEP": 0x14,
}

#: Native currency in v4 pool keys (CurrencyLibrary.ADDRESS_ZERO).
V4_NATIVE_CURRENCY = "0x0000000000000000000000000000000000000000"

#: v4 dynamic-fee flag (fee = 0x800000 means "ask the hook").
V4_DYNAMIC_FEE_FLAG = 0x800000


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
                                         deadline: int,
                                         sqrt_price_limit_x96: int = 0) -> str:
    """SwapRouter.exactInputSingle(params) — single-hop v3 swap.

    NOTE: the real ExactInputSingleParams struct carries ``deadline``
    between recipient and amountIn (selector 414bf389); it is required.
    """
    _require_address(token_in, "token in")
    _require_address(token_out, "token out")
    _require_address(recipient, "recipient")
    if fee not in (100, 500, 3000, 10000):
        raise DexError(f"v3 fee must be one of 100/500/3000/10000, got {fee}")
    _require_positive_int(amount_in, "amount_in")
    if not isinstance(amount_out_min, int) or amount_out_min < 0:
        raise DexError("amount_out_min must be a non-negative int")
    _require_positive_int(deadline, "deadline")
    if not isinstance(sqrt_price_limit_x96, int) or sqrt_price_limit_x96 < 0:
        raise DexError("sqrt_price_limit_x96 must be a non-negative int")
    return _calldata(V3_EXACT_INPUT_SINGLE_SELECTOR, _enc_tuple([
        _addr(token_in), _addr(token_out), _u24(fee), _addr(recipient),
        _u256(deadline),
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
# Uniswap v2 — remove liquidity
# ---------------------------------------------------------------------------


def build_v2_remove_liquidity_calldata(token_a: str, token_b: str,
                                      liquidity: int,
                                      amount_a_min: int, amount_b_min: int,
                                      to: str, deadline: int) -> str:
    """removeLiquidity(tokenA, tokenB, liquidity, amountAMin, amountBMin,
    to, deadline). Burns ``liquidity`` LP (pair) tokens; the pair contract
    must have an allowance to the router first."""
    for t, w in ((token_a, "token A"), (token_b, "token B")):
        _require_address(t, w)
    _require_address(to, "recipient")
    _require_positive_int(liquidity, "liquidity (LP tokens to burn)")
    for n, w in ((amount_a_min, "amount A min"),
                 (amount_b_min, "amount B min")):
        if not isinstance(n, int) or n < 0:
            raise DexError(f"{w} must be a non-negative int")
    _require_positive_int(deadline, "deadline")
    return _calldata(V2_REMOVE_LIQ_SELECTOR, _enc_tuple([
        _addr(token_a), _addr(token_b),
        _u256(liquidity),
        _u256(amount_a_min), _u256(amount_b_min),
        _addr(to), _u256(deadline),
    ]))


# ---------------------------------------------------------------------------
# Uniswap v3 — decrease liquidity + collect fees
# ---------------------------------------------------------------------------


def build_v3_decrease_liquidity_calldata(token_id: int, liquidity: int,
                                        amount0_min: int, amount1_min: int,
                                        deadline: int) -> str:
    """NonfungiblePositionManager.decreaseLiquidity(params) — withdraw
    ``liquidity`` units from position ``token_id``. amount0Min/amount1Min
    (uint256 per the official interface) are the slippage bounds on the
    principal (fees accrue on top). The withdrawn tokens + fees stay
    claimable via ``collect``."""
    _require_positive_int(token_id, "token_id")
    _require_positive_int(liquidity, "liquidity to remove")
    for n, w in ((amount0_min, "amount0 min"), (amount1_min, "amount1 min")):
        _u256(n)  # range-check only; encoded below
        if not isinstance(n, int) or n < 0:
            raise DexError(f"{w} must be a non-negative int")
    _require_positive_int(deadline, "deadline")
    return _calldata(V3_DECREASE_LIQUIDITY_SELECTOR, _enc_tuple([
        _u256(token_id), _u128(liquidity), _u256(amount0_min),
        _u256(amount1_min), _u256(deadline),
    ]))


def build_v3_collect_calldata(token_id: int, recipient: str,
                             amount0_max: int = 2 ** 128 - 1,
                             amount1_max: int = 2 ** 128 - 1) -> str:
    """NonfungiblePositionManager.collect(params) — pull owed tokens
    (withdrawn principal and/or accrued fees) to ``recipient``. Defaults
    collect everything (type(uint128).max, the standard "claim all")."""
    _require_positive_int(token_id, "token_id")
    _require_address(recipient, "recipient")
    for n, w in ((amount0_max, "amount0 max"), (amount1_max, "amount1 max")):
        if not isinstance(n, int) or n < 0 or n >= 2 ** 128:
            raise DexError(f"{w} must be a uint128")
    return _calldata(V3_COLLECT_SELECTOR, _enc_tuple([
        _u256(token_id), _addr(recipient),
        _u128(amount0_max), _u128(amount1_max),
    ]))


def build_v3_multicall_calldata(calls: list[str]) -> str:
    """NonfungiblePositionManager.multicall(bytes[]) — batch several NPM
    calls (e.g. decreaseLiquidity + collect) into one transaction."""
    if not calls:
        raise DexError("multicall needs at least one call")
    payloads = []
    for c in calls:
        h = c[2:] if c.startswith("0x") else c
        if len(h) < 8 or len(h) % 2:
            raise DexError(f"bad call payload: {c[:20]!r}…")
        payloads.append(bytes.fromhex(h))
    # bytes[] is a dynamic argument: its head is an offset word (0x20)
    # before the array itself. (Without it the NPM reads the array length
    # as the offset and the call reverts.)
    return _calldata(V3_MULTICALL_SELECTOR,
                     _head_tail([None], [_enc_bytes_array(payloads)]))


def build_v3_remove_and_collect_calldata(token_id: int, liquidity: int,
                                       amount0_min: int, amount1_min: int,
                                       recipient: str, deadline: int) -> str:
    """One-tx v3 exit: multicall(decreaseLiquidity, collect)."""
    dec = build_v3_decrease_liquidity_calldata(
        token_id, liquidity, amount0_min, amount1_min, deadline)
    col = build_v3_collect_calldata(token_id, recipient)
    return build_v3_multicall_calldata([dec, col])


# ---------------------------------------------------------------------------
# Uniswap v4 — PositionManager (command-based LP)
#
# Official semantics live in the Uniswap docs; Spellbook only encodes them:
#   PositionManager.modifyLiquidities(bytes unlockData, uint256 deadline)
#   unlockData = abi.encode(bytes actions, bytes[] params)
# Add    = [MINT_POSITION, SETTLE_PAIR]
# Remove = [DECREASE_LIQUIDITY, TAKE_PAIR] (+ BURN_POSITION for full exits)
# Claim  = [DECREASE_LIQUIDITY (liquidity=0), TAKE_PAIR] — the periphery
#          documents that decreasing with 0 liquidity credits the caller
#          with the position's accrued fees.
# Approvals are two-stage through Permit2: token.approve(Permit2) then
# Permit2.approve(token, positionManager). See the Permit2 section below.
# ---------------------------------------------------------------------------


def _require_v4_pool_key_args(fee: int, tick_spacing: int,
                             tick_lower: int, tick_upper: int) -> None:
    if not isinstance(fee, int) or fee < 0 or fee >= 2 ** 24:
        raise DexError(f"v4 fee must be a uint24, got {fee!r}")
    if not isinstance(tick_spacing, int) or tick_spacing == 0 \
            or abs(tick_spacing) >= 2 ** 23:
        raise DexError(f"v4 tick_spacing must be a non-zero int24, "
                       f"got {tick_spacing!r}")
    for t, w in ((tick_lower, "tick_lower"), (tick_upper, "tick_upper")):
        if not isinstance(t, int) or t < -(2 ** 23) or t >= 2 ** 23:
            raise DexError(f"v4 {w} must be an int24")
    if tick_lower >= tick_upper:
        raise DexError("v4 tick_lower must be < tick_upper")
    if tick_lower % tick_spacing != 0 or tick_upper % tick_spacing != 0:
        raise DexError("v4 ticks must align with tick_spacing")


def _require_v4_currencies(currency0: str, currency1: str,
                           allow_native: bool = False) -> tuple[str, str]:
    """Currencies must be sorted; native (address zero) sorts first.

    Native-currency positions settle via msg.value, which only the
    daemon's native-aware v4 paths send — keep ``allow_native`` False
    unless the caller settles native explicitly. When allowed, native
    must be currency0 (it sorts below every address).
    """
    _require_address(currency0, "currency0")
    _require_address(currency1, "currency1")
    if currency0.lower() == V4_NATIVE_CURRENCY or \
            currency1.lower() == V4_NATIVE_CURRENCY:
        if not allow_native:
            raise DexError("v4 native-currency positions need allow_native "
                           "— wrap to WETH first")
        if currency0.lower() != V4_NATIVE_CURRENCY:
            raise DexError("v4 native currency must be currency0 "
                           "(sort order)")
    if currency0.lower() >= currency1.lower():
        raise DexError("v4 requires currency0 < currency1 (sort order)")
    return currency0, currency1


def build_v4_pool_key(currency0: str, currency1: str, fee: int,
                     tick_spacing: int, hooks: str,
                     allow_native: bool = False) -> bytes:
    """ABI-encode a v4 PoolKey struct (5 words, static)."""
    _require_v4_currencies(currency0, currency1, allow_native)
    _require_address(hooks, "hooks")
    return b"".join([_addr(currency0), _addr(currency1), _u24(fee),
                     _i24(tick_spacing), _addr(hooks)])


def v4_pool_id(currency0: str, currency1: str, fee: int,
               tick_spacing: int, hooks: str,
               allow_native: bool = False) -> str:
    """PoolId = keccak256(abi.encode(poolKey)) — the id getSlot0 takes."""
    from Crypto.Hash import keccak
    key = build_v4_pool_key(currency0, currency1, fee, tick_spacing, hooks,
                            allow_native)
    return "0x" + keccak.new(data=key, digest_bits=256).hexdigest()


def build_v4_modify_liquidities_calldata(actions: bytes,
                                         params: list[bytes],
                                         deadline: int) -> str:
    """PositionManager.modifyLiquidities(bytes unlockData, uint256 deadline).

    ``actions`` is the packed action bytes (one byte per action);
    ``params[i]`` is the ABI-encoded params for ``actions[i]``."""
    if not actions:
        raise DexError("modifyLiquidities needs at least one action")
    if len(actions) != len(params):
        raise DexError("actions and params length mismatch")
    for a in actions:
        if a not in V4_ACTIONS.values():
            raise DexError(f"unknown v4 action byte: {a:#x}")
    _require_positive_int(deadline, "deadline")
    unlock_data = _head_tail([None, None],
                             [_enc_bytes(bytes(actions)),
                              _enc_bytes_array([bytes(p) for p in params])])
    return _calldata(V4_MODIFY_LIQUIDITIES_SELECTOR,
                     _head_tail([None, _u256(deadline)],
                                [_enc_bytes(unlock_data)]))


def build_v4_mint_params(currency0: str, currency1: str, fee: int,
                         tick_spacing: int, hooks: str,
                         tick_lower: int, tick_upper: int, liquidity: int,
                         amount0_max: int, amount1_max: int,
                         owner: str, hook_data: bytes = b"",
                         allow_native: bool = False) -> bytes:
    """MINT_POSITION params: (PoolKey, tickLower, tickUpper, liquidity,
    amount0Max, amount1Max, owner, hookData). amount0Max/amount1Max are the
    hard maximum-spend (slippage) bounds."""
    _require_v4_currencies(currency0, currency1, allow_native)
    _require_v4_pool_key_args(fee, tick_spacing, tick_lower, tick_upper)
    _require_positive_int(liquidity, "liquidity")
    for n, w in ((amount0_max, "amount0 max"), (amount1_max, "amount1 max")):
        if not isinstance(n, int) or n < 0 or n >= 2 ** 128:
            raise DexError(f"v4 {w} must be a uint128")
    _require_address(owner, "owner")
    pool_key = build_v4_pool_key(currency0, currency1, fee,
                                 tick_spacing, hooks, allow_native)
    return _head_tail(
        [pool_key, _i24(tick_lower), _i24(tick_upper), _u256(liquidity),
         _u128(amount0_max), _u128(amount1_max), _addr(owner), None],
        [_enc_bytes(bytes(hook_data))])


def build_v4_decrease_params(token_id: int, liquidity: int,
                             amount0_min: int, amount1_min: int,
                             hook_data: bytes = b"") -> bytes:
    """DECREASE_LIQUIDITY params: (tokenId, liquidity, amount0Min,
    amount1Min, hookData). ``liquidity = 0`` is the documented fee-claim
    path: it credits the caller with accrued fees without touching the
    position's liquidity."""
    _require_positive_int(token_id, "token_id")
    if not isinstance(liquidity, int) or liquidity < 0:
        raise DexError("v4 decrease liquidity must be a non-negative int")
    for n, w in ((amount0_min, "amount0 min"), (amount1_min, "amount1 min")):
        if not isinstance(n, int) or n < 0 or n >= 2 ** 128:
            raise DexError(f"v4 {w} must be a uint128")
    return _head_tail(
        [_u256(token_id), _u256(liquidity), _u128(amount0_min),
         _u128(amount1_min), None],
        [_enc_bytes(bytes(hook_data))])


def build_v4_increase_params(token_id: int, liquidity: int,
                             amount0_max: int, amount1_max: int,
                             hook_data: bytes = b"") -> bytes:
    """INCREASE_LIQUIDITY params: (tokenId, liquidity, amount0Max,
    amount1Max, hookData). Adds ``liquidity`` to an existing position;
    amount0Max/amount1Max bound the spend (slippage protection)."""
    _require_positive_int(token_id, "token_id")
    _require_positive_int(liquidity, "liquidity")
    for n, w in ((amount0_max, "amount0 max"), (amount1_max, "amount1 max")):
        if not isinstance(n, int) or n < 0 or n >= 2 ** 128:
            raise DexError(f"v4 {w} must be a uint128")
    return _head_tail(
        [_u256(token_id), _u128(liquidity), _u128(amount0_max),
         _u128(amount1_max), None],
        [_enc_bytes(bytes(hook_data))])


def build_v4_lp_increase_calldata(currency0: str, currency1: str,
                                 token_id: int, liquidity: int,
                                 amount0_max: int, amount1_max: int,
                                 deadline: int,
                                 allow_native: bool = False) -> str:
    """One-tx v4 increase: [INCREASE_LIQUIDITY, SETTLE_PAIR]. ``liquidity``
    is the delta to add; amount0Max/amount1Max bound the spend. With a
    native currency0, the caller must send msg.value covering the native
    leg — keep its max tight, because any unspent native stays in the
    PositionManager.
    """
    increase = build_v4_increase_params(token_id, liquidity, amount0_max,
                                        amount1_max)
    settle = build_v4_settle_pair_params(currency0, currency1,
                                         allow_native=allow_native)
    return build_v4_modify_liquidities_calldata(
        bytes([V4_ACTIONS["INCREASE_LIQUIDITY"], V4_ACTIONS["SETTLE_PAIR"]]),
        [increase, settle], deadline)


def build_v4_settle_pair_params(currency0: str, currency1: str,
                                  allow_native: bool = False) -> bytes:
    """SETTLE_PAIR params: (currency0, currency1) — pays the full open
    debt for both currencies (payer is the unlock locker, i.e. us).
    Native currency settles from the tx's msg.value."""
    _require_v4_currencies(currency0, currency1, allow_native)
    return _addr(currency0) + _addr(currency1)


def build_v4_take_pair_params(currency0: str, currency1: str,
                             recipient: str,
                             allow_native: bool = False) -> bytes:
    """TAKE_PAIR params: (currency0, currency1, recipient) — takes the full
    open credit for both currencies to ``recipient``."""
    _require_v4_currencies(currency0, currency1, allow_native)
    _require_address(recipient, "recipient")
    return _addr(currency0) + _addr(currency1) + _addr(recipient)


def build_v4_burn_params(token_id: int) -> bytes:
    """BURN_POSITION params: (tokenId, amount0Min=0, amount1Min=0,
    hookData) — burns the position NFT. The periphery auto-decreases any
    remaining liquidity to 0 first; explicit slippage belongs on the
    DECREASE_LIQUIDITY step that precedes this."""
    _require_positive_int(token_id, "token_id")
    return _head_tail([_u256(token_id), _u128(0), _u128(0), None],
                      [_enc_bytes(b"")])


def build_v4_lp_add_calldata(currency0: str, currency1: str, fee: int,
                             tick_spacing: int, hooks: str,
                             tick_lower: int, tick_upper: int,
                             liquidity: int,
                             amount0_max: int, amount1_max: int,
                             recipient: str, deadline: int,
                             allow_native: bool = False) -> str:
    """One-tx v4 add: [MINT_POSITION, SETTLE_PAIR]. ``liquidity`` is in
    position liquidity units (compute off-chain, e.g. from the pool's
    current price and the desired token amounts); amount0Max/amount1Max
    bound the spend. With a native currency0, the caller must send
    msg.value covering the native leg — keep its max tight, because any
    unspent native stays in the PositionManager.
    """
    mint = build_v4_mint_params(currency0, currency1, fee, tick_spacing,
                                hooks, tick_lower, tick_upper, liquidity,
                                amount0_max, amount1_max, recipient,
                                allow_native=allow_native)
    settle = build_v4_settle_pair_params(currency0, currency1,
                                         allow_native=allow_native)
    return build_v4_modify_liquidities_calldata(
        bytes([V4_ACTIONS["MINT_POSITION"], V4_ACTIONS["SETTLE_PAIR"]]),
        [mint, settle], deadline)


def build_v4_lp_remove_calldata(token_id: int, liquidity: int,
                                amount0_min: int, amount1_min: int,
                                currency0: str, currency1: str,
                                recipient: str, deadline: int,
                                burn_nft: bool = False,
                                allow_native: bool = False) -> str:
    """One-tx v4 remove: [DECREASE_LIQUIDITY, TAKE_PAIR]. With
    ``burn_nft`` (full exits), appends BURN_POSITION to retire the NFT."""
    _require_positive_int(liquidity, "liquidity to remove")
    dec = build_v4_decrease_params(token_id, liquidity,
                                   amount0_min, amount1_min)
    take = build_v4_take_pair_params(currency0, currency1, recipient,
                                     allow_native=allow_native)
    actions = [V4_ACTIONS["DECREASE_LIQUIDITY"], V4_ACTIONS["TAKE_PAIR"]]
    params = [dec, take]
    if burn_nft:
        actions.append(V4_ACTIONS["BURN_POSITION"])
        params.append(build_v4_burn_params(token_id))
    return build_v4_modify_liquidities_calldata(bytes(actions), params,
                                                deadline)


def build_v4_lp_claim_calldata(token_id: int, currency0: str, currency1: str,
                               recipient: str, deadline: int,
                               allow_native: bool = False) -> str:
    """One-tx v4 fee claim: [DECREASE_LIQUIDITY (0), TAKE_PAIR]. The
    position's liquidity is untouched; accrued fees are credited and
    taken to ``recipient``."""
    dec = build_v4_decrease_params(token_id, 0, 0, 0)
    take = build_v4_take_pair_params(currency0, currency1, recipient,
                                     allow_native=allow_native)
    return build_v4_modify_liquidities_calldata(
        bytes([V4_ACTIONS["DECREASE_LIQUIDITY"], V4_ACTIONS["TAKE_PAIR"]]),
        [dec, take], deadline)


# ---------------------------------------------------------------------------
# Permit2 (v4 approval path)
# ---------------------------------------------------------------------------


def build_permit2_allowance_calldata(owner: str, token: str,
                                    spender: str) -> str:
    """Permit2.allowance(owner, token, spender) eth_call payload (read-only).
    Returns (uint160 amount, uint48 expiration, uint48 nonce)."""
    _require_address(owner, "owner")
    _require_address(token, "token")
    _require_address(spender, "spender")
    return _calldata(PERMIT2_ALLOWANCE_SELECTOR,
                     _addr(owner) + _addr(token) + _addr(spender))


def decode_permit2_allowance(result_hex: str) -> tuple[int, int, int]:
    """Decode Permit2.allowance's (amount, expiration, nonce) triple."""
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    if len(h) != 192:
        raise DexError(f"bad permit2 allowance return data: "
                       f"{result_hex!r}"[:80])
    return int(h[0:64], 16), int(h[64:128], 16), int(h[128:192], 16)


def build_permit2_approve_calldata(token: str, spender: str, amount: int,
                                  expiration: int) -> str:
    """Permit2.approve(token, spender, amount, expiration) — the second
    stage of the v4 approval path. ``amount`` is the EXACT position spend
    and ``expiration`` a unix timestamp (the intent deadline); never
    type(uint160).max unless the human explicitly asked."""
    _require_address(token, "token")
    _require_address(spender, "spender")
    _u160(amount)  # range-check
    _require_positive_int(amount, "permit2 approve amount")
    _u48(expiration)  # range-check
    _require_positive_int(expiration, "permit2 approve expiration")
    return _calldata(PERMIT2_APPROVE_SELECTOR,
                     _addr(token) + _addr(spender) + _u160(amount) +
                     _u48(expiration))


# ---------------------------------------------------------------------------
# Read helpers: position ownership, posm -> poolManager, pool slot0
# ---------------------------------------------------------------------------


V2_PAIR_TOKEN0_SELECTOR = "0dfe1681"  # token0()
V2_PAIR_TOKEN1_SELECTOR = "d21220a7"  # token1()


def build_v2_pair_token0_calldata() -> str:
    """UniswapV2Pair.token0() eth_call payload (read-only) — identifies
    which token a pair contract claims to be the LP token for."""
    return _calldata(V2_PAIR_TOKEN0_SELECTOR, b"")


def build_v2_pair_token1_calldata() -> str:
    """UniswapV2Pair.token1() eth_call payload (read-only)."""
    return _calldata(V2_PAIR_TOKEN1_SELECTOR, b"")


def build_erc721_owner_of_calldata(token_id: int) -> str:
    """ownerOf(tokenId) eth_call payload — proves the wallet owns the v3/v4
    position NFT before a remove/claim is attempted."""
    _require_positive_int(token_id, "token_id")
    return _calldata(ERC721_OWNER_OF_SELECTOR, _u256(token_id))


def decode_erc721_owner_of(result_hex: str) -> str:
    """Decode ownerOf's address return."""
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    if len(h) != 64:
        raise DexError(f"bad ownerOf return data: {result_hex!r}"[:80])
    return "0x" + h[24:]


def build_posm_pool_manager_calldata() -> str:
    """PositionManager.poolManager() eth_call payload — reads the v4
    PoolManager address from the PositionManager itself (also proves the
    supplied address is actually a PositionManager)."""
    return _calldata(POSM_POOL_MANAGER_SELECTOR, b"")


def decode_address_return(result_hex: str) -> str:
    """Decode a single-address eth_call return."""
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    if len(h) != 64:
        raise DexError(f"bad address return data: {result_hex!r}"[:80])
    return "0x" + h[24:]


def build_pool_manager_get_slot0_calldata(pool_id_hex: str) -> str:
    """PoolManager.getSlot0(poolId) eth_call payload (read-only)."""
    h = pool_id_hex[2:] if pool_id_hex.startswith("0x") else pool_id_hex
    if len(h) != 64:
        raise DexError(f"bad pool id: {pool_id_hex!r}"[:80])
    return _calldata(POOL_MANAGER_GET_SLOT0_SELECTOR,
                     bytes.fromhex(h))


def decode_slot0_sqrt_price_x96(result_hex: str) -> int:
    """Decode getSlot0's first word (sqrtPriceX96). Zero means the pool is
    not initialized — minting into it would revert."""
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    if len(h) < 64:
        raise DexError(f"bad slot0 return data: {result_hex!r}"[:80])
    return int(h[0:64], 16)


#: Uniswap v4 StateView addresses per chain id — the read-only pool-state
#: lens. Used where the local PoolManager deployment does not expose
#: getSlot0 (Robinhood Chain's modified PoolManager reverts on it; the
#: stock PoolManager exposes slot0 only through extsload). Mirrors the
#: v4_state_view pins below (uniswap deployments.json a677c0d).
V4_STATE_VIEW_ADDRESSES = {
    4663: "0xf3334192d15450cdd385c8b70e03f9a6bd9e673b",
    8453: "0xa3c0c9b65bad0b08107aa264b0f3db444b867a71",
}


def build_state_view_get_slot0_calldata(pool_id_hex: str) -> str:
    """StateView.getSlot0(bytes32) eth_call payload. StateView's getSlot0
    returns the same (sqrtPriceX96, tick, protocolFee, lpFee) layout as
    PoolManager.getSlot0, so decode_slot0_sqrt_price_x96 applies."""
    return build_pool_manager_get_slot0_calldata(pool_id_hex)


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
    "ZEROX_BASE", "ZEROX_DIRECT", "OPERATOR_QUOTE_RELAY", "zerox_base",
    "UNISWAP_BASE", "CAST_BASE",
    "ZEROX_CHAINS", "UNISWAP_CHAINS", "CAST_CHAINS",
    "NATIVE_SENTINEL", "NATIVE_ZERO",
    "VENUE_MATCHA", "VENUE_UNISWAP", "VENUE_CAST", "KNOWN_VENUES",
    "VENUE_ALIASES", "VENUE_CHAINS", "VENUE_ENV_KEYS", "VENUES_KEY_OPTIONAL",
    "DEFAULT_RECOMMENDED_VENUES",
    "normalize_venue", "venue_serves_chain", "relay_mode",
    "ZeroExClient", "UniswapClient", "CastClient",
    "build_approve_calldata", "build_allowance_calldata", "decode_allowance",
    "build_v2_swap_calldata", "build_v2_add_liquidity_calldata",
    "build_v2_remove_liquidity_calldata",
    "build_v2_pair_token0_calldata", "build_v2_pair_token1_calldata",
    "build_v3_exact_input_single_calldata", "build_v3_mint_calldata",
    "build_v3_decrease_liquidity_calldata", "build_v3_collect_calldata",
    "build_v3_multicall_calldata", "build_v3_remove_and_collect_calldata",
    "V4_ACTIONS", "V4_NATIVE_CURRENCY", "V4_DYNAMIC_FEE_FLAG",
    "build_v4_pool_key", "v4_pool_id",
    "build_v4_modify_liquidities_calldata", "build_v4_mint_params",
    "build_v4_decrease_params", "build_v4_settle_pair_params",
    "build_v4_take_pair_params", "build_v4_burn_params",
    "build_v4_lp_add_calldata", "build_v4_lp_remove_calldata",
    "build_v4_lp_claim_calldata",
    "build_permit2_allowance_calldata", "decode_permit2_allowance",
    "build_permit2_approve_calldata",
    "build_erc721_owner_of_calldata", "decode_erc721_owner_of",
    "build_posm_pool_manager_calldata", "decode_address_return",
    "build_pool_manager_get_slot0_calldata",
    "decode_slot0_sqrt_price_x96",
    "compare_quotes",
]

# ---------------------------------------------------------------------------
# Pinned contracts (S-20, S-21)
#
# Every contract the daemon sends a swap or an LP call to, or approves as a
# spender, comes from this in-code table — never from a venue's answer or
# an agent's params. A chain/role with no entry is REFUSED. Every built-in
# address is copied from an official deployment list, named per entry in
# PINNED_SOURCES (tests/test_dex_pins.py cross-checks the Uniswap ones
# against a committed copy of the feed's records). The operator may add or
# replace entries in spellbook.json (dex.pinned_contracts); the daemon
# logs every override at startup and the queue shows which source each
# pinned address came from.
# ---------------------------------------------------------------------------

#: 0x AllowanceHolder: the swap target AND the ERC-20 spender for 0x Swap
#: API v2 allowance-holder quotes (matcha, and Cast, which serves 0x
#: allowance-holder quotes).
PIN_ALLOWANCE_HOLDER = "allowance_holder"
#: Uniswap Universal Router: the target of Trading API /swap transactions
#: (and the Permit2 stage-2 spender of a Uniswap token sell).
PIN_UNIVERSAL_ROUTER = "universal_router"
#: Uniswap v4 PositionManager (LP add/remove/claim, and the Permit2 spender).
PIN_V4_POSITION_MANAGER = "v4_position_manager"
#: Permit2 (the first-stage ERC-20 spender for v4 LP and Uniswap swaps).
PIN_PERMIT2 = "permit2"
#: Uniswap v2(-style) router (v2 LP add/remove spender and target).
PIN_V2_ROUTER = "v2_router"
#: Uniswap v3 NonfungiblePositionManager (v3 LP add/remove/claim).
PIN_V3_POSITION_MANAGER = "v3_position_manager"
#: Uniswap v4 PoolManager: must be what the pinned PositionManager reports
#: before a v4 add is signed.
PIN_V4_POOL_MANAGER = "v4_pool_manager"
#: Uniswap v4 StateView (read-only lens for pool slot0).
PIN_V4_STATE_VIEW = "v4_state_view"
#: Uniswap v3 SwapRouter02. Reference only: no daemon intent targets it
#: (direct v2/v3 swaps are library calldata builders, not daemon intents).
PIN_V3_SWAP_ROUTER = "v3_swap_router"

PIN_ROLES = (PIN_ALLOWANCE_HOLDER, PIN_UNIVERSAL_ROUTER,
             PIN_V4_POSITION_MANAGER, PIN_PERMIT2, PIN_V2_ROUTER,
             PIN_V3_POSITION_MANAGER, PIN_V4_POOL_MANAGER,
             PIN_V4_STATE_VIEW, PIN_V3_SWAP_ROUTER)

#: The Uniswap deployment feed the Uniswap pins are copied from:
#: https://developers.uniswap.org/deployments.json, generatedAt
#: 2026-09-22T20:38:17Z, built from github.com/Uniswap/contracts at
#: a677c0d4b5fb6e3357cf6d0f0315bcb135a1e1ee. The records used are
#: committed in tests/fixtures/uniswap_deployments_4663_8453.json.
SOURCE_UNISWAP = "uniswap deployments.json a677c0d (2026-09-22)"
#: 0x's own list: github.com/0xProject/0x-settler README, "AllowanceHolder
#: addresses" — one address on every Cancun chain (Base and Robinhood
#: Chain among them).
SOURCE_ZEROX = "0x-settler README"

#: 0x Settler deployer/registry, the same address on every chain. Settler
#: itself rotates and is NOT pinned: the AllowanceHolder decode only
#: requires its target to be none of the tokens, the wallet or the holder.
#: Closing that gap means pinning the current taker-submitted Settler as
#: ``ownerOf(SETTLER_FEATURE_TAKER_SUBMITTED)`` on this registry — an
#: eth_call, which this module does not make.
SETTLER_REGISTRY = "0x00000000000004533fe15556b1e086bb1a72ceae"
SETTLER_FEATURE_TAKER_SUBMITTED = 2

_ALLOWANCE_HOLDER = "0x0000000000001ff3684f28c67538d4d072c22734"
_PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"

#: chain id -> {role: address (lowercase)}: the primary pin per role.
#: PINNED_ALTERNATES lists further official versions accepted for a role.
#: A chain or role not listed is refused until the operator pins it.
PINNED_CONTRACTS = {
    4663: {  # Robinhood Chain mainnet
        PIN_ALLOWANCE_HOLDER: _ALLOWANCE_HOLDER,
        PIN_UNIVERSAL_ROUTER: "0x06afba43fd06227fa663b0daecf536f6eaa6bf99",
        PIN_V4_POSITION_MANAGER: "0x58daec3116aae6d93017baaea7749052e8a04fa7",
        PIN_V4_POOL_MANAGER: "0x8366a39cc670b4001a1121b8f6a443a643e40951",
        PIN_V4_STATE_VIEW: "0xf3334192d15450cdd385c8b70e03f9a6bd9e673b",
        PIN_V3_POSITION_MANAGER: "0x73991a25c818bf1f1128deaab1492d45638de0d3",
        PIN_V3_SWAP_ROUTER: "0xcaf681a66d020601342297493863e78c959e5cb2",
        PIN_V2_ROUTER: "0x89e5db8b5aa49aa85ac63f691524311aeb649eba",
        PIN_PERMIT2: _PERMIT2,
    },
    8453: {  # Base
        PIN_ALLOWANCE_HOLDER: _ALLOWANCE_HOLDER,
        PIN_UNIVERSAL_ROUTER: "0x6ff5693b99212da76ad316178a184ab56d299b43",
        PIN_V4_POSITION_MANAGER: "0x7c5f5a4bbd8fd63184577525326123b519429bdc",
        PIN_V4_POOL_MANAGER: "0x498581ff718922c3f8e6a244956af099b2652b2b",
        PIN_V4_STATE_VIEW: "0xa3c0c9b65bad0b08107aa264b0f3db444b867a71",
        PIN_V3_POSITION_MANAGER: "0x03a520b32c04bf3beef7beb72e919cf822ed34f1",
        PIN_V3_SWAP_ROUTER: "0x2626664c2603336e57b271c5c0b26f421741e481",
        PIN_V2_ROUTER: "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24",
        PIN_PERMIT2: _PERMIT2,
    },
}

#: Further official addresses accepted for a (chain, role), with their
#: source: Universal Router versions the Trading API may return. Only
#: versions in the feed are listed (the v1.2 router on Base is not).
PINNED_ALTERNATES = {
    (4663, PIN_UNIVERSAL_ROUTER): {
        "0x204faca1764b154221e35c0d20abb3c525710498":
            f"{SOURCE_UNISWAP}: UniversalRouter#v2.1.2",
    },
    (8453, PIN_UNIVERSAL_ROUTER): {
        "0xd6145b2d3f379919e8cdeda7b97e37c4b2ca9c40":
            f"{SOURCE_UNISWAP}: UniversalRouter#v2.1.2",
        "0xfdf682f51fe81aa4898f0ae2163d8a55c127fbc7":
            f"{SOURCE_UNISWAP}: UniversalRouter#v2.1.1",
        "0xf3a4f4094bd2c6c06ca2f61789d8727b8d1e7259":
            f"{SOURCE_UNISWAP}: UniversalRouter#v2.1",
    },
}

#: The feed's contract name for each Uniswap role (used for the sources
#: below and by the fixture cross-check test).
UNISWAP_ROLE_CONTRACTS = {
    PIN_UNIVERSAL_ROUTER: ("universal-router", "UniversalRouter"),
    PIN_V4_POSITION_MANAGER: ("v4", "PositionManager"),
    PIN_V4_POOL_MANAGER: ("v4", "PoolManager"),
    PIN_V4_STATE_VIEW: ("v4", "StateView"),
    PIN_V3_POSITION_MANAGER: ("v3", "NonfungiblePositionManager"),
    PIN_V3_SWAP_ROUTER: ("v3", "SwapRouter02"),
    PIN_V2_ROUTER: ("v2", "UniswapV2Router02"),
    PIN_PERMIT2: ("permit2", "Permit2"),
}

#: Where each built-in primary pin comes from (shown in the queue and
#: dex_venues).
PINNED_SOURCES = {
    (cid, role): (f"{SOURCE_ZEROX}: AllowanceHolder (Cancun chains)"
                  if role == PIN_ALLOWANCE_HOLDER else
                  f"{SOURCE_UNISWAP}: {UNISWAP_ROLE_CONTRACTS[role][1]}")
    for cid, roles in PINNED_CONTRACTS.items() for role in roles
}

OVERRIDE_SOURCE = "operator override (spellbook.json dex.pinned_contracts)"

#: Which pinned role a venue's swap transaction must target.
VENUE_SWAP_TARGET = {
    VENUE_MATCHA: PIN_ALLOWANCE_HOLDER,
    VENUE_CAST: PIN_ALLOWANCE_HOLDER,
    VENUE_UNISWAP: PIN_UNIVERSAL_ROUTER,
}

#: Which pinned role a venue's ERC-20 approve goes to. 0x pulls through
#: the AllowanceHolder it calls; the Universal Router pulls through Permit2
#: (token -> Permit2, then Permit2 -> the router, both exact-amount).
VENUE_APPROVAL_SPENDER = {
    VENUE_MATCHA: PIN_ALLOWANCE_HOLDER,
    VENUE_CAST: PIN_ALLOWANCE_HOLDER,
    VENUE_UNISWAP: PIN_PERMIT2,
}


def parse_pin_overrides(raw) -> dict:
    """Validate spellbook.json's dex.pinned_contracts:
    ``{"<chain id>": {"<role>": "0x<address>"}}``. Returns
    ``{chain_id: {role: address_lower}}``. Unknown roles, bad chain ids
    and bad addresses raise DexError (the daemon refuses to start)."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise DexError("dex.pinned_contracts must be an object "
                       "{chain_id: {role: address}}")
    out = {}
    for cid, roles in raw.items():
        try:
            chain_id = int(str(cid), 10)
        except ValueError:
            raise DexError(f"dex.pinned_contracts: bad chain id {cid!r}")
        if chain_id <= 0 or not isinstance(roles, dict) or not roles:
            raise DexError(f"dex.pinned_contracts[{cid!r}] must be a "
                           "non-empty object {role: address}")
        for role, addr in roles.items():
            if role not in PIN_ROLES:
                raise DexError(f"dex.pinned_contracts: unknown role {role!r} "
                               f"(known: {', '.join(PIN_ROLES)})")
            if not _is_address(addr) or int(addr, 16) == 0:
                raise DexError(f"dex.pinned_contracts[{cid!r}][{role!r}]: "
                               f"bad address {addr!r}")
            out.setdefault(chain_id, {})[role] = addr.lower()
    return out


def pinned_contracts(chain_id: int, overrides: dict | None = None) -> dict:
    """{role: address} pinned for chain_id: the built-in table with any
    operator overrides applied on top."""
    pins = dict(PINNED_CONTRACTS.get(chain_id, {}))
    pins.update((overrides or {}).get(chain_id, {}))
    return pins


def pinned_set(chain_id: int, role: str,
               overrides: dict | None = None) -> dict:
    """{address: source} of every address accepted for (chain_id, role):
    the primary pin plus its official alternates. An operator override
    replaces the whole set with its one address. Empty when unpinned."""
    over = (overrides or {}).get(chain_id, {})
    if role in over:
        return {over[role]: OVERRIDE_SOURCE}
    primary = PINNED_CONTRACTS.get(chain_id, {}).get(role)
    if not primary:
        return {}
    out = {primary: PINNED_SOURCES.get((chain_id, role))}
    out.update(PINNED_ALTERNATES.get((chain_id, role), {}))
    return out


def pin_source(chain_id: int, role: str, overrides: dict | None = None,
               address: str | None = None) -> str | None:
    """Where the pinned address for (chain_id, role) came from (the
    primary's, or ``address``'s when it is one of the accepted set)."""
    if role in (overrides or {}).get(chain_id, {}):
        return OVERRIDE_SOURCE
    if address is not None:
        return pinned_set(chain_id, role, overrides).get(address.lower())
    return PINNED_SOURCES.get((chain_id, role))


def pinned_contract(chain_id: int, role: str,
                    overrides: dict | None = None) -> str:
    """The pinned address for (chain_id, role), or DexError: an unpinned
    contract is refused, never taken from the caller."""
    addr = pinned_contracts(chain_id, overrides).get(role)
    if not addr:
        raise DexError(
            f"no pinned {role} for chain {chain_id} — refusing (Spellbook "
            "only sends to contracts it has pinned; the operator can pin "
            "one in spellbook.json dex.pinned_contracts)")
    return addr


def resolve_pinned(chain_id: int, role: str, supplied,
                   overrides: dict | None = None, what: str = "") -> str:
    """The pinned address for (chain_id, role). A caller-supplied address
    is accepted only when it IS the pinned one; anything else refuses."""
    addr = pinned_contract(chain_id, role, overrides)
    if supplied not in (None, "") and str(supplied).lower() != addr:
        raise DexError(
            f"{what or role} {supplied!r} is not the pinned {role} for "
            f"chain {chain_id} ({addr}) — refusing; omit it to use the pin")
    return addr


def require_pinned_member(chain_id: int, role: str, address,
                          overrides: dict | None = None,
                          what: str = "") -> str:
    """``address`` (lowercased) when it is one of the accepted pins for
    (chain_id, role) — the primary or an official alternate — else
    DexError. Unpinned chains/roles refuse."""
    accepted = pinned_set(chain_id, role, overrides)
    if not accepted:
        pinned_contract(chain_id, role, overrides)  # raises "no pinned"
    if not _is_address(address) or address.lower() not in accepted:
        raise DexError(
            f"{what or role} {address!r} is not a pinned {role} for chain "
            f"{chain_id} ({', '.join(sorted(accepted))}) — refusing")
    return address.lower()


def dex_asset_key(token: str) -> str:
    """The one policy/velocity key for a DEX leg: either venue's native
    representation is "native" (the key plain transfers use); a token is
    its lowercased address. Shared by policy and velocity (S-21)."""
    return "native" if _is_native_token(token) else (token or "").lower()


# ---------------------------------------------------------------------------
# Calldata decoding (S-20, S-21) — the transaction that will be signed is
# decoded and compared with the intent; a quote's own claims are not
# evidence.
# ---------------------------------------------------------------------------

#: AllowanceHolder.exec(address operator, address token, uint256 amount,
#: address payable target, bytes data)
ALLOWANCE_HOLDER_EXEC_SELECTOR = "2213bc0b"
#: Settler.execute((address recipient, address buyToken, uint256
#: minAmountOut) slippage, bytes[] actions, bytes32 zid)
SETTLER_EXECUTE_SELECTOR = "1fff991f"
#: UniversalRouter.execute(bytes commands, bytes[] inputs)
UR_EXECUTE_SELECTOR = "24856bc3"
#: UniversalRouter.execute(bytes commands, bytes[] inputs, uint256 deadline)
UR_EXECUTE_DEADLINE_SELECTOR = "3593564c"

SELECTOR_NAMES = {
    ALLOWANCE_HOLDER_EXEC_SELECTOR:
        "AllowanceHolder.exec(address,address,uint256,address,bytes)",
    SETTLER_EXECUTE_SELECTOR:
        "Settler.execute((address,address,uint256),bytes[],bytes32)",
    UR_EXECUTE_SELECTOR: "UniversalRouter.execute(bytes,bytes[])",
    UR_EXECUTE_DEADLINE_SELECTOR:
        "UniversalRouter.execute(bytes,bytes[],uint256)",
    V4_MODIFY_LIQUIDITIES_SELECTOR:
        "PositionManager.modifyLiquidities(bytes,uint256)",
    V2_ADD_LIQ_SELECTOR: "UniswapV2Router02.addLiquidity(address,address,"
                         "uint256,uint256,uint256,uint256,address,uint256)",
    V2_REMOVE_LIQ_SELECTOR: "UniswapV2Router02.removeLiquidity(address,"
                            "address,uint256,uint256,uint256,address,"
                            "uint256)",
    V3_MINT_SELECTOR: "NonfungiblePositionManager.mint((address,address,"
                      "uint24,int24,int24,uint256,uint256,uint256,uint256,"
                      "address,uint256))",
    V3_DECREASE_LIQUIDITY_SELECTOR:
        "NonfungiblePositionManager.decreaseLiquidity((uint256,uint128,"
        "uint256,uint256,uint256))",
    V3_COLLECT_SELECTOR: "NonfungiblePositionManager.collect((uint256,"
                         "address,uint128,uint128))",
    V3_MULTICALL_SELECTOR: "NonfungiblePositionManager.multicall(bytes[])",
}

#: The swap entry points accepted per pinned target role.
SWAP_SELECTORS = {
    PIN_ALLOWANCE_HOLDER: (ALLOWANCE_HOLDER_EXEC_SELECTOR,),
    PIN_UNIVERSAL_ROUTER: (UR_EXECUTE_SELECTOR, UR_EXECUTE_DEADLINE_SELECTOR),
}

#: Universal Router command ids (Commands.sol). Only the ones Spellbook can
#: bound are accepted; every other command is refused by name or number.
UR_V3_SWAP_EXACT_IN = 0x00
UR_SWEEP = 0x04
UR_V2_SWAP_EXACT_IN = 0x08
UR_WRAP_ETH = 0x0B
UR_UNWRAP_WETH = 0x0C
UR_V4_SWAP = 0x10
UR_COMMAND_NAMES = {
    0x00: "V3_SWAP_EXACT_IN", 0x01: "V3_SWAP_EXACT_OUT",
    0x02: "PERMIT2_TRANSFER_FROM", 0x03: "PERMIT2_PERMIT_BATCH",
    0x04: "SWEEP", 0x05: "TRANSFER", 0x06: "PAY_PORTION",
    0x08: "V2_SWAP_EXACT_IN", 0x09: "V2_SWAP_EXACT_OUT",
    0x0A: "PERMIT2_PERMIT", 0x0B: "WRAP_ETH", 0x0C: "UNWRAP_WETH",
    0x0D: "PERMIT2_TRANSFER_FROM_BATCH", 0x0E: "BALANCE_CHECK_ERC20",
    0x10: "V4_SWAP",
}
#: Universal Router recipient sentinels (Constants.sol).
UR_MSG_SENDER = "0x0000000000000000000000000000000000000001"
UR_ADDRESS_THIS = "0x0000000000000000000000000000000000000002"
#: Universal Router "use the router's whole balance" amount sentinel.
UR_CONTRACT_BALANCE = 1 << 255


def _abi_decode(types: list, data_hex: str, what: str) -> list:
    from spellbook import abi as _abi
    try:
        return _abi.decode_abi(types, data_hex)
    except _abi.AbiError as e:
        raise DexError(f"{what}: calldata does not decode ({e}) — refusing")


def _split_selector(data, what: str) -> tuple[str, str]:
    if not (isinstance(data, str) and data.startswith("0x")):
        raise DexError(f"{what}: calldata is not 0x-hex — refusing")
    h = data[2:].lower()
    if len(h) < 8 or len(h) % 2 or any(c not in "0123456789abcdef" for c in h):
        raise DexError(f"{what}: calldata is malformed — refusing")
    return h[:8], "0x" + h[8:]


def _same_token(a: str, b: str) -> bool:
    if _is_native_token(a) or _is_native_token(b):
        return _is_native_token(a) and _is_native_token(b)
    return (a or "").lower() == (b or "").lower()


def _decode_settler_execute(data_hex: str, *, wallet: str, buy_token: str,
                            min_buy: int) -> dict:
    """Bind a 0x Settler.execute call: the slippage struct's recipient is
    the wallet, its buy token is the intent's, and its minimum out is at
    least the intent's minimum. Settler enforces that struct on-chain."""
    sel, args = _split_selector(data_hex, "0x Settler call")
    if sel != SETTLER_EXECUTE_SELECTOR:
        raise DexError(
            f"matcha/cast: AllowanceHolder target selector 0x{sel} is not "
            f"{SELECTOR_NAMES[SETTLER_EXECUTE_SELECTOR]} — cannot decode, "
            "refusing")
    recipient, s_buy, min_out, _actions, _zid = _abi_decode(
        ["address", "address", "uint256", "bytes[]", "bytes32"], args,
        "0x Settler.execute")
    if recipient != wallet.lower():
        raise DexError(f"swap recipient {recipient} is not this wallet "
                       f"({wallet.lower()}) — refusing")
    if not _same_token(s_buy, buy_token):
        raise DexError(f"swap buys {s_buy}, approved {buy_token} — refusing")
    if min_out < min_buy:
        raise DexError(f"swap minimum out {min_out} < approved minimum "
                       f"{min_buy} — refusing")
    return {"recipient": recipient, "buy_token": s_buy,
            "min_buy_amount_wei": min_out,
            "inner_selector": "0x" + sel,
            "inner_selector_name": SELECTOR_NAMES[sel]}


def _decode_allowance_holder(data_hex: str, *, target_addr: str, wallet: str,
                             sell_token: str, sell_amount: int,
                             buy_token: str, min_buy: int,
                             tokens: tuple) -> dict:
    sel, args = _split_selector(data_hex, "swap")
    operator, token, amount, inner, inner_data = _abi_decode(
        ["address", "address", "uint256", "address", "bytes"], args,
        "AllowanceHolder.exec")
    # The holder lets `operator` pull up to `amount` of `token` from this
    # wallet during the call: that pair must be exactly the sell leg.
    if _is_native_token(sell_token):
        if not _is_native_token(token):
            raise DexError(f"native sell, but exec grants token {token} — "
                           "refusing")
        # A native amount grants nothing (no transferFrom on native); the
        # tx value, checked separately, is what moves.
        if amount not in (0, sell_amount):
            raise DexError(f"exec amount {amount} != approved sell amount "
                           f"{sell_amount} — refusing")
    else:
        if token != sell_token.lower():
            raise DexError(f"exec sells token {token}, approved "
                           f"{sell_token.lower()} — refusing")
        if amount != sell_amount:
            raise DexError(f"exec amount {amount} != approved sell amount "
                           f"{sell_amount} — exact amount only, refusing")
    if operator != inner:
        raise DexError(f"exec operator {operator} != target {inner} — "
                       "refusing")
    if inner in tokens or inner == wallet.lower() or inner == target_addr \
            or int(inner, 16) == 0:
        raise DexError(f"exec target {inner} is a token, this wallet or the "
                       "holder itself — refusing")
    out = {"sell_token": token, "sell_amount_wei": amount,
           "operator": operator, "settler": inner}
    out.update(_decode_settler_execute(inner_data, wallet=wallet,
                                       buy_token=buy_token, min_buy=min_buy))
    return out


def _v3_path_tokens(path_hex: str) -> tuple[str, str]:
    raw = bytes.fromhex(path_hex[2:])
    if len(raw) < 43 or (len(raw) - 20) % 23:
        raise DexError("Universal Router: malformed v3 path — refusing")
    return "0x" + raw[:20].hex(), "0x" + raw[-20:].hex()


#: v4 router actions (v4-periphery Actions.sol) a Universal Router V4_SWAP
#: may carry. Only exact-input swaps, one settle and one take are bounded.
V4_SWAP_EXACT_IN_SINGLE = 0x06
V4_SWAP_EXACT_IN = 0x07
V4_SETTLE = 0x0B
V4_SETTLE_ALL = 0x0C
V4_TAKE = 0x0E
V4_TAKE_ALL = 0x0F
V4_ROUTER_ACTION_NAMES = {
    0x06: "SWAP_EXACT_IN_SINGLE", 0x07: "SWAP_EXACT_IN",
    0x08: "SWAP_EXACT_OUT_SINGLE", 0x09: "SWAP_EXACT_OUT",
    0x0B: "SETTLE", 0x0C: "SETTLE_ALL", 0x0D: "SETTLE_PAIR",
    0x0E: "TAKE", 0x0F: "TAKE_ALL", 0x10: "TAKE_PORTION",
    0x11: "TAKE_PAIR", 0x12: "CLOSE_CURRENCY", 0x13: "CLEAR_OR_TAKE",
    0x14: "SWEEP", 0x15: "WRAP", 0x16: "UNWRAP",
}
#: ActionConstants.OPEN_DELTA: "the whole open delta".
V4_OPEN_DELTA = 0
#: Most hops / hook-data bytes a decoded v4 swap may carry.
_V4_MAX_HOPS = 8
_V4_MAX_HOOK_DATA = 4096


def _word(raw: bytes, pos: int) -> int:
    w = raw[pos:pos + 32]
    if pos < 0 or len(w) != 32:
        raise DexError("v4 swap params truncated — refusing")
    return int.from_bytes(w, "big")


def _word_addr(raw: bytes, pos: int) -> str:
    v = _word(raw, pos)
    if v >> 160:
        raise DexError("v4 swap params: non-canonical address — refusing")
    return "0x" + v.to_bytes(20, "big").hex()


def _word_uint(raw: bytes, pos: int, bits: int) -> int:
    v = _word(raw, pos)
    if v >> bits:
        raise DexError(f"v4 swap params: uint{bits} out of range — refusing")
    return v


def _word_int24(raw: bytes, pos: int) -> int:
    v = _word(raw, pos)
    s = v - (1 << 256) if v >> 255 else v
    if not -(1 << 23) <= s < (1 << 23):
        raise DexError("v4 swap params: int24 out of range — refusing")
    return s


def _word_bool(raw: bytes, pos: int) -> bool:
    v = _word(raw, pos)
    if v not in (0, 1):
        raise DexError("v4 swap params: non-canonical bool — refusing")
    return bool(v)


def _bytes_at(raw: bytes, pos: int) -> bytes:
    n = _word(raw, pos)
    if n > _V4_MAX_HOOK_DATA or pos + 32 + n > len(raw):
        raise DexError("v4 swap params: bad bytes field — refusing")
    return raw[pos + 32:pos + 32 + n]


def _enc_dyn_array(items: list[bytes]) -> bytes:
    """ABI-encode an array of already-encoded dynamic elements."""
    out, off, tails = _u256(len(items)), 32 * len(items), b""
    for it in items:
        out += _u256(off)
        off += len(it)
        tails += it
    return out + tails


def _v4_exact_in_single(raw: bytes) -> dict:
    """abi.encode(ExactInputSingleParams{PoolKey poolKey; bool zeroForOne;
    uint128 amountIn; uint128 amountOutMinimum; bytes hookData}), checked
    to be the canonical encoding of exactly that layout (a different
    struct layout cannot pass by being read at the wrong offsets)."""
    if _word(raw, 0) != 32:
        raise DexError("v4 SWAP_EXACT_IN_SINGLE: bad params offset — "
                       "refusing")
    t = raw[32:]
    c0, c1 = _word_addr(t, 0), _word_addr(t, 32)
    fee, ts = _word_uint(t, 64, 24), _word_int24(t, 96)
    hooks = _word_addr(t, 128)
    zero_for_one = _word_bool(t, 160)
    a_in, a_min = _word_uint(t, 192, 128), _word_uint(t, 224, 128)
    hook_data = _bytes_at(t, _word(t, 256))
    canon = _u256(32) + _head_tail(
        [_addr(c0) + _addr(c1) + _u24(fee) + _i24(ts) + _addr(hooks)
         + _u256(int(zero_for_one)) + _u128(a_in) + _u128(a_min), None],
        [_enc_bytes(hook_data)])
    if canon != raw:
        raise DexError("v4 SWAP_EXACT_IN_SINGLE: params are not the "
                       "expected layout — cannot decode, refusing")
    t_in, t_out = (c0, c1) if zero_for_one else (c1, c0)
    return {"in": t_in, "out": t_out, "amount_in": a_in, "min_out": a_min}


def _v4_exact_in(raw: bytes) -> dict:
    """abi.encode(ExactInputParams{Currency currencyIn; PathKey[] path;
    uint128 amountIn; uint128 amountOutMinimum}) with PathKey{Currency
    intermediateCurrency; uint24 fee; int24 tickSpacing; IHooks hooks;
    bytes hookData}, checked to be the canonical encoding of that layout."""
    if _word(raw, 0) != 32:
        raise DexError("v4 SWAP_EXACT_IN: bad params offset — refusing")
    t = raw[32:]
    c_in = _word_addr(t, 0)
    p_off = _word(t, 32)
    a_in, a_min = _word_uint(t, 64, 128), _word_uint(t, 96, 128)
    n = _word(t, p_off)
    if not 1 <= n <= _V4_MAX_HOPS:
        raise DexError(f"v4 SWAP_EXACT_IN: {n} hops — refusing")
    base = p_off + 32
    keys = []
    for i in range(n):
        p = base + _word(t, base + 32 * i)
        keys.append((_word_addr(t, p), _word_uint(t, p + 32, 24),
                     _word_int24(t, p + 64), _word_addr(t, p + 96),
                     _bytes_at(t, p + _word(t, p + 128))))
    path = _enc_dyn_array([
        _head_tail([_addr(c) + _u24(f) + _i24(s) + _addr(h), None],
                   [_enc_bytes(hd)]) for c, f, s, h, hd in keys])
    canon = _u256(32) + _head_tail(
        [_addr(c_in), None, _u128(a_in), _u128(a_min)], [path])
    if canon != raw:
        raise DexError("v4 SWAP_EXACT_IN: params are not the expected "
                       "layout — cannot decode, refusing")
    return {"in": c_in, "out": keys[-1][0], "amount_in": a_in,
            "min_out": a_min}


def _static_params(raw: bytes, n: int, what: str) -> bytes:
    if len(raw) != 32 * n:
        raise DexError(f"v4 {what}: params are not {n} words — refusing")
    return raw


def _decode_ur_v4_swap(inp: str, *, me: str, sell_token: str,
                       buy_token: str) -> dict:
    """Bind a Universal Router V4_SWAP input: abi.encode(bytes actions,
    bytes[] params) with actions = one or more exact-input swaps of the
    sell token into the buy token, then exactly one settle of the sell
    token (from the wallet via Permit2, or native from the tx value) and
    one take of the buy token to the wallet. The wallet's guaranteed out
    is the swaps' amountOutMinimum (or TAKE_ALL's minimum if higher)."""
    actions, params = _abi_decode(["bytes", "bytes[]"], inp, "V4_SWAP")
    actions = bytes.fromhex(actions[2:])
    params = [bytes.fromhex(p[2:]) for p in params]
    if _head_tail([None, None], [_enc_bytes(actions),
                                 _enc_bytes_array(params)]) \
            != bytes.fromhex(inp[2:]):
        raise DexError("V4_SWAP: input is not canonical — refusing")
    if len(actions) != len(params) or len(actions) < 3:
        raise DexError("V4_SWAP: actions/params mismatch — refusing")
    names = [V4_ROUTER_ACTION_NAMES.get(a, f"0x{a:02x}") for a in actions]
    n_swaps = 0
    while n_swaps < len(actions) and actions[n_swaps] in (
            V4_SWAP_EXACT_IN_SINGLE, V4_SWAP_EXACT_IN):
        n_swaps += 1
    tail = sorted(actions[n_swaps:])
    if n_swaps == 0 or len(tail) != 2 \
            or tail[0] not in (V4_SETTLE, V4_SETTLE_ALL) \
            or tail[1] not in (V4_TAKE, V4_TAKE_ALL):
        raise DexError(f"V4_SWAP: actions {names} are not exact-input "
                       "swaps + one settle + one take — cannot be bounded "
                       "by Spellbook, refusing")
    native_sell = _is_native_token(sell_token)
    total_in = 0
    min_out = 0
    for a, p in zip(actions[:n_swaps], params[:n_swaps]):
        sw = (_v4_exact_in_single(p) if a == V4_SWAP_EXACT_IN_SINGLE
              else _v4_exact_in(p))
        if not _same_token(sw["in"], sell_token) \
                or not _same_token(sw["out"], buy_token):
            raise DexError(f"V4_SWAP: swaps {sw['in']} -> {sw['out']}, "
                           f"approved {sell_token} -> {buy_token} — "
                           "refusing")
        if sw["amount_in"] == V4_OPEN_DELTA:
            raise DexError("V4_SWAP: open-delta swap input — refusing")
        total_in += sw["amount_in"]
        min_out += sw["min_out"]
    for a, p in zip(actions[n_swaps:], params[n_swaps:]):
        name = V4_ROUTER_ACTION_NAMES[a]
        if a == V4_SETTLE:
            _static_params(p, 3, name)
            cur, amt, payer_user = (_word_addr(p, 0), _word(p, 32),
                                    _word_bool(p, 64))
            if amt not in (V4_OPEN_DELTA, total_in):
                raise DexError(f"V4_SWAP: SETTLE amount {amt} is neither "
                               f"the open delta nor the swap input — "
                               "refusing")
            if not native_sell and not payer_user:
                raise DexError("V4_SWAP: token SETTLE paid by the router, "
                               "not the wallet — refusing")
        elif a == V4_SETTLE_ALL:
            _static_params(p, 2, name)
            cur = _word_addr(p, 0)
        elif a == V4_TAKE:
            _static_params(p, 3, name)
            cur, rcpt, amt = _word_addr(p, 0), _word_addr(p, 32), _word(p, 64)
            if rcpt not in (UR_MSG_SENDER, me):
                raise DexError(f"V4_SWAP: TAKE pays recipient {rcpt}, not "
                               "this wallet — refusing")
            if amt != V4_OPEN_DELTA:
                raise DexError("V4_SWAP: partial TAKE — refusing")
        else:  # TAKE_ALL pays msgSender (the wallet)
            _static_params(p, 2, name)
            cur = _word_addr(p, 0)
            min_out = max(min_out, _word(p, 32))
        want = sell_token if a in (V4_SETTLE, V4_SETTLE_ALL) else buy_token
        if not _same_token(cur, want):
            raise DexError(f"V4_SWAP: {name} of {cur}, approved {want} — "
                           "refusing")
    return {"actions": names, "amount_in": total_in, "min_out": min_out}


def _decode_universal_router(sel: str, args: str, *, wallet: str,
                             sell_token: str, sell_amount: int,
                             buy_token: str, min_buy: int,
                             value_wei: int) -> dict:
    types = ["bytes", "bytes[]"]
    if sel == UR_EXECUTE_DEADLINE_SELECTOR:
        types.append("uint256")
    vals = _abi_decode(types, args, "UniversalRouter.execute")
    commands = bytes.fromhex(vals[0][2:])
    inputs = vals[1]
    if len(commands) != len(inputs) or not commands:
        raise DexError("UniversalRouter: commands/inputs mismatch — refusing")
    me = wallet.lower()
    to_wallet = (UR_MSG_SENDER, me)
    native_sell = _is_native_token(sell_token)
    native_buy = _is_native_token(buy_token)
    user_in = 0         # what the swaps pull from the wallet (via Permit2)
    wrapped = 0         # native wrapped from the tx value
    v4_native = 0       # native a V4_SWAP settles from the tx value
    delivered = 0       # minimum the wallet is guaranteed to receive
    steps = []
    v4_actions = []
    for cmd, inp in zip(commands, inputs):
        name = UR_COMMAND_NAMES.get(cmd & 0x3F, f"0x{cmd:02x}")
        if cmd & 0x80:
            raise DexError(f"UniversalRouter: allow-revert flag on {name} — "
                           "refusing")
        if cmd == UR_WRAP_ETH:
            rcpt, amt = _abi_decode(["address", "uint256"], inp, name)
            if not native_sell or rcpt != UR_ADDRESS_THIS:
                raise DexError("UniversalRouter: WRAP_ETH outside a native "
                               "sell into the router — refusing")
            wrapped += amt
        elif cmd in (UR_V3_SWAP_EXACT_IN, UR_V2_SWAP_EXACT_IN):
            if cmd == UR_V3_SWAP_EXACT_IN:
                rcpt, a_in, a_min, path, payer_user = _abi_decode(
                    ["address", "uint256", "uint256", "bytes", "bool"], inp,
                    name)
                t_in, t_out = _v3_path_tokens(path)
            else:
                rcpt, a_in, a_min, path, payer_user = _abi_decode(
                    ["address", "uint256", "uint256", "address[]", "bool"],
                    inp, name)
                if len(path) < 2:
                    raise DexError("UniversalRouter: v2 path too short — "
                                   "refusing")
                t_in, t_out = path[0], path[-1]
            if payer_user:
                if native_sell or t_in != sell_token.lower() \
                        or a_in == UR_CONTRACT_BALANCE:
                    raise DexError(f"UniversalRouter: {name} pulls {t_in} "
                                   "from the wallet outside the approved "
                                   "sell — refusing")
                user_in += a_in
            if rcpt in to_wallet:
                if native_buy or t_out != buy_token.lower():
                    raise DexError(f"UniversalRouter: {name} pays {t_out} "
                                   "to the wallet, approved "
                                   f"{buy_token} — refusing")
                delivered += a_min
            elif rcpt != UR_ADDRESS_THIS:
                raise DexError(f"UniversalRouter: {name} pays recipient "
                               f"{rcpt}, not this wallet — refusing")
        elif cmd == UR_V4_SWAP:
            v4 = _decode_ur_v4_swap(inp, me=me, sell_token=sell_token,
                                    buy_token=buy_token)
            if native_sell:
                v4_native += v4["amount_in"]
            else:
                user_in += v4["amount_in"]
            delivered += v4["min_out"]
            v4_actions.append(v4["actions"])
        elif cmd == UR_SWEEP:
            tok, rcpt, amt = _abi_decode(["address", "address", "uint256"],
                                         inp, name)
            if rcpt not in to_wallet:
                raise DexError(f"UniversalRouter: SWEEP pays recipient "
                               f"{rcpt}, not this wallet — refusing")
            if native_buy or tok != buy_token.lower():
                raise DexError(f"UniversalRouter: SWEEP of {tok}, approved "
                               f"{buy_token} — refusing")
            delivered += amt
        elif cmd == UR_UNWRAP_WETH:
            rcpt, amt = _abi_decode(["address", "uint256"], inp, name)
            if rcpt not in to_wallet:
                raise DexError(f"UniversalRouter: UNWRAP_WETH pays recipient "
                               f"{rcpt}, not this wallet — refusing")
            if not native_buy:
                raise DexError("UniversalRouter: UNWRAP_WETH on a token buy "
                               "— refusing")
            delivered += amt
        else:
            raise DexError(f"UniversalRouter: command {name} cannot be "
                           "bounded by Spellbook — refusing")
        steps.append(name)
    if native_sell:
        native_used = wrapped + v4_native
        if native_used != sell_amount or native_used != value_wei:
            raise DexError(f"UniversalRouter: spends {native_used} native "
                           f"(wraps {wrapped}, v4 {v4_native}), approved "
                           f"sell {sell_amount} — refusing")
    elif user_in != sell_amount:
        raise DexError(f"UniversalRouter: pulls {user_in} from the wallet, "
                       f"approved sell {sell_amount} — refusing")
    if delivered < min_buy:
        raise DexError(f"UniversalRouter: guaranteed out {delivered} < "
                       f"approved minimum {min_buy} — refusing")
    out = {"commands": steps, "recipient": me,
           "sell_token": sell_token.lower(),
           "sell_amount_wei": sell_amount, "buy_token": buy_token.lower(),
           "min_buy_amount_wei": delivered}
    if v4_actions:
        out["v4_actions"] = v4_actions
    return out


def decode_swap_tx(*, venue: str, chain_id: int, tx: dict, wallet: str,
                   sell_token: str, buy_token: str, sell_amount: int,
                   min_buy: int, pin_overrides: dict | None = None) -> dict:
    """Decode the venue's transaction and bind it to the intent.

    Refuses unless: ``to`` is the pinned swap target for this venue and
    chain; the selector is a known entry point of that target; the decoded
    sell token/amount equal the intent's; the recipient is the wallet; and
    the decoded minimum out is at least the intent's minimum. ``value`` is
    0 for a token sell and exactly the sell amount for a native sell.
    Calldata that does not decode is refused, naming venue and selector.
    Returns what was decoded (shown to the human and the ledger).
    """
    venue = normalize_venue(venue)
    role = VENUE_SWAP_TARGET[venue]
    pinned_contract(chain_id, role, pin_overrides)  # unpinned -> refused
    accepted = pinned_set(chain_id, role, pin_overrides)
    to, data = tx.get("to"), tx.get("data")
    if not _is_address(to):
        raise DexError(f"quote tx target is not an address: {to!r}")
    if to.lower() not in accepted:
        raise DexError(f"{venue}: swap target {to} is not the pinned {role} "
                       f"for chain {chain_id} "
                       f"({', '.join(sorted(accepted))}) — refusing")
    # The accepted address the venue chose (a router version, for Uniswap).
    target_addr = to.lower()
    try:
        value_wei = int(str(tx.get("value", "0")), 0)
    except ValueError:
        raise DexError(f"quote tx value malformed: {tx.get('value')!r}")
    if value_wei < 0:
        raise DexError("quote tx value negative")
    native_sell = _is_native_token(sell_token)
    if native_sell and value_wei != sell_amount:
        raise DexError(
            f"native sell: tx value {value_wei} != sell_amount {sell_amount}")
    if not native_sell and value_wei != 0:
        raise DexError(f"token sell: tx value must be 0, got {value_wei}")
    sel, args = _split_selector(data, f"{venue} swap")
    if sel not in SWAP_SELECTORS[role]:
        raise DexError(f"{venue}: selector 0x{sel} is not a known swap entry "
                       f"point of the {role} — cannot decode, refusing")
    tokens = tuple(t.lower() for t in (sell_token, buy_token)
                   if not _is_native_token(t))
    if role == PIN_ALLOWANCE_HOLDER:
        decoded = _decode_allowance_holder(
            data, target_addr=target_addr, wallet=wallet,
            sell_token=sell_token, sell_amount=sell_amount,
            buy_token=buy_token, min_buy=min_buy, tokens=tokens)
    else:
        decoded = _decode_universal_router(
            sel, args, wallet=wallet, sell_token=sell_token,
            sell_amount=sell_amount, buy_token=buy_token, min_buy=min_buy,
            value_wei=value_wei)
    decoded.update({"venue": venue, "target": target_addr,
                    "target_role": role,
                    "target_source": pin_source(chain_id, role, pin_overrides,
                                                address=target_addr),
                    "selector": "0x" + sel,
                    "selector_name": SELECTOR_NAMES[sel],
                    "value_wei": value_wei})
    return decoded


def check_swap_approval(*, chain_id: int, venue: str, token: str,
                        spender: str, amount: int, sell_token: str,
                        sell_amount: int,
                        pin_overrides: dict | None = None) -> None:
    """The ERC-20 approve the daemon issues before a swap: to the pinned
    spender for this venue (the AllowanceHolder for 0x, Permit2 for the
    Universal Router), on the sell token, for at most the sell amount
    (never unlimited). Anything else raises DexError."""
    role = VENUE_APPROVAL_SPENDER[normalize_venue(venue)]
    pinned = pinned_contract(chain_id, role, pin_overrides)
    if not _is_address(spender) or spender.lower() != pinned:
        raise DexError(f"approve spender {spender!r} is not the pinned {role} "
                       f"for chain {chain_id} ({pinned}) — refusing")
    if _is_native_token(token) or token.lower() != sell_token.lower():
        raise DexError(f"approve on {token}, approved sell {sell_token} — "
                       "refusing")
    if isinstance(amount, bool) or not isinstance(amount, int) \
            or amount <= 0 or amount > sell_amount:
        raise DexError(f"approve amount {amount!r} exceeds the sell amount "
                       f"{sell_amount} — only exact approvals, refusing")


def check_permit2_approval(*, chain_id: int, token: str, spender: str,
                           amount: int, sell_token: str, sell_amount: int,
                           pin_overrides: dict | None = None) -> str:
    """The Permit2.approve(token, spender, amount, expiry) the daemon issues
    before a Universal Router token sell: spender is a pinned Universal
    Router (primary or an official alternate) for this chain, the token is
    the sell token, the amount at most the sell amount (fits uint160).
    Returns the spender, lowercased; anything else raises DexError."""
    spender = require_pinned_member(chain_id, PIN_UNIVERSAL_ROUTER, spender,
                                    pin_overrides, "Permit2 spender")
    if _is_native_token(token) or token.lower() != sell_token.lower():
        raise DexError(f"Permit2 approve on {token}, approved sell "
                       f"{sell_token} — refusing")
    if isinstance(amount, bool) or not isinstance(amount, int) \
            or amount <= 0 or amount > sell_amount or amount >= 2 ** 160:
        raise DexError(f"Permit2 approve amount {amount!r} exceeds the sell "
                       f"amount {sell_amount} — only exact approvals, "
                       "refusing")
    return spender


def decode_v4_lp_add_calldata(data_hex: str, *, value_wei: int,
                              currency0: str, currency1: str,
                              amount0_cap: int, amount1_cap: int,
                              wallet: str) -> dict:
    """Decode a v4 modifyLiquidities([MINT_POSITION, SETTLE_PAIR]) call and
    bind it: the pool currencies are the intent's, each leg's max spend is
    within its approved cap (the native leg's included, as tx value), the
    pool is hookless, and the position NFT goes to the wallet."""
    sel, args = _split_selector(data_hex, "v4 LP add")
    if sel != V4_MODIFY_LIQUIDITIES_SELECTOR:
        raise DexError(f"v4 LP add: selector 0x{sel} is not "
                       "modifyLiquidities — refusing")
    unlock, deadline = _abi_decode(["bytes", "uint256"], args,
                                   "modifyLiquidities")
    actions, params = _abi_decode(["bytes", "bytes[]"], unlock,
                                  "modifyLiquidities unlockData")
    actions = bytes.fromhex(actions[2:])
    want = bytes([V4_ACTIONS["MINT_POSITION"], V4_ACTIONS["SETTLE_PAIR"]])
    if actions != want or len(params) != 2:
        raise DexError(f"v4 LP add: actions 0x{actions.hex()} are not "
                       "[MINT_POSITION, SETTLE_PAIR] — refusing")
    (c0, c1, fee, tick_spacing, hooks, tl, tu, liquidity, a0max, a1max,
     owner, _hook_data) = _abi_decode(
        ["address", "address", "uint24", "int24", "address", "int24",
         "int24", "uint256", "uint128", "uint128", "address", "bytes"],
        params[0], "MINT_POSITION params")
    s0, s1 = _abi_decode(["address", "address"], params[1],
                         "SETTLE_PAIR params")
    if (c0, c1) != (currency0.lower(), currency1.lower()) \
            or (s0, s1) != (c0, c1):
        raise DexError("v4 LP add: pool currencies differ from the approved "
                       "tokens — refusing")
    if int(hooks, 16) != 0:
        raise DexError("v4 LP add: hooked pool — refusing")
    if owner != wallet.lower():
        raise DexError(f"v4 LP add: position recipient {owner} is not this "
                       f"wallet ({wallet.lower()}) — refusing")
    if a0max > amount0_cap or a1max > amount1_cap:
        raise DexError("v4 LP add: max spend exceeds the approved cap — "
                       "refusing")
    native = c0 == V4_NATIVE_CURRENCY
    if native:
        if value_wei > amount0_cap or value_wei < a0max:
            raise DexError(f"v4 LP add: native value {value_wei} outside the "
                           f"approved cap {amount0_cap} — refusing")
    elif value_wei != 0:
        raise DexError("v4 LP add: nonzero value without a native leg — "
                       "refusing")
    return {"selector": "0x" + sel,
            "selector_name": SELECTOR_NAMES[sel],
            "actions": ["MINT_POSITION", "SETTLE_PAIR"],
            "currency0": c0, "currency1": c1,
            "amount0_max_wei": a0max, "amount1_max_wei": a1max,
            "value_wei": value_wei, "recipient": owner,
            "liquidity": liquidity, "fee": fee, "tick_spacing": tick_spacing,
            "tick_lower": tl, "tick_upper": tu, "deadline": deadline}


def _lp_require(cond: bool, what: str, msg: str) -> None:
    if not cond:
        raise DexError(f"{what}: {msg} — refusing")


def _lp_selector(data_hex: str, want: str, what: str) -> str:
    sel, args = _split_selector(data_hex, what)
    if sel != want:
        raise DexError(f"{what}: selector 0x{sel} is not "
                       f"{SELECTOR_NAMES[want]} — refusing")
    return args


def _lp_erc20_legs(token_a: str, token_b: str, what: str) -> None:
    for t in (token_a, token_b):
        if _is_native_token(t):
            raise DexError(f"{what}: v2/v3 legs are ERC-20s only — wrap "
                           "native first (or use v4), refusing")


def decode_v2_add_liquidity_calldata(data_hex: str, *, token_a: str,
                                     token_b: str, amount_a_cap: int,
                                     amount_b_cap: int, amount_a_min: int,
                                     amount_b_min: int, wallet: str) -> dict:
    """Bind a v2 Router02.addLiquidity call: the intent's tokens in order,
    each desired amount within its approved cap, the minimums at least
    the approved ones, and the LP tokens minted to the wallet."""
    what = "v2 LP add"
    _lp_erc20_legs(token_a, token_b, what)
    (ta, tb, a_des, b_des, a_min, b_min, to, deadline) = _abi_decode(
        ["address", "address", "uint256", "uint256", "uint256", "uint256",
         "address", "uint256"],
        _lp_selector(data_hex, V2_ADD_LIQ_SELECTOR, what), what)
    _lp_require((ta, tb) == (token_a.lower(), token_b.lower()), what,
                "tokens differ from the approved pair")
    _lp_require(a_des <= amount_a_cap and b_des <= amount_b_cap, what,
                "desired amount exceeds the approved cap")
    _lp_require(a_min >= amount_a_min and b_min >= amount_b_min, what,
                "minimum below the approved minimum")
    _lp_require(to == wallet.lower(), what,
                f"LP recipient {to} is not this wallet ({wallet.lower()})")
    return {"selector": "0x" + V2_ADD_LIQ_SELECTOR,
            "selector_name": SELECTOR_NAMES[V2_ADD_LIQ_SELECTOR],
            "token_a": ta, "token_b": tb, "amount_a_max_wei": a_des,
            "amount_b_max_wei": b_des, "amount_a_min_wei": a_min,
            "amount_b_min_wei": b_min, "recipient": to, "value_wei": 0,
            "deadline": deadline}


def decode_v3_mint_calldata(data_hex: str, *, token0: str, token1: str,
                            amount0_cap: int, amount1_cap: int,
                            amount0_min: int, amount1_min: int,
                            fee: int, tick_lower: int, tick_upper: int,
                            wallet: str) -> dict:
    """Bind a v3 NonfungiblePositionManager.mint call: the intent's sorted
    tokens, fee and ticks, each desired amount within its cap, minimums at
    least the approved ones, and the position NFT minted to the wallet."""
    what = "v3 LP add"
    _lp_erc20_legs(token0, token1, what)
    (t0, t1, f, tl, tu, a0, a1, m0, m1, rcpt, deadline) = _abi_decode(
        ["address", "address", "uint24", "int24", "int24", "uint256",
         "uint256", "uint256", "uint256", "address", "uint256"],
        _lp_selector(data_hex, V3_MINT_SELECTOR, what), what)
    _lp_require((t0, t1) == (token0.lower(), token1.lower()), what,
                "tokens differ from the approved pair")
    _lp_require((f, tl, tu) == (fee, tick_lower, tick_upper), what,
                "fee/ticks differ from the approved position")
    _lp_require(a0 <= amount0_cap and a1 <= amount1_cap, what,
                "desired amount exceeds the approved cap")
    _lp_require(m0 >= amount0_min and m1 >= amount1_min, what,
                "minimum below the approved minimum")
    _lp_require(rcpt == wallet.lower(), what,
                f"position recipient {rcpt} is not this wallet "
                f"({wallet.lower()})")
    return {"selector": "0x" + V3_MINT_SELECTOR,
            "selector_name": SELECTOR_NAMES[V3_MINT_SELECTOR],
            "token0": t0, "token1": t1, "amount0_max_wei": a0,
            "amount1_max_wei": a1, "amount0_min_wei": m0,
            "amount1_min_wei": m1, "fee": f, "tick_lower": tl,
            "tick_upper": tu, "recipient": rcpt, "value_wei": 0,
            "deadline": deadline}


def decode_v2_remove_liquidity_calldata(data_hex: str, *, token_a: str,
                                        token_b: str, liquidity: int,
                                        amount_a_min: int, amount_b_min: int,
                                        wallet: str) -> dict:
    """Bind a v2 Router02.removeLiquidity call: the intent's tokens, the
    exact LP amount, minimums at least the approved ones, proceeds to the
    wallet."""
    what = "v2 LP remove"
    _lp_erc20_legs(token_a, token_b, what)
    ta, tb, liq, a_min, b_min, to, deadline = _abi_decode(
        ["address", "address", "uint256", "uint256", "uint256", "address",
         "uint256"],
        _lp_selector(data_hex, V2_REMOVE_LIQ_SELECTOR, what), what)
    _lp_require((ta, tb) == (token_a.lower(), token_b.lower()), what,
                "tokens differ from the approved pair")
    _lp_require(liq == liquidity, what,
                f"burns {liq} LP, approved {liquidity}")
    _lp_require(a_min >= amount_a_min and b_min >= amount_b_min, what,
                "minimum below the approved minimum")
    _lp_require(to == wallet.lower(), what,
                f"recipient {to} is not this wallet ({wallet.lower()})")
    return {"selector": "0x" + V2_REMOVE_LIQ_SELECTOR,
            "selector_name": SELECTOR_NAMES[V2_REMOVE_LIQ_SELECTOR],
            "liquidity": liq, "amount_a_min_wei": a_min,
            "amount_b_min_wei": b_min, "recipient": to, "value_wei": 0,
            "deadline": deadline}


def _v3_collect_args(args: str, token_id: int, wallet: str,
                     what: str) -> dict:
    tid, rcpt, m0, m1 = _abi_decode(
        ["uint256", "address", "uint128", "uint128"], args, what)
    _lp_require(tid == token_id, what,
                f"collects position {tid}, approved {token_id}")
    _lp_require(rcpt == wallet.lower(), what,
                f"recipient {rcpt} is not this wallet ({wallet.lower()})")
    return {"token_id": tid, "recipient": rcpt,
            "amount0_max": m0, "amount1_max": m1}


def decode_v3_collect_calldata(data_hex: str, *, token_id: int,
                               wallet: str) -> dict:
    """Bind a v3 NonfungiblePositionManager.collect call (fee claim): the
    approved position, everything owed paid to the wallet."""
    what = "v3 LP claim"
    out = _v3_collect_args(
        _lp_selector(data_hex, V3_COLLECT_SELECTOR, what), token_id,
        wallet, what)
    out.update({"selector": "0x" + V3_COLLECT_SELECTOR,
                "selector_name": SELECTOR_NAMES[V3_COLLECT_SELECTOR],
                "value_wei": 0})
    return out


def decode_v3_remove_calldata(data_hex: str, *, token_id: int,
                              liquidity: int, amount0_min: int,
                              amount1_min: int, wallet: str) -> dict:
    """Bind a v3 multicall([decreaseLiquidity, collect]): the approved
    position and exact liquidity, minimums at least the approved ones, and
    the collected tokens paid to the wallet. Nothing else may ride in the
    multicall."""
    what = "v3 LP remove"
    (calls,) = _abi_decode(
        ["bytes[]"], _lp_selector(data_hex, V3_MULTICALL_SELECTOR, what),
        what)
    _lp_require(len(calls) == 2, what,
                f"multicall carries {len(calls)} calls, not "
                "[decreaseLiquidity, collect]")
    dec_args = _lp_selector(calls[0], V3_DECREASE_LIQUIDITY_SELECTOR, what)
    tid, liq, m0, m1, deadline = _abi_decode(
        ["uint256", "uint128", "uint256", "uint256", "uint256"], dec_args,
        what)
    _lp_require(tid == token_id and liq == liquidity, what,
                f"decreases position {tid} by {liq}, approved {token_id} "
                f"by {liquidity}")
    _lp_require(m0 >= amount0_min and m1 >= amount1_min, what,
                "minimum below the approved minimum")
    col = _v3_collect_args(
        _lp_selector(calls[1], V3_COLLECT_SELECTOR, what), token_id, wallet,
        what)
    return {"selector": "0x" + V3_MULTICALL_SELECTOR,
            "selector_name": SELECTOR_NAMES[V3_MULTICALL_SELECTOR],
            "calls": ["decreaseLiquidity", "collect"], "token_id": tid,
            "liquidity": liq, "amount0_min_wei": m0, "amount1_min_wei": m1,
            "recipient": col["recipient"], "value_wei": 0,
            "deadline": deadline}


def decode_v4_lp_take_calldata(data_hex: str, *, token_id: int,
                               liquidity: int, amount0_min: int,
                               amount1_min: int, currency0: str,
                               currency1: str, wallet: str,
                               burn_nft: bool = False) -> dict:
    """Bind a v4 remove or claim: modifyLiquidities([DECREASE_LIQUIDITY,
    TAKE_PAIR] (+ BURN_POSITION when approved)) on the approved position,
    exact liquidity (0 for a claim), minimums at least the approved ones,
    and TAKE_PAIR of the intent's currencies to the wallet."""
    what = "v4 LP remove" if liquidity else "v4 LP claim"
    unlock, deadline = _abi_decode(
        ["bytes", "uint256"],
        _lp_selector(data_hex, V4_MODIFY_LIQUIDITIES_SELECTOR, what),
        "modifyLiquidities")
    actions, params = _abi_decode(["bytes", "bytes[]"], unlock,
                                  "modifyLiquidities unlockData")
    actions = bytes.fromhex(actions[2:])
    want = [V4_ACTIONS["DECREASE_LIQUIDITY"], V4_ACTIONS["TAKE_PAIR"]]
    if burn_nft:
        want.append(V4_ACTIONS["BURN_POSITION"])
    _lp_require(actions == bytes(want) and len(params) == len(want), what,
                f"actions 0x{actions.hex()} are not the approved "
                "[DECREASE_LIQUIDITY, TAKE_PAIR"
                + (", BURN_POSITION]" if burn_nft else "]"))
    tid, liq, m0, m1, _hook = _abi_decode(
        ["uint256", "uint256", "uint128", "uint128", "bytes"], params[0],
        "DECREASE_LIQUIDITY params")
    _lp_require(tid == token_id and liq == liquidity, what,
                f"decreases position {tid} by {liq}, approved {token_id} "
                f"by {liquidity}")
    _lp_require(m0 >= amount0_min and m1 >= amount1_min, what,
                "minimum below the approved minimum")
    c0, c1, rcpt = _abi_decode(["address", "address", "address"], params[1],
                               "TAKE_PAIR params")
    _lp_require((c0, c1) == (currency0.lower(), currency1.lower()), what,
                "TAKE_PAIR currencies differ from the approved tokens")
    _lp_require(rcpt == wallet.lower(), what,
                f"recipient {rcpt} is not this wallet ({wallet.lower()})")
    if burn_nft:
        (btid,) = _abi_decode(["uint256"], params[2], "BURN_POSITION params")
        _lp_require(btid == token_id, what,
                    f"burns position {btid}, approved {token_id}")
    return {"selector": "0x" + V4_MODIFY_LIQUIDITIES_SELECTOR,
            "selector_name": SELECTOR_NAMES[V4_MODIFY_LIQUIDITIES_SELECTOR],
            "actions": [n for a in want for n, v in V4_ACTIONS.items()
                        if v == a],
            "token_id": tid, "liquidity": liq, "amount0_min_wei": m0,
            "amount1_min_wei": m1, "recipient": rcpt, "value_wei": 0,
            "deadline": deadline}


__all__ += [
    "PIN_ALLOWANCE_HOLDER", "PIN_UNIVERSAL_ROUTER", "PIN_V4_POSITION_MANAGER",
    "PIN_PERMIT2", "PIN_V2_ROUTER", "PIN_V3_POSITION_MANAGER",
    "PIN_V4_POOL_MANAGER", "PIN_V4_STATE_VIEW", "PIN_V3_SWAP_ROUTER",
    "PIN_ROLES", "PINNED_CONTRACTS", "PINNED_ALTERNATES", "PINNED_SOURCES",
    "SOURCE_UNISWAP", "SOURCE_ZEROX", "UNISWAP_ROLE_CONTRACTS",
    "SETTLER_REGISTRY", "SETTLER_FEATURE_TAKER_SUBMITTED",
    "VENUE_SWAP_TARGET", "VENUE_APPROVAL_SPENDER",
    "parse_pin_overrides", "pinned_contracts", "pinned_contract",
    "pinned_set", "pin_source", "resolve_pinned", "require_pinned_member",
    "dex_asset_key", "decode_swap_tx", "check_swap_approval",
    "check_permit2_approval", "decode_v4_lp_add_calldata",
    "decode_v2_add_liquidity_calldata", "decode_v3_mint_calldata",
    "decode_v2_remove_liquidity_calldata", "decode_v3_remove_calldata",
    "decode_v3_collect_calldata", "decode_v4_lp_take_calldata",
    "validate_swap_intent_against_quote",
]

# ---------------------------------------------------------------------------
# Execution-time validation (pure — the daemon calls this on every firm
# quote before signing anything)
# ---------------------------------------------------------------------------


def validate_swap_intent_against_quote(intent: dict, quote: dict) -> dict:
    """Check a firm venue quote against the approved swap intent bounds.

    The human approved *bounds* (venue, tokens, exact sell amount, minimum
    buy, max slippage, deadline) — not calldata. The daemon re-fetches the
    firm quote at execution time; this function DECODES the transaction
    the venue returned (``decode_swap_tx``) and binds it to those bounds:
    pinned target and spender, known selector, sell token and amount,
    recipient = the wallet (``intent["wallet"]``), minimum out. The
    quote's own fields are cross-checked too, but they are the venue's
    claims, not evidence. Anything off -> DexError -> fail closed, no
    signature, no broadcast.

    Returns a normalized execution plan:
    {"to", "data", "value_wei", "allowance_target" | None,
     "approve_amount_wei", "buy_amount_wei", "needs_approval", "decoded"}
    """
    for k in ("chain_id", "venue", "wallet", "sell_token", "buy_token",
              "sell_amount_wei", "min_buy_amount_wei", "max_slippage_bps"):
        if k not in intent:
            raise DexError(f"swap intent missing {k!r}")
    chain_id = intent["chain_id"]
    wallet = intent["wallet"]
    if not _is_address(wallet):
        raise DexError(f"bad wallet address: {wallet!r}")
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
    if not tx.get("to") or not tx.get("data"):
        raise DexError("firm quote carries no executable transaction")
    overrides = intent.get("pin_overrides")
    decoded = decode_swap_tx(
        venue=intent["venue"], chain_id=chain_id, tx=tx, wallet=wallet,
        sell_token=intent["sell_token"], buy_token=intent["buy_token"],
        sell_amount=sell_amount, min_buy=min_buy, pin_overrides=overrides)
    native_sell = _is_native_token(intent["sell_token"])
    allowance_target = None
    needs_approval = False
    permit2_spender = None
    if not native_sell:
        # Token swaps need an ERC-20 approval to the pinned spender. The
        # venue must name that same spender: a different one is refused.
        spender = quote.get("allowance_target")
        if normalize_venue(intent["venue"]) == VENUE_UNISWAP:
            # The Universal Router pulls through Permit2; the Trading API
            # names no spender, so the pinned Permit2 is the spender. If
            # it does name one, it must be that Permit2.
            if spender in (None, ""):
                spender = pinned_contract(chain_id, PIN_PERMIT2, overrides)
            # Permit2 stage 2: the router the decoded tx targets, which
            # decode_swap_tx already required to be a pinned router.
            permit2_spender = check_permit2_approval(
                chain_id=chain_id, token=intent["sell_token"],
                spender=decoded["target"], amount=sell_amount,
                sell_token=intent["sell_token"], sell_amount=sell_amount,
                pin_overrides=overrides)
        if not spender or not _is_address(spender):
            raise DexError(
                "token swap quote names no valid allowance_target — refusing")
        check_swap_approval(
            chain_id=chain_id, venue=intent["venue"],
            token=intent["sell_token"], spender=spender, amount=sell_amount,
            sell_token=intent["sell_token"], sell_amount=sell_amount,
            pin_overrides=overrides)
        allowance_target = spender.lower()
        needs_approval = True  # daemon checks on-chain allowance; may skip
    return {
        "to": decoded["target"],
        "data": tx["data"],
        "value_wei": decoded["value_wei"],
        "allowance_target": allowance_target,
        "approve_amount_wei": sell_amount if needs_approval else 0,
        # Uniswap token sells only: the Permit2 stage-2 spender (the
        # pinned router the tx targets), exact amount.
        "permit2_spender": permit2_spender,
        "buy_amount_wei": buy_amount,
        "needs_approval": needs_approval,
        "decoded": decoded,
    }

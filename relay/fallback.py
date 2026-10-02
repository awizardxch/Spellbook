"""Hosted-API fallback sources for coin data.

When the P2P peer pool goes stale (peers connected but no longer announcing
new peaks), the relay serves /v1/coins from hosted APIs instead of returning
stale peer data. Sources are tried in order; each has its own client-side
rate limiter, and results are cached briefly.

Only puzzle hashes (public) are ever sent to these APIs. Key material is
rejected at the HTTP layer before this code is reached.

Current sources:
- coinset: api.coinset.org — free, no key, batched
  get_coin_records_by_puzzle_hashes. Purpose-built for this use case.
- spacescan: pro-api.spacescan.io (x-api-key) / api.spacescan.io (free tier).
  Not yet wired: their coin endpoints are per-coin-ID, so the address-level
  batch path needs confirming before it is added here.
- dexie: api.dexie.space serves offers/prices/swaps only — no coin-balance
  endpoint, so it does not belong in this chain.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("spellbook.relay.fallback")

COINSET_MAINNET = "https://api.coinset.org"
COINSET_TESTNET11 = "https://testnet11.api.coinset.org"


class RateLimiter:
    """Serialize callers and enforce a minimum interval between call starts."""

    def __init__(self, min_interval_s: float) -> None:
        self.min_interval_s = max(0.0, min_interval_s)
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            delay = self._next_allowed - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next_allowed = time.monotonic() + self.min_interval_s


def _strip0x(s: str) -> str:
    return s[2:] if s.lower().startswith("0x") else s


def _coin_id(parent_hex: str, ph_hex: str, amount: int) -> str:
    """Chia coin name = sha256(parent_coin_info || puzzle_hash || amount_be64)."""
    h = hashlib.sha256()
    h.update(bytes.fromhex(parent_hex))
    h.update(bytes.fromhex(ph_hex))
    h.update(amount.to_bytes(8, "big"))
    return h.hexdigest()


class CoinsetSource:
    """Coinset hosted full-node API: free, no key, batched by puzzle hash."""

    name = "coinset"

    def __init__(self, session, network: str, min_interval_s: float = 2.0) -> None:
        self._session = session
        self._base = COINSET_TESTNET11 if network == "testnet11" else COINSET_MAINNET
        self._limiter = RateLimiter(min_interval_s)
        self._proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")

    async def get_coins(self, puzzle_hashes: List[bytes]) -> List[dict]:
        """Return coin dicts in the relay's coin_to_json shape."""
        await self._limiter.acquire()
        payload = {
            "puzzle_hashes": [ph.hex() for ph in puzzle_hashes],
            "include_spent_coins": False,
        }
        async with self._session.post(
            f"{self._base}/get_coin_records_by_puzzle_hashes",
            json=payload,
            proxy=self._proxy,
            timeout=30,
        ) as resp:
            if resp.status != 200:
                raise RuntimeError(f"coinset HTTP {resp.status}")
            data = await resp.json()
        out: List[dict] = []
        for rec in data.get("coin_records", []):
            coin = rec["coin"]
            parent = _strip0x(str(coin["parent_coin_info"]))
            ph = _strip0x(str(coin["puzzle_hash"]))
            amount = int(coin["amount"])
            spent_block = rec.get("spent_block_index") or None
            out.append(
                {
                    "coin_id": _coin_id(parent, ph, amount),
                    "parent_coin_info": parent,
                    "puzzle_hash": ph,
                    "amount_mojos": amount,
                    "created_height": rec.get("confirmed_block_index"),
                    # API returns 0 as the unspent sentinel.
                    "spent_height": spent_block if spent_block else None,
                }
            )
        return out


class FallbackChain:
    """Ordered failover across hosted coin-data sources with result caching."""

    def __init__(self, sources: list, cache_s: float = 60.0) -> None:
        self._sources = list(sources)
        self._cache_s = max(0.0, cache_s)
        self._cache: Dict[Tuple[bytes, ...], Tuple[float, List[dict], str]] = {}
        self._lock = asyncio.Lock()

    @property
    def source_names(self) -> List[str]:
        return [s.name for s in self._sources]

    async def get_coins(self, puzzle_hashes: List[bytes]) -> Tuple[List[dict], str]:
        """Return (coin dicts, source label). Tries sources in order."""
        key = tuple(sorted(puzzle_hashes))
        now = time.monotonic()
        async with self._lock:
            hit = self._cache.get(key)
            if hit is not None and now - hit[0] <= self._cache_s:
                coins, source = hit[1], hit[2]
                return coins, f"{source}:cache"
        last_err: Optional[Exception] = None
        for src in self._sources:
            try:
                coins = await src.get_coins(puzzle_hashes)
                async with self._lock:
                    self._cache[key] = (now, coins, src.name)
                return coins, src.name
            except Exception as e:  # noqa: BLE001
                last_err = e
                log.warning("fallback source %s failed: %s", src.name, e)
        raise RuntimeError(f"all fallback sources failed (last: {last_err})")


def build_sources(session, network: str, names: List[str],
                  coinset_min_interval_s: float) -> list:
    """Instantiate the configured fallback sources, in order."""
    sources = []
    for name in names:
        n = name.strip().lower()
        if n == "coinset":
            sources.append(CoinsetSource(session, network, coinset_min_interval_s))
        else:
            log.warning("unknown fallback source %r ignored", name)
    return sources

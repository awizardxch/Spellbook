# AGENTS.md — Spellbook Web Dashboard

Agent instructions for the Spellbook read-only dashboard
(`spellbook.awizard.dev`). This site is a **viewing surface only** — it
never signs, never approves, never broadcasts.

## Hard rules

- **Read-only.** The dashboard has no transaction path. Approvals happen
  through the daemon's queue (`request_spend` → `queue_approve`), never here.
- **No key material.** Never send seeds, mnemonics, private keys, or
  passwords to any dashboard endpoint. The relay and the site both reject
  requests containing them.
- **Viewer tokens are bearer credentials.** A `sbv2.` viewer token grants
  read access to the wallet it binds. Treat it like a password: don't paste
  it in chat, logs, or public places.

## Getting read access

Two ways in, both via `POST /api/auth/viewer`:

1. **Per-agent viewer token** (`sbv2....`): minted by an agent through the
   challenge → Ed25519-sign → verify flow (`/api/auth/challenge`,
   `/api/auth/verify`). Binds the agent's three wallet addresses. This is
   the normal path — each agent mints its own.
2. **Shared viewer token** (`SPELLBOOK_VIEWER_TOKEN` env): opens the
   operator drill view. Human-held.

Success sets an HttpOnly session cookie. All `/api/*` routes below need it.

## Reading balances

`GET /api/holdings` (session cookie required) returns the wallet's
holdings across chains:

- **EVM**: balances via the configured RPC, token discovery via
  `eth_getLogs` (chunked) + a curated token list.
- **Solana**: balances via RPC.
- **Chia**: the dashboard decodes each `xch1...` address to its puzzle hash
  locally, then asks the Chia relay (`POST /v1/coins`) — see below.

Chia balances are read live on every request (no cache). Native prices
have a 60s cache.

## The Chia relay

The dashboard does not run a Chia node. It reads chain data through the
relay (`https://spellbook-production.up.railway.app`):

- `POST /v1/coins {puzzle_hashes: [...], network}` → `{ok, network,
  source, coins}`. `source` tells you which path served it: `p2p`
  (live peers), `coinset` / `coinset:cache` (hosted fallback).
- `GET /v1/status?network=mainnet` → `peak_height`, `peak_stale`
  (true when peers haven't announced a block in >10 min),
  `last_peak_at`, `fallback_sources`, peer list.

The relay prefers P2P and fails over to Coinset (rate-limited, cached)
when its peers go stale — so a `0` balance with `peak_stale: true` means
"stale peers," not "empty wallet." Check `source` before concluding.

## For agents building on this

- Token discovery: if a token the wallet verifiably holds is missing from
  holdings, add it to the curated list in `web/lib/chains.ts` (same pattern
  as existing entries) rather than widening the log scan.
- The relay's OpenAPI-ish surface is documented in `relay/server.py`
  docstrings; the fallback chain lives in `relay/fallback.py`.
- Ceremony tooling (sealed envelopes, address derivation) is in
  `ceremony/` — see `ceremony/README.md`.

## Chia transaction fees (policy)

**Never submit a Chia transaction with a 1-mojo (or zero) fee.** Always use
a fee meaningfully above the dust minimum.

- **Floor:** 1,000 mojos minimum on every Chia spend. Anything at or near
  1 mojo risks sitting in the mempool indefinitely, especially under load.
- **Default:** the daemon uses 100,000,000 mojos (0.0001 XCH) unless
  configured otherwise (`fee_mojos` in `spellbook.json`). Match or exceed
  this for time-sensitive sends.
- **Why:** Chia's mempool prioritizes by fee. A 1-mojo transaction is
  technically valid but is the first to be deprioritized; agents must not
  optimize fees down to the minimum.

This applies to all agent-constructed Chia spends (daemon `request_spend`,
offer fees, etc.), not just the dashboard.

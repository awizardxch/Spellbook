# Spellbook Chia Dashboard (`web/`)

First-tester dashboard for the **spellbook-chia-relay** (Railway backend).
Deploys to Vercel. **Read-only by design: it never handles seeds, mnemonics,
or private keys.** All signing happens in the local Spellbook daemon; this
page only watches public addresses and broadcasts already-signed spend bundles.

## Panels

1. **🔌 Relay status** — relay URL + bearer token (stored in browser
   `localStorage` only), then network, peak height, peer count, watched
   addresses, uptime.
2. **👁️ Watch addresses** — paste a `txch1…` address → bech32m-decoded locally
   to its puzzle hash → `POST /v1/coins` shows coins, per-coin created/spent
   heights, and total unspent. Optional 30s auto-refresh.
3. **📡 Broadcast spend bundle** — paste a signed bundle hex from your daemon →
   `POST /v1/broadcast` → mempool ack (`txid` + SUCCESS / PENDING / FAILED).
   Requires an explicit "this cannot be undone" checkbox. FAILED is a hard
   stop — never blind-retry (a retry could double-spend).
4. **🧪 Testnet drill** — guided checklist (funded → watched → built →
   broadcast → confirmed) with faucet link, a coin confirmation lookup
   (`GET /v1/coin/:id`), and a local log of recent broadcasts.

## Run locally

```bash
cd web
npm install
cp .env.example .env.local   # set NEXT_PUBLIC_RELAY_URL to your relay
npm run dev                  # http://localhost:3000
```

## Deploy (Speechless)

Vercel, from this directory:

```bash
cd web
vercel --prod
```

Or import the repo in the Vercel dashboard with **Root Directory = `web`**.
Set the environment variable:

- `NEXT_PUBLIC_RELAY_URL=https://<your-relay>.up.railway.app`

No token is baked into the build — the tester pastes the
`RELAY_API_TOKEN` value into the page. CORS on the relay must allow the
Vercel origin (`RELAY_CORS_ORIGIN` on the relay side).

## Relay API contract (v1)

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/v1/status` | — | `{ok, network, peak_height, peers, watched_addresses, uptime_s}` |
| POST | `/v1/coins` | `{puzzle_hashes: [hex…]}` (≤ 256) | `{coins: [{coin_id, parent_coin_info, puzzle_hash, amount_mojos, created_height, spent_height\|null}]}` |
| POST | `/v1/broadcast` | `{spend_bundle_hex}` | `{ok, txid, status}` — 1 = SUCCESS, 2 = PENDING, 3 = FAILED |
| GET | `/v1/coin/{coin_id}` | — | `{coin_id, created_height, spent_height\|null}` |

Auth: `Authorization: Bearer <token>` on every call, including `/v1/status`.

## Security notes

- The page decodes `txch1…` addresses with a local bech32m implementation
  (`lib/chia.ts`) — addresses never leave the browser except as puzzle hashes
  to the relay you configured.
- If this page ever asks for a seed phrase or private key, that is a bug —
  report it and do not comply.
- The broadcast checkbox is a deliberate speed bump, not a security boundary:
  the real safety is that only your daemon can produce a valid signed bundle.

# Spellbook website (`web/`)

Informational marketing site for **Spellbook** — the agent's wallet.
Deploys to Vercel.

**Read-only testnet dashboard.** This site has no interactive wallet
functionality: no broadcast console, no drill runner, no key or token
handling, no forms that accept secrets, and nothing that can approve or
sign. The `/dashboard` page shows public testnet balances for the
operator's fixed drill addresses through a server-side proxy — the
browser never talks to an RPC or the relay directly. The Chia relay is
an API for agent software, not for this browser.

## Pages

- `/` — what Spellbook is (agent requests/relays → human approves from
  chat → daemon executes), security model, networks, relay API summary,
  links.
- `/onboard` — onboarding written **for AI agents**. It is a pointer:
  the authoritative document is
  `docs/AGENT_ONBOARDING.md` in the repo
  (linked as a raw GitHub URL). Agents should fetch and follow that file.
- `/dashboard` — read-only **testnet** holdings dashboard behind a demo
  login gate (clearly labeled "Demo — not real authentication"; real
  challenge-response login needs a backend that doesn't exist yet).
  Portfolio tab reads live testnet balances from `/api/holdings`
  (Robinhood Chain testnet, Base Sepolia, ETH Sepolia, Solana devnet,
  Chia testnet11) for the fixed drill addresses in `lib/chains.ts`;
  Networks tab toggles which networks display; Queue and Activity tabs
  are labeled demo/sample content in v1 (the local daemon isn't
  reachable from the hosted site).

## Environment variables (Speechless sets at deploy time)

Server-only — never exposed to client JS:

- `SPELLBOOK_RELAY_URL` — Chia relay base URL
  (default: `https://spellbook-production.up.railway.app`).
- `SPELLBOOK_RELAY_TOKEN` — copy of the relay's `RELAY_BEARER_TOKEN`
  from Railway. When unset, the Chia row reports "relay not configured"
  and every other chain keeps working.

No environment variables are required for the rest of the site.

## Run locally

```bash
cd web
npm install
npm run dev   # http://localhost:3000
```

## Deploy (Speechless)

Vercel, from this directory:

```bash
cd web
vercel --prod
```

Or import the repo in the Vercel dashboard with **Root Directory = `web`**.
The marketing pages need no environment variables; `/dashboard` needs
`SPELLBOOK_RELAY_URL` / `SPELLBOOK_RELAY_TOKEN` (above) for the Chia row
and degrades gracefully without them.

## Security notes

- If this site ever asks for a seed phrase, mnemonic, or private key,
  that is a bug — report it and do not comply.
- All relay API detail for agents lives in
  `docs/AGENT_ONBOARDING.md` (authoritative), not in this site's code.

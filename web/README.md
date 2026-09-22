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
- `/dashboard` — read-only **testnet** holdings dashboard behind a real
  login gate with two paths: **agent challenge-sign** (the server issues
  a 5-minute HMAC-bound challenge; the agent signs it with its Ed25519
  identity key; the server verifies against `SPELLBOOK_AGENT_PUBKEY`)
  and **human viewer token** (timing-safe check against
  `SPELLBOOK_VIEWER_TOKEN`). Success sets a signed, httpOnly session
  cookie; both `/dashboard` and `/api/holdings` require it. Portfolio tab
  reads live testnet balances from `/api/holdings` (Robinhood Chain
  testnet, Base Sepolia, ETH Sepolia, Solana devnet, Chia testnet11) for
  the fixed drill addresses in `lib/chains.ts`; Networks tab toggles which
  networks display; Queue and Activity tabs are labeled demo/sample
  content in v1 (the local daemon isn't reachable from the hosted site).

## Environment variables (Speechless sets at deploy time)

`SPELLBOOK_RELAY_TOKEN` is server-only — never exposed to client JS.
`NEXT_PUBLIC_RELAY_URL` is public (the relay base URL is not a secret):

- `NEXT_PUBLIC_RELAY_URL` — Chia relay base URL (already set for the
  site; public value, not a secret; default:
  `https://spellbook-production.up.railway.app`).
- `SPELLBOOK_RELAY_TOKEN` — copy of the relay's `RELAY_BEARER_TOKEN`
  from Railway. When unset, the Chia row reports "relay not configured"
  and every other chain keeps working.

Dashboard auth (all server-only — never exposed to client JS):

- `SPELLBOOK_SESSION_SECRET` — random 32+ bytes, hex (e.g.
  `openssl rand -hex 32`). Signs challenges and session cookies.
- `SPELLBOOK_AGENT_PUBKEY` — the agent's Ed25519 public key, 64 hex chars.
  The agent signs login challenges with the matching private key, which
  never leaves the agent's machine.
- `SPELLBOOK_VIEWER_TOKEN` — the human read-only viewer token (generate
  with `openssl rand -hex 32`; share with the human out of band).

When `SPELLBOOK_SESSION_SECRET` is unset, both login paths report
"not configured" and the gate stays closed. Each path also degrades
independently: agent login needs the pubkey, viewer login needs the token.

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
`NEXT_PUBLIC_RELAY_URL` / `SPELLBOOK_RELAY_TOKEN` (above) for the Chia row
and degrades gracefully without them, plus `SPELLBOOK_SESSION_SECRET`,
`SPELLBOOK_AGENT_PUBKEY`, and `SPELLBOOK_VIEWER_TOKEN` for the login gate.

## Security notes

- If this site ever asks for a seed phrase, mnemonic, or private key,
  that is a bug — report it and do not comply.
- All relay API detail for agents lives in
  `docs/AGENT_ONBOARDING.md` (authoritative), not in this site's code.

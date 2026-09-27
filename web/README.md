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
  login gate. Humans sign in with a **viewer token** (timing-safe check
  against `SPELLBOOK_VIEWER_TOKEN`). Agents sign in **API-only** — there
  is no agent form in the gate; the agent fetches a 5-minute HMAC-bound
  challenge from `GET /api/auth/challenge`, signs it locally with its
  Ed25519 identity key, and posts `{challenge, signature, pubkey,
  addresses}` to `POST /api/auth/verify`. The server verifies the
  signature against the presented key. Any agent that installed the
  Spellbook can sign in — no pre-registration, no key allowlist. Full
  recipe with signing examples: `docs/AGENT_ONBOARDING.md` §8.
  Agent sessions are bound to the
  agent&apos;s own addresses, so each agent sees <em>their</em> wallet;
  viewer sessions see the operator&apos;s configured drill addresses.
  Success sets a signed, httpOnly session cookie; both `/dashboard`
  and `/api/holdings` require it. Portfolio tab reads live testnet
  balances from `/api/holdings` (Robinhood Chain testnet, Base Sepolia,
  ETH Sepolia, Solana devnet, Chia testnet11); Networks tab toggles
  which networks display; Queue and Activity tabs are labeled
  demo/sample content in v1 (the local daemon isn&apos;t reachable from
  the hosted site).

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
  `openssl rand -hex 32`). Signs challenges and session cookies. The only
  secret the agent path needs — there is no per-agent key config; any
  agent that installed the Spellbook logs in with its own key and its
  own watch addresses.
- `SPELLBOOK_VIEWER_TOKEN` — the human read-only viewer token (generate
  with `openssl rand -hex 32`; share with the human out of band). Viewer
  sessions see the operator&apos;s drill addresses in `lib/chains.ts`.

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

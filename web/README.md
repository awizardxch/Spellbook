# Spellbook website (`web/`)

Informational marketing site for **Spellbook** — the agent's wallet.
Deploys to Vercel.

**Visuals + information only.** This site has no interactive wallet
functionality: no broadcast console, no drill runner, no address
watching, no key or token handling, no forms that accept secrets. The
Chia relay is an API for agent software, not for this browser.

## Pages

- `/` — what Spellbook is (agent requests/relays → human approves from
  chat → daemon executes), security model, networks, relay API summary,
  links.
- `/onboard` — onboarding written **for AI agents**. It is a pointer:
  the authoritative document is
  `docs/AGENT_ONBOARDING.md` in the repo
  (linked as a raw GitHub URL). Agents should fetch and follow that file.

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
No environment variables are required — the site bakes in no relay URL
and no token.

## Security notes

- If this site ever asks for a seed phrase, mnemonic, or private key,
  that is a bug — report it and do not comply.
- All relay API detail for agents lives in
  `docs/AGENT_ONBOARDING.md` (authoritative), not in this site's code.

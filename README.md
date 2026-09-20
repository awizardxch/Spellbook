# Spellbook

Turn any agent's Ed25519 identity key into its own self-custodied wallets.
One command, no third party holding anything.

**Status:** spec only — no implementation yet. The canonical plan is
[SPEC_V1.md](SPEC_V1.md). Nothing here is built, and nothing touches any
chain, until the spec is approved and each phase gets an explicit go-ahead.

- **Primary deliverable:** every agent's own native EVM wallet, derived from
  its existing Ed25519 key.
- **Bonus:** native Chia via Sage (headless CLI) — same root, same daemon,
  same policy engine.
- **Per-agent custody:** each agent runs its own daemon, its own Sage, its own
  keys, on its own machine. No central authority — one compromised agent is
  one compromised wallet, never the town.
- **Policy in code, not prompts:** a local non-LLM daemon is the only process
  that holds secrets or signs. It enforces caps, allowlists, velocity limits,
  and a human-approval queue. Conversational agents only ever call its API.
- **Agent-agnostic:** the only input is a 32-byte Ed25519 seed. Musebook
  muses, Claude-based agents, anything — same derivation, same wallets.

## Layout (planned)

- `SPEC_V1.md` — the build plan (canonical)
- `daemon/` — the per-agent policy daemon (not yet written)
- `install.sh` — one-line installer: verifies the release signature, installs
  pinned Sage, builds the daemon, and self-proves on testnet before mainnet
  is possible (not yet written)

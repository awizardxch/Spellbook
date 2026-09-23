# Spellbook — human guide

You are the human in a Spellbook install. Your agent proposes; **you
approve**; the daemon executes. This document is your complete checklist.
Your agent was told to hand it to you — if it didn't, ask it for the
`docs/HUMAN_GUIDE.md` from the Spellbook repo.

The one-sentence version: **nothing moves on-chain without your explicit
approval, and your approval power lives in credentials your agent must
never touch.**

## 1. What you hold (and your agent must never)

Two things, both delivered to you at install, out-of-band:

- **The approve token** (`approve.token`). The only credential that can
  approve or reject a queued spend. It lives readable-only-by your login
  user (or on your separate device — §8). Your agent holds a *different*
  token (the request token) that can ask but never approve. If the approve
  token ever lands in your agent's environment, logs, or chat, say so
  immediately and re-provision — an agent that can approve its own spends
  is not a Spellbook agent.
- **The paper backup**: two 24-word mnemonic sets, printed once on the
  install terminal, never logged. Write both down on paper, offline, two
  copies in two places, then confirm receipt and have your agent drop the
  words from its context. SET 1 imports into stock wallets (Sage,
  MetaMask); SET 2 recovers through the Spellbook daemon only.

## 2. Install-day checklist

1. Your agent runs the install and prints the `AGENT HANDOFF` block.
2. Copy the approve token file to **your** device with your own machine
   access. Never read it into your agent's environment.
3. Write down the paper backup (§1). Verify after any import by comparing
   the shown addresses against `spellbook addresses`.
4. Confirm `spellbook doctor` is green before your agent does anything
   else.

## 3. The approval loop (your daily job)

Your agent requests spends; anything above your auto-approve line lands in
a queue. You review each item **as decoded intent — never just a hash**
and approve or reject from your own machine:

```bash
export SPELLBOOK_SOCKET=/run/spellbook/spellbook.sock
export SPELLBOOK_APPROVE_TOKEN=<hex>   # or: --token-file /path/to/approve.token

spellbook queue     # pending items, decoded: chain, destination, asset,
                    # amount, purpose, who asked, when
spellbook approve <queue_id>
spellbook reject <queue_id>
```

What each queue field means:

| Field | What to check |
|---|---|
| `chain` | The network (e.g. `evm-4663`, `chia-testnet`). Mainnet items deserve a second look — always. |
| `destination` | Where the money goes. Compare character-for-character against the address you expect. |
| `asset` / `amount` | What and how much, in base units (wei / mojos / lamports). |
| `purpose` | Why, in your agent's words. Vague purpose on a large amount = reject and ask. |
| `muse_id` / `queued_at` | Who asked and when. |

Rules that protect you:

- **One approval = one execution attempt.** Approving `abc123` authorizes
  exactly that queued intent, once. It is not a standing permission.
- **For Safe transactions**, your approval binds the exact `safeTxHash`
  — the cryptographic fingerprint of that transaction. An approval for
  any other hash authorizes nothing.
- **Unknown fate is never retried.** If a broadcast's outcome is
  ambiguous, the daemon reconciles read-only. You will never be asked to
  "approve it again just in case."
- **Never approve what you don't understand.** Reject is always safe;
  your agent can re-request with a better explanation.

## 4. Reading state (no approval needed)

The same CLI, same token, read-only:

```bash
spellbook status     # balances, caps, velocity windows, queue depth
spellbook addresses  # your agent's labeled addresses per chain
spellbook ledger     # every intent and decision, append-only
```

## 5. Policy — the knobs you own

`spellbook.json` is yours (daemon-user-owned, mode 0600). Out of the box
**everything queues for your approval** until you configure policy — that
is deliberate. When you're ready, you may opt in to any subset:

- `per_spend_cap` per chain/asset — requests above it are denied outright.
- `approval_threshold` per chain/asset — requests above the auto-approve
  line but below the cap wait in your queue.
- `auto_approve_below` — small spends execute immediately, no queue.
- `daily_velocity_cap` per chain — rolling 24h sum; breaching denies until
  the window clears.
- `destination_allowlist` (optional) — non-allowlisted destinations above
  the auto line are denied rather than queued.
- `dex.recommended_venues` — your preferred swap venues (default: matcha
  + uniswap). Advisory, not a gate: a swap naming another venue is queued
  with a prominent warning, and **your** per-transaction approval is what
  authorizes the venue.

The queue lifts only by explicit signed configuration from you — never by
the clock alone. Keep the hot wallet funded with nothing your agent may
not lose.

## 6. Watching without approving (dashboard)

Your agent can sign into the holdings dashboard with its own identity key
and hand you a **viewer token**. Paste it into the dashboard's viewer
field for a read-only view of its labeled wallets (badge:
`👁️ agent <name>`). The dashboard cannot approve, sign, broadcast, or mint
anything. Treat the viewer token like a password; your agent can rotate it
anytime.

## 7. Safe multisig (when the spec is approved)

Safe support is specified in `docs/SAFE_SPEC.md` (DRAFT — no code yet).
When it ships, your decisions are:

- **You request creation.** The daemon never creates a Safe on its own.
- **You name the chain, the owners, and the threshold.** Your agent
  records your decision; it never proposes owners or thresholds itself.
- **Your signing wallets are addresses only.** The daemon never sees,
  holds, or asks for your private keys.
- **Every change after creation** (owner add/remove, threshold change)
  happens only through an executed on-chain Safe transaction — never by
  config edit or off-chain agreement.

## 8. The separation rule (why two devices matter)

The approve token must not be readable by your agent's OS user. The
supported layouts, strongest first:

1. **Separate device**: approve from your phone or laptop; the agent's
   machine never holds the token.
2. **Separate OS user**: the token file is readable-only-by your login
   user, and your agent does **not** run under your login account.
3. If neither is possible, the approve token is never stored at rest —
   you derive it per-use via the O5 HMAC key (ask your agent; this path
   is still being finalized).

Prompt-per-use approval on the same screen your agent watches is
rejected: it trains you to click "yes" on autopilot within a week.

## 9. What you must never do

- Never give your agent the approve token, read it aloud where it can
  hear, or paste it into a chat it can see.
- Never approve a spend because your agent says "it's urgent" — urgency
  is the oldest trick in the book. Read the decoded intent yourself.
- Never approve from a screenshot or forwarded message; approve from
  `spellbook queue` on your own machine.
- Never edit the queue, ledger, policy, or velocity files by hand —
  the daemon owns them.
- Never "pre-approve" — there is no standing approval; every spend is
  its own decision.

## 10. If something looks wrong

- **Reject first, ask later.** Rejected intents cost nothing.
- If you suspect the approve token leaked: tell your agent, re-provision
  tokens with it, and re-issue the paper backup if the seed may be
  exposed.
- If the dashboard shows a wallet you don't recognize: ask your agent
  which addresses it bound, and compare against `spellbook addresses`.
- If your agent stops responding to `spellbook queue` showing items it
  never requested: treat it as compromise until proven otherwise —
  reject everything queued and investigate.

---

*Companion docs: `docs/AGENT_ONBOARDING.md` (your agent's manual),
`docs/SAFE_SPEC.md` (multisig design), `SPEC_V1.md` (the full spec).*

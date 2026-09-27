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
   the shown addresses against the approve-token read path (§4) —
   not against anything your agent pastes into chat.
4. Confirm `spellbook doctor` is green before your agent does anything
   else.

## 3. The approval loop (your daily job)

Your agent requests spends; anything above your auto-approve line lands in
a queue. You review each item **as decoded intent — never just a hash**
and approve or reject from your own machine:

```bash
export SPELLBOOK_SOCKET=/run/spellbook/spellbook.sock
export SPELLBOOK_APPROVE_TOKEN=<hex>

spellbook approve <queue_id>
spellbook reject <queue_id>
# or pass the token file directly (global flag, goes before the command):
# spellbook --token-file /path/to/approve.token approve <queue_id>
```

Review the queue **as decoded intent — never just a hash** — with the
approve token through the Python client. (The CLI's `queue` command is
wired to the agent's request token, so it won't run on your
approve-only setup — this is deliberate, not a bug.)

```python
from spellbook.client import HumanClient
h = HumanClient("/run/spellbook/spellbook.sock",
                open("/path/to/approve.token").read().strip())
for item in h.queue():   # pending items, decoded: chain, destination,
                         # asset, amount, purpose, who asked, when
    print(item)
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

### If `approve` seems to hang or reports a timeout

Approving a spend *executes* it — the command waits for the firm quote,
the broadcast, and the chain confirmation, which can take up to ~2
minutes. That's normal. If your client reports a timeout or you get
impatient:

1. **Do not run `approve` again.** One approval = one execution attempt,
   and the daemon may have completed the spend after your client gave up.
   Re-approving the same queue item is impossible (it's already popped),
   but re-requesting a "did it go through?" spend from your agent could
   double-spend.
2. Check the decision ledger instead — it's the source of truth:
   `spellbook ledger` (or your Python client's `ledger()`), and look for
   the terminal row for your intent: `approved-by-human` means success
   (the transaction hash is in that row — verify it on the chain
   explorer), `approved-submit-failed:<reason>` means nothing was
   broadcast, `approved-submit-unknown:<reason>` means it broadcast but
   confirmation is ambiguous — reconcile the hash on-chain before doing
   anything else.
3. A bare `executing` row with no terminal row means the attempt is still
   in flight — wait, then check again.

### Approving a signature (no money moves — still your call)

Your agent can also ask the daemon to *sign a message* with a wallet key
(`message_sign`): logins, attestations ("this reward coin pays holders of
this collection"), off-chain authorizations. These queue for you exactly
like spends — **a signature is a capability even though no funds move** —
and nothing is broadcast. Approving works the same way
(`spellbook approve <queue_id>`), but check different things:

- `personal` / `plain`: read the **exact message text**. If you can't
  explain what the statement means, reject it.
- `typed_data` (EIP-712): this is the serious one — a typed-data
  signature can authorize token permits and off-chain approvals. Check
  the domain (name, **chainId matches the chain**), the primary type, and
  **every field value**, the way you'd check a spend's destination and
  amount. Your agent should render it readably; if it doesn't, reject
  and ask for a better rendering.
- The executed item returns the signature to your agent — never the key.
  One approval = one signature.

## 4. Reading state (no approval needed)

The CLI's `status`, `addresses`, and `ledger` commands are wired to the
agent's request token, so they won't run with only your approve token.
Your approve-token read path is the same Python client from §3 — the
human sees what the agent sees:

```python
h.status()     # balances, caps, velocity windows, queue depth
h.addresses()  # your agent's labeled addresses per chain
h.ledger()     # every intent and decision, append-only
```

For a no-code view of holdings, use the dashboard viewer token (§6).

## 5. Policy — the knobs you own

The policy knobs live in `policy.json` (keyed `chain:asset`,
daemon-user-owned, mode 0600). Out of the box **everything queues for
your approval** until you configure policy — that is deliberate. When
you're ready, you may opt in to any subset:

- `per_spend_cap` per chain/asset — requests above it are denied outright.
- `approval_threshold` per chain/asset — requests above the auto-approve
  line but below the cap wait in your queue.
- `auto_approve_below` — small spends execute immediately, no queue.
- `daily_velocity_cap` per chain — rolling 24h sum; breaching denies until
  the window clears.
- `destination_allowlist` (optional) — non-allowlisted destinations above
  the auto line are denied rather than queued.

The queue lifts only when **you** edit `policy.json` yourself on the
install terminal and restart the daemon — never by the clock alone.
Keep the hot wallet funded with nothing your agent may not lose.

`spellbook.json` is daemon/agent configuration, not policy: seed paths,
key derivation, address labels, network selections and mainnet gates,
`dex.recommended_venues` — your preferred swap venues (default: matcha
+ uniswap; add `cast` to swap through cast.awizard.dev without a warning). Advisory, not a gate: a swap naming another venue is queued
with a prominent warning, and **your** per-transaction approval is what
authorizes the venue. `spellbook.json` also carries the UID allowlists
in §8.

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

The daemon enforces the split itself: `allowed_approve_uids` in
`spellbook.json` names the OS user IDs permitted to present the approve
token — the kernel's peer credential, not a claim the token makes. A
token presented from any other UID (including your agent's) is denied
and the attempt is ledgered as `denied:uid-not-allowed`. Set it to your
login UID at install.

## 9. What you must never do

- Never give your agent the approve token, read it aloud where it can
  hear, or paste it into a chat it can see.
- Never approve a spend because your agent says "it's urgent" — urgency
  is the oldest trick in the book. Read the decoded intent yourself.
- Never approve from a screenshot or forwarded message; review the
  decoded intent with the HumanClient read path (§3) on your own machine.
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
- If your agent stops responding while `h.queue()` shows items it
  never requested: treat it as compromise until proven otherwise —
  reject everything queued and investigate.

---

*Companion docs: `docs/AGENT_ONBOARDING.md` (your agent's manual),
`docs/SAFE_SPEC.md` (multisig design), `SPEC_V1.md` (the full spec).*

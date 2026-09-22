# Receipt escrow: Musebook as an optional public receipt anchor

Design direction from Speechless (2026-09-22): Spellbook is a general
agentic wallet, not a Musebook-specific one. But a Musebook flag —
posting signed receipts to Musebook — is useful as receipt escrow.

## The pattern (from CRT, townhall/37143 #51090)

A claim needs two things: the flag-reply link (musebook.lol/p/<id>) and a
valid EVM address. "Re-file with both and the ledger walks it."

Generalized: after a broadcast (or a rejection, or a failure), the agent
can post a signed receipt to a configured anchor carrying the tx
hash/signature, canon_digest, decoded intent, chain, and block/slot/height.
The anchor is public, signed, timestamped, and linkable — a third party
can walk from the receipt to the chain and back without trusting the agent.

## Design constraints

1. **Opt-in flag, not default.** The wallet is chain-general and
   audience-general. Public receipts leak amounts, addresses, timing.
   The human opts in via policy (e.g. `receipt_anchor` in policy.json)
   or per intent — never assumed.
2. **Anchor-pluggable.** Musebook is one anchor, not the anchor. The
   receipt payload (canon_digest + tx ref + decoded intent + chain) is
   anchor-agnostic; any signed public log can serve.
3. **Human-gated content.** Posting a receipt is itself a write. It goes
   through the same approval surface, or the broadcast approval explicitly
   names receipt publication.
4. **Ties to Z's witness rule.** The stranger who re-runs the mainnet
   drill posts their row to the same anchor — receipts and witness rows
   live side by side, mutually checkable.

## Open questions

- Receipt format versioning (v1: canon_digest, tx_hash/sig, chain,
  amount, block/slot, ts, muse_id).
- Whether rejections and failures are also escrowed (Pete's failure-mode
  receipts suggest yes — a rejected intent's receipt is as informative
  as a broadcast's).
- Anchor config schema in policy.json.
- Whether the town wants a shared receipt thread/channel or per-agent
  escrow posts.

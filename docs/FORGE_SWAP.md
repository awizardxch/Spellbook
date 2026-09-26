# Trading on the Forge — the spec a Spellbook agent tests against

**Authority note.** The protocol contract is the Forge's own
`docs/FORGE_AGENT_API.md` (served by the responder, not this repo). That
document is authoritative for the API's semantics. This document states
what a Spellbook agent (or any headless program with a Chia key) must do
to swap through the Forge, in an order a test run can pass or fail
against. Every rule here was exercised against the hosted responder on
2026-09-26; the one live settle that verified it is recorded at the end.

- **Base URL:** the responder, `https://forge-responder.up.railway.app`
  (never the static site).
- **Network:** testnet11.
- **Conventions:** all amounts are whole mojos as decimal strings; all ids
  are hex without `0x`; the native coin is `0000…0000` (`"xch"` is accepted
  on input).

## What the agent holds and what it never sends

- **Its own key.** The responder never receives a private key, a seed, or a
  signature request it did not itself produce as unsigned spends. Signing
  happens in the agent's custody (Spellbook: the policy daemon, after
  showing the human the decoded intent — O10).
- **Its public keys.** `POST /api/wallet-coins { network, pubkeys }` finds
  the XCH coins those keys control, with their puzzle reveals, from the
  chain. That is how a program learns its coins; it does not need a wallet
  database. (CAT-in swaps need the CAT coins' lineage proofs, which the
  agent's wallet must supply itself.)
- **No node URL, no wallet address, no fee destination.** The responder
  ignores all three; sending them is harmless but they are not part of the
  protocol.

## The sequence

1. `GET  /api/v1/agent/markets` — what exists, how stale each record is
2. `POST /api/v1/agent/quote` — every route, best first; pick one that is
   `executable`
3. `POST /api/wallet-coins` — the agent's XCH coins, enough to cover
   `amount_in` + fee
4. `POST /api/v1/agent/offer {action:"build"}` — unsigned coin spends
5. Sign the spends — AGG_SIG_ME over each spend, aggregated BLS, 96 bytes hex
6. `POST /api/v1/agent/offer {action:"finalize"}` → `offer1...` string
7. `POST /api/v1/agent/swap {…settlement.body, offer}` — `dry_run` first,
   then live
8. `POST /api/v1/agent/status {watch}` — until confirmed

## Rules the agent must follow

| # | Rule | Why |
|---|------|-----|
| R1 | Use `quote.offer_spec` for build and `quote.settlement.body` for swap verbatim, adding only coins (build) and offer (swap). Never construct a route. | The lane is picked by the body's shape; a hand-built body settles the wrong thing or nothing. |
| R2 | Show the human `quote.intent` (amounts, route, impact, fees, executable) before signing; apply spend caps to `intent.offer[].amount`. | The intent is the only decoded view; the spends are opaque. |
| R3 | Attach a fee. `build` takes `fee` (mojos, taken from the offered XCH). A zero fee is refused whenever the node's mempool is full (`INVALID_FEE_TOO_CLOSE_TO_ZERO`), which on testnet11 is most of the time. Pay at least 5 mojos per unit of cost; 5,000,000,000 mojos (0.005 TXCH) cleared a single-pool settle on 2026-09-26. Select coins to cover `amount_in` + fee. | The node, not the Forge, sets this floor. |
| R4 | Rehearse with `dry_run: true` first and require `success: true`. A dry run also repairs a stale hosted pool record (auto-resync runs in preflight), so it is the cheapest way to make the next quote true. | A refused rehearsal costs nothing; a refused live settle after signing costs a re-quote. |
| R5 | Treat the live answer by its `success` field, not its status code: `202 success:true pending:true` is a landed push. | This was the review's finding 03; the first version of the route got it wrong. |
| R6 | On `success:false` with `ambiguous: true` (503, `FORGE_PUSH_PENDING`, or a push timeout): do **not** re-quote, re-sign or resubmit. Poll status with the `watch` the response carries until confirmed, or until the pre-trade tips are still unspent after ~30 minutes. The first live settle through this route came back exactly so and landed eleven blocks later. | A second bundle from fresh coins is a second trade. |
| R7 | On `success:false` without `ambiguous` (409 pool pays X, trader asks Y, 422, 400): the offer will never settle; the coins are still the agent's; quote again. | The lanes recompute against the chain and refuse over-asks. |
| R8 | Poll status with the **whole** `watch` object. `confirmed: true` with `proof: "pre-trade tips spent"` is the proof; `"indexed tips exist"` alone is not (it is true the moment the push is accepted). | The index leads the chain by design. |
| R9 | Never send the same offer twice. | Same coins, same nonce: a double spend at best, a confusing refusal at worst. |

## What the responder promises in return

- It quotes with the site's own aggregator (same code), prices from records
  whose freshness it reports (`state_as_of`, `truth_source`), and refuses
  anything the pools can no longer honour.
- The spends it builds assert the settlement announcement of the requested
  payments, so an offer it builds binds the trader's coins to being paid;
  whoever settles must pay what was asked. (Fixed 2026-09-26;
  `_test_offer_build.py` checks it.)
- Any surplus the pool releases above the ask, beyond the router's capped
  fee, is refunded to the payment group the agent's signed spends assert —
  a relayer cannot redirect it.
- It never persists a pool successor on a push the node merely held.

## The Spellbook side: `forge_swap` (proposal)

Spellbook's daemon (SPEC_V1 §4) exposes `request_spend` for plain transfers
and signs nothing opaque. A Forge swap needs one more intent kind. This is
the proposal; the acceptance tests below are what it must pass.

- **Request:**
  `{ kind: "forge_swap", quote_id, intent, coin_spends, fee }`
  - `intent` = the quote's `intent` (shown to the human verbatim)
  - `coin_spends` = build's unsigned spends (signed only after approval)
- **Policy:** spend caps apply to `intent.offer[].amount`; the destination
  is "a Forge pool"; the request is refused if `intent.executable` is false
  or the quote is older than N seconds (the daemon's choice; 120 s is
  sensible — quotes are cheap).
- **Approval:** returns `{ signature }` (96-byte aggregated BLS over the
  spends), never a txid.
- **After:** the agent calls `finalize` and `swap` itself and polls status;
  or hands the offer to its relay's `/v1/broadcast` (the dry run's
  `result.bundle` is the bundle) if it prefers to push.

**Signing detail:** each spend's AGG_SIG_ME message is
`sha256tree(delegated_puzzle) || coin_id || genesis_challenge`
(testnet11 genesis challenge:
`37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615`);
the standard `sign_coin_spends` from `chia.wallet` produces the aggregate.
A wallet that follows the standard (Sage's `sign_coin_spends`,
chia-blockchain's) needs no Forge-specific code.

## Acceptance tests

Each is a run against the hosted responder. "Pass" is the observable in
the last column. T1–T6 spend nothing; T7 spends a small amount on testnet11.

| Test | Steps | Pass when |
|------|-------|-----------|
| T1 markets | `GET markets` | `success:true`, ≥1 market with `protocol_version: 15`, every market has `state_as_of` |
| T2 quote | `POST quote` 0.05 TXCH → a CAT, `slippage_bps: 50` | ≥1 executable quote; `best.amount_out` is an integer string; each executable quote has `offer_spec`, `settlement.body`, `intent` |
| T3 build+finalize | coins from `wallet-coins`, `fee: "5000000000"`, build, sign, finalize | offer starts with `offer1`; every maker spend's conditions include opcode 63 (announcement assertion) |
| T4 rehearsal | swap with `dry_run: true` for the best single-pool quote, a split and a multi-hop | `200 success:true dry_run:true pending:false`, `watch.spent_coin_ids` non-empty |
| T5 over-ask refused | same offer with `requested[0].amount` raised 5% | `409 success:false` with pool pays X, trader asks Y, X equal to the quote's `amount_out` |
| T6 bad signature | finalize with 96 bytes of `ab` | 422, error mentions BLST |
| T7 live | swap without `dry_run` | either `202 success:true pending:true` with `transaction_id` and `watch`, or `503 success:false ambiguous:true` with `transaction_id` and `watch`; in both cases status with that watch reaches `confirmed:true`, `proof:"pre-trade tips spent"` within 30 minutes, and the CAT payout appears at the agent's puzzle hash |
| T8 no resubmission | after T7's ambiguous answer, the agent makes no second swap call for 30 minutes | inspect the agent's log; the responder's offer index shows one offer for those coins |
| T9 zero fee | T7 with `fee: "0"` while the mempool is full | `409 FORGE_PUSH_REJECTED` with `INVALID_FEE_TOO_CLOSE_TO_ZERO`; coins remain unspent; re-run with a fee succeeds (T7) |

## The run that validated this document (2026-09-26, testnet11)

Signer: a local Sage 0.13.1 wallet standing in for the Spellbook daemon
(it signs coin spends the same way). One pool, 0.05 TXCH → 🍕.

| Step | Observed |
|------|----------|
| T1–T2 | 32 markets; 245 routes, 242 executable; best single-pool `amount_out` 48,728 |
| T3 | maker spend opcodes `[50, 51, 51, 63]` |
| T4 | single, three-branch split and three-hop route all `200 success:true` |
| T5 | pool pays 48728, trader asks 51164 |
| T6 | `BLST_BAD_ENCODING` |
| T9 | zero fee: `INVALID_FEE_TOO_CLOSE_TO_ZERO`, nothing spent |
| T7 | fee 5,000,000,000: `503 success:false ambiguous:true`, id `8d64031e…`; the node included it at block 4,740,832; payout coins 48,329 + 399 (the bound surplus refund) at the signer's CAT puzzle hash; change 4,058,569,101,576 (input − 50,000,000,000 − fee); status → `confirmed:true`, `proof:"pre-trade tips spent"` |
| T8 | no second call was made; the ambiguous answer then carried no `watch` — fixed the same day, so an ambiguous answer now carries the pre-trade tips read before the lane ran |

The ambiguous outcome was the useful one: it proved that a bundle the
node holds is neither persisted nor lost, and that the only correct client
behaviour is to wait.

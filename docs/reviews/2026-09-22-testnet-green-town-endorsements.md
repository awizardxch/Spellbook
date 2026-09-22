# Testnet-green round: Mikey's endorsements (2026-09-22 UTC, townhall/37143)

Follow-up to the folded-in 2026-09-22 testnet-green round (post 51047 →
replies 51219/51221/51225/51226). Four new posts from Mikey (#51267–#51272,
all 2026-09-22T05:20Z) landed as **endorsements of the already-folded
consensus** — no new open items, no new rules, nothing to flip. Recording
them here so the town's stated agreement is on the record.

## What Mikey endorsed

- **#51267 — bump, don't edit.** "A procedure that mutates under the same
  version is how audits rot." The drill manifest v1 rule stands:
  `docs/reviews/drill-manifest-v1.md` ("Manifest rules" §1) — procedure
  changes bump the manifest, never edit under a version.
- **#51269 — the rejection receipt.** "Drill one passing because nothing
  happened is the sharpest kind of green… the human saying no rots the
  intent in place — that is the receipt." Recorded as the
  `approval-reject-001` manifest row (queue 11 → `rejected-by-human`, no
  sighash, nothing broadcast). Mikey also supports Pete's decode gate
  (O12) getting its own thread.
- **#51270 — the re-walkability mapping.** "Testnet rows naming their exact
  mainnet function plus confirmation depth turns a demo into an audit
  trail." Recorded in `docs/reviews/2026-09-22-testnet-rewalkability.md`;
  the town-witness re-walk for the first mainnet dust is pending
  Speechless's mainnet authorization.
- **#51272 — CRT's two identifiers + receipt escrow.** Endorses the
  flag-reply link + EVM address rule (`docs/reviews/2026-09-22-receipt-escrow.md`)
  and the "failures escrowed too" sketch: "a rejected intent's receipt as
  informative as a broadcast's." The escrow doc's open question on
  escrowing failures/rejections now has town support for yes; the whole
  `receipt_anchor` design (O11) stays pending Speechless's build approval.

## Status

No new decisions, no locked-decision changes. O11 (receipt escrow) and O12
(decode-gate stranger veto) remain open, pending Speechless. O9
(single-device fallback) still open. Next town-facing step is the decode-gate
thread, when Speechless is ready.

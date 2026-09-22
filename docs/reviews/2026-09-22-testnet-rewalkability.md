# Testnet drill → mainnet re-walkability map

Response to town feedback (Z, townhall/37143 #51097) on the 2026-09-22
testnet-green post. Each testnet row names the exact mainnet code path it
exercises, what differs on mainnet, and the confirmation depth used.

## EVM (Robinhood testnet, chain 46630)

- Testnet tx: 0x445fea553468dae960947b0069578aa95945629e914d7bb883e0b1b736b3d4ed,
  block 122587750, 0.001 tETH self-send.
- Code path: `src/spellbook/evm.py` `_execute_spend` — build, sign (local key),
  submit via RPC, wait-for-receipt.
- Mainnet mapping: identical function; the only differences are the chain
  config (`evm-46630` → Robinhood EVM mainnet) and the
  `mainnet_submit_enabled` policy gate, which is OFF until Speechless
  authorizes. Same signing code, same receipt parsing.
- Confirmation depth: waited for the transaction receipt with status 0x1
  (success). One failed attempt (fee race: maxFeePerGas under base fee)
  was consumed as `approved-submit-failed`, never retried blind.

## Solana (devnet)

- Testnet sig: 49omtTfbZLiK6rMeACLXk1UsE2N3tLVSqqVGKpPi4SSzdKaY5PZkJG2DZyQE6kevsEbpLdxHyz4h61KCfrb5Wame,
  finalized slot 502258936, 0.001 SOL self-send.
- Code path: `src/spellbook/solana.py` `_execute_spend` — build transfer,
  sign locally, submit, poll `getSignatureStatuses` until `finalized`.
- Mainnet mapping: identical function; chain config devnet → mainnet-beta,
  same `mainnet_submit_enabled` gate. Same fee (5000 lamports) logic.
- Confirmation depth: `finalized` commitment. Balance reconciled on-chain
  after finalization (4.999995 SOL).

## Chia (testnet11)

- Testnet: self-sends + native offer create/take (offer C,
  d27151b82c206b81360ff9a440d90cfe89a6b3ad0022a99eec69213fcc87d406) +
  A/B offer cancels reconciled (maker coins spent at block 4718261).
- Code path: `src/spellbook/chia_relay.py` (HTTPS relay broadcast) and
  `src/spellbook/chia_offer.py` (native offer construction/take).
- Mainnet mapping: identical functions; network testnet11 → mainnet,
  same gate. Relay auth and broadcast path are network-parameterized.
- Confirmation depth: coin-spent observed at a specific block height via
  the relay's coins-by-puzzle-hash lookup; change math reconciled.

## The stranger's row (Z's ask)

Before mainnet unlocks, the same three drills should be re-run by someone
who is not us — a town member re-walks the ladder (dust self-send per
chain) and posts their row (tx/sig, block/slot, balance before/after).
The drill is only a drill once a stranger has reproduced it. Proposed:
the first mainnet dust amounts are funded to a town-witnessed address and
the witness posts the receipts in 37143.

## Pete's approval-failure drill (2026-09-22, run)

Queued a 1,000,000-wei EVM testnet intent (queue id 11, purpose
"approval-failure drill"), then rejected it via queue_reject. Result:
queue empty, ledger shows `queued:11` → `rejected-by-human` on the same
canon_digest, no sighash, nothing broadcast. The human saying no
mid-queue rots the intent in place — it never fires. An unanswered queue
item likewise sits until explicitly approved or rejected (no TTL, no
auto-fire); nothing moves without an approval.

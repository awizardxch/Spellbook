# Drill manifest v1 (pinned)

From Turbo, townhall/37143 #51216: one pinned drill manifest, version-stamped.
Every testnet row and its mainnet re-run cite the same manifest version, so a
stranger diffs rows mechanically instead of squinting at descriptions.

A complete row = **drill id + manifest version + finality rule + decoded intent**.

## Rows

### evm-selfsend-001
- Chain: evm-46630 (testnet) → Robinhood EVM mainnet
- Function: `src/spellbook/evm.py::_execute_spend`
- Finality rule: transaction receipt with status `0x1`
- Decoded intent: plain native transfer — amount, destination, no contract data
- Testnet receipt: `0x445fea553468dae960947b0069578aa95945629e914d7bb883e0b1b736b3d4ed`, block 122587750
- Known failure mode: fee race (maxFeePerGas under base fee) → `approved-submit-failed`, approval consumed, never retried blind

### sol-selfsend-001
- Chain: devnet → mainnet-beta
- Function: `src/spellbook/solana.py::_execute_spend`
- Finality rule: `getSignatureStatuses` → `finalized`
- Decoded intent: plain SOL transfer — amount, destination
- Testnet receipt: `49omtTfbZLiK6rMeACLXk1UsE2N3tLVSqqVGKpPi4SSzdKaY5PZkJG2DZyQE6kevsEbpLdxHyz4h61KCfrb5Wame`, slot 502258936, balance reconciled 4.999995 SOL
- Known failure mode: public RPC connection drop before construction → approval consumed, nothing moved

### xch-selfsend-001
- Chain: testnet11 → mainnet
- Function: `src/spellbook/chia_relay.py` broadcast (signed bundle, keys local)
- Finality rule: coin spent observed at a block height via coins-by-puzzle-hash; change math reconciled
- Testnet receipts: `113cf906339b53c927909191938e8891690c40e80e62f201534228835c40f09c` (block 4717816), `9c14874589837bf3ca5325d8915c4a85cbf4961e7338eac7824aba80ac9621c7`

### xch-offer-take-001
- Chain: testnet11 → mainnet
- Function: `src/spellbook/chia_offer.py` `take_offer`
- Finality rule: both maker and taker spends confirmed at block height
- Testnet receipt: `d27151b82c206b81360ff9a440d90cfe89a6b3ad0022a99eec69213fcc87d406` (offer C, 2,000 mojos for 2,000)

### approval-reject-001
- Function: `rt_queue_reject`
- Finality rule: ledger shows `queued:N` → `rejected-by-human` on the same canon_digest, queue empty, no sighash, nothing broadcast
- Testnet receipt: queue 11, canon `6e224058f0ba11c2671b39fd47f5905f2b43af0fe511c17a31dc4c236967c985`
- Note: unanswered intents rot the same way — no TTL, no auto-fire

## Manifest rules

1. New drill rows cite this manifest version. If the procedure changes, bump
   the manifest — never silently edit a row's meaning.
2. Mainnet re-runs MUST cite the same drill id + manifest version, with the
   witness's own receipts. A mainnet row without a manifest citation is a
   rehearsal, not a drill (Z).
3. Receipts may be escrowed to a public anchor (`receipt_anchor` flag,
   see `2026-09-22-receipt-escrow.md`) so the stranger's row and ours are
   mutually checkable.

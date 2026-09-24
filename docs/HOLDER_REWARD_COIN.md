# No-LP Holder-Reward Coin — Spec v2 (draft)

**Status:** draft for Speechless review — 2026-09-24. **Not approved for build or deploy.**
**Author:** aWizard, for Speechless
**Request:** The Astral Alien — lobby post `61897` (2026-09-23 20:42). Co-signs: Nimbus (`61909`), Mikey (`62186`). Acknowledged by aWizard in `62150`.
**v2 changes:** folds the full feedback round — Alien `63091` (per-tokenId lock, tranches, SAUCER audit status, test-pilot confirmation, claim-path + verification questions), Mikey `62695` (public live coverage readout), Alien `63135` (coverage() view proposal, two-tier verification + registry), Mikey `63177` (button greys out below 100%, view-only readout), aWizard `63502` + Mikey `63514` (verification stack as the town spell).

**Goal:** A Forge spell (aWizard skill) that deploys — in **one transaction** — a fixed-supply ERC-20 whose contract holds its own reward pool. Holders of a chosen NFT collection claim rewards permissionlessly, with eligibility read **live** from the NFT contract's `ownerOf` — no merkle tree, no snapshot. The human approves the deploy **and the reward rate** through Spellbook; the daemon signs; claimants pay their own claim gas. Zero LP, zero treasury spend.

**Reference build:** Saucer (SAUCER), built by the Alien as the reward coin for THE ABDUCTED holders, live on Robinhood testnet. **Audit status (Alien, `63091`): internal review + 22 passing forge tests, NO external audit — this spec must not present SAUCER as the audited shape.** Source shareable for convergence. Independent audit required before any mainnet deploy (unchanged).

**How to read this spec:** statements labeled **GUARANTEE** hold under the stated assumptions; **ASSUMPTION** must be true for the guarantees to apply; **VALIDATION REQUIRED** names claims that must be independently verified (testnet/audit) before implementation treats them as fact.

**Standing rules apply:** no deployment of any kind without explicit approval — testnet drills need a human tap, mainnet needs the full six-gate no-launch rule. This spec is a design document, not an authorization.

---

## 1. Design decisions (locked)

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Fixed-supply ERC-20, single deploy tx** | The request's shape: one tx, one coin, no follow-on admin. |
| 2 | **Reward pool = retained share of the coin's own supply, held by the token contract** | "Holds its own reward pool." No treasury funding step, no LP seeding. |
| 3 | **Eligibility read live at claim time** — `claim()` checks the NFT contract at that block. No merkle root, no snapshot, no off-chain allowlist | The elegant half (Mikey, `62186`): the reward math never goes stale and any stranger can re-check it on the spot. A spell that audits itself. |
| 4 | **Claims are per-NFT-tokenId; each tokenId claims exactly once**, tracked as `paidForToken[keccak256(collection, tokenId)]` (converged with SAUCER, Alien `63091`) | The anti-gaming core. Live `ownerOf` reads alone are flash-borrowable (borrow NFT → claim → return). Per-tokenId-once kills that: a borrowed tokenId's claim is already spent. Secondary buyers can still claim if that tokenId never has. Keying by `(collection, tokenId)` makes the mapping multi-collection-ready. **GUARANTEE** (flash-borrow resistance) under ASSUMPTION 1. |
| 5 | **Claim path: caller-supplied tokenIds is PRIMARY** — the claimant passes `tokenIds[]` as calldata; the contract verifies `ownerOf(tokenId) == msg.sender` per id (SAUCER's answer, Alien `63091`). `claimAll()` via ERC721Enumerable is an optional convenience, not the default | No enumerable extension required; cheaper for collections without it. Answers the Alien's question 1: the spec leans caller-supplied. |
| 6 | **Reward rate immutable at deploy** — set in the constructor, no owner key can change it | The human approves the rate once; the deal can't be re-priced later. No owner, no upgrade, no pause in v1. |
| 7 | **Permissionless claims; claimants pay their own gas** | No keeper, no airdrop run. The pool sits until holders come. |
| 8 | **Deploy is Spellbook-gated** — agent prepares with the request token, human approves the exact deploy (bytecode + constructor args incl. rate) with the approve token; one approval = one deploy attempt | Standard Spellbook flow. The deploy is the launch; it gets the launch-grade gate. |
| 9 | **Tranches, not one-shot funding** (Alien `63091`): the coin's owner funds each wave's allocation via `mintTranche(waveId, amount)` **before that wave's holders claim**. A claim reverts if the pool is short for the wave. Standard: *"pool must cover wave supply × rate before the wave opens."* Max liability per wave is exactly `waveSupply × rate` — computable up front. **GUARANTEE** (no dry pool within a funded wave) under ASSUMPTION 2. |
| 10 | **Public live `coverage()` view** (Mikey `62695`, Alien `63135`): `coverage() = poolBalance / (unclaimedTokens × rate)`. Strictly view — it can never move funds (Mikey `63177`). Any frontend renders a pool-health meter from it; the claim button **greys out below 100%** — warn before gas gets spent, never after. | The coverage check is not a doc line; it's a number claimants read before paying gas. Nothing worse than spending gas on dust. |
| 11 | **Two-tier collection verification at deploy** (Alien `63135`, aWizard `63502`): **(a)** the spell checks `owner()` on the NFT contract — if the deployer controls the collection, the impersonator is stopped at the door; **(b)** otherwise, a **signed attestation** from the collection deployer ("reward coin `<coin>` pays holders of `<collection>`"), produced through Spellbook's `message_sign` (`personal`/EIP-191 on the project's chain) and verifiable by anyone against the deployer's address. Answers the Alien's question 2: both, in that order. |
| 12 | **On-chain registry of spell-minted coins** (Alien `63135`, Mikey `63514`): each deploy registers `{coin, collection, attestation, deployTx}` in a canonical registry — the part that makes it a town spell. A stranger re-walks one list before touching a claim: the coin's real, the pool's funded (decision 10), the name can't be squatted. **VALIDATION REQUIRED:** registry contract shape and who may write (spell-at-deploy with the decision-11 proof). |
| 13 | **Chain: Robinhood Chain** — testnet reference first | The town's chain; SAUCER is already on Robinhood testnet. |

### Non-goals (v1)
- LP/DEX integration, price oracles, vesting schedules.
- Recurring/epoch rewards — v1 is claim-once-per-tokenId; tranches cover wave-scoped funding (decision 9 answers the old "pool top-ups" question: bounded, per-wave, no arbitrary top-up role).
- Unverified collections — the spell refuses when neither verification tier passes.

---

## 2. Actors

- **Spell caster (aWizard skill):** takes parameters, verifies the collection (decision 11), checks tranche funding (decision 9), builds the deploy intent, publishes claim instructions.
- **Human (Speechless, or the commissioning project's human):** approves the deploy + rate. Nothing deploys without this tap.
- **Spellbook daemon:** holds the deployer key, signs only the approved deploy; signs collection attestations via `message_sign` (decision 11b).
- **NFT holders:** claim permissionlessly whenever they want; check `coverage()` first; pay their own gas.
- **NFT project (e.g. THE ABDUCTED):** names the eligible collection and funds each tranche. Distribution of the non-pool supply is the project's/human's decision — out of scope for the spell.

---

## 3. Contract sketch

- **Constructor:** `name, symbol, totalSupply, nftContract, rewardPerNft, poolAmount`.
  Mints `totalSupply` to the deployer, transfers `poolAmount` to the coin contract itself. Emits the parameters for the ledger.
- **`mintTranche(uint256 waveId, uint256 amount)`:** owner-only; moves `amount` of the deployer's balance into the claim pool and records `waveFunded[waveId] += amount`. Emitted per wave for the ledger.
- **`claim(uint256[] calldata tokenIds)`:** for each id — require `nft.ownerOf(tokenId) == msg.sender` (reverts cleanly on nonexistent ids); key = `keccak256(abi.encodePacked(nftContract, tokenId))`; require `!paidForToken[key]`; set `paidForToken[key] = true`; accumulate `rewardPerNft`. Require the pool covers the payout for the active wave (revert on short pool — decision 9). Single ERC-20 transfer of the total at the end (checks-effects-interactions).
- **`claimAll()`** (enumerable collections only, optional): builds the caller's unclaimed tokenId list via `tokenOfOwnerByIndex` and runs the same logic. **VALIDATION REQUIRED:** gas per claim; cap tokenIds per tx (suggested max 50) so claims can't grief themselves into out-of-gas.
- **`coverage() view returns (uint256)`:** `poolBalance * 1e18 / (unclaimedTokens * rewardPerNft)` — per-mille/per-ether health figure; strictly view, no state, no funds movement (decision 10).
- **Invariant:** `sum(all claimed) + contractBalance == poolAmount + sum(tranches)`, always. Checkable by anyone, forever — the self-auditing property.
- **No owner functions beyond `mintTranche` / no upgrade / no pause** in v1 (decision 6; tranches are the only owner role and are wave-scoped).

### Assumptions
1. **A1:** The NFT contract's `ownerOf` is truthful at claim time (i.e., the collection contract itself isn't malicious or upgradeable-under-us — if it's a proxy, eligibility logic could change; note in the human review surface).
2. **A2:** `waveSupply` used in the tranche coverage check is the true final supply for that wave (not an uncapped collection still minting into the wave — if the collection can still mint, coverage can't be proven; the spell must refuse or require a capped wave).

---

## 4. The skill (Forge spell) flow

1. **Intake:** NFT contract address, reward rate, supply, name/symbol, pool allocation, wave plan.
2. **Verification (before any intent is built):**
   - NFT contract exists and is ERC-721 (`supportsInterface(0x80ac58cd)`).
   - **Tier 1:** `owner()` on the NFT contract == deployer → control proven.
   - **Tier 2 (fallback):** signed attestation from the collection deployer via Spellbook `message_sign` (`personal`, EIP-191); the spell recovers the signer and checks it against the collection's known deployer/owner address.
   - **Registry:** on deploy, the spell writes `{coin, collection, attestation, deployTx}` to the spell-coin registry (decision 12). Refuse when neither tier passes — no spoofed collections, ever.
   - Wave supply: capped wave or still minting (gates decision 9 / A2).
   - Tranche funding math (decision 9) — refuse with a clear reason if the wave's pool can't cover `waveSupply × rate`.
3. **Human review surface:** decoded intent showing exact bytecode hash, constructor args, rate, tranche plan, max liability per wave, claim paths, verification tier used, registry entry preview, and the A1/A2 assumptions in plain language. Approve token signs here.
4. **Deploy + verify:** daemon signs and broadcasts the approved deploy; skill verifies the deployed bytecode, writes the registry entry, and records the address, tx hash, and parameters in the decision ledger.
5. **Publish:** town post with claim instructions for holders (check `coverage()` first — button greys out below 100%; how to call `claim`/`claimAll`, what it costs, the invariant anyone can check).

---

## 5. Security considerations

- **Reentrancy:** `claim()` makes external calls (`ownerOf` reads; one ERC-20 transfer out). Checks-effects-interactions ordering + `ReentrancyGuard`. The NFT contract is untrusted input — a malicious `ownerOf` can't steal funds under CEI, but note it. **VALIDATION REQUIRED:** independent audit before any mainnet deploy (SAUCER's 22 forge tests do not substitute).
- **`ownerOf` on nonexistent tokenIds reverts** — the loop must handle/skip cleanly (suggest `try/catch` or pre-validation).
- **Gas griefing:** per-tx tokenId cap (decision: 50 suggested).
- **Pool exhaustion:** prevented per-wave by the tranche funding rule + the on-chain revert (decision 9); surfaced live by `coverage()` (decision 10).
- **Front-running claims:** none — claims are per-tokenId-once; racing a claim for a tokenId you don't own fails `ownerOf`.
- **Spoofed collections:** stopped by the two-tier verification + registry (decisions 11–12). A lookalike collection gets no registry entry and no attestation; the claim page shows the registry check cold.
- **Deployer remainder:** `totalSupply - poolAmount - tranches` lands with the deployer key; its distribution is a human decision, recorded in the ledger, not the spell's business.

---

## 6. Testnet-first rollout

1. **Spec review** — this document. Speechless decides: build at all, and priority vs. other Forge work.
2. **Obtain + verify the SAUCER reference build** — contract address and source from the Alien (offered, `63091`); read-only verification of the claim flow on Robinhood testnet. Converge the v3 deltas against their repo, not its description.
3. **Implement contract + skill against Robinhood testnet.** The Alien test-pilots — **confirmed** (`63091`): full loop on testnet (deploy through the spell, tranche funding, claims, coverage readout).
4. **Testnet drill recorded** in the decision ledger — full claim cycle, tranche revert case, invariant check, `coverage()` readings, gas measurements.
5. **Mainnet:** only with explicit six-gate approval **and** an independent audit. No exceptions, no "it's just a small deploy."

---

## 7. Open questions

- **For Speechless:** green-light to build? Priority? Take up Nimbus's suggestion (pitch in #musemoneychallenge + bounty for first adopter project)?
- **Registry (decision 12):** standalone registry contract vs. registry-as-spell-record? Who pays its deploy, and who may write — spell-at-deploy only, or also later attestations?
- **Recurring epochs:** v2, or does one-time-per-tokenId + tranches cover the real use cases?
- **SAUCER convergence:** exact `mintTranche`/access-control shape in their repo — read the source before v3.

## 8. Provenance

- Request: The Astral Alien, lobby `61897` — "@aWizard — feature request from the saucer… **Spell: no-LP holder-reward coin**…"
- Co-sign: Nimbus, lobby `61909` (pitch in #musemoneychallenge; bounty for first adopter).
- Co-sign: Mikey, lobby `62186` ("a spell that audits itself").
- aWizard ack: lobby `62150` (filed; spellbook spec review; docs as authority; human signs off; no launch promised).
- aWizard feedback: lobby `62662` (half the spec is already Spellbook's request/approve flow; per-tokenId flash-borrow defense).
- Feedback round (folded into this v2): Alien `63091` (per-tokenId mapping, tranches, SAUCER audit status, test-pilot confirmed, Q1 claim path, Q2 verification); Mikey `62695` (public live coverage readout); Alien `63135` (`coverage()` view, two-tier verification + registry); Mikey `63177` (grey-out below 100%, view-only); aWizard `63502` + Mikey `63514` (verification stack as the town spell).

**Scan note (2026-09-23):** swept Musebook search (`feature request`, `spell`, `skill`, `request`, `commission`, `forge`, `bounty`, `@aWizard`) — this was the only explicit aWizard-directed feature request. Other hits were town-platform ideas (image embeds, news desk), welcomes, or unrelated chatter — not skill candidates.

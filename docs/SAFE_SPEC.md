# Spellbook Safe multisig spec — DRAFT

**Status:** DRAFT. No code exists for this. Implementation starts only
after Speechless approves this spec. Approved pieces fold into
SPEC_V1.md; until then this document is the design of record.

**Date:** 2026-09-23
**Decision owner:** Speechless

## 1. Decisions (2026-09-23, Speechless)

1. **Per-agent Safe.** Each agent gets their own Safe. Never a shared
   multi-agent Safe.
2. **Creation only on explicit human request.** The human asks for the
   Safe to be created; the daemon never creates one on its own, during
   install, or as a side effect of anything else.
3. **Threshold and signing wallets are human-decided.** The human names
   the chain, the owners, and the threshold. The agent records what the
   human decided — it never proposes owners or thresholds on its own.
4. **After initial creation, every change to the Safe requires on-chain
   signing per the Safe's setup.** Owner add/remove/swap and threshold
   changes happen only through an executed Safe transaction carrying a
   signature set that meets the Safe's threshold. Nothing changes by
   daemon fiat, config edit, or off-chain agreement.

## 2. Goals

- Every agent that installs Spellbook can leverage a Safe multisig.
- The Spellbook-derived EVM key can serve as a threshold signer of the
  agent's Safe (the human decides whether it is an owner at all).
- The human keeps full custody authority: they chose the owners and the
  threshold, and every spend still needs their per-transaction approval.
- Safe transactions inherit the entire existing trust machinery: queue,
  decoded intent, per-transaction approval, ledger, policy, velocity,
  one-approval-one-attempt, unknown-fate-never-retried, on-demand
  daemon (§4, §5).

## 3. Non-goals (v1)

- Shared multi-agent Safes.
- Safe modules, guards, or spending-limit modules.
- Anything beyond the Safe contract itself (no other account
  abstraction in v1).
- Changing the approval model: the O5 separate-device HMAC / two-token
  split (S7) is unchanged. The human's approval remains the gate; the
  Safe is a smarter vault, not a new authority.

## 4. Creation

- `POST /v1/safe_create {chain, owners[], threshold, label?}` is an
  **approve-token-only** route (S7). A request-token caller gets a
  refusal, logged.
- Two paths, both human-initiated:
  - **Deploy new:** the daemon deploys an official Safe v1.4.1 proxy
    (deterministic CREATE2 address, canonical deployment) with the
    human-named owners and threshold. The human approves the deployment
    transaction itself like any other spend.
  - **Register existing:** the human names a Safe address they already
    control. The daemon verifies on-chain that it is a Safe proxy,
    reads owners/threshold/nonce, and records it. Registration fails
    closed if the address is not a Safe.
- The Spellbook-derived key for that chain (the §2
  `muse-wallet/v1/<chain>/sign/<label>` secp256k1 derivation) becomes
  an owner **only if the human lists it**. The daemon never adds
  itself.
- The human's signing wallets are **addresses only**. The daemon never
  sees, holds, or asks for the human's private keys.
- v1 scope: one Safe per agent per chain. The daemon records, per Safe:
  chain, Safe address, owners, threshold, creation approval id, and
  (for deployments) the deployment txid.

## 5. Safe transaction lifecycle

Every Safe spend goes through the same shape as every other spend:

1. **Request** (request token): the agent calls
   `request_safe_tx {safe, to, value_wei, data, operation, purpose}`.
   The intent is queued with decoded intent surfaced to the human
   (destination, value, and calldata decoded where a decoder exists).
2. **Human approval** (approve token only): the approval binds the
   **exact `safeTxHash`** — the EIP-712 hash over the Safe domain
   separator and the transaction fields. An approval for any other
   hash, or for the intent without the hash, does not authorize
   signing. One approval = one execution attempt.
3. **Signing:** the daemon recomputes `safeTxHash` from the queued
   fields, checks it matches the approved hash byte-for-byte, and only
   then signs with the Spellbook-derived key (EIP-712, EOA v=27/28
   format the Safe contract accepts). No approval, no signature.
4. **Collection:** if the human-configured threshold needs more than
   the Spellbook key (threshold > 1, or the Spellbook key is not an
   owner), the remaining owner signatures arrive via the human's
   tooling. The daemon verifies every signature against the Safe's
   recorded owner set and EIP-712 domain before assembling. It never
   executes with fewer valid signatures than the threshold.
5. **Simulation:** `eth_call` dry-run of `execTransaction` with the
   assembled signatures. Revert → abort, report, no broadcast.
6. **Execution:** broadcast `execTransaction`. The unknown-fate rule
   applies unchanged: txid mismatch or ambiguous ack = UNKNOWN fate,
   never retried — reconcile read-only.
7. **Ledger:** the safeTxHash, approval id, nonce, and outcome land in
   the decision ledger like any spend.

## 6. Post-creation changes

Owner add/remove/swap, threshold change, and (later) module changes
are Safe transactions like any other:

- The daemon may **propose** the calldata (e.g. `addOwnerWithThreshold`,
  `removeOwner`, `swapOwner`, `changeThreshold`) but only at the
  human's request.
- The human approves the exact `safeTxHash` of the change.
- The change executes on-chain with a threshold-satisfying signature
  set. The daemon signs with the Spellbook key only under an approval
  covering that exact change.
- The daemon's recorded owners/threshold update **only from the
  on-chain event** after execution — never from the proposal, never
  from a config edit.

## 7. Nonces

- The daemon reads the Safe nonce on-chain at proposal time and binds
  it into the approved `safeTxHash`.
- One in-flight Safe transaction at a time per Safe. No parallel
  nonce signing, no nonce pre-signing.

## 8. Hard invariants

1. No Safe is created without an explicit human request on the
   approve-token route.
2. No owner or threshold change except via an executed on-chain Safe
   transaction with threshold-satisfying signatures.
3. No signature on a `safeTxHash` without a human approval bound to
   that exact hash.
4. No execution below the Safe's threshold.
5. The daemon never holds human private keys; human wallets are
   addresses only.
6. Safe transactions flow through queue, ledger, policy, and velocity
   exactly like EOA spends.
7. `mainnet_submit_enabled` semantics and the on-demand daemon rule
   are unchanged.

## 9. Open questions

- **Human signature delivery for threshold > 1:** via the existing O5
  approval tooling (human pastes an EIP-712 signature alongside the
  approval) or via a Safe{Wallet} UI flow the human drives themselves.
  Recommendation: the human's existing tooling first; document both.
- **Batched calls:** `request_safe_tx` supporting `MultiSend` batches
  in v1, with per-call decoding. Recommendation: yes — batching is a
  core reason to want a Safe.
- **§10 drill shape:** deploy a Safe on Robinhood testnet (46630),
  threshold 1 with the Spellbook key, execute a no-op, then an
  owner-change round trip back to the original set. All on testnet.

## 10. What this does not change

D1–D14, the two-token split (S7), the O5 approval path, the
one-approval-one-attempt rule, the unknown-fate rule, the paper-backup
duty (D10), and the agent contract (§9) all stand. This spec adds a
vault type; it moves no authority from the human to the agent.

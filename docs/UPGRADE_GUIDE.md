# Upgrading an existing wallet to the sealed seed

## Who this is for

This guide is for an existing Spellbook wallet on an agent VM that should
survive wipes and session resets. The steps are:

1. Confirm which wallet you have.
2. Confirm the paper backup.
3. Seal the seed with a password.

Background: [SEALED_SEED.md](SEALED_SEED.md) and [KEY_RECOVERY.md](KEY_RECOVERY.md).

> The earlier plan (a hot wallet in `~/workspace/.spellbook/hot.key` plus a
> `keymanager.py` encrypted key) has been removed. It stored a plain-text
> private key where the agent could read it. If you created
> `~/workspace/.spellbook/hot.key` or `key.enc`, move any funds that key
> alone controls to the daemon's wallet, then delete both files.

## Prerequisites

- An updated Spellbook install that has the `spellbook-seed` command
  (`pip install -e .` in the repo, or `install.sh --upgrade`).
- Either the seed files are on disk, or you have the paper backup.

## Step 1: Check the state

```bash
spellbook-seed status
python3 -m spellbook.recovery addresses   # the live EVM address
```

The address must match the one the dashboard shows for this agent.

## Step 2: Restore the seed files if the VM was already wiped

```bash
python3 -m spellbook.recovery restore             # SET 2 words -> seed.key
python3 -m spellbook.recovery restore --standard  # SET 1 words -> std_seed.key
```

Standard-derivation installs (every `install.sh` install) need both.
After restoring, re-run Step 1 and check the address.

## Step 3: Confirm the paper backup

```bash
python3 -m spellbook.recovery backup
```

Compare the SET 2 words with your paper. SET 1's words cannot be shown
again, so check that you still have them on paper. If you don't, write
down the raw keys that `backup` prints. The seal from Step 4 then becomes
your main digital recovery path.

## Step 4: Seal the seed

```bash
spellbook-seed serve
```

The human opens the printed link and chooses a password of 12 or more
characters. Keep that password in a password manager.
`spellbook-seed status` should now report `unlocked`.

## Step 5: Add the per-session check

Add this to the agent's session-start instructions or hook (see
[AGENT_ONBOARDING.md §6b](AGENT_ONBOARDING.md)):

```bash
spellbook-seed status
```

## Automation

Crons and bots sign through the daemon, as every agent spend does. They
use `AgentClient` with the request token and are subject to policy. No
separate key file is needed: once the seed is unlocked, the daemon signs.

## Checklist

- [ ] `recovery.py addresses` matches the dashboard
- [ ] Paper backup confirmed: SET 2 words match, and SET 1 is on paper or the raw keys are
- [ ] `spellbook-seed status` → `unlocked` (sealed)
- [ ] Seal password stored in a password manager
- [ ] Session-start check added for the agent
- [ ] Any old `hot.key` / `key.enc` emptied and deleted

## Chia addresses changed (Chialisp audit 2026-10-07, finding S1)

Before this release the daemon built its curried standard puzzle as
`(a (f (q MOD)) (c (f (q PK)) 1))`. That program *runs* exactly like the
canonical curry `(a (q . MOD) (c (q . PK) 1))`, but it is a different
program, so it had a different puzzle hash — and therefore every `txch1…` /
`xch1…` address the daemon printed or served was one that no stock wallet
(Sage, the reference wallet) derives from the same key. Importing the key
into Sage showed a different address and a zero balance.

The daemon now builds the canonical curry (pinned against chia-blockchain
in `tests/test_chia_sign.py` and verified on chia's spend simulator in
`tests/test_chia_sim.py`). Consequences for an existing install:

1. **Every Chia address changes.** `spellbook addresses`, `rt_addresses`,
   `scripts/make_standard_wallet.py`, `install.sh`'s paper-backup block and
   `ceremony/derive_addresses.py` now print the **standard** address only.
   Re-run `recovery.py addresses` / `ceremony/derive_addresses.py` and
   re-bind the new Chia address wherever the old one was bound (dashboard
   viewer token, counterparties, directory entries).
2. **Coins already received at the old addresses are not lost.** The relay
   coin scan (`relay_scan_indices` derivation indices) includes the old
   ("legacy") puzzle hashes alongside the standard ones, so existing coins
   stay visible in balances, can back or cancel an offer, and are spent
   with the reveal that matches their puzzle hash. **Sweep them with the
   daemon before you rely on a Sage import:** send the balance to your own
   new address with a normal `request_spend` (or let an offer's change do
   it) — change always goes to the standard address. Sage cannot see or
   spend legacy coins; only this daemon can.
3. **`chia_sign.legacy_standard_puzzle_reveal` /
   `legacy_puzzle_hash_for_synthetic_pk`** reproduce the pre-fix shape.
   They exist only so the scan finds and `build_standard_spend` sweeps
   legacy coins. Nothing prints, serves or accepts a legacy address as a
   *new* receive address, and they can be removed once every legacy coin
   on your install has been swept (`spellbook status --balances` shows a
   balance only at standard addresses).

Two related hardening changes from the same audit ship alongside:

- **`offer_make` `receive_address` (S2)** must now be one of the daemon's
  own addresses (the scanned set, legacy included); omit it and the
  requested leg pays the primary address. A foreign address is refused and
  the queue entry shows `receive_address` / `receive_ph` to the approver.
- **`offer_delete` (S5)** needs the approve token. It drops Sage's *local*
  record only — not an on-chain cancel — and for an offer this wallet made
  that record is the only handle `offer_cancel` has. Agents cancel with
  `offer_cancel`; the human deletes with
  `spellbook offer-delete --token-file <approve token>`.

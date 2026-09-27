# Spellbook Key Recovery Guide

## The Problem

Spellbook agent VMs are wiped every few sessions (on compaction or a fresh
session). Everything outside `~/workspace` is lost, including:
- the daemon's seed files (`~/.spellbook-testnet/seed.key`, and
  `std_seed.key` on standard-derivation installs)
- the daemon's in-memory keys

**If the seed is not backed up somewhere that survives, the funds are
permanently locked.** There are two backups, and you want both:

| Backup | Survives | Restores with | Protects against |
|---|---|---|---|
| **Sealed seed** (`~/workspace/.spellbook/seed.sealed`) | VM wipes | the human's password, on a one-time local page | routine wipes and session resets |
| **Paper** (24 words, two sets) | everything | the human re-typing the words | losing the VM, the workspace, or the password |

## 1. Every session: check the seed

```bash
spellbook-seed status
```

| State | Exit | Meaning | Do |
|---|---|---|---|
| `unlocked` | 0 | seed present, matches the seal | nothing |
| `locked` | 3 | seal present, seed missing (after a wipe) | `spellbook-seed serve` → human unlocks |
| `unsealed` | 4 | seed present, no seal | `spellbook-seed serve` → human seals |
| `mismatch` | 5 | seed on disk ≠ sealed seed | stop; tell the human |
| `empty` | 6 | no seed, no seal | fresh install, or paper restore |

Full design: [SEALED_SEED.md](SEALED_SEED.md).

## 2. Seal the seed (once)

```bash
spellbook-seed serve
```

It prints a one-time link (`http://127.0.0.1:8787/<token>/`). The human
opens it, picks a password (12+ characters), and the seed files are
encrypted into `~/workspace/.spellbook/seed.sealed` (scrypt + AES-256-GCM).
A human at the VM's terminal can instead run `spellbook-seed seal`.

## 3. After a wipe: unlock

```bash
spellbook-seed status   # -> locked
spellbook-seed serve    # human opens the link, enters the password
spellbook-seed status   # -> unlocked; start the daemon
```

Unlock writes the seed files back exactly as they were (0600). It never
overwrites a different seed, and a wrong password writes nothing. The
viewer stops after 5 wrong passwords.

**The agent never handles the password**: not in chat, not in argv, not in
env. Only the human types it, into the viewer page or the terminal.

## 4. Paper backup

The installer shows two sets of 24 words **once**:

- **SET 1: standard recovery.** These are the daemon's live keys
  (`key_derivation=standard`). The words work in Sage and MetaMask. They
  **cannot be shown again**, because `std_seed.key` is a one-way BIP-39 seed.
- **SET 2: daemon seed.** These words recover through Spellbook only.
  They are the contents of `seed.key`, so they can be re-shown:

```bash
python3 -m spellbook.recovery backup      # SET 2 words + the LIVE EVM/Chia keys
python3 -m spellbook.recovery addresses   # live EVM address only
```

`backup` shows the keys the daemon actually signs with, for both
standard and kdf installs. Write the words on paper, keep two copies in
two places, and never put them in chat, email, cloud notes or screenshots.

### Restore from paper (no seal, or password lost)

```bash
python3 -m spellbook.recovery restore             # SET 2 -> seed.key
python3 -m spellbook.recovery restore --standard  # SET 1 -> std_seed.key
```

Standard installs need both. Neither command overwrites an existing
file. Afterwards, seal again (`spellbook-seed serve`).

## Where the files are

Tools find paths through the daemon's `spellbook.json`. They look in
`--config-dir`, then `$SPELLBOOK_CONFIG_DIR`, then `~/.spellbook-testnet`,
then `/opt/spellbook`. The sealed file lives at
`$SPELLBOOK_SEALED_PATH`, or by default `~/workspace/.spellbook/seed.sealed`.

## Dashboard Security tab

The hosted dashboard runs on Vercel, not on your VM, so it cannot read or
unlock the seed. Seal and unlock always happen on the VM's own viewer
page. **Never** type the seal password or the recovery words into the
hosted dashboard.

## Hot wallet and `keymanager.py`: removed

An earlier version kept a **plain-text** private key in
`~/workspace/.spellbook/hot.key` where the agent could read it, which
defeats the daemon's key isolation. It also had an unused encrypted-key
helper. Both are gone. Use the sealed seed instead: after unlock, the
daemon signs as usual. If a `hot.key` or `key.enc` file exists, move any
funds that key alone controls and delete the file.

## If the keys are already lost

With no seal, no paper and no seed file, **there is no recovery**:
1. Create a new wallet.
2. Seal it and write down the paper backup IMMEDIATELY.
3. Move any funds you can still reach to the new wallet.

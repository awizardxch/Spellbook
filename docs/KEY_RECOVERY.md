# Spellbook Key Recovery Guide

## The Problem

Spellbook agent VMs are wiped every few sessions (on compaction). When the VM is wiped:
- The seed file (`~/.spellbook-testnet/seed.key`) is destroyed
- The daemon's in-memory key is gone
- **If you didn't save your recovery phrase, your funds are permanently locked**

There is no way to recover a lost private key. This guide shows you how to back up NOW, before it's too late.

## Quick Start: Backup Your Keys NOW

Run this on your VM **before** the next wipe:

```bash
python3 ~/workspace/.spellbook/recovery.py backup
```

This displays:
1. **Master seed** (64-byte hex) — the root of everything
2. **24-word recovery phrase** — restores all chains
3. **EVM private key** — import into MetaMask (single chain)
4. **Chia master secret key** — for Chia wallet import
5. **Addresses** — verify they're correct

### What to write down

- ✅ The **24-word phrase** on **paper**, pen, by hand — this restores EVERYTHING
- ✅ **Two copies**, in **two separate physical locations**
- ✅ Verify by reading the words back
- ❌ NEVER store in chat, email, cloud notes, or screenshots
- ❌ NEVER share with anyone

The individual private keys (EVM, Chia) are for importing ONE chain into a wallet app without exposing the master phrase. You don't need to write these down if you have the 24 words — they can be re-derived.

## Automated Transactions: Hot Wallet Setup

For frequent automated transactions (crons, bots), the agent needs key access without user interaction.

### Architecture

- **Hot wallet** (`~/workspace/.spellbook/hot.key`): Plain private key, 600 permissions. Persists across VM wipes because `~/workspace` survives. The agent reads it directly for signing.
- **Cold backup** (encrypted file + paper phrase): For disaster recovery if the hot wallet is lost.

### Setup (one time)

```bash
# 1. Provide the private key via env var (transient)
export SPELLBOOK_PRIVKEY="0x..."

# 2. Initialize the hot wallet
python3 ~/workspace/.spellbook/hotwallet.py setup

# 3. Verify the address
python3 ~/workspace/.spellbook/hotwallet.py address

# 4. Clear the env var
unset SPELLBOOK_PRIVKEY
```

### Using in automation

```python
from hotwallet import HotWallet

w = HotWallet()  # loads from ~/workspace/.spellbook/hot.key
print(w.address)

# Sign a transaction
signed = w.sign_transaction({
    'to': '0x...',
    'value': 0,
    'gas': 200000,
    'maxFeePerGas': 10**9,
    'maxPriorityFeePerGas': 10**9,
    'nonce': 0,
    'chainId': 4663,
    'data': '0x...',
})
# Broadcast signed.rawTransaction via your RPC
```

### Rotating the hot key

If compromised, or for regular rotation:

```bash
export SPELLBOOK_PRIVKEY="0x...new key..."
python3 ~/workspace/.spellbook/hotwallet.py rotate
unset SPELLBOOK_PRIVKEY
```

Then transfer funds to the new address and update any references.

## Recover After a VM Wipe

### From paper backup

```bash
python3 ~/workspace/.spellbook/recovery.py restore
# Enter your 24 words when prompted
```

This restores the seed file. Then re-run hot wallet setup.

### From encrypted backup

If you created an encrypted backup:

```bash
# The backup file is in ~/workspace/.spellbook/backups/
# Decrypt with your password, then restore
```

## Import into MetaMask

1. Run `python3 ~/workspace/.spellbook/recovery.py backup`
2. Copy the **EVM Private Key** (0x...)
3. MetaMask → Account menu → Import Account → Paste private key
4. Your EVM wallet appears (same address as Spellbook)

This imports ONLY the EVM chain. Your Chia/Solana wallets are unaffected.
To import everything, use the 24-word phrase (MetaMask → Import via recovery phrase).

## For Developers: Preventing Key Loss

### At wallet creation time

The installer MUST enforce paper backup:

1. Generate the wallet
2. Display the 24-word phrase + all derived addresses
3. **Require the user to type 3 random words** (e.g., words #7, #15, #22) to prove they wrote it down
4. Do not proceed until verification passes
5. Offer to set up the hot wallet for automation

### Dashboard Security page

Add a "Security" section with MetaMask-style controls:
- **Reveal Recovery Phrase** (human password required)
- **Reveal Private Key** (human password required)
- **Download Encrypted Backup**
- **Hot Wallet Status** (initialized? address?)

Agent cannot access these — human-only.

## If You've Already Lost Your Keys

**There is no recovery.** The funds are permanently locked.

1. Create a new wallet
2. Back up IMMEDIATELY using this guide
3. Transfer any accessible funds to the new wallet

## Technical Details

- Seed file: `~/.spellbook-testnet/seed.key` (64 hex chars = 32 bytes entropy)
- Mnemonic: BIP-39, 24 words, English wordlist
- Master seed: BIP-39 seed (64 bytes) from mnemonic
- EVM derivation: BIP-32 `m/44'/60'/0'/0/0` (MetaMask-compatible)
- Chia derivation: `chia_master_sk()` from master seed
- Hot wallet: `~/workspace/.spellbook/hot.key` (600 perms, plain hex)
- Encryption: AES-256-GCM with Scrypt KDF (for cold backups)

## Files

- `~/workspace/.spellbook/recovery.py` — Backup/restore (master + individual keys)
- `~/workspace/.spellbook/hotwallet.py` — Hot wallet for automation
- `~/workspace/.spellbook/keymanager.py` — Encrypted cold storage
- `~/workspace/.spellbook/hot.key` — Hot wallet private key (600)
- `~/workspace/.spellbook/backups/` — Encrypted backups
- `~/workspace/.spellbook/KEY_RECOVERY.md` — This guide

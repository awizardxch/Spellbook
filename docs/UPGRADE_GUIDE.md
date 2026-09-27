# Upgrading to the Spellbook Key Recovery System

## Who This Is For

You have an existing Spellbook wallet with a master seed (24-word phrase or raw seed file). You want to:
1. Set up the hot wallet for automated transactions
2. Create an encrypted backup
3. Verify your paper backup is correct

## Prerequisites

- Your 24-word recovery phrase (paper backup from original install)
- OR access to your existing seed file (`~/.spellbook-testnet/seed.key` or `/opt/spellbook/seed.key`)
- The Spellbook repo with the new recovery tools (v1.1+)

## Step 1: Verify Your Current Wallet

First, confirm which wallet you're working with:

```bash
# If you have the seed file:
python3 -m spellbook.recovery addresses

# If you only have the 24 words, restore first (see Step 2)
```

Note the addresses. These should match what you see in the dashboard.

## Step 2: Restore from Paper Backup (if needed)

If your VM was wiped and you only have the paper phrase:

```bash
python3 -m spellbook.recovery restore
# Enter your 24 words when prompted
```

This restores the seed file. Verify the addresses match your expectations.

## Step 3: Create a Full Backup

Run the backup tool to see ALL your key material:

```bash
python3 -m spellbook.recovery backup
```

This displays:
1. **Master seed** (64-byte hex)
2. **24-word phrase** — verify it matches your paper backup
3. **EVM private key** — for MetaMask import
4. **Chia master key** — for Chia wallet import
5. **All addresses** — verify they match

**If the 24 words DON'T match your paper backup:** STOP. You may have the wrong phrase. Do not proceed until resolved.

**If they match:** Your paper backup is verified. Continue.

## Step 4: Set Up the Hot Wallet (for automation)

The hot wallet lets the agent sign transactions automatically (for crons, bots):

```bash
# 1. Get your EVM private key from the backup output above
# 2. Set it as an env var (transient)
export SPELLBOOK_PRIVKEY="0x...your EVM private key..."

# 3. Initialize the hot wallet
python3 -m spellbook.hotwallet setup

# 4. Verify
python3 -m spellbook.hotwallet address
# Should match your EVM address from Step 3

# 5. Clear the env var
unset SPELLBOOK_PRIVKEY
```

The hot wallet file is at `~/workspace/.spellbook/hot.key` (600 permissions).
It persists across VM wipes.

## Step 5: Create an Encrypted Backup

For digital disaster recovery (in addition to paper):

```bash
# 1. Choose a strong password, store it in your password manager
# 2. Set env vars (transient)
export SPELLBOOK_PASSWORD="your-strong-password"
export SPELLBOOK_PRIVKEY="0x...your EVM private key..."

# 3. Create encrypted backup
python3 -m spellbook.keymanager store

# 4. Clear env vars
unset SPELLBOOK_PASSWORD
unset SPELLBOOK_PRIVKEY
```

The encrypted file is at `~/workspace/.spellbook/key.enc`.
It persists across VM wipes.

**Test the backup:**
```bash
export SPELLBOOK_PASSWORD="your-strong-password"
python3 -m spellbook.keymanager load
unset SPELLBOOK_PASSWORD
# Should display your private key (verify it matches)
```

## Step 6: Update Your Automation

Replace direct seed file access with the hot wallet:

**Before:**
```python
# Old: reading seed file directly
with open('/opt/spellbook/seed.key', 'rb') as f:
    seed = f.read()
```

**After:**
```python
# New: use hot wallet
from spellbook.hotwallet import HotWallet
w = HotWallet()
signed = w.sign_transaction(tx_dict)
```

## Step 7: Verify Everything

Run the doctor to confirm the new system is working:

```bash
spellbook doctor
```

Check:
- [ ] Hot wallet file exists with 600 permissions
- [ ] Hot wallet address matches your EVM address
- [ ] Encrypted backup exists
- [ ] Paper backup verified (24 words match)

## Troubleshooting

### "Hot key not found"

You haven't run Step 4 yet. The hot wallet is optional — the daemon still works with the seed file. But automation requires it.

### "Permission denied" on hot.key

```bash
chmod 600 ~/workspace/.spellbook/hot.key
```

### Addresses don't match

You may have:
- The wrong 24-word phrase (check your paper backup)
- A different wallet (check if you have multiple)
- A KDF-derived wallet (see install.sh SET 2 — daemon-native keys)

For KDF wallets, the recovery tools work with the seed file directly, not the 24-word phrase.

### I lost my paper backup

If you still have the seed file, run `python3 -m spellbook.recovery backup` NOW to regenerate the phrase. Write it down immediately.

If you've lost both the seed file AND the paper backup, the funds are permanently locked. See `docs/KEY_RECOVERY.md` for details.

## Migration Checklist

- [ ] Verified current wallet addresses
- [ ] Restored from paper backup (if VM was wiped)
- [ ] Ran full backup, verified 24 words match paper
- [ ] Set up hot wallet for automation
- [ ] Created encrypted backup
- [ ] Tested encrypted backup decryption
- [ ] Updated automation code to use HotWallet
- [ ] Ran `spellbook doctor` — all green
- [ ] Stored backup password in password manager
- [ ] Confirmed paper backup in two physical locations

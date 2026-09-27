#!/usr/bin/env python3
"""
Spellbook Hot Wallet — for automated transactions.

The hot key lives at ~/workspace/.spellbook/hot.key (600 permissions).
It persists across VM wipes (workspace survives).
The agent reads it directly for cron jobs and automated signing.

SECURITY:
- File has 600 permissions (owner read/write only)
- Never log the key, never output it, never commit it
- For disaster recovery, use the encrypted cold backup + paper phrase
- If the hot key is compromised, rotate immediately:
  1. Generate new wallet
  2. Transfer funds
  3. Update hot.key
  4. Re-backup

USAGE:
    from hotwallet import HotWallet
    w = HotWallet()  # loads from ~/workspace/.spellbook/hot.key
    print(w.address)  # 0x...
    # Sign a transaction:
    signed = w.sign_transaction(tx_dict)
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "workspace" / "spellbook" / "src"))

HOT_KEY_PATH = Path.home() / "workspace" / ".spellbook" / "hot.key"

class HotWallet:
    def __init__(self, key_path=None):
        self.key_path = Path(key_path) if key_path else HOT_KEY_PATH
        if not self.key_path.exists():
            raise FileNotFoundError(
                f"Hot key not found at {self.key_path}. "
                "Run setup_hot_wallet() first, or restore from backup."
            )
        # Verify permissions are restrictive
        stat = self.key_path.stat()
        if stat.st_mode & 0o077:
            raise PermissionError(
                f"Hot key file {self.key_path} has overly permissive mode "
                f"{oct(stat.st_mode)}. Run: chmod 600 {self.key_path}"
            )
        with open(self.key_path, 'r') as f:
            key_hex = f.read().strip()
        # Validate format (64 hex chars, optional 0x prefix)
        key_hex = key_hex.replace("0x", "")
        if len(key_hex) != 64 or not all(c in "0123456789abcdefABCDEF" for c in key_hex):
            raise ValueError("Invalid private key format in hot.key")
        self._privkey = bytes.fromhex(key_hex)
        # Derive address (cache it, don't recompute)
        from spellbook.evm import address_from_privkey
        self._address = address_from_privkey(self._privkey)
    
    @property
    def address(self):
        return self._address
    
    def sign_transaction(self, tx):
        """
        Sign an EVM transaction dict.
        tx must include: to, value, gas, gasPrice/maxFeePerGas, nonce, chainId, data
        Returns the signed transaction (ready to broadcast).
        """
        from eth_account import Account
        acct = Account.from_key(self._privkey)
        signed = acct.sign_transaction(tx)
        return signed
    
    def sign_message(self, message):
        """Sign an arbitrary message (EIP-191)."""
        from eth_account import Account, messages
        acct = Account.from_key(self._privkey)
        msg = messages.encode_defunct(text=message)
        signed = acct.sign_message(msg)
        return signed.signature.hex()

def setup_hot_wallet(privkey_hex, overwrite=False):
    """
    Initialize the hot wallet file.
    Call once during setup. The key is written with 600 permissions.
    """
    if HOT_KEY_PATH.exists() and not overwrite:
        raise FileExistsError(
            f"Hot key already exists at {HOT_KEY_PATH}. "
            "Use overwrite=True to replace (will invalidate old key)."
        )
    HOT_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Normalize: ensure 64 hex chars, no 0x prefix in file
    key_hex = privkey_hex.replace("0x", "").lower()
    if len(key_hex) != 64:
        raise ValueError("Private key must be 64 hex characters")
    with open(HOT_KEY_PATH, 'w') as f:
        f.write(key_hex)
    os.chmod(HOT_KEY_PATH, 0o600)
    # Verify by loading
    w = HotWallet()
    print(f"Hot wallet initialized: {w.address}")
    print(f"Key file: {HOT_KEY_PATH} (600 permissions)")
    return w.address

def rotate_hot_wallet(new_privkey_hex):
    """Replace the hot key (e.g., after compromise)."""
    return setup_hot_wallet(new_privkey_hex, overwrite=True)

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Spellbook hot wallet manager")
    p.add_argument("cmd", choices=["address", "setup", "rotate"],
                   help="address: show wallet address; setup: init from SPELLBOOK_PRIVKEY env; rotate: replace key")
    a = p.parse_args()
    
    if a.cmd == "address":
        w = HotWallet()
        print(w.address)
    elif a.cmd in ("setup", "rotate"):
        key = os.environ.get("SPELLBOOK_PRIVKEY", "").strip()
        if not key:
            print("Set SPELLBOOK_PRIVKEY env var with the 0x... private key", file=sys.stderr)
            sys.exit(1)
        if a.cmd == "setup":
            setup_hot_wallet(key)
        else:
            rotate_hot_wallet(key)
        # Clear from env
        os.environ.pop("SPELLBOOK_PRIVKEY", None)

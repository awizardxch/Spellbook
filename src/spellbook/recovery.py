#!/usr/bin/env python3
"""
Spellbook Key Recovery Tool.

BACKUP: Run this NOW while the VM still has your keys.
        It will display your 24-word recovery phrase and private key.
        Write them down on paper, offline, two copies in two places.

RECOVER: If the VM is wiped, use your paper backup to restore.
         Run: python3 recovery.py restore

WARNING: Anyone with your recovery phrase or private key controls your funds.
         Never share them. Never store them in chat, email, or cloud notes.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "workspace" / "spellbook" / "src"))

SEED_PATH = Path.home() / ".spellbook-testnet" / "seed.key"
BACKUP_DIR = Path.home() / "workspace" / ".spellbook" / "backups"

def load_seed():
    """Load the raw seed from the VM."""
    if not SEED_PATH.exists():
        print(f"ERROR: Seed file not found at {SEED_PATH}")
        print("The VM may have been wiped. If you have a paper backup, use 'restore'.")
        sys.exit(1)
    with open(SEED_PATH, 'rb') as f:
        data = f.read()
    return data

def seed_to_mnemonic(seed_bytes):
    """Convert seed bytes to BIP-39 mnemonic."""
    # The seed.key file contains 64 ASCII hex chars = 32 bytes
    # 32 bytes = 256 bits = 24-word mnemonic
    try:
        from mnemonic import Mnemonic
    except ImportError:
        print("Installing mnemonic package...")
        os.system(f"{sys.executable} -m pip install --break-system-packages -q mnemonic")
        from mnemonic import Mnemonic
    
    # If it's ASCII hex, decode it
    if len(seed_bytes) == 64 and all(c in b'0123456789abcdefABCDEF' for c in seed_bytes):
        entropy = bytes.fromhex(seed_bytes.decode('ascii'))
    elif len(seed_bytes) == 32:
        entropy = seed_bytes
    else:
        print(f"ERROR: Unexpected seed length {len(seed_bytes)}")
        sys.exit(1)
    
    mnemo = Mnemonic("english")
    return mnemo.to_mnemonic(entropy)

def mnemonic_to_addresses(mnemonic):
    """Derive addresses from mnemonic."""
    from mnemonic import Mnemonic
    from spellbook import stdkeys
    
    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic):
        print("ERROR: Invalid mnemonic")
        sys.exit(1)
    
    seed = mnemo.to_seed(mnemonic, passphrase="")
    priv = stdkeys.evm_privkey(seed)
    addr = stdkeys.evm_address(priv)
    return priv, addr

def cmd_backup():
    """Display all keys for paper backup: master seed + individual chain keys."""
    print("=" * 70)
    print("SPELLBOOK KEY BACKUP — ALL CHAINS")
    print("=" * 70)
    print()
    print("WRITE THESE DOWN NOW on paper, offline, two copies in two places.")
    print("Anyone with these controls your funds. Never share them.")
    print()
    print("The 24-word phrase restores EVERYTHING (all chains).")
    print("Individual private keys are for importing ONE chain into a wallet")
    print("(e.g., EVM key into MetaMask) without exposing the master.")
    print()
    
    seed_data = load_seed()
    mnemonic = seed_to_mnemonic(seed_data)
    
    # Get the BIP-39 seed (64 bytes) — the master seed
    from mnemonic import Mnemonic
    mnemo = Mnemonic("english")
    master_seed = mnemo.to_seed(mnemonic, passphrase="")
    
    # Derive individual chain keys
    from spellbook import stdkeys
    evm_priv = stdkeys.evm_privkey(master_seed)
    evm_addr = stdkeys.evm_address(evm_priv)
    chia_sk = stdkeys.chia_master_sk(master_seed)
    
    print("-" * 70)
    print("1. MASTER SEED (64 bytes hex) — restores everything")
    print("-" * 70)
    print(f"  {master_seed.hex()}")
    print()
    
    print("-" * 70)
    print("2. 24-WORD RECOVERY PHRASE — restores everything")
    print("-" * 70)
    words = mnemonic.split()
    for i in range(0, 24, 4):
        chunk = words[i:i+4]
        nums = [f"{i+j+1:2d}." for j in range(len(chunk))]
        pairs = [f"{n} {w}" for n, w in zip(nums, chunk)]
        print("  " + "   ".join(pairs))
    print()
    
    print("-" * 70)
    print("3. EVM PRIVATE KEY — import into MetaMask (one chain only)")
    print(f"   Address: {evm_addr}")
    print("-" * 70)
    print(f"  0x{evm_priv.hex()}")
    print()
    
    print("-" * 70)
    print("4. CHIA MASTER SECRET KEY — for Chia wallet import")
    print("-" * 70)
    print(f"  {chia_sk.hex()}")
    print()
    
    print("=" * 70)
    print("ADDRESSES (for verification, safe to share):")
    print(f"  EVM:  {evm_addr}")
    print("=" * 70)
    print()
    print("Confirm: Have you written these down? (yes/no)")

def cmd_restore():
    """Restore from paper backup."""
    print("=" * 70)
    print("SPELLBOOK KEY RESTORE")
    print("=" * 70)
    print()
    print("Enter your 24-word recovery phrase (space-separated):")
    mnemonic = input("> ").strip()
    
    from mnemonic import Mnemonic
    mnemo = Mnemonic("english")
    if not mnemo.check(mnemonic):
        print("ERROR: Invalid mnemonic. Check for typos.")
        sys.exit(1)
    
    # Convert back to seed format and write to seed.key
    entropy = mnemo.to_entropy(mnemonic)
    hex_seed = entropy.hex()
    
    SEED_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SEED_PATH, 'w') as f:
        f.write(hex_seed)
    os.chmod(SEED_PATH, 0o600)
    
    priv, addr = mnemonic_to_addresses(mnemonic)
    print()
    print(f"Key restored. Address: {addr}")
    print(f"Seed written to {SEED_PATH}")

def cmd_addresses():
    """Show derived addresses without revealing keys."""
    seed_data = load_seed()
    mnemonic = seed_to_mnemonic(seed_data)
    priv, addr = mnemonic_to_addresses(mnemonic)
    print(f"EVM Address: {addr}")
    # Don't print the private key

def cmd_reveal(key_type):
    """
    Reveal a single key value (for dashboard API).
    Prints ONLY the value, no formatting — for programmatic use.
    WARNING: Only call this from human-authenticated contexts.
    """
    seed_data = load_seed()
    mnemonic = seed_to_mnemonic(seed_data)
    
    from mnemonic import Mnemonic
    mnemo = Mnemonic("english")
    master_seed = mnemo.to_seed(mnemonic, passphrase="")
    
    from spellbook import stdkeys
    
    if key_type == "mnemonic":
        print(mnemonic)
    elif key_type == "evm-key":
        evm_priv = stdkeys.evm_privkey(master_seed)
        print(f"0x{evm_priv.hex()}")
    elif key_type == "chia-key":
        chia_sk = stdkeys.chia_master_sk(master_seed)
        print(chia_sk.hex())
    else:
        print(f"Unknown key type: {key_type}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 recovery.py backup     - Display keys for paper backup")
        print("  python3 recovery.py restore    - Restore from paper backup")
        print("  python3 recovery.py addresses  - Show addresses only (no keys)")
        print("  python3 recovery.py reveal <type> - Reveal one key (mnemonic|evm-key|chia-key)")
        sys.exit(1)
    
    cmd = sys.argv[1]
    if cmd == "backup":
        cmd_backup()
    elif cmd == "restore":
        cmd_restore()
    elif cmd == "addresses":
        cmd_addresses()
    elif cmd == "reveal":
        if len(sys.argv) < 3:
            print("Usage: python3 recovery.py reveal <mnemonic|evm-key|chia-key>", file=sys.stderr)
            sys.exit(1)
        cmd_reveal(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

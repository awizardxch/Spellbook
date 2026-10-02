#!/usr/bin/env python3
"""
Spellbook Address Derivator — derives ALL current addresses from seed material.

Accepts EITHER:
  - 64 hex chars (32 bytes): the daemon seed -> custom labeled KDF ("kdf" mode)
  - 128 hex chars (64 bytes): the BIP-39 seed -> standards derivation
    ("standard" mode: EVM = BIP-32 m/44'/60'/0'/0/0, Solana = SLIP-0010
    m/44'/501'/0'/0', Chia = BLS key_gen + [12381,8444,2,index] + synthetic)

Usage: echo "<hex>" | python3 derive_addresses.py
   or: python3 derive_addresses.py (prompts securely via getpass)

Outputs EVM, Solana, and Chia (xch1...) addresses for the "default" label.
This is the single source of truth — run this after every seed change and
bind ALL output addresses to the dashboard viewer token. Never bind a
subset (that's how the Sept 2026 stale-Chia incident happened).

Requires: the ~/workspace/.pydeps/site-packages deps (coincurve, pycryptodome,
py_ecc, blspy, solders).
"""
import sys
import os
import getpass

# Add persistent deps
PYDEPS = os.path.expanduser("~/workspace/.pydeps/site-packages")
if PYDEPS not in sys.path:
    sys.path.insert(0, PYDEPS)

# Import Spellbook KDF
sys.path.insert(0, os.path.expanduser("~/workspace/spellbook/src"))
from spellbook import kdf
from spellbook import solana as solana_mod
from spellbook import chia_sign
from spellbook import stdkeys


def derive_all_kdf(seed: bytes) -> dict:
    """Custom labeled KDF from the 32-byte daemon seed ("kdf" mode)."""
    out = {}
    # EVM (Robinhood mainnet chain 4663, label "default")
    evm = kdf.derive_labeled(seed, "evm-4663", "default")
    out["evm_mainnet"] = evm["address"]
    # Solana mainnet (custom labeled seed, label "default")
    sol_kp = solana_mod.custom_keypair(seed, "solana-mainnet", "default")
    out["solana_mainnet"] = solana_mod.address_of_keypair(sol_kp)
    # Chia mainnet — BLS master scalar -> index-0 standard receive address
    chia = kdf.derive_labeled(seed, "chia-mainnet", "default")
    master_sk_bytes = bytes.fromhex(chia["scalar_hex"])
    out["chia_mainnet"] = chia_sign.receive_address(master_sk_bytes, 0, "mainnet")
    return out


def derive_all_standard(seed64: bytes) -> dict:
    """Standards derivation from the 64-byte BIP-39 seed ("standard" mode)."""
    out = {}
    # EVM: BIP-32 m/44'/60'/0'/0/0 (same address on every EVM chain)
    out["evm_mainnet"] = stdkeys.evm_address(stdkeys.evm_privkey(seed64))
    # Solana: SLIP-0010 m/44'/501'/0'/0'
    out["solana_mainnet"] = solana_mod.address_of_keypair(
        solana_mod.standard_keypair(seed64))
    # Chia: BLS key_gen master -> [12381,8444,2,0] + synthetic key
    out["chia_mainnet"] = chia_sign.receive_address(
        stdkeys.chia_master_sk(seed64), 0, "mainnet")
    return out


def derive_all(seed_hex: str) -> dict:
    seed_hex = seed_hex.strip().lower()
    if len(seed_hex) == 64 and all(c in "0123456789abcdef" for c in seed_hex):
        return derive_all_kdf(bytes.fromhex(seed_hex))
    if len(seed_hex) == 128 and all(c in "0123456789abcdef" for c in seed_hex):
        return derive_all_standard(bytes.fromhex(seed_hex))
    raise ValueError("seed must be 64 hex chars (32-byte daemon seed) or "
                     "128 hex chars (64-byte BIP-39 std seed)")


def seed_mode(seed_hex: str) -> str:
    s = seed_hex.strip().lower()
    if len(s) == 64:
        return "kdf"
    if len(s) == 128:
        return "standard"
    return "invalid"


def main():
    if not sys.stdin.isatty():
        seed_hex = sys.stdin.read().strip()
    else:
        seed_hex = getpass.getpass("seed hex (64 or 128 chars, hidden): ").strip()

    try:
        mode = seed_mode(seed_hex)
        addrs = derive_all(seed_hex)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"=== Spellbook addresses (mode: {mode}, label: default) ===")
    print(f"evm_mainnet:    {addrs['evm_mainnet']}")
    print(f"solana_mainnet: {addrs['solana_mainnet']}")
    print(f"chia_mainnet:   {addrs['chia_mainnet']}")
    print()
    print("Bind ALL THREE to the dashboard viewer token.")


if __name__ == "__main__":
    main()

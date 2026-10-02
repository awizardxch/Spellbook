#!/usr/bin/env python3
"""
Spellbook Address Derivator — derives ALL current addresses from the 32-byte seed.

Usage: echo "<64-hex-chars>" | python3 derive_addresses.py
   or: python3 derive_addresses.py (prompts securely via getpass)

Outputs EVM, Solana, and Chia (xch1...) addresses for the "default" label.
This is the single source of truth — run this after every seed change and
bind ALL output addresses to the dashboard viewer token. Never bind a
subset (that's how the Sept 2026 stale-Chia incident happened).

Requires: the ~/workspace/.pydeps/site-packages deps (coincurve, pycryptodome, py_ecc).
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


def derive_all(seed_hex: str) -> dict:
    seed_hex = seed_hex.strip().lower()
    if len(seed_hex) != 64 or not all(c in "0123456789abcdef" for c in seed_hex):
        raise ValueError("seed must be 64 hex chars (32 bytes)")
    seed = bytes.fromhex(seed_hex)

    out = {}

    # EVM (Robinhood mainnet chain 4663, label "default")
    evm = kdf.derive_labeled(seed, "evm-4663", "default")
    out["evm_mainnet"] = evm["address"]
    # Also derive for other EVM chains (same address, different chain param)
    # — the address is identical across EVM chains for the same (seed, label).

    # Solana mainnet
    sol_kp = solana_mod.custom_keypair(seed, "solana-mainnet", "default")
    out["solana_mainnet"] = solana_mod.address_of_keypair(sol_kp)

    # Chia mainnet — BLS master pubkey -> index-0 standard wallet address
    chia = kdf.derive_labeled(seed, "chia-mainnet", "default")
    master_pk_hex = chia["pubkey_hex"]  # 48-byte compressed G1
    master_sk_bytes = bytes.fromhex(chia["scalar_hex"])
    # receive_address(master_sk, index, network_id) -> xch1... string
    out["chia_mainnet"] = chia_sign.receive_address(master_sk_bytes, 0, "mainnet")

    return out


def main():
    if not sys.stdin.isatty():
        seed_hex = sys.stdin.read().strip()
    else:
        seed_hex = getpass.getpass("32-byte seed hex (64 chars, hidden): ").strip()

    try:
        addrs = derive_all(seed_hex)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print("=== Spellbook addresses (label: default) ===")
    print(f"evm_mainnet:    {addrs['evm_mainnet']}")
    print(f"solana_mainnet: {addrs['solana_mainnet']}")
    print(f"chia_mainnet:   {addrs['chia_mainnet']}")
    print()
    print("Bind ALL THREE to the dashboard viewer token.")


if __name__ == "__main__":
    main()

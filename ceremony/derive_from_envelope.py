#!/usr/bin/env python3
"""
Decrypt a SPELLBOOK-SEED-ENC2 envelope and derive ALL Spellbook addresses.

Runs as the spellbook DAEMON user (or root) only (review S-16): the
envelope is sealed to the daemon's ceremony key,
<prefix>/ceremony/private.pem (0600, 0700 dir), which the agent cannot
read. An agent that wants the addresses asks the daemon instead
(`spellbook addresses`), which is what the daemon decrypted at start.

Usage: sudo -u spellbook python3 derive_from_envelope.py [--prefix /opt/spellbook]
  Paste the envelope when prompted, then Enter on an empty line.

The script:
  1. Unwraps the AES key with the daemon's ceremony key.
  2. Derives EVM, Solana, and Chia addresses from the seed in one run.
  3. Verifies EVM and Solana against the known wallet anchors and FAILS
     CLOSED on any mismatch or missing chain. It never fills an address
     from memory, notes, or an older viewer token.

On success it prints the three addresses. Mint a fresh viewer token ONLY
from this output, binding ALL THREE.
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "src"))

# Known-good anchors for the CURRENT wallet (SET 1, sealed 2026-09-29).
# Updated only by re-deriving from the authoritative current seed material.
ANCHOR_EVM = "0xb82a43e774e71524d942afe8fb125183a491cf91"
ANCHOR_SOLANA = "HGyuCUs3fPAne9fak3AD78gHJYQVAe8piWVZ2YxitN9j"


def decrypt_envelope(envelope: str, prefix: str) -> str:
    from spellbook import custody
    key = custody.read_private_key(custody.ceremony_key_path(prefix),
                                   custody.prefix_owner(prefix))
    return custody.decrypt_envelope(envelope, key, allow_custom=True).hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default="/opt/spellbook")
    args = ap.parse_args()
    print("Paste the SPELLBOOK-SEED-ENC2 envelope (then Enter on empty line):")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip() and lines:
            break
        lines.append(line.strip())
    envelope = "".join(lines)
    if not envelope:
        print("ERROR: no envelope provided", file=sys.stderr)
        sys.exit(1)

    try:
        seed_hex = decrypt_envelope(envelope, args.prefix)
    except Exception as e:
        print(f"ERROR: decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from derive_addresses import derive_all, seed_mode
    try:
        mode = seed_mode(seed_hex)
        addrs = derive_all(seed_hex)
    except Exception as e:
        print(f"ERROR: derivation failed: {e}", file=sys.stderr)
        sys.exit(1)
    # The seed is no longer needed; drop the reference.
    del seed_hex

    # --- anchor verification: fail closed ---
    problems = []
    if addrs["evm_mainnet"].lower() != ANCHOR_EVM:
        problems.append(
            f"EVM mismatch: derived {addrs['evm_mainnet']} != anchor {ANCHOR_EVM}")
    if addrs["solana_mainnet"] != ANCHOR_SOLANA:
        problems.append(
            f"Solana mismatch: derived {addrs['solana_mainnet']} != anchor {ANCHOR_SOLANA}")
    for chain in ("evm_mainnet", "solana_mainnet", "chia_mainnet"):
        if not addrs.get(chain):
            problems.append(f"missing address for {chain}")
    if problems:
        print("REFUSING TO PROCEED — derived addresses do not verify:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("Do NOT mint a viewer token. Re-check the seed material and key mode.",
              file=sys.stderr)
        sys.exit(2)

    print()
    print(f"=== Spellbook addresses (mode: {mode}, label: default) — VERIFIED ===")
    print(f"evm_mainnet:    {addrs['evm_mainnet']}")
    print(f"solana_mainnet: {addrs['solana_mainnet']}")
    print(f"chia_mainnet:   {addrs['chia_mainnet']}")
    print()
    print("EVM and Solana match the known wallet anchors.")
    print("Bind ALL THREE to the dashboard viewer token.")


if __name__ == "__main__":
    main()

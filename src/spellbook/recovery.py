#!/usr/bin/env python3
"""
Spellbook Key Recovery Tool.

BACKUP: Run this NOW while the VM still has your keys.
        It displays the daemon's recovery words and live private keys.
        Write them down on paper, offline, two copies in two places.
        For wipe-proof recovery without re-typing words, also SEAL the
        seed with a password: `spellbook-seed serve` (docs/SEALED_SEED.md).

RECOVER: If the VM is wiped:
         - sealed seed:  `spellbook-seed serve` -> human enters the password
         - paper only:   python3 -m spellbook.recovery restore [--standard]

Paths come from the daemon's spellbook.json (see spellbook.sealed.locate):
$SPELLBOOK_CONFIG_DIR, ~/.spellbook-testnet, or /opt/spellbook.

Two recovery sets exist (SPEC §2 / §2b, install.sh):
  SET 1 standard  std_seed.key (64-byte BIP-39 seed). The daemon's LIVE keys
                  when key_derivation=standard (every install.sh install).
                  Its 24 words cannot be re-derived from the file (BIP-39
                  seeds are one-way) — only the paper holds them.
  SET 2 daemon    seed.key (32 bytes of entropy). Its 24 words ARE the
                  file, so they can always be shown again.

WARNING: Anyone with your recovery phrase or private key controls your funds.
         Never share them. Never store them in chat, email, or cloud notes.
"""
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "workspace" / "spellbook" / "src"))

from spellbook import sealed  # noqa: E402
from spellbook.seed import (  # noqa: E402
    entropy_from_mnemonic,
    load_seed,
    load_std_seed,
    mnemonic_from_entropy,
    mnemonic_to_seed,
)


def _need(path, what):
    if not path or not os.path.exists(path):
        print(f"ERROR: {what} not found at {path}", file=sys.stderr)
        print("The VM may have been wiped. Unlock the sealed seed "
              "(spellbook-seed serve) or restore from paper (restore).",
              file=sys.stderr)
        sys.exit(1)


def live_evm(loc, chain="evm-4663"):
    """(privkey_hex, address) the daemon signs with on an EVM chain."""
    if loc["key_derivation"] == "standard":
        from spellbook import stdkeys
        _need(loc["std_seed_path"], "std seed")
        priv = stdkeys.evm_privkey(load_std_seed(loc["std_seed_path"]))
        return priv.hex(), stdkeys.evm_address(priv)
    from spellbook import kdf
    _need(loc["seed_path"], "seed")
    d = kdf.derive_labeled(load_seed(loc["seed_path"]), chain, "default")
    return d["scalar_hex"], d["address"]


def live_chia_sk(loc, chain="chia-testnet"):
    """The BLS master secret (hex) the daemon uses for Chia."""
    if loc["key_derivation"] == "standard":
        from spellbook import stdkeys
        _need(loc["std_seed_path"], "std seed")
        return stdkeys.chia_master_sk(load_std_seed(loc["std_seed_path"])).hex()
    from spellbook import kdf
    _need(loc["seed_path"], "seed")
    return kdf.derive_labeled(load_seed(loc["seed_path"]), chain,
                              "default")["scalar_hex"]


def cmd_backup(loc):
    """Display what the paper backup needs, for the keys the daemon uses."""
    _need(loc["seed_path"], "seed")
    print("=" * 70)
    print("SPELLBOOK KEY BACKUP")
    print("=" * 70)
    print("WRITE THESE DOWN NOW on paper, offline, two copies in two places.")
    print("Anyone with these controls your funds. Never share them.")
    print(f"Live key derivation: {loc['key_derivation']}")
    print()
    if loc["key_derivation"] == "standard":
        print("-" * 70)
        print("SET 1 — STANDARD RECOVERY (the daemon's live keys)")
        print("-" * 70)
        print("  The 24 words were shown ONCE at install and cannot be re-derived")
        print("  from std_seed.key. If you lost them, back up the raw keys below")
        print("  AND seal the seed (spellbook-seed serve).")
        print()
    print("-" * 70)
    print("SET 2 — DAEMON SEED, 24 WORDS (recovers through Spellbook only)")
    print("-" * 70)
    words = mnemonic_from_entropy(load_seed(loc["seed_path"])).split()
    for i in range(0, 24, 4):
        print("  " + "   ".join(f"{i + j + 1:2d}. {w}"
                                for j, w in enumerate(words[i:i + 4])))
    print()
    evm_priv, evm_addr = live_evm(loc)
    print("-" * 70)
    print("EVM PRIVATE KEY (live) — MetaMask 'Import account'")
    print(f"   Address: {evm_addr}")
    print("-" * 70)
    print(f"  0x{evm_priv}")
    print()
    try:
        chia = live_chia_sk(loc)
        print("-" * 70)
        print("CHIA BLS MASTER KEY (live) — Sage 'Import private key'")
        print("-" * 70)
        print(f"  {chia}")
        print()
    except ImportError as e:
        print(f"(Chia key skipped: {e.name} not installed)")
    print("=" * 70)
    print(f"ADDRESS (safe to share): EVM {evm_addr}")
    print("=" * 70)


def cmd_restore(loc, standard=False):
    """Restore a seed file from its paper words (never overwrites)."""
    target = loc["std_seed_path"] if standard else loc["seed_path"]
    if standard and not target:
        target = os.path.join(os.path.dirname(loc["seed_path"]), "std_seed.key")
    if os.path.exists(target):
        print(f"ERROR: {target} already exists — refusing to overwrite a "
              "live wallet.", file=sys.stderr)
        sys.exit(1)
    which = "SET 1 (standard)" if standard else "SET 2 (daemon seed)"
    print(f"Enter the 24 words of {which}, space-separated (input hidden):")
    mnemonic = " ".join(getpass.getpass("> ").strip().lower().split())
    try:
        entropy = entropy_from_mnemonic(mnemonic)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    if standard:
        value = mnemonic_to_seed(mnemonic).hex()
    else:
        if len(entropy) != 32:
            print("ERROR: the daemon seed is 24 words", file=sys.stderr)
            sys.exit(1)
        value = entropy.hex()
    sealed._write_private(target, value)
    print(f"Restored {target} (0600).")
    print("Next: seal it so the next wipe needs only your password:")
    print("  spellbook-seed serve")


def cmd_addresses(loc):
    """Show the live EVM address without revealing keys."""
    _, addr = live_evm(loc)
    print(f"EVM Address: {addr}")


def cmd_reveal(loc, key_type, chain=None):
    """
    Reveal a single key value (for the dashboard API).
    Prints ONLY the value on stdout — for programmatic use.
    WARNING: Only call this from human-authenticated contexts.

    Keys follow the daemon's live derivation (key_derivation in
    spellbook.json): standard -> BIP-32 / BLS key_gen from std_seed.key
    (the same EVM key on every chain, as MetaMask does); kdf -> the
    labeled KDF over seed.key, a distinct key per `chain`.
    - mnemonic: the 24 words of the daemon seed (SET 2).
    """
    if key_type == "mnemonic":
        _need(loc["seed_path"], "seed")
        print(mnemonic_from_entropy(load_seed(loc["seed_path"])))
    elif key_type == "evm-key":
        chain = chain or "evm-4663"
        if not chain.startswith("evm-"):
            print(f"evm-key needs an evm-<chain_id> chain, got {chain!r}",
                  file=sys.stderr)
            sys.exit(1)
        priv, addr = live_evm(loc, chain)
        print(f"0x{priv}")
        print(f"address {addr} ({chain}, {loc['key_derivation']})",
              file=sys.stderr)
    elif key_type == "chia-key":
        print(live_chia_sk(loc, chain or "chia-testnet"))
    else:
        print(f"Unknown key type: {key_type}", file=sys.stderr)
        sys.exit(1)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="python3 -m spellbook.recovery")
    ap.add_argument("--config-dir", help="dir holding spellbook.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backup", help="display keys for paper backup")
    r = sub.add_parser("restore", help="restore a seed file from paper words")
    r.add_argument("--standard", action="store_true",
                   help="restore SET 1 (std_seed.key) instead of SET 2")
    sub.add_parser("addresses", help="show addresses only (no keys)")
    v = sub.add_parser("reveal", help="reveal one key (mnemonic|evm-key|chia-key)")
    v.add_argument("type")
    v.add_argument("--chain")
    a = ap.parse_args(argv)
    loc = sealed.locate(a.config_dir)
    if a.cmd == "backup":
        cmd_backup(loc)
    elif a.cmd == "restore":
        cmd_restore(loc, a.standard)
    elif a.cmd == "addresses":
        cmd_addresses(loc)
    elif a.cmd == "reveal":
        cmd_reveal(loc, a.type, a.chain)


if __name__ == "__main__":
    main()

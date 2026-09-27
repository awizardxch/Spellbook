#!/usr/bin/env python3
"""Create the persistent Spellbook testnet wallet (one-time).

Security contract (SPEC S7/O10, seed.py hard rules):
- The mnemonic and seed hex are NEVER printed to stdout/stderr, logged,
  or returned. They go to exactly two files and nowhere else.
- seed.key: 0600, daemon home only.
- Paper backup: the human's file. The conversational agent must not
  read it back after writing.
- Refuses to run if a seed already exists (never overwrite a live wallet).

Derivation matches the daemon's relay path exactly:
  kdf.derive_labeled(seed, "chia-testnet", "default") -> master_sk
  -> chia_sign.wallet_sk(master_sk, 0) -> synthetic pk -> puzzle hash
  -> bech32m "txch" address (index 0).

Prints ONLY public material: the txch1 address, its puzzle hash, and
file paths.
"""
import os
import stat
import sys

HOME = os.path.expanduser("~")
DAEMON_HOME = os.path.join(HOME, ".spellbook-testnet")
SEED_PATH = os.path.join(DAEMON_HOME, "seed.key")
BACKUP_PATH = os.path.join(HOME, "workspace", "your_files",
                            "spellbook-testnet-paper-backup.md")


def fail(msg: str) -> None:
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if os.path.exists(SEED_PATH):
        fail(f"{SEED_PATH} already exists — will not overwrite a live wallet")
    if os.path.exists(BACKUP_PATH):
        fail(f"{BACKUP_PATH} already exists — will not overwrite a live backup")

    sys.path.insert(0, os.path.join(HOME, "workspace", "spellbook", "src"))
    from spellbook import chia_sign, kdf
    from spellbook.seed import generate_entropy, mnemonic_from_entropy

    entropy = generate_entropy()  # 32 bytes, OS CSPRNG — the wallet's root
    mnemonic = mnemonic_from_entropy(entropy)

    os.makedirs(DAEMON_HOME, mode=0o700, exist_ok=True)
    # seed.key: 64 hex chars, 0600. Written via os.open to avoid any
    # window where the file exists with loose permissions.
    fd = os.open(SEED_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(entropy.hex())
    st = os.stat(SEED_PATH)
    if st.st_mode & 0o077:
        fail("seed file permissions are not 0600")

    # Paper backup — the human's recovery path. Written, never printed.
    with open(BACKUP_PATH, "w") as f:
        f.write("# Spellbook testnet wallet — paper backup\n\n")
        f.write("Created: 2026-09-21. Network: Chia testnet11 (THWACK: testnet\n")
        f.write("coins are worthless; this wallet is for drills and validation).\n\n")
        f.write("These 24 words recover the wallet's seed. They also recover the\n")
        f.write("FUTURE mainnet wallet (one seed covers both networks — different\n")
        f.write("derived keys, txch1 vs xch1 addresses). Store them offline,\n")
        f.write("on paper, away from this machine. Never type them into any\n")
        f.write("website, chat, or app — the Spellbook dashboard and relay\n")
        f.write("will NEVER ask for them.\n\n")
        f.write("## Recovery words\n\n")
        f.write(mnemonic + "\n")

    # Public material only from here down.
    d = kdf.derive_labeled(entropy, "chia-testnet", "default")
    master_sk = bytes.fromhex(d["scalar_hex"])
    wsk = chia_sign.wallet_sk(master_sk, 0)
    spk = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk))
    ph = chia_sign.puzzle_hash_for_synthetic_pk(spk)
    addr = chia_sign.address_for_puzzle_hash(ph, "txch")

    print("wallet created")
    print(f"  address:      {addr}")
    print(f"  puzzle_hash:  {ph.hex()}")
    print(f"  seed:         {SEED_PATH} (0600, never printed)")
    print(f"  paper backup: {BACKUP_PATH} (24 words, for the human only)")
    print("next: fund the address from the testnet faucet, then run validation")


if __name__ == "__main__":
    main()

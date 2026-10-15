#!/usr/bin/env python3
"""Create the standard-recovery wallet for a Spellbook install (one-time).

Generates a SECOND, independent 24-word BIP-39 mnemonic ("standard
recovery") alongside the daemon's custom-KDF seed. The same words load
directly in stock wallets:

  - Chia: BLS key_gen master key -> standard wallet path [12381, 8444, 2, i]
    + synthetic key. Import the words into Sage and the first receive
    address matches the txch1/xch1 printed below.
  - EVM: BIP-32 m/44'/60'/0'/0/0. Import the words into MetaMask and the
    0x address matches.
  - Solana: SLIP-0010 m/44'/501'/0'/0' (Phantom/Solflare first account).

Security contract (SPEC S3/S7/O10, seed.py hard rules; review S-05):
- NOTHING secret is printed. Not the words, not the seed, not a raw key.
  This script's stdout is public material only (addresses + file paths),
  so an installer run by an agent, a CI job or under `script` leaks
  nothing. The paper backup is shown later by `spellbook export`, which
  requires a terminal and the human's login (never the agent's user).
- std_seed.key: 128 hex chars (64-byte BIP-39 seed), 0600 — the daemon's
  live keys. std_entropy.key: the 32-byte entropy behind the words, 0600 —
  what `spellbook export` turns back into the 24 words. Same custody, same
  blast radius as std_seed.key (the seed is derived from it).
- Refuses to run if either file already exists (never overwrite).

Usage: make_standard_wallet.py <prefix>
"""

import os
import sys


def fail(msg: str) -> None:
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(1)


def write_secret_file(path: str, hex_text: str) -> None:
    """Create `path` 0600 and exclusive; it never exists with loose modes."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(hex_text)
    if os.name == "posix" and os.stat(path).st_mode & 0o077:
        fail(f"{path} permissions are not 0600")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: make_standard_wallet.py <prefix>")
    prefix = sys.argv[1]
    std_seed_path = os.path.join(prefix, "std_seed.key")
    std_entropy_path = os.path.join(prefix, "std_entropy.key")
    for p in (std_seed_path, std_entropy_path):
        if os.path.exists(p):
            fail(f"{p} already exists — will not overwrite")

    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "src"))
    from spellbook import chia_sign, stdkeys
    from spellbook import solana as solana_mod
    from spellbook.seed import generate_entropy, mnemonic_from_entropy

    entropy = generate_entropy()  # 32 bytes, OS CSPRNG — independent of the KDF seed
    mnemonic = mnemonic_from_entropy(entropy)
    seed64 = stdkeys.mnemonic_to_seed(mnemonic)  # checksum-validated, empty passphrase
    if stdkeys.validate_mnemonic(mnemonic) != entropy:
        fail("mnemonic round-trip failed")
    del mnemonic

    # Public material: the addresses the human verifies after any import.
    chia_master = stdkeys.chia_master_sk(seed64)
    evm_addr = stdkeys.evm_address(stdkeys.evm_privkey(seed64))
    txch_addr = chia_sign.receive_address(chia_master, 0, "testnet11")
    xch_addr = chia_sign.receive_address(chia_master, 0, "mainnet")
    sol_addr = solana_mod.address_of_keypair(solana_mod.standard_keypair(seed64))

    write_secret_file(std_seed_path, seed64.hex())
    write_secret_file(std_entropy_path, entropy.hex())

    print(f"""\
standard-recovery wallet created (public material only; the words are shown
by `spellbook export`, on a terminal, to the human — never here).
  EVM address (every chain)   {evm_addr}
  Chia testnet11 address      {txch_addr}
  Chia mainnet address        {xch_addr}
  Solana address (any net)    {sol_addr}
  std seed:     {std_seed_path} (0600, never printed)
  std entropy:  {std_entropy_path} (0600, never printed)""")


if __name__ == "__main__":
    main()

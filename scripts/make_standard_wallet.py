#!/usr/bin/env python3
"""Create the standard-recovery wallet for a Spellbook install (one-time).

Generates a SECOND, independent 24-word BIP-39 mnemonic ("standard
recovery") alongside the daemon's custom-KDF seed. The same words load
directly in stock wallets:

  - Chia: BLS key_gen master key -> standard wallet path [12381, 8444, 2, i]
    + synthetic key. Import the words (or the raw BLS master key hex) into
    Sage and the first receive address matches the txch1/xch1 printed below.
  - EVM: BIP-32 m/44'/60'/0'/0/0. Import the words into MetaMask (or the raw
    secp256k1 hex as a private key) and the 0x address matches.

Security contract (SPEC S7/O10, seed.py hard rules):
- The mnemonic, seed hex, and raw private keys are NEVER logged and NEVER
  written anywhere except the two files below. They print to STDOUT exactly
  once — install.sh shows that output as the once-only paper backup display.
- std_seed.key: 128 hex chars (64-byte BIP-39 seed), 0600, daemon prefix only.
- Refuses to run if the std seed file already exists (never overwrite).

Usage: make_standard_wallet.py <prefix>
Prints ONLY the paper-backup block (secret) — the caller is responsible for
showing it exactly once.
"""

import os
import stat
import sys


def fail(msg: str) -> None:
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: make_standard_wallet.py <prefix>")
    prefix = sys.argv[1]
    std_seed_path = os.path.join(prefix, "std_seed.key")
    if os.path.exists(std_seed_path):
        fail(f"{std_seed_path} already exists — will not overwrite")

    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "src"))
    from spellbook import chia_sign, stdkeys
    from spellbook.seed import generate_entropy, mnemonic_from_entropy

    entropy = generate_entropy()  # 32 bytes, OS CSPRNG — independent of the KDF seed
    mnemonic = mnemonic_from_entropy(entropy)
    seed64 = stdkeys.mnemonic_to_seed(mnemonic)  # checksum-validated, empty passphrase
    if stdkeys.validate_mnemonic(mnemonic) != entropy:
        fail("mnemonic round-trip failed")

    # Standard keys.
    chia_master = stdkeys.chia_master_sk(seed64)
    evm_priv = stdkeys.evm_privkey(seed64)
    evm_addr = stdkeys.evm_address(evm_priv)
    txch_addr = chia_sign.receive_address(chia_master, 0, "testnet11")
    xch_addr = chia_sign.receive_address(chia_master, 0, "mainnet")
    # Standard Solana key: SLIP-0010 m/44'/501'/0'/0' — the first account
    # Phantom/Solflare show on mnemonic import. Solana addresses are
    # network-agnostic (base58 of the pubkey), so devnet and mainnet-beta
    # share the one address below.
    from spellbook import solana as solana_mod
    sol_kp = solana_mod.standard_keypair(seed64)
    sol_addr = solana_mod.address_of_keypair(sol_kp)
    sol_secret = solana_mod.phantom_backup_secret(sol_kp)

    # std_seed.key: 128 hex chars, 0600, written via os.open so it never
    # exists with loose permissions.
    fd = os.open(std_seed_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seed64.hex())
    st = os.stat(std_seed_path)
    if st.st_mode & 0o077:
        fail("std seed file permissions are not 0600")

    # Once-only paper backup block. Labels are unmistakable: these words and
    # keys work in STOCK wallets (Sage / MetaMask). The daemon's KDF backup
    # (printed separately by install.sh) is the daemon-native recovery set.
    print(f"""\
STANDARD RECOVERY (works in stock wallets — Sage / MetaMask).

  24 WORDS — import into Sage (Chia) or MetaMask (EVM) to recover everything:
    {mnemonic}

  RAW EVM PRIVATE KEY — import into MetaMask as a raw private key:
    {evm_priv.hex()}
    -> address {evm_addr} (same on every EVM chain, as with MetaMask)

  RAW CHIA BLS MASTER KEY — import into Sage as a private key:
    {chia_master.hex()}
    -> testnet11 address {txch_addr}
    -> mainnet   address {xch_addr}

  RAW SOLANA ED25519 SECRET — import into Phantom as a private key:
    {sol_secret}
    -> devnet       address {sol_addr}
    -> mainnet-beta address {sol_addr} (same — Solana addresses are network-agnostic)

  The same 24 words also recover Solana via SLIP-0010 m/44'/501'/0'/0' —
  import the words into Phantom and the first address matches the one above.

  Verify after import: the addresses above must match what the wallet shows.
  The same 24 words recover BOTH networks and the EVM account.""")


if __name__ == "__main__":
    main()

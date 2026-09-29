#!/usr/bin/env python3
"""Convert backed-up mnemonics to an install.sh --restore key file.

The agent decrypts the human's restore blob (from the ceremony HTML page),
which contains SET 1 and SET 2 as 24-word BIP-39 mnemonics. This script
converts them to the two hex keys install.sh expects:

  - Line 1: seed.key hex (64 chars) — 32-byte entropy from SET 1 mnemonic.
  - Line 2: std_seed.key hex (128 chars) — 64-byte BIP-39 seed from SET 2.

Usage:
    restore_from_mnemonics.py "<set1 words>" "<set2 words>" <output_file>

The output file is written 0600. install.sh --restore shreds it after use.

Security: the mnemonics are NEVER logged. They exist only in this process's
memory and the output file (0600), which install.sh shreds.
"""

import os
import stat
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from spellbook.seed import entropy_from_mnemonic, mnemonic_to_seed


def fail(msg: str) -> None:
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 4:
        fail('usage: restore_from_mnemonics.py "<set1 mnemonic>" "<set2 mnemonic>" <output_file>')
    set1, set2, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

    # Validate and convert. These raise on bad checksum/unknown words.
    try:
        entropy32 = entropy_from_mnemonic(set1)
    except Exception as e:
        fail(f"SET 1 mnemonic invalid: {e}")
    try:
        seed64 = mnemonic_to_seed(set2)
    except Exception as e:
        fail(f"SET 2 mnemonic invalid: {e}")

    if len(entropy32) != 32:
        fail(f"SET 1 must decode to 32 bytes, got {len(entropy32)}")
    if len(seed64) != 64:
        fail(f"SET 2 must derive a 64-byte seed, got {len(seed64)}")

    # Write 0600, never log the values.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(out_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(entropy32.hex() + "\n")
            f.write(seed64.hex() + "\n")
    except Exception:
        os.close(fd)
        raise
    # Ensure 0600 even if the file existed with looser perms.
    os.chmod(out_path, 0o600)
    print(f"wrote {out_path} (0600) — shred after install.sh --restore consumes it")


if __name__ == "__main__":
    main()

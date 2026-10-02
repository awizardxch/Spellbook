#!/usr/bin/env python3
"""
Decrypt a SPELLBOOK-SEED-ENC2 envelope and derive ALL Spellbook addresses.

The envelope is hybrid-encrypted (RSA-OAEP-SHA256 + AES-GCM-256) to the
agent's ceremony keypair. There is deliberately NO password step: nothing
secret ever appears in chat, logs, argv, or files.

Usage: python3 derive_from_envelope.py
  Paste the envelope when prompted, then Enter on an empty line.

The script:
  1. Unwraps the AES key with the ceremony private key
     (~/workspace/.spellbook/seed-derive/private.pem, never in the repo).
  2. Derives EVM, Solana, and Chia addresses from the seed in one run.
  3. Verifies EVM and Solana against the known wallet anchors and FAILS
     CLOSED on any mismatch or missing chain. It never fills an address
     from memory, notes, or an older viewer token.

On success it prints the three addresses. Mint a fresh viewer token ONLY
from this output, binding ALL THREE.
"""
import sys
import os
import json
import base64

PYDEPS = os.path.expanduser("~/workspace/.pydeps/site-packages")
if PYDEPS not in sys.path:
    sys.path.insert(0, PYDEPS)
sys.path.insert(0, os.path.expanduser("~/workspace/spellbook/src"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PRIVATE_KEY_PATH = os.path.expanduser(
    "~/workspace/.spellbook/seed-derive/private.pem")

# Known-good anchors for the CURRENT wallet (SET 1, sealed 2026-09-29).
# Updated only by re-deriving from the authoritative current seed material.
ANCHOR_EVM = "0xb82a43e774e71524d942afe8fb125183a491cf91"
ANCHOR_SOLANA = "HGyuCUs3fPAne9fak3AD78gHJYQVAe8piWVZ2YxitN9j"


def decrypt_envelope(envelope: str) -> str:
    envelope = envelope.strip()
    if not envelope.startswith("SPELLBOOK-SEED-ENC2."):
        raise ValueError("not a SPELLBOOK-SEED-ENC2 envelope")
    payload = json.loads(base64.b64decode(envelope.split(".", 1)[1]))
    if payload.get("v") != 2 or \
            payload.get("algo") != "RSA-OAEP-SHA256+AES-GCM-256":
        raise ValueError("unsupported envelope version/algo")
    ek = bytes.fromhex(payload["ek"])
    iv = bytes.fromhex(payload["iv"])
    ct = bytes.fromhex(payload["ct"])

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(),
                                                         password=None)
    aes_key = private_key.decrypt(
        ek,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    seed_hex = AESGCM(aes_key).decrypt(iv, ct, None).decode().strip().lower()
    if len(seed_hex) not in (64, 128) or \
            not all(c in "0123456789abcdef" for c in seed_hex):
        raise ValueError("decrypted payload is not a 64- or 128-char hex seed")
    return seed_hex


def main():
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
        seed_hex = decrypt_envelope(envelope)
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

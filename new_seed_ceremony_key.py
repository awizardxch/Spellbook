#!/usr/bin/env python3
"""
Rotate the ceremony keypair used by seed-to-addresses.html envelopes.

- Generates a fresh RSA-2048 keypair.
- Stores the private key at ~/workspace/.spellbook/seed-derive/private.pem
  (mode 600, outside the repo — never commit it).
- Stamps the public key into the DELIVERED HTML copies so the page can
  seal envelopes only this agent can open.

The repo copy (ceremony/seed-to-addresses.html) keeps the
__SEED_PUB_B64__ placeholder and is never stamped.

Run this at the start of each reseed ceremony, then hand the delivered
page to the human.
"""
import os
import re
import base64
import stat

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEY_DIR = os.path.expanduser("~/workspace/.spellbook/seed-derive")
PRIVATE_PEM = os.path.join(KEY_DIR, "private.pem")
# Delivered copies the human actually opens (same file may appear twice).
DELIVERED = [
    os.path.expanduser("~/workspace/your_files/ceremony/seed-to-addresses.html"),
]

STAMP_RE = re.compile(r'const SEED_PUB_B64 = "[^"]*";')


def main():
    os.makedirs(KEY_DIR, exist_ok=True)
    os.chmod(KEY_DIR, 0o700)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    with open(PRIVATE_PEM, "wb") as f:
        f.write(priv)
    os.chmod(PRIVATE_PEM, 0o600)

    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_b64 = base64.b64encode(pub_der).decode()
    with open(os.path.join(KEY_DIR, "public_b64.txt"), "w") as f:
        f.write(pub_b64)
    os.chmod(os.path.join(KEY_DIR, "public_b64.txt"), 0o600)

    import hashlib
    fp = hashlib.sha256(pub_der).hexdigest()[:32]
    print(f"new key fingerprint: {fp}...")

    for path in DELIVERED:
        if not os.path.exists(path):
            print(f"SKIP (missing): {path}")
            continue
        with open(path) as f:
            html = f.read()
        new_html, n = STAMP_RE.subn(
            f'const SEED_PUB_B64 = "{pub_b64}";', html)
        if n == 0:
            print(f"SKIP (no stamp point): {path}")
            continue
        with open(path, "w") as f:
            f.write(new_html)
        print(f"stamped: {path}")

    print("Done. Private key stays at", PRIVATE_PEM)


if __name__ == "__main__":
    main()

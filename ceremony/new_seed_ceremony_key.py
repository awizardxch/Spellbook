#!/usr/bin/env python3
"""
Rotate the ceremony keypair the hosted pages encrypt to.

RUN AS THE KEY HOLDER (the daemon user, or the human on their own
machine), never as the agent: whoever holds private.pem can open every
envelope the human's pages make (review S-16 / S-17).

- Generates a fresh RSA-2048 keypair.
- Stores the private key at <key dir>/private.pem (mode 600, outside the
  repo — never commit it). Key dir: --key-dir, $SPELLBOOK_CEREMONY_KEY_DIR,
  or ~/workspace/.spellbook/seed-derive of the user running this (the
  daemon's ceremony_key_path default; review S-16 moves it out of any
  agent-reachable workspace).
- Writes the PUBLIC half as <key dir>/ceremony.pub.pem (0644) and
  public_b64.txt. Point the agent's tools at the .pem with
  ceremony_pub_path in spellbook.json or $SPELLBOOK_CEREMONY_PUB.
- Prints the hosted page links with the public key in the URL fragment,
  and the fingerprint the human compares on the page.

Nothing is stamped into HTML any more: the hosted pages
(https://spellbook.awizard.dev/ceremony/, pinned by ceremony/asset-index.json)
read the public key from the link.
"""
import argparse
import base64
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

ORIGIN = "https://spellbook.awizard.dev"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--key-dir", default=os.environ.get(
        "SPELLBOOK_CEREMONY_KEY_DIR",
        os.path.expanduser("~/workspace/.spellbook/seed-derive")))
    a = ap.parse_args()
    key_dir = a.key_dir
    private_pem = os.path.join(key_dir, "private.pem")
    os.makedirs(key_dir, mode=0o700, exist_ok=True)
    os.chmod(key_dir, 0o700)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    # Created 0600 (review S-05): the key never exists with loose modes,
    # even for the instant between write and chmod.
    fd = os.open(private_pem, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv)
    os.chmod(private_pem, 0o600)

    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(os.path.join(key_dir, "ceremony.pub.pem"), "wb") as f:
        f.write(pub_pem)
    os.chmod(os.path.join(key_dir, "ceremony.pub.pem"), 0o644)
    with open(os.path.join(key_dir, "public_b64.txt"), "w") as f:
        f.write(base64.b64encode(pub_der).decode())
    os.chmod(os.path.join(key_dir, "public_b64.txt"), 0o644)

    fp = hashlib.sha256(pub_der).hexdigest()
    frag = base64.urlsafe_b64encode(pub_der).decode().rstrip("=")
    print("key fingerprint (the human compares this on the page):")
    print("  " + " ".join(fp[i:i + 4] for i in range(0, len(fp), 4)))
    print("restore page: " + f"{ORIGIN}/ceremony/restore.html#k={frag}&op=restore")
    print("seal page:    " + f"{ORIGIN}/ceremony/seal.html#k={frag}&op=seal")
    print("Private key stays at", private_pem, "(0600). Public key:",
          os.path.join(key_dir, "ceremony.pub.pem"))


if __name__ == "__main__":
    main()

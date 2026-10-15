#!/usr/bin/env python3
"""
Stamp the DAEMON's ceremony public key into the delivered seed-to-addresses
page. This script never makes or touches a private key (review S-16).

The key that decrypts the human's envelope belongs to the spellbook daemon
user. It is created inside the daemon's own config dir by:

    sudo spellbook ceremony-key --prefix /opt/spellbook

(install.sh runs this as the daemon user at install). That command, and
`spellbook status` (custody.ceremony_public_key), print only the PUBLIC key
and its fingerprint. Hand the public key to this script and it stamps it
into the delivered copy the human opens. The human checks the fingerprint
against the one the daemon printed.

Usage:
    python3 new_seed_ceremony_key.py --public-key-file PUB.b64 [HTML ...]
    python3 new_seed_ceremony_key.py --stdin [HTML ...]   # key on stdin

The repo copy (ceremony/seed-to-addresses.html) keeps the
__SEED_PUB_B64__ placeholder and is never stamped.

Earlier versions generated an RSA key here and kept private.pem in the
agent's workspace. Any such key must be moved to the daemon with
`sudo spellbook ceremony-adopt --prefix /opt/spellbook`, which overwrites
and unlinks the agent's copy.
"""
import argparse
import base64
import hashlib
import os
import re
import sys

DELIVERED = [
    os.path.expanduser("~/workspace/your_files/ceremony/seed-to-addresses.html"),
]

STAMP_RE = re.compile(r'const SEED_PUB_B64 = "[^"]*";')


def public_b64(text: str) -> tuple[str, str]:
    """(base64 SPKI, fingerprint) of an RSA-2048+ PUBLIC key; refuses a
    private key."""
    pub = "".join(text.split())
    if pub.startswith("public_key_b64:"):
        pub = pub.split(":", 1)[1]
    der = base64.b64decode(pub, validate=True)
    from Crypto.PublicKey import RSA
    key = RSA.import_key(der)
    if key.has_private() or key.size_in_bits() < 2048:
        raise ValueError("need the daemon's RSA-2048+ PUBLIC key")
    return pub, hashlib.sha256(der).hexdigest()[:32]


def main(argv=None):
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--public-key-file")
    src.add_argument("--stdin", action="store_true")
    ap.add_argument("html", nargs="*")
    a = ap.parse_args(argv)
    if a.public_key_file:
        with open(a.public_key_file) as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    try:
        pub, fp = public_b64(text)
    except Exception as e:
        raise SystemExit(f"refused: {type(e).__name__}: {e}")
    print(f"daemon ceremony key fingerprint: {fp}")
    for path in (a.html or DELIVERED):
        if not os.path.exists(path):
            print(f"SKIP (missing): {path}")
            continue
        with open(path) as f:
            html = f.read()
        new_html, n = STAMP_RE.subn(f'const SEED_PUB_B64 = "{pub}";', html)
        if n == 0:
            print(f"SKIP (no stamp point): {path}")
            continue
        with open(path, "w") as f:
            f.write(new_html)
        print(f"stamped: {path}")


if __name__ == "__main__":
    main()

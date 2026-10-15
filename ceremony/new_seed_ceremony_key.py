#!/usr/bin/env python3
"""
Print the hosted ceremony links for the DAEMON's ceremony PUBLIC key.
This script never makes, reads or touches a private key (review S-16), and
it stamps no HTML (review S-17): the ceremony pages are hosted at
https://spellbook.awizard.dev/ceremony/ and read the public key from the
link's #fragment; the old ceremony/*.html files are pointers to them.

The key that decrypts the human's envelopes belongs to the spellbook
daemon user. It is created inside the daemon's own 0700 dir by

    sudo spellbook ceremony-key --prefix /opt/spellbook

(install.sh runs this as the daemon user and publishes the public half,
root-owned, at /usr/local/share/spellbook/ceremony.pub.pem). The same
public key is in `spellbook status` (custody.ceremony_public_key).

Usage (safe for the agent: public material only):
    python3 new_seed_ceremony_key.py                       # the published key
    python3 new_seed_ceremony_key.py --public-key-file PUB # PEM or base64 SPKI
    python3 new_seed_ceremony_key.py --stdin               # key on stdin

It prints the key fingerprint and the seal / restore links. The human
compares the fingerprint the page shows with the one the DAEMON printed
for them (installer log, terminal `spellbook export`, `spellbook
ceremony-key` in their own root shell), never only the one the agent
quotes. `spellbook-ceremony url seal|restore|backup` does the same.

Earlier versions generated an RSA key here and kept private.pem in the
agent's workspace. Any such key must be moved to the daemon with
`sudo spellbook ceremony-adopt --prefix /opt/spellbook`, which overwrites
and unlinks the agent's copy.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "src"))


def main(argv=None):
    from spellbook import ceremony
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--public-key-file")
    src.add_argument("--stdin", action="store_true")
    ap.add_argument("--origin", default=ceremony.HOSTED_ORIGIN)
    a = ap.parse_args(argv)
    try:
        if a.stdin:
            text = sys.stdin.read()
        else:
            path = a.public_key_file or ceremony.find_public_key()
            if not path:
                raise ceremony.CeremonyError(
                    "no published ceremony public key; pass --public-key-file")
            with open(path) as f:
                text = f.read()
        if "PRIVATE KEY" in text:
            raise ceremony.CeremonyError("that is a PRIVATE key — only the "
                                         "public half is ever handled here")
        text = "".join(text.split()) if not text.lstrip().startswith("-----") \
            else text
        if text.startswith("public_key_b64:"):
            text = text.split(":", 1)[1]
        der = ceremony.public_der(text)
    except (ceremony.CeremonyError, OSError) as e:
        raise SystemExit(f"refused: {e}")
    fp = ceremony.grouped(ceremony.key_fingerprint(der))
    print("Spellbook daemon key fingerprint (the human compares it on the page):")
    print("  " + fp)
    for page, op in (("seal", "seal"), ("seal", "unlock"), ("restore", "restore")):
        print(f"{op + ' page:':<14} "
              + ceremony.hosted_url(page, pub_der=der, op=op, origin=a.origin))
    print(f"{'backup page:':<14} " + ceremony.hosted_url("backup", origin=a.origin))


if __name__ == "__main__":
    main()

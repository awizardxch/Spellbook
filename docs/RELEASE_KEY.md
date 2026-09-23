# Spellbook release key

Every Spellbook release tarball is signed with the project's release key.
`install.sh` (and the agent self-upgrade wrapper) verify the tarball's
SHA-256 checksum **and** the GPG signature before installing anything —
and the signature is only accepted if the signer's fingerprint exactly
matches the pinned fingerprint below.

## Fingerprint (the trust anchor)

```
7DEA43CA62DF3F8FB041C1551FCF79089E54DC35
```

Read it here, and cross-check it against the pinned town thread and the
README — never trust a fingerprint that arrives only inside a release
page or tarball.

## The key

- UID: `Spellbook Release Signing <spellbook@awizard.dev>`
- Algorithm: Ed25519 (sign) / Curve25519 (encrypt subkey)
- Expires: 2028-09-22 (extended before expiry; rotations are announced in
  the town thread with both fingerprints shown)
- Public key: [`docs/release-key.asc`](release-key.asc)

## Importing it (fresh installs)

Before running `install.sh` for the first time:

```sh
curl -fsSL https://raw.githubusercontent.com/awizardxch/Spellbook/main/docs/release-key.asc \
  | gpg --import
gpg --list-keys --with-colons "spellbook@awizard.dev"   # compare the fpr: line
```

Then pass the fingerprint you verified (not one copied from the key file):

```sh
sudo SPELLBOOK_RELEASE_KEY_FPR=7DEA43CA62DF3F8FB041C1551FCF79089E54DC35 \
  ./install.sh --agent-user ...
```

Upgrades reuse the fingerprint recorded in `/opt/spellbook/install.env`
(root-owned) and the key already in root's keyring — the agent never has
to handle key material.

## Custody

The private key is held by the aWizard agent on its operations VM
(`~/.gnupg`, mode 0700, no passphrase — it must sign releases
unattended). A revocation certificate was generated at key creation and is
stored with the key. If the key is ever lost or compromised, it is rotated
and the new fingerprint is announced in the town thread; Speechless may at
any time ask for the private key to be transferred to their sole custody.

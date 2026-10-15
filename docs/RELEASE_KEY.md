# Spellbook release key

Every Spellbook release tarball is signed with the project's release key.
`install.sh` (and the agent self-upgrade wrapper) verify the tarball's
SHA-256 checksum **and** the GPG signature before installing anything —
and the signature is only accepted if the signer's fingerprint exactly
matches the pinned fingerprint below, and the key is neither expired nor
revoked.

The key alone does not ship a release to installed machines. The upgrade
wrapper also requires the release to be on the canonical `main` branch and
past a delay window (see "Release acceptance" below), so whoever holds the
key still needs a reviewed merge to `main` and the delay to pass.

## Fingerprint (the trust anchor)

```
7DEA43CA62DF3F8FB041C1551FCF79089E54DC35
```

Read it here, and cross-check it against the pinned town thread and the
README — never trust a fingerprint that arrives only inside a release
page or tarball.

## What the fingerprint proves (and what it doesn't)

The fingerprint is **public**. Anyone can copy it into their own document —
and that proves nothing. A fingerprint in a doc is not what makes the doc
correct.

What makes a document correct is **whose channels it came through**: the
pinned town thread is posted by aWizard's Musebook identity (Ed25519-signed
posts — nobody else can post as aWizard), and this repo lives in
Speechless's GitHub org. Check both; they must agree.

What the fingerprint *does* do is let you check whether a **key** is
correct. GPG computes the fingerprint **from the key material itself** — a
fake key cannot produce Speechless's fingerprint. So the check below is not
"does this doc say the right string." It is: "does the key I imported
*compute to* the string from Speechless's channels." An attacker who copies
the fingerprint next to their own key fails this check every time.

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

Upgrades reuse the fingerprint recorded in
`/usr/local/lib/spellbook/install.env` (root-owned) — the agent never has
to handle key material. The upgrade wrapper verifies against a fresh
keyring holding only `docs/release-key.asc` as published on `main`, so a
revocation or expiry published there takes effect on the next upgrade.

## Release acceptance (review S-22)

`/usr/local/bin/spellbook-upgrade X.Y.Z` (the agent via NOPASSWD sudo, or
the human via `sudo`) installs a release only when every step holds,
checked from the installing machine against
`https://github.com/awizardxch/Spellbook.git`:

1. **Clean call.** Exactly one `X.Y.Z` argument (a leading `v` is accepted),
   no steering variables in the environment (`LD_*`, `BASH_ENV`, `GIT_*`,
   `GNUPGHOME`, `SPELLBOOK_*`, …), and the root-trusted files
   (`/usr/local/lib/spellbook/{install.sh,install.env,VERSION}` and every
   parent directory) root-owned, not symlinks, writable by no one else.
2. **Signed tag.** `refs/tags/X.Y.Z` on the canonical repo is an annotated
   tag that names itself `X.Y.Z`, with exactly one good signature by the
   pinned fingerprint. `EXPKEYSIG`, `REVKEYSIG`, `BADSIG`, `ERRSIG` are
   refused.
3. **On main.** The tag's commit is reachable from `main`, and its
   `VERSION` file reads `X.Y.Z`.
4. **Not yanked.** Neither `X.Y.Z` nor the signing fingerprint appears in
   `releases/YANKED` on `main` (one entry per line, `#` comments).
5. **Hash published on main.** `main` carries
   `releases/X.Y.Z/spellbook-X.Y.Z.tar.gz.sha256`; the installer is passed
   that hash and refuses any downloaded tarball that differs, and takes a
   prebuilt Sage binary only from the copy on `main`.
6. **Delay window.** The tag is at least 24 h old (configurable as
   `SPELLBOOK_UPGRADE_DELAY_HOURS` in `install.env`), by both its signed
   tagger date and when this machine first saw it. Inside the window the
   wrapper exits 75 ("NOT YET") and records the first sighting.
7. **Forward only.** Older than the installed version is refused.

The installer then re-verifies the tarball's SHA-256 and signature.

### Per release (the release maker and the owner)

1. Sign the tag: `git tag -s -u <fpr> X.Y.Z -m 'Spellbook X.Y.Z'` on a
   commit that is on `main`; `git push origin X.Y.Z`.
2. `bash scripts/cut-release.sh X.Y.Z` (it refuses an unsigned tag).
3. Open a PR with `releases/X.Y.Z/`. A human reviews and merges it after
   checking that `git archive --format=tar.gz --prefix=spellbook-X.Y.Z/
   X.Y.Z | sha256sum` matches the vendored `.sha256`. That merge is what
   publishes the hash installs require.
4. Publish the GitHub Release assets as `cut-release.sh` prints.
5. Wait. Installs take it once the tag is past the delay window.

To stop a release (or a key), commit a line to `releases/YANKED` on `main`
before the window ends: `X.Y.Z <reason>` or `<fingerprint> <reason>`.

What this assumes: `main` is protected so that merging needs a human
review the release-key holder cannot bypass (branch protection, no direct
pushes or admin bypass for the agent's GitHub credential). If the key's
holder can also push to `main` unreviewed, the merge condition adds
nothing, and only the delay window and yank list remain.

## Custody

The private key may be held by the aWizard agent on its operations VM
(a cloud VM such as Muse by Meta, `~/.gnupg`, mode 0700, no passphrase, so
it can sign releases unattended), or locally by the maintainer. A
revocation certificate was generated at key creation; keep a copy where the
VM cannot reach it too. Because installs also require the release on `main`
and past the delay window, whoever controls that VM (for example a
prompt-injected agent) can sign a tag but cannot get it installed: it is
refused unless a human merges it to `main`, and anything that gets there
can still be yanked inside the window.

If the key is ever lost or compromised: add its fingerprint to
`releases/YANKED` on `main` (installs refuse it at once), publish the
revocation in `docs/release-key.asc` on `main`, rotate, and announce the
new fingerprint in the town thread; installs then need the new fingerprint
in `install.env` (a human step). Speechless may at any time ask for the
private key to be transferred to their sole custody.

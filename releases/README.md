# Vendored release artifacts

Each `<tag>/` directory holds the signed distribution files for that
Spellbook release:

- `spellbook-<tag>.tar.gz` — the release tarball
- `spellbook-<tag>.tar.gz.sha256` — its SHA-256 checksum
- `spellbook-<tag>.tar.gz.asc` — detached GPG signature from the
  Spellbook release key (`7DEA43CA62DF3F8FB041C1551FCF79089E54DC35`;
  public key in `docs/release-key.asc`)

`install.sh` downloads these from the GitHub Release asset URLs first
and falls back to this directory via raw.githubusercontent.com, so
agent upgrades keep working even when release-asset upload is
unavailable. The tarball is verified by checksum AND by the pinned
release-key signature before anything is installed — the download URL
is never the trust anchor.

Do not hand-edit these files. To cut a release: build the tarball from
the release commit, checksum it, sign it with the release key, and
drop the three files here.

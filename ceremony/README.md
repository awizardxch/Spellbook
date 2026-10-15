# Seed ceremony

Reviews 2026-10-15 S-16, S-17 and S-18. One model:

- **One key, the daemon's.** Every ceremony envelope is opened by the
  daemon user's ceremony key, `<prefix>/ceremony/private.pem` (0600 in a
  0700 dir, owned by the daemon user). The agent never holds it and never
  holds any other key that opens what the human types (S-16).
- **Hosted pages, client-side only.** The pages the human types a secret
  into are served from the Spellbook site, run only in the human's
  browser, and encrypt to the daemon's PUBLIC key. The agent never runs,
  serves or reads such a page (S-17, S-18).
- **The agent relays public keys and ciphertext.** It hands out the page
  link and carries the envelope back to the daemon user.

## Who holds what

| What | Where | Owner / mode | Who reads it |
|---|---|---|---|
| Ceremony private key | `<prefix>/ceremony/private.pem` | daemon user, 0600, dir 0700 | the daemon at start; `spellbook-ceremony apply/restore` and `derive_from_envelope.py` as the daemon user or root |
| Public key, beside it | `<prefix>/ceremony/ceremony.pub.pem`, `public_b64.txt` | daemon user, 0644 (inside the 0700 prefix) | daemon user, root |
| Public key, published | `/usr/local/share/spellbook/ceremony.pub.pem` | root, 0644, dir 0755 | anyone, the agent included; the agent cannot replace it |
| Backup record | `<prefix>/backup.json` | daemon user, 0600 | the daemon (fund routes wait for it) |

`spellbook.json`: `ceremony_pub_path` points at the published copy (fresh
installs); without it, `spellbook-ceremony` and the agent's
`spellbook_seed_viewer` look at `$SPELLBOOK_CEREMONY_PUB`, then
`<config dir>/ceremony.pub.pem`, then the published path. On fresh
installs `ceremony_key_path` names the daemon's own key; on upgraded
installs it may still name the LEGACY key the old ceremony left in the
agent's workspace, so nothing reads it as the daemon key: it is only what
`spellbook ceremony-adopt` moves.

## Commands

| Command | Who | Does |
|---|---|---|
| `spellbook ceremony-key --prefix P` | daemon user or root (install.sh runs it as the daemon user) | creates the key if missing; prints the public key and the **Spellbook daemon key fingerprint** (sha256 of the SPKI DER). `--pem` prints the public PEM install.sh publishes. `--rotate` replaces it: old envelopes stop opening, the backup is required again, and the published PEM must be refreshed (re-run `install.sh --upgrade`) |
| `spellbook ceremony-adopt --prefix P [--from PATH]` | root (install.sh --upgrade runs it) | MOVES a legacy agent-reach key into `<prefix>/ceremony/`, overwrites and unlinks the original |
| `spellbook-ceremony url seal\|restore\|backup` | anyone, the agent included | the hosted link, public key in the URL fragment, plus the fingerprint |
| `spellbook-ceremony inspect FILE` | anyone | an envelope's public header (kind, key fingerprint) |
| `sudo -u spellbook spellbook-ceremony apply FILE` | daemon user or root | opens a seal/unlock envelope and seals or unlocks |
| `sudo -u spellbook spellbook-ceremony restore FILE --out NEW` | daemon user or root | opens a restore envelope and writes the `install.sh --restore` key file |
| `sudo spellbook export [--reveal-key PUB]` | the human at a terminal; root for the agent's reveal-key run | the paper backup (below) |
| `sudo spellbook backup-confirm` | root or the daemon user, code on stdin | confirms the backup with the code from the reveal-key backup |

`apply` and `restore` use the daemon's own key by default, loaded
strictly (no symlinks, file and dir owned by the daemon user, no
group/other bits). `--key PATH` is an explicit override (the file must be
0600). Both refuse the agent's OS user (the request-token UIDs in
`spellbook.json`), read the envelope from a file or stdin (never argv),
and check the envelope was made for this key and this operation (kind and
key fingerprint are AES-GCM associated data). `apply` enforces the seal
password strength rule the page also shows. `restore` maps SET 1
(standard) to `std_seed.key` and SET 2 (daemon) to `seed.key`, the paper
labels, and creates its output with `O_EXCL|O_NOFOLLOW`, 0600.

## The human's flow

| Step | Human (own browser) | Agent | Daemon user / root |
|---|---|---|---|
| Paper backup | opens `backup.html`, makes a reveal key, writes the words down, sends back the **BACKUP CONFIRMATION CODE** | relays the reveal PUBLIC key and the envelope; pipes the code to `sudo spellbook backup-confirm` | `spellbook export --reveal-key` encrypts the backup |
| Seal | types a new password on `seal.html` | relays the link and the envelope | `spellbook-ceremony apply` seals |
| Unlock after a wipe | types the password on `seal.html` | same | `spellbook-ceremony apply` unlocks |
| Restore from paper | types SET 1 + SET 2 on `restore.html` | same | `spellbook-ceremony restore --out FILE`, then `install.sh --restore FILE` |
| Passwordless sealed seed | types SET 1 (or the 128-hex seed) on `restore.html` | stores the `SPELLBOOK-SEED-ENC2` envelope (ciphertext to it) | the daemon opens it at every start (`sealed_envelope_path`) |

Pages (source `web/public/ceremony/`):

- `https://spellbook.awizard.dev/ceremony/seal.html#k=<daemon public key>&op=seal|unlock`
- `https://spellbook.awizard.dev/ceremony/restore.html#k=<daemon public key>&op=restore`
- `https://spellbook.awizard.dev/ceremony/backup.html` (makes its own reveal key)

The public key rides in the URL **fragment**, which browsers never send
to the server. All crypto runs in the browser (WebCrypto: RSA-OAEP-SHA256
+ AES-256-GCM). The pages carry a CSP with `default-src 'none';
connect-src 'none'`, load only same-origin scripts and stylesheets pinned
by `integrity=` hashes, and have no inline script.

**The fingerprint check.** The seal and restore pages show the Spellbook
daemon key fingerprint of the key in the link and ask the human to type
at least its first 16 hex digits as the DAEMON printed them for the
human: the installer log, the terminal `spellbook export` screen, or
`sudo spellbook ceremony-key` in the human's own root shell. Never only
the one the agent quotes: the agent builds the link, so this check is
what stops a swapped key. The reveal-key backup deliberately carries no
fingerprint: the agent knows that reveal key and could write an envelope
of its own.

**Forced backup (S-16).** A fresh or restored install, and a seed loaded
through the daemon's ceremony key, is BACKUP PENDING: fund-moving routes
refuse, reads work. The terminal `spellbook export` confirms it once the
typed-back words match the live seed (all 24 when only the sealed seed is
on the machine). Through `backup.html`, the decrypted backup ends with a
one-time BACKUP CONFIRMATION CODE (one use, 7 days); the page shows it
apart and the human hands it back for `sudo spellbook backup-confirm`
(stdin, never argv). An install that keeps only the passwordless sealed
seed shows the SET 1 addresses and no words: the human's paper words
must derive them.

**The relay step needs the daemon user.** There is deliberately no
request-token daemon route that accepts an envelope: it would let the
agent seal a seed of its own to the public key and have the daemon
install it. The agent saves the envelope to a file and the daemon user
(or root) runs `spellbook-ceremony apply|restore`. On a single-user agent
VM, where the daemon runs as the agent's own OS user, there is no custody
separation for software to enforce; the daemon warns at every start.

## Migrating an old ceremony

Earlier versions had the agent mint the key and keep `private.pem` in
`~/workspace/.spellbook/seed-derive/`. Root runs `sudo spellbook
ceremony-adopt --prefix /opt/spellbook [--from PATH]` (`install.sh
--upgrade` does it too): the key moves into the daemon's directory and the
agent's copy is overwritten and unlinked. Guaranteed: the old path no
longer holds the key, and the file was overwritten in place where it was
writable. Not guaranteed: that no copy survives (journaling/copy-on-write
filesystems, SSD remapping, snapshots, backups, or a copy the agent
already made). A key that was ever in agent reach is exposed: re-seed when
practical.

## Asset index

`asset-index.json` here is a byte-identical mirror of the published
`https://spellbook.awizard.dev/asset-index.json`, rendered at
`/onboard/integrity`; install.sh copies it to `${PREFIX}/share/ceremony/`.
It lists every ceremony page and asset with its SHA-256 and SRI hash, the
ceremony CSP, and every API route the site exposes with its source hash.

```bash
PYTHONPATH=src python -m spellbook.asset_index write    # after changing a page, asset or API route
PYTHONPATH=src python -m spellbook.asset_index check    # what the tests and the web prebuild run
PYTHONPATH=src python -m spellbook.asset_index verify --fetch   # compare the live site with this repo
```

## The files here

- `seal-password-encryptor.html`, `minimal-encryptor.html`,
  `seed-to-addresses.html`: pointers to the hosted pages. The old versions
  had the agent decrypt the seal password and the restore words.
- `new_seed_ceremony_key.py`: prints the fingerprint and the hosted links
  for the published PUBLIC key. It never makes or reads a private key and
  stamps no HTML (agent-safe; same as `spellbook-ceremony url`).
- `derive_from_envelope.py --prefix P`: opens a `SPELLBOOK-SEED-ENC2`
  envelope with the daemon's key and derives the addresses. Daemon user or
  root only; it refuses anyone else, since whoever runs it holds the seed
  in memory.
- `derive_addresses.py`: addresses from seed hex.

Code: `src/spellbook/ceremony.py` (envelopes, links, apply/restore),
`src/spellbook/custody.py` (the key, adoption, the backup record),
`src/spellbook/export.py` (the paper backup).

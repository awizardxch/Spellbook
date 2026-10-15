# Seed ceremony

Review 2026-10-15, S-17 and S-18: the human's ceremony pages are **hosted**,
and the agent never runs, serves or reads a page the human types a secret
into. It never holds a key that opens what the human types.

## Who sees what

| Step | Human (own browser) | Agent | Key holder (daemon user) |
|---|---|---|---|
| Paper backup | makes a reveal key on `backup.html`, reads the words there | relays the reveal PUBLIC key and the export envelope | `spellbook export --reveal-key` encrypts the backup |
| Seal | types a new password on `seal.html` | relays the link (daemon PUBLIC key) and the envelope | `spellbook-ceremony apply` decrypts it and seals |
| Unlock after a wipe | types the password on `seal.html` | same | `spellbook-ceremony apply` decrypts and unlocks |
| Restore from paper | types SET 1 + SET 2 on `restore.html` | same | `spellbook-ceremony restore --out FILE`, then `install.sh --restore FILE` |
| Passwordless sealed seed | types SET 1 (or the 128-hex seed) on `restore.html` | same | the daemon opens the `SPELLBOOK-SEED-ENC2` envelope at start |

The agent only ever carries public keys and ciphertext.

## The pages (hosted)

Served from the Spellbook site, source in `web/public/ceremony/`:

- `https://spellbook.awizard.dev/ceremony/seal.html#k=<daemon public key>&op=seal|unlock`
- `https://spellbook.awizard.dev/ceremony/restore.html#k=<daemon public key>&op=restore`
- `https://spellbook.awizard.dev/ceremony/backup.html` (makes its own reveal key)

The public key rides in the URL **fragment** (after `#`), which browsers
never send to the server. All crypto runs in the human's browser
(WebCrypto: RSA-OAEP-SHA256 + AES-256-GCM). The pages carry a CSP with
`default-src 'none'; connect-src 'none'`, load only same-origin scripts
and stylesheets pinned by `integrity=` hashes, and have no inline script.

Get a link (agent-safe; public material only):

```bash
spellbook-ceremony url seal               # or restore / backup
spellbook-ceremony fingerprint            # what the page shows
```

The page shows the key's fingerprint. The human compares it with the one
the key holder printed for them, not only with the one the agent quotes:
the agent relays the key, so the fingerprint check is what stops a
swapped key.

## Opening an envelope (key holder only)

```bash
sudo -u spellbook spellbook-ceremony apply envelope.txt            # seal / unlock
sudo -u spellbook spellbook-ceremony restore envelope.txt --out /root/restore.keys
```

Both refuse the agent's OS user (the request-token UIDs in
`spellbook.json`), read the envelope from a file or stdin (never argv),
check the key file is 0600, and check the envelope was made for this key
and for this operation (the kind and key fingerprint are bound as AES-GCM
associated data). `apply` enforces the seal password strength rule the
page also shows. `restore` maps SET 1 (standard) to `std_seed.key` and
SET 2 (daemon) to `seed.key`, the paper labels, and creates its output
with `O_EXCL|O_NOFOLLOW`, 0600.

Envelope format: `src/spellbook/ceremony.py`.

## Asset index

`asset-index.json` here is a byte-identical mirror of the published
`https://spellbook.awizard.dev/asset-index.json`, rendered at
`/onboard/integrity`. It lists every ceremony page and asset with its
SHA-256 and SRI hash, the ceremony CSP, and every API route the site
exposes with its source hash.

```bash
PYTHONPATH=src python -m spellbook.asset_index write    # after changing a page, asset or API route
PYTHONPATH=src python -m spellbook.asset_index check    # what the tests and the web prebuild run
PYTHONPATH=src python -m spellbook.asset_index verify --fetch   # compare the live site with this repo
```

## The old pages

`seal-password-encryptor.html`, `minimal-encryptor.html` and
`seed-to-addresses.html` are now pointers to the hosted pages. The old
versions had the agent decrypt the seal password and the restore words.

## Helpers (key holder or human, never the agent)

- `new_seed_ceremony_key.py`: makes the ceremony key pair, writes the
  public half for the agent's tools, prints the page links.
- `derive_from_envelope.py`: opens a `SPELLBOOK-SEED-ENC2` envelope and
  derives the addresses. Whoever runs it holds the seed in memory.
- `derive_addresses.py`: addresses from seed hex.

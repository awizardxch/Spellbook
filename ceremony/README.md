# Seal Ceremony HTML Pages

Offline HTML pages for the Spellbook fresh-install seal ceremony. The human
opens one in a browser; the agent and human pass encrypted blobs back and
forth in chat. Fully offline — no network calls, keys never leave the page
except encrypted.

## Pages

- **`seal-password-encryptor.html`** — Full ceremony, 3 steps:
  1. Human generates a reveal key, pastes the public key to the agent.
     Agent runs `sudo spellbook export --reveal-key <public key>`, which
     encrypts the recovery document (both 24-word sets and their
     addresses; no raw private keys) to it and prints only the envelope;
     the agent sends that back as a copy-paste block and never sees a
     word (review S-05).
  2. Human pastes the envelope, decrypts, verifies, writes everything on
     paper. Agent waits for "backup recorded".
  3. Human enters a new seal password (writes it on paper first), encrypts,
     pastes the ciphertext to the agent. Agent seals the keys.

- **`minimal-encryptor.html`** — Same 3 steps, stripped down. Fallback if the
  main page misbehaves.

## Agent setup (per ceremony)

Both pages ship with `__SEAL_PUB_B64__` as a placeholder. Before handing a
page to the human:

1. Generate a fresh RSA-2048 seal keypair. Keep `private.pem` secret.
2. Replace `__SEAL_PUB_B64__` with the base64 DER SPKI public key.
3. The human's encrypted seal password can only be decrypted with `private.pem`.
4. After the ceremony, shred `private.pem`.

## Install location

`install.sh` copies this directory to `${PREFIX}/share/ceremony/`
(e.g. `/opt/spellbook/share/ceremony/`).

## Restore from backup

If the human has backed-up keys (from a previous install's paper backup):

1. **Human:** Opens the page, fills in **Step 0** with their SET 1 and SET 2
   mnemonics (24 words each), encrypts to the agent's seal key, pastes the
   ciphertext into chat. Skips Steps 1–2, does Step 3 (seal password) next.
2. **Agent:** Decrypts the restore blob with the seal private key, then runs:
   ```
   scripts/restore_from_mnemonics.py "<set1>" "<set2>" /tmp/restore.keys
   bash install.sh <tag> --restore /tmp/restore.keys --agent-user ... --human-user ...
   ```
   `install.sh --restore` validates the two hex keys (64 + 128 chars),
   installs them as `seed.key` / `std_seed.key` (0600), and shreds the
   restore file. No fresh keys are generated; no new mnemonic is displayed
   (the human already has these words on paper).
3. The agent confirms the derived addresses match the human's backup before
   sealing with the Step 3 password.

`--restore` and `--upgrade` are mutually exclusive.

## Permanent direction

These pages are a bridge. The permanent implementation belongs inside
Spellbook itself (likely `spellbook-seed serve`), portable across LLM
environments with no Muse-specific dependency.

## Passwordless ceremony (current)

**`seed-to-addresses.html`** — the current ceremony page. No passwords, no
chat secrets. The human pastes one of:

- 24 BIP-39 recovery words (standard wallet — the set that imports into
  Sage/MetaMask), validated with checksum in-page, or
- 128-hex standard seed, or
- 64-hex custom (32-byte) seed.

The page derives EVM / Solana / Chia addresses entirely offline and seals
the seed into a `SPELLBOOK-SEED-ENC2` envelope (AES-256-GCM, key wrapped by
RSA-OAEP-SHA256 to the ceremony public key). The envelope is the only thing
that leaves the browser — the seed and words never do.

The page ships with `__SEED_PUB_B64__` as a placeholder and **refuses to
seal until stamped**. The key it seals to belongs to the **daemon**, never
to the agent (review S-16):

1. The decrypting key is `<prefix>/ceremony/private.pem`, owned by the
   spellbook daemon user, 0600 in a 0700 directory. `install.sh` creates it
   as that user; on an existing install root runs
   `sudo spellbook ceremony-key --prefix /opt/spellbook`. That command and
   `spellbook status` (`custody.ceremony_public_key`) print only the PUBLIC
   key and its fingerprint.
2. The agent stamps that public key into the delivered copy:
   `python3 ceremony/new_seed_ceremony_key.py --public-key-file PUB.b64`
   (or `--stdin`). The script never makes or reads a private key.
3. The human checks the fingerprint the page shows against the one the
   daemon printed, then seals. The envelope may be stored anywhere,
   including the agent's workspace: it is ciphertext to a key the agent
   cannot read. Point `sealed_envelope_path` in spellbook.json at it.
4. The daemon decrypts it at every start with its own key (no password,
   no re-entry). A seed loaded this way is **backup-pending**: fund-moving
   routes refuse until the human proves the words — `sudo spellbook
   export` at their own terminal (all 24 words typed back, since only the
   seed is on the machine), or `spellbook export --reveal-key` then
   `spellbook backup-confirm` with the code inside the encrypted backup.

**Migrating an old ceremony.** Earlier versions had the agent mint the key
and keep `private.pem` in `~/workspace/.spellbook/seed-derive/`. Root runs
`sudo spellbook ceremony-adopt --prefix /opt/spellbook [--from PATH]`
(`install.sh --upgrade` does it too): the key is moved into the daemon's
directory and the agent's copy is overwritten and unlinked. What that
guarantees: the old path no longer holds the key, and the file was
overwritten in place where it was writable. What it cannot guarantee:
that no copy survives (journaling/copy-on-write filesystems, SSD
remapping, snapshots, backups, or a copy the agent already made). A key
that was ever in agent reach should be treated as exposed — re-seed when
practical. On a host with no daemon-user split (the daemon runs as the
agent's own user) nothing can be separated; the daemon leaves the key in
place and warns on every start.

### Tools

- **`derive_from_envelope.py`** — run as the daemon user or root
  (`--prefix`): paste an envelope, get the EVM/Solana/Chia addresses,
  verified against known anchors. The agent cannot run it (it cannot read
  the key); it asks the daemon for `spellbook addresses` instead.
- **`derive_addresses.py`** — derive all addresses from a seed hex directly.
- **`new_seed_ceremony_key.py`** — stamp the daemon's PUBLIC key into the
  delivered page.

The daemon (`src/spellbook/daemon.py`, `src/spellbook/custody.py`)
decrypts the envelope on startup via `sealed_envelope_path` and its own
ceremony key; `ceremony_key_path` now names only a legacy key to move.

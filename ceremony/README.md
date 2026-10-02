# Seal Ceremony HTML Pages

Offline HTML pages for the Spellbook fresh-install seal ceremony. The human
opens one in a browser; the agent and human pass encrypted blobs back and
forth in chat. Fully offline — no network calls, keys never leave the page
except encrypted.

## Pages

- **`seal-password-encryptor.html`** — Full ceremony, 3 steps:
  1. Human generates a reveal key, pastes the public key to the agent.
     Agent encrypts the full recovery document (both 24-word sets, all
     private keys/addresses) and sends the envelope back as a copy-paste block.
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
seal until stamped**. Before handing it to the human:

1. Run `python3 ceremony/new_seed_ceremony_key.py` — generates a fresh
   RSA-2048 keypair. Keep `private.pem` secret (mode 600, outside the repo).
2. Replace `__SEED_PUB_B64__` with the base64 DER SPKI public key.
3. After the ceremony, `private.pem` decrypts envelopes; guard it like a key.

### Agent tools (for other agents)

These scripts let any agent work with sealed envelopes without ever seeing
key material:

- **`derive_from_envelope.py`** — paste an envelope, get the EVM/Solana/Chia
  addresses. Verifies EVM + Solana against known anchors and fails closed
  on mismatch. The seed is derived in-process and never printed.
- **`derive_addresses.py`** — derive all addresses from a seed hex directly.
- **`new_seed_ceremony_key.py`** — mint a fresh ceremony RSA keypair.

The daemon (`src/spellbook/daemon.py`) decrypts the same envelope format on
startup via `sealed_envelope_path` + `ceremony_key_path` (see PR #105), so
keys survive restarts without re-entry.

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

## Permanent direction

These pages are a bridge. The permanent implementation belongs inside
Spellbook itself (likely `spellbook-seed serve`), portable across LLM
environments with no Muse-specific dependency.

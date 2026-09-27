# Sealed seed: password unlock that survives VM wipes

**Goal:** every new or compacted agent session on the same VM can get the
**same** wallet back. The human only enters a password. Nobody re-types
24 words, and the agent never sees the password or the seed.

Code: `src/spellbook/sealed.py`. CLI: `spellbook-seed`. Tests:
`tests/test_sealed.py`.

## Flow

```
install / first run            VM wipe                       next session
───────────────────            ───────                       ────────────
seed.key (+ std_seed.key)      seed files gone               spellbook-seed status → locked (exit 3)
        │                      seed.sealed survives          spellbook-seed serve  → one-time link
spellbook-seed serve           (~/workspace persists)        human: link → password → Unlock
human: link → password → Seal                                seed files rewritten (0600), same wallet
        │                                                    daemon starts
~/workspace/.spellbook/seed.sealed
```

## Commands

| Command | Who | What |
|---|---|---|
| `spellbook-seed status [--json]` | agent, every session | Shows the public state and needs no password. Exit codes: 0 unlocked, 3 locked, 4 unsealed, 5 mismatch, 6 empty |
| `spellbook-seed serve [--port 8787]` | agent starts it, human uses it | One-time local page. It shows **Seal** when unsealed and **Unlock** when locked, and exits after one success or 5 wrong passwords |
| `spellbook-seed seal [--replace]` | human at a terminal | TTY password prompt, entered twice. `--replace` changes the password, but only for the **same** wallet |
| `spellbook-seed unlock` | human at a terminal | TTY password prompt |

Every command also takes `--config-dir DIR` and `--sealed PATH`. The
environment variables `SPELLBOOK_CONFIG_DIR` and `SPELLBOOK_SEALED_PATH`
set the same things. `--password-stdin` exists for a human's own
pipeline. An agent must never use it.

## Reaching the viewer page

`serve` binds `127.0.0.1` by default. The human reaches it by one of:
- a browser on the VM itself
- an SSH tunnel: `ssh -L 8787:127.0.0.1:8787 <vm>`, then open the link locally
- the platform's port-forward or preview URL, **if it is TLS and private
  to the human**: `spellbook-seed serve --host 0.0.0.0 --allow-remote`

The page is plain HTTP, so it must never be exposed on an open network
without TLS in front. The URL carries a random one-time token, and every
other path returns 404. Responses are `no-store` with a CSP that allows
no scripts. The server logs neither the token nor the password.

## File format (`seed.sealed`, version 1)

```json
{"format": "spellbook-sealed-seed", "version": 1,
 "kdf": {"name": "scrypt", "n": 131072, "r": 8, "p": 1, "salt": "<b64>"},
 "cipher": "aes-256-gcm", "nonce": "<b64>", "created": "…Z",
 "fingerprint": "<16 hex>", "has_std_seed": true,
 "ciphertext": "<b64 ciphertext+tag>"}
```

- The plaintext is `{"seed": <64 hex>, "std_seed": <128 hex>|null}`,
  which is exactly the files the daemon loads.
- The whole header is GCM additional data. Editing any field, or using a
  wrong password, fails closed with nothing written.
- scrypt costs about 128 MiB per guess. The cost is stored in the header
  and bounded when the file is opened.
- `fingerprint` is `sha256("spellbook-sealed-fp/v1" ‖ seed)[:16 hex]`.
  It lets `status` check the disk seed against the seal without the
  password, and reveals nothing usable about a 256-bit seed.
- The file is written 0600 through a temp file and an atomic rename. The
  seed files are written 0600 with `O_EXCL`. When run as root (system
  install), each file is chowned to the owner of its directory.

## Safety rules the code enforces

1. **It never overwrites a different wallet.** Unlock refuses if any seed
   file exists with different contents, and it checks every target before
   writing any. Seal with `--replace` refuses if the existing seal holds a
   different wallet than the disk.
2. **It never seals partially.** A `key_derivation=standard` config must
   have `std_seed.key` before sealing.
3. **The daemon names the problem.** If a seed file is missing and a seal
   exists, `spellbookd` fails with "seed is sealed and not unlocked … ask
   the human". The agent must not re-install, because that would mint a
   new wallet.
4. **Secrets stay out of every output.** No seed or password appears in
   stdout, stderr, logs, argv or env.

## What it does and does not protect

- **Protects:** the seed at rest in `~/workspace`, including a leaked,
  synced or backed-up workspace. An attacker must brute-force the
  password against scrypt.
- **Does not protect** against a hostile process running as the same OS
  user while the seed is unlocked. The seed files are readable then, just
  as they were before this change. The system install's separate daemon
  user (install.sh, S2) is what isolates the key from the agent.
- **Losing the password** means the seal is useless. Only the paper
  backup recovers the wallet then, so keep both.

## Wiring it into agent sessions

In the agent's startup instructions (or a session-start hook), add:

```bash
spellbook-seed status || echo "Spellbook seed not unlocked — see docs/SEALED_SEED.md"
```

On `locked`/`unsealed`, the agent runs `spellbook-seed serve`, sends the
link to its human, and waits for the page to report success before it
starts `spellbookd`.

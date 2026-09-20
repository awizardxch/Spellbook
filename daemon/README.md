# spellbook daemon (scaffold)

A small non-LLM policy daemon — one per muse — implementing SPEC_V1.md §4.

**Status: scaffold.** The HTTP/socket plumbing, token auth, route table,
policy evaluation, and the decision ledger are real. Everything that touches
a chain or a secret's curve math is stubbed with an explicit `TODO(build)`
until the open decisions land and audited crypto libs are vendored.

## Layout

| File | What |
|---|---|
| `spellbookd.py` | Entry point: Unix-socket server, routing, token auth, peer-credential check. |
| `kdf.py` | §2 KDF: HKDF-SHA256 + reject/resample (real, stdlib). Curve ops are `TODO(build)` — the daemon must reproduce `vectors/vectors.json` before any real key is derived (§10 step 2). |
| `policy.py` | Policy-config evaluation, default-off (D9). Real logic, no I/O. |
| `ledger.py` | Append-only decision ledger (§4, P6). Real: JSONL, fsync, restart-surviving. |
| `tokens.py` | Request/approve token loading + constant-time check. Real. |
| `config.py` | Config + policy file loading (daemon-user-owned, mode 600). Real. |

## API (SPEC §4)

Request-token routes: `request_spend`, `queue` (read), `status`, `addresses`,
`ledger`, `sign_musebook_request`.
Approve-token routes: `queue/{id}/approve`, `queue/{id}/reject`,
`publish_directory_entry`.

`sign_musebook_request` is implemented but **inert** until the S1 decision:
`musebook_signing_mode` defaults to `"disabled"`. When enabled it builds the
canonical Musebook signing string itself with a fixed domain prefix and
never signs caller-supplied bytes (P1).

## Running (dev only — no secrets, no chains)

```
python3 spellbookd.py --socket /tmp/spellbook-dev.sock --config ./dev-config/
```

The dev config ships with throwaway tokens and a default-off policy.
Nothing here touches a real key.

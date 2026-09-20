# Muse Wallet Stack — SPEC v1 (pre-implementation)

**Status:** spec only. No implementation, no keys generated, nothing on-chain
(testnet included), nothing posted. Implementation begins only after Speechless
approves this spec *and* gives explicit go-ahead per phase.
**Supersedes as canonical plan:** `SPEC_DRAFT.md` and `MUSE_OWNED_WALLET.md`
remain as research notes; this document is the build plan.

**Framing (D13):** this project turns every muse into its own **native EVM
wallet** — self-custodied, derived from the muse key, no third party. The
Sage/Chia branch is a bonus feature on top: same root, same daemon, same
policy engine, heavier machinery.

## 0. Locked decisions

| ID | Decision | Set |
|----|----------|-----|
| D1 | No central authority. Every muse runs its own Sage, derives its own keys, runs its own policy daemon, on its own machine. One compromised muse = one compromised wallet, never the town. | 2026-09-20, Speechless |
| D2 | The muse's Ed25519 key is the custody root. Chain keys are KDF-derived locally from it — never generated as separate mnemonics, never held by a third party. | 2026-09-20, Speechless |
| D3 | A non-LLM policy daemon (per muse) is the only process that holds secrets or signs. Conversational agents request spends; they never see keys. Policy in code, not in prompts. | 2026-09-20 |
| D4 | Sage source pinned to `xch-dev/sage` release tag **v0.13.1**. Upgrades are deliberate: review changelog, re-pin, rebuild. | 2026-09-20, Speechless |
| D5 | Silent: nothing about this project is posted anywhere until Speechless says otherwise. | standing |
| D6 | No on-chain execution without explicit instruction — testnet included. | standing |
| D7 | The six-gate no-launch rule is unaffected: this project moves no tokens and launches nothing. | standing |
| D8 | Keys: local signing only. Never pasted, uploaded, typed into, or sent anywhere — same posture as the aWizard Ed25519 Musebook key. | standing |
| D9 | Thresholds and caps are per muse, set by that muse's human — never town-wide. **Default is no caps**: every policy knob ships disabled/opt-in. Approval is 1-of-1: a single user is the full controller of their individual wallet. (Multisig could change this later; not now.) | 2026-09-20, Speechless |
| D10 | A human may ask for their private keys; the daemon may export them to the owner through a private channel only. Private keys are never posted, published, or written to any shared surface — ever. | 2026-09-20, Speechless |
| D11 | Greenwood is a separate project and is not part of this plan. | 2026-09-20, Speechless |
| D12 | The public distribution repo is named **`spellbook`** — https://github.com/awizardxch/Spellbook. | 2026-09-20, Speechless |
| D13 | Positioning: the project's primary deliverable is every muse's own
  **native EVM wallet** — self-custodied, derived from the muse key. The
  Sage/Chia integration is a bonus feature on the same root. | 2026-09-20, Speechless |
| D14 | Speechless is the first tester: the full install + testnet drill must
  pass on Speechless's own machine before anything is announced to the town. | 2026-09-20, Speechless |

## 1. Architecture (per muse — no shared services)

```
muse Ed25519 seed (existing; e.g. ~/.config/musebook/key.json)
  │  owned by the daemon's OS user (S2) — see "Trust boundary" below
  │
  ├─ KDF("muse-wallet/v1/evm-4663/sign/<label>") ──► secp256k1 secret ──► EVM operational wallet   ◄── PRIMARY (D13)
  │                                                       native EVM: self-custodied, no third party
  │
  └─ KDF("muse-wallet/v1/chia-mainnet/sign/<label>") ──► BLS12-381 secret ──► Sage (headless CLI, v0.13.1)  ◄── BONUS
                                                          native Chia: XCH, CATs, NFTs, DIDs, offers
  │
  ▼
Policy daemon (per muse, dedicated OS user `spellbook` — S2)
  - derives secrets at boot, holds them in memory only
  - enforces caps / allowlist / velocity / human-approval queue in code
  - sole talker to Sage RPC (127.0.0.1:9257, mTLS) and to the EVM RPC endpoint
  - sole signer of Musebook API requests (S1 — recommended, pending Speechless's call)
  │
  ▼
Conversational agents ──► daemon API only (request token). Never keys, certs,
or RPC access. Never the approve/export token (S7).
  │
  ▼
Human ──► cold storage + approval queue above threshold + paper backup of muse key
```

**Trust boundary (S2 — the mechanism, not just the words).** Every "only the
daemon" claim in this spec rests on this: the daemon runs as a dedicated OS
user (`spellbook`, created by the installer; `systemd` `DynamicUser=` where
available). That user alone owns: the seed file, the Sage data dir, the mTLS
certs, the export directory, and the decision ledger — files 0600, dirs 0700.
The agent's tool process runs as the agent's own user and can read exactly one
daemon file: the *request* token. The API listens on a Unix domain socket with
peer-credential checks (preferred) or localhost HTTP; either way the daemon
rejects privileged routes from the request token (S7). Mode 600 alone was the
v1 story and it protected against other users, not against the agent — that
is fixed here.

**Seed hygiene (S1, Mikey).** Today the aWizard seed also lives in the agent's
environment (the Musebook client reads it from `.env` inside the agent's tool
process) — the spec's isolation starts from that true location, not from
where we wish it lived. The fix, recommended: Musebook signing moves behind
the daemon via `POST /v1/sign_request {bytes}` → `{signature}`; `musebook.mjs`
and any sibling agent hold a request token, not the seed. Then D3 ("the
daemon is the only process that holds secrets") is true by construction and
one paper backup still covers everything. **This changes how aWizard signs
Musebook posts today — pending Speechless's explicit call.** The honest
alternative, documented: a separate wallet root (daemon-generated 32-byte
seed; identity key signs directory entries only; two papers).

What is per-muse and never shared: muse key, derived secrets, Sage instance and
`keys.bin`, mTLS certs, daemon process and its queue. What may be shared (holds
no keys): daemon source code, setup guide, town directory (addresses only).

## 2. Key derivation spec

- **KDF:** HKDF-SHA256 (RFC 5869). Boring and standard by design.
- **IKM:** the 32-byte Ed25519 private *seed* (not the 64-byte expanded secret).
- **salt (fixed, public):** `"muse-wallet-v1"`.
- **info (purpose registry — fixed strings, never reused across purposes):**
  `info = "muse-wallet/v1/" + chain + "/" + purpose + "/" + label`, where
  `chain` carries the chain id (`evm-4663`, `evm-46630`, `chia-mainnet`,
  `chia-testnet`), `purpose` is `sign` (spend-signing) or `derive` (address
  derivation), and `label` names the wallet (`default`, `tips`, `bounties`,
  `trading`). The tag carries chain id + purpose (Turbo's checkable binding)
  so one seed can never collide across contexts.
- **One standalone key per label (S5):** each info string yields its own
  secp256k1/BLS key. There is no HD beneath a derived master — a 32-byte
  scalar is not a BIP-32 master (no chain code), so every labeled address is
  its own key and restores with a plain private-key import in stock software.
  The daemon never invents a chain code.
- **Expand length:** `L = 32` always.
- **Bytes → scalar (single rule — S12, Nimbus):** interpret the 32 info-bound
  bytes big-endian as an integer. If the value is zero or ≥ the curve order
  (secp256k1 `n`, BLS12-381 `r`), re-expand with info suffixed `"/ctr/1"`,
  `"/ctr/2"`, … and retry. Never reduce modulo the order — reduction biases
  the distribution and lets two implementations disagree.
- **BLS12-381:** scalar → secret key → G1 public key by standard BLS keygen →
  Chia address (bech32m) via Sage's derivation for the imported key.
- **secp256k1:** scalar → standard private key → **uncompressed** 64-byte
  public key → EVM address = last 20 bytes of `keccak256(pubkey)`. (v1 of this
  spec said compressed — wrong; an Ethereum address is keccak of the
  uncompressed key. S5.)
- **Key-reuse tradeoff, stated out loud (Nimbus):** one root does identity
  AND money. Identity compromise = funds compromise, and a town identity key
  cannot rotate the way a wallet key can. Accepted deliberately (D2); the
  mitigation is the daemon-user boundary (§1/S2) plus moving Musebook signing
  behind the daemon (S1 — recommended, pending Speechless's call), which
  shrinks the seed's exposure to a single OS user. The documented opt-out: a
  separate wallet root (daemon-generated 32-byte seed; the identity key signs
  directory entries only; the human keeps two papers).
- **Honesty row (ARION):** the 24 words ARE every chain's wallet.
  Backup-compromise = total compromise. There is no separate "identity
  backup" vs "funds backup" — one root, one blast radius.
- **Test vectors (implementation gate — Turbo, ARION, Zuckbot):**
  `vectors/vectors.json` in the repo holds, per vector,
  `{vector_id, test_seed_hex, domain_tag, chain, expected_address,
  expected_pubkey}`, plus negative vectors (short seed, bad BIP-39 checksum,
  first-expansion-rejected scalar) each carrying its expected failure — specs
  fork at the edges nobody wrote down, so the edges are written down. One
  SHA-256 over the canonical file per spec version, printed in this spec.
  Before any real key is derived, two independent implementations (e.g.
  Python `hkdf`+`coincurve`+`py_ecc` vs the daemon) must reproduce every
  vector from the published test seed. Mismatch = stop.
- **Binding row (Turbo):** the town directory entry (§8) carries
  `muse_id + ed25519_pubkey + domain_tag → address`, so a stranger recomputes
  any address from the public key without trusting any daemon.
- **Agent-agnostic:** the KDF's only input is a 32-byte Ed25519 seed. Any agent
  holding one — a Musebook muse, a Claude-based agent, anything — derives the
  same wallets from the same seed. Nothing in §2–§7 is Musebook-specific. The
  Musebook layer is thin and sits on top: the default key path (§4), the
  identity field in the directory schema (§8), and the town watcher (§14). A
  non-muse agent adopts spellbook by pointing the daemon at its own Ed25519
  key file. (The `"muse-wallet/…"` purpose strings are frozen — "muse" reads
  fine as a generic term for an AI agent.)

### Address derivation — many hot addresses, one root (revised per S5)

New labeled addresses never need a new backup, and every one restores in stock
software:
- **Chia:** the daemon imports the `chia-mainnet/sign/default` BLS secret;
  Sage manages address discovery natively (derivations, derivation indices,
  gap limit). Labeled receive addresses come through the Sage RPC.
- **EVM:** each label is its own info string
  (`muse-wallet/v1/evm-4663/sign/<label>`) → its own secp256k1 key → its own
  address. `tips`, `bounties`, `trading` are independent keys, each
  importable as a plain private key anywhere.
- `GET /v1/addresses` returns the labeled set. The town directory may list
  several addresses per muse, each with its binding row (§8).
- Backup is unchanged: the root backup re-derives every label ever created.

## 3. Sage deployment spec (per muse)

- **Source:** `xch-dev/sage` at tag `v0.13.1` (D4), pinned **by commit as well
  as tag**: `f2ec89dd59d07227bed657bc268fc32ce97551f6` (a git tag is mutable;
  the commit is not — S9). Install from the release binary built from that
  commit, or `cargo install --git … --rev f2ec89dd…`. Upgrades are deliberate:
  review changelog, re-pin commit, rebuild.
- **Mode:** CLI only. Never run GUI and CLI simultaneously (they can overwrite
  each other's data).
- **Network:** testnet first (Phase 1). Mainnet only after the Phase 1 drill
  passes *and* Speechless approves Phase 2.
- **Data dir:** OS default (`~/.local/share/com.rigidnetwork.sage/` on Linux),
  owned by the daemon's OS user (S2) — the agent's user cannot read `keys.bin`.
- **RPC:** `sage rpc start` → `https://127.0.0.1:9257`, mutual TLS; certs under
  `<datadir>/ssl/`, daemon-user-owned. The daemon is the only process that
  reads the client cert.
- **Key import:** at first boot the daemon imports the derived BLS secret via
  `POST /import_key` as a 32-byte hex private key (verified against
  `v0.13.1`: 32-byte hex → raw BLS master secret; 48-byte hex → watch-only
  public key — S11). `save_secrets` defaults true; the daemon sets it
  explicitly true and fails closed if the wallet comes back watch-only. The
  wallet fingerprint is recorded in the daemon config. No mnemonic is ever
  generated or displayed.
- **Sync:** Sage connects to Chia peers directly or to a configured trusted
  node. Record observed sync behavior in the Phase 1 log; slow/failed sync is a
  go/no-go input for Phase 2.

## 4. Policy daemon spec

A small non-LLM service (one per muse), running as the dedicated `spellbook`
OS user (§1), listening on a Unix domain socket (peer-credential checks) or
localhost HTTP. It is the *only* process that may hold secrets, read the Sage
mTLS cert, or submit transactions.

**Secrets handling**
- At boot: reads the configured Ed25519 key file (default
  `~/.config/musebook/key.json` for muses; any 32-byte Ed25519 seed file works
  — §2 is agent-agnostic), daemon-user-owned, mode 600; runs the §2 KDF;
  holds derived secrets in memory only, zeroes them on shutdown. Never writes
  secrets to disk. Never logs them.
- The only secret-export path is the **human-local export command** (below) —
  there is no agent-callable export route (S3).

**API — two tokens from day one (S7)**
- A *request token* lives in the agent's environment: it may call
  `request_spend`, `queue` (read), `status`, `addresses`, `sign_request`.
- An *approve token* is held only by the human's own tooling (a tiny CLI on
  the human's machine; v1 may use the O5 HMAC — O5 is a Phase 1 item, not an
  improvement). It alone may call `/approve`, `/reject`, and the export
  command's auth. The daemon rejects privileged routes presented with the
  request token: an approval the requester can grant is not an approval.
- `POST /v1/request_spend {chain, destination, asset, amount_mojos|wei, purpose}`
  → `{decision: "approved"|"queued"|"denied", reason?, queue_id?, txid?}`
  (v1 scope is plain transfers only — the schema cannot express contract
  calls, deliberately (S13); contract-call support arrives with the intent
  decoder below.)
- `GET /v1/queue` → pending human approvals with full decoded intent
- `POST /v1/queue/{id}/approve` and `/reject` → approve-token only
- `GET /v1/status` → balances, caps, velocity windows, queue depth
- `GET /v1/addresses` → the muse's labeled Chia and EVM addresses
- `POST /v1/sign_request {bytes}` → `{signature}` — daemon-side Musebook
  request signing (S1 — recommended, pending Speechless's call)

**Policy config (per muse, file, daemon-user-owned, mode 600 — set by that
muse's human, D9)**

Defaults: **everything off** (D9) — and the spec says so plainly: the default
daemon is a *signer*, not a policy engine, until the human writes a config
(S4). A prompt-injected agent with the request token can empty the hot wallet
in one call under the default config. The hot wallet should therefore hold
nothing the agent may not lose, and the installer says so out loud. Each human
may opt in to any subset of the knobs below; the daemon enforces whatever is
configured, nothing more.
- `per_spend_cap` per chain/asset — any request above is denied outright
- `approval_threshold` per chain/asset — requests above auto-approve level but
  below the cap are queued for the human (1-of-1 approval, D9)
- `auto_approve_below` — small spends execute immediately
- `daily_velocity_cap` per chain — rolling 24h sum; breaching denies until window clears
- `destination_allowlist` (optional) — when set, non-allowlisted destinations
  above the auto-approve level are denied rather than queued
- All amounts in base units (mojos / wei).
- **Decision ledger (S10, Turbo, ARION):** every intent and decision is
  appended to a daemon-user-owned log — never secrets. Row shape, canonical:
  `{ts, requester_muse, canon_digest(request_bytes_stored), sighash, decision}` —
  the digest is over the stored bytes, never a quote, so the trail is
  stranger-recomputable and clips can't drift it. This matches the desk
  registry's shape (ARION's offer taken up; exact schema to be confirmed
  against the registry's canonical thread). The ledger survives restarts —
  the velocity window and queue with it (§10 step 11).

**Human approval path (v1)** — dormant unless an `approval_threshold` is
configured (default off, D9).
- Queued spends surface to the human's own tooling (approve token), showing
  the **decoded intent** — never just a hash (Zuckbot's blind-signing fix):
  `to`, `value`, and decoded calldata for at least the ERC20 / ERC721 /
  Permit2 shapes; anything the decoder cannot parse is labeled OPAQUE and
  treated as hostile (denied unless a policy explicitly allows opaque
  calldata). The decoder is part of the daemon, not the agent.
- **No malicious-relay assumption:** the v1 "agent relays the human's chat
  approval" design is removed with the two-token split (S7). The daemon's job
  remains bounding *autonomous* agent spends.

**Key export — owner only, human-local (D10, S3)**
- Export is **never an API call the agent can make**. It is a local command
  the human runs as the daemon user: `spellbook export --scope muse-root |
  --scope <label>`, with an interactive confirmation on the daemon's own TTY,
  writing into a directory the agent's user cannot read (S2). The conversational
  agent MUST NEVER invoke it, read its output file, reproduce key material in
  chat, or write it anywhere else.
- The export file contains, clearly labeled per item: the 24-word BIP-39
  encoding of the root (words = root only, restores via our tooling only) and
  the hex of each requested wallet key (hex = that wallet's key, imports as a
  private key into stock software). Beside each hex, its exact restore
  instruction ("paste into Sage `/import_key` as a private key"; "import as a
  private key into any EVM wallet"). The root is exported as words only and
  wallet keys as hex only, so the two cannot be confused at restore time
  (S11) — a 32-byte root hex pasted into Sage yields a different, empty
  wallet with no error, and the labeling is the guard.
  - `hex` per label: the **tooling-independent backup**. EVM label hex →
    any EVM wallet's private-key import → exactly that address. Chia hex →
    Sage `/import_key` (verified: 32-byte hex = raw BLS master secret at
    v0.13.1) → exactly that wallet. (Zuckbot's nit, answered precisely: the
    stock-import promise covers EVM-via-any-wallet and Chia-via-Sage; it does
    not cover generic BLS tooling.)
  - `words`: 24-word BIP-39 encoding (fixed wordlist + checksum algorithm
    pinned in the spec) of the 32-byte root. Hand-copyable, checksum built
    in. For the root this is the paper backup — but it restores **only
    through our tooling** (words → bytes → §2 KDF → chain keys). Pinning
    BIP-39 (Nimbus) standardizes transcription; it does **not** make the
    words a standard mnemonic — typing them into a stock wallet's
    mnemonic field derives a different key (Sage runs
    `SecretKey::from_seed(mnemonic.to_seed(""))`, S11). The export file states
    this in plain language: *never type these words into a wallet expecting
    our wallet back.*
- Private keys are never posted, published, committed, logged, or written to
  any shared surface — including Musebook, the town directory, chat
  transcripts that get published, and this repo. No exceptions.

**Build → verify → sign → submit discipline**
- Chia: build with `auto_submit: false`, verify the summary against the
  approved intent, then sign and submit.
- EVM: simulate/estimate, verify recipient/amount/chain id against the decoded
  intent, then sign. No contract calls in v1 (schema can't express them —
  deliberate); the decoder gates their future.

## 5. EVM operation spec — the primary deliverable (D13)

- **The pitch:** one command turns a muse's Ed25519 key into that muse's own
  native, self-custodied EVM wallet — no Bankr, no Privy, no third party
  holding anything. This is the feature; everything else is supporting cast.

- Key: the §2 `evm-hot/v1` secp256k1 derivation. Address published by the muse
  to the town directory (only the key holder can compute it — self-reported,
  like the Chia address).
- The daemon signs EIP-1559 transactions via a local signer against a
  configurable chain RPC endpoint. Default town chain: Robinhood Chain
  (chain id 4663; testnet 46630 for Phase 1).
- Same policy engine as Chia (§4), caps denominated per chain.
- The existing Bankr/X Privy wallet remains the EVM treasury; the derived key
  is the muse's self-custodied operational wallet.
- (Greenwood vault integration is a separate project per D11 — not in this plan.)

## 6. Hot / cold and backup

- **Hot (per muse):** the daemon-guarded wallets above (caps opt-in, default
  none — D9). Day-to-day town activity lives here.
- **Cold (human-held):** Speechless's own Sage / hardware wallet; no agent
  process can reach it. Surplus above a hot cap — when one is set — is swept
  to cold on a schedule (O6) via the approval queue.
- **Paper backup (O7 — approved 2026-09-20):** the human writes down the
  32-byte muse Ed25519 seed on paper, stored offline. One backup covers the
  whole stack — the Musebook identity plus every derived hot wallet re-derives
  from it.
  1. Human requests the backup in chat.
  2. Human runs `spellbook export --scope muse-root` as the daemon user on
     their own machine (S3 — the agent never invokes export, never sees the
     output).
  3. Daemon writes the seed (24-word phrase; root is words-only, S11) to a
     fresh file in a directory the agent's user cannot read; prints only the
     path on its own TTY.
  4. Human reads the file through their own machine access, copies the
     24-word phrase to paper (words are easier to hand-copy than hex, and the
     built-in checksum catches transcription errors), stores offline.
  5. Human confirms done; the file is deleted (by the human, or by the daemon
     on confirmation).
  6. The agent never sees, reads, or reproduces the bytes — in chat or
     anywhere (D10).
  7. Verification is local-only: the human may re-derive and compare on their
     own machine. Key material never transits chat.
- **Second backup — the wallet keys themselves (recommended):** the paper backup
  above restores via our tooling. For backups that need no custom software,
  the human may additionally write down each label's **hex** from
  `spellbook export --scope <label>`: importing that hex as a private key
  into Sage (Chia labels) or any EVM wallet (EVM labels) recovers the exact
  hot wallet with stock software. Two pieces of paper: one root (words → our
  tooling), one set of wallet hexes (hex → any wallet).
- **Restore (disaster recovery) — path (a), full stack via our tooling:**
  1. On a fresh machine: install the daemon + Sage per §3.
  2. Human types the 24-word phrase from the paper backup into a fresh file,
     mode 600 — the only time key material is manually entered, and only ever
     into a local file.
  3. Daemon import verifies the BIP-39 checksum, decodes to 32 bytes, and
     re-derives all chain keys (§2). Checksum failure = stop and recheck the
     words against the paper.
  4. Human deletes the words file after successful re-derivation.
  5. The agent never sees the words or bytes at any point (D10).
- **Restore — path (b), wallet-only with stock software:** import a label's
  **hex** as a private key directly into Sage (`/import_key`, Chia labels) or
  any EVM wallet (EVM labels). No daemon, no KDF, no custom code — this is the
  backstop if our tooling is ever unavailable.
- The cold wallet follows its own backup procedure.
- Balances stay modest until the stack has run cleanly on mainnet through at
  least one full rotation drill.

## 7. Rotation spec

Trigger: suspected compromise, or scheduled. Steps, in order:
1. Generate a new muse Ed25519 key; complete Musebook's rotation/re-onboarding
   for the muse identity (mechanics TBD — O2).
2. Fresh Sage data dir + fresh daemon config on the muse's machine; derive the
   new chain keys (§2); import into Sage; record new fingerprint.
3. Sweep every asset old → new (Chia via daemon-built spends, EVM via daemon;
   each sweep human-approved through the queue).
4. Publish the new addresses to the town directory (§8), signed by the *new*
   muse key; include a signed supersession statement from the old key if it is
   still available.
5. Destroy the old: delete old Sage data dir, wipe old daemon config, zero
   memory, confirm zero balances on old addresses.
6. No rotation story tested on testnet = no mainnet deployment (Phase 1 gate).

**Conflict rule (S8):** directory consumers accept only entries signed by the
key Musebook currently binds to that `muse_id` — rotation validity is anchored
to the Musebook binding, which a compromised old key cannot rewrite. Until O2
(Musebook rotation mechanics) is answered, rotation is **unspecified**, and by
this spec's own rule an unspecified rotation gates mainnet: no mainnet
deployment until the rotation story is fully specified *and* drilled.

## 8. Town directory spec

- **Content per agent:** `agent_id` (a muse's `muse_id`), `chia_addresses[]`,
  `evm_addresses[]` (labeled, §2), `agent_pubkey` (the Ed25519 identity key),
  `key_fingerprint`, `domain_tags[]`, `updated_at`, plus a signature over the
  entry by the identity key (self-attestation). The entry carries Turbo's
  binding row — `muse_id + ed25519_pubkey + domain_tag → address` — so a
  stranger recomputes every address from the public key without trusting any
  daemon.
- **Format:** JSON (schema frozen at implementation; versioned).
- **Location/publishing:** TBD — repo or Musebook board (O3). Silent until
  Speechless un-silences (D5).
- **Updates:** the muse republishes on rotation (§7); entries are append-only
  history, never edited in place.

## 9. Conversational agent contract

Agents (including aWizard's chat presence) MUST NEVER: read the muse key for
derivation, touch the Sage RPC, read the mTLS certs, see or log secrets,
construct/submit transactions directly, reproduce private key material in chat
or anywhere else (D10), read the daemon's key-export output file, invoke the
export command, or present the request token to privileged routes.
Agents MAY: call the daemon's request-token API (`request_spend`, `queue`
read, `status`, `addresses`, `sign_request`) and read the decision ledger.
Standard spend flow: agent drafts intent → `request_spend` → approved (execute),
queued (the human's own tooling approves via the approve token — the agent
never relays approvals), or denied (report reason).

## 10. Test plan — Phase 1 (testnet)

All steps on testnet with a **throwaway test muse key** (never the real one).
Steps 4–7 enable temporary test values to prove the policy machinery works,
then reset the config to default-off (D9). The EVM path is the primary
acceptance target (D13); the Chia/Sage path is drilled alongside as the bonus
feature.
1. Install Sage CLI from the pinned tag; verify version string.
2. Daemon boots; §2 test vectors reproduce; imports derived test key into Sage.
3. Fund from the testnet faucet; confirm receipt via `/get_sync_status`.
4. Spend below auto-approve threshold → executes, confirms on-chain.
5. Spend above approval threshold → queued → relay approval in chat → executes.
6. Spend above per-spend cap → denied with reason.
7. Velocity: exceed daily cap → denied until window clears.
8. Offer flow: `make_offer` → `take_offer` between two test wallets.
9. EVM: derive address, fund on Robinhood testnet (46630), send a small tx
   through the daemon; verify caps/queue behavior.
10. Rotation drill (§7) end-to-end on testnet.
11. Kill -9 the daemon mid-queue; verify no secret material on disk, clean
    reboot re-derives correctly, **and** the decision ledger, velocity window,
    and queue survive the restart (S10 — policy state is not allowed to be
    memory-only).
12. Boundary drill (S2): as the agent's OS user, attempt to read the seed
    file, the Sage data dir, the mTLS certs, the export directory, and the
    decision ledger — and attempt to call `/approve` with the request token.
    Every attempt must fail.
13. Seed-hygiene drill (S1): grep the agent's environment and workspace for
    the seed (or any 32-byte value matching it); the drill fails if it is
    found anywhere outside the daemon user's files.

**Mainnet smoke test (dust amounts — separate explicit go-ahead, real funds)**
14. Fund the hot wallets with dust: a few cents of XCH and a tiny amount of
    the Robinhood Chain (4663) gas token — amounts approved by Speechless.
15. Self-send dust XCH through the daemon (build → verify → sign → submit);
    confirm on-chain.
16. Small EVM self-send on Robinhood Chain mainnet through the daemon;
    verify policy behavior against the real chain id.
17. Record observed mainnet peer/sync/RPC behavior vs testnet; sweep or leave
    the dust per Speechless's call.
Steps 14–17 run only on Speechless's explicit instruction, and only after
steps 1–13 are fully green. Testnet proves the logic; mainnet dust proves the
real path.

All green → Phase 2 proposal to Speechless. Any red → fix, re-run, re-report.

## 11. Phases

- **Phase 0 — spec (this document).** Done when Speechless approves; open
  questions (§12) answered or explicitly deferred.
- **Phase 1 — build + testnet drill + gated mainnet smoke test.** Daemon + KDF
  implementation; full §10 drill for the aWizard reference implementation
  (EVM-first); then §10 steps 14–17 on mainnet with dust amounts, on
  Speechless's explicit go-ahead.
- **Phase 2 — aWizard mainnet hot wallet.** No caps by default (D9); cold
  storage live; sweep schedule running.
- **Gate — first test (D14).** Before anything is announced: Speechless runs
  the installer on their own machine, verifies the signature check, completes
  the §10 testnet drill with a throwaway key, and exercises the paper-backup
  export flow. The town announcement waits for their sign-off.
- **Phase 3 — town kit.** §14 distribution: public repo, signed releases,
  one-line self-verifying installer, town announcement, new-muse watcher.
  Town directory goes live when Speechless un-silences (D5/O3).

**Deferred (not in this plan):** greenwood vault integration — separate
project per D11. Its research stays in `SPEC_DRAFT.md` §1–§2 for whenever that
project starts.

## 12. Open questions (need answers before the phases they gate)

- **O1** — moved to the deferred greenwood project (D11). Not in this plan.
- **O2** (gates §7): Musebook key-rotation mechanics — can a muse rotate to a
  new Ed25519 key under the same `muse_id`?
- **O3** (gates Phase 3): town directory location/format + the un-silencing
  decision. Speechless.
- **O4** — answered: default is no caps (D9); each muse's human may opt in to
  caps/thresholds. No numbers needed.
- **O5** (Phase 1 item, per S7): human-approval auth — the approve token is
  held only by the human's own tooling (v1: O5 HMAC from a human-held key).
  The chat-relayed approval design is removed.
- **O6** (gates Phase 2): cold sweep schedule and mechanics.
- **O7** — answered: yes, via the private export flow (§6). The human writes
  the muse seed on paper and stores it offline; the agent never sees the bytes.

## 13. Residual risks (accepted, not solved)

- **VM compromise** takes the hot wallet — that is what the hot/cold split and
  caps are for; the daemon does not defend this layer. Note the default
  config is a signer, not a policy engine (S4) — caps only help once the
  human opts in.
- **Monoculture:** one daemon codebase for every muse = one bug fits all.
  Open-source it, audit before Phase 3, welcome independent implementations.
  The `vectors/` file lets independent implementations prove conformance.
- **Supply chain:** Sage pinned to `v0.13.1` **by commit**
  `f2ec89dd59d07227bed657bc268fc32ce97551f6` as well as tag (D4/S9); the
  installer itself is in scope — its SHA-256 and the release-key fingerprint
  are published in the pinned town thread and the README, release tags are
  signed, and the documented install command verifies before executing (S9).
  Track upstream advisories; deliberate upgrades only.
- **Social layer:** a compromised muse can still lie to other muses. Per-muse
  custody bounds the financial blast radius, not the social one.
- **Seed bedroom (Mikey/S1):** until Musebook signing moves behind the
  daemon, the seed lives where the agent can read it — the wallet is only as
  safe as the seed's bedroom. The §10 seed-hygiene drill keeps this honest.

## 14. Distribution — automatic, pull-only

Distribution follows D1: we publish code, muses pull it themselves. Nobody's
machine is ever touched by us; nothing is pushed; no one's keys are ever
involved. "Automatic" means a new muse's agent goes from zero to a
testnet-proven install with one command and no human coordination.

**Source repo — `spellbook` (public, after un-silencing per D5; D12)**
- https://github.com/awizardxch/Spellbook
- Daemon source, setup guide, install script, §2 KDF test vectors, JSON
  schemas (policy config, directory entry).
- Tagged releases (`vX.Y.Z`); tags signed with the release key. Per tag: source
  tarball + SHA256 checksums + detached signature.

**One-line installer (S9 — verify before you run)**
- The documented command is *not* `curl | bash`. It is:
  `curl -fsSL -o install.sh https://raw.githubusercontent.com/awizardxch/Spellbook/<tag>/install.sh`
  then `sha256sum -c` against the hash published in the pinned town thread
  and the README (or `git clone` the tag + `git verify-tag`), and only then
  `bash install.sh`. The script that does the signature verification is
  itself verified first — a compromised tag rewrites every muse at once
  otherwise. Release tags are signed with the release key; the fingerprint is
  published in the pinned thread.
- The installer:
  1. Fetches the pinned release tarball + checksum + signature; verifies both
     against the pinned release-key fingerprint — fail closed on mismatch,
     never installs unverified code.
  2. Installs Sage CLI from its pinned commit (§3 / D4).
  3. Creates the dedicated `spellbook` OS user (S2); builds and installs the
     daemon under it; writes a default-off policy config (D9).
  4. Runs the §10 testnet drill automatically with a throwaway key — minus
     the rotation drill, which runs on the maintainer's machine only (S14).
     The install only completes when the drill passes — every install proves
     itself on testnet before mainnet is possible. A failed drill leaves the
     machine clean and prints how to resume without reinstalling (S14).
  5. Prints next steps: opt-in policy knobs, paper backup (§6), directory
     entry (§8) — and says out loud that the default config is a signer, not
     a policy engine (S4).
- The installer never asks for keys, never transmits anything outward, and
  never touches the real muse key — the drill uses a throwaway.

**Upgrades**
- New release → announcement in the town thread → each muse re-runs the
  installer, which re-verifies, rebuilds, and re-runs a smoke subset of the
  drill. No silent auto-update: auto-update is a remote-code-execution vector,
  so every upgrade is pulled and approved by that muse's human.

**Discovery (gated by D5 un-silencing / O3 / D14 first-test)**
- Pinned town thread: the installer line, the release-key fingerprint, what
  the installer does and never does, and the verification story. One thread,
  kept current — not repeated broadcasts.
- **New-muse watcher (proposed):** a town cron watches for new muse intro
  posts; on each, a short reply *inside that intro thread* offers the kit —
  one-line installer, one sentence of what it is ("turns your muse key into
  your own native EVM wallet — Chia via Sage included as a bonus"), link to
  the pinned thread.
  This matches the town norm (replies in live threads, never broadcasts) and
  makes distribution genuinely automatic: every new muse is offered the kit
  with zero coordination. Clearly labeled, no pressure, never repeated to the
  same muse. Needs Speechless's go-ahead at un-silencing.

**What "automatic" never means:** we never push code to anyone, never run
anyone's daemon, never hold anyone's keys, never see anyone's secrets. Pull,
verify, install locally — per muse, per D1.

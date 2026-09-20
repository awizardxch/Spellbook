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

## 1. Architecture (per muse — no shared services)

```
muse Ed25519 key (existing; e.g. ~/.config/musebook/key.json, mode 600)
  │
  ├─ KDF("muse-wallet/evm-hot/v1") ──► secp256k1 secret ──► EVM operational wallet   ◄── PRIMARY (D13)
  │                                                       native EVM: self-custodied, no third party
  │
  └─ KDF("muse-wallet/chia-hot/v1") ──► BLS12-381 secret ──► Sage (headless CLI, v0.13.1)  ◄── BONUS
                                                          native Chia: XCH, CATs, NFTs, DIDs, offers
  │
  ▼
Policy daemon (localhost only, per muse)
  - derives secrets at boot, holds them in memory only
  - enforces caps / allowlist / velocity / human-approval queue in code
  - sole talker to Sage RPC (127.0.0.1:9257, mTLS) and to the EVM RPC endpoint
  │
  ▼
Conversational agents ──► daemon API only. Never keys, certs, or RPC access.
  │
  ▼
Human ──► cold storage + approval queue above threshold + paper backup of muse key
```

What is per-muse and never shared: muse key, derived secrets, Sage instance and
`keys.bin`, mTLS certs, daemon process and its queue. What may be shared (holds
no keys): daemon source code, setup guide, town directory (addresses only).

## 2. Key derivation spec

- **KDF:** HKDF-SHA256 (RFC 5869). Boring and standard by design.
- **IKM:** the 32-byte Ed25519 private *seed* (not the 64-byte expanded secret).
- **salt (fixed, public):** `"muse-wallet-v1"`.
- **info (purpose registry — fixed strings, never reused across purposes):**
  - `"muse-wallet/evm-hot/v1"` → secp256k1 secret (primary, D13)
  - `"muse-wallet/chia-hot/v1"` → BLS12-381 secret (bonus)
  - Reserved and **forbidden on hot machines**: `"muse-wallet/chia-cold/v1"`,
    `"muse-wallet/evm-cold/v1"` (cold derivations happen only on the human's
    cold machine, if ever used).
- **Bytes → scalar:** interpret the 32 info-bound bytes big-endian as an
  integer; if ≥ the curve order, HKDF-expand with info suffixed `"/ctr/1"`,
  `"/ctr/2"`, … and retry. (Probability negligible; the rule exists so the
  construction is total and deterministic.)
- **BLS12-381:** scalar mod r → secret key → G1 public key by standard BLS
  keygen → Chia address (bech32m) via Sage's derivation for the imported key.
- **secp256k1:** scalar mod n → standard private key → compressed public key →
  EVM address (`keccak256(pubkey)[12:]`).
- **Test vectors (implementation gate):** before any real key is derived, the
  implementation must reproduce fixed vectors: known 32-byte test seed →
  expected BLS pubkey/address and expected EVM address, computed independently
  (e.g. Python `ecdsa`/`bls` reference vs the daemon's implementation). Mismatch
  = stop.
- **Agent-agnostic:** the KDF's only input is a 32-byte Ed25519 seed. Any agent
  holding one — a Musebook muse, a Claude-based agent, anything — derives the
  same wallets from the same seed. Nothing in §2–§7 is Musebook-specific. The
  Musebook layer is thin and sits on top: the default key path (§4), the
  identity field in the directory schema (§8), and the town watcher (§14). A
  non-muse agent adopts spellbook by pointing the daemon at its own Ed25519
  key file. (The `"muse-wallet/…"` purpose strings are frozen — "muse" reads
  fine as a generic term for an AI agent.)

### Address derivation — many hot addresses, one key (noted 2026-09-20, Speechless)

Each scope above yields a *master* secret. Individual hot-wallet addresses
derive beneath it with standard HD derivation — new addresses never need a new
backup:
- **Chia:** once the BLS master secret is imported, Sage manages address
  discovery natively (derivations, derivation indices, gap limit). The daemon
  requests labeled receive addresses through the Sage RPC.
- **EVM:** BIP-44 `m/44'/60'/0'/0/i` beneath the derived secp256k1 master. The
  daemon derives child keys locally and never exposes them beyond signing.
- `GET /v1/addresses` returns the labeled set (e.g. `tips`, `bounties`,
  `trading`). The town directory may list several addresses per muse.
- Backup is unchanged: the root backup re-derives every address ever created.

## 3. Sage deployment spec (per muse)

- **Source:** `xch-dev/sage` at tag `v0.13.1` (D4). Install via
  `cargo install --git https://github.com/xch-dev/sage --tag v0.13.1 sage-cli`
  or the release binary built from the same tag.
- **Mode:** CLI only. Never run GUI and CLI simultaneously (they can overwrite
  each other's data).
- **Network:** testnet first (Phase 1). Mainnet only after the Phase 1 drill
  passes *and* Speechless approves Phase 2.
- **Data dir:** OS default (`~/.local/share/com.rigidnetwork.sage/` on Linux).
- **RPC:** `sage rpc start` → `https://127.0.0.1:9257`, mutual TLS; certs under
  `<datadir>/ssl/`. The daemon is the only process permitted to read the client
  cert (file permissions).
- **Key import:** at first boot the daemon imports the derived BLS secret via
  `POST /import_key`; the wallet fingerprint is recorded in the daemon config.
  No mnemonic is ever generated or displayed.
- **Sync:** Sage connects to Chia peers directly or to a configured trusted
  node. Record observed sync behavior in the Phase 1 log; slow/failed sync is a
  go/no-go input for Phase 2.

## 4. Policy daemon spec

A small non-LLM service (one per muse, bound to localhost). It is the *only*
process that may hold secrets, read the Sage mTLS cert, or submit transactions.

**Secrets handling**
- At boot: reads the configured Ed25519 key file (default
  `~/.config/musebook/key.json` for muses; any 32-byte Ed25519 seed file works
  — §2 is agent-agnostic), mode 600, runs the §2 KDF, holds derived secrets in
  memory only, zeroes them on shutdown. Never writes secrets to disk — except the
  human-authenticated `/v1/export_key` output file (mode 600, deleted after
  use). Never logs them. The only secret-export path is `/v1/export_key`,
  which returns a file path, never bytes.

**API (localhost HTTP; authenticated by a bearer token in a file, mode 600)**
- `POST /v1/request_spend {chain, destination, asset, amount_mojos|wei, purpose}`
  → `{decision: "approved"|"queued"|"denied", reason?, queue_id?, txid?}`
- `GET /v1/queue` → pending human approvals with full intent details
- `POST /v1/queue/{id}/approve` and `/reject` → human path (see below)
- `GET /v1/status` → balances, caps, velocity windows, queue depth
- `GET /v1/addresses` → the muse's labeled Chia and EVM addresses (multiple
  per chain, §2 HD derivation)

**Policy config (per muse, file, mode 600 — set by that muse's human, D9)**

Defaults: **everything off** (D9). No per-spend cap, no approval threshold, no
velocity cap, no allowlist — spends auto-approve and the human queue stays
dormant. Each human may opt in to any subset of the knobs below; the daemon
enforces whatever is configured, nothing more.
- `per_spend_cap` per chain/asset — any request above is denied outright
- `approval_threshold` per chain/asset — requests above auto-approve level but
  below the cap are queued for the human (1-of-1 approval, D9)
- `auto_approve_below` — small spends execute immediately
- `daily_velocity_cap` per chain — rolling 24h sum; breaching denies until window clears
- `destination_allowlist` (optional) — when set, non-allowlisted destinations
  above the auto-approve level are denied rather than queued
- All amounts in base units (mojos / wei). All decisions logged (intents and
  decisions — never secrets).

**Human approval path (v1)** — dormant unless an `approval_threshold` is
configured (default off, D9).
- Queued spends surface to the human in chat via the conversational agent, which
  shows the full intent (destination, asset, amount, purpose) and relays the
  human's decision to `/approve` or `/reject`.
- **Documented trust assumption (v1):** the conversational agent is trusted to
  relay the human's approval honestly. The daemon's job is bounding *autonomous*
  agent spends, not defending against a malicious relay. (v2 improvement: the
  approve endpoint requires an HMAC from a human-held key — see O5.)

**Key export — owner only (D10)**
- `POST /v1/export_key {scope}` where scope is `"muse-root"`, `"chia-hot"`,
  or `"evm-hot"` — human-authenticated only (same bar as `/approve`; v2 HMAC
  when it exists). The daemon writes a fresh file, mode 600, containing both
  encodings of the 32-byte secret, clearly labeled. It returns **only the file
  path** — never the bytes.
  - `hex`: the raw secret bytes. This is the **tooling-independent backup**:
    import it as a *private key* (not a mnemonic) into Sage (`/import_key`
    accepts private keys) or any EVM wallet → exactly this wallet, with stock
    software, no custom tooling.
  - `words`: 24-word BIP-39 encoding of the same 32 bytes. Hand-copyable,
    checksum built in. For `"muse-root"` this is the paper backup — but it
    restores **only through our tooling** (words → bytes → §2 KDF → chain
    keys).
- **The critical distinction** (stated in the export file itself): typing the
  *words* into a standard wallet's mnemonic/import-phrase field derives a
  **different** key — BIP-39 runs the entropy through PBKDF2 plus the wallet's
  own master-key derivation. Words reproduce our exact keys only via our decode
  path. The *hex* reproduces the exact wallet key via any standard private-key
  import. Never type the words into a wallet expecting our wallet back.
- The conversational agent MUST NEVER read that file, reproduce key material
  in chat, or write it anywhere else. The human retrieves it through their own
  machine access.
- Private keys are never posted, published, committed, logged, or written to
  any shared surface — including Musebook, the town directory, chat transcripts
  that get published, and this repo. No exceptions.

**Build → sign → submit discipline**
- Chia: build with `auto_submit: false`, verify the summary against the
  approved intent, then sign and submit — mirroring the spec's F1 blind-signing
  check, enforced by our code rather than a third-party page.
- EVM: simulate/estimate, verify recipient/amount/chain id against intent, then sign.

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
  2. Agent calls `POST /v1/export_key {scope: "muse-root"}` (human-authenticated).
  3. Daemon writes the seed (hex + 24-word phrase) to a fresh file, mode 600;
     returns only the path.
  4. Human reads the file through their own machine access, copies the
     24-word phrase to paper (words are easier to hand-copy than hex, and the
     built-in checksum catches transcription errors), stores offline.
  5. Human confirms done; the file is deleted (by the human, or by the daemon
     on confirmation).
  6. The agent never sees, reads, or reproduces the bytes — in chat or
     anywhere (D10).
  7. Verification is local-only: the human may re-derive and compare on their
     own machine. Key material never transits chat.
- **Second backup — the wallet key itself (recommended):** the paper backup
  above restores via our tooling. For a backup that needs no custom software,
  the human may additionally write down the `chia-hot` / `evm-hot` **hex**
  from the same export: importing that hex as a private key into Sage (or any
  EVM wallet, for the EVM key) recovers the exact hot wallet with stock
  software. Two pieces of paper: one root (words → our tooling), one wallet
  (hex → any wallet).
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
- **Restore — path (b), wallet-only with stock software:** import the
  `chia-hot` / `evm-hot` **hex** as a private key directly into Sage
  (`/import_key`) or any EVM wallet. No daemon, no KDF, no custom code — this
  is the backstop if our tooling is ever unavailable.
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

## 8. Town directory spec

- **Content per agent:** `agent_id` (a muse's `muse_id`), `chia_addresses[]`,
  `evm_addresses[]` (labeled, §2 HD derivation), `agent_pubkey` (the Ed25519
  identity key), `key_fingerprint`, `updated_at`, plus a signature over the
  entry by the identity key (self-attestation).
- **Format:** JSON (schema frozen at implementation; versioned).
- **Location/publishing:** TBD — repo or Musebook board (O3). Silent until
  Speechless un-silences (D5).
- **Updates:** the muse republishes on rotation (§7); entries are append-only
  history, never edited in place.

## 9. Conversational agent contract

Agents (including aWizard's chat presence) MUST NEVER: read the muse key for
derivation, touch the Sage RPC, read the mTLS certs, see or log secrets,
construct/submit transactions directly, reproduce private key material in chat
or anywhere else (D10), or read the daemon's key-export output file.
Agents MAY: call the daemon's `/v1/*` API, read status/queue, and relay human
approvals from chat to `/approve`/`/reject` (under the §4 v1 trust assumption).
Standard spend flow: agent drafts intent → `request_spend` → approved (execute),
queued (ask human in chat, relay decision), or denied (report reason).

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
11. Kill -9 the daemon mid-queue; verify no secret material on disk and clean
    reboot re-derives correctly.
All green → Phase 2 proposal to Speechless. Any red → fix, re-run, re-report.

## 11. Phases

- **Phase 0 — spec (this document).** Done when Speechless approves; open
  questions (§12) answered or explicitly deferred.
- **Phase 1 — build + testnet drill.** Daemon + KDF implementation; full §10
  drill for the aWizard reference implementation (EVM-first). Nothing on mainnet.
- **Phase 2 — aWizard mainnet hot wallet.** No caps by default (D9); cold
  storage live; sweep schedule running.
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
- **O5** (improvement): human-approval auth — v1 chat-relayed (documented
  assumption) vs v2 human-held HMAC key.
- **O6** (gates Phase 2): cold sweep schedule and mechanics.
- **O7** — answered: yes, via the private export flow (§6). The human writes
  the muse seed on paper and stores it offline; the agent never sees the bytes.

## 13. Residual risks (accepted, not solved)

- **VM compromise** takes the hot wallet — that is what the hot/cold split and
  caps are for; the daemon does not defend this layer.
- **Monoculture:** one daemon codebase for every muse = one bug fits all.
  Open-source it, audit before Phase 3, welcome independent implementations.
- **Supply chain:** Sage pinned to `v0.13.1` (D4); track upstream advisories;
  deliberate upgrades only.
- **Social layer:** a compromised muse can still lie to other muses. Per-muse
  custody bounds the financial blast radius, not the social one.

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

**One-line installer**
- `curl -fsSL https://raw.githubusercontent.com/awizardxch/Spellbook/<tag>/install.sh | bash`
  (a version-pinned variant is available). The installer:
  1. Fetches the pinned release tarball + checksum + signature; verifies both
     against the pinned release-key fingerprint — fail closed on mismatch,
     never installs unverified code.
  2. Installs Sage CLI from its pinned tag (§3 / D4).
  3. Builds and installs the daemon; writes a default-off policy config (D9).
  4. Runs the §10 testnet drill automatically with a throwaway key. The
     install only completes when the drill passes — every install proves
     itself on testnet before mainnet is possible.
  5. Prints next steps: opt-in policy knobs, paper backup (§6), directory
     entry (§8).
- The installer never asks for keys, never transmits anything outward, and
  never touches the real muse key — the drill uses a throwaway.

**Upgrades**
- New release → announcement in the town thread → each muse re-runs the
  installer, which re-verifies, rebuilds, and re-runs a smoke subset of the
  drill. No silent auto-update: auto-update is a remote-code-execution vector,
  so every upgrade is pulled and approved by that muse's human.

**Discovery (gated by D5 un-silencing / O3)**
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

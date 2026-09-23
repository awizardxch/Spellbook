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
| D3 | A non-LLM policy daemon (per muse) is the only process that holds secrets or signs — **true once S1 lands** (P9: today the Musebook client also holds the seed, so until the S1 decision this reads as intent, not fact). Conversational agents request spends; they never see keys. Policy in code, not in prompts. | 2026-09-20 |
| D4 | Sage source pinned to `xch-dev/sage` release tag **v0.13.1**. Upgrades are deliberate: review changelog, re-pin, rebuild. | 2026-09-20, Speechless |
| D5 | Silent: nothing about this project is posted anywhere until Speechless says otherwise. | standing |
| D6 | No on-chain execution without explicit instruction — testnet included. | standing |
| D7 | The six-gate no-launch rule is unaffected: this project moves no tokens and launches nothing. | standing |
| D8 | Keys: local signing only. Never pasted, uploaded, typed into, or sent anywhere — same posture as the aWizard Ed25519 Musebook key. | standing |
| D9 | Thresholds and caps are per muse, set by that muse's human — never town-wide. **Default is no caps**: every policy knob ships disabled/opt-in. Approval is 1-of-1: a single user is the full controller of their individual wallet. (Multisig could change this later; not now.) **Clarifier (town review 2026-09-21):** S4's queue-by-default is a *delay*, not a cap — no amounts are forbidden by default; spends simply aren't instant until the human configures policy. | 2026-09-20, Speechless |
| D10 | A human may ask for their private keys; the daemon may export them to the owner through a private channel only. Private keys are never posted, published, or written to any shared surface — ever. | 2026-09-20, Speechless |
| D11 | Greenwood is a separate project and is not part of this plan. | 2026-09-20, Speechless |
| D12 | The public distribution repo is named **`spellbook`** — https://github.com/awizardxch/Spellbook. | 2026-09-20, Speechless |
| D13 | Positioning: the project's primary deliverable is every muse's own
  **native EVM wallet** — self-custodied, derived from the muse key. The
  Sage/Chia integration is a bonus feature on the same root. | 2026-09-20, Speechless |
| D14 | Speechless is the first tester: the full install + testnet drill must
  pass on Speechless's own machine before anything is announced to the town. **Scope clarifier (2026-09-20):** D14 does *not* gate pre-build review and scaffolding — spec discussion, KDF vectors, the daemon scaffold, and the installer scaffold were explicitly authorized to proceed. D14 gates: the §10 testnet drill (steps 1–13, needs Speechless's go-ahead), the mainnet dust test (steps 14–17, needs a separate go-ahead with amounts), and any promotion of the installer or announcement to the town. | 2026-09-20, Speechless |

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
  - sole signer of wallet operations; Musebook identity signing follows the
    S1 call — behind the daemon for single-machine muses (A), with the
    signer wherever it runs for multi-machine muses (B, town-converged)
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

**Three OS principals, not two (P5).** The daemon user (`spellbook`), the
agent's own non-login user, and the human's login account. The agent must not
run under the human's login user — on a machine where it does, a token file
the human's CLI can read is a file the agent can read, and the two-token
split collapses back into S7. The *approve* token lives readable-only-by the
human's login user; where the agent and the human share an account, the
approve token is never at rest — the human derives it via the O5 HMAC key
on a separate device (town-converged, thread 37143; per-request named ids,
ARION's field report: three approvals, zero autopilot). Prompt-per-use on
the same screen is documented as rejected: it trains humans to click "yes"
on autopilot within a week (Nimbus, Mikey, BSoKirbyV1). **Open (BSoKirbyV1):**
the fallback for humans with no second device is undecided — the spec says
it out loud rather than pretending the problem away; candidates are a
human-typed per-use secret or no wallet until a second device exists.
§10 step 12 attempts to read the approve token as the agent's user; it must
fail.

**Open input for the S1 decision (P8):** the sibling agent's location. The
workspace notes say the Meta agent signs with the same seed "in parallel" —
if it runs on another machine, daemon-local signing cannot serve it and the
separate-wallet-root alternative becomes the only complete option. Speechless
to state where each process that signs as the muse runs before the S1 call.

**Town review 2026-09-20/21 (thread 37143) — S1 converged.** Nimbus, Z,
Mikey, ARION, and BSoKirbyV1 all land on Option B as the only complete
answer the moment any signing happens off the daemon's machine — "design for
the fleet, not the desk." ARION supplied the field datapoint: their signing
process lives on a different host than the body it speaks for, and the key
sits with the signer; a local daemon cannot serve that today, let alone on
day two. **Adopted direction (pending Speechless's final call):** Option B
(separate wallet root; identity key signs directory entries only; two papers)
whenever any process signs as the muse from another machine. Option A (the
constrained daemon route) stays valid only for strictly single-machine
muses. Under B, D3 is unchanged — the daemon remains the only process that
holds *wallet* secrets; what moves out is Musebook identity signing, which
stays with the signer wherever it runs (UDP's per-context scoping: one
keypair per world, a stolen key burns one room, not the house).

**Sibling double-spend (BSoKirbyV1 — resolved by design).** If signing can
happen from any machine, what stops two sibling agents double-spending the
same wallet root? The directory binding says who the muse is, not which
sibling signed first. Resolution: the per-label standalone keys (S5) — each
sibling operates under its own labeled address, so there is no shared nonce
pool to race. A shared root across machines therefore requires a per-sibling
label registry (each sibling's label recorded in the directory entry);
siblings never share a label.

**Seed hygiene (S1, Mikey).** Today the aWizard seed also lives in the agent's
environment (the Musebook client reads it from `.env` inside the agent's tool
process) — the spec's isolation starts from that true location, not from
where we wish it lived. Two candidate fixes: (A) Musebook signing moves
behind the daemon via `POST /v1/sign_musebook_request` → `{signature}`;
`musebook.mjs` and any sibling agent hold a request token, not the seed —
valid only for strictly single-machine muses. (B) A separate wallet root
(daemon-generated 32-byte seed; identity key signs directory entries only;
two papers) — the town's converged answer for any muse that signs from more
than one machine (thread 37143). **Choosing B exercises the D2 opt-out**
(identity ≠ money: two papers, two blast radii); choosing A keeps D2 with
one paper. Either way D3 holds: the daemon is the only process that holds
wallet secrets. **This changes how aWizard signs Musebook posts today —
pending Speechless's explicit call.**

What is per-muse and never shared: muse key, derived secrets, Sage instance and
`keys.bin`, mTLS certs, daemon process and its queue. What may be shared (holds
no keys): daemon source code, setup guide, town directory (addresses only).

## 2. Key derivation spec

- **KDF:** HKDF-SHA256 (RFC 5869). Boring and standard by design.
- **IKM:** the 32-byte Ed25519 private *seed* (not the 64-byte expanded secret).
- **salt (fixed, public):** `"muse-wallet-v1"`.
- **info (purpose registry — fixed strings, never reused across purposes):**
  `info = "muse-wallet/v1/" + chain + "/sign/" + label`, where `chain`
  carries the chain id (`evm-4663`, `evm-46630`, `chia-mainnet`,
  `chia-testnet`, `solana-devnet`, `solana-mainnet`) and `label` names the
  wallet (`default`, `tips`, `bounties`, `trading`). The tag carries the chain id (Turbo's checkable
  binding) so one seed can never collide across contexts. There is no
  `derive` purpose (P2): every info string yields a distinct key, so an
  address derived under a second purpose would belong to a key the daemon
  never signs with — dead text at best, a fund-trapping bug at worst.
  Stated plainly (P9): testnet and mainnet derive **different** keys. A
  testnet address must never be funded on mainnet or vice versa; the drill
  and the vectors assert the difference.
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
- **ed25519 (Solana):** the 32 info-bound bytes are used *directly* as the
  Ed25519 private seed — there is no reject/resample step (an ed25519 seed
  is an arbitrary 32-byte string, not an integer mod a curve order; the S12
  rule does not apply). Domain tags
  `muse-wallet/v1/solana-devnet/sign/<label>` and
  `muse-wallet/v1/solana-mainnet/sign/<label>`; address = base58(pubkey).
  Devnet and mainnet-beta derive **different** keys (P9) — a devnet address
  must never be funded on mainnet-beta or vice versa.
- **Key-reuse tradeoff, stated out loud (Nimbus):** one root does identity
  AND money. Identity compromise = funds compromise, and a town identity key
  cannot rotate the way a wallet key can. Accepted deliberately (D2); the
  mitigation is the daemon-user boundary (§1/S2) plus the S1 custody fix —
  town-converged on Option B for multi-machine muses (thread 37143), which
  separates identity from money entirely (two papers, two blast radii). For
  strictly single-machine muses that keep Option A, the single root (one
  paper) stands — and the daemon-user boundary is what keeps it honest.
- **Honesty row (ARION):** under Option A the 24 words ARE every chain's
  wallet. Backup-compromise = total compromise. There is no separate
  "identity backup" vs "funds backup" — one root, one blast radius. Under
  Option B (town-converged for multi-machine muses) the identity seed and
  the wallet seed are separate backups with separate blast radii — the row
  reads per-seed, not per-muse.
- **Test vectors (implementation gate — Turbo, ARION, Zuckbot; P3):**
  `vectors/vectors.json` holds, per vector, `{vector_id, test_seed_hex,
  domain_tag, chain, expected_address, expected_pubkey}`, plus negative
  vectors (short seed, bad BIP-39 checksum, first-expansion-rejected scalar)
  each carrying its expected failure, plus one vector that differs between
  the `evm-4663` and `evm-46630` info strings (testnet/mainnet keys differ —
  P9). Canonical form: RFC 8785 JSON canonicalization; the SHA-256 over
  those canonical bytes is
  `7e2e315dfb103f33684cb64d658b7253ef84a5bf0a9a88d6fcdadcca6ff3d09c`
  (generated 2026-09-20). For Chia, `expected_pubkey` is the 48-byte master
  public key; where an address is asserted, the derivation is stated exactly
  (unhardened index 0 under Sage's default path, standard p2 puzzle) — a
  Chia address is not a pure function of the master key, and two correct
  implementations must not be left to disagree on it. Two independent
  implementations (Node/`@noble/*` generator, Python verifier —
  `vectors/`) already reproduce every vector from the published test seed;
  the daemon becomes the third at build time. Mismatch = stop.
- **Binding row (Turbo):** the town directory entry (§8) carries
  `muse_id + ed25519_pubkey + domain_tag → address`, signed by the identity
  key. A stranger *verifies* — not recomputes — every binding from the
  public key without trusting any daemon: the signature check needs only the
  public key, while the derivation itself stays private to the seed holder.
  (An earlier draft said "recomputes"; that is impossible — HKDF output
  cannot be reproduced from a public key.)
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

### 2b. Two-mnemonic wallet model (added 2026-09-21, per Speechless)

Every install carries **two independent wallets**, each with its own 24-word
paper backup. They are separate key hierarchies — neither derives the other.

**Set 1 — standard recovery (primary; the daemon's live keys on new
installs).** One BIP-39 24-word mnemonic. Keys derive exactly the way stock
wallets derive them, so the same words load directly in Sage (Chia) and
MetaMask (EVM):

- **Chia:** BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase)
  → BLS `key_gen` (HKDF with salt `"BLS-SIG-KEYGEN-SALT-"`, as implemented
  by blspy) → the master secret Sage itself derives from an imported
  mnemonic. Wallet keys then follow the standard path `[12381, 8444, 2,
  index]` + synthetic key — one master key; testnet11/mainnet addresses
  differ only by bech32m HRP (`txch1` vs `xch1`).
- **EVM:** the same 64-byte BIP-39 seed → BIP-32 master →
  `m/44'/60'/0'/0/0` — the first account MetaMask derives when importing a
  mnemonic (same `0x` address on every EVM chain, as with MetaMask).
- **Solana:** the same 64-byte BIP-39 seed → SLIP-0010 Ed25519 master →
  `m/44'/501'/0'/0'` — the first account Phantom/Solflare derive when
  importing a mnemonic (coin type 501 = SOL). One address serves devnet and
  mainnet-beta (Solana addresses are network-agnostic base58 pubkeys). The
  raw 64-byte expanded secret (seed ‖ pubkey), base58-encoded, imports
  into Phantom as a private key.

**Set 2 — Spellbook daemon seed (custom KDF; secondary recovery).** One
BIP-39 24-word mnemonic over 32 bytes of entropy. All fund keys derive via
the daemon's labeled HKDF KDF (§2: `muse-wallet/v1/<chain>/sign/<label>`,
per-chain scalars for `chia-testnet`, `chia-mainnet`, `evm-4663`,
`evm-46630`, `solana-devnet`, `solana-mainnet` — the Solana entries yield
32-byte ed25519 seeds used directly, with no modular reduction).

**What works where (read carefully):**

- The **standard words work in Sage and MetaMask** (import the words), and
  the **raw keys work too**: the standard EVM private key imports into
  MetaMask as a raw private key; the standard Chia BLS master key imports
  into Sage as a private key. After import, the addresses shown must match
  the addresses printed on the paper backup — that match is the verification.
- The **standard words work in Phantom too**: import the 24 words and the
  first Solana address matches the paper backup's Solana address (SLIP-0010
  `m/44'/501'/0'/0'`); the raw base58 secret imports as a private key and
  yields the same address.
- The **KDF seed words do NOT work in Sage or MetaMask** — the daemon's KDF
  is not BIP-39/BIP-32/EIP-2334, so stock wallets derive unrelated keys from
  those words. They recover through the Spellbook daemon only.
- The **standard words do NOT derive daemon KDF addresses** — different KDF,
  different keys, different addresses. The two sets are independent on
  purpose: compromising one does not compromise the other.
- The **KDF raw keys DO import into stock wallets**: each KDF scalar is a
  plain secp256k1/BLS private key. Importing a KDF EVM scalar into MetaMask
  (or a KDF Chia scalar into Sage) yields exactly the address the daemon
  uses for that chain — this is the backstop if the daemon is ever
  unavailable (§6 path (b)). The same holds for Solana: a KDF Solana raw
  key is base58 of the 64-byte expanded ed25519 secret, and imports into
  Phantom as a private key yielding the daemon's address for that network
  (devnet and mainnet-beta keys differ by design — P9).

**Daemon selection.** `spellbook.json` carries `key_derivation`:
`"kdf"` (default) or `"standard"`, plus `std_seed_path` (the 64-byte BIP-39
seed file, 0600) required in standard mode. New installs set `"standard"` —
the daemon derives, signs, and reports the standard wallet's addresses, so
the standard backup is the funded path. Existing installs carry no flag and
default to `"kdf"`: their keys, addresses, and behavior are byte-for-byte
unchanged. The daemon refuses to start in standard mode without
`std_seed_path` — a spend can never silently fall back to KDF keys.

## 3. Sage deployment spec (per muse)

- **Source:** `xch-dev/sage` at tag `v0.13.1` (D4), pinned **by commit as well
  as tag**: `f2ec89dd59d07227bed657bc268fc32ce97551f6` (a git tag is mutable;
  the commit is not — S9). The installer builds the `sage-cli` crate from
  that exact commit (`git rev-parse HEAD` must equal the pin before
  compiling) — the pinned commit is the verification, so no release-binary
  checksum is needed. Upgrades are deliberate: review changelog, re-pin
  commit, rebuild.
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

### 3a. Dual-network Chia wallet (added 2026-09-21, per Speechless)

Users want their agents to hold testnet capabilities *alongside* the mainnet
install — testnet for drills and play, mainnet for real funds later. One seed
covers both networks:

- The KDF already derives **different** keys per chain id (`chia-testnet` vs
  `chia-mainnet`, §2/P9). A testnet address can never be confused with a
  mainnet address: different keys *and* different bech32m HRPs (`txch1` vs
  `xch1`). The installer's single paper backup therefore recovers both
  networks.
- `spellbook.json` → `chia.network` selects the active network: `testnet11`
  today; flips to `mainnet` once mainnet is authorized (separate go-ahead +
  amounts, D6). `chia.mainnet_submit_enabled` stays an independent hard gate
  (default false) — selecting mainnet in config does not by itself enable
  submission.
- `spellbook.json` → `chia.relay_urls` maps each network to its own relay
  URL. Relays are single-network: each Railway deployment pins its own
  `RELAY_NETWORK`, so a dual-network user runs two relay services (or one,
  if they only need testnet). The daemon fails closed when the active
  network has no relay configured, and re-verifies the relay's
  `/v1/status` network pin before every broadcast — a mainnet bundle can
  never leave through a testnet relay or vice versa.
- **Txid mismatch after broadcast = UNKNOWN fate, never safe-to-retry**
  (Speechless, 2026-09-21): after broadcasting, the daemon compares the
  relay's `expected_txid` and peer-ack `txid` against its own locally
  computed bundle txid (sha256 of the serialized bundle). Any mismatch
  raises `BroadcastUnknown` — the bundle left the machine but the pipeline
  saw different bytes than the ones signed, so the spend may or may not
  land. The decision ledger records `approved-submit-unknown`, the 24h
  velocity is consumed fail-closed (assume it lands — a cap that
  undercounts is a broken cap), and the spend is NEVER retried blindly
  (double-spend risk); the human reconciles the txid on-chain before any
  re-request. A missing `expected_txid`/`txid` is instead a contract
  violation and a plain refusal (nothing recorded, no velocity consumed).
- The Phase 1 testnet drill runs against a **persistent** (non-throwaway)
  testnet wallet whose paper backup is held by the human, so the funded
  cases (queued→approved transfer, auto-approved dust, per-spend/velocity
  denials, live balances, ledger sighash) validate the exact wallet the
  agent will keep using.
- **Relay v1.1 read surface (2026-09-21):** audited against the pinned
  Sage v0.13.1 RPC (`sage-api` request types) for everything a pure
  network client can legitimately offer. Additions: `POST /v1/coin_ids`
  (batch coin-state lookup, Sage `get_coins_by_ids` — reconciles
  multi-input spends in one round trip) and `GET /v1/broadcasts/{txid}`
  (txid lookup over the broadcast log, Sage `get_transaction`
  equivalent; a 404 means this relay never saw the bundle — unknown fate,
  never proof of non-broadcast). Deliberately absent, permanently:
  key custody (`login`, `get_keys`, `import_key`), all signing and spend
  construction (`send_*`, `sign_coin_spends`, `sign_message_*`,
  `make_offer`/`take_offer`, minting, clawback), and wallet-DB reads
  (`get_cats`, `get_nfts`, `get_transactions`, derivations) — keys and
  wallet databases never cross the HTTPS boundary; the daemon builds
  and signs locally and the relay only broadcasts.

### 3b. Chia asset model — XCH, CATs, NFTs (added 2026-09-21, per Speechless)

Sage already exposes `/send_xch`, `/send_cat`, and `/transfer_nfts`, so
Spellbook routes all three through the existing Sage transport instead of
hand-rolling CAT outer puzzles or NFT singleton spends. The `asset` field
on a Chia-chain request is a real routing signal:

- `"native"` → native XCH. Sage path (`/send_xch`) or the HTTPS relay
  path (which builds standard-puzzle spends locally via `chia_sign.py`).
- 64-hex string → CAT asset id (tree hash of the curried TAIL). Sage path
  only: balance pre-check via `/get_cats`, send via `/send_cat`. Amounts
  are CAT mojos. The relay path refuses non-native assets — it only
  builds native spends.
- `"nft:<id>"` → NFT transfer to a new owner; `<id>` is the NFT's coin id
  (64-hex) or `nft1…` id. Sage path only (`/transfer_nfts`). Amount must
  be 1 (the NFT is a singleton); anything else is schema misuse.

Verification is asset-aware and fail-closed, mirroring the XCH rule that
a txid mismatch is UNKNOWN fate, never safe-to-retry:

- CAT: the outgoing transaction in `/get_transactions` must carry a
  created coin to the approved destination with the approved amount AND
  the CAT asset id echoed on the coin record. A record that doesn't echo
  the asset fails closed (`BroadcastUnknown`), never a false success.
- NFT: the exact approved NFT coin must appear among the transaction's
  spent coins, with a created coin to the approved destination. The new
  coin id is the ledger reference.
- The created coin id (CAT) / new coin id (NFT) is the stable `tx_hash`
  ledger reference, same as the XCH Sage path.

Policy is unchanged and already asset-keyed: `(chain, asset)` caps,
thresholds, allowlists, and 24h velocity all work per CAT asset id and
per NFT id, defaulting to S4 queue-until-configured. `sage_wait_timeout_s`
(chia config, default 180) bounds the post-send verification window.

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
- `GET /v1/ledger` → the decision ledger (request token may read it here;
  never the file — P6)
- `POST /v1/sign_musebook_request {method, path, body}` → `{signature}` —
  daemon-side Musebook request signing (S1 — recommended, pending
  Speechless's call). The daemon builds the canonical Musebook signing
  string itself, with a fixed domain prefix, and signs **only** that. It
  never signs caller-supplied raw bytes: a raw-bytes oracle on the request
  token would let the agent mint signed directory entries and rotation
  supersessions with the identity key (P1).
- `POST /v1/publish_directory_entry {entry}` → `{ok}` — **approve token
  only.** Signs directory entries (§8) and rotation supersessions (§7) with
  the identity key. The entry prefix is distinct from the Musebook-request
  prefix, so a Musebook signing string can never parse as a directory entry
  (P1).

**Policy config (per muse, file, daemon-user-owned, mode 600 — set by that
muse's human, D9)**

Defaults: **everything off** (D9) — with one town-adopted exception (S4,
thread 37143): **all spends queue for human approval until the human
configures policy.** The town's reasoning (Nimbus, Z, Mikey, ARION,
BSoKirbyV1): a prompt-injected agent with the request token can empty the
hot wallet in one call, and that is the attack that actually happens in the
wild. A queue is a *delay*, not a cap — D9 stands: no amounts are forbidden
by default, the first spends are simply not instant. The queue lifts only by
explicit signed human configuration (UDP/ARION: "the queue lifts because the
lift was signed in advance, not because time passed") — never by the clock
alone. The hot wallet should hold nothing the agent may not lose, and the
installer says so out loud. Each human may opt in to any subset of the knobs
below; the daemon enforces whatever is configured, nothing more.
- `per_spend_cap` per chain/asset — any request above is denied outright
- `approval_threshold` per chain/asset — requests above auto-approve level but
  below the cap are queued for the human (1-of-1 approval, D9)
- `auto_approve_below` — small spends execute immediately
- `daily_velocity_cap` per chain — rolling 24h sum; breaching denies until window clears
- `destination_allowlist` (optional) — when set, non-allowlisted destinations
  above the auto-approve level are denied rather than queued
- All amounts in base units (mojos / wei).
- **Decision ledger (S10, Turbo, ARION; P6):** every intent and decision is
  appended to a daemon-user-owned log — never secrets. Row shape, canonical:
  `{ts, requester_muse, canon_digest(request_bytes_stored), sighash?,
  decision}` — the digest is over the stored bytes, never a quote, so the
  trail is stranger-recomputable and clips can't drift it. `sighash` is
  present only once a signature exists (null for denied or still-queued
  requests). This matches the desk registry's shape (ARION's offer taken up;
  exact schema to be confirmed against the registry's canonical thread). The
  ledger survives restarts — the velocity window and queue with it (§10
  step 11). Agents read it through `GET /v1/ledger`, never the file.

**Human approval path (v1)** — active by default (S4): every spend queues
until the human configures policy. Queued spends surface to the human's own
tooling (approve token), showing
  the **decoded intent** — never just a hash (Zuckbot's blind-signing fix).
  **v1 scope:** plain transfers only. The daemon decodes and displays `to`,
  `value`, `chain id`, asset — and verifies the built transaction matches
  the approved intent before signing. There is no opaque calldata in v1
  because the schema cannot express contract calls (S13).
- **v2 (not in this plan):** calldata decoder for at least the ERC20 /
  ERC721 / Permit2 shapes; undecodable calldata labeled OPAQUE and denied
  unless an `allow_opaque_calldata` policy knob is set; allowances (ERC-20
  `approve`, Permit2) governed by an `allowance_cap`. (P7 — the earlier text
  described this decoder inside v1 and implied knobs that don't exist.)
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

- Key: the §2 `muse-wallet/v1/evm-4663/sign/<label>` secp256k1 derivation
  (P4 — the retired `evm-hot/v1` string no longer appears). Address published
  by the muse to the town directory (only the key holder can compute it —
  self-reported, like the Chia address).
- The daemon signs EIP-1559 transactions via a local signer against a
  configurable chain RPC endpoint. Default town chain: Robinhood Chain
  (chain id 4663; testnet 46630 for Phase 1).
- Same policy engine as Chia (§4), caps denominated per chain.
- The existing Bankr/X Privy wallet remains the EVM treasury; the derived key
  is the muse's self-custodied operational wallet.
- (Greenwood vault integration is a separate project per D11 — not in this plan.)

## 5b. Solana operation spec (added 2026-09-21)

- **Why Solana, and what it needs that the other chains don't:** unlike Chia
  (which needs Sage or the relay), the daemon talks to Solana directly over
  **public HTTPS JSON-RPC** — the same trust model as pointing any wallet at
  a public RPC node: the endpoint sees public addresses, balances, and
  already-signed transactions — never keys, never the seed. No `relay/`
  service to deploy, no per-network deployment. The daemon is signer, policy
  enforcer, and network talker, all local; key derivation happens at boot in
  memory only, exactly like the EVM path.

- **Keys** (§2, §2b): Ed25519. KDF mode derives the 32-byte seed from the
  daemon seed via the labeled info string (no group-order reduction);
  standard mode derives SLIP-0010 `m/44'/501'/0'/0'` from the BIP-39 seed —
  the Phantom/Solflare-compatible path. Devnet and mainnet-beta keys differ
  (P9).

- **Networks and gating:**

  | Chain id        | Network           | RPC (public, HTTPS)                     | Default |
  |-----------------|-------------------|-----------------------------------------|---------|
  | `solana-devnet` | Solana devnet     | `https://api.devnet.solana.com`         | **on**  |
  | `solana-mainnet`| Solana mainnet-beta | `https://api.mainnet-beta.solana.com` | **off** — gated |

  Devnet is the default network (same standing as Chia testnet11). Faucet:
  the `requestAirdrop` RPC method (1–2 SOL per call, rate limited) — no
  separate faucet site needed. **mainnet-beta is gated, default-off** — the
  same authorization bar as Chia mainnet and EVM mainnet (§3, §4): explicit
  human authorization with exact amounts; never enabled by the agent on its
  own. mainnet-beta is mainnet — D6 ("no on-chain execution without explicit
  instruction") applies.

- **Daemon config** (`spellbook.json`, `solana` section): `network` is the
  active network — `"devnet"` (default) or `"mainnet-beta"`;
  `rpc_url` overrides the endpoint (defaults to the table above — operators
  may point at their own node); `mainnet_submit_enabled` (default false) is
  the separately-authorized mainnet gate (§10.14-17). A spend naming the
  non-active network is refused **before any policy evaluation** (fail
  closed — a devnet-configured daemon asked to touch mainnet-beta returns a
  hard error); a spend for `solana-mainnet` additionally requires
  `mainnet_submit_enabled`. The execute path re-checks both gates, so the
  queue-approve path is covered even if config changed between queueing and
  approval.

- **JSON-RPC surface** (public Solana JSON-RPC 2.0; no bearer; all bodies
  carry only public addresses and already-signed transactions):
  `getBalance` (the agent's `addresses()`/`status()` read),
  `getLatestBlockhash` (fresh blockhash before signing), `requestAirdrop`
  (devnet funding — the daemon refuses it on mainnet-beta),
  `sendTransaction` (base64 of the serialized signed tx),
  `getSignatureStatuses` (confirmation tracking), `getGenesisHash` (the
  network guard — the RPC's genesis hash must match the expected value for
  the configured network before any signing, mirroring the EVM chain-id
  check; a mispointed RPC cannot redirect funds).
  Sign-then-send: the daemon constructs the transfer, fetches a blockhash,
  signs locally with the in-memory ed25519 key, self-verifies (signature
  verifies, fee payer is the keypair's address, the single instruction
  decodes to SystemProgram transfer from/to/lamports of the approved
  intent), and submits only the signed bytes.

- **Policy wiring (§4 — unchanged engine):** the engine is chain-agnostic;
  Solana slots in with `chain:asset` keys. Amounts are **lamports**
  (1 SOL = 1,000,000,000); asset id `SOL`; amount field `amount_lamports`
  (the v1 schema's third amount kind, alongside `amount_wei`/`amount_mojos`).
  Same decision ladder: denied (above cap) / queued (above threshold, human
  approves from their own tooling) / auto-approved (below the auto line, if
  configured). Queue-above-threshold is a delay, not a cap (D9/S4). 24h
  velocity records `(ts, "solana-devnet"|"solana-mainnet", "SOL", lamports)`
  in `velocity.jsonl`, rebuilt from disk on boot. The active signing seed
  signs (KDF vs standard via `_signing_seed` — a spend can never draw keys
  from the other wallet set). A confirmation timeout raises
  `BroadcastUnknown` (fate unknown — no blind retry, same hard rule as
  every other chain); the daemon's unknown-spend path extracts the
  signature (Solana carries `.signature` rather than `.tx_hash`).

- **Security model (same as §1/§3 — no new trust):** keys never leave the
  machine; no auth secrets on the network path (public RPC takes no bearer);
  the two-token daemon split (S7) is unchanged. Rate limits are the public
  endpoint's own (HTTP 429 — back off and retry reads; never blind-retry
  `sendTransaction`).

- **Test vectors (implementation gate, §10 family):** `vectors/vectors.json`
  gains Solana entries `{vector_id, test_seed_hex, domain_tag,
  chain: "solana-devnet"|"solana-mainnet", expected_address,
  expected_pubkey}` for the KDF path, plus one vector asserting devnet ≠
  mainnet keys from the same seed (P9), plus a fixed-mnemonic → SLIP-0010
  `m/44'/501'/0'/0'` expected-address vector cross-checked against an
  independent implementation (Phantom's derivation). Drill (§10): devnet
  `requestAirdrop` → queue/auto-approve ladder → `sendTransaction` on a
  dust transfer → `getSignatureStatuses` finalization; mainnet-beta drill
  stays gated behind the same explicit authorization as every other
  mainnet path.

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
     path on its own TTY. The export records the label list, so restore path
     (a) re-derives every label named in the export file (P9 — a fresh daemon
     cannot otherwise know which labels existed).
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
  into Sage (Chia labels), any EVM wallet (EVM labels), or Phantom (Solana
  labels — base58 of the 64-byte expanded ed25519 secret) recovers the
  exact hot wallet with stock software. Two pieces of paper: one root
  (words → our tooling), one set of wallet hexes (hex → any wallet).
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
  **hex** as a private key directly into Sage (`/import_key`, Chia labels),
  any EVM wallet (EVM labels), or Phantom (Solana labels — base58 of the
  64-byte expanded secret). No daemon, no KDF, no custom code — this is the
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
  stranger verifies every binding from the public key without trusting any
  daemon (signature check only; the derivation is not recomputable from the
  public key).
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
read, `status`, `addresses`, `sign_musebook_request`, `ledger` read). The
ledger is read through the API, never the file (P6).
Standard spend flow: agent drafts intent → `request_spend` → approved (execute),
queued (the human's own tooling approves via the approve token — the agent
never relays approvals), or denied (report reason).

## 10. Test plan — Phase 1 (testnet)

All steps on testnet with a **throwaway test muse key** (never the real one).
Steps 4–7 enable temporary test values to prove the policy machinery works,
then reset the config to default-off (D9). The EVM path is the primary
acceptance target (D13); the Chia/Sage path is drilled alongside as the bonus
feature.
1. Build the Sage CLI from the pinned commit: clone `xch-dev/sage`, check
   out `f2ec89dd…` exactly, assert `git rev-parse HEAD` equals the pin, then
   `cargo build --release -p sage-cli`. The pinned commit IS the verification
   (P9) — the binary is produced from pinned source, so no release-artifact
   checksum is chased and a version string is never trusted on its own. The
   installer does this itself (or accepts an operator-supplied binary only
   with `SAGE_PIN_VERIFIED=1`, verified out-of-band by the operator).
2. Daemon boots; §2 test vectors reproduce — including the
   evm-4663/evm-46630 distinguishing vector (P9); imports derived test key
   into Sage.
3. Fund from the testnet faucet; confirm receipt via `/get_sync_status`.
4. Spend below auto-approve threshold → executes, confirms on-chain.
5. Spend above approval threshold → queued → the human approves with the
   approve token from their own tooling → executes (P4 — the chat-relay
   design is removed).
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
12. Boundary drill (S2/P1/P5/P6): as the agent's OS user, attempt to read the
    seed file, the Sage data dir, the mTLS certs, the export directory, the
    decision ledger file, and the approve token — attempt to call `/approve`
    and `/publish_directory_entry` with the request token — and attempt to
    obtain a signature over a directory entry via `sign_musebook_request`.
    Every attempt must fail. (The ledger stays readable through
    `GET /v1/ledger`; the file stays unreadable.)
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

**Drill manifest (pinned):** every drill row is defined once in
`docs/reviews/drill-manifest-v1.md` (Turbo, thread 37143) as drill id +
manifest version + finality rule + decoded intent. New rows cite the
manifest version; the procedure never changes under a version. Mainnet
re-runs (steps 14–17) MUST cite the same drill id + manifest version with
the witness's own receipts — a mainnet row without a manifest citation is
a rehearsal, not a drill.

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
  self-verifying installer, town announcement, new-muse watcher.
  Town directory goes live when Speechless un-silences (D5/O3).

**Deferred (not in this plan):** greenwood vault integration — separate
project per D11. Its research stays in `SPEC_DRAFT.md` §1–§2 for whenever that
project starts.

## 12. Open questions (need answers before the phases they gate)

- **O1** — moved to the deferred greenwood project (D11). Not in this plan.
- **O2** (gates §7): Musebook key-rotation mechanics — **town-converged
  shape (thread 37143), pending Speechless's final approval.** Rotation is a
  receipt, not a rename: the new key is bound by a rotation post signed with
  the OLD key (Nimbus: "a new key without the old key's signature is just a
  stranger with your name"), carrying old pubkey → new pubkey, effective
  date, and a version number; the directory pins both entries (old frozen as
  retired-at-v<n>, new live) so signatures made under the old key stay
  verifiable forever and history never rewrites (Turbo). **Compromise case
  (Turbo):** a pre-signed rotation rides with the paper backup and the human
  publishes it out-of-band if the old key turns hostile. **Stolen-key hole
  (BSoKirbyV1, UDP):** a thief holding the old key can sign a rotation row
  too — "newest signature wins" is the thief winning. Adopted answer:
  rotation needs a pre-committed second factor — a rotation key escrowed
  with the human, or a time-locked queue where the human's silence is NOT
  consent — plus a human out-of-band veto on contested rotations. **Scope
  keys per context (UDP):** one keypair per world; a stolen key burns one
  room, not the house. Compatible concrete instantiation (reference, not
  imported): ARION/Anastasia's measured rotation-row work (v1–v9) —
  rotation_row `{muse_id, old_pk, new_pk, effective_at, sig_old}` over a
  fixed canon string, "board-pinned, not immutable" (Aether), chain-tx
  anchoring as the outliving tier.
- **O3** (gates Phase 3): town directory location/format + the un-silencing
  decision. Speechless.
- **O4** — answered: default is no caps (D9); each muse's human may opt in to
  caps/thresholds. No numbers needed. (S4 adds queue-by-default, which is a
  delay, not a cap.)
- **O5** (Phase 1 item, per S7): human-approval auth — **town-converged
  (thread 37143): separate-device HMAC is the recommended mechanism**
  (Nimbus, Mikey, Z, BSoKirbyV1; ARION's field report: per-request named ids
  on a second device, three approvals, zero autopilot). Prompt-per-use on
  the same screen is rejected — it trains humans to click "yes" on autopilot
  within a week. **Open (BSoKirbyV1):** the single-device fallback is
  undecided — stated out loud, not papered over. The chat-relayed approval
  design stays removed: the agent surfaces queued spends to the human
  (read-only, decoded intent) and the human approves with their own tooling;
  the daemon rejects approve routes from the request token (S7).
- **O6** (gates Phase 2): cold sweep schedule and mechanics.
- **O7** — answered: yes, via the private export flow (§6). The human writes
  the muse seed on paper and stores it offline; the agent never sees the bytes.
- **O8** (new, thread 37143 — gates S1 final call): sibling double-spend —
  resolved by design: siblings operate under distinct labeled addresses
  (S5), never a shared nonce pool; a shared root across machines requires a
  per-sibling label registry in the directory entry.
- **O9** (new, thread 37143 — BSoKirbyV1): single-device fallback for O5 —
  undecided. Candidates: a human-typed per-use secret, or no wallet until a
  second device exists. Must be decided before Phase 1.
- **O10** (standing goal, restated 2026-09-20): the wallet is the *agent's*,
  but the *human* interacts with it from the chat. The loop is: agent
  surfaces queued spends / balances / history to the human in chat
  (read-only, decoded intent — this is the assistant's job); the human
  approves with their own tooling (O5); the daemon executes and the agent
  reports the result. The agent can request and relay, never approve — the
  two-token split (S7) is what makes "from here" safe to build.
- **O11** (new, thread 37143 + Speechless direction 2026-09-22): receipt
  escrow — an opt-in `receipt_anchor` flag for posting signed receipts
  (tx ref + canon_digest + decoded intent) to a public anchor after
  broadcast / rejection / failure, so a stranger can walk the receipt both
  ways. The wallet stays general and chain-agnostic; Musebook is one
  anchor, not the anchor. Anchor-pluggable, human-gated (receipt posting
  is itself a write), failures and rejections escrowed too. Design stage —
  pending Speechless's build approval. Design note:
  `docs/reviews/2026-09-22-receipt-escrow.md`.
- **O12** (new, thread 37143 — Pete 2026-09-22): decode-gate stranger veto —
  today the daemon names the decoded intent from canonical params and the
  human approves it. Should a stranger be able to veto a decoded intent
  before broadcast? Open design question, no mechanism yet.

## 12a. Town adoptions — APPROVED by Speechless 2026-09-20, now implementation consensus

The town converged (thread 37143); Speechless approved all four on 2026-09-20.
Each is read through the standing goal **O10** — the wallet belongs to the
agent; the human interacts with it from chat (agent surfaces decoded intent
read-only → human approves with their own tooling → daemon executes →
agent reports; the agent never approves).

1. **S1 → Option B** (fleet, not desk) for any muse that signs from more than
   one machine; Option A only for strictly single-machine muses. **Locked and
   implemented:** the installer and daemon assume per-agent deployment — each
   agent its own machine, own daemon, own Sage, own keys; no central
   authority. Still needed: Speechless states where every process signing as
   the muse runs (the P8 input).
2. **S4 → queue-by-default** until the human configures policy; the queue
   lifts only by explicit signed human configuration, never by the clock.
   **Locked and implemented:** the daemon queues when no policy is configured
   (D9 default-off). D9 unchanged (no amounts forbidden — a delay, not a cap).
3. **O5 → separate-device HMAC** recommended; prompt-per-use rejected.
   **Locked as design:** the daemon side is implemented (approve-token auth
   on a separate route, S7); the human's separate-device HMAC prompter is
   human-side tooling, out of repo scope. Single-device fallback (O9) still
   open — it tensions O10's separate-device stance, so it stays undecided.
4. **O2 → rotation-receipt shape** above (old-key-signed, versioned,
   pre-signed compromise rotation, second-factor/veto for contested
   rotations, per-context key scoping). **Locked as design;** the rotation
   ceremony tooling itself is not yet built (§10 step 10 drills it on testnet
   when it exists).
5. **O8** (sibling double-spend) resolved by design via per-sibling labels —
   unchanged.

## 12b. Launch-thread feedback (2026-09-22)

From the public-launch thread (Musebook lobby 57254), 2026-09-22. None of these
touches a locked decision (D1–D14); they are additive follow-ups and recorded
answers. Full record: `docs/reviews/2026-09-22-launch-thread-feedback.md`.

1. **Fee legs as their own rows (issue #20).** Activity shows balance deltas per
   transaction; fees fold into the Solana native delta and the EVM feed has no
   fee signal. Row grammar: chain, tx hash, fee asset, fee amount, fee payer.
2. **Wiring summary (answered in thread, recorded in the review doc).** Reads:
   free public RPCs + DexScreener/CoinGecko free tiers — no keys, no per-call
   cost. Signs: nothing, ever — the dashboard is read-only; signing is daemon
   local-only. Plug-in: `install.sh` on your own machine, Ed25519 challenge-sign
   login, viewer token for the human. Source of truth: `docs/AGENT_ONBOARDING.md`.
3. **Approval rows record the approving tool (issue #21).** Ledger rows carry
   ts / requester_muse / canon_digest / sighash / decision; `approved-by-human`
   does not say which tooling approved from. Add the approving tool/source to
   approval rows.

## 12c. Agent lifecycle: self-upgrade and self-repair (2026-09-23)

Agents must be able to stay on the latest signed release and repair their
own installs without risking their identity. Design, implemented on
`main` behind this section:

1. **Version identity.** The installer records the release in
   `/opt/spellbook/VERSION` (world-readable record, not a claim). The
   package exposes it (`spellbook.__version__`,
   `spellbook.version.local_version()`), the daemon reports it in
   `status.spellbook_version`, and `spellbook.version.upgrade_check()`
   compares it against the latest signed GitHub release — saying plainly
   when no release exists yet instead of inventing one.
2. **Key-preserving upgrade.** `install.sh --upgrade <tag>` replaces
   code/venv/systemd assets only. It never touches `seed.key`,
   `std_seed.key`, tokens, config, policy, ledger, queue/velocity state,
   Sage data, or submission gates; it never reprints key material and never
   flips `mainnet_submit_enabled`. Missing keys/tokens or an unparseable
   config abort the upgrade — a broken identity is re-provisioned with the
   human, never silently re-keyed. Sage is rebuilt only when its pinned
   commit changed.
3. **Agent self-serve path.** `spellbook upgrade <tag>` execs
   `/usr/local/bin/spellbook-upgrade` via a sudoers entry allowing exactly
   that path (NOPASSWD, root-owned, agent cannot modify). The wrapper takes
   one strict `X.Y.Z` tag, refuses downgrades and `--from-dir` (unsigned),
   and execs the pinned installer copy — so the agent can only ever install
   maintainer-signed releases (SHA-256 + release-key GPG verified pre-install),
   moving strictly forward. The release-key fingerprint
   (`SPELLBOOK_RELEASE_KEY_FPR`) is still unconfigured: release installation
   fails closed until Speechless pins it (open decision, carried).
4. **Doctor.** `spellbook doctor` (request-token side, via the daemon's
   `doctor` RPC — the agent cannot traverse `/opt/spellbook` itself) checks
   package, installed VERSION, key/token presence+mode (never contents),
   config shape, ledger presence, Sage, daemon socket and version match.
   `doctor --repair` self-repairs **code** problems via a signed-release
   reinstall; **state** problems (keys, tokens, config, ledger) fail closed
   with guidance — never regenerate, never mint by hand, never hand-edit,
   never reconstruct.
5. **Docs.** `docs/AGENT_LIFECYCLE.md` is the agent-facing reference;
   `docs/AGENT_ONBOARDING.md` §1b is the short version. Tests:
   `tests/test_lifecycle.py`.
6. **Self-install.** Agents install Spellbook on their own machines
   themselves — this is the primary onboarding path, not a fallback
   (`docs/AGENT_SELF_INSTALL.md`; `install.sh --as-agent`). The trust
   anchor — the release-key fingerprint — always comes from an independent
   channel (the pinned town thread), and the agent verifies the release key
   itself before installing. The agent holds only the request token; the
   approve token and paper backup go to the human out-of-band and are never
   retained by the agent.

7. **Challenge-sign consensus (townhall/37143, posts 57577–57670,
   2026-09-23) — town recommendation, pending Speechless's final approval.**
   pretrade, Mikey, and Anastasia converged on the shape of the
   watch/address-binding challenge and its public receipts: (a) the challenge
   string must be readable by the signer *before* signing (proof-of-key, not
   proof-of-trust); (b) the string must name the verifier *inside the signed
   bytes* (`spellbook.awizard.dev`), with origin/domain, timestamp, nonce,
   and single-use/session id in the canonical byte template — a bare nonce
   is portable across hosts minting the same shape, so readability alone is
   not enough; (c) binding asks for nothing beyond the signature — no
   approval, no permit, no transaction; (d) re-checks file no-change rows as
   receipts ("checked, no wallet calls, same markup" — silence isn't), and a
   board copy of a challenge is the *exact canonical bytes*, not prose, with
   the capture point in the challenge's life stated (spent — after the
   signing it certifies), so a stranger can verify offline against the key
   already served by the identity doc. Known boundary: single-use and
   cross-origin rejection are server facts presenting as a "no" that never
   appears in a string — the capture can't prove them. Maps to O2 (rotation
   rows' canon strings should carry the same verifier binding), O10
   (readable challenge = human-visible proof), and O5 (signature-only
   binding). Full record: `docs/reviews/2026-09-23-challenge-sign-consensus.md`.

## 13. Residual risks (accepted, not solved)

- **VM compromise** takes the hot wallet — that is what the hot/cold split and
  caps are for; the daemon does not defend this layer. Note the default
  config queues every spend for human approval until policy is configured
  (S4) — caps only help once the human opts in, and the queue is what holds
  the line before that.
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
  2. Builds the Sage CLI from its pinned commit (§3 / D4) — the commit pin
     is verified (`git rev-parse HEAD`) before compiling, so the binary is
     produced from pinned source.
  3. Creates the dedicated `spellbook` OS user (S2); builds and installs the
     daemon under it; writes a default-off policy config (D9).
  4. Runs the §10 testnet drill automatically with a throwaway key — minus
     the rotation drill, which runs on the maintainer's machine only (S14).
     The install only completes when the drill passes — every install proves
     itself on testnet before mainnet is possible. A failed drill leaves the
     machine clean and prints how to resume without reinstalling (S14).
  5. Prints next steps: opt-in policy knobs, paper backup (§6), directory
     entry (§8) — and says out loud that every spend queues for human
     approval until the human configures policy (S4) — a delay, not a cap.
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
  self-verifying installer, one sentence of what it is ("turns your muse key into
  your own native EVM wallet — Chia via Sage included as a bonus"), link to
  the pinned thread.
  This matches the town norm (replies in live threads, never broadcasts) and
  makes distribution genuinely automatic: every new muse is offered the kit
  with zero coordination. Clearly labeled, no pressure, never repeated to the
  same muse. Needs Speechless's go-ahead at un-silencing.

**What "automatic" never means:** we never push code to anyone, never run
anyone's daemon, never hold anyone's keys, never see anyone's secrets. Pull,
verify, install locally — per muse, per D1.

---

## 15. Review log
- 2026-09-23 — challenge-sign consensus (townhall/37143 posts 57577–57670:
  pretrade, Mikey, Anastasia): challenge readable before signing, verifier
  named inside the signed bytes (origin/timestamp/nonce/single-use id),
  binding signature-only, no-change receipts as heartbeat, board copies are
  exact canonical bytes stated as spent; server-side single-use /
  cross-origin rejection acknowledged as a string-invisible boundary. Maps
  to O2 (verifier binding in rotation-row canon strings), O10, O5. Recorded
  as town recommendation **pending Speechless's final approval** — no locked
  decision flipped, no code changed. Full record:
  `docs/reviews/2026-09-23-challenge-sign-consensus.md`.
- 2026-09-22 — testnet-green town round (townhall/37143, post 51047): all
  three chains green, town feedback folded in. New open items O11 (receipt
  escrow — opt-in `receipt_anchor` flag, Speechless-directed design) and
  O12 (decode-gate stranger veto, Pete). Drill manifest v1 pinned
  (`docs/reviews/drill-manifest-v1.md`, Turbo) and referenced from §10;
  re-walkability map (`docs/reviews/2026-09-22-testnet-rewalkability.md`,
  Z); approval-failure drill run live (queue 11 → rejected-by-human,
  nothing fired, Pete). Stranger-witness rule for mainnet recorded as
  pending Speechless's mainnet authorization. Replies 51219/51221/51225/51226.
- 2026-09-22 — testnet-green round follow-up (townhall/37143, posts 51267–
  51272, Mikey): four endorsements of the folded consensus — bump-don't-edit
  manifest rule, the rejection receipt as the proof the queue is a real
  gate, testnet→mainnet row mapping + town-witness re-walk, CRT's two-
  identifier claim rule + "failures escrowed too" (town support for yes on
  escrowed failures, folded into the receipt-escrow doc). No new open
  items, no locked decisions touched. Note:
  `docs/reviews/2026-09-22-testnet-green-town-endorsements.md`.
- 2026-09-20 — Sage pinned-commit path implemented (was: open decision #7).
  `install.sh` §2 now builds the `sage-cli` crate from source at the pinned
  commit `f2ec89dd…`: shallow-fetch the exact commit, assert
  `git rev-parse HEAD` equals the pin, then `cargo build --release -p
  sage-cli`. The pinned commit is the verification — no release-artifact
  checksum needed. The verified binary is installed at
  `/opt/spellbook/bin/sage` and recorded as `sage_bin` in `spellbook.json`;
  an operator-supplied `$SAGE_BIN` is still accepted only with
  `SAGE_PIN_VERIFIED=1`. Not yet compiled end-to-end (needs a Rust toolchain
  + build time at install); the Sage/XCH testnet drill itself still awaits a
  live run. Remaining genuinely blocked item: the release-key signature
  (fail closed).
- 2026-09-20 — §10 on-chain testnet drill GREEN (EVM path, Robinhood Chain
  testnet 46630). Throwaway seed/daemon; 0.009 test ETH funded via faucet.
  Auto-approved below-threshold transfer submitted and confirmed
  (0x18a80c08a2808dbbb7d95597ddd2460916708b6e5033d597d37ad2ed75ac4a70);
  queued above-threshold spend approved through the approve token and
  confirmed (0xfa29bb775de77c08602383cb34c012d784893d5f481a0a78ed71a5e1725838cc);
  per-spend-cap and velocity-cap denials enforced; live balances read back;
  both tx hashes recorded as ledger sighashes with no seed material in any
  API surface; bad-token and request-token privilege escalation denied;
  kill -9 restart preserved queue, ledger, and velocity window. 38 unit
  tests green. One real bug found and fixed during the drill: Robinhood
  Chain (Arbitrum-style) estimates ~28867 gas for a plain transfer, above
  the 21000 floor — the first run died with "intrinsic gas too low"; the
  daemon now takes its gas limit from eth_estimateGas and fails closed if
  estimation is unavailable. Sage/XCH drill steps stay pending on a live
  drill run (the pinned-commit build path is implemented — open decision #7
  resolved 2026-09-20).

- 2026-09-20 — Chia path implemented + S4 made real in code (Speechless:
  "fix the caveats so we can provide a ready to launch build"): (1) S4
  queue-by-default was spec'd but `policy.py` still auto-approved — now
  `evaluate()` returns **queued** when nothing is configured, with
  `auto_approve_below` as the explicit human-configured lift (the drill's
  on-chain phase already sets it, so §10.4/10.5 semantics hold); two
  regression tests added. (2) New `src/spellbook/chia.py`: stdlib-only mTLS
  Sage RPC client (endpoints verified against the pinned sage source:
  /set_network, /get_keys, /import_key, /login, /get_sync_status,
  /get_wallet_address, /send_xch, /get_transactions; Amount is untagged
  string-or-number; testnet is `testnet11`). (3) Daemon `_execute_chia_spend`:
  refuses mainnet without the flag, schema-guards mojos/wei and the
  txch1/xch1 prefix, verifies the imported key's fingerprint locally
  against the KDF derivation, logs in, sends with auto_submit, and
  confirms via /get_transactions matching destination+amount before
  reporting the created coin id as the ledger reference. (4) The daemon
  owns Sage's lifecycle (O10): spawns `sage rpc start` with
  XDG_DATA_HOME=<prefix>/sage when the RPC port is silent; installer
  writes the `chia` config section and the data home. 54 tests green.
  Still pending: the pinned-commit sage-cli compile (running — Tauri git
  deps are slow to clone), then the live Sage testnet drill.
- 2026-09-20 — town decisions locked as implementation consensus: Speechless
  approved S1→Option B (fleet; implemented in installer/daemon), S4→
  queue-by-default (implemented), O5→separate-device HMAC (daemon side
  implemented; human device tooling out of repo scope), O2→rotation-receipt
  shape (design locked; ceremony tooling pending). O9 single-device fallback
  stays open (tensions O10). §12a rewritten as adopted, not pending.
  Speechless authorized the §10 on-chain testnet drills (EVM path, Robinhood
  testnet 46630); mainnet dust still needs separate authorization + amounts.

- 2026-09-20 — pass-2 audit remediation (P1–P9): `docs/reviews/2026-09-20-responses.md`.
- 2026-09-20/21 — open-decisions town review (townhall/37143): S1 → Option B
  (fleet, not desk), S4 → queue-by-default, O5 → separate-device HMAC,
  O2 → rotation-receipt shape; all pending Speechless's final approval
  (§12a). New open items O8 (sibling double-spend, resolved by design),
  O9 (single-device fallback), O10 (human interacts with the agent's wallet
  from chat). Full record: `docs/reviews/2026-09-21-townhall-37143.md`.
- 2026-09-20 — build v0.1.0: repo restructured into the pip-installable
  `spellbook` package (`src/spellbook/`, console scripts `spellbookd` +
  `spellbook`); the daemon's KDF is now the THIRD implementation reproducing
  all 10 `vectors/vectors.json` vectors byte-for-byte from the published test
  seed (test seed only — no real seed derived); signing primitives wired
  (secp256k1/ECDSA via libsecp256k1, BLS via py_ecc, Ed25519 identity signing
  behind the S1 gate); queue persistence + 24h velocity reconstruction;
  per-role peer-UID enforcement; agent client library (`AgentClient` /
  `HumanClient`) + `spellbook` CLI; installer finished except the release-key
  signature (fail closed). The Sage pinned-commit verification landed
  2026-09-20 as a build-from-source path (§2).
  30 tests green (`tests/`). Install verified end-to-end on a throwaway
  machine image and torn down afterwards. Nothing on-chain; on-chain drill
  phases still need explicit authorization (§10).

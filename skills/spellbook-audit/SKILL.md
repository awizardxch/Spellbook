---
name: spellbook-custody-auditor
description: "Runbook for auditing Spellbook, the per-agent self-custody wallet stack (Ed25519 identity seed to HKDF-derived EVM and Chia keys, a local policy daemon, Sage headless, signed pull-only distribution), at every stage from spec prose to running code. Use when the user says Audit Spellbook, Review the wallet spec, Check the key derivation, Audit the policy daemon, or Run the Spellbook audit."
---

# Spellbook custody auditor

A runbook for structural security review of Spellbook: a stack that turns an agent's
32-byte Ed25519 identity seed into self-custodied EVM and Chia wallets behind a local,
non-LLM policy daemon. It is written to be loaded by a model and argued with, and it
lives in this repository on purpose: the method that finds defects in a custody design
should be as public as the design. Where a rule exists because a review got something
wrong, the mistake is named.

The project is spec-first. `SPEC_V1.md` is the canonical plan and, until code exists, the
thing under audit. A finding against the prose is a real finding: the prose is what the
implementation will be built from, and what every other agent will read to decide whether
to install it. When code lands, the same catalog applies and the lanes below gain teeth.

## Non-negotiable audit rules

1. **Audit enforcement, not intent.** Every "MUST NEVER", "only process", "never sees" and
   "human-authenticated" in the spec must name the mechanism that makes it true: an OS
   user boundary, a file owner and mode, a socket peer check, a separate credential, a
   hardware boundary. A rule that is only stated to the agent is a prompt, and the spec's
   own thesis is "policy in code, not prompts". Where no mechanism is named, the finding
   is that the rule is unenforced, however emphatic the wording.
2. **Verify every external fact against its source at the pinned version.** RPC request
   shapes, ports, data directories, chain ids, curve orders, address formulas, tag
   existence. Cite `file:line` in the pinned checkout or the URL. A spec that names a
   version is auditable only against that version; a fact from memory is a hypothesis.
3. **Build the artifact table before reading for bugs.** One row per secret or
   credential (identity seed, each derived key, each child key, bearer token, mTLS certs,
   export files, backups): who holds it, in which process and OS user, on which path with
   which mode, which sections mention it, and which software restores it. Most custody
   defects are two rows that disagree.
4. **Round-trip every backup claim.** For each export, name the exact stock software and
   the exact import field that yields the exact same address. If you cannot name both,
   the claim is false, and a backup that restores only through the project's own tooling
   is a dependency, not a backup. Do this on paper for the spec and with real software
   when code exists.
5. **Audit the defaults, not the best configuration.** A policy engine is reviewed as it
   ships. If every knob is off by default, the threat model of the default install is
   "no policy", and every claim the spec makes about caps is conditional.
6. **Two endpoints with the same credential are one endpoint.** For each API route, list
   the principal that can call it and what a caller gains. If the route that exports
   keys and the route an agent uses to request a spend accept the same token, the agent
   can export keys. Approval routes that the requester can call are not approvals.
7. **Test vectors are part of the spec.** Before any real key is derived, the derivation
   must be reproduced by two independent implementations (for example Python `hkdf` +
   `coincurve` + `py_ecc` against the daemon) from a published test seed, and the
   expected addresses must appear in the repository. A derivation spec without vectors
   cannot be audited for the address formula, only for its prose.
8. **State where the same defect already exists today.** This stack reuses an identity
   key that other software already holds. If that software runs inside an LLM-driven
   process, say so with the file and line, because the spec's isolation story starts
   from where the key actually lives, not from where the spec wishes it lived.

## Target architecture (from SPEC_V1.md, verified 2026-09-20)

- **Root:** the agent's 32-byte Ed25519 seed (Musebook muses keep it in a key file or in
  `projects/musebook/.env`; the Musebook client `musebook.mjs` reads it to sign posts).
- **KDF:** HKDF-SHA256, salt `"muse-wallet-v1"`, info strings per purpose
  (`evm-hot/v1`, `chia-hot/v1`, reserved `*-cold/v1`), bytes to scalar with a retry rule.
- **EVM:** secp256k1 key, EIP-1559 signer, Robinhood Chain (mainnet 4663, testnet 46630).
- **Chia:** BLS12-381 key imported into Sage `v0.13.1` (`xch-dev/sage` tag
  `f2ec89dd…`, 2026-09-19) through `POST /import_key`, whose request is
  `{name, key: "mnemonic phrase or private key", derivation_index, hardened}`
  (`crates/sage-api/src/requests/keys.rs:151`); RPC on `127.0.0.1:9257`
  (`crates/sage-config/src/config.rs:69`) with mutual TLS.
- **Daemon:** localhost HTTP, bearer token in a file, routes `request_spend`, `queue`,
  `approve`/`reject`, `status`, `addresses`, `export_key`; policy knobs all off by
  default (D9); v1 approvals relayed by the conversational agent.
- **Distribution:** `curl | bash` installer at a pinned tag that verifies a signed release
  tarball, installs Sage, builds the daemon, and runs the testnet drill.

## Lanes, and what each cannot decide

| Lane | What it runs | Can decide | Cannot decide |
|---|---|---|---|
| Prose | the spec, the pinned dependency sources, chain documentation | consistency, enforceability, correctness of formulas and facts, completeness of the threat model | whether the implementation matches |
| Vectors | two independent KDF and address implementations from a test seed | the derivation and address formulas, the retry rule, restore round-trips into stock software | anything about the daemon's process boundary |
| Boundary | the daemon and an agent under two OS users on one machine | which files and routes each principal can reach, what survives `kill -9`, what a prompt-injected agent can do with only its token | network and chain behaviour |
| Drill | the §10 testnet plan on a throwaway seed | end-to-end flows, Sage sync, faucet and RPC realities, rotation | anything needing mainnet funds; nothing here authorises a mainnet action |

## Attack-vector catalog

Every item is a hypothesis to probe, not a finding.

### Key custody and derivation

- The identity seed is the wallet root: every process that holds the seed holds every
  wallet. List those processes today, not in the target architecture.
- Cold purposes derived from the hot root are not cold: anyone with the root derives them.
- HD children versus single keys: a 32-byte scalar is not a BIP-32 master (no chain
  code). Which is it, and does the backup story still hold for child addresses?
- Address formula: Ethereum hashes the 64-byte uncompressed public key, not the
  compressed one. Chia addresses come from the puzzle hash of the wallet key at a
  hardened or unhardened derivation, not from the master key directly.
- Scalar edge cases: zero, values at or above the order, and whether "mod order" and
  "retry" are both specified for the same step.
- BIP-39 words from 32 bytes are a 24-word encoding; typing them into a wallet's phrase
  field runs PBKDF2 and yields a different key. Is that stated where the human will read
  it, in the export file itself?

### Process boundary

- Same OS user for daemon and agent means the agent can read the key file, the token,
  the certs and the export file regardless of any MUST NEVER.
- Bearer token in a file: who can read the file, and can the same token call
  `approve` and `export_key`?
- `export_key` writes a file: which user owns it, who can read it, and who deletes it?
- `kill -9` and restart: which policy state (velocity windows, queue) lives only in
  memory, and can the agent restart the daemon to reset it?
- Sage's mTLS client cert: same-user readability makes the daemon's monopoly on the
  RPC a convention.

### Policy engine

- Defaults: what an agent can spend in the first minute after install, with no human
  configuration.
- Velocity accounting persistence; allowlist semantics when the allowlist is empty
  versus unset; per-chain versus per-asset caps for tokens with different decimals.
- What `request_spend` can express: if only destination, asset and amount, contract
  calls are out of scope, and that should be stated; if calldata is ever accepted, the
  policy engine cannot reason about it.
- Chain id binding of every EVM signature (EIP-155) and of every policy decision.
- The build-verify-sign-submit step: what is compared against the intent, and by whom.

### Approvals

- Relay trust: an approval relayed by the requester is the requester's approval.
- Separate credentials for request and approve, and a human-only channel for export.

### Directory and rotation

- Self-attested entries with append-only history: which entry wins when two conflict,
  and can a compromised old key publish a supersession?
- Rotation ordering: sweep before or after publishing, and what a race looks like when
  the attacker holds the old key.

### Supply chain and distribution

- `curl | bash` fetches the verifier unverified; the tag it pins is mutable unless the
  tag is signed and the commit hash is stated.
- `cargo install --git … --tag` pins a tag, not a commit.
- A drill inside the installer depends on faucets, sync and RPCs; what a failed drill
  leaves behind on the machine.

## Required audit procedure

1. Record the spec commit, and clone every pinned dependency at its pinned tag into a
   scratch directory. Record commit hashes and dates.
2. Build the artifact table (rule 3). Every secret, every holder, every path, every mode.
3. Build the principal table (rule 6). Every route, every credential, every gain.
4. Read the spec section by section against the catalog; verify each external fact
   (rule 2) and note each unenforced rule (rule 1).
5. Round-trip each backup and restore path on paper (rule 4).
6. Audit the default configuration end to end as an attacker who controls the agent's
   prompt and nothing else (rule 5).
7. When code exists: run the vectors lane, then the boundary lane under two OS users,
   then the drill. Write probes that pass while a finding is open and invert them when it
   closes, as `test/Audit.*` does in the Obsidian repository.
8. Write the report in `docs/audit/` using the finding format below. Every finding names
   the section and the sentence it is against, and proposes the replacement text or the
   mechanism. Separate findings from hypotheses and state residual gaps.

## Strict finding format

### [Finding ID] - [Descriptive Title]

- **Risk Level:** Critical / High / Medium / Low / Informational
- **Surface:** Key custody / Process boundary / Policy engine / Approvals / Directory /
  Supply chain / Documentation
- **Target:** `SPEC_V1.md` section and the sentence, or `file:line` once code exists

#### 1. Observed condition

What the spec says, what is actually true (with the source cited), and what an attacker
with the stated access gains. Mark unexecuted reasoning as provisional.

#### 2. Evidence

The citation, the artifact-table rows that disagree, or the probe name once code exists.

#### 3. Remediation

The replacement text or the mechanism, and the test that will pin it.

## Completion gate

A spec audit is complete when the report names the spec commit and every pinned
dependency commit, every external fact in the spec has been checked against its source,
the artifact and principal tables are in the report, and each finding has a cited
sentence and a concrete remediation. A code audit is complete when, additionally, the
vectors lane reproduces the published test vectors two ways, the boundary lane has been
run under two OS users, and every finding has a probe that was inverted on its fix.

## Changing this runbook

Say what a change would have caught, or what it missed, and keep the facts current: the
Sage citations above are to tag `v0.13.1`; when the pin moves, re-read them, because a
runbook that cites a stale line teaches the wrong fact with confidence.

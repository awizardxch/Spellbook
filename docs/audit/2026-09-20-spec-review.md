# Spellbook spec audit, 2026-09-20

Method: `skills/spellbook-audit/SKILL.md`. Target: `SPEC_V1.md` at commit `02403ee`
(spec-only repository; no code exists). This is an internal review of the prose before
Phase 1; nothing here authorises any key generation or on-chain action.

## Sources checked

| Item | Value |
|---|---|
| Spec | `SPEC_V1.md`, commit `02403ee`, 454 lines |
| Sage pin | `xch-dev/sage` tag `v0.13.1` = `f2ec89dd59d07227bed657bc268fc32ce97551f6` (2026-09-19); tag exists |
| Sage `import_key` | `crates/sage-api/src/requests/keys.rs:151` (request), `crates/sage/src/endpoints/keys.rs:124` (handler) |
| Sage RPC port | `crates/sage-config/src/config.rs:69`: 9257 |
| Sage data dir | `crates/sage-cli/src/main.rs:32`: `com.rigidnetwork.sage` |
| Robinhood Chain | mainnet 4663, testnet 46630 (chainid.network, Robinhood docs) |
| Musebook client | `aWizard-Familiar/projects/musebook/musebook.mjs:3-4,32-47` reads the Ed25519 seed from `.env` |

## Summary

| ID | Title | Risk |
|---|---|---|
| S1 | The custody root is already held by LLM-driven processes | High |
| S2 | No OS boundary separates the daemon from the agent | High |
| S3 | Key export shares the approval bar, which the agent relays | High |
| S4 | The default install has no policy | Medium |
| S5 | The EVM derivation contradicts itself and breaks the stock-software restore | Medium |
| S6 | Cold purposes derived from the hot root are not cold | Medium |
| S7 | One credential requests and approves | Medium |
| S8 | Directory rotation has no conflict rule | Medium |
| S9 | The installer's own supply chain is unaddressed | Medium |
| S10 | Policy state lives only in memory | Low |
| S11 | Sage import details the spec does not state | Low |
| S12 | The scalar rule is specified twice, differently | Low |
| S13 | Facts verified correct | Informational |
| S14 | The installer's drill has external dependencies | Informational |

The design's shape is right: one root, standard HKDF, a non-LLM daemon, pull-only
distribution, testnet before mainnet. The High findings are all one theme: the spec
states isolation in MUST NEVER language and names no mechanism, and today the seed it
wants to isolate is read by the very process it wants to exclude.

## Artifact table (rule 3)

| Artifact | Holder today | Holder per spec | Path and mode | Restores with |
|---|---|---|---|---|
| Ed25519 seed (root) | Musebook client in the agent's tool process, the Meta agent, the human | daemon only (D3) | `~/.config/musebook/key.json` or `projects/musebook/.env`, 600, agent's user | our tooling (words) |
| `evm-hot/v1` scalar | none | daemon memory | none | any EVM wallet, private-key import (single address only, see S5) |
| `evm` child keys `m/44'/60'/0'/0/i` | none | daemon memory | none | nothing stock (see S5) |
| `chia-hot/v1` scalar | none | daemon memory and Sage keychain | Sage `keys.bin` | Sage `import_key` as 32-byte hex (`save_secrets` defaults true) |
| `*-cold/v1` scalars | none | "cold machine only" | none | derivable from the root wherever the root is (S6) |
| Daemon bearer token | none | agent and daemon | file, 600, agent's user | n/a |
| Sage mTLS client cert | none | daemon "by file permissions" | `<datadir>/ssl/` | n/a |
| Export file | none | human | fresh file, 600, same user as daemon | see above |

## Principal table (rule 6)

| Route | Credential | Who holds it | What a caller gains |
|---|---|---|---|
| `request_spend` | bearer token | agent | a spend, auto-approved under default config (S4) |
| `queue`, `status`, `addresses` | bearer token | agent | read |
| `approve`, `reject` | "human-authenticated": v1 is the agent relaying | agent | any queued spend (S7) |
| `export_key` | "same bar as approve" | agent | the root seed on disk, readable under one OS user (S3, S2) |

## Findings

### S1 - The custody root is already held by LLM-driven processes

- **Risk Level:** High
- **Surface:** Key custody
- **Target:** D2, D3, §1 ("Conversational agents: never keys"), §4 "Secrets handling", §9

#### 1. Observed condition

The spec makes the muse's existing Ed25519 seed the root of every wallet (D2) and says
the daemon is the only process that holds secrets (D3) and that agents MUST NEVER read
the muse key (§9). The seed already lives elsewhere. The Musebook client reads it from
`projects/musebook/.env` (or the environment) to sign every post, and that client runs
inside the aWizard Claude session's tool process; the `.env` comment says the Meta agent
holds the same seed and both sign in parallel. The moment Spellbook ships, that env
variable is the private key of every wallet the muse owns, sitting where a
prompt-injected agent can `cat` it. The spec's isolation story starts from a wrong
premise about where the key is.

#### 2. Evidence

`aWizard-Familiar/projects/musebook/musebook.mjs:3-4` ("Reads MUSEBOOK_PRIVATE_KEY from
projects/musebook/.env"), `:32-47` (decodes the 32-byte seed and builds the signing key),
`.env` line 1 ("both agents can sign in parallel"). Artifact table, row 1.

#### 3. Remediation

Move Musebook signing behind the daemon. The daemon owns the seed (file owned by the
daemon's OS user, S2) and exposes `POST /v1/sign_request {bytes}` returning a signature,
so `musebook.mjs` and the Meta agent hold a token, not the seed. Then D3 becomes true by
construction and one backup still covers everything. If that is not possible for the
Meta agent, the honest alternative is a separate wallet root: the daemon generates its
own 32-byte seed, the identity key only signs directory entries, and the human keeps two
papers. Either way, rewrite D2's "chain keys are derived from the identity key" to say
where the identity key must live for that to be safe, and add a §10 step that greps the
agent's environment and workspace for the seed and fails if it is found.

### S2 - No OS boundary separates the daemon from the agent

- **Risk Level:** High
- **Surface:** Process boundary
- **Target:** §1 (architecture diagram), §3 "the daemon is the only process permitted to read the client cert (file permissions)", §4 "bearer token in a file, mode 600", §9

#### 1. Observed condition

Every isolation claim rests on file modes, and the spec never says the daemon runs as a
different OS user from the agent. Mode 600 protects against other users, not against
the same user. If the agent's tool process and the daemon share a user, the agent can
read the key file, the bearer token, the mTLS client cert, and any export file, and can
restart the daemon (S10). Each MUST NEVER in §9 is then a prompt, which is what the
spec's thesis says it must not be.

#### 2. Evidence

§4 names "mode 600" three times and no owner. §3 says "file permissions" without naming
whose. Artifact table: every row's holder is "agent's user".

#### 3. Remediation

State the mechanism in §1 and §4: the daemon runs as a dedicated OS user (`spellbook`,
or a systemd `DynamicUser`), which alone owns the seed file, the Sage data dir, the
certs, and the export directory, all 0600 or 0700. The API is a Unix domain socket with
peer-credential checks, or localhost HTTP whose request token is the only file the
agent's user can read. Add to §10: "as the agent's user, attempt to read each artifact
and to call each route with the agent token; every attempt must fail" (the boundary lane
in the runbook). The installer creates the user.

### S3 - Key export shares the approval bar, which the agent relays

- **Risk Level:** High
- **Surface:** Approvals / Key custody
- **Target:** §4 "Key export: human-authenticated only (same bar as /approve; v2 HMAC when it exists)", §6 paper backup step 2 "Agent calls POST /v1/export_key"

#### 1. Observed condition

In v1 the "human" bar for `/approve` is the conversational agent relaying a chat
message (§4 "Documented trust assumption"). `export_key` uses the same bar. So the
agent can call `export_key {scope: "muse-root"}` on its own initiative, and with S2 it
can read the file it produces. The paper-backup flow even scripts the agent as the
caller. D10's "never" and §9's "MUST NEVER read the export file" have no mechanism
behind them.

#### 2. Evidence

§4, §6 step 2, principal table.

#### 3. Remediation

Export is never an API call the agent can make. Make it a local command the human runs
as the daemon user (`spellbook export --scope muse-root`), with an interactive
confirmation on the daemon's own TTY, writing into a directory the agent's user cannot
read. Remove step 2 from §6 and replace with "the human runs the export command". If a
remote route must exist, it takes a human-only credential that is never in the agent's
environment (make O5's HMAC the v1 requirement for this route).

### S4 - The default install has no policy

- **Risk Level:** Medium
- **Surface:** Policy engine
- **Target:** D9, §4 "Defaults: everything off", §13 "that is what the hot/cold split and caps are for"

#### 1. Observed condition

With every knob off, `request_spend` auto-approves anything, so a prompt-injected agent
empties the hot wallet in one call, and §13's stated defence against VM compromise
(caps) is not present in the default install. D9 is a locked decision, so this finding
is against the prose: the README and §4 sell "policy in code" while the default is "a
signer that does what it is told". Note also that turning on `approval_threshold`
helps only after S3 and S7, because in v1 the requester relays the approval.

#### 2. Evidence

§4 defaults paragraph; §13 first bullet; README "It enforces caps, allowlists, velocity
limits, and a human-approval queue".

#### 3. Remediation

Keep D9 if the decision stands, but say in the README and §4 that the default daemon is
a signer, not a policy engine, until the human writes a config, and that the hot wallet
should hold nothing the agent may not lose. Consider one non-optional safety: for the
first 24 hours after install, or until the human has written any config, queue every
spend. Add a §10 step that exercises the default config explicitly.

### S5 - The EVM derivation contradicts itself and breaks the stock-software restore

- **Risk Level:** Medium
- **Surface:** Key custody
- **Target:** §2 "compressed public key → EVM address (keccak256(pubkey)[12:])"; §2 "BIP-44 m/44'/60'/0'/0/i beneath the derived secp256k1 master"; §6 restore path (b)

#### 1. Observed condition

Three statements cannot all be true. An Ethereum address is the last 20 bytes of
`keccak256` of the 64-byte uncompressed public key, not the compressed one; implemented
literally, the spec derives wrong addresses. A 32-byte scalar is not a BIP-32 master
key, which needs a chain code, so "BIP-44 beneath the derived master" is undefined
until the spec says how the chain code arises. And path (b) promises that importing the
`evm-hot` hex into any EVM wallet "recovers the exact hot wallet": a stock wallet's
private-key import yields one account, so every labeled child address beyond the master
is unrecoverable with stock software, which is the property path (b) exists to provide.

#### 2. Evidence

§2 and §6 as cited; artifact table rows for `evm-hot` and its children.

#### 3. Remediation

Choose one key per label instead of HD: info strings `muse-wallet/evm-hot/v1/<label>`
each yield a standalone secp256k1 key, every address restores with a plain private-key
import, and the export lists one hex per label. Fix the address sentence to "the
uncompressed 64-byte public key". State `L = 32` for HKDF-Expand. Publish test vectors
(a fixed seed, the expected address per label) computed by two independent
implementations before Phase 1, per §2's own gate.

### S6 - Cold purposes derived from the hot root are not cold

- **Risk Level:** Medium
- **Surface:** Key custody
- **Target:** §2 "Reserved and forbidden on hot machines: chia-cold/v1, evm-cold/v1"

#### 1. Observed condition

Anything derived from the root is available to whoever holds the root, and the root
lives on the hot machine (and, per S1, in the agent's environment). A purpose string
cannot make a derivation cold; "forbidden on hot machines" is a rule with no mechanism.
§6 already defines cold correctly as the human's own hardware wallet.

#### 3. Remediation

Delete the reserved cold purposes. Cold is a separate root, full stop.

### S7 - One credential requests and approves

- **Risk Level:** Medium
- **Surface:** Approvals
- **Target:** §4 "Human approval path (v1)", O5

#### 1. Observed condition

The agent that calls `request_spend` is the same principal that calls `approve`. An
approval the requester can grant is not an approval; the spec says so itself and defers
the fix to v2. Combined with S4 the queue is dormant anyway, so today this costs nothing
to fix and later it is the whole value of the queue.

#### 3. Remediation

Two tokens from day one: a request token in the agent's environment and an approve
token that only the human's own tool holds (a tiny CLI on the human's machine, or the
HMAC of O5). The daemon rejects `approve` and `export_key` with the request token. Make
O5 a Phase 1 item, not an improvement.

### S8 - Directory rotation has no conflict rule

- **Risk Level:** Medium
- **Surface:** Directory
- **Target:** §7 step 4, §8 "entries are append-only history, never edited in place", O2

#### 1. Observed condition

Entries are self-attested and append-only, and a rotation entry is signed by the new key
with an optional supersession from the old one. An attacker who has the old key can
publish exactly that: a "rotation" to keys they control, with a valid old-key
supersession. Readers have no rule for which of two conflicting entries is current, so
the last writer wins, and the attacker can always write last. Rotation validity has to
be anchored somewhere the compromised key cannot reach.

#### 3. Remediation

Make Musebook's `muse_id` to public-key binding the authority (this is O2), and have
directory consumers accept only entries signed by the key Musebook currently binds to
that `muse_id`. Until O2 is answered, §7 step 6 should say that rotation is unspecified
and therefore, by its own rule, mainnet is gated on it. State the conflict rule in §8.

### S9 - The installer's own supply chain is unaddressed

- **Risk Level:** Medium
- **Surface:** Supply chain
- **Target:** §14 one-line installer, §3 `cargo install --git … --tag v0.13.1`, §13 "Supply chain"

#### 1. Observed condition

`curl … | bash` fetches the script that does the signature verification, itself
unverified, from a tag; a git tag is mutable unless signed, and a compromised GitHub
account rewrites it for every muse at once. `cargo install --git --tag` has the same
property for Sage. §13 lists only Sage as a supply-chain risk.

#### 3. Remediation

Publish the installer's SHA-256 and the release-key fingerprint in the pinned thread and
the README, and make the documented command `curl -o install.sh … && sha256sum -c` or
`git clone` plus `git verify-tag`. Sign release tags. Pin Sage by commit
(`f2ec89dd59d07227bed657bc268fc32ce97551f6`) as well as by tag, the way Obsidian pins
DN404. Add the installer to §13.

### S10 - Policy state lives only in memory

- **Risk Level:** Low
- **Surface:** Policy engine
- **Target:** §4 "holds derived secrets in memory only", `daily_velocity_cap` "rolling 24h sum", §10 step 11

#### 1. Observed condition

The spec says secrets are memory-only, which is right, but never says where the
velocity window and the queue live. If they are memory-only too, a restart resets the
24-hour window, and with S2 the agent can restart the daemon. Step 11 tests that no
secret survives `kill -9`, not that policy state does.

#### 3. Remediation

Persist the decision ledger (intents, decisions, timestamps; never secrets) to an
append-only file owned by the daemon user, and make step 11 assert that the velocity
window and queue survive the restart.

### S11 - Sage import details the spec does not state

- **Risk Level:** Low
- **Surface:** Key custody / Documentation
- **Target:** §3 "Key import", §6 restore path (b)

#### 1. Observed condition

Verified against `crates/sage/src/endpoints/keys.rs:124-190` at `v0.13.1`:

- A hex `key` of 32 bytes is taken as a raw BLS master secret (`SecretKey::from_bytes`),
  48 bytes as a master public key (watch-only). So the `chia-hot` hex import in path
  (b) works as described. The secret is stored only when `save_secrets` is true
  (`keys.rs:139-143`); the field defaults to true (`requests/keys.rs:168-171`), so an
  omitted field is safe, but a daemon that sets it false gets a watch-only wallet that
  cannot sign. Worth one sentence in §3.
- The `muse-root` hex and the `chia-hot` hex are both 32 bytes, and Sage accepts either
  as a master secret without complaint. A human who pastes the root by mistake gets a
  different, empty wallet and no error. The export file's labelling is the only guard.
- A 24-word phrase is imported through `SecretKey::from_seed(mnemonic.to_seed(""))`
  (`keys.rs:174`), which confirms the spec's warning that words and hex are different
  keys.

#### 3. Remediation

Note `save_secrets` in §3. In the export file, put the restore instruction beside
each hex ("this 32-byte hex is the Chia wallet key: paste into Sage import as a private
key"; "this 32-byte hex is the root: never paste into a wallet"). Consider exporting
the root only as words and the wallet keys only as hex, so the two cannot be confused.

### S12 - The scalar rule is specified twice, differently

- **Risk Level:** Low
- **Surface:** Key custody
- **Target:** §2 "Bytes → scalar" versus "BLS12-381: scalar mod r" and "secp256k1: scalar mod n"

#### 1. Observed condition

One sentence says retry with `/ctr/n` when the value is at or above the order; the next
two say reduce modulo the order. Both give valid keys, but they give different keys, and
two implementations following different sentences will disagree on the vectors. Zero is
not excluded by either.

#### 3. Remediation

One rule: `L = 32`; if the value is zero or at or above the order, re-expand with the
`/ctr/n` suffix; never reduce. Pin it with a vector whose first expansion is rejected,
constructed by choosing the seed.

### S13 - Facts verified correct

- **Risk Level:** Informational

HKDF-SHA256 with a fixed public salt and purpose-bound info is a sound construction for
a full-entropy 32-byte seed. 32 bytes encode to exactly 24 BIP-39 words. The Sage tag,
port, data directory and `import_key` shape match the spec. Chain ids 4663 and 46630
are correct. The D8 exception for typing restore words into a local file is stated. The
`request_spend` schema cannot express contract calls, which is the right scope for v1
and should be stated as deliberate.

### S14 - The installer's drill has external dependencies

- **Risk Level:** Informational
- **Target:** §14 step 4 "The install only completes when the drill passes"

The drill needs a faucet, peer sync and two RPC endpoints. Say what a failed drill
leaves on the machine and how to resume without reinstalling, and drop the rotation
drill (§10 step 10) from the per-install run; it belongs in the reference drill on the
maintainer's machine.

## Residual gaps

- No code exists, so the vectors, boundary and drill lanes were not run. The
  derivation findings (S5, S12) are from the prose and will be pinned by vectors.
- The Sage endpoints named in §10 (`get_sync_status`, `make_offer`, `take_offer`) were
  checked for existence only, not for request shape.
- The Meta agent's copy of the seed was not inspected; S1 relies on the `.env` comment.

## Recommended order

1. S1 and S2 together, because the fix for one is the fix for the other: a daemon user
   that owns the seed and signs Musebook requests.
2. S3 and S7 together: export becomes a local human command, approve gets its own token.
3. S5, S6 and S12 in §2, then publish the vectors.
4. S4 as a decision (keep D9, fix the prose, consider the 24-hour queue).
5. S8 waits on O2 and should be named as a mainnet gate. S9 to S11 before Phase 3.

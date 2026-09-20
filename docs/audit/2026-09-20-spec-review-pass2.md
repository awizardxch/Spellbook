# Spellbook spec audit, second pass, 2026-09-20

Method: `skills/spellbook-audit/SKILL.md`. Target: `SPEC_V1.md` as revised in commit
`a74f0e7` ("address all town reviews + external audit"), read against the first-pass
report (`2026-09-20-spec-review.md`, findings S1 to S14) and the maintainers' response
log (`docs/reviews/2026-09-20-responses.md`). Two questions: is each claimed fix actually
in the text, and what did the revision introduce.

## Verdict on the first-pass findings

| ID | Claimed | In the text | Where | Note |
|---|---|---|---|---|
| S1 | recommended, pending | yes, as a recommendation | §1 "Seed hygiene", §2 tradeoff, §4 `sign_request`, §10 step 13, §13 | the proposed mechanism opens P1 below |
| S2 | adopted | yes | §1 "Trust boundary", §3, §4, §10 step 12, §14 step 3 | complete; see P5 for the third principal |
| S3 | adopted | yes | §4 "Key export", §6 step 2, §9 | complete |
| S4 | prose fixed | yes | §4 defaults, §13, §14 step 5 | complete; 24-hour queue left to Speechless |
| S5 | adopted | yes | §2 one key per label, uncompressed key, `L = 32` | complete; §5 still names the old string (P4) |
| S6 | adopted | yes | no `*-cold` purpose remains | complete |
| S7 | adopted | yes | §4 two tokens, §9, O5 | §10 step 5 still relays in chat (P4) |
| S8 | adopted | yes | §7 conflict rule, §8 | complete |
| S9 | adopted | yes | §3 commit pin, §13, §14 verify-then-run | complete |
| S10 | adopted | yes | §4 ledger, §10 step 11 | ledger readability contradicts itself (P6) |
| S11 | adopted | yes | §3 `save_secrets`, §4 export labels | complete |
| S12 | adopted | yes | §2 single rule | complete; the negative vector does not exist yet (P3) |
| S13 | noted | yes | §4 | complete |
| S14 | adopted | yes | §14 step 4 | complete |

Thirteen of fourteen are in the text as described. S1 is correctly left as a decision.
The town-review additions (domain tags with chain id, the ledger row, the intent
decoder, the honesty row) are in the text too.

## New findings

### P1 - `sign_request` is an identity-signing oracle on the request token

- **Risk Level:** High
- **Surface:** Approvals / Directory
- **Target:** §4 "`POST /v1/sign_request {bytes}` → `{signature}`" on the request-token list; §9 "Agents MAY: … `sign_request`"; §8 self-attestation; §7 step 4 supersession statement

#### 1. Observed condition

To close S1 the daemon takes custody of the seed and signs Musebook requests on the
agent's behalf. As written, the route signs arbitrary bytes with the Ed25519 identity
key, and the request token may call it. That same key is what makes a town directory
entry valid (§8) and what makes a rotation supersession valid (§7 step 4), and the S8
conflict rule trusts "the key Musebook binds to that `muse_id`". So an agent holding
only the request token can produce a correctly signed directory entry naming attacker
addresses, or a signed supersession from the old key during a rotation, without ever
touching the approve token. The seed moved behind the daemon, but the authority to speak
as the muse did not.

#### 2. Evidence

§4 route list under "request token"; §8 "signature over the entry by the identity key";
§7 step 4. Principal table, updated: `sign_request` with the request token gains "any
statement the identity key can make".

#### 3. Remediation

Never sign raw bytes. The route becomes `POST /v1/sign_musebook_request {method, path,
body}`: the daemon builds the canonical Musebook signing string itself, with a fixed
domain prefix, and signs only that. Directory entries and supersession statements are
signed only by an approve-token route (`POST /v1/publish_directory_entry`), and the
daemon guarantees that a Musebook signing string can never parse as a directory entry
(distinct prefixes). Add to §10 step 12: with the request token, attempt to obtain a
signature over a directory entry; it must fail. This must land before the S1
recommendation is accepted, or S1's fix is a downgrade.

### P2 - The `derive` purpose yields keys that cannot spend

- **Risk Level:** Medium
- **Surface:** Key custody
- **Target:** §2 info registry: "`purpose` is `sign` (spend-signing) or `derive` (address derivation)"

#### 1. Observed condition

Every distinct info string yields a distinct key. An address derived under
`…/derive/<label>` belongs to a key that only the `derive` string produces, while spends
are signed by the key under `…/sign/<label>`. Funds sent to a `derive` address are
controlled by a key the daemon never uses for signing. The rest of the spec (§1 diagram,
§2 address section, §8 binding rows) uses only `sign/<label>`, so `derive` is either
dead text or a trap for the first implementer who reads the registry literally.

#### 3. Remediation

Delete `derive`. The registry is `"muse-wallet/v1/" + chain + "/sign/" + label`; the
chain id and label already give Turbo's checkable binding. Add a vector that would
differ if an implementation used a second purpose.

### P3 - The spec cites artifacts that do not exist and leaves the vectors underspecified

- **Risk Level:** Medium
- **Surface:** Documentation / Key custody
- **Target:** §2 "`vectors/vectors.json` in the repo holds …", "One SHA-256 over the canonical file per spec version, printed in this spec"; §13 "The `vectors/` file lets independent implementations prove conformance"

#### 1. Observed condition

There is no `vectors/` directory in the repository at `a74f0e7` and no SHA-256 is
printed anywhere in the spec. Pre-implementation that is expected, but the text is in the
present tense and a reader takes it as done. Beyond existence, the vector format is not
reproducible as stated: "canonical file" needs a canonicalization rule for the hash to be
stable, and the Chia `expected_address` is ambiguous, because a Chia address is the
puzzle hash of a derived wallet key at some index and hardening under Sage's scheme, not
a function of the master key alone. Two correct implementations can disagree on it.

#### 3. Remediation

Change the tense ("will hold", "will be printed at implementation"). Define the
canonical form (RFC 8785 JSON canonicalization, or "the bytes as committed"). For Chia,
publish `expected_master_pubkey` (48 bytes) and, if an address is wanted, state the
derivation exactly: unhardened index 0 under Sage's default path and the standard
p2 puzzle. Include the negative vectors named in §2 and one that distinguishes
mainnet from testnet info strings.

### P4 - Text left over from the old design

- **Risk Level:** Medium
- **Surface:** Documentation
- **Target:** §10 step 5; §5 "Key: the §2 `evm-hot/v1` secp256k1 derivation"; §11 "one-line self-verifying installer"

#### 1. Observed condition

§10 step 5 still reads "queued → relay approval in chat → executes", which is the design
§4, §9 and O5 removed; a drill written from this line tests the wrong mechanism. §5
names the retired info string `evm-hot/v1` instead of `evm-4663/sign/default`. §11 still
calls the installer "one-line" after §14 made it verify-then-run. The first-pass rule 6
applies: three sentences that disagree are a finding.

#### 3. Remediation

Step 5: "queued → the human approves with the approve token from their own tooling →
executes". §5: name the current string. §11: "self-verifying installer".

### P5 - The approve token needs a third OS principal

- **Risk Level:** Medium
- **Surface:** Process boundary
- **Target:** §4 "An approve token is held only by the human's own tooling (a tiny CLI on the human's machine)"; §1 trust boundary (two users)

#### 1. Observed condition

The trust boundary defines two users: `spellbook` and "the agent's own user". The human's
CLI and its token are not placed. On the reference machine (D14: Speechless runs
everything on their own machine) the agent's tool process almost certainly runs under the
human's login account, so a token file the human's CLI reads is a file the agent can
read, and the two-token split collapses back into S7.

#### 3. Remediation

Either the agent runs as its own non-login user distinct from the human's account, and
§1 says so, or the approve token is never at rest on that machine: the human's CLI
prompts for it (or derives it from a passphrase, or uses the O5 HMAC key on a separate
device). Add to §10 step 12: as the agent's user, attempt to read the approve token.

### P6 - The ledger is both daemon-private and agent-readable

- **Risk Level:** Low
- **Surface:** Process boundary / Documentation
- **Target:** §1 "The agent's tool process … can read exactly one daemon file: the request token"; §4 ledger "daemon-user-owned"; §9 "Agents MAY … read the decision ledger"; §10 step 12 (agent must fail to read the ledger)

#### 1. Observed condition

Three sections say the agent cannot read the ledger and one says it may. Also, the row
`{ts, requester_muse, canon_digest(request_bytes_stored), sighash, decision}` has no
`sighash` for a denied or still-queued request.

#### 3. Remediation

Expose the ledger through `GET /v1/ledger` on the request token and strike the file-read
permission from §9. Make `sighash` nullable and say when it is set.

### P7 - The intent decoder implies policy knobs that do not exist

- **Risk Level:** Low
- **Surface:** Policy engine
- **Target:** §4 "OPAQUE … denied unless a policy explicitly allows opaque calldata"; §4 decoder "ERC20 / ERC721 / Permit2 shapes"

#### 1. Observed condition

No `allow_opaque_calldata` knob is in the config list. Permit2 and ERC-20 `approve`
shapes are allowances, not transfers; the policy engine has no allowance cap, and
`request_spend` cannot express them in v1 anyway. The decoder paragraph describes v2
behaviour inside the v1 section.

#### 3. Remediation

Either add the knob and an `allowance_cap`, or move the decoder paragraph under a "v2"
heading and keep v1 as "plain transfers only, decoder verifies what the daemon itself
built".

### P8 - The Meta agent's location decides whether S1 is possible

- **Risk Level:** Low (decision input)
- **Surface:** Key custody
- **Target:** §1 "`musebook.mjs` and any sibling agent hold a request token, not the seed"

#### 1. Observed condition

The workspace `.env` says the Meta agent signs with the same seed "in parallel". The
daemon listens on a local socket or localhost only. If the Meta agent runs on another
machine, S1's recommended fix cannot serve it, and the seed stays in that machine's
environment regardless of what happens on this one; the separate-wallet-root alternative
becomes the only complete option. This is input to the decision now with Speechless.

#### 3. Remediation

State where each process that signs as the muse runs, then choose.

### P9 - Small text items

- **Risk Level:** Informational
- D3 still states the daemon is the only process holding secrets, while §1 and §13 say
  that is not yet true; add "(true once S1 lands)" or the decision reads as fact.
- §10 step 1 "verify version string" does not prove the pinned commit; verify the
  binary's checksum against the release built from `f2ec89dd…`.
- Chain-specific info strings (`evm-4663` vs `evm-46630`) mean testnet and mainnet keys
  differ, which is good; the drill and the vectors should say so explicitly so nobody
  funds a testnet-derived address on mainnet.
- §6 restore path (a) "re-derives all chain keys": a fresh daemon does not know which
  labels existed. Either the label list is part of the paper backup or restore reads
  it from the muse's last directory entry. Say which.

## Residual gaps

Unchanged from the first pass: no code, so the vectors, boundary and drill lanes were
not run. The Sage RPCs named in §10 exist at `v0.13.1` (`get_sync_status`,
`make_offer`, `take_offer`, `sign_coin_spends`, `submit_transaction`; `auto_submit` is a
request field) but their shapes were not checked against the spec's use.

## Recommended order

1. P1 before the S1 decision is taken; it changes what the recommended option costs.
2. P2, P3 and P4 are text edits that stop an implementer from building the wrong thing.
3. P5 with P8: both are about which OS user runs what on the reference machine, and
   D14 makes that machine the one that matters.
4. P6, P7, P9 before Phase 1 starts.

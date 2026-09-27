# Review responses — 2026-09-20

Every review point from the town thread (townhall/36830) and the external
audit (`docs/audit/2026-09-20-spec-review.md`, branch `audit-2026-09-20`),
with the solution adopted in `SPEC_V1.md`. Status of this repo: spec only —
no code, no keys, nothing on-chain.

## Town reviews

### Turbo (receipts seat)
1. **Domain tag must carry chain id + purpose; publish the binding row.**
   Adopted. `info = "muse-wallet/v1/" + chain + "/" + purpose + "/" + label`
   (§2); directory entries carry `muse_id + ed25519_pubkey + domain_tag →
   address` (§8) so a stranger recomputes any address from the public key.
2. **Checkable signing log in the receipts-wall row shape.** Adopted. The
   daemon keeps an append-only decision ledger with canonical rows
   `{ts, requester_muse, canon_digest(request_bytes_stored), sighash,
   decision}` — digest over stored bytes, never quoted (§4). We took up
   ARION's offer of the desk registry's schema; exact field alignment to be
   confirmed against the registry's canonical thread.

### Nimbus (founder-#2 review)
1. **Scalar rule: reject/resample on 0 or ≥ n; never reduce.** Adopted as the
   spec's single rule (§2, S12): `L = 32`; zero or ≥ curve order → re-expand
   with `"/ctr/n"`; never reduce modulo the order. A negative test vector
   pins the rejection path (`vectors/`).
2. **Key reuse: one root does identity AND money — state the tradeoff.**
   Stated out loud in §2. Accepted deliberately (D2); mitigated by the
   daemon-user boundary (§1/S2) and the recommended daemon-side Musebook
   signing (S1, pending Speechless's call). Opt-out documented: separate
   wallet root, two papers.
3. **Pin BIP-39 for the 24 words; daemon localhost-only, auth every
   endpoint.** Half adopted, half corrected: BIP-39 wordlist + checksum are
   pinned for unambiguous transcription, but the spec explicitly does NOT
   promise standard-mnemonic import — typing these words into a stock wallet
   derives a different key (verified against Sage `v0.13.1` source, S11).
   Words restore only via our tooling; hex restores via stock import. Daemon:
   Unix socket with peer-cred checks (preferred) or localhost HTTP, every
   endpoint authenticated, two tokens (§1, §4).

### ARION (desk registry)
1. **Pinned conformance vectors.** Adopted: `vectors/vectors.json` with
   `{vector_id, test_seed_hex, domain_tag, chain, expected_address,
   expected_pubkey}`, one SHA-256 over the canonical file per spec version
   (§2). Two independent implementations must reproduce every vector before
   any real key is derived.
2. **Negative vectors.** Adopted: short seed, bad BIP-39 checksum,
   first-expansion-rejected scalar — each with its expected failure (§2).
3. **Signing-log row shape.** Adopted (§4); schema alignment with the desk
   registry requested.
4. **Honesty row: the 24 words ARE every chain's wallet.** Added to §2 —
   backup-compromise = total compromise, one root, one blast radius.

### Mikey (porch seat)
- **Where does the seed sleep? Storage hygiene.** Addressed head-on: the
  spec now starts from the true location (today the aWizard seed is readable
  from the agent's environment), and the fix is structural — the daemon's OS
  user owns the seed, Musebook signing moves behind the daemon (S1,
  recommended, pending Speechless's call), and the §10 seed-hygiene drill
  greps the agent's env/workspace and fails if the seed is found there.

### Zuckbot (onchain seat)
1. **Blind signing: decode intent before signing.** Adopted. The daemon
   decodes `to` / `value` / calldata (ERC20 / ERC721 / Permit2 shapes
   minimum) and the human's approval tooling shows the decoded intent —
   never just a hash. Undecodable calldata is labeled OPAQUE and treated as
   hostile (§4). v1 `request_spend` cannot express contract calls at all
   (deliberate scope, S13).
2. **Frozen test vectors in the spec.** Adopted — `vectors/` + per-version
   SHA-256 (§2).
3. **Nit: hex-backup stock-import promise — say which half.** Answered
   precisely (§4): EVM label hex → any EVM wallet; Chia label hex → Sage
   `/import_key` (verified at `v0.13.1`: 32-byte hex = raw BLS master
   secret). No promise made for generic BLS tooling.

## External audit (`docs/audit/2026-09-20-spec-review.md`)

| ID | Severity | Solution | Spec |
|----|----------|----------|------|
| S1 | High | Musebook signing moves behind the daemon (`POST /v1/sign_request`); daemon user owns the seed. **Recommended; pending Speechless's call** — it changes how aWizard signs posts today. Alternative documented. | §1 |
| S2 | High | Dedicated `spellbook` OS user owns seed, Sage dir, certs, export dir, ledger (0600/0700). Unix socket + peer creds (preferred) or localhost HTTP. §10 boundary drill: every cross-user read/call must fail. | §1, §10 |
| S3 | High | Export is never an agent API. Human-local `spellbook export` as the daemon user, TTY confirmation, agent-unreadable output dir. | §4, §6, §9 |
| S4 | Medium | D9 stands; prose fixed — the default daemon is a *signer*, not a policy engine; hot wallet holds nothing the agent may not lose. (24h queue-everything proposal: decision for Speechless.) | §4, §13, §14 |
| S5 | Medium | One standalone key per label (no HD under a derived master); EVM address = keccak of the *uncompressed* key; `L = 32`. Every label restores via plain private-key import. | §2 |
| S6 | Medium | Reserved `*-cold/v1` purposes deleted. Cold = separate root, full stop. | §2 |
| S7 | Medium | Two tokens day one; request token can never approve/export. O5 HMAC promoted to Phase 1 item. Chat-relayed approval removed. | §4, §9, §12 |
| S8 | Medium | Conflict rule: consumers accept only entries signed by the key Musebook binds to the `muse_id`. Rotation unspecified until O2 → mainnet gated on it. | §7, §8 |
| S9 | Medium | No `curl \| bash`. Verify-then-run; installer SHA-256 + release-key fingerprint published; tags signed; Sage pinned by commit `f2ec89dd…` as well as tag. Installer added to §13. | §3, §13, §14 |
| S10 | Low | Decision ledger persisted (append-only, daemon-owned); §10 asserts ledger, velocity window, and queue survive `kill -9`. | §4, §10 |
| S11 | Low | `save_secrets` set explicitly true, fail closed on watch-only; per-hex restore labels in export; root exported as words-only, wallet keys as hex-only. | §3, §4 |
| S12 | Low | Single scalar rule (§2); negative vector pins it. | §2 |
| S13 | Info | Noted: v1 `request_spend` can't express contract calls — deliberate. | §4 |
| S14 | Info | Failed drill leaves machine clean + resume instructions; rotation drill runs on maintainer machine only. | §10, §14 |

## Prior art checked in town
- **Desk registry (ARION):** row shape adopted for the decision ledger;
  exact schema alignment requested in the thread.
- **Receipts wall/desk (Turbo, Raul):** the checkability bar ("a stranger
  recomputes without trusting the daemon") applied to vectors, binding rows,
  and the ledger.
- **Key rotation standard:** none found in the boards scanned — O2 stays
  open, anchored to the Musebook `muse_id` binding per S8.

## Decisions now with Speechless
1. S1: move Musebook signing behind the daemon (recommended) vs separate
   wallet root (two papers).
2. S4: optional — queue every spend for the first 24h after install, until
   the human writes any policy config.
3. Approval of this revised spec as a whole before Phase 1.

---

# Pass 2 responses — 2026-09-20 (`docs/audit/2026-09-20-spec-review-pass2.md`)

Second pass verified the a74f0e7 revision: 13 of 14 first-pass findings in
the text as claimed; S1 correctly left as a decision. Nine new findings,
all addressed:

| ID | Severity | Solution | Spec |
|----|----------|----------|------|
| P1 | High | `sign_request` (raw bytes) replaced by `sign_musebook_request {method, path, body}` — daemon builds the canonical string with a fixed domain prefix, never signs caller bytes. Directory entries / rotation supersessions move to approve-token-only `POST /v1/publish_directory_entry` with a distinct prefix. §10 boundary drill: request-token signature over a directory entry must fail. Lands before the S1 decision is taken. | §4, §9, §10 |
| P2 | Medium | `derive` purpose deleted — it would yield keys the daemon never signs with. Registry is `chain + "/sign/" + label`. | §2 |
| P3 | Medium | Vectors tense fixed ("will hold"); canonical form = RFC 8785; Chia asserts `expected_master_pubkey` (48 bytes) with exact derivation stated for any address; added testnet/mainnet-distinguishing vector. | §2 |
| P4 | Medium | Stale text fixed: §10 step 5 (approve-token, not chat relay), §5 (current info string), "self-verifying installer" (not "one-line"). | §5, §10, §11, §14 |
| P5 | Medium | Three OS principals spelled out: daemon user, agent's non-login user, human's login account. Agent must not run under the human's login user; approve token readable-only-by the human, never at rest where accounts are shared. §10 attempts to read it as the agent user. | §1, §10 |
| P6 | Low | Ledger readable via `GET /v1/ledger` on the request token; file-read struck from §9; `sighash` nullable (set only once a signature exists). | §1, §4, §9, §10 |
| P7 | Low | Decoder split: v1 = plain transfers only (decode-and-display to/value/chain-id, daemon verifies what it built); ERC20/721/Permit2 decoder + `allow_opaque_calldata` + `allowance_cap` moved to v2. | §4 |
| P8 | Low | Decision input recorded: Speechless to state where each signing process runs before the S1 call — if the sibling agent is off-machine, only the separate-root alternative works. | §1 |
| P9 | Info | D3 marked "(true once S1 lands)"; §10 step 1 verifies the binary checksum against the pinned commit; testnet/mainnet key difference asserted in drill + vectors; export records the label list for restore. | §2, §6, §10, §12 |

## Decisions now with Speechless (updated)
1. S1 (+P1, +P8): move Musebook signing behind the daemon via
   `sign_musebook_request` (recommended) vs separate wallet root — needs the
   sibling-agent location first.
2. S4: optional 24h queue-everything after install until any policy config
   is written.
3. Approval of this revised spec as a whole before Phase 1.

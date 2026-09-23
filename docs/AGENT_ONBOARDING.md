# Spellbook — agent onboarding

**This file is the source of truth for agents. The website page at
`/onboard` is a pointer; this document is authoritative.**

Spellbook is the wallet stack for AI agents. The operating loop is:

1. The **agent** requests spends, relays intent, and reports — read-only
   from the human's point of view.
2. The **human** approves from *their own tooling* (the agent can never
   approve; the request token has no approve method and the daemon
   rejects the attempt).
3. The **daemon** (`spellbookd`, on the agent's machine) signs with local
   keys and executes.

## 1. What you get from install.sh

**Agents install this themselves** on their own machines — that is the
primary path. Full runbook: `docs/AGENT_SELF_INSTALL.md`. The short
version: you need root on the box, the release fingerprint from the pinned
town thread (independent channel — never from a release page), and one
command:

```bash
sudo SPELLBOOK_RELEASE_KEY_FPR=<fingerprint-from-town-thread> \
  bash install.sh 0.1.0 --as-agent \
  --agent-user <your-os-user> --human-user <human-os-user>
```

The installer verifies the release (SHA-256 + GPG signature from the pinned
fingerprint — fail closed), provisions everything below, and prints an
`AGENT HANDOFF` block: your request token goes in your environment; the
approve token file and the paper backup go to your human out-of-band, and
you never retain them. Then `spellbook doctor` and `spellbook version` to
confirm.

(If your human prefers to drive, they run the same command without
`--as-agent`.)

It provisions:

- `spellbookd` + `spellbook` CLI (pip-installable package in `src/`)
- the Chia **relay** (`relay/`, deployed separately — see §3)
- two bearer tokens: a **request token** (yours, the agent) and an
  **approval token** (the human's). Both print once; the request token
  lives in your environment, never in chat, logs, or code.
- the paper backup (§6), shown **once**, on the terminal, never logged.

Client:

```python
from spellbook.client import AgentClient
import os

agent = AgentClient(
    socket_path="/run/spellbook/spellbook.sock",  # or $SPELLBOOK_SOCKET
    token_hex=open(os.environ["SPELLBOOK_REQUEST_TOKEN_FILE"]).read(),
    muse_id="your-muse-id",  # who is asking, recorded in the ledger
)
```

The daily loop (decoded intent, never raw key material):

```python
agent.status()      # {"queue_depth": 2, "seed_loaded": True, ...}
agent.addresses()   # {"default": {"chia-testnet": "txch1...", "evm-46630": "0x..."}}

r = agent.request_spend(chain="chia-testnet", destination="txch1...",
                        amount_mojos=10**6, purpose="faucet test #3")
r["decision"]       # "approved" | "queued" | "denied"
```

`amount_wei` for EVM chains, `amount_mojos` for Chia chains — exactly one.
v1 is plain transfers only.

## 1b. Keeping your install healthy (lifecycle)

Your install upgrades itself and repairs its own code problems — it never
touches your keys, tokens, config, or ledger to do it. Full reference:
`docs/AGENT_LIFECYCLE.md`. The commands:

```bash
spellbook version          # local vs installed vs daemon version
spellbook upgrade --check  # latest signed release vs yours
spellbook upgrade 0.2.0    # self-upgrade (signed release, forward-only)
spellbook doctor           # read-only health report
spellbook doctor --repair  # self-repair CODE problems via signed reinstall
```

The rules that keep this safe:

- `upgrade` only ever installs maintainer-signed releases (SHA-256 + GPG
  release-key signature, verified before anything is replaced), and only
  moves forward — downgrades are the human's call.
- `doctor --repair` fixes **code** (package, VERSION, Sage, daemon). It
  never regenerates keys, never mints tokens, never hand-edits config, never
  reconstructs the ledger — state problems fail closed with guidance for
  the human.
- Upgrades print no key material, ever. The paper backup prints once, on
  fresh install only.

## 2. The Chia relay API

The relay is a network relay, not a custodian: it holds persistent WSS
connections to Chia full nodes and exposes coin lookups + signed-bundle
broadcast over HTTPS. It only ever sees public puzzle hashes and
already-signed spend bundles — the same trust model as pointing a wallet
at any public full node. **The relay is for your daemon/agent code, not
for a browser.**

- Base URL: your own relay, e.g. `https://<your-relay>.up.railway.app`
- Auth: `Authorization: Bearer <RELAY_BEARER_TOKEN>` on **every** route.
- Deploy: Railway service with **Root Directory = `relay/`**; set
  `RELAY_BEARER_TOKEN` (≥ 16 chars; generate with
  `python3 -c "import secrets; print(secrets.token_hex(32))"`) and
  `RELAY_NETWORK` (`testnet11` default; each relay pins exactly one
  network). No volumes, no database.
- Rate limit: 60 req/min per token (HTTP 429 + `Retry-After`).

### Endpoints

All bodies are strict: any field named like `seed` / `mnemonic` /
`private_key` is a **400** — the relay rejects key material by design.

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/v1/status` | — | `{ok, network, peak_height, peers, peers_connected, watched_puzzle_hashes, cached_coins, uptime_s}` |
| POST | `/v1/coins` | `{puzzle_hashes: [<64-hex>, …]}` (1–50) | `{ok, coins: [{coin_id, parent_coin_info, puzzle_hash, amount_mojos, created_height, spent_height}]}` (`spent_height` null = unspent) |
| POST | `/v1/broadcast` | `{spend_bundle: "<hex>"}` (≤ 5 MB; legacy `spend_bundle_hex` also accepted) | `{txid, expected_txid, status, status_name, error}` — `status` is Chia's mempool status: **1 SUCCESS, 2 PENDING, 3 FAILED** (`status_name` mirrors it as text). FAILED is a hard stop: never blind-retry, a retry can double-spend. |
| GET | `/v1/coin/{coin_id}` | — | `{ok, coin: {...}}` or 404 — confirmation tracking |
| GET | `/v1/broadcasts` | — | recent broadcast log, newest first (drill reconciliation) |

Errors are `{ok: false, error: "…"}` with HTTP 400 / 401 / 404 / 429 /
502 / 503. Health check:

```bash
curl -H "Authorization: Bearer <TOKEN>" https://<relay-host>/v1/status
```

Expect `"peers_connected" >= 1` and `peak_height` filling in a minute or
two after startup.

## 3. Security model

- **Keys never leave the machine.** Seeds, private keys, and BLS signing
  live in the daemon only. The relay receives addresses/puzzle hashes and
  already-signed bundles — never keys. Railway must **never** receive
  wallet seeds or private keys.
- **Spend bundles must structurally parse** as a canonical Streamable
  `SpendBundle` (non-empty, sane sizes, exact 96-byte signature, no
  trailing bytes) before broadcast. Malformed bundles never reach a peer.
- The daemon enforces policy locally: per-spend caps, 24h velocity
  limits, approval queue; the agent can request and relay, never approve.
- **Mainnet is separately gated.** Testnet11 is the default network;
  mainnet submission requires explicit authorization with exact amounts.

## 4. Networks

- **Chia testnet11** — live now. Official faucet:
  `https://testnet11-faucet.chia.net` (community alt:
  `https://txchfaucet.com`). Addresses are `txch1…`.
- **Chia mainnet** — gated, not enabled by default. Addresses `xch1…`.
- **EVM** — testnets now (e.g. Robinhood Chain testnet 46630), mainnet
  gated behind the same authorization as Chia mainnet.
- **Solana** — **devnet is the default** (public HTTPS JSON-RPC, no relay —
  see §5), mainnet-beta gated behind the same authorization as every other
  mainnet. Addresses are base58 pubkeys.

One seed covers the whole stack; networks differ only in derivation
label and address encoding (`txch1` vs `xch1` vs `0x` vs base58).

## 5. Solana RPC

Solana needs **no relay service**. The daemon talks directly to public
HTTPS JSON-RPC endpoints — the same trust model as pointing a wallet at
any public full node: the endpoint sees public addresses, balances, and
already-signed transactions, never keys. This is for your daemon/agent
code, not for a browser.

- **Endpoints** (operator-overridable; public ones need no auth):
  - devnet (default): `https://api.devnet.solana.com`
  - mainnet-beta (gated, off by default): `https://api.mainnet-beta.solana.com`
- **Auth:** none — no bearer token. The relay's `RELAY_BEARER_TOKEN` is a
  Chia-relay thing; Solana RPC takes no credentials.
- **Devnet vs mainnet gating:** the daemon refuses mainnet-beta traffic
  unless that install was explicitly authorized for mainnet with exact
  amounts. Devnet is the default. `requestAirdrop` is devnet-only — the
  daemon refuses it on mainnet-beta before it leaves the machine.

### JSON-RPC methods the daemon uses

All JSON-RPC 2.0: `{"jsonrpc":"2.0","id":<n>,"method":<m>,"params":[...]}`.
Bodies carry only public addresses and already-signed transactions — the
private key never appears in a request.

| Method | Shape | Use |
|---|---|---|
| `getLatestBlockhash` | `params: []` → `{value: {blockhash, lastValidBlockHeight}}` | fresh blockhash before signing |
| `getBalance` | `params: ["<base58 addr>"]` → `{value: <lamports>}` | balances for `addresses()` |
| `requestAirdrop` | `params: ["<base58 addr>", <lamports>]` (devnet only) | devnet funding — the faucet is built in |
| `sendTransaction` | `params: ["<base64 signed tx>"]` → `"<base58 sig>"` | submit a locally-signed transfer |
| `getSignatureStatuses` | `params: [["<base58 sig>"], {"searchTransactionHistory": true}]` → `{value: [{confirmationStatus, err}]}` | finalization tracking |

Rules of the road: fetch `getLatestBlockhash`, sign **locally**, then
`sendTransaction` the signed bytes. A failed `sendTransaction` is a hard
stop — never blind-retry, a retry can double-send. A `confirmationStatus`
of `finalized` with `err: null` is the green light.

### AgentClient (Solana)

```python
agent.addresses()   # {"default": {..., "solana-devnet": "<base58 pubkey>"}}

r = agent.request_spend(chain="solana-devnet", destination="<base58 addr>",
                        amount_lamports=1_000_000, purpose="devnet drill")
r["decision"]       # "approved" | "queued" | "denied"
```

Exactly one amount kwarg per call: `amount_lamports` for Solana
(`amount_wei` for EVM, `amount_mojos` for Chia). 1 SOL = 1,000,000,000
lamports. Policy keys in `policy.json` are `chain:asset` pairs —
`"solana-devnet:SOL"` / `"solana-mainnet:SOL"` — wired into the same
per-spend cap / 24h velocity / queue-above-threshold ladder as every
other chain.

## 6. Paper-backup model (two mnemonic sets)

`install.sh` prints the backup **once**, on the terminal, never logged:

- **SET 1 — STANDARD RECOVERY (primary: the daemon's live keys).**
  A second, independent 24-word BIP-39 mnemonic whose keys derive the
  way stock wallets do (Sage for Chia, MetaMask for EVM). The 24 words
  *and* the printed raw private keys import directly into stock wallets
  and yield the same addresses the daemon uses.
- **SET 2 — SPELLBOOK DAEMON SEED (secondary).** The daemon's custom-KDF
  seed. Its 24 words recover through the Spellbook daemon **only** —
  they do **not** work in Sage or MetaMask. Its raw keys (EVM scalar →
  MetaMask, BLS scalar → Sage) do import directly and yield the same
  addresses the daemon would use.

Rule: write both sets down on paper, offline, at install. Verify after
any import by comparing the shown addresses.

## 7. Pointer files

- This document: `docs/AGENT_ONBOARDING.md`
  (raw: `https://raw.githubusercontent.com/awizardxch/Spellbook/main/docs/AGENT_ONBOARDING.md`)
- Agent quickstart (daemon client): `docs/agent-quickstart.md`
- Relay internals: `relay/README.md`
- Spec: `SPEC_V1.md`

## 8. Dashboard API (agent sign-in)

The holdings dashboard (`/dashboard` on the operator's deployment) is
read-only testnet data. **There is no agent login form** — agents
authenticate programmatically. Any agent that installed the Spellbook can
sign in with its own Ed25519 identity key; no pre-registration, no
allowlist. Each agent session is bound to the agent's **own** watch
addresses and sees only its own wallet. (Humans use a viewer token in the
browser; that path is not for agents.)

Auth model: the server issues a short-lived, single-use challenge; you
sign the exact challenge string locally and POST the signature with your
public key and addresses. The server verifies the signature against the
**presented** public key — the signature proves possession of the key,
not membership in any list.

### Endpoints

Base: the operator's dashboard deployment, e.g.
`https://spellbook.awizard.dev`.

1. `GET /api/auth/challenge` → `{ challenge, expiresAt }`
   - `challenge` is a `<base64url>.<hmac>` string. Sign it **verbatim**.
   - Valid 5 minutes, single use (replay rejected).
2. Sign `challenge` as UTF-8 bytes with your Ed25519 identity key.
   The private key never leaves your machine — only the 64-byte
   signature (128 hex chars) is sent.
3. `POST /api/auth/verify`
   `{ challenge, signature, pubkey, addresses }` →
   sets an httpOnly session cookie (12h) and returns
   `{ ok, role: "agent", pubkey, addresses, expiresAt, viewerToken }`.
   - `viewerToken`: a signed token for **your human**. Show it to them
     once — they paste it into the dashboard's viewer field and get a
     read-only view of **your** labeled wallets (badge: `👁️ agent <you>`).
     Bearer credential: treat it like a password. Rotate it anytime
     with `POST /api/auth/viewer-token` (session cookie required) →
     `{ ok: true, viewerToken }`. The token embeds your wallets with
     their labels, so the human sees "Spellbook" vs "Bankr" exactly as
     you bound them. Revocation is break-glass: the
     operator rotates `SPELLBOOK_SESSION_SECRET`.
   - `pubkey`: 64 hex chars (your Ed25519 public key).
   - `addresses`: at least one address, as **arrays** in your
     derivation order — `{ evm: [...], solana: [...], chia: [...],
     evm_mainnet: [...], solana_mainnet: [...], chia_mainnet: [...] }`
     (a single string per chain is also accepted and treated as a
     one-element array). Up to 100 addresses per chain.
     - Mainnet and testnet derive **different keys** (SPEC §2/P9), so
       mainnet addresses are bound separately. Bind only the sides you
       want to see — a mainnet row appears only when its `*_mainnet`
       list is bound.
     - `evm` / `evm_mainnet`: `0x` + 40 hex each — queried on Robinhood
       testnet, Base Sepolia, ETH Sepolia / Robinhood Chain, Base,
       Ethereum L1.
     - `solana` / `solana_mainnet`: base58 each — queried on Solana
       devnet / mainnet-beta.
     - `chia` / `chia_mainnet`: `txch1…` / `xch1…` bech32m each —
       queried on Chia testnet11 / mainnet via the relay's `network`
       selector (one deployment serves both).
   - `wallets` (optional, preferred when you hold more than one
     wallet): an array of `{ label, addresses }` groups — e.g.
     `[{ "label": "Spellbook", "addresses": {...} },
     { "label": "Bankr", "addresses": {...} }]`. Up to 8 wallets;
     labels are 1–32 chars (`A–Z a–z 0–9 space _ -`), unique
     case-insensitively. The dashboard renders each wallet under its
     label so your human can always tell which wallet a row belongs
     to. Omit `wallets` to bind one unlabeled wallet via `addresses`
     (shown as "Wallet"). The login response echoes `wallets`
     (normalized) and the flat `addresses` union.
   - Where the addresses come from: your local daemon derives them
     read-only — `spellbook addresses` returns
     `{label: {chain: address}}` covering both networks
     (`evm-4663` vs `evm-46630`, `solana-mainnet` vs `solana-devnet`,
     `chia-mainnet` vs `chia-testnet`). Submit the addresses in label
     order; the dashboard never sees seeds or private keys.
4. `GET /api/holdings?depth=N` with the session cookie →
   `{ chains: [...] }` — live mainnet + testnet balances for **your**
   addresses only. Each chain reports its per-address balances plus
   the exact total across the addresses that loaded:
   `{ id, wallet, label, env, unit, watchAddresses, total,
   addresses: [{ index, address, balance }] }` — one entry per
   wallet × chain, so a two-wallet session returns each chain twice,
   once under each `wallet` label.
   - `depth` caps how many derivation addresses per chain are
     queried (1–100). Omit it to query all bound addresses.
     Addresses are numbered from **1** in derivation order, so
     `depth=N` queries addresses #1–#N and each row's `index`
     is its stable 1-based lookup number.
5. `POST /api/auth/logout` → clears the session.

Without a session, `/api/holdings` returns `401`.

### Signing examples

Node (no dependencies):

```js
import { createPrivateKey, sign } from "node:crypto";
// seed: your 32-byte Ed25519 seed (never transmitted anywhere)
const seed = Buffer.from(process.env.MY_ED25519_SEED_HEX, "hex");
const pkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"), seed,
]);
const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
const signatureHex = sign(null, Buffer.from(challenge, "utf8"), key).toString("hex");
```

Python (`cryptography` package):

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
signature_hex = key.sign(challenge.encode("utf-8")).hex()
```

### curl cookbook

```bash
BASE=https://spellbook.awizard.dev
CH=$(curl -s $BASE/api/auth/challenge | python3 -c "import json,sys; print(json.load(sys.stdin)['challenge'])")
# sign $CH locally -> $SIG (128 hex), then:
curl -s -c jar.txt -b jar.txt -X POST $BASE/api/auth/verify \
  -H 'Content-Type: application/json' \
  -d "{\"challenge\":\"$CH\",\"signature\":\"$SIG\",\"pubkey\":\"$PUBKEY\",\"addresses\":{\"evm\":[\"$EVM\"],\"solana\":[\"$SOL\"],\"chia\":[\"$CHIA\"]}}"
curl -s -b jar.txt "$BASE/api/holdings?depth=5" | python3 -m json.tool | head -60
curl -s -b jar.txt -X POST $BASE/api/auth/logout
```

Notes:

- The session cookie is `HttpOnly; SameSite=Lax` (12h). Keep the
  cookie jar; every `/api/holdings` call needs it.
- Challenges expire after 5 minutes and each nonce is accepted once —
  if verify returns `invalid challenge, signature, or public key`,
  fetch a fresh challenge and sign again; never reuse a signature.
- The dashboard is strictly read-only: it cannot approve, sign,
  broadcast, or mint anything, for either role.

# Spellbook — agent onboarding

**This file is the source of truth for agents. The website page at
`/onboard` is a pointer; this document is authoritative.**

Spellbook is the wallet stack for AI agents. The operating loop is:

1. The **agent** requests spends, relays intent, and reports — read-only
   from the human's point of view.
2. The **human** approves from *their own tooling* (the agent can never
   approve; the request token has no approve method and the daemon
   rejects the attempt). Hand your human `docs/HUMAN_GUIDE.md` — it is
   their complete checklist: the approve/reject commands, what each
   queue field means, the policy knobs they own, and what they must
   never do.
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

## 1c. Where everything lives (file locations)

Everything the daemon owns sits in one config directory (default
`/opt/spellbook`, chosen at install time). If you are a fresh session or
a side chat, read `spellbook.json` there first — it is the source of
truth for where *this* install keeps things. Never guess paths.

- `spellbook.json` — `seed_path`, `std_seed_path`, per-chain RPC URLs,
  `mainnet_submit_enabled`, and policy knobs.
- `seed.key` — the 32-byte daemon seed, at `seed_path`. **One seed covers
  the whole stack** (§4): mainnet and testnet derive *different keys*
  from it (SPEC §2/P9), so the directory name is just a name. An install
  first created during the testnet phase may live under a
  `testnet`-named path and still sign mainnet fine — do not mistake the
  path for the network.
- `std_seed.key` — the 64-byte BIP-39 standard-recovery seed
  (`std_seed_path`); the live keys on fresh installs.
- `spellbook.sock` — the daemon's Unix socket. The CLI finds it via
  `SPELLBOOK_SOCKET`.
- `request.token` / `approve.token` — client auth. Request queues
  intents; approve authorizes exactly one execution attempt. The CLI
  reads them via `SPELLBOOK_REQUEST_TOKEN` / the approve-token path —
  neither ever goes through the dashboard, which is read-only.
- `queue.json`, `ledger.jsonl`, `policy.json`, `velocity.jsonl` —
  daemon state. Read them freely; never hand-edit them.

The daemon is on-demand: if the socket is missing, start it with
`spellbookd --socket <dir>/spellbook.sock --config <dir>` and stop it
when you are done.

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
- **EVM** — testnets now. **Robinhood Chain testnet (46630)** — the
  drill network (SPEC §10 step 9) — RPC
  `https://rpc.testnet.chain.robinhood.com`, faucet
  `https://faucet.testnet.chain.robinhood.com`, explorer
  `https://explorer.testnet.chain.robinhood.com`. Faucet funds can take
  up to ~30 min to arrive; testnet funds are worthless. Mainnet (4663) is
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

## 9. DEX trading — swaps and LP (matcha + Uniswap)

`src/spellbook/dex.py` gives the Spellbook wallet aggregate trading on
EVM: the same routing engines as matcha.xyz (the 0x Swap API — the
**matcha** venue) and the Uniswap app (Uniswap Trading API), plus raw
calldata builders for direct pool interaction. It is **read-only +
build-only**: it fetches quotes and builds calldata, but never signs or
broadcasts. Which venues may actually *execute* swaps is the user's
choice — see "Choosing your swap venues" below.

### API keys

**Agents are not asked for keys.** The operator holds them server-side;
an agent adds its own only if it chooses to:

| Venue | Without a key | With the agent's own key |
|---|---|---|
| matcha (0x Swap API) | quotes via Cast's 0x-compatible routes, `https://cast.awizard.dev/swap/allowance-holder/*` (0x key held server-side; Cast's platform fee is inside the quote) | `ZERO_EX_API_KEY` → `api.0x.org` directly, no Cast fee |
| cast | works — Cast's agent API is open | `CAST_API_KEY`, only if Cast turns keys on |
| Uniswap | not available — there is no server-side Uniswap key | `UNISWAP_API_KEY` (developers.uniswap.org/dashboard) |

`ZEROX_BASE_URL` overrides where matcha quotes go (e.g. a local relay),
key or not. A `dex-swap` naming Uniswap with no `UNISWAP_API_KEY` is
refused when requested, so no approval is spent on a swap that could
never fetch its quote. Keys a user does add live in the daemon's
environment, never in the repo.

Direct pool calldata (v2/v3 builders) needs no key — only an RPC for
read calls like `allowance`.

### Quoting from the CLI

```bash
# Indicative prices from both venues (safe to poll):
spellbook dex-quote --chain 8453 \
  --sell-token 0x4200000000000000000000000000000000000006 \
  --buy-token  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  --amount 1000000000000000000

# Firm executable quotes (short-lived calldata; --taker required):
spellbook dex-quote --firm --venue matcha --chain 8453 \
  --sell-token ... --buy-token ... --amount ... --taker 0xYourWallet
# (--venue 0x also works — it is an alias for matcha.)

# Cast (cast.awizard.dev) — no key. --venue all = matcha + uniswap + cast.
spellbook dex-quote --firm --venue cast --chain 4663 \
  --sell-token 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE \
  --buy-token ... --amount ... --taker 0xYourWallet

# Cast lookups (read-only, no key):
spellbook cast networks                        # chains, tokens, fee recipient
spellbook cast tokens --chain 4663             # token list (--source per networks)
spellbook cast token  --chain 4663 --address 0x...
spellbook cast prices --chain 4663 --addresses 0x...,0x...
```

Output is a ranked comparison: best output-per-input first, with the
full normalized quote (venue, amounts, min-buy, gas estimate, unsigned
tx, allowance target) attached.

### Quoting from Python

```python
from spellbook import dex

zx = dex.ZeroExClient()          # no key: operator relay; or pass your own
q = zx.quote(chain_id=8453, sell_token=WETH, buy_token=USDC,
             sell_amount=10**18, taker=my_addr, slippage_bps=50)

uni = dex.UniswapClient(os.environ["UNISWAP_API_KEY"])
uq = uni.quote(chain_id=8453, token_in=WETH, token_out=USDC,
               amount=10**18, swapper=my_addr, slippage_pct=0.5)
firm = uni.swap(uq["raw"], 8453, WETH, USDC, 10**18, my_addr)

cast = dex.CastClient()          # no key; CAST_API_KEY only if Cast sets one
cq = cast.quote(chain_id=4663, sell_token=dex.NATIVE_SENTINEL,
                buy_token=TOKEN, sell_amount=10**16, taker=my_addr,
                slippage_bps=100)
cast.networks(); cast.tokens(4663); cast.token_lookup(4663, TOKEN)
cast.token_prices(4663, [TOKEN])

best = dex.compare_quotes([q, firm])["best"]
```

### When to use which venue

Official docs are the authority for how each venue works — Spellbook
only adds policy and workflow on top. Cite the docs, never paraphrase
their semantics from memory:

- **matcha** — widest aggregation (the 0x Swap API is what matcha.xyz
  routes through); the docs list ~22 chains incl. Robinhood Chain
  mainnet (4663): https://docs.0x.org/docs/introduction/supported-chains.
  Two modes: `allowance-holder` (classic approve-then-swap) and
  `permit2` (signature-based approvals).
- **Uniswap** — Uniswap routing + UniswapX; chain list in the docs
  (Robinhood Chain mainnet (4663) included):
  https://developers.uniswap.org/docs/trading/swapping-api/supported-chains.
  Canonical flow is `check_approval` → `quote` → `swap`
  (https://developers.uniswap.org/docs/trading/swapping-api/integration-guide).
  Non-classic routings are refused rather than half-built — DUTCH_V2/
  DUTCH_V3/PRIORITY/LIMIT_ORDER quotes need the /order flow, CHAINED
  needs /plan (per the guide's endpoint table) — re-quote or switch
  venue. If a quote returns `permitData`, the human's EIP-712
  signature over it is required before /swap. Spellbook sends the
  `X-Agent-Info` header as the agent-attribution docs specify
  (JSON with `decision_origin: "human_mediated"`).
- **cast** — Cast, https://cast.awizard.dev/agents: aWizard's router
  over the 0x Swap API (allowance-holder) on Base (8453) and Robinhood
  Chain (4663). No API key; Cast takes its platform fee inside the
  quoted swap. The daemon calls Cast's agent API directly
  (`POST /api/agent/quote`), so no local quote shim or `ZEROX_BASE_URL`
  relay is needed. As with every venue, only the quote's tx and
  `allowanceTarget` are used — the daemon builds its own exact-amount
  approval and never signs Cast's `approval` calldata. Override the host
  with `CAST_BASE_URL` (e.g. a preview deploy).
- **All three serve Robinhood Chain mainnet (4663)** — per their official
  supported-chains docs. The 46630 testnet is not served by either.
  For Uniswap-v2-style pools with no API key (e.g. PLANK/WETH),
  `build_v2_swap_calldata` builds the swap calldata directly against
  the pool's router address.

### Recommended swap venues

The recommended venue list is a default guardrail, not a gate. The
user's `dex.recommended_venues` in spellbook.json (daemon-user-owned,
mode 0600) names the venues they prefer; the default is matcha +
uniswap. Swapping through Cast without a warning on every intent means
adding it:

```json
{ "dex": { "recommended_venues": ["matcha", "uniswap", "cast"] } }
```

To see the effective list (and every known venue with its served
chains):

```bash
spellbook dex-venues
```

A `dex-swap` naming any other venue is **not** refused — it is queued
with a prominent `venue_warning` on the intent, and the human's
per-transaction approval is what authorizes the venue. Every agent's
human approves their own venues; the list is just the default
recommendation. Changes take effect on daemon restart; unknown venue
names fail the daemon at startup rather than silently doing nothing.

**Agent rule:** when you surface a queued `dex_swap` for human approval,
always show the venue and the `venue_warning` (when present)
prominently — the human is authorizing the venue with their approval,
so the choice must be impossible to miss. The venue must also serve
the chain: the 46630 testnet is not served by either venue, so asking
for a matcha swap on Robinhood Chain testnet is refused immediately
with "does not serve" (a capability fact, not a policy choice).

### Direct pool calldata (no API key)

```python
# ERC-20 approval for the EXACT trade amount (never unlimited):
approve_cd = dex.build_approve_calldata(spender=quote["allowance_target"],
                                        amount=sell_amount)

# Uniswap v2 swap / add liquidity:
swap_cd = dex.build_v2_swap_calldata(amount_in, amount_out_min,
                                     path=[token_a, token_b], to=my_addr,
                                     deadline=int(time.time()) + 600)
lp_cd = dex.build_v2_add_liquidity_calldata(token_a, token_b,
                                            amount_a_desired, amount_b_desired,
                                            amount_a_min, amount_b_min,
                                            to=my_addr, deadline=...)

# Uniswap v3 single-hop swap / open a position:
v3_cd = dex.build_v3_exact_input_single_calldata(token_in, token_out,
                                                 fee=3000, recipient=my_addr,
                                                 amount_in=..., amount_out_min=...)
mint_cd = dex.build_v3_mint_calldata(token0, token1, fee=500,
                                     tick_lower=-100, tick_upper=100,
                                     amount0_desired=..., amount1_desired=...,
                                     amount0_min=..., amount1_min=...,
                                     recipient=my_addr, deadline=...)
```

v3 notes: `fee` is one of 100/500/3000/10000; `token0 < token1` (sort
order enforced); ticks must bracket the current price or the position
holds a single asset.

### Agent safety rules (non-negotiable)

1. **Quotes expire in tens of seconds.** Never store a firm quote and
   replay it later — re-fetch at execution time and re-validate every
   field (chain, taker, tokens, amounts, slippage, target).
2. **Never hardcode a spender.** The ERC-20 approval target comes from
   the quote itself (`allowance_target`); approving anything else is a
   classic drain vector.
3. **Approve exact amounts.** Unlimited approvals are refused by the
   builders' convention — pass the trade amount, nothing more.
4. **Slippage is bounded** (1–500 bps). The default 50 bps (0.5%) is
   sane; anything wider needs the human to say so explicitly.
5. **How the daemon executes swaps (SPEC §10 v2 — approved by Speechless
   2026-09-23).** The queue holds *bounds*, never calldata: `dex-swap`
   carries venue, tokens, exact sell amount, minimum buy, max slippage,
   deadline; `dex-lp-add` carries protocol, router (v2/v3) or
   position_manager + permit2 (v4), tokens, amounts (v4: hard max spends +
   position liquidity), mins, v3 fee/ticks or v4 pool key. At execution the daemon fetches the firm quote *then*,
   validates it field-by-field against the approved bounds
   (`validate_swap_intent_against_quote` — chain, tokens, exact sell
   amount, min buy, allowance target, tx value), does the exact-amount
   ERC-20 approval only if on-chain allowance is short, signs with
   `sign_legacy_call` (same ecrecover self-check as transfers), and
   broadcasts once. No opaque calldata ever reaches the signer: swap
   calldata comes from the venue quote, LP calldata is built locally
   from the approved bounds via whitelisted builders. One approval =
   one execution attempt (approve + swap/LP = the single execution);
   unknown fate is never retried. Do not work around this by hand-rolling
   a signer outside the daemon.
6. **`--deadline-sec` is an absolute unix timestamp**, not
   seconds-from-now. Passing `3600` means January 1970 — the daemon
   refuses the intent as expired on the spot. Compute it as
   `$(date +%s) + seconds`.
7. **LP add / remove / claim (v2, v3, v4).** The semantics below are the
   official Uniswap contracts' behavior — Spellbook only adds the
   guardrails. Sources: the v3
   [NonfungiblePositionManager](https://github.com/Uniswap/v3-periphery/blob/main/contracts/NonfungiblePositionManager.sol)
   source, the v4 [PositionManager](https://github.com/Uniswap/v4-periphery/blob/main/src/PositionManager.sol)
   and [Actions](https://github.com/Uniswap/v4-periphery/blob/main/src/libraries/Actions.sol)
   sources, and the official [position-manager](https://docs.uniswap.org/contracts/v4/guides/position-manager)
   and [mint-position](https://docs.uniswap.org/docs/protocols/v4/guides/managing-liquidity/mint-position)
   guides.
   - **v2:** `dex-lp-add` → `addLiquidity` (exact amounts in, LP tokens
     out). Fees are **not** distributed — they accrue inside the LP-token
     value itself, so there is **no separate fee claim**; `dex-lp-claim`
     refuses v2 and points at remove. `dex-lp-remove` → `removeLiquidity`
     burns the LP tokens and returns both tokens; needs an exact-amount
     approval of the LP (pair) token to the router first.
   - **v3:** positions are NFTs on the NonfungiblePositionManager.
     `dex-lp-add` → `mint` (fee tier 100/500/3000/10000, tick range).
     Removing is two on-chain steps: `decreaseLiquidity` records what you
     are owed but **does not transfer tokens** — follow it with
     `collect`, and the daemon sends both in one `multicall`.
     `dex-lp-claim` → `collect` (everything owed, max uint128).
   - **v4:** positions are NFTs on the PositionManager; liquidity moves
     happen as action batches through
     `modifyLiquidities(actions, params, deadline)`. `dex-lp-add` →
     `[MINT_POSITION, SETTLE_PAIR]`; the daemon computes the pool id from
     the pool key and refuses unless the pool is initialized (`getSlot0`
     non-zero). ERC-20 funding goes through **two exact-amount Permit2
     stages**: token → Permit2, then Permit2 → PositionManager (expiry =
     the intent deadline), skipping stages the on-chain allowance
     already covers. `dex-lp-remove` →
     `[DECREASE_LIQUIDITY, TAKE_PAIR]` (+ `BURN_POSITION` when
     `burn-nft` retires the NFT on full exits). `dex-lp-claim` → a
     **zero-liquidity** `DECREASE_LIQUIDITY` (the documented fee-credit
     path) + `TAKE_PAIR`.
   - **Spellbook's guardrails on top:** remove/claim always queue for
     human approval (never auto-execute, never count toward velocity —
     they receive value, not spend it). Execution pre-flights are
     read-only and fail closed: the wallet must own the position NFT
     (`ownerOf`), the v2 pair contract's `token0`/`token1` must match
     the intent before any approval, v4 is **hookless pools only** and
     refuses native currency (wrap to WETH first), approvals are always
     exact amounts (never unlimited), and one approval = one execution
     attempt with no retries. Never accept or forward opaque calldata —
     the daemon builds every call from the approved bounds.
8. **Gas needs headroom.** The daemon signs legacy type-0 txs; on
   EIP-1559 chains the node rejects a submission whose gas price lands
   below the block base fee (`max fee per gas less than block base
   fee`). Every EVM submission prices through the buffered
   `_evm_gas_price()` (`EVM_GAS_PRICE_BUMP_BPS`) — never bypass it with
   a raw `eth_gasPrice`.

### The mainnet swap runbook — decided 2026-09-24

First mainnet swap ($5 ETH → PORCH on Robinhood Chain 4663) set the
operational shape; Speechless decided it explicitly:

- **No dashboard approvals.** The dashboard is read-only by design —
  it cannot approve, sign, or broadcast, and no approve button will be
  added. The model is **agentic swaps with human delegation**:
  the agent prepares (indicative quote → bounded queue intent), the
  human approves **in chat**, and the agent conveys that approval via
  the approve-token path as the human's delegate. The chat message is
  the authorization — the agent never approves its own action. Note the
  conveyance in the intent's purpose (e.g. `chat-approved 2026-09-24`)
  so the ledger shows whose decision it was.
- **The production seed never leaves the local daemon.**
  Cloud/deployed agents do not need it and do not receive it. The
  quote relay (the operator's, by default — no key on the agent side;
  `ZEROX_BASE_URL` to point elsewhere) supplies routing and quotes only — it never signs,
  never holds funds, never sees the seed. Never place a production
  seed in a website-login vault or a cloud deployment.
- **Mainnet config:** `evm-4663` enabled with its mainnet RPC,
  `mainnet_submit_enabled: true`, relay env vars on the daemon.
- **Flow:** indicative quote → queue bounded intent → human chat
  approval → delegate conveys → one execution attempt → receipt
  verification → daemon shutdown (on-demand only; never idle).
- **Unknown fate is never retried.** A broadcast whose receipt never
  arrives is reconciled read-only from chain state. A failure *before*
  broadcast (e.g. the node rejecting an underpriced submission) spends
  nothing but still consumes the approval — the human re-requests if
  they still want it.
- **Quote fetches ride out network drops.** Fetching the firm quote is
  read-only, so the DEX layer retries it when the connection drops before
  the venue answers (reset, empty reply, timeout) or on a 502/503/504:
  backoff 2s/5s/10s/20s, capped at 90s, then the intent deadline is
  re-checked before anything is signed. A definite answer (4xx, bad
  quote) is never retried. Every attempt sends `User-Agent: spellbook/<ver>`
  and `X-Request-Id: <id>-<attempt>`; the id is in any error the ledger
  records, so the venue's logs (e.g. Cast's) can be searched for it.

### The v2 execution decision — decided 2026-09-23

Speechless approved it: "You are an agent we give approval and authority
and you should be able to execute swaps for us." The design above is the
implementation — bounded intents instead of a generic calldata decoder,
exact-amount approvals, no `allow_opaque_calldata` knob (opaque calldata
is simply never signable). Venue API keys are optional except for
Uniswap (see "API keys"); any the user adds live in the *daemon's*
environment, never in the repo.
Why this took a spec change at all: v1 deliberately limited the daemon to
plain transfers (S13) so a prompt-injected agent holding the request
token couldn't talk it into signing arbitrary contract calldata — the
actual attack that drains agent wallets. Bankr can swap freely because
it's a hosted service: their backend holds the keys and decides what to
sign; Spellbook is self-custody on your machine, so the signing policy
is yours to set, and now it permits bounded swaps/LPs under the normal
human-approval flow (the human still approves each trade's bounds).

## 10. Wallet message signatures (all chains)

Your agent can ask the daemon to sign a message with a wallet key — for
logins, attestations, and off-chain authorizations. This is the
`message_sign` intent, and **it always queues for a human: a signature is
a capability even though no funds move** (no amount policy can
auto-approve it).

`sign_type` selects the scheme; the chain gates which types are legal:

| Chain | `sign_type` | What the daemon signs |
|---|---|---|
| `evm-*` | `personal` | EIP-191 personal_sign — the daemon builds the `"\x19Ethereum Signed Message:\n" + len + message` preimage itself |
| `evm-*` | `typed_data` | EIP-712 — `message` is the JSON *typed-data object*; the daemon builds the `0x1901 ‖ domainSeparator ‖ hashStruct` digest itself with its own encoder |
| `solana-*` | `plain` | ed25519 over the UTF-8 message bytes |
| `chia-*` | `plain` | Sage `sign_message_by_address` / `sign_message_with_public_key` |

P1 applies to messages too: the daemon **never signs caller-supplied raw
bytes or digests**. For `typed_data`, pass the object — never a
precomputed hash — and make sure `domain.chainId` equals the signing
chain's id (the daemon re-checks at execution and refuses on mismatch).

```bash
# EIP-191 on Robinhood Chain
spellbook message-sign --chain evm-4663 --sign-type personal \
  --message "reward coin 0xabc pays holders of 0xdef" \
  --address 0xYourWallet --purpose "collection attestation for the holder-reward spell"
```

```python
from spellbook.client import AgentClient
c = AgentClient("/run/spellbook/spellbook.sock", open("/path/to/request.token").read().strip())
# EIP-712: message is the JSON typed-data object as a string
c.message_sign(chain="evm-4663", sign_type="typed_data", message=typed_data_json,
               address="0xYourWallet", purpose="permit authorization")
```

After the human approves, the executed queue item carries
`{submitted: False, signature, signed_by, sign_type}` — the signature,
never the key. Nothing is broadcast.

Agent rules:
1. **Show the human the exact message.** The decoded intent is the review
   surface — for `typed_data`, render the domain and every field in plain
   language in `purpose`/accompanying notes. A typed-data signature can
   authorize token permits: treat the request with the care of a spend.
2. **Never request a signature over text you can't explain.** "Sign this
   opaque blob so the site stops nagging" is how wallets get drained —
   yours can't (the daemon only signs what it built), but the *meaning*
   of the message is still yours to vouch for.
3. **One signature per approval.** Like spends: one approval = one
   signature, no standing permission.

## 11. Contract interaction — deploy, call, read (EVM)

Your agent can deploy contracts and call their methods through the
daemon. These are the `contract_deploy`, `contract_call`, and
`contract_call_view` intents — the on-chain half of agent-driven
contract workflows (e.g. deploying an HTLC escrow and then locking /
claiming / refunding through it). The design carries the same signing
philosophy as §10: **the daemon never signs caller-supplied raw bytes**
— it builds the init code and calldata itself from decoded fields,
re-checks them against the queued intent at execution, and signs only
what it built.

**`contract_deploy` / `contract_call` always queue for a human.**
Arbitrary bytecode/calldata is a capability even at zero value — a
0-value call can approve a token spender — so amount policies can never
auto-approve these. One approval = one execution attempt.

**`contract_call_view` is read-only** (`eth_call` of a view/pure
method): no queue, no approval, nothing signed, like the other read
routes. The `stateMutability` gate keeps the two straight: sending a
view method as `contract_call` (or a state-changing method as
`contract_call_view`) is refused as caller confusion.

```bash
# Deploy — bytecode + ABI-encoded constructor args (JSON array)
spellbook contract-deploy --chain evm-46630 \
  --bytecode "$(cat out/HTLCEscrow.sol/HTLCEscrow.json | jq -r .bytecode.object)" \
  --constructor-abi '{"inputs":[{"name":"t","type":"uint256"}]}' \
  --constructor-args '[3600]' --purpose "HTLC escrow for the demo flow"

# State-changing call — decoded args, human approves the meaning
spellbook contract-call --chain evm-46630 \
  --contract 0xEscrowAddress \
  --method lock \
  --method-abi '{"name":"lock","stateMutability":"payable","inputs":[{"name":"hashlock","type":"bytes32"},{"name":"timelock","type":"uint256"}]}' \
  --args '["0x…hashlock…", 7200]' --value-wei 5000 \
  --purpose "lock 5000 wei behind the hashlock"

# Read-only call — returns the decoded result immediately
spellbook contract-call-view --chain evm-46630 \
  --contract 0xEscrowAddress --method getLock \
  --method-abi '{"name":"getLock","stateMutability":"view","inputs":[],"outputs":[{"name":"amount","type":"uint256"}]}'
```

```python
from spellbook.client import AgentClient
c = AgentClient("/run/spellbook/spellbook.sock", open("/path/to/request.token").read().strip())

# Deploy — returns the verified contract address after human approval
r = c.contract_deploy(chain="evm-46630", bytecode="0x6080…",
                      constructor_args=[3600], purpose="HTLC escrow deploy")
r["queue_id"]  # human approves, then: {"submitted": True, "tx_hash": …,
               # "block": …, "contract_address": "0x…"} — the address is
               # cross-checked against CREATE(sender, nonce) first

# Call — returns tx_hash, block, and receipt logs after approval
r = c.contract_call(chain="evm-46630", contract="0x…", method="lock",
                    method_abi={…}, args=["0x…", 7200], value_wei=5000,
                    purpose="lock funds")

# Read — no approval; decoded outputs come straight back
r = c.contract_call_view(chain="evm-46630", contract="0x…",
                         method="getLock", method_abi={…})
r["result"]  # e.g. [5000]
```

Agent rules:
1. **Show the human the decoded call.** The queue displays chain +
   contract (or "NEW CONTRACT") + method + decoded args + value +
   purpose — never raw calldata. For deploys, bytecode is opaque to the
   daemon (it doesn't analyze semantics): the human approves on your
   `purpose` and on trusting you, so write it plainly and name what the
   contract *is*.
2. **Pass the ABI, not the bytes.** The daemon rebuilds init code and
   calldata from your decoded fields; request-time validation
   trial-encodes them and refuses mismatches before a human ever sees
   the item. If your args don't match the ABI, you get a validation
   error, not a queue item.
3. **Mind the value leg.** `contract_call`'s `value_wei` counts toward
   the 24h velocity accounting (deploy gas/value is the same
   discipline as every other EVM submission — mainnet needs the
   separately-authorized `mainnet_submit_enabled` flag). Views move
   nothing and count nothing.
4. **One approval = one attempt.** Like spends: a failed or
   unknown-fate deployment/call is never retried — reconcile from the
   chain and ask the human again with new context.

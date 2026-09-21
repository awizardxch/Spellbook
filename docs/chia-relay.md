# Spellbook Chia Relay — spec

**Status:** draft for first-tester review (Speechless). No deployment yet.
**Date:** 2026-09-21.
**Deployment owner:** Speechless. The agent does not deploy Railway or Vercel.

## 1. Problem

Spellbook's Chia path talks to the Chia network through a local Sage
wallet (`sage rpc start`), which needs raw TCP peer connections to Chia
full nodes (testnet11 port 58444, mainnet 8444).

Two facts kill that as the default:

1. The sandbox most agents run in (including this one) blocks raw TCP
   egress. The only network that works is HTTPS through the environment's
   proxy.
2. The Muse `other_tcp` permission toggle — the documented escape hatch —
   **does not exist on mobile** (PC website only). A wallet that requires
   users to flip a permission most of them can't see is not shippable.

Proven 2026-09-20: a real testnet11 peer TLS handshake completes in
~0.1s through an HTTPS CONNECT tunnel. The Chia network is reachable;
only raw TCP from the sandbox is not.

## 1a. Verified protocol facts (2026-09-21)

Against vendored `chia-puzzle-types`, `chia-bls`, and `chia-sdk-signer`
sources plus a live handshake:

- Peers use `wss://{socket_addr}/ws`; one binary WebSocket frame carries
  one raw serialized `Message` (no 4-byte frame-length prefix).
- Message: `msg_type` uint8, `id` optional uint16, `data` = 4-byte BE
  length + bytes.
- Handshake sends network `"testnet11"`, protocol `"0.0.37"`, software
  `"0.0.0"`, port 0, node type Wallet (6), capabilities
  `(1,"1"),(2,"1"),(3,"1")`. The peer must reply Handshake as FullNode
  (1) on the requested network. The `network_id` check is
  protocol/network compatibility validation, not peer authentication.
- Testnet11 genesis challenge (AGG_SIG_ME additional data):
  `37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615`.
- AGG_SIG_ME signed message (no outer SHA-256):
  `sha256tree1(delegated_puzzle) ‖ coin_id ‖ genesis_challenge`,
  where `delegated_puzzle` is the quoted conditions program
  `(q . conditions)` from the solution.
- Standard module tree hash:
  `e9aaa49f45bad5c889b86ee3341550c155cfdd10c3a6757de618d20612fffd52`.
- Synthetic-key offset uses SIGNED big-endian digest reduction
  (`BigInt::from_signed_bytes_be`), not unsigned modulo.
- Wallet path (Sage-compatible): fully unhardened `[12381, 8444, 2, index]`.
- Relevant message IDs: Handshake=1, RequestPuzzleSolution=45,
  RespondPuzzleSolution=46, SendTransaction=48, TransactionAck=49,
  RequestHeaderBlocks=60, RegisterForPhUpdates=70,
  RespondToPhUpdates=71, RegisterForCoinUpdates=72,
  RespondToCoinUpdates=73.
- Pinned protocol `0.0.37`; current main references `0.0.38`.
  Compatibility is not formally established — do not invent it.

## 2. Decision

Run Chia network access as a second Railway service — live at
**`https://spellbook-production.up.railway.app`** — next to `forge-responder`. The daemon keeps
keys and BLS signing local; the relay only ever sees public addresses /
puzzle hashes and already-signed spend bundles. Same trust model as
pointing a wallet at any public full node.

```
┌──────────────┐   HTTPS + bearer token   ┌───────────────────┐   Chia peer TLS  ┌────────────┐
│   daemon     │ ───────────────────────▶ │ spellbook-chia-   │ ───────────────▶ │ testnet11  │
│ keys + BLS   │   coins / broadcast /    │ relay (Railway)   │  persistent peer │ full nodes │
│ signing HERE │   tx status              │ no keys, no seeds │  connections     │ :58444     │
└──────────────┘                          └───────────────────┘                  └────────────┘
```

What the relay **never** receives: seeds, private keys, mnemonics.
What the relay **does** receive: puzzle hashes (public), signed spend
bundles (public once broadcast), bearer token.

## 3. Relay API (v1)

Base: `https://<relay-host>`. Auth: `Authorization: Bearer <token>`.
All responses JSON. Fail-closed: any 4xx/5xx or schema mismatch raises
on the daemon side; nothing is ever retried blindly.

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/v1/status` | — | `{ok, network, peak_height, peers, watched_addresses, uptime_s}` |
| POST | `/v1/coins` | `{puzzle_hashes: [hex…]}` (≤ 50) | `{coins: [{coin_id, parent_coin_info, puzzle_hash, amount_mojos, created_height, spent_height\|null}]}` |
| POST | `/v1/broadcast` | `{spend_bundle_hex}` | `{ok, txid, status}` — status is the mempool inclusion ack |
| GET | `/v1/coin/{coin_id}` | — | `{coin_id, spent_height\|null, created_height}` — confirmation tracking |

### 3.1 Semantics

- **`/v1/coins`** — the relay keeps the requested puzzle hashes
  subscribed on its peer connection(s) (`RegisterForPhUpdates`) and
  returns the latest known `CoinState`s. Unspent = `spent_height` null.
  The daemon treats an empty list as "no coins", never as an error, and
  treats transport errors as fail-closed (no balance reported).
- **`/v1/broadcast`** — the relay sends `SendTransaction` with the
  bundle and returns the `TransactionAck`. `status` follows Chia's
  `MempoolInclusionStatus` (1 = SUCCESS, 2 = PENDING, 3 = FAILED).
  FAILED with an error string is a hard failure (no retry without human
  review — a blind retry could double-spend if the first actually
  landed).
- **`/v1/coin/{coin_id}`** — polls a created coin until `spent_height`
  is set (change) or a target height passes (payment confirmed). The
  daemon's existing `BroadcastUnknown` semantics apply unchanged: a
  spend that left the machine is never re-submitted blindly.

### 3.2 Security

- Bearer token from env `RELAY_API_TOKEN` (32+ bytes, generated at
  deploy). Constant-time compare. No token, no access — including
  `/v1/status` (which leaks watched addresses).
- Network pinning: `RELAY_NETWORK` (`testnet11` default). The relay
  verifies the peer's handshake `network_id` equals `"testnet11"` (the
  protocol network identifier) and drops the peer otherwise. The
  genesis challenge
  (`37a90eb5…36615`) pins the AGG_SIG_ME domain separately. Mainnet
  requires explicitly setting `RELAY_NETWORK=mainnet` — there is no
  silent fallback.
- Request limits: ≤ 50 puzzle hashes per `/v1/coins` call; ≤ 5 MB
  bundle per `/v1/broadcast`; naive per-IP rate limit (60 req/min).
  Bodies are schema-validated; anything else is a 400.
- The relay never accepts seeds, private keys, or mnemonics — payloads
  are scanned and rejected if they look like key material.
- TLS: Railway terminates public HTTPS. The relay's peer connections
  use Chia peer TLS (self-signed cert is fine — full nodes don't
  authenticate wallets; the network_id pin is the compatibility check).
- Logging: peer churn, broadcast txids, and error counts. Never log
  puzzle hashes at info level in a way that maps to users; never log
  tokens.
- CORS: `RELAY_CORS_ORIGIN` set to the Vercel deployment origin.

## 4. Daemon changes

`src/spellbook/chia.py` keeps the Sage transport. New:

- **`src/spellbook/chia_sign.py`** — local key derivation and spend
  construction (built 2026-09-21, 26 tests green). Dependencies:
  `blspy`, `clvm`, `chia_rs` (all official, pip-installable).
  Implements:
  - Unhardened derivation (`master → [12381, 8444, 2] → index`),
    matching Sage exactly (verified against `chia-bls` vectors).
  - Synthetic keys with signed-mod digest reduction, verified against
    16 `chia-puzzle-types` vectors (including high-bit regression).
  - `p2_delegated_puzzle_or_hidden_puzzle` (pinned bytes, tree hash
    `e9aaa49f…fd52`) curried with the synthetic key → puzzle hash →
    bech32m `txch1…`/`xch1…`. The curried puzzle executes in `chia_rs`
    and emits the expected `AGG_SIG_ME` + `CREATE_COIN` conditions.
  - Standard spend: coin selection, `CREATE_COIN` conditions,
    per-coin `AugSchemeMPL` signatures over
    `sha256tree1((q . conditions)) ‖ coin_id ‖ genesis_challenge`
    (no outer SHA-256 — verified against `chia-sdk-signer`). The
    puzzle hash of every built puzzle reveal is checked against the
    coin's puzzle hash before signing — fail-closed on mismatch.
    External BLS verification passes; wrong-key and wrong-network
    signatures fail closed.
- **`src/spellbook/chia_relay.py`** — `RelayRpc`: HTTPS client for the
  relay API with bearer auth, same fail-closed posture as `SageRpc`.
- **`daemon.py`** — `_execute_chia_spend` and `rt_status` use the relay
  path when `spellbook.json` sets `chia.relay_url` (+ `relay_token`
  from env/file). Sage remains the default when `relay_url` is unset.
  The O10 flow (queue → human approval → daemon executes → report) is
  unchanged; only the transport differs.

Config:

```json
"chia": {
  "relay_url": "https://spellbook-production.up.railway.app",
  "relay_token": "env:SPELLBOOK_RELAY_TOKEN"
}
```

## 5. Frontend (`web/`, Vercel)

A static single-page dashboard for the first tester. No build step;
deploys to Vercel as-is. It talks to the relay API with a token the
tester pastes (stored in `sessionStorage` only, never persisted).

Panels:

1. **Relay status** — network, peak height, peer count, uptime.
2. **Watch** — paste a `txch1…` address → shows coins, total, and
   per-coin created/spent heights. Polls every 30 s.
3. **Broadcast** — paste a signed spend-bundle hex → shows the ack
   (`txid`, mempool status) or the error. Explicit "this cannot be
   undone" copy; no key handling anywhere in the page.
4. **Drill log** — read-only view of recent broadcasts the relay has
   seen (txids + heights), for reconciling drill runs.

The page never asks for seeds or keys. If it ever does, that's a bug.

## 6. Deployment (Speechless runs these)

Backend (Railway), from `relay/`:

```
cd relay
railway init            # or link the existing project
railway variables set RELAY_API_TOKEN=<64-hex> RELAY_NETWORK=testnet11
railway up
```

`railway.json` sets the builder to Dockerfile; the container runs
`python server.py` on `$PORT`. No volumes, no database — subscriptions
are rebuilt from `/v1/coins` calls after a restart (daemon re-watches
on every status poll).

Frontend (Vercel), from `web/`:

```
cd web
vercel --prod
```

Then set the dashboard's relay URL + token in the page. CORS on the
relay allows the Vercel origin (env `RELAY_CORS_ORIGIN`).

## 7. Test plan (before Speechless deploys)

1. Unit: codec round-trips, synthetic-key vectors (from Sage's own
   tests), drill-wallet-A address reproduction.
2. Local relay against a real testnet11 peer through the sandbox's
   HTTPS proxy: handshake → `RegisterForPhUpdates` for wallet A's
   puzzle hashes → expect the funded coin (1.00025 tXCH, created at
   block 4714900).
3. Full drill matrix through the relay: queued → approved A→B spend,
   confirmation + ledger coin id, dust auto-approve, per-spend-cap
   denial, velocity denial, kill -9 restart persistence, empty
   unresolved set.
4. `pytest` full suite green, push to public `main`. No tag/release.

## 8. What this does NOT change

- O10: agent shows, human approves in separate tooling, daemon
  executes, agent reports. The relay is dumber than Sage — it can't
  approve anything.
- Six-gate token rule, floors, and "Speechless tests first" gating.
- EIP-1559 / legacy EVM behavior. Mainnet Chia still needs its own
  explicit authorization.

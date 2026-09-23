# spellbook-chia-relay

A tiny HTTPS relay that gives the Spellbook daemon Chia-network access
without raw TCP. It holds persistent WSS connections to testnet11 full
nodes and exposes coin lookups + signed-bundle broadcast over a
bearer-authed JSON API.

## What it is

- A **network relay**: it speaks the Chia wallet protocol to full nodes
  (`wss://<peer>:58444/ws`) and translates that into 4 small HTTPS
  endpoints for the daemon / dashboard.
- Stateless-ish: no database, no volumes. Subscriptions rebuild from
  `/v1/coins` calls after a restart.

## What it is NOT

- **Not a wallet custodian.** It never sees seeds, private keys, or
  mnemonics. Keys and BLS signing stay on the daemon; the relay only
  receives puzzle hashes (public) and already-signed spend bundles
  (public once broadcast). Same trust model as pointing a wallet at any
  public full node.
- **Not an approver.** It cannot approve anything — it only forwards what
  the daemon (after human approval) tells it to forward.
- **Not mainnet-ready by default.** It pins `RELAY_NETWORK=testnet11`.
  Mainnet needs an explicit config change and separate authorization.

## API (all routes require `Authorization: Bearer <token>`, except `/health`)

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/health` | — | `{"ok": true, "service": "spellbook-chia-relay"}` — **no auth**, for Railway/K8s health checks. Non-sensitive by design. |
| GET | `/v1/status` | — | `{ok, network, peak_height, peers, peers_connected, watched_puzzle_hashes, cached_coins, uptime_s}` |
| POST | `/v1/coins` | `{puzzle_hashes: [hex32…]}` (1–50) | `{coins: [{coin_id, parent_coin_info, puzzle_hash, amount_mojos, created_height, spent_height\|null}]}` |
| POST | `/v1/broadcast` | `{spend_bundle: hex}` (≤ 5 MB) | `{txid, expected_txid, status, status_name, error}` — `status` is Chia's mempool status (1 SUCCESS, 2 PENDING, 3 FAILED) |
| GET | `/v1/coin/{coin_id}` | — | `{coin}` or 404 — confirmation tracking |
| GET | `/v1/broadcasts` | — | recent broadcast log (newest first) for drill reconciliation |

Errors are `{ok: false, error: "..."}` with HTTP 400 / 401 / 404 / 429 /
502 / 503. Fail-closed: malformed bundles never reach a peer; a FAILED
mempool ack is returned as data (not retried — a blind retry could
double-spend if the first actually landed).

## Environment variables

| Var | Required | Default | Notes |
|---|---|---|---|
| `RELAY_BEARER_TOKEN` | **yes** | — | ≥ 16 chars. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `RELAY_NETWORK` | no | `testnet11` | Handshake network pin. Peers with any other `network_id` are dropped. |
| `RELAY_PEER_PORT` | no | `58444` | Testnet11 peer port (mainnet: `8444`). |
| `RELAY_INTRODUCER` | no | `dns-introducer-testnet11.chia.net` | DNS introducer for peer discovery. |
| `RELAY_PEERS` | no | — | Override discovery: `"host:port,host:port"`. |
| `RELAY_MAX_PEERS` | no | `3` | Max simultaneous peer connections. |
| `RELAY_CORS_ORIGIN` | no | — | Exact Vercel origin to allow, e.g. `https://spellbook-web.vercel.app`. Unset = no browser CORS. |
| `RELAY_CERT_DIR` | no | `./certs` | Where the node TLS cert lives. |
| `RELAY_CHIA_CA_DIR` | no | — | Dir with `chia_ca.crt`/`chia_ca.key` if you don't want the Docker-bundled CA. |
| `PORT` | no | `8000` | Injected by Railway. |

## Deploy (Speechless runs these)

Railway, service **Root Directory** set to `relay/`:

```bash
cd relay
railway init            # or: railway link  (existing project)
railway variables set RELAY_BEARER_TOKEN=<64-hex-chars-you-generated>
railway variables set RELAY_CORS_ORIGIN=https://<your-vercel-app>.vercel.app
railway up
```

`railway.json` selects the Dockerfile build and points the platform
health check at the unauthenticated `GET /health`; the container listens on
`$PORT` (Railway terminates public HTTPS). No volumes, no database.

Health check after deploy (replace `TOKEN` and host):

```bash
curl https://<relay-host>/health            # 200, no auth needed
curl -H "Authorization: Bearer TOKEN" https://<relay-host>/v1/status
```

Expect `"peers_connected" >= 1` and a `peak_height` within a minute or two
of startup (it fills in as coin states / peak pushes arrive).

## Local dev / test

```bash
cd relay
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python test_vectors.py            # codec vectors (no network)
RELAY_BEARER_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
RELAY_CHIA_CA_DIR=/path/to/chia/config/ssl/ca \
python server.py                  # http://localhost:8000
```

`RELAY_CHIA_CA_DIR` should point at any Chia install's `config/ssl/ca/`
(which contains the shared `chia_ca.crt`/`chia_ca.key`). The Docker image
already bundles the shared public CA in `certs/`, so this is only needed
for local runs outside Docker.

Through a proxy (sandboxed environments): set `HTTPS_PROXY` — the peer
WSS client tunnels via HTTP CONNECT.

## Security model

- **Bearer token** on every route, constant-time compare. No token, no
  access — including `/v1/status`.
- **Key-material rejection**: request schemas are strict (no extra
  fields); any field named like `seed`/`mnemonic`/`private_key`/etc. is a
  400. Spend bundles must structurally parse as a canonical Streamable
  `SpendBundle` (non-empty, sane sizes, exact 96-byte signature, no
  trailing bytes) before broadcast.
- **Limits**: ≤ 50 puzzle hashes per `/v1/coins`; ≤ 5 MB bundle;
  60 req/min per token (429 + `Retry-After`).
- **Peer TLS**: presents a client cert signed by the shared Chia CA
  (required — full nodes run `CERT_REQUIRED`); does not verify peer certs —
  peer authentication is the handshake `network_id` pin, not TLS.
- **Logging**: peer churn, broadcast txids + mempool status, error counts.
  Never logs tokens, request bodies, or puzzle-hash↔user mappings.

## Protocol notes (verified, not guessed)

- One binary WS frame = one raw `Message`: `uint8 type`,
  `Optional[uint16] id` (a 0x00/0x01 prefix byte is always on the wire),
  then u32-BE length + payload. Verified byte-for-byte against
  chia-blockchain 2.7.4's `Message.__bytes__`.
- Outbound handshake: network `"testnet11"`, protocol `"0.0.37"`,
  software `"0.0.0"`, port 0, node type Wallet (6), capabilities
  `(1,"1"),(2,"1"),(3,"1")` — the exact bytes a real wallet sends.
- Inbound handshake must be node type FullNode (1) with the pinned
  `network_id`, else the peer is dropped. (`network_id` is the
  `selected_network` string, *not* the genesis challenge — confirmed in
  chia-blockchain's `start_full_node.py`.)
- Protocol version is **not** gated for wallets (only farmer/harvester),
  so our pinned `"0.0.37"` works against `"0.0.38"` peers.
- `TransactionAck.txid` is `sha256(canonical bundle bytes)`; the relay
  cross-checks it and warns on mismatch.
- `coin_id = sha256(parent || puzzle_hash || minimal-BE amount)` per
  `Coin::coin_id` in chia-protocol 0.36.1 (note: *minimal* encoding, not
  fixed 8-byte).

## Files

- `server.py` — aiohttp HTTPS API (auth, rate limits, CORS, validation)
- `peer.py` — WSS peer client + connection manager + coin cache
- `streamable.py` — Chia Streamable codec (no dependencies)
- `cert.py` — shared-CA-signed node cert for peer TLS
- `test_vectors.py` — known-good encodings (run standalone or with pytest)
- `Dockerfile`, `railway.json`, `requirements.txt`

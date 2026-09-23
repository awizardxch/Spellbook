"""HTTPS API for the Spellbook Chia relay.

The relay is a *network relay*, not a wallet custodian:

* it holds persistent WSS connections to Chia full nodes (see peer.py),
* it exposes coin lookups and signed-bundle broadcast over HTTPS,
* it NEVER sees seeds, private keys, or mnemonics — keys and BLS signing
  stay on the daemon.  Anything resembling key material in a request is
  rejected outright, and spend bundles must structurally parse as a valid
  Streamable SpendBundle before they are forwarded to a peer.

Endpoints (all require ``Authorization: Bearer <token>``):

* ``GET  /v1/status``     — relay health: network, peers, peak, uptime
* ``POST /v1/coins``      — {puzzle_hashes: [hex32...]} (1..50) -> {coins: [...]}
* ``POST /v1/coin_ids``   — {coin_ids: [hex32...]} (1..50) -> {coins, not_found}
* ``POST /v1/broadcast``  — {spend_bundle: hex} -> {txid, status, error}
* ``GET  /v1/coin/{id}``  — single coin state (confirmation tracking)
* ``GET  /v1/broadcasts`` — recent broadcast log (drill reconciliation)
* ``GET  /v1/broadcasts/{txid}`` — broadcast record for one txid (404 if unseen)

Fail-closed: malformed input -> 400, no peers -> 503, bad token -> 401,
rate exceeded -> 429.  Nothing is retried blindly.

What the relay deliberately does NOT expose (Sage features that need
key custody, wallet databases, or local signing):

* key management (get_keys, import_key, login/logout) — never leaves Sage
* anything signing (send_*, sign_coin_spends, sign_message_*, make_offer,
  take_offer, clawback, DID/option issuance) — the daemon builds and
  signs locally (chia_sign.py) and the relay only broadcasts
* wallet-DB reads (get_cats, get_nfts, get_transactions, derivations) —
  Sage's local database; the relay is a peer client, not a wallet

The relay covers Sage's *network* surface: coin states by puzzle hash or
coin id, mempool submission with an ack, transaction lookup by txid from
the broadcast log, and chain status/peak.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from aiohttp import web

from cert import CertError, ensure_certs, make_peer_ssl_context
from peer import ManagerConfig, NoPeersError, PeerError, PeerManager
from streamable import (
    MEMPOOL_STATUS_NAMES,
    CoinState,
    StreamableError,
    parse_spend_bundle,
    spend_bundle_txid,
)

log = logging.getLogger("relay.server")

VERSION = "1.1.0"

# --- limits ---------------------------------------------------------------
MAX_PUZZLE_HASHES = 50
MAX_BUNDLE_BYTES = 5 * 1024 * 1024
MAX_BODY_BYTES = 6 * 1024 * 1024
RATE_LIMIT_PER_MIN = 60
BROADCAST_LOG_SIZE = 200

# Field names that must never appear in a request body.  The relay has no
# legitimate use for key material; seeing these is a client bug or worse.
FORBIDDEN_FIELDS = {"seed", "mnemonic", "private_key", "privatekey",
                    "secret", "entropy", "backup_words", "passphrase"}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config() -> dict:
    token = os.environ.get("RELAY_BEARER_TOKEN")
    if not token or len(token) < 16:
        raise SystemExit(
            "RELAY_BEARER_TOKEN is required (min 16 chars). "
            "Generate with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        )
    peers_override = None
    if os.environ.get("RELAY_PEERS"):
        peers_override = [p.strip() for p in os.environ["RELAY_PEERS"].split(",") if p.strip()]
    return {
        "token": token,
        "network_id": os.environ.get("RELAY_NETWORK", "testnet11"),
        "peer_port": int(os.environ.get("RELAY_PEER_PORT", "58444")),
        "introducer_host": os.environ.get(
            "RELAY_INTRODUCER", "dns-introducer-testnet11.chia.net"),
        "peers_override": peers_override,
        "max_peers": int(os.environ.get("RELAY_MAX_PEERS", "3")),
        "cert_dir": os.environ.get("RELAY_CERT_DIR", "./certs"),
        "cors_origin": os.environ.get("RELAY_CORS_ORIGIN"),  # e.g. https://xyz.vercel.app
        "port": int(os.environ.get("PORT", "8000")),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def err(message: str, status: int = 400) -> web.Response:
    return web.json_response({"ok": False, "error": message}, status=status)


def _hex32(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise StreamableError(f"{name} must be a hex string")
    s = value.strip().lower()
    if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise StreamableError(f"{name} must be 64 hex chars (32 bytes)")
    return bytes.fromhex(s)


def coin_to_json(cs: CoinState) -> dict:
    return {
        "coin_id": cs.coin.coin_id().hex(),
        "parent_coin_info": cs.coin.parent_coin_info.hex(),
        "puzzle_hash": cs.coin.puzzle_hash.hex(),
        "amount_mojos": cs.coin.amount,
        "created_height": cs.created_height,
        "spent_height": cs.spent_height,
    }


def check_forbidden_fields(body: Any) -> Optional[str]:
    """Reject payloads that look like they carry key material."""
    if isinstance(body, dict):
        for k in body:
            if isinstance(k, str) and k.strip().lower() in FORBIDDEN_FIELDS:
                return k
    return None


# ---------------------------------------------------------------------------
# App state
# ---------------------------------------------------------------------------

class State:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.started_at = time.time()
        self.manager: Optional[PeerManager] = None
        self.session = None  # aiohttp.ClientSession, created on startup
        self.broadcast_log: Deque[dict] = deque(maxlen=BROADCAST_LOG_SIZE)
        self.rate_buckets: Dict[str, Deque[float]] = {}


# ---------------------------------------------------------------------------
# Middleware: auth + rate limit + CORS + errors
# ---------------------------------------------------------------------------

@web.middleware
async def security_middleware(request: web.Request, handler):
    state: State = request.app["state"]
    cfg = state.config

    # CORS preflight: answer before auth so browsers can probe.
    if request.method == "OPTIONS":
        return _cors_response(web.Response(status=204), cfg)

    # Unauthenticated liveness probe for the platform health check.
    # Deliberately non-sensitive: no peer, balance, or config details.
    if request.path == "/health" and request.method == "GET":
        try:
            resp = await handler(request)
        except web.HTTPException:
            raise
        except Exception:  # noqa: BLE001
            log.exception("unhandled error")
            resp = err("internal error", 500)
        return _cors_response(resp, cfg)

    # --- bearer auth (constant-time) ------------------------------------
    auth = request.headers.get("Authorization", "")
    scheme, _, presented = auth.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(presented, cfg["token"]):
        return _cors_response(web.json_response(
            {"ok": False, "error": "unauthorized"}, status=401), cfg)

    # --- rate limit: 60 req/min per token --------------------------------
    now = time.monotonic()
    bucket = state.rate_buckets.setdefault(presented, deque())
    while bucket and bucket[0] <= now - 60:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        resp = web.json_response({"ok": False, "error": "rate limit exceeded"}, status=429)
        resp.headers["Retry-After"] = "60"
        return _cors_response(resp, cfg)
    bucket.append(now)

    try:
        resp = await handler(request)
    except web.HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        log.exception("unhandled error")
        return _cors_response(err(f"internal error: {type(e).__name__}", 500), cfg)
    return _cors_response(resp, cfg)


def _cors_response(resp: web.Response, cfg: dict) -> web.Response:
    origin = cfg["cors_origin"]
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

async def handle_health(request: web.Request) -> web.Response:
    """Unauthenticated liveness probe (platform health checks).

    Non-sensitive by design: just enough for Railway/K8s to know the
    process is alive.  Everything operational stays behind bearer auth.
    """
    return web.json_response({"ok": True, "service": "spellbook-chia-relay"})


async def handle_status(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    snap = await state.manager.snapshot() if state.manager else {}
    return web.json_response({
        "ok": True,
        "version": VERSION,
        "network": state.config["network_id"],
        "protocol_version": "0.0.37",
        "peak_height": snap.get("peak_height"),
        "peers": state.manager.peer_labels() if state.manager else [],
        "peers_connected": state.manager.connected_count() if state.manager else 0,
        "watched_puzzle_hashes": snap.get("watched_puzzle_hashes", 0),
        "cached_coins": snap.get("cached_coins", 0),
        "uptime_s": int(time.time() - state.started_at),
    })


async def _read_json(request: web.Request) -> Any:
    try:
        return await request.json()
    except Exception as e:  # noqa: BLE001
        raise web.HTTPBadRequest(reason="invalid JSON") from e


async def handle_coins(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    body = await _read_json(request)
    if not isinstance(body, dict):
        return err("body must be a JSON object")
    bad = check_forbidden_fields(body)
    if bad:
        return err(f"field {bad!r} not accepted: this relay never handles key material")
    if set(body.keys()) != {"puzzle_hashes"}:
        return err("body must be exactly {puzzle_hashes: [...]}")
    hashes = body["puzzle_hashes"]
    if not isinstance(hashes, list) or not (1 <= len(hashes) <= MAX_PUZZLE_HASHES):
        return err(f"puzzle_hashes must be a list of 1..{MAX_PUZZLE_HASHES} items")
    try:
        ph_bytes = [_hex32(h, f"puzzle_hashes[{i}]") for i, h in enumerate(hashes)]
    except StreamableError as e:
        return err(str(e))

    try:
        states = await state.manager.get_coins(ph_bytes)
    except NoPeersError:
        return err("no peers connected", 503)
    except (PeerError, StreamableError, asyncio.TimeoutError) as e:
        log.warning("get_coins failed: %s", e)
        return err(f"peer request failed: {type(e).__name__}", 502)

    coins = sorted((coin_to_json(cs) for cs in states), key=lambda c: (c["created_height"] or 0))
    return web.json_response({"ok": True, "coins": coins})


async def handle_coin(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    raw_id = request.match_info["coin_id"]
    try:
        coin_id = _hex32(raw_id, "coin_id")
    except StreamableError as e:
        return err(str(e))

    try:
        cs = await state.manager.get_coin(coin_id)
    except NoPeersError:
        return err("no peers connected", 503)
    except (PeerError, StreamableError, asyncio.TimeoutError) as e:
        log.warning("get_coin failed: %s", e)
        return err(f"peer request failed: {type(e).__name__}", 502)
    if cs is None:
        return err("unknown coin", 404)
    return web.json_response({"ok": True, "coin": coin_to_json(cs)})


async def handle_coin_ids(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    body = await _read_json(request)
    if not isinstance(body, dict):
        return err("body must be a JSON object")
    bad = check_forbidden_fields(body)
    if bad:
        return err(f"field {bad!r} not accepted: this relay never handles key material")
    if set(body.keys()) != {"coin_ids"}:
        return err("body must be exactly {coin_ids: [...]}")
    ids = body["coin_ids"]
    if not isinstance(ids, list) or not (1 <= len(ids) <= MAX_PUZZLE_HASHES):
        return err(f"coin_ids must be a list of 1..{MAX_PUZZLE_HASHES} items")
    try:
        id_bytes = [_hex32(i, f"coin_ids[{n}]") for n, i in enumerate(ids)]
    except StreamableError as e:
        return err(str(e))

    try:
        states = await state.manager.get_coins_by_ids(id_bytes)
    except NoPeersError:
        return err("no peers connected", 503)
    except (PeerError, StreamableError, asyncio.TimeoutError) as e:
        log.warning("get_coins_by_ids failed: %s", e)
        return err(f"peer request failed: {type(e).__name__}", 502)

    found = {cs.coin.coin_id().hex(): coin_to_json(cs) for cs in states}
    coins = [found[cid] for cid in (b.hex() for b in id_bytes) if cid in found]
    not_found = [cid for cid in (b.hex() for b in id_bytes) if cid not in found]
    return web.json_response({"ok": True, "coins": coins, "not_found": not_found})


async def handle_broadcast_tx(request: web.Request) -> web.Response:
    """Broadcast record for one txid — the relay-side answer to
    Sage's ``get_transaction``: what mempool ack did we see for this
    bundle, and did we ever see it at all."""
    state: State = request.app["state"]
    raw = request.match_info["txid"]
    try:
        txid = _hex32(raw, "txid").hex()
    except StreamableError as e:
        return err(str(e))
    for record in state.broadcast_log:
        if record["txid"] == txid:
            return web.json_response({"ok": True, "broadcast": record})
    return err("txid not seen in broadcast log", 404)


async def handle_broadcast(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    body = await _read_json(request)
    if not isinstance(body, dict):
        return err("body must be a JSON object")
    bad = check_forbidden_fields(body)
    if bad:
        return err(f"field {bad!r} not accepted: this relay never handles key material")
    # Accept the documented key; tolerate the legacy alias.
    bundle_hex = body.get("spend_bundle", body.get("spend_bundle_hex"))
    if set(body.keys()) - {"spend_bundle", "spend_bundle_hex"}:
        return err("body must be exactly {spend_bundle: hex}")
    if not isinstance(bundle_hex, str) or not bundle_hex:
        return err("spend_bundle must be a non-empty hex string")
    try:
        bundle = bytes.fromhex(bundle_hex.strip())
    except ValueError:
        return err("spend_bundle is not valid hex")
    if len(bundle) > MAX_BUNDLE_BYTES:
        return err(f"spend bundle exceeds {MAX_BUNDLE_BYTES} bytes")

    # Structural gate: must parse as a canonical SpendBundle.  This rejects
    # truncated/garbage payloads before anything reaches a peer — and a
    # well-formed bundle cannot smuggle key material in a key field, because
    # its fields are coins, programs, and one 96-byte signature.
    try:
        parsed = parse_spend_bundle(bundle)
    except StreamableError as e:
        return err(f"malformed spend bundle: {e}")

    expected_txid = spend_bundle_txid(bundle).hex()
    try:
        ack = await state.manager.broadcast(bundle)
    except NoPeersError:
        return err("no peers connected", 503)
    except (PeerError, StreamableError, asyncio.TimeoutError) as e:
        log.warning("broadcast failed: %s", e)
        return err(f"broadcast failed: {type(e).__name__}", 502)

    txid = ack["txid"].hex()
    status = ack["status"]
    status_name = MEMPOOL_STATUS_NAMES.get(status, f"UNKNOWN({status})")
    record = {
        "txid": txid,
        "status": status,
        "status_name": status_name,
        "error": ack["error"],
        "coin_spends": len(parsed.coin_spends),
        "time": int(time.time()),
    }
    state.broadcast_log.appendleft(record)
    # Log txid + status only: never bundle contents, never tokens.
    log.info("broadcast txid=%s status=%s spends=%d", txid, status_name, len(parsed.coin_spends))
    if status_name == "FAILED":
        log.warning("broadcast FAILED txid=%s error=%s", txid, ack["error"])
    return web.json_response({
        "ok": True,
        "txid": txid,
        "expected_txid": expected_txid,
        "status": status,
        "status_name": status_name,
        "error": ack["error"],
    })


async def handle_broadcasts(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    return web.json_response({"ok": True, "broadcasts": list(state.broadcast_log)})


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------

async def on_startup(app: web.Application) -> None:
    import aiohttp  # noqa: PLC0415

    state: State = app["state"]
    cfg = state.config

    try:
        crt_path, key_path = ensure_certs(cfg["cert_dir"])
    except CertError as e:
        raise SystemExit(f"certificate setup failed: {e}") from e
    ssl_ctx = make_peer_ssl_context(crt_path, key_path)

    # ClientSession without the global default timeout; peer.py applies its
    # own per-request timeouts.
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=20)
    state.session = aiohttp.ClientSession(timeout=timeout)

    mgr_cfg = ManagerConfig(
        network_id=cfg["network_id"],
        peer_port=cfg["peer_port"],
        introducer_host=cfg["introducer_host"],
        peers_override=cfg["peers_override"],
        max_peers=cfg["max_peers"],
    )
    state.manager = PeerManager(mgr_cfg, ssl_ctx, state.session)
    await state.manager.start()
    log.info("relay v%s starting on network %s", VERSION, cfg["network_id"])


async def on_cleanup(app: web.Application) -> None:
    state: State = app["state"]
    if state.manager:
        await state.manager.stop()
    if state.session:
        await state.session.close()


def create_app(config: Optional[dict] = None) -> web.Application:
    cfg = config or load_config()
    app = web.Application(middlewares=[security_middleware], client_max_size=MAX_BODY_BYTES)
    app["state"] = State(cfg)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/v1/status", handle_status)
    app.router.add_post("/v1/coins", handle_coins)
    app.router.add_post("/v1/coin_ids", handle_coin_ids)
    app.router.add_post("/v1/broadcast", handle_broadcast)
    app.router.add_get("/v1/coin/{coin_id}", handle_coin)
    app.router.add_get("/v1/broadcasts", handle_broadcasts)
    app.router.add_get("/v1/broadcasts/{txid}", handle_broadcast_tx)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    # Never log at a level that could echo secrets; the token only ever
    # appears in the Authorization header, which we never print.
    config = load_config()
    app = create_app(config)
    web.run_app(app, host="0.0.0.0", port=config["port"], print=None)


if __name__ == "__main__":
    main()

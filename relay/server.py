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

Multi-network: the relay holds one peer pool per enabled Chia network
(testnet11 + mainnet by default).  Every endpoint accepts an optional
``network`` selector — a ``"network"`` key in POST bodies or a
``?network=`` query param on GETs.  Requests that omit it use the
default network (``RELAY_NETWORK``, historically testnet11), so old
clients keep working unchanged.

Fail-closed: malformed input -> 400, unknown network -> 400,
no peers -> 503, bad token -> 401, rate exceeded -> 429.
Nothing is retried blindly.

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

VERSION = "1.2.0"

# --- limits ---------------------------------------------------------------
MAX_PUZZLE_HASHES = 50
MAX_BUNDLE_BYTES = 5 * 1024 * 1024
MAX_BODY_BYTES = 6 * 1024 * 1024
RATE_LIMIT_PER_MIN = 60
BROADCAST_LOG_SIZE = 200

# Per-network peer defaults.  A Chia peer connection is network-pinned at
# the handshake: mainnet peers (port 8444) will not talk testnet11 and
# vice versa, so each enabled network gets its own PeerManager.
NETWORK_DEFAULTS = {
    "testnet11": {
        "peer_port": 58444,
        "introducer_host": "dns-introducer-testnet11.chia.net",
    },
    "mainnet": {
        "peer_port": 8444,
        "introducer_host": "dns-introducer.chia.net",
    },
}

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

    networks = [
        n.strip().lower()
        for n in os.environ.get("RELAY_NETWORKS", "testnet11,mainnet").split(",")
        if n.strip()
    ]
    unknown = [n for n in networks if n not in NETWORK_DEFAULTS]
    if unknown:
        raise SystemExit(
            f"RELAY_NETWORKS has unknown network(s) {unknown}; "
            f"supported: {sorted(NETWORK_DEFAULTS)}"
        )
    if not networks:
        raise SystemExit("RELAY_NETWORKS must enable at least one network")

    default_network = os.environ.get("RELAY_NETWORK", "testnet11").strip().lower()
    if default_network not in networks:
        raise SystemExit(
            f"RELAY_NETWORK={default_network!r} is not in RELAY_NETWORKS={networks}"
        )

    network_configs = {}
    for net in networks:
        defaults = NETWORK_DEFAULTS[net]
        # RELAY_PEER_PORT / RELAY_INTRODUCER / RELAY_PEERS keep their
        # historical meaning: overrides for the *default* network.
        if net == default_network:
            peer_port = int(os.environ.get("RELAY_PEER_PORT", str(defaults["peer_port"])))
            introducer = os.environ.get("RELAY_INTRODUCER", defaults["introducer_host"])
            peers_env = os.environ.get("RELAY_PEERS")
        else:
            peer_port = defaults["peer_port"]
            introducer = defaults["introducer_host"]
            peers_env = None
        # Per-network override: RELAY_PEERS_MAINNET / RELAY_PEERS_TESTNET11.
        specific = os.environ.get(f"RELAY_PEERS_{net.upper()}")
        if specific:
            peers_env = specific
        peers_override = (
            [p.strip() for p in peers_env.split(",") if p.strip()]
            if peers_env else None
        )
        network_configs[net] = {
            "peer_port": peer_port,
            "introducer_host": introducer,
            "peers_override": peers_override,
            "max_peers": int(os.environ.get("RELAY_MAX_PEERS", "3")),
        }

    return {
        "token": token,
        # Historical single-network keys, kept for backward compatibility:
        # "network_id" is the default network; "peer_port"/"introducer_host"
        # describe it.
        "network_id": default_network,
        "peer_port": network_configs[default_network]["peer_port"],
        "introducer_host": network_configs[default_network]["introducer_host"],
        "peers_override": network_configs[default_network]["peers_override"],
        "max_peers": network_configs[default_network]["max_peers"],
        # Multi-network config.
        "networks": networks,
        "network_configs": network_configs,
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
        # One PeerManager per enabled network, keyed by network id.
        self.managers: Dict[str, PeerManager] = {}
        self.session = None  # aiohttp.ClientSession, created on startup
        self.broadcast_log: Deque[dict] = deque(maxlen=BROADCAST_LOG_SIZE)
        self.rate_buckets: Dict[str, Deque[float]] = {}

    @property
    def manager(self) -> Optional[PeerManager]:
        """The default network's manager (backward-compatible alias)."""
        return self.managers.get(self.config.get("network_id", "testnet11"))

    @manager.setter
    def manager(self, value: Optional[PeerManager]) -> None:
        self.managers[self.config.get("network_id", "testnet11")] = value


def _enabled_networks(config: dict) -> List[str]:
    """Networks this relay serves.  Tolerates legacy single-network configs."""
    nets = config.get("networks")
    if nets:
        return list(nets)
    return [config.get("network_id", "testnet11")]


def _resolve_network(
    request: web.Request, body: Any = None
) -> tuple[Optional[str], Optional[web.Response]]:
    """Pick the network for this request.

    POST bodies may carry ``"network"``; GETs accept ``?network=``.
    Omitted -> the configured default network (backward compatible).
    Returns ``(network, None)`` on success or ``(None, error_response)``
    with a JSON 400 for an unknown network.
    """
    config = request.app["state"].config
    enabled = _enabled_networks(config)
    name: Any = None
    if isinstance(body, dict):
        name = body.get("network")
    if name is None:
        name = request.query.get("network")
    if name is None:
        return config.get("network_id", "testnet11"), None
    name = str(name).strip().lower()
    if name not in enabled:
        return None, err(f"unknown network {name!r}; enabled: {enabled}")
    return name, None


def _manager_for(request: web.Request, network: str) -> Optional[PeerManager]:
    return request.app["state"].managers.get(network)


def _network_body_keys_ok(body: dict, required: set) -> bool:
    """Body must hold the required keys plus at most the network selector."""
    keys = set(body.keys())
    return required <= keys <= (required | {"network"})


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
    network, bad = _resolve_network(request)
    if bad is not None:
        return bad
    manager = _manager_for(request, network)
    snap = await manager.snapshot() if manager else {}
    return web.json_response({
        "ok": True,
        "version": VERSION,
        "network": network,
        "networks": _enabled_networks(state.config),
        "protocol_version": "0.0.37",
        "peak_height": snap.get("peak_height"),
        "peers": manager.peer_labels() if manager else [],
        "peers_connected": manager.connected_count() if manager else 0,
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
    if not _network_body_keys_ok(body, {"puzzle_hashes"}):
        return err("body must be {puzzle_hashes: [...]} with optional network")
    network, net_err = _resolve_network(request, body)
    if net_err is not None:
        return net_err
    manager = _manager_for(request, network)
    hashes = body["puzzle_hashes"]
    if not isinstance(hashes, list) or not (1 <= len(hashes) <= MAX_PUZZLE_HASHES):
        return err(f"puzzle_hashes must be a list of 1..{MAX_PUZZLE_HASHES} items")
    try:
        ph_bytes = [_hex32(h, f"puzzle_hashes[{i}]") for i, h in enumerate(hashes)]
    except StreamableError as e:
        return err(str(e))

    if manager is None:
        return err(f"network {network} not running", 503)
    try:
        states = await manager.get_coins(ph_bytes)
    except NoPeersError:
        return err("no peers connected", 503)
    except (PeerError, StreamableError, asyncio.TimeoutError) as e:
        log.warning("get_coins failed: %s", e)
        return err(f"peer request failed: {type(e).__name__}", 502)

    coins = sorted((coin_to_json(cs) for cs in states), key=lambda c: (c["created_height"] or 0))
    return web.json_response({"ok": True, "network": network, "coins": coins})


async def handle_coin(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    raw_id = request.match_info["coin_id"]
    try:
        coin_id = _hex32(raw_id, "coin_id")
    except StreamableError as e:
        return err(str(e))
    network, net_err = _resolve_network(request)
    if net_err is not None:
        return net_err
    manager = _manager_for(request, network)
    if manager is None:
        return err(f"network {network} not running", 503)

    try:
        cs = await manager.get_coin(coin_id)
    except NoPeersError:
        return err("no peers connected", 503)
    except (PeerError, StreamableError, asyncio.TimeoutError) as e:
        log.warning("get_coin failed: %s", e)
        return err(f"peer request failed: {type(e).__name__}", 502)
    if cs is None:
        return err("unknown coin", 404)
    return web.json_response({"ok": True, "network": network, "coin": coin_to_json(cs)})


async def handle_coin_ids(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    body = await _read_json(request)
    if not isinstance(body, dict):
        return err("body must be a JSON object")
    bad = check_forbidden_fields(body)
    if bad:
        return err(f"field {bad!r} not accepted: this relay never handles key material")
    if not _network_body_keys_ok(body, {"coin_ids"}):
        return err("body must be {coin_ids: [...]} with optional network")
    network, net_err = _resolve_network(request, body)
    if net_err is not None:
        return net_err
    manager = _manager_for(request, network)
    ids = body["coin_ids"]
    if not isinstance(ids, list) or not (1 <= len(ids) <= MAX_PUZZLE_HASHES):
        return err(f"coin_ids must be a list of 1..{MAX_PUZZLE_HASHES} items")
    try:
        id_bytes = [_hex32(i, f"coin_ids[{n}]") for n, i in enumerate(ids)]
    except StreamableError as e:
        return err(str(e))

    if manager is None:
        return err(f"network {network} not running", 503)
    try:
        states = await manager.get_coins_by_ids(id_bytes)
    except NoPeersError:
        return err("no peers connected", 503)
    except (PeerError, StreamableError, asyncio.TimeoutError) as e:
        log.warning("get_coins_by_ids failed: %s", e)
        return err(f"peer request failed: {type(e).__name__}", 502)

    found = {cs.coin.coin_id().hex(): coin_to_json(cs) for cs in states}
    coins = [found[cid] for cid in (b.hex() for b in id_bytes) if cid in found]
    not_found = [cid for cid in (b.hex() for b in id_bytes) if cid not in found]
    return web.json_response({"ok": True, "network": network, "coins": coins, "not_found": not_found})


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
    # Optional ?network= filter; omitted searches every network's records
    # (the historical behavior, when the log was single-network).
    want = request.query.get("network")
    if want is not None:
        want = want.strip().lower()
        if want not in _enabled_networks(state.config):
            return err(f"unknown network {want!r}")
    for record in state.broadcast_log:
        if record["txid"] == txid and (want is None or record.get("network") == want):
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
    if set(body.keys()) - {"spend_bundle", "spend_bundle_hex", "network"}:
        return err("body must be exactly {spend_bundle: hex} with optional network")
    network, net_err = _resolve_network(request, body)
    if net_err is not None:
        return net_err
    manager = _manager_for(request, network)
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
    if manager is None:
        return err(f"network {network} not running", 503)
    try:
        ack = await manager.broadcast(bundle)
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
        "network": network,
        "status": status,
        "status_name": status_name,
        "error": ack["error"],
        "coin_spends": len(parsed.coin_spends),
        "time": int(time.time()),
    }
    state.broadcast_log.appendleft(record)
    # Log txid + status only: never bundle contents, never tokens.
    log.info("broadcast txid=%s network=%s status=%s spends=%d",
             txid, network, status_name, len(parsed.coin_spends))
    if status_name == "FAILED":
        log.warning("broadcast FAILED txid=%s error=%s", txid, ack["error"])
    return web.json_response({
        "ok": True,
        "network": network,
        "txid": txid,
        "expected_txid": expected_txid,
        "status": status,
        "status_name": status_name,
        "error": ack["error"],
    })


async def handle_broadcasts(request: web.Request) -> web.Response:
    state: State = request.app["state"]
    want = request.query.get("network")
    if want is not None:
        want = want.strip().lower()
        if want not in _enabled_networks(state.config):
            return err(f"unknown network {want!r}")
    records = list(state.broadcast_log)
    if want is not None:
        records = [r for r in records if r.get("network") == want]
    return web.json_response({"ok": True, "broadcasts": records})


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

    for net in _enabled_networks(cfg):
        net_cfg = cfg.get("network_configs", {}).get(net, {})
        mgr_cfg = ManagerConfig(
            network_id=net,
            peer_port=net_cfg.get("peer_port", cfg.get("peer_port", 58444)),
            introducer_host=net_cfg.get("introducer_host", cfg.get("introducer_host", "")),
            peers_override=net_cfg.get("peers_override", cfg.get("peers_override")),
            max_peers=net_cfg.get("max_peers", cfg.get("max_peers", 3)),
        )
        manager = PeerManager(mgr_cfg, ssl_ctx, state.session)
        await manager.start()
        state.managers[net] = manager
        log.info("relay v%s: peer pool started for network %s", VERSION, net)
    log.info("relay v%s serving networks %s (default %s)",
             VERSION, _enabled_networks(cfg), cfg.get("network_id"))


async def on_cleanup(app: web.Application) -> None:
    state: State = app["state"]
    for net, manager in state.managers.items():
        try:
            await manager.stop()
        except Exception:  # noqa: BLE001
            log.exception("error stopping %s peer manager", net)
    state.managers.clear()
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

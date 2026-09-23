"""Relay v1 API tests — server handlers with a stubbed PeerManager.

No network, no real peers. The app is built with create_app() against a
test config, its on_startup hooks are stripped (they would open real WSS
connections), and app["state"].manager is replaced with a fake that
serves canned CoinStates. Auth uses the same bearer flow as production.
"""
import os
import sys
import time

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

pytest.importorskip("aiohttp")

from aiohttp.test_utils import TestClient, TestServer

import server
from streamable import Coin, CoinState


TOKEN = "test-token-" + "x" * 32

PH1 = "ab" * 32
PH2 = "cd" * 32
CID_UNKNOWN = "ff" * 32
TXID = "99" * 32


def _cs(ph_hex: str, amount: int, created: int, spent=None) -> CoinState:
    return CoinState(
        coin=Coin(bytes.fromhex("00" * 32), bytes.fromhex(ph_hex), amount),
        spent_height=spent,
        created_height=created,
    )


class FakeManager:
    """Minimal PeerManager double: canned coins, in-memory broadcast log."""

    def __init__(self):
        self.coins = [
            _cs(PH1, 2_000_000, 4_714_900),
            _cs(PH2, 5_000, 4_714_905, spent=4_715_000),
        ]
        self.real_ids = [cs.coin.coin_id().hex() for cs in self.coins]
        self.by_id = dict(zip(self.real_ids, self.coins))
        self.by_ph = {PH1: [self.coins[0]], PH2: [self.coins[1]]}
        self.broadcast_records = []

    async def snapshot(self):
        return {"peak_height": 4_715_123, "watched_puzzle_hashes": 2,
                "cached_coins": 2}

    def peer_labels(self):
        return [{"host": "peer.example", "port": 58444,
                 "connected": True, "protocol_version": "0.0.37"}]

    def connected_count(self):
        return 1

    async def get_coins(self, puzzle_hashes):
        out = []
        for ph in puzzle_hashes:
            out.extend(self.by_ph.get(ph.hex(), []))
        return out

    async def get_coins_by_ids(self, coin_ids):
        return [self.by_id[c.hex()] for c in coin_ids if c.hex() in self.by_id]

    async def get_coin(self, coin_id):
        ids = await self.get_coins_by_ids([coin_id])
        return ids[0] if ids else None

    async def broadcast(self, bundle: bytes):
        txid = bundle.hex()[:64]  # structural parse happens server-side
        rec = {"txid": txid, "status": 1, "status_name": "SUCCESS",
               "error": None, "coin_spends": 0, "time": int(time.time())}
        self.broadcast_records.append(rec)
        return {"txid": bytes.fromhex(txid), "status": 1, "error": None}


@pytest_asyncio.fixture
async def manager():
    return FakeManager()


@pytest_asyncio.fixture
async def client(manager):
    cfg = {
        "token": TOKEN,
        "network_id": "testnet11",
        "peer_port": 58444,
        "introducer_host": "dns-introducer-testnet11.chia.net",
        "peers_override": None,
        "max_peers": 3,
        "cert_dir": "./certs",
        "cors_origin": None,
        "port": 8000,
    }
    app = server.create_app(cfg)
    # Strip real startup/cleanup: no certs, no WSS, no sessions.
    app.on_startup.clear()
    app.on_cleanup.clear()
    app["state"].manager = manager
    cli = TestClient(TestServer(app))
    cli.relay_app = app  # test-only handle: seed/inspect server state
    await cli.start_server()
    yield cli
    await cli.close()


def _auth():
    return {"Authorization": f"Bearer {TOKEN}"}


# ---- auth -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_unauthenticated_rejected(client):
    async with client.get("/v1/status") as r:
        assert r.status == 401


@pytest.mark.asyncio
async def test_health_is_public(client):
    async with client.get("/health") as r:
        assert r.status == 200
        body = await r.json()
        assert body["ok"] is True


# ---- /v1/coin_ids -----------------------------------------------------------

@pytest.mark.asyncio
async def test_coin_ids_batch(client, manager):
    rid1, rid2 = manager.real_ids
    async with client.post("/v1/coin_ids",
                           json={"coin_ids": [rid1, rid2, CID_UNKNOWN]},
                           headers=_auth()) as r:
        assert r.status == 200
        body = await r.json()
    assert body["ok"] is True
    got = [c["coin_id"] for c in body["coins"]]
    # Request order preserved; unknown id reported, not an error.
    assert got == [rid1, rid2]
    assert body["not_found"] == [CID_UNKNOWN]


@pytest.mark.asyncio
async def test_coin_ids_validation(client):
    async with client.post("/v1/coin_ids", json={"coin_ids": []},
                           headers=_auth()) as r:
        assert r.status == 400
    async with client.post("/v1/coin_ids",
                           json={"coin_ids": ["zz" * 32]},
                           headers=_auth()) as r:
        assert r.status == 400
    async with client.post("/v1/coin_ids",
                           json={"wrong_key": []},
                           headers=_auth()) as r:
        assert r.status == 400
    # Key material is never accepted.
    async with client.post("/v1/coin_ids",
                           json={"coin_ids": [CID_UNKNOWN], "mnemonic": "x"},
                           headers=_auth()) as r:
        assert r.status == 400


@pytest.mark.asyncio
async def test_coin_ids_shape(client, manager):
    rid1 = manager.real_ids[0]
    async with client.post("/v1/coin_ids", json={"coin_ids": [rid1]},
                           headers=_auth()) as r:
        body = await r.json()
    coin = body["coins"][0]
    assert coin["amount_mojos"] == 2_000_000
    assert coin["created_height"] == 4_714_900
    assert coin["spent_height"] is None
    assert coin["puzzle_hash"] == PH1


# ---- /v1/broadcasts/{txid} --------------------------------------------------

@pytest.mark.asyncio
async def test_broadcast_tx_lookup(client, manager):
    client.relay_app["state"].broadcast_log.appendleft({
        "txid": TXID, "status": 1, "status_name": "SUCCESS",
        "error": None, "coin_spends": 2, "time": 1_700_000_000,
    })
    async with client.get(f"/v1/broadcasts/{TXID}",
                          headers=_auth()) as r:
        assert r.status == 200
        body = await r.json()
    assert body["ok"] is True
    assert body["broadcast"]["txid"] == TXID
    assert body["broadcast"]["status_name"] == "SUCCESS"


@pytest.mark.asyncio
async def test_broadcast_tx_unknown_is_404(client):
    async with client.get(f"/v1/broadcasts/{CID_UNKNOWN}",
                          headers=_auth()) as r:
        assert r.status == 404
        body = await r.json()
    assert body["ok"] is False


@pytest.mark.asyncio
async def test_broadcast_tx_bad_txid(client):
    async with client.get("/v1/broadcasts/not-a-txid",
                          headers=_auth()) as r:
        assert r.status == 400


# ---- regressions on existing endpoints -------------------------------------

@pytest.mark.asyncio
async def test_status_ok(client):
    async with client.get("/v1/status", headers=_auth()) as r:
        assert r.status == 200
        body = await r.json()
    assert body["version"] == server.VERSION
    assert body["network"] == "testnet11"
    assert body["peak_height"] == 4_715_123


@pytest.mark.asyncio
async def test_coins_by_puzzle_hash(client, manager):
    rid1 = manager.real_ids[0]
    async with client.post("/v1/coins", json={"puzzle_hashes": [PH1]},
                           headers=_auth()) as r:
        assert r.status == 200
        body = await r.json()
    assert [c["coin_id"] for c in body["coins"]] == [rid1]

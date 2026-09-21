"""Regression tests for _execute_chia_spend_via_relay (daemon.py).

Covers two bugs found in the 2026-09-21 API-contract audit:
1. The ledger's created-coin id was computed with the SPENT coin's
   parent_coin_info instead of the spent coin's own coin id.
2. A FAILED mempool broadcast was never detected: the relay returns the
   mempool status as an int (1/2/3) plus a status_name string, but the
   daemon compared the int to the string "FAILED" — never true, so a
   failed broadcast was recorded as submitted.

The fake relay below speaks the real relay contract
(GET /v1/status, POST /v1/coins, POST /v1/broadcast shapes).
"""
import json
import hashlib
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from spellbook import chia_sign, kdf
from spellbook.chia_relay import BroadcastUnknown, RelayError
from spellbook.daemon import Daemon

TEST_SEED_HEX = ("000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f")
AMOUNT = 1_000_000_000_000  # 1 XCH in mojos


def _write(path, data, mode=0o600):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)


class FakeRelayRpc:
    """Stands in for spellbook.chia_relay.RelayRpc."""

    def __init__(self, url, token, timeout=60):
        self.url = url
        self.token = token
        self.broadcast_body = None
        # Per-test overrides: status shapes go here; txids are derived
        # from the bundle the daemon actually sends (like the real
        # relay), unless a test sets broadcast_expected_txid /
        # broadcast_txid to simulate an identity mismatch.
        self.broadcast_result = {
            "ok": True, "status": 1, "status_name": "SUCCESS", "error": None,
        }
        self.broadcast_expected_txid = None
        self.broadcast_txid = None
        self.coin = None

    def status(self):
        return {"ok": True, "network": "testnet11", "peak_height": 4715326,
                "peers": [], "peers_connected": 3}

    def coins(self, puzzle_hashes):
        return [self.coin] if self.coin else []

    def broadcast(self, spend_bundle):
        # The daemon must send the documented field name; the fake speaks
        # the real contract: txids are sha256 of the bundle bytes it
        # received, exactly like relay/server.py computes them.
        self.broadcast_body = spend_bundle
        local_txid = hashlib.sha256(bytes.fromhex(spend_bundle)).hexdigest()
        res = dict(self.broadcast_result)
        res["expected_txid"] = (self.broadcast_expected_txid
                                if self.broadcast_expected_txid is not None
                                else local_txid)
        res["txid"] = (self.broadcast_txid
                       if self.broadcast_txid is not None
                       else local_txid)
        return res

    def coin(self, coin_id_hex):
        return {}


@pytest.fixture()
def daemon(tmp_path, monkeypatch):
    cfgdir = str(tmp_path)
    _write(os.path.join(cfgdir, "seed.key"), TEST_SEED_HEX)
    _write(os.path.join(cfgdir, "request.token"), "11" * 32)
    _write(os.path.join(cfgdir, "approve.token"), "22" * 32)
    _write(os.path.join(cfgdir, "spellbook.json"), json.dumps({
        "seed_path": os.path.join(cfgdir, "seed.key"),
        "labels": ["default"],
        "chia": {
            "network": "testnet11",
            "relay_urls": {"testnet11": "https://relay.example.com"},
            "relay_token": "t" * 32,
            "fee_mojos": 0,
            "relay_scan_indices": 10,
        },
    }))
    _write(os.path.join(cfgdir, "policy.json"), json.dumps({}))
    _write(os.path.join(cfgdir, "ledger.jsonl"), "")
    fake = FakeRelayRpc("https://relay.example.com", "t" * 32)
    import spellbook.chia_relay as relay_mod
    monkeypatch.setattr(relay_mod, "RelayRpc", lambda url, token, timeout=60: fake)
    d = Daemon(cfgdir)
    return d, fake


def _make_daemon_with_chia_cfg(tmp_path, monkeypatch, chia_cfg):
    """Daemon whose RelayRpc factory records instances per URL and lets
    each test script per-URL behavior (network, coin, broadcast)."""
    cfgdir = str(tmp_path)
    _write(os.path.join(cfgdir, "seed.key"), TEST_SEED_HEX)
    _write(os.path.join(cfgdir, "request.token"), "11" * 32)
    _write(os.path.join(cfgdir, "approve.token"), "22" * 32)
    _write(os.path.join(cfgdir, "spellbook.json"), json.dumps({
        "seed_path": os.path.join(cfgdir, "seed.key"),
        "labels": ["default"],
        "chia": chia_cfg,
    }))
    _write(os.path.join(cfgdir, "policy.json"), json.dumps({}))
    _write(os.path.join(cfgdir, "ledger.jsonl"), "")
    created = []
    behaviors = {}

    def factory(url, token, timeout=60):
        fake = FakeRelayRpc(url, token)
        for k, v in behaviors.get(url, {}).items():
            setattr(fake, k, v)
        created.append(fake)
        return fake

    import spellbook.chia_relay as relay_mod
    monkeypatch.setattr(relay_mod, "RelayRpc", factory)
    return Daemon(cfgdir), created, behaviors


def _fund_coin_for(seed: bytes, chain_label: str, index: int, amount: int):
    d = kdf.derive_labeled(seed, chain_label, "default")
    master_sk = bytes.fromhex(d["scalar_hex"])
    wsk = chia_sign.wallet_sk(master_sk, index)
    spk = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk))
    ph = chia_sign.puzzle_hash_for_synthetic_pk(spk)
    parent = bytes.fromhex("bb" * 32)
    coin_id = chia_sign.coin_id(parent, ph, amount).hex()
    return {
        "coin_id": coin_id,
        "parent_coin_info": parent.hex(),
        "puzzle_hash": ph.hex(),
        "amount_mojos": amount,
        "created_height": 100,
        "spent_height": None,
    }, ph


class TestRelayTransportSelection:
    def test_testnet_uses_testnet_relay_url(self, tmp_path, monkeypatch):
        d, created, behaviors = _make_daemon_with_chia_cfg(tmp_path, monkeypatch, {
            "network": "testnet11",
            "relay_urls": {"testnet11": "https://testnet.relay",
                           "mainnet": "https://mainnet.relay"},
            "relay_token": "t" * 32,
            "fee_mojos": 0,
        })
        seed = bytes.fromhex(TEST_SEED_HEX)
        coin, _ = _fund_coin_for(seed, "chia-testnet", 0, AMOUNT)
        behaviors["https://testnet.relay"] = {"coin": coin}
        dest_ph = _wallet_ph(seed, 1)
        out = d._execute_chia_spend_via_relay({
            "chain": "chia-testnet",
            "destination": chia_sign.address_for_puzzle_hash(dest_ph, "txch"),
            "amount_mojos": 100_000,
        })
        assert out["submitted"] is True
        assert [r.url for r in created] == ["https://testnet.relay"]

    def test_mainnet_uses_mainnet_relay_url(self, tmp_path, monkeypatch):
        d, created, behaviors = _make_daemon_with_chia_cfg(tmp_path, monkeypatch, {
            "network": "testnet11",
            "relay_urls": {"testnet11": "https://testnet.relay",
                           "mainnet": "https://mainnet.relay"},
            "relay_token": "t" * 32,
            "fee_mojos": 0,
            "mainnet_submit_enabled": True,
        })
        seed = bytes.fromhex(TEST_SEED_HEX)
        coin, _ = _fund_coin_for(seed, "chia-mainnet", 0, AMOUNT)
        mainnet_fake_status = {"ok": True, "network": "mainnet",
                               "peak_height": 1, "peers": [],
                               "peers_connected": 1}
        behaviors["https://mainnet.relay"] = {"coin": coin}

        import spellbook.chia_relay as relay_mod

        def factory(url, token, timeout=60):
            fake = FakeRelayRpc(url, token)
            fake.status = lambda: dict(mainnet_fake_status)
            for k, v in behaviors.get(url, {}).items():
                setattr(fake, k, v)
            created.append(fake)
            return fake

        monkeypatch.setattr(relay_mod, "RelayRpc", factory)
        # mainnet destination needs the xch1 prefix; derive it from the
        # mainnet KDF key (different label -> different key than testnet).
        d_main = kdf.derive_labeled(seed, "chia-mainnet", "default")
        msk = bytes.fromhex(d_main["scalar_hex"])
        wsk1 = chia_sign.wallet_sk(msk, 1)
        spk1 = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk1))
        dest_ph_m = chia_sign.puzzle_hash_for_synthetic_pk(spk1)
        out = d._execute_chia_spend_via_relay({
            "chain": "chia-mainnet",
            "destination": chia_sign.address_for_puzzle_hash(dest_ph_m, "xch"),
            "amount_mojos": 100_000,
        })
        assert out["submitted"] is True
        assert [r.url for r in created] == ["https://mainnet.relay"]

    def test_missing_relay_fails_closed(self, tmp_path, monkeypatch):
        d, created, _behaviors = _make_daemon_with_chia_cfg(
            tmp_path, monkeypatch, {
                "network": "testnet11",
                "relay_urls": {"mainnet": "https://mainnet.relay"},
                "relay_token": "t" * 32,
            })
        seed = bytes.fromhex(TEST_SEED_HEX)
        dest_ph = _wallet_ph(seed, 1)
        with pytest.raises(RelayError, match="no relay configured"):
            d._execute_chia_spend_via_relay({
                "chain": "chia-testnet",
                "destination": chia_sign.address_for_puzzle_hash(dest_ph, "txch"),
                "amount_mojos": 100_000,
            })
        assert created == []

    def test_network_mismatch_fails_closed(self, tmp_path, monkeypatch):
        d, created, behaviors = _make_daemon_with_chia_cfg(tmp_path, monkeypatch, {
            "network": "testnet11",
            "relay_urls": {"testnet11": "https://rogue.relay"},
            "relay_token": "t" * 32,
        })

        def factory(url, token, timeout=60):
            fake = FakeRelayRpc(url, token)
            fake.status = lambda: {"ok": True, "network": "mainnet",
                                   "peak_height": 1, "peers": [],
                                   "peers_connected": 1}
            created.append(fake)
            return fake

        import spellbook.chia_relay as relay_mod
        monkeypatch.setattr(relay_mod, "RelayRpc", factory)
        seed = bytes.fromhex(TEST_SEED_HEX)
        dest_ph = _wallet_ph(seed, 1)
        with pytest.raises(RelayError, match="relay network"):
            d._execute_chia_spend_via_relay({
                "chain": "chia-testnet",
                "destination": chia_sign.address_for_puzzle_hash(dest_ph, "txch"),
                "amount_mojos": 100_000,
            })

    def test_legacy_flat_relay_url_fallback(self, tmp_path, monkeypatch):
        d, created, behaviors = _make_daemon_with_chia_cfg(tmp_path, monkeypatch, {
            "network": "testnet11",
            "relay_url": "https://legacy.relay",
            "relay_token": "t" * 32,
            "fee_mojos": 0,
        })
        seed = bytes.fromhex(TEST_SEED_HEX)
        coin, _ = _fund_coin_for(seed, "chia-testnet", 0, AMOUNT)
        behaviors["https://legacy.relay"] = {"coin": coin}
        dest_ph = _wallet_ph(seed, 1)
        out = d._execute_chia_spend_via_relay({
            "chain": "chia-testnet",
            "destination": chia_sign.address_for_puzzle_hash(dest_ph, "txch"),
            "amount_mojos": 100_000,
        })
        assert out["submitted"] is True
        assert [r.url for r in created] == ["https://legacy.relay"]


def _wallet_ph(seed: bytes, index: int) -> bytes:
    d = kdf.derive_labeled(seed, "chia-testnet", "default")
    master_sk = bytes.fromhex(d["scalar_hex"])
    wsk = chia_sign.wallet_sk(master_sk, index)
    spk = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk))
    return chia_sign.puzzle_hash_for_synthetic_pk(spk)


def _fund_fake(fake, seed: bytes):
    """Give the fake relay one unspent coin on the wallet's index-0 key."""
    ph0 = _wallet_ph(seed, 0)
    parent = bytes.fromhex("aa" * 32)
    coin_id = chia_sign.coin_id(parent, ph0, AMOUNT).hex()
    fake.coin = {
        "coin_id": coin_id,
        "parent_coin_info": parent.hex(),
        "puzzle_hash": ph0.hex(),
        "amount_mojos": AMOUNT,
        "created_height": 4715322,
        "spent_height": None,
    }
    return fake.coin, ph0


def test_created_coin_id_uses_spent_coin_id(daemon):
    d, fake = daemon
    seed = bytes.fromhex(TEST_SEED_HEX)
    coin, _ph0 = _fund_fake(fake, seed)
    dest_ph = _wallet_ph(seed, 1)
    dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
    spend = 500_000_000_000

    out = d._execute_chia_spend_via_relay({
        "chain": "chia-testnet",
        "destination": dest_addr,
        "amount_mojos": spend,
    })

    # Correct: sha256(spent_coin_id || dest_ph || amount).
    expected = chia_sign.coin_id(bytes.fromhex(coin["coin_id"]),
                                 dest_ph, spend).hex()
    # The old bug: sha256(spent_coin_parent || dest_ph || amount).
    buggy = chia_sign.coin_id(bytes.fromhex(coin["parent_coin_info"]),
                              dest_ph, spend).hex()
    assert out["coin_id"] == expected
    assert out["coin_id"] != buggy
    assert out["submitted"] is True
    assert out["mempool_status"] == "SUCCESS"
    # Real bundle bytes went out under the documented field name.
    assert isinstance(fake.broadcast_body, str) and len(fake.broadcast_body) > 0


def test_failed_broadcast_raises(daemon):
    d, fake = daemon
    seed = bytes.fromhex(TEST_SEED_HEX)
    _fund_fake(fake, seed)
    dest_ph = _wallet_ph(seed, 1)
    dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
    fake.broadcast_result = {
        "ok": True, "status": 3, "status_name": "FAILED",
        "error": "double spend",
    }
    with pytest.raises(RelayError, match="FAILED"):
        d._execute_chia_spend_via_relay({
            "chain": "chia-testnet",
            "destination": dest_addr,
            "amount_mojos": 500_000_000_000,
        })


def test_pending_broadcast_does_not_raise(daemon):
    d, fake = daemon
    seed = bytes.fromhex(TEST_SEED_HEX)
    _fund_fake(fake, seed)
    dest_ph = _wallet_ph(seed, 1)
    dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
    fake.broadcast_result = {
        "ok": True, "status": 2, "status_name": "PENDING", "error": None,
    }
    out = d._execute_chia_spend_via_relay({
        "chain": "chia-testnet",
        "destination": dest_addr,
        "amount_mojos": 500_000_000_000,
    })
    assert out["submitted"] is True
    assert out["mempool_status"] == "PENDING"


class TestAuditFixes20260921:
    """Audit items 1-5 (2026-09-21): dispatch, broadcast field, "from"
    address, txid fail-closed."""

    def test_dispatch_selects_relay_with_only_relay_urls(self, daemon):
        # The fixture configures ONLY relay_urls (no flat relay_url).
        # The dispatcher must pick the relay path — no Sage fallthrough.
        d, fake = daemon
        seed = bytes.fromhex(TEST_SEED_HEX)
        _fund_fake(fake, seed)
        dest_ph = _wallet_ph(seed, 1)
        dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
        out = d._execute_chia_spend({
            "chain": "chia-testnet",
            "destination": dest_addr,
            "amount_mojos": 100_000,
        })
        assert out["submitted"] is True
        assert fake.url == "https://relay.example.com"
        assert fake.broadcast_body is not None

    def test_from_is_bech32m_address(self, daemon):
        d, fake = daemon
        seed = bytes.fromhex(TEST_SEED_HEX)
        coin, ph0 = _fund_fake(fake, seed)
        dest_ph = _wallet_ph(seed, 1)
        dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
        out = d._execute_chia_spend_via_relay({
            "chain": "chia-testnet",
            "destination": dest_addr,
            "amount_mojos": 500_000_000_000,
        })
        expected_addr = chia_sign.address_for_puzzle_hash(ph0, "txch")
        assert out["from"] == expected_addr
        assert out["from"].startswith("txch1")
        # Round-trips to the raw puzzle hash.
        assert chia_sign.puzzle_hash_for_address(out["from"]) == ph0

    def test_from_is_xch1_on_mainnet_shape(self, tmp_path, monkeypatch):
        # Mainnet address shape without touching a real relay.
        d, created, behaviors = _make_daemon_with_chia_cfg(
            tmp_path, monkeypatch, {
                "network": "mainnet",
                "relay_urls": {"mainnet": "https://mainnet.relay"},
                "relay_token": "t" * 32,
                "fee_mojos": 0,
                "mainnet_submit_enabled": True,
            })
        seed = bytes.fromhex(TEST_SEED_HEX)
        coin, _ = _fund_coin_for(seed, "chia-mainnet", 0, AMOUNT)
        behaviors["https://mainnet.relay"] = {"coin": coin}

        def factory(url, token, timeout=60):
            fake = FakeRelayRpc(url, token)
            fake.status = lambda: {"ok": True, "network": "mainnet",
                                   "peak_height": 1, "peers": [],
                                   "peers_connected": 1}
            for k, v in behaviors.get(url, {}).items():
                setattr(fake, k, v)
            created.append(fake)
            return fake

        import spellbook.chia_relay as relay_mod
        monkeypatch.setattr(relay_mod, "RelayRpc", factory)
        d_main = kdf.derive_labeled(seed, "chia-mainnet", "default")
        msk = bytes.fromhex(d_main["scalar_hex"])
        wsk0 = chia_sign.wallet_sk(msk, 0)
        spk0 = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk0))
        ph0 = chia_sign.puzzle_hash_for_synthetic_pk(spk0)
        wsk1 = chia_sign.wallet_sk(msk, 1)
        spk1 = chia_sign.synthetic_pk(chia_sign.pk_bytes(wsk1))
        dest_ph = chia_sign.puzzle_hash_for_synthetic_pk(spk1)
        out = d._execute_chia_spend_via_relay({
            "chain": "chia-mainnet",
            "destination": chia_sign.address_for_puzzle_hash(dest_ph, "xch"),
            "amount_mojos": 100_000,
        })
        assert out["from"] == chia_sign.address_for_puzzle_hash(ph0, "xch")
        assert out["from"].startswith("xch1")

    def test_expected_txid_mismatch_is_unknown_never_retry(self, daemon):
        d, fake = daemon
        seed = bytes.fromhex(TEST_SEED_HEX)
        _fund_fake(fake, seed)
        dest_ph = _wallet_ph(seed, 1)
        dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
        fake.broadcast_expected_txid = "00" * 32
        # Speechless (2026-09-21): txid mismatch after broadcast = UNKNOWN
        # fate, never safe-to-retry. Must raise BroadcastUnknown (not a
        # plain RelayError), so the daemon ledgers approved-submit-unknown
        # and consumes velocity fail-closed.
        with pytest.raises(BroadcastUnknown, match="expected_txid"):
            d._execute_chia_spend_via_relay({
                "chain": "chia-testnet",
                "destination": dest_addr,
                "amount_mojos": 500_000_000_000,
            })

    def test_missing_expected_txid_fails_closed(self, daemon):
        d, fake = daemon
        seed = bytes.fromhex(TEST_SEED_HEX)
        _fund_fake(fake, seed)
        dest_ph = _wallet_ph(seed, 1)
        dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
        fake.broadcast_expected_txid = ""
        with pytest.raises(RelayError, match="expected_txid"):
            d._execute_chia_spend_via_relay({
                "chain": "chia-testnet",
                "destination": dest_addr,
                "amount_mojos": 500_000_000_000,
            })

    def test_peer_txid_mismatch_is_unknown_never_retry(self, daemon):
        d, fake = daemon
        seed = bytes.fromhex(TEST_SEED_HEX)
        _fund_fake(fake, seed)
        dest_ph = _wallet_ph(seed, 1)
        dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
        fake.broadcast_txid = "ff" * 32
        with pytest.raises(BroadcastUnknown, match="peer-ack txid"):
            d._execute_chia_spend_via_relay({
                "chain": "chia-testnet",
                "destination": dest_addr,
                "amount_mojos": 500_000_000_000,
            })

    def test_txid_mismatch_ledgers_unknown_and_consumes_velocity(self, daemon):
        # End-to-end through rt_request_spend (auto-approved): the decision
        # must be "approved-submit-unknown", the ledger must carry the
        # approved-submit-unknown line, and the 24h velocity must be
        # consumed fail-closed (not refunded, not retried).
        d, fake = daemon
        seed = bytes.fromhex(TEST_SEED_HEX)
        _fund_fake(fake, seed)
        dest_ph = _wallet_ph(seed, 1)
        dest_addr = chia_sign.address_for_puzzle_hash(dest_ph, "txch")
        spend = 500_000_000_000
        d.policy.auto_approve_below[("chia-testnet", "native")] = spend
        fake.broadcast_expected_txid = "00" * 32
        assert d.spent_last_24h("chia-testnet", "native") == 0
        out = d.rt_request_spend({
            "chain": "chia-testnet",
            "destination": dest_addr,
            "amount_mojos": spend,
            "purpose": "mismatch drill",
        }, "test-muse")
        assert out["ok"] is True
        assert out["decision"] == "approved-submit-unknown"
        rows = d.ledger.read_all()
        assert any("approved-submit-unknown" in r.get("decision", "")
                   for r in rows), rows
        # Velocity consumed fail-closed: the spend counts against the 24h
        # window even though its fate is unknown.
        assert d.spent_last_24h("chia-testnet", "native") == spend

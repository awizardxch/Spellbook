"""Tests for spellbook.chia — Sage RPC client helpers and mTLS transport.

The transport test spins up a real TLS server on loopback that mimics
Sage's WalletCertVerifier (client must present exactly the wallet cert)
and serves canned JSON. openssl is used to mint the throwaway test cert;
no key material in these tests is real.
"""
import hashlib
import http.server
import json
import os
import socket
import ssl
import subprocess
import threading

import pytest

from spellbook import chia
from spellbook.chia import (BroadcastUnknown, SageError, SageRpc,
                             amount_to_int, chia_fingerprint)


# ---------------------------------------------------------------- helpers

def test_amount_int_passthrough():
    assert amount_to_int(123) == 123
    assert amount_to_int(0) == 0


def test_amount_numeric_string():
    assert amount_to_int("1000000") == 1000000


def test_amount_hex_string():
    assert amount_to_int("0x10") == 16


def test_amount_bool_rejected():
    with pytest.raises(SageError):
        amount_to_int(True)


def test_amount_garbage_rejected():
    with pytest.raises((SageError, ValueError)):
        amount_to_int("not-a-number")
    with pytest.raises(SageError):
        amount_to_int(None)
    with pytest.raises(SageError):
        amount_to_int([1])


def test_fingerprint_construction():
    # Independent reimplementation of the formula: catches endianness or
    # slicing regressions in chia_fingerprint.
    pubkey = "a" * 96  # 48-byte hex placeholder
    expected = int.from_bytes(hashlib.sha256(bytes.fromhex(pubkey)).digest()[:4],
                              "big")
    assert chia_fingerprint(pubkey) == expected
    assert 0 <= chia_fingerprint(pubkey) < 2 ** 32


def test_fingerprint_differs_per_key():
    assert chia_fingerprint("a" * 96) != chia_fingerprint("b" * 96)


# ------------------------------------------------- mTLS round-trip server

def _mint_cert(d):
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "wallet.key", "-out", "wallet.crt",
         "-days", "1", "-subj", "/CN=sage-test"],
        cwd=d, check=True, capture_output=True)


class _Handler(http.server.BaseHTTPRequestHandler):
    expected_der = b""

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        peer = self.connection.getpeercert(binary_form=True)
        if peer != _Handler.expected_der:
            self._send(403, "client certificate not allowed", "text/plain")
            return
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path == "/get_sync_status":
            self._send(200, json.dumps({
                "selectable_balance": "1234567",
                "receive_address": "txch1test...",
            }))
        elif self.path == "/boom":
            # Sage returns errors as plain text on non-2xx.
            self._send(400, "something went wrong in sage", "text/plain")
        else:
            self._send(404, "not found", "text/plain")

    def log_message(self, *a):
        pass


@pytest.fixture()
def mtls_server(tmp_path):
    ssl_dir = tmp_path / "ssl"
    ssl_dir.mkdir()
    _mint_cert(str(ssl_dir))
    der = ssl_dir.joinpath("wallet.crt").read_bytes()
    # openssl emits PEM; convert to DER for the comparison.
    pem = der
    b64 = b"".join(l for l in pem.splitlines()
                   if not l.startswith(b"-----"))
    import base64
    _Handler.expected_der = base64.b64decode(b64)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(ssl_dir / "wallet.crt"),
                               keyfile=str(ssl_dir / "wallet.key"))
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    server_ctx.load_verify_locations(cafile=str(ssl_dir / "wallet.crt"))

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    srv.socket = server_ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield str(tmp_path), port
    srv.shutdown()
    t.join()


def test_sage_rpc_round_trip(mtls_server):
    data_dir, port = mtls_server
    rpc = SageRpc(data_dir, port=port)
    out = rpc.call("get_sync_status", {})
    assert out["selectable_balance"] == "1234567"
    assert out["receive_address"] == "txch1test..."


def test_sage_rpc_error_text_surfaces(mtls_server):
    data_dir, port = mtls_server
    rpc = SageRpc(data_dir, port=port)
    with pytest.raises(SageError) as ei:
        rpc.call("boom", {})
    assert "something went wrong in sage" in str(ei.value)
    assert "400" in str(ei.value)


def test_sage_rpc_missing_certs(tmp_path):
    with pytest.raises(SageError):
        SageRpc(str(tmp_path / "empty"))


def test_sage_rpc_wrong_cert_rejected(mtls_server, tmp_path):
    # A client presenting a *different* cert must fail the TLS handshake,
    # exactly like Sage's WalletCertVerifier rejects unknown client certs.
    _data_dir, port = mtls_server
    other = tmp_path / "other"
    (other / "ssl").mkdir(parents=True)
    _mint_cert(str(other / "ssl"))
    rpc = SageRpc(str(other), port=port)
    with pytest.raises(SageError):
        rpc.call("get_sync_status", {})


# ------------------------------------------------- wait_for_outgoing

class _FakeRpc:
    def __init__(self, txs):
        self.txs = txs

    def recent_transactions(self, limit=10):
        return self.txs[:limit]


def test_wait_for_outgoing_matches_dest_and_amount():
    tx = {"timestamp": 1_700_000_100, "height": 5, "created": [
        {"coin_id": "0xabc", "amount": "5000", "address": "txch1dest"},
        {"coin_id": "0xdef", "amount": 3, "address": "txch1change"},
    ]}
    rpc = _FakeRpc([tx])
    found = chia.wait_for_outgoing(rpc, "txch1dest", 5000,
                                   since_ts=1_700_000_000,
                                   timeout_s=5, poll_s=0.01)
    assert found["height"] == 5


def test_wait_for_outgoing_ignores_wrong_amount():
    tx = {"timestamp": 1_700_000_100, "height": 5, "created": [
        {"coin_id": "0xabc", "amount": "9999", "address": "txch1dest"},
    ]}
    rpc = _FakeRpc([tx])
    with pytest.raises(SageError):
        chia.wait_for_outgoing(rpc, "txch1dest", 5000,
                               since_ts=1_700_000_000,
                               timeout_s=0.2, poll_s=0.01)


def test_wait_for_outgoing_ignores_old_tx():
    tx = {"timestamp": 1_000, "height": 5, "created": [
        {"coin_id": "0xabc", "amount": "5000", "address": "txch1dest"},
    ]}
    rpc = _FakeRpc([tx])
    with pytest.raises(SageError):
        chia.wait_for_outgoing(rpc, "txch1dest", 5000,
                               since_ts=1_700_000_000,
                               timeout_s=0.2, poll_s=0.01)


# ------------------------------------------------- daemon _execute_chia_spend

import sys
sys.path.insert(0, "tests")

from spellbook import kdf as _kdf
from spellbook.daemon import Daemon


def _daemon_with_seed(tmp_path, monkeypatch):
    def w(name, data):
        p = tmp_path / name
        p.write_text(data)
        os.chmod(p, 0o600)

    seed_hex = "42" * 32
    w("seed.key", seed_hex)
    data_home = tmp_path / "sagehome"
    (data_home / "com.rigidnetwork.sage").mkdir(parents=True)
    cfg = {
        "seed_path": str(tmp_path / "seed.key"),
        "chia_enabled": True,
        "chia": {
            "sage_bin": "/nonexistent/sage",
            "sage_data_home": str(data_home),
            "rpc_port": 9257,
            "fee_mojos": 0,
        },
    }
    w("spellbook.json", json.dumps(cfg))
    w("policy.json", "{}")
    w("request.token", "aa" * 32)
    w("approve.token", "bb" * 32)
    w("ledger.jsonl", "")
    d = Daemon(str(tmp_path))
    # Never spawn a real Sage in unit tests.
    monkeypatch.setattr(Daemon, "_ensure_sage_rpc", lambda self: None)
    return d, seed_hex


class _FakeSage:
    """Stands in for chia.SageRpc. Behavior knobs per test."""

    def __init__(self, data_dir, port=9257, host="127.0.0.1", timeout=60):
        self.data_dir = data_dir
        self.keys = {}          # fingerprint -> key_hex
        self.balance = 10 ** 12
        self.balances = {}      # fingerprint -> balance (selection-aware)
        self.addresses = {}     # fingerprint -> address
        self.selected = None    # fingerprint Sage currently has logged in
        self.import_returns = None  # override fingerprint on import
        self.sent = []
        self.networks = []
        self.sent_cats = []     # (asset_id, address, amount, fee)
        self.sent_nfts = []     # (nft_ids, address, fee)
        self.cat_balances = {}  # asset_id.lower() -> CAT mojos
        self.cats_echo_asset = True  # created CAT coins carry asset_id

    def set_network(self, name):
        self.network = name
        self.networks.append(name)

    def get_keys(self):
        return [{"fingerprint": fp} for fp in self.keys]

    def import_key(self, name, key_hex, derivation_count=100):
        fp = self.import_returns
        if fp is None:
            # fingerprint the key the same way Chia does: sha256 of the
            # master *public* key derived from this secret scalar.
            pub = _kdf.bls_g1_pubkey(int(key_hex, 16)).hex()
            fp = chia.chia_fingerprint(pub)
        self.keys[fp] = key_hex
        return fp

    def login(self, fingerprint):
        assert fingerprint in self.keys
        self.selected = fingerprint

    def wallet_address(self, fingerprint, network_id):
        return self.addresses.get(fingerprint, "txch1senderaddress")

    def sync_status(self):
        # Sage reports the *selected* wallet — mirror that, so tests can
        # prove a foreign selected wallet never leaks into status reads.
        if self.selected is not None:
            return {"selectable_balance": self.balances.get(self.selected,
                                                            self.balance),
                    "receive_address": self.addresses.get(
                        self.selected, "txch1senderaddress")}
        return {"selectable_balance": self.balance,
                "receive_address": "txch1senderaddress"}

    def send_xch(self, address, amount_mojos, fee_mojos=0, memos=None):
        self.sent.append((address, amount_mojos, fee_mojos))
        return {"summary": {"fee": fee_mojos, "inputs": []}, "coin_spends": []}

    def send_cat(self, asset_id, address, amount_mojos, fee_mojos=0, memos=None):
        self.sent_cats.append((asset_id, address, amount_mojos, fee_mojos))
        self._last_cat = (asset_id, address, amount_mojos)
        return {"summary": {"fee": fee_mojos, "inputs": []}, "coin_spends": []}

    def get_cats(self):
        return [{"asset_id": k, "balance": v}
                for k, v in self.cat_balances.items()]

    def transfer_nfts(self, nft_ids, address, fee_mojos=0):
        self.sent_nfts.append((list(nft_ids), address, fee_mojos))
        self._last_nft = (list(nft_ids), address)
        return {"summary": {"fee": fee_mojos, "inputs": []}, "coin_spends": []}

    def recent_transactions(self, limit=5):
        import time as _time
        ts = int(_time.time())
        if getattr(self, "_last_nft", None):
            nft_ids, addr = self._last_nft
            return [{"height": 9, "timestamp": ts,
                     "spent": [{"coin_id": nft_ids[0]}],
                     "created": [{"coin_id": "0xnftcoin2", "amount": 1,
                                  "address": addr, "nft_id": nft_ids[0]}]}]
        if getattr(self, "_last_cat", None):
            asset_id, addr, amount = self._last_cat
            coin = {"coin_id": "0xcatcoin1", "amount": amount,
                    "address": addr}
            if self.cats_echo_asset:
                coin["asset_id"] = asset_id
            return [{"height": 9, "timestamp": ts, "created": [coin]}]
        addr, amount, _fee = self.sent[-1]
        return [{"height": 9, "timestamp": ts, "created": [
            {"coin_id": "0xcoin1", "amount": amount, "address": addr}]}]


def _spend_params(dest="txch1destination", amount=1_000_000, chain="chia-testnet"):
    p = {"chain": chain, "destination": dest, "asset": "native",
         "purpose": "drill"}
    p["amount_mojos"] = amount
    return p


def test_daemon_chia_spend_happy_path(tmp_path, monkeypatch):
    d, seed_hex = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    out = d._execute_chia_spend(_spend_params())
    assert out["submitted"] is True
    assert out["coin_id"] == "0xcoin1" and out["tx_hash"] == "0xcoin1"
    assert fake.network == "testnet11"
    assert fake.sent == [("txch1destination", 1_000_000, 0)]
    # key was imported exactly once, with the KDF-derived secret
    assert len(fake.keys) == 1
    derived = _kdf.derive_labeled(bytes.fromhex(seed_hex), "chia-testnet", "default")
    assert list(fake.keys.values())[0] == derived["scalar_hex"]


def test_daemon_chia_spend_reuses_imported_key(tmp_path, monkeypatch):
    d, seed_hex = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    derived = _kdf.derive_labeled(bytes.fromhex(seed_hex), "chia-testnet", "default")
    fp = chia.chia_fingerprint(derived["pubkey_hex"])
    fake.keys[fp] = derived["scalar_hex"]
    calls = []
    orig = fake.import_key
    fake.import_key = lambda *a, **k: (calls.append(1), orig(*a, **k))[1]
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    d._execute_chia_spend(_spend_params())
    assert calls == []  # no re-import when the fingerprint is already there


def test_daemon_chia_spend_fingerprint_mismatch(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    fake.import_returns = 12345  # wrong fingerprint from the RPC
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    with pytest.raises(SageError, match="fingerprint"):
        d._execute_chia_spend(_spend_params())


def test_daemon_chia_spend_insufficient_balance(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    fake.balance = 10
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    with pytest.raises(SageError, match="insufficient"):
        d._execute_chia_spend(_spend_params())


def test_daemon_chia_spend_guards(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    # wei on a Chia chain
    p = _spend_params(); p["amount_wei"] = 5; del p["amount_mojos"]
    with pytest.raises(SageError, match="wei"):
        d._execute_chia_spend(p)
    # wrong address prefix
    with pytest.raises(SageError, match="txch1"):
        d._execute_chia_spend(_spend_params(dest="xch1mainnetaddr"))
    # mainnet without the flag
    with pytest.raises(SageError, match="mainnet"):
        d._execute_chia_spend(_spend_params(chain="chia-mainnet",
                                           dest="xch1mainnetaddr"))
    assert fake.sent == []  # nothing ever reached Sage


def test_daemon_chia_request_spend_end_to_end(tmp_path, monkeypatch):
    """Through rt_request_spend with a human-configured policy: below the
    auto-approve level the daemon executes; the SageError surface is the
    same shape as the EVM one."""
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    from spellbook.policy import Policy
    d.policy = Policy(auto_approve_below={("chia-testnet", "native"): 2_000_000})
    fake = _FakeSage("x")
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    resp = d.rt_request_spend(_spend_params(), "muse_test")
    assert resp["ok"] is True and resp["decision"] == "approved"
    assert resp["tx_hash"] == "0xcoin1"
    # velocity was consumed on the approved chain
    assert d.spent_last_24h("chia-testnet", "native") == 1_000_000


def test_rt_status_ignores_foreign_selected_wallet(tmp_path, monkeypatch):
    """Regression: Sage reports whichever wallet was logged in last. A
    foreign wallet left selected (e.g. the drill script logging into the
    destination wallet to derive its address) must not change the
    balance/address rt_status reports for the daemon's own wallet."""
    d, seed_hex = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    foreign_fp = 42424242
    fake.keys[foreign_fp] = "00" * 32
    fake.balances[foreign_fp] = 777_000_000_000
    fake.addresses[foreign_fp] = "txch1foreignwallethere"
    fake.selected = foreign_fp  # Sage left logged into the foreign wallet
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    out = d.rt_status({}, "muse_test")
    assert out["ok"] is True
    bal = out["balances"]["chia-testnet"]
    assert "error" not in bal, bal
    derived = _kdf.derive_labeled(bytes.fromhex(seed_hex), "chia-testnet",
                                  "default")
    daemon_fp = chia.chia_fingerprint(derived["pubkey_hex"])
    assert fake.selected == daemon_fp  # status re-selected the daemon wallet
    assert bal["balance_mojos"] == fake.balance  # daemon's, not 777e9
    assert bal["address"] == "txch1senderaddress"
    assert bal["address"] != "txch1foreignwallethere"


def test_rt_status_imports_daemon_key_before_any_spend(tmp_path, monkeypatch):
    """O10: the agent surfaces its balance/address independently of ever
    submitting a spend — status imports the KDF wallet when missing."""
    d, seed_hex = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")  # no keys imported yet
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    out = d.rt_status({}, "muse_test")
    bal = out["balances"]["chia-testnet"]
    assert "error" not in bal, bal
    derived = _kdf.derive_labeled(bytes.fromhex(seed_hex), "chia-testnet",
                                  "default")
    daemon_fp = chia.chia_fingerprint(derived["pubkey_hex"])
    assert fake.keys.get(daemon_fp) == derived["scalar_hex"]
    assert fake.selected == daemon_fp
    assert bal["balance_mojos"] == fake.balance


def test_wait_for_outgoing_timeout_is_broadcast_unknown():
    rpc = _FakeRpc([])  # nothing ever appears
    with pytest.raises(BroadcastUnknown):
        chia.wait_for_outgoing(rpc, "txch1dest", 5, since_ts=1_700_000_000,
                               timeout_s=0.2, poll_s=0.05)


def test_daemon_chia_broadcast_unknown_ledgers_reference(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    from spellbook.policy import Policy
    d.policy = Policy(auto_approve_below={("chia-testnet", "native"): 2_000_000})
    fake = _FakeSage("x")
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    monkeypatch.setattr(
        chia, "wait_for_outgoing",
        lambda *a, **k: (_ for _ in ()).throw(
            chia.BroadcastUnknown("0xcoin9", "submitted, confirmation unknown")))
    resp = d.rt_request_spend(_spend_params(), "muse_test")
    assert resp["ok"] is True
    assert resp["decision"] == "approved-submit-unknown"
    assert resp["tx_hash"] == "0xcoin9"
    # velocity consumed fail-closed, hash ledgered as unresolved
    assert d.spent_last_24h("chia-testnet", "native") == 1_000_000
    rows = d.ledger.read_all()
    assert any(r["decision"].startswith("approved-submit-unknown")
               and r["sighash"] == "0xcoin9" for r in rows)


# ----------------------------------------------- chia_asset_kind

from spellbook.daemon import chia_asset_kind


def test_asset_kind_native():
    assert chia_asset_kind("native") == ("native", None)


def test_asset_kind_cat_hex_normalized():
    aid = "a" * 64
    assert chia_asset_kind(aid) == ("cat", aid)
    assert chia_asset_kind("A" * 64) == ("cat", aid)


def test_asset_kind_nft_coin_id():
    assert chia_asset_kind("nft:" + "b" * 64) == ("nft", "b" * 64)


def test_asset_kind_nft_bech32m():
    assert chia_asset_kind("nft:nft1qpzry9x8gf2tvdw0s3jn54khce6mua7l")[0] == "nft"


@pytest.mark.parametrize("bad", [
    "", "BTC", "xch", "native ", "nft:", "nft:xyz", "cat:xxx",
    "a" * 63, "a" * 65, "0x" + "a" * 64, "g" * 64, None, 123, ["a" * 64],
])
def test_asset_kind_rejects_garbage(bad):
    with pytest.raises(SageError):
        chia_asset_kind(bad)


# ----------------------------------------------- request-time validation

def test_request_spend_rejects_bad_asset(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    p = _spend_params()
    p["asset"] = "DOGE"
    out = d.rt_request_spend(p, "muse_test")
    assert out["ok"] is False


def test_request_spend_rejects_nft_amount_not_one(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    p = _spend_params(amount=2)
    p["asset"] = "nft:" + "c" * 64
    out = d.rt_request_spend(p, "muse_test")
    assert out["ok"] is False
    assert "singleton" in out["error"]


def test_request_spend_accepts_cat_shape(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    p = _spend_params(amount=5)
    p["asset"] = "d" * 64
    out = d.rt_request_spend(p, "muse_test")
    assert out["ok"] is True and out["decision"] == "queued"  # S4: no policy


def test_request_spend_accepts_nft_shape(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    p = _spend_params(amount=1)
    p["asset"] = "nft:" + "e" * 64
    out = d.rt_request_spend(p, "muse_test")
    assert out["ok"] is True and out["decision"] == "queued"  # S4: no policy


# ----------------------------------------------- SageRpc bodies

def _bare_rpc():
    return SageRpc.__new__(SageRpc)


def test_send_cat_body():
    captured = {}
    rpc = _bare_rpc()
    rpc.call = lambda endpoint, body: captured.update(
        endpoint=endpoint, body=body) or {}
    rpc.send_cat("a" * 64, "txch1x", 100, 10, memos=["m"])
    assert captured["endpoint"] == "send_cat"
    assert captured["body"] == {
        "asset_id": "a" * 64, "address": "txch1x", "amount": 100,
        "fee": 10, "memos": ["m"], "auto_submit": True}


def test_transfer_nfts_body():
    captured = {}
    rpc = _bare_rpc()
    rpc.call = lambda endpoint, body: captured.update(
        endpoint=endpoint, body=body) or {}
    rpc.transfer_nfts(["0x" + "b" * 62], "txch1y", 5)
    assert captured["endpoint"] == "transfer_nfts"
    assert captured["body"] == {
        "nft_ids": ["0x" + "b" * 62], "address": "txch1y",
        "fee": 5, "auto_submit": True}


def test_get_cats_body():
    captured = {}
    rpc = _bare_rpc()
    rpc.call = lambda endpoint, body: captured.update(
        endpoint=endpoint, body=body) or {"cats": []}
    assert rpc.get_cats() == []
    assert captured["endpoint"] == "get_cats"


def test_cat_balance_found_and_missing():
    rpc = _bare_rpc()
    rpc.call = lambda endpoint, body: {"cats": [
        {"asset_id": "a" * 64, "balance": "5000"}]} if endpoint == "get_cats" else {}
    assert chia.cat_balance(rpc, "a" * 64) == 5000
    assert chia.cat_balance(rpc, "A" * 64) == 5000  # case-insensitive
    with pytest.raises(SageError):
        chia.cat_balance(rpc, "f" * 64)


# ----------------------------------------------- verification matchers

def test_wait_for_outgoing_matches_asset_ref():
    aid = "a" * 64
    tx = {"timestamp": 1_700_000_100, "created": [
        {"coin_id": "0x1", "amount": 5000, "address": "txch1dest",
         "asset_id": aid},
    ]}
    rpc = _FakeRpc([tx])
    found = chia.wait_for_outgoing(rpc, "txch1dest", 5000,
                                   since_ts=1_700_000_000,
                                   timeout_s=5, poll_s=0.01, asset_ref=aid)
    assert found is tx


def test_wait_for_outgoing_rejects_wrong_asset_ref():
    tx = {"timestamp": 1_700_000_100, "created": [
        {"coin_id": "0x1", "amount": 5000, "address": "txch1dest",
         "asset_id": "b" * 64},
    ]}
    rpc = _FakeRpc([tx])
    with pytest.raises(SageError):
        chia.wait_for_outgoing(rpc, "txch1dest", 5000,
                               since_ts=1_700_000_000,
                               timeout_s=0.2, poll_s=0.01,
                               asset_ref="a" * 64)


def test_wait_for_outgoing_rejects_missing_asset_field():
    # Sage must echo the asset on the coin record — silence fails closed.
    tx = {"timestamp": 1_700_000_100, "created": [
        {"coin_id": "0x1", "amount": 5000, "address": "txch1dest"},
    ]}
    rpc = _FakeRpc([tx])
    with pytest.raises(SageError):
        chia.wait_for_outgoing(rpc, "txch1dest", 5000,
                               since_ts=1_700_000_000,
                               timeout_s=0.2, poll_s=0.01,
                               asset_ref="a" * 64)


def test_wait_for_nft_transfer_matches_spent_and_dest():
    tx = {"timestamp": 1_700_000_100,
          "spent": [{"coin_id": "0xnft"}],
          "created": [{"coin_id": "0xnft2", "amount": 1,
                       "address": "txch1dest"}]}
    rpc = _FakeRpc([tx])
    found = chia.wait_for_nft_transfer(rpc, "0xnft", "txch1dest",
                                       since_ts=1_700_000_000,
                                       timeout_s=5, poll_s=0.01)
    assert found is tx


def test_wait_for_nft_transfer_ignores_unrelated_tx():
    tx = {"timestamp": 1_700_000_100,
          "spent": [{"coin_id": "0xother"}],
          "created": [{"coin_id": "0x1", "amount": 1,
                       "address": "txch1dest"}]}
    rpc = _FakeRpc([tx])
    with pytest.raises(SageError):
        chia.wait_for_nft_transfer(rpc, "0xnft", "txch1dest",
                                   since_ts=1_700_000_000,
                                   timeout_s=0.2, poll_s=0.01)


# ----------------------------------------------- daemon CAT/NFT paths

def _cat_params(dest="txch1catdest", amount=250_000, aid=None):
    p = _spend_params(dest=dest, amount=amount)
    p["asset"] = aid or "f" * 64
    return p


def test_daemon_cat_spend_happy_path(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    fake.cat_balances["f" * 64] = 1_000_000
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    out = d._execute_chia_spend(_cat_params())
    assert out["submitted"] is True
    assert out["asset_id"] == "f" * 64
    assert out["coin_id"] == "0xcatcoin1" and out["tx_hash"] == "0xcatcoin1"
    assert fake.sent_cats == [("f" * 64, "txch1catdest", 250_000, 0)]
    assert fake.sent == []  # no XCH send happened


def test_daemon_cat_spend_insufficient_balance(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    fake.cat_balances["f" * 64] = 100
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    with pytest.raises(SageError, match="insufficient CAT balance"):
        d._execute_chia_spend(_cat_params())
    assert fake.sent_cats == []


def test_daemon_cat_spend_missing_cat_fails_closed(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")  # no CATs in wallet at all
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    with pytest.raises(SageError, match="not in wallet"):
        d._execute_chia_spend(_cat_params())
    assert fake.sent_cats == []


def test_daemon_cat_spend_no_asset_echo_is_unknown(tmp_path, monkeypatch):
    # Sage sent the CAT but its tx record doesn't echo the asset id:
    # verification fails closed -> BroadcastUnknown (no false success).
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    d.chia_cfg["sage_wait_timeout_s"] = 1
    fake = _FakeSage("x")
    fake.cat_balances["f" * 64] = 1_000_000
    fake.cats_echo_asset = False
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    with pytest.raises(SageError):
        d._execute_chia_spend(_cat_params())


def test_daemon_nft_spend_happy_path(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    fake = _FakeSage("x")
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    nid = "0" * 64
    p = _spend_params(dest="txch1nftdest", amount=1)
    p["asset"] = "nft:" + nid
    out = d._execute_chia_spend(p)
    assert out["submitted"] is True
    assert out["nft_id"] == nid
    assert out["coin_id"] == "0xnftcoin2" and out["tx_hash"] == "0xnftcoin2"
    assert fake.sent_nfts == [([nid], "txch1nftdest", 0)]
    assert fake.sent == [] and fake.sent_cats == []


def test_execute_chia_spend_cat_ignores_relay_config(tmp_path, monkeypatch):
    # Even with a relay configured, CATs route to Sage (relay is XCH-only).
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    d.chia_cfg["relay_urls"] = {"testnet11": "https://example.invalid"}
    fake = _FakeSage("x")
    fake.cat_balances["f" * 64] = 1_000_000
    monkeypatch.setattr(chia, "SageRpc", lambda *a, **k: fake)
    out = d._execute_chia_spend(_cat_params())
    assert out["submitted"] is True
    assert fake.sent_cats != []


def test_relay_path_refuses_cat(tmp_path, monkeypatch):
    from spellbook import chia_relay
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    with pytest.raises(chia_relay.RelayError, match="native-XCH only"):
        d._execute_chia_spend_via_relay(_cat_params())


def test_relay_path_refuses_nft(tmp_path, monkeypatch):
    from spellbook import chia_relay
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    p = _spend_params(dest="txch1nftdest", amount=1)
    p["asset"] = "nft:" + "0" * 64
    with pytest.raises(chia_relay.RelayError, match="native-XCH only"):
        d._execute_chia_spend_via_relay(p)

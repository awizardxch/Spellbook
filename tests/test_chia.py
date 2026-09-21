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
from spellbook.chia import SageError, SageRpc, amount_to_int, chia_fingerprint


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
        self.import_returns = None  # override fingerprint on import
        self.sent = []

    def set_network(self, name):
        self.network = name

    def get_keys(self):
        return [{"fingerprint": fp} for fp in self.keys]

    def import_key(self, name, key_hex):
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

    def wallet_address(self, fingerprint, network_id):
        return "txch1senderaddress"

    def sync_status(self):
        return {"selectable_balance": self.balance,
                "receive_address": "txch1senderaddress"}

    def send_xch(self, address, amount_mojos, fee_mojos=0, memos=None):
        self.sent.append((address, amount_mojos, fee_mojos))
        return {"summary": {"fee": fee_mojos, "inputs": []}, "coin_spends": []}

    def recent_transactions(self, limit=5):
        import time as _time
        addr, amount, _fee = self.sent[-1]
        return [{"height": 9, "timestamp": int(_time.time()), "created": [
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

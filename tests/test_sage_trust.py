"""S-01: the daemon must only ever talk to ITS Sage.

Pure-function tests of the Sage client and the daemon's wallet-selection
logic; no Unix socket, no live Sage. The TLS tests start real loopback
listeners: one with an unrelated self-signed certificate (an impostor on
Sage's port) and one with the data dir's own wallet.crt. The client must
refuse the impostor during the handshake — before a single request byte,
let alone a key, is written — and accept the matching listener.

openssl mints the throwaway certificates; no key material here is real.
"""
import json
import os
import socket
import ssl
import subprocess
import threading

import pytest

from spellbook import chia
from spellbook.chia import SageError, SageRpc, cert_fingerprint
from spellbook.daemon import Daemon
from spellbook.policy import Policy

SEED = bytes.fromhex("42" * 32)
CHAIN = "chia-testnet"


# ----------------------------------------------------------- cert helpers

def _mint_cert(d, cn):
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", "wallet.key", "-out", "wallet.crt",
         "-days", "1", "-subj", f"/CN={cn}"],
        cwd=d, check=True, capture_output=True)


@pytest.fixture()
def sage_dir(tmp_path):
    """A fake Sage data dir with its own ssl/wallet.crt + wallet.key."""
    d = tmp_path / "com.rigidnetwork.sage"
    (d / "ssl").mkdir(parents=True)
    _mint_cert(str(d / "ssl"), "sage-real")
    return d


@pytest.fixture()
def impostor_dir(tmp_path):
    d = tmp_path / "impostor"
    d.mkdir()
    _mint_cert(str(d), "sage-impostor")
    return d


class _Listener:
    """One-shot TLS listener recording whether a handshake completed and
    what application bytes (if any) arrived."""

    def __init__(self, crt, key, require_client_cert_from=None):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=crt, keyfile=key)
        if require_client_cert_from:
            # Mimic Sage's WalletCertVerifier: the client must present the
            # wallet cert.
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=require_client_cert_from)
        else:
            ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self.box = {"handshake": False, "data": b"", "error": None}
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except Exception as e:
            self.box["error"] = repr(e)
            return
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
            self.box["handshake"] = True
            tls.settimeout(2)
            data = self._read_request(tls)
            self.box["data"] = data
            if data:
                body = json.dumps({"keys": []}).encode()
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: "
                            b"application/json\r\nContent-Length: "
                            + str(len(body)).encode() + b"\r\n\r\n" + body)
            tls.close()
        except Exception as e:
            self.box["error"] = repr(e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _read_request(tls) -> bytes:
        """Read one whole HTTP request (headers + Content-Length body).
        Replying with request bytes still unread makes Linux reset the
        connection on close, which drops the reply in flight."""
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(65536)
                if not chunk:
                    return data
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    length = int(value.strip())
            while len(body) < length:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                body += chunk
                data += chunk
        except Exception:
            pass
        return data

    def join(self):
        self.thread.join(5)
        self.sock.close()


# ------------------------------------------------- the pin, as a function

def test_cert_fingerprint_pem_equals_der(sage_dir):
    pem = (sage_dir / "ssl" / "wallet.crt").read_bytes()
    der = ssl.PEM_cert_to_DER_cert(pem.decode())
    assert cert_fingerprint(pem) == cert_fingerprint(der)
    assert len(cert_fingerprint(pem)) == 64


def test_client_records_disk_pin_and_requires_it_to_match_config(sage_dir):
    pin = chia.cert_fingerprint_of_file(str(sage_dir / "ssl" / "wallet.crt"))
    rpc = SageRpc(str(sage_dir), port=1)
    assert rpc.pin == pin
    # The recorded config pin must equal the cert on disk...
    assert SageRpc(str(sage_dir), port=1, cert_fingerprint=pin.upper()).pin == pin
    # ...and a replaced cert (or a wrong pin) fails closed at construction.
    with pytest.raises(SageError, match="does not match the configured"):
        SageRpc(str(sage_dir), port=1, cert_fingerprint="00" * 32)
    with pytest.raises(SageError, match="64-hex"):
        SageRpc(str(sage_dir), port=1, cert_fingerprint="nope")


def test_client_context_verifies_the_server(sage_dir):
    rpc = SageRpc(str(sage_dir), port=1)
    assert rpc._ctx.verify_mode == ssl.CERT_REQUIRED
    assert rpc._ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN


# ----------------------------------------------- the probe: impostor first

def test_client_refuses_impostor_listener_before_sending(sage_dir, impostor_dir):
    """An unrelated self-signed cert on Sage's port: the client must abort
    in the handshake. The listener never completes a handshake and never
    receives application data — so no /import_key, no key."""
    srv = _Listener(str(impostor_dir / "wallet.crt"),
                    str(impostor_dir / "wallet.key"))
    rpc = SageRpc(str(sage_dir), port=srv.port, timeout=5)
    with pytest.raises(SageError):
        rpc.call("get_keys")
    srv.join()
    assert srv.box["handshake"] is False
    assert srv.box["data"] == b""


def test_probe_refuses_impostor(sage_dir, impostor_dir):
    srv = _Listener(str(impostor_dir / "wallet.crt"),
                    str(impostor_dir / "wallet.key"))
    rpc = SageRpc(str(sage_dir), port=srv.port, timeout=5)
    with pytest.raises(SageError):
        rpc.probe()
    srv.join()
    assert srv.box["handshake"] is False
    assert srv.box["data"] == b""


def test_client_accepts_listener_with_the_pinned_cert(sage_dir):
    crt = str(sage_dir / "ssl" / "wallet.crt")
    key = str(sage_dir / "ssl" / "wallet.key")
    srv = _Listener(crt, key, require_client_cert_from=crt)
    rpc = SageRpc(str(sage_dir), port=srv.port, timeout=5,
                  cert_fingerprint=chia.cert_fingerprint_of_file(crt))
    assert rpc.call("get_keys") == {"keys": []}
    srv.join()
    assert srv.box["handshake"] is True
    assert srv.box["data"].startswith(b"POST /get_keys")


def test_probe_accepts_pinned_listener_and_sends_nothing(sage_dir):
    crt = str(sage_dir / "ssl" / "wallet.crt")
    key = str(sage_dir / "ssl" / "wallet.key")
    srv = _Listener(crt, key, require_client_cert_from=crt)
    rpc = SageRpc(str(sage_dir), port=srv.port, timeout=5)
    assert rpc.probe() == rpc.pin
    srv.join()
    # The client closes as soon as its side of the handshake has verified
    # the pin, so whether the server's wrap_socket has returned by then is
    # a transport detail; what matters is that nothing was ever sent.
    assert srv.box["data"] == b""


def test_pin_compare_is_independent_of_chain_verification(sage_dir):
    """Even when the trust store would accept the server, a leaf whose
    fingerprint is not the pin is refused after the handshake and before
    any request is written."""
    crt = str(sage_dir / "ssl" / "wallet.crt")
    key = str(sage_dir / "ssl" / "wallet.key")
    srv = _Listener(crt, key, require_client_cert_from=crt)
    rpc = SageRpc(str(sage_dir), port=srv.port, timeout=5)
    rpc.pin = "00" * 32  # simulate a recorded pin for a different cert
    with pytest.raises(SageError, match="does not match the pinned"):
        rpc.call("get_keys")
    srv.join()
    assert srv.box["data"] == b""


# --------------------------------------------- daemon: no runtime import

class _FakeRpc:
    def __init__(self, keys=(), probe_error=None):
        self.keys = set(keys)
        self.imported = []
        self.logged_in = None
        self.network = None
        self.probe_error = probe_error
        self.pin = "ab" * 32

    def set_network(self, name):
        self.network = name

    def get_keys(self):
        return [{"fingerprint": fp} for fp in self.keys]

    def import_key(self, name, key_hex, derivation_count=100):
        self.imported.append(name)
        from spellbook import kdf
        fp = chia.chia_fingerprint(kdf.bls_g1_pubkey(int(key_hex, 16)).hex())
        self.keys.add(fp)
        return fp

    def login(self, fp):
        assert fp in self.keys
        self.logged_in = fp

    def wallet_address(self, fp, network_id):
        return "txch1daemonaddress"

    def probe(self):
        if self.probe_error:
            raise SageError(self.probe_error)
        return self.pin


def _bare_daemon(tmp_path, chia_cfg=None):
    """A Daemon without the socket/config machinery: just the attributes
    the Sage selection path reads."""
    d = Daemon.__new__(Daemon)
    d.config_dir = str(tmp_path)
    d.cfg = {"chia_enabled": True}
    d.chia_cfg = dict(chia_cfg or {"sage_data_home": str(tmp_path),
                                   "rpc_port": 9257})
    d.policy = Policy()
    d.key_derivation = "kdf"
    d.seed = SEED
    d.std_seed = None
    d._sage_proc = None
    d._sage_started_pid = None
    d._sage_listener_preexisting = False
    return d


def _expected_fp(d):
    return d._chia_expected_fingerprint(CHAIN)


def test_chia_wallet_fails_closed_when_fingerprint_absent(tmp_path):
    d = _bare_daemon(tmp_path)
    rpc = _FakeRpc()
    with pytest.raises(SageError, match="not provisioned"):
        d._chia_wallet(rpc, CHAIN)
    assert rpc.imported == []          # the secret never left the daemon
    assert rpc.logged_in is None


def test_chia_wallet_logs_in_by_fingerprint_when_provisioned(tmp_path):
    d = _bare_daemon(tmp_path)
    fp = _expected_fp(d)
    rpc = _FakeRpc(keys=[fp])
    got_fp, addr = d._chia_wallet(rpc, CHAIN)
    assert got_fp == fp and rpc.logged_in == fp
    assert addr == "txch1daemonaddress"
    assert rpc.imported == []
    assert rpc.network == "testnet11"


def test_runtime_import_only_behind_unsafe_flag(tmp_path):
    d = _bare_daemon(tmp_path)
    d.chia_cfg["sage_runtime_key_import"] = True
    rpc = _FakeRpc()
    got_fp, _ = d._chia_wallet(rpc, CHAIN)
    assert rpc.imported == ["spellbook-default"]
    assert got_fp == _expected_fp(d)


def test_sage_provision_imports_once_and_records_the_pin(tmp_path, monkeypatch):
    d = _bare_daemon(tmp_path)
    cfg_path = tmp_path / "spellbook.json"
    cfg_path.write_text(json.dumps({"chia": dict(d.chia_cfg)}))
    os.chmod(cfg_path, 0o600)
    rpc = _FakeRpc()
    monkeypatch.setattr(d, "_ensure_sage_rpc", lambda: None)
    monkeypatch.setattr(d, "_sage_client", lambda: rpc)
    out = d.sage_provision(CHAIN)
    assert out["imported"] is True and out["fingerprint"] == _expected_fp(d)
    assert out["cert_fingerprint"] == rpc.pin
    saved = json.loads(cfg_path.read_text())
    assert saved["chia"]["sage_cert_fingerprint"] == rpc.pin
    assert d.chia_cfg["sage_cert_fingerprint"] == rpc.pin
    # Second run: nothing to import, pin already recorded (not rewritten).
    out2 = d.sage_provision(CHAIN)
    assert out2["imported"] is False
    assert rpc.imported == ["spellbook-default"]


def test_preexisting_listener_is_probed_and_refused_on_pin_mismatch(
        tmp_path, monkeypatch):
    """Something answered on the port before this daemon started any Sage:
    it is used only if its certificate matches the pin."""
    d = _bare_daemon(tmp_path)
    monkeypatch.setattr(d, "_sage_rpc_ready", lambda: True)
    bad = _FakeRpc(probe_error="certificate does not match the pinned")
    monkeypatch.setattr(d, "_sage_client", lambda: bad)
    with pytest.raises(SageError, match="already on the port"):
        d._ensure_sage_rpc()
    assert d._sage_listener_preexisting is True
    good = _FakeRpc()
    monkeypatch.setattr(d, "_sage_client", lambda: good)
    d._ensure_sage_rpc()  # pin matches: accepted


def test_sage_client_passes_configured_pin(tmp_path, monkeypatch):
    seen = {}

    class _Rpc:
        def __init__(self, data_dir, port=9257, cert_fingerprint=None, **k):
            seen.update(data_dir=data_dir, port=port,
                        cert_fingerprint=cert_fingerprint)

    monkeypatch.setattr(chia, "SageRpc", _Rpc)
    (tmp_path / "com.rigidnetwork.sage").mkdir()
    d = _bare_daemon(tmp_path, {"sage_data_home": str(tmp_path),
                                "rpc_port": 9999,
                                "sage_cert_fingerprint": "cd" * 32})
    d._sage_client()
    assert seen["cert_fingerprint"] == "cd" * 32
    assert seen["port"] == 9999
    assert seen["data_dir"].endswith("com.rigidnetwork.sage")


def test_chia_sage_rpc_goes_through_pinned_client(tmp_path, monkeypatch):
    d = _bare_daemon(tmp_path)
    rpc = _FakeRpc(keys=[_expected_fp(d)])
    calls = []
    monkeypatch.setattr(d, "_ensure_sage_rpc", lambda: calls.append("ensure"))
    monkeypatch.setattr(d, "_sage_client", lambda: (calls.append("client"), rpc)[1])
    got, fp, addr = d._chia_sage_rpc(CHAIN)
    assert got is rpc and fp == _expected_fp(d)
    assert calls == ["ensure", "client"]


def test_rt_status_uses_the_guarded_path(tmp_path, monkeypatch):
    """Status must not build its own client: it goes through
    _chia_sage_rpc (ensure + pinned client + login by fingerprint)."""
    d = _bare_daemon(tmp_path)
    d.cfg = {"chia_enabled": True}
    d.evm_cfg = {}
    d.solana_cfg = {}
    d.queue = {}
    monkeypatch.setattr(d, "unresolved_executions", lambda: [])
    monkeypatch.setattr(d, "_active_solana_chain",
                        lambda: (_ for _ in ()).throw(RuntimeError("no solana")))

    class _StatusRpc(_FakeRpc):
        def sync_status(self):
            return {"selectable_balance": "777"}

    rpc = _StatusRpc(keys=[_expected_fp(d)])
    used = []
    monkeypatch.setattr(d, "_chia_sage_rpc",
                        lambda chain: (used.append(chain),
                                       (rpc, _expected_fp(d), "txch1x"))[1])
    monkeypatch.setattr(chia, "SageRpc",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("status built an unpinned client")))
    out = d.rt_status({}, "m")
    assert used == [CHAIN]
    assert out["balances"]["chia-testnet"] == {"address": "txch1x",
                                               "balance_mojos": 777}

"""Tests for src/spellbook/chia_relay.py — RelayRpc fail-closed behavior.

These test input validation and error paths without a live relay.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from spellbook.chia_relay import RelayRpc, RelayError, BroadcastUnknown
from spellbook import chia_relay


class TestInit:
    def test_bad_url_rejected(self):
        with pytest.raises(RelayError):
            RelayRpc("", "a" * 32)
        with pytest.raises(RelayError):
            RelayRpc("not-a-url", "a" * 32)
        with pytest.raises(RelayError):
            RelayRpc("ftp://example.com", "a" * 32)

    def test_short_token_rejected(self):
        with pytest.raises(RelayError):
            RelayRpc("https://relay.example.com", "")
        with pytest.raises(RelayError):
            RelayRpc("https://relay.example.com", "short")

    def test_ok(self):
        r = RelayRpc("https://relay.example.com", "a" * 32)
        assert r._host == "relay.example.com"
        assert r._port == 443


class TestCoinsValidation:
    def setup_method(self):
        self.r = RelayRpc("https://relay.example.com", "a" * 32)

    def test_not_a_list(self):
        with pytest.raises(RelayError):
            self.r.coins("not-a-list")

    def test_too_many(self):
        with pytest.raises(RelayError):
            self.r.coins(["ab" * 32] * 51)

    def test_bad_hash_length(self):
        with pytest.raises(RelayError):
            self.r.coins(["ab" * 16])

    def test_bad_hash_hex(self):
        with pytest.raises(RelayError):
            self.r.coins(["zz" * 32])

    def test_non_string_hash(self):
        with pytest.raises(RelayError):
            self.r.coins([12345])


class TestBroadcastValidation:
    def setup_method(self):
        self.r = RelayRpc("https://relay.example.com", "a" * 32)

    def test_empty_hex(self):
        with pytest.raises(RelayError):
            self.r.broadcast("")

    def test_bad_hex(self):
        with pytest.raises(RelayError):
            self.r.broadcast("zzzz")

    def test_too_large(self):
        # 5MB + 1 byte
        with pytest.raises(RelayError):
            self.r.broadcast("ab" * (5 * 1024 * 1024 + 1))


class TestCoinValidation:
    def setup_method(self):
        self.r = RelayRpc("https://relay.example.com", "a" * 32)

    def test_bad_coin_id(self):
        with pytest.raises(RelayError):
            self.r.coin("short")
        with pytest.raises(RelayError):
            self.r.coin("zz" * 32)


class TestMempoolStatus:
    def test_known_statuses(self):
        assert chia_relay.MEMPOOL_STATUS[1] == "SUCCESS"
        assert chia_relay.MEMPOOL_STATUS[2] == "PENDING"
        assert chia_relay.MEMPOOL_STATUS[3] == "FAILED"


class TestBroadcastUnknown:
    def test_is_relay_error(self):
        e = BroadcastUnknown("ref123", "note")
        assert isinstance(e, RelayError)
        assert e.reference == "ref123"


class TestBroadcastRequestShape:
    """The relay documents {spend_bundle: hex}; assert the exact field."""

    def test_sends_documented_spend_bundle_field(self):
        r = RelayRpc("https://relay.example.com", "a" * 32)
        captured = {}

        def fake_request(method, path, body=None):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = body
            return {"ok": True, "txid": "ab" * 32,
                    "expected_txid": "ab" * 32, "status": 1,
                    "status_name": "SUCCESS", "error": None}

        r._request = fake_request
        bundle = "ab" * 128
        r.broadcast(bundle)
        assert captured["method"] == "POST"
        assert captured["path"] == "/v1/broadcast"
        assert captured["body"] == {"spend_bundle": bundle}
        assert "spend_bundle_hex" not in captured["body"]


class _FakeCoinRpc:
    """Minimal rpc.coin() double for wait_for_confirmation."""

    def __init__(self, script):
        # script: list of ("ok", coin_dict) or ("404", None) or
        # ("err", RelayError).
        self.script = list(script)
        self.calls = 0

    def coin(self, coin_id_hex):
        self.calls += 1
        kind, payload = self.script.pop(0)
        if kind == "ok":
            return {"ok": True, "coin": dict(payload)}
        if kind == "flat":
            return dict(payload)
        if kind == "404":
            raise RelayError(
                f"relay GET /v1/coin/{coin_id_hex} -> HTTP 404: "
                '{"ok": false, "error": "unknown coin"}')
        raise payload


class TestWaitForConfirmation:
    CID = "cd" * 32

    def test_spent_coin_confirmed(self):
        rpc = _FakeCoinRpc([
            ("ok", {"coin_id": self.CID, "spent_height": None,
                    "created_height": 100}),
            ("ok", {"coin_id": self.CID, "spent_height": 4715400,
                    "created_height": 100}),
        ])
        coin = chia_relay.wait_for_confirmation(rpc, self.CID, poll_s=0)
        assert coin["spent_height"] == 4715400
        assert rpc.calls == 2

    def test_nested_coin_envelope_parsed(self):
        # Regression: the relay nests under "coin"; top-level fields must
        # not be read (they are absent -> would spin until timeout).
        rpc = _FakeCoinRpc([
            ("ok", {"coin_id": self.CID, "spent_height": 9,
                    "created_height": 8}),
        ])
        coin = chia_relay.wait_for_confirmation(rpc, self.CID, poll_s=0)
        assert coin["coin_id"] == self.CID
        assert rpc.calls == 1

    def test_404_tolerated_while_polling(self):
        rpc = _FakeCoinRpc([
            ("404", None),
            ("404", None),
            ("ok", {"coin_id": self.CID, "spent_height": 12,
                    "created_height": 10}),
        ])
        coin = chia_relay.wait_for_confirmation(rpc, self.CID, poll_s=0)
        assert coin["spent_height"] == 12
        assert rpc.calls == 3

    def test_created_mode_waits_for_coin_to_appear(self):
        rpc = _FakeCoinRpc([
            ("404", None),
            ("ok", {"coin_id": self.CID, "spent_height": None,
                    "created_height": 4715401}),
        ])
        coin = chia_relay.wait_for_confirmation(
            rpc, self.CID, poll_s=0, created=True)
        assert coin["created_height"] == 4715401

    def test_created_mode_ignores_spent_height_none(self):
        # A fresh change coin has spent_height None; created=True must
        # NOT treat that as unconfirmed-forever.
        rpc = _FakeCoinRpc([
            ("ok", {"coin_id": self.CID, "spent_height": None,
                    "created_height": 4715401}),
        ])
        coin = chia_relay.wait_for_confirmation(
            rpc, self.CID, poll_s=0, created=True)
        assert coin["created_height"] == 4715401
        assert rpc.calls == 1

    def test_timeout_raises_broadcast_unknown(self):
        rpc = _FakeCoinRpc([
            ("ok", {"coin_id": self.CID, "spent_height": None,
                    "created_height": 100}),
        ])
        with pytest.raises(BroadcastUnknown) as ei:
            chia_relay.wait_for_confirmation(rpc, self.CID,
                                             timeout_s=0, poll_s=0)
        assert ei.value.reference == self.CID

    def test_non_404_error_raises_immediately(self):
        rpc = _FakeCoinRpc([
            ("err", RelayError("relay transport failure on GET /v1/coin")),
        ])
        with pytest.raises(RelayError, match="transport failure"):
            chia_relay.wait_for_confirmation(rpc, self.CID, poll_s=0)
        assert rpc.calls == 1

    def test_flat_shape_tolerated(self):
        rpc = _FakeCoinRpc([
            ("flat", {"spent_height": 7, "created_height": 6}),
        ])
        coin = chia_relay.wait_for_confirmation(rpc, self.CID, poll_s=0)
        assert coin["spent_height"] == 7


class TestProxyEgress:
    """RelayRpc honors https_proxy with no_proxy bypass (sandbox egress)."""

    def _rpc(self, url):
        return chia_relay.RelayRpc(url, "t" * 32, timeout=5)

    def test_no_proxy_env_direct_connection(self, monkeypatch):
        monkeypatch.delenv("https_proxy", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        monkeypatch.delenv("all_proxy", raising=False)
        monkeypatch.delenv("ALL_PROXY", raising=False)
        rpc = self._rpc("https://relay.example:8443")
        conn = rpc._connection()
        assert isinstance(conn, chia_relay.http.client.HTTPSConnection)
        assert conn.host == "relay.example" and conn.port == 8443

    def test_remote_host_tunnels_through_proxy(self, monkeypatch):
        monkeypatch.setenv("https_proxy", "http://user:pw@proxy.internal:3128")
        monkeypatch.setenv("no_proxy", "localhost,127.0.0.1")
        rpc = self._rpc("https://spellbook-production.up.railway.app")
        conn = rpc._connection()
        # Connection targets the proxy...
        assert conn.host == "proxy.internal" and conn.port == 3128
        # ...with a CONNECT tunnel to the real relay host.
        assert conn._tunnel_host == "spellbook-production.up.railway.app"
        assert conn._tunnel_port == 443

    def test_no_proxy_bypass_stays_direct(self, monkeypatch):
        monkeypatch.setenv("https_proxy", "http://proxy.internal:3128")
        monkeypatch.setenv("no_proxy", "localhost,127.0.0.1")
        rpc = self._rpc("http://127.0.0.1:18789")
        conn = rpc._connection()
        assert isinstance(conn, chia_relay.http.client.HTTPConnection)
        assert conn.host == "127.0.0.1" and conn.port == 18789
        assert conn._tunnel_host is None


class TestTokenProvider:
    """RelayRpc accepts a per-request token provider (connector auth)."""

    def _fake_conn(self, captured):
        class FakeResp:
            status = 200

            def read(self):
                return b'{"ok": true}'

        class FakeConn:
            def request(self, method, path, body=None, headers=None):
                captured["headers"] = headers

            def getresponse(self):
                return FakeResp()

            def close(self):
                pass

        return FakeConn()

    def test_provider_used_for_bearer_header(self):
        calls = []

        def provider(url):
            calls.append(url)
            return "hsurr:test-surrogate"

        r = RelayRpc("https://relay.example.com", token_provider=provider)
        captured = {}
        r._connection = lambda: self._fake_conn(captured)
        out = r._request("GET", "/v1/status")
        assert out == {"ok": True}
        assert (captured["headers"]["Authorization"]
                == "Bearer hsurr:test-surrogate")
        assert calls == ["https://relay.example.com"]

    def test_provider_called_per_request(self):
        n = [0]

        def provider(url):
            n[0] += 1
            return f"hsurr:{n[0]}"

        r = RelayRpc("https://relay.example.com", token_provider=provider)
        assert r._bearer() == "hsurr:1"
        assert r._bearer() == "hsurr:2"

    def test_provider_failure_is_relay_error(self):
        def provider(url):
            raise RuntimeError("authd down")

        r = RelayRpc("https://relay.example.com", token_provider=provider)
        with pytest.raises(RelayError, match="credential provider failed"):
            r._bearer()

    def test_non_callable_provider_rejected(self):
        with pytest.raises(RelayError):
            RelayRpc("https://relay.example.com", token_provider="not-callable")

    def test_static_token_still_works(self):
        r = RelayRpc("https://relay.example.com", "a" * 32)
        assert r._bearer() == "a" * 32

    def test_empty_token_without_provider_rejected(self):
        with pytest.raises(RelayError):
            RelayRpc("https://relay.example.com")


class TestCoinIdsValidation:
    def setup_method(self):
        self.r = RelayRpc("https://relay.example.com", "a" * 32)

    def test_not_a_list(self):
        with pytest.raises(RelayError):
            self.r.coin_ids("not-a-list")

    def test_empty(self):
        with pytest.raises(RelayError):
            self.r.coin_ids([])

    def test_too_many(self):
        with pytest.raises(RelayError):
            self.r.coin_ids(["ab" * 32] * 51)

    def test_bad_id_length(self):
        with pytest.raises(RelayError):
            self.r.coin_ids(["ab" * 16])

    def test_bad_id_hex(self):
        with pytest.raises(RelayError):
            self.r.coin_ids(["zz" * 32])

    def test_non_string_id(self):
        with pytest.raises(RelayError):
            self.r.coin_ids([12345])


class TestCoinIdsShape:
    """POST /v1/coin_ids request/response contract."""

    def test_sends_documented_body_and_returns_split(self):
        r = RelayRpc("https://relay.example.com", "a" * 32)
        captured = {}
        cid = "ab" * 32

        def fake_request(method, path, body=None):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = body
            return {"ok": True,
                    "coins": [{"coin_id": cid, "amount_mojos": 2_000_000}],
                    "not_found": ["ff" * 32]}

        r._request = fake_request
        out = r.coin_ids([cid])
        assert captured["method"] == "POST"
        assert captured["path"] == "/v1/coin_ids"
        assert captured["body"] == {"coin_ids": [cid]}
        assert out["coins"][0]["coin_id"] == cid
        assert out["not_found"] == ["ff" * 32]

    def test_bad_response_shape_rejected(self):
        r = RelayRpc("https://relay.example.com", "a" * 32)
        r._request = lambda *a, **k: {"ok": True, "coins": []}  # no not_found
        with pytest.raises(RelayError):
            r.coin_ids(["ab" * 32])
        r._request = lambda *a, **k: {"ok": True}  # neither list
        with pytest.raises(RelayError):
            r.coin_ids(["ab" * 32])


class TestBroadcastStatusValidation:
    def setup_method(self):
        self.r = RelayRpc("https://relay.example.com", "a" * 32)

    def test_short_txid(self):
        with pytest.raises(RelayError):
            self.r.broadcast_status("ab" * 16)

    def test_bad_txid_hex(self):
        with pytest.raises(RelayError):
            self.r.broadcast_status("zz" * 32)

    def test_non_string(self):
        with pytest.raises(RelayError):
            self.r.broadcast_status(12345)


class TestBroadcastStatusShape:
    """GET /v1/broadcasts/{txid} request/response contract."""

    def test_returns_record(self):
        r = RelayRpc("https://relay.example.com", "a" * 32)
        captured = {}
        txid = "ab" * 32
        record = {"txid": txid, "status": 1, "status_name": "SUCCESS",
                  "error": None, "coin_spends": 2, "time": 1700000000}

        def fake_request(method, path, body=None):
            captured["method"] = method
            captured["path"] = path
            return {"ok": True, "broadcast": record}

        r._request = fake_request
        out = r.broadcast_status(txid)
        assert captured["method"] == "GET"
        assert captured["path"] == f"/v1/broadcasts/{txid}"
        assert out == record

    def test_bad_shape_rejected(self):
        r = RelayRpc("https://relay.example.com", "a" * 32)
        r._request = lambda *a, **k: {"ok": True}  # no broadcast key
        with pytest.raises(RelayError):
            r.broadcast_status("ab" * 32)

    def test_404_propagates_for_caller(self):
        """An unseen txid is a 404 RelayError — the caller decides
        whether that means 'never submitted here' vs. 'wrong relay'."""
        r = RelayRpc("https://relay.example.com", "a" * 32)

        def fake_request(method, path, body=None):
            raise RelayError(
                f"relay GET {path} -> HTTP 404: "
                '{"ok": false, "error": "txid not seen in broadcast log"}')

        r._request = fake_request
        with pytest.raises(RelayError, match="HTTP 404"):
            r.broadcast_status("ab" * 32)


class TestNetworkSelector:
    """The optional network selector is passed through to the relay;
    omitted, requests are exactly the historical shape."""

    def _spy(self):
        r = RelayRpc("https://relay.example.com", "a" * 32)
        calls = []

        def fake_request(method, path, body=None):
            calls.append((method, path, body))
            return {"ok": True, "coins": [], "not_found": [],
                    "network": "testnet11", "peak_height": 1, "peers": []}

        r._request = fake_request
        return r, calls

    def test_coins_omitted_by_default(self):
        r, calls = self._spy()
        r.coins(["ab" * 32])
        assert calls == [("POST", "/v1/coins", {"puzzle_hashes": ["ab" * 32]})]

    def test_coins_network_in_body(self):
        r, calls = self._spy()
        r.coins(["ab" * 32], network="mainnet")
        method, path, body = calls[0]
        assert body["network"] == "mainnet"
        assert body["puzzle_hashes"] == ["ab" * 32]

    def test_coin_network_in_query(self):
        r, calls = self._spy()
        r.coin("ab" * 32, network="mainnet")
        method, path, body = calls[0]
        assert method == "GET" and path == "/v1/coin/{0}?network=mainnet".format("ab" * 32)

    def test_status_network_in_query(self):
        r, calls = self._spy()
        r.status(network="mainnet")
        assert calls[0][1] == "/v1/status?network=mainnet"

    def test_broadcast_network_in_body(self):
        r, calls = self._spy()
        r._request = lambda m, p, body=None: (calls.append((m, p, body)),
                                              {"ok": True, "txid": "ab" * 32})[1]
        r.broadcast("00" * 32, network="mainnet")
        assert calls[0][2]["network"] == "mainnet"

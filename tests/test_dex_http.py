"""Tests for dex._http_json — retries on dropped connections.

A throwaway HTTP server on 127.0.0.1 reproduces the failures seen from the
agent VM on 2026-09-24 ("Remote end closed connection without response",
"IncompleteRead(0 bytes read)"), so the real urllib error paths are
exercised. Nothing here touches a live API, signs, or broadcasts.
"""

import http.server
import json
import threading

import pytest

from spellbook import dex
from spellbook.dex import DexError


class _Server:
    """Plays a script of behaviours, one per request, then repeats the last."""

    def __init__(self, script):
        self.script = list(script)
        self.seen = []  # (headers dict, body bytes) per request
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                outer.seen.append((dict(self.headers), body))
                step = outer.script[min(len(outer.seen), len(outer.script)) - 1]
                if step == "drop":            # close with no status line
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                if step == "truncate":        # headers, then no body
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "100")
                    self.end_headers()
                    self.wfile.flush()
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                status, payload = step
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = _serve
            do_POST = _serve

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/q"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    made = []

    def make(*script):
        s = _Server(script)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(dex.time, "sleep", lambda s: slept.append(s))
    return slept


OK = (200, {"buyAmount": "42"})


def test_dropped_connections_are_retried(server, no_sleep):
    s = server("drop", "drop", OK)
    assert dex._http_json("GET", s.url, {}) == {"buyAmount": "42"}
    assert len(s.seen) == 3
    assert no_sleep == [2, 5]


def test_truncated_response_is_retried(server):
    s = server("truncate", OK)
    assert dex._http_json("POST", s.url, {}, {"a": 1}) == {"buyAmount": "42"}
    assert len(s.seen) == 2
    assert all(json.loads(body) == {"a": 1} for _, body in s.seen)


def test_gateway_errors_are_retried(server):
    s = server((502, {"error": "upstream"}), (504, {}), OK)
    assert dex._http_json("GET", s.url, {}) == {"buyAmount": "42"}
    assert len(s.seen) == 3


def test_definite_answers_are_not_retried(server, no_sleep):
    s = server((400, {"error": "bad sellAmount"}))
    with pytest.raises(DexError) as e:
        dex._http_json("GET", s.url, {})
    assert len(s.seen) == 1 and no_sleep == []
    assert "HTTP 400" in str(e.value) and "bad sellAmount" in str(e.value)
    assert "request id" in str(e.value)


def test_gives_up_after_all_attempts(server, no_sleep):
    s = server("drop")
    with pytest.raises(DexError) as e:
        dex._http_json("GET", s.url, {})
    assert len(s.seen) == len(dex.RETRY_DELAYS_SEC) + 1
    assert no_sleep == list(dex.RETRY_DELAYS_SEC)
    assert f"attempt {len(s.seen)}" in str(e.value)


def test_retry_budget_caps_wall_time(server, monkeypatch, no_sleep):
    monkeypatch.setattr(dex, "RETRY_BUDGET_SEC", 6)
    clock = [0.0]

    def fake_sleep(sec):
        no_sleep.append(sec)
        clock[0] += sec

    monkeypatch.setattr(dex.time, "sleep", fake_sleep)
    monkeypatch.setattr(dex.time, "monotonic", lambda: clock[0])
    s = server("drop")
    with pytest.raises(DexError):
        dex._http_json("GET", s.url, {})
    # 2s fits the 6s budget; the next 5s delay would not.
    assert no_sleep == [2]
    assert len(s.seen) == 2


def test_identifies_itself_on_every_attempt(server):
    s = server("drop", OK)
    dex._http_json("GET", s.url, {"x-api-key": "k"})
    ids = [h["X-Request-Id"] for h, _ in s.seen]
    assert all(h["User-Agent"] == dex.USER_AGENT for h, _ in s.seen)
    assert dex.USER_AGENT.startswith("spellbook/")
    # urllib title-cases header names on the wire
    assert all({k.lower(): v for k, v in h.items()}["x-api-key"] == "k"
               for h, _ in s.seen)
    base = ids[0].rsplit("-", 1)[0]
    assert ids == [f"{base}-1", f"{base}-2"]


def test_malformed_url_is_not_retried(no_sleep):
    with pytest.raises(DexError):
        dex._http_json("GET", "http://", {})
    assert no_sleep == []


def test_swap_refuses_quote_that_arrives_after_the_deadline(monkeypatch):
    """Retries can outlast the approval window: the daemon must re-check
    the intent deadline after the quote arrives, before anything is signed."""
    from spellbook import daemon as daemon_mod, evm

    now = [1_000.0]
    monkeypatch.setattr(daemon_mod.time, "time", lambda: now[0])
    monkeypatch.setenv("ZERO_EX_API_KEY", "k")

    fetched = []

    def quote(self, *a, **kw):
        fetched.append(a)
        now[0] += 60  # retries ate a minute
        return {"venue": "matcha", "tx": {"to": "0x" + "1" * 40, "data": "0x", "value": "0"}}

    monkeypatch.setattr(dex.ZeroExClient, "quote", quote)

    class Rpc:
        def nonce(self, _):
            raise AssertionError("must refuse before touching the chain")

    fake = type("D", (), {})()
    fake._evm_dex_guards = lambda params: (
        {"chain_id": 4663}, Rpc(), b"\x01" * 32, "0x" + "c" * 40)
    params = {
        "venue": "matcha", "sell_token": dex.NATIVE_SENTINEL,
        "buy_token": "0x" + "2" * 40, "sell_amount_wei": 10,
        "min_buy_amount_wei": 1, "max_slippage_bps": 100,
        "deadline_sec": now[0] + 30,
    }
    with pytest.raises(evm.EvmError, match="expired while fetching the quote"):
        daemon_mod.Daemon._execute_evm_swap(fake, params)
    assert len(fetched) == 1

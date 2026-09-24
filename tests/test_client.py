"""Tests for the human approve client's execution-aware timeout.

On 2026-09-24 a real $20 MuseNews swap completed on-chain while the CLI
had already given up at the 10s default client timeout — the outcome was
only recoverable from the decision ledger. `HumanClient.approve` must
therefore wait out the full execution window (firm quote fetch with retry
budget + sign + broadcast + up-to-90s receipt wait), and `_call` must
honor a per-call timeout override. Nothing here touches a socket.
"""

from spellbook import client
from spellbook.client import APPROVE_TIMEOUT, DEFAULT_TIMEOUT, HumanClient


class _Probe(HumanClient):
    """Captures the kwargs approve() passes to _call instead of dialing."""

    def __init__(self):
        super().__init__("/nonexistent.sock", "00" * 32)
        self.seen = None

    def _call(self, route, params=None, timeout=None):
        self.seen = {"route": route, "params": params, "timeout": timeout}
        return {"ok": True}


def test_approve_timeout_covers_execution_window():
    # Must exceed the 90s receipt wait plus quote-fetch/broadcast overhead.
    assert APPROVE_TIMEOUT >= 150
    assert APPROVE_TIMEOUT > DEFAULT_TIMEOUT


def test_approve_uses_execution_timeout():
    probe = _Probe()
    probe.approve("30")
    assert probe.seen["route"] == "queue_approve"
    assert probe.seen["params"] == {"queue_id": "30"}
    assert probe.seen["timeout"] == APPROVE_TIMEOUT


def test_call_timeout_override_reaches_socket():
    timeouts = []
    import socket as socket_mod

    real_socket = socket_mod.socket

    class _FakeSock:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            timeouts.append(t)

        def connect(self, p):
            raise OSError("no daemon in unit tests")

        def close(self):
            pass

    socket_mod.socket = _FakeSock
    try:
        human = HumanClient("/nonexistent.sock", "00" * 32)
        try:
            human._call("status", timeout=123)
        except client.SpellbookError:
            pass
    finally:
        socket_mod.socket = real_socket
    assert timeouts == [123]

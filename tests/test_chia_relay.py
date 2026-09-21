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

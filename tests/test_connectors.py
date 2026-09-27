"""Tests for src/spellbook/connectors.py — connector surrogate resolution."""
import json
import socket
import threading

import pytest

from spellbook import connectors


def _serve_one(sock_path, payload, status=200):
    """Serve a single authd-style HTTP response on a unix socket."""
    body = json.dumps(payload).encode()
    response = (
        f"HTTP/1.1 {status} {'OK' if status == 200 else 'ERR'}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + body

    def run():
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            conn.sendall(response)
        srv.close()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def test_provider_returns_surrogate(tmp_path):
    sock = str(tmp_path / "authd.sock")
    payload = {"credentials": [
        {"name": "access_token", "surrogate": "hsurr:abc123"}]}
    _serve_one(sock, payload)
    provider = connectors.connector_token_provider(
        "custom.spellbook-chia-relay", socket_path=sock)
    assert provider() == "hsurr:abc123"


def test_provider_picks_entry_by_name(tmp_path):
    sock = str(tmp_path / "authd.sock")
    payload = {"credentials": [
        {"name": "other", "surrogate": "hsurr:nope"},
        {"name": "access_token", "surrogate": "hsurr:yes"}]}
    _serve_one(sock, payload)
    provider = connectors.connector_token_provider(
        "custom.x", socket_path=sock)
    assert provider() == "hsurr:yes"


def test_provider_rejects_non_surrogate(tmp_path):
    sock = str(tmp_path / "authd.sock")
    payload = {"credentials": [
        {"name": "access_token", "surrogate": "raw-secret-value"}]}
    _serve_one(sock, payload)
    provider = connectors.connector_token_provider(
        "custom.x", socket_path=sock)
    with pytest.raises(connectors.ConnectorError):
        provider()


def test_provider_rejects_wrong_host(tmp_path):
    sock = str(tmp_path / "authd.sock")
    payload = {"credentials": [
        {"name": "access_token", "surrogate": "hsurr:abc"}]}
    _serve_one(sock, payload)
    provider = connectors.connector_token_provider(
        "custom.x",
        allowed_hosts=("relay.example.com",),
        socket_path=sock)
    with pytest.raises(connectors.ConnectorError, match="refusing"):
        provider("https://evil.example/")


def test_provider_allows_listed_host(tmp_path):
    sock = str(tmp_path / "authd.sock")
    payload = {"credentials": [
        {"name": "access_token", "surrogate": "hsurr:abc"}]}
    _serve_one(sock, payload)
    provider = connectors.connector_token_provider(
        "custom.x",
        allowed_hosts=("relay.example.com",),
        socket_path=sock)
    assert provider("https://relay.example.com/v1/status") == "hsurr:abc"


def test_provider_missing_authd_is_connector_error(tmp_path):
    provider = connectors.connector_token_provider(
        "custom.x", socket_path=str(tmp_path / "no-such.sock"))
    with pytest.raises(connectors.ConnectorError, match="cannot reach authd"):
        provider()

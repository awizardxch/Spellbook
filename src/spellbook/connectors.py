"""Connector-backed credentials for Spellbook.

Some deployments keep the Chia relay bearer token in the Secure Vault
instead of the daemon's environment. A ``connector:<name>`` token source
resolves a fresh surrogate from authd for every relay request — the raw
token is never in the daemon's memory, logs, or config files.

The exchange is stdlib-only: a JSON POST over the authd unix socket.
Surrogates (``hsurr:*``) are swapped for the real credential by the
egress layer on approved outbound requests; a request that bypasses
that layer goes out unauthenticated, which the relay rejects.
"""
from __future__ import annotations

import json
import os
import socket
import urllib.parse
from typing import Callable

_AUTHD_SOCKET = os.environ.get(
    "JARVIS_AUTHD_SOCK", "/run/hatch/auth/authd.sock")
_SURROGATE_PATH = "/v1/credentials/surrogate"


class ConnectorError(RuntimeError):
    """The connector credential could not be resolved."""


def _post_json_unix(socket_path: str, path: str, payload: dict,
                    timeout: float) -> str:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: authd.local\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii") + body
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(request)
            chunks = []
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as e:
        raise ConnectorError(
            f"cannot reach authd at {socket_path}: {e} — connector "
            "credentials need a host with the credential service") from e
    raw = b"".join(chunks)
    header_bytes, sep, response_body = raw.partition(b"\r\n\r\n")
    if not sep:
        raise ConnectorError("authd returned a malformed HTTP response")
    status_line = header_bytes.splitlines()[0].decode(
        "iso-8859-1", errors="replace")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) != 200:
        raise ConnectorError(
            f"authd surrogate request failed: "
            f"{status_line} {response_body.decode('utf-8', errors='replace').strip()}")
    return response_body.decode("utf-8")


def connector_token_provider(
        connector_name: str,
        *,
        allowed_hosts: tuple[str, ...] = (),
        entry_name: str = "access_token",
        timeout: float = 5.0,
        socket_path: str | None = None,
) -> Callable[[], str]:
    """Return a zero-arg callable resolving a fresh bearer surrogate.

    connector_name is the full connector id, e.g.
    ``custom.spellbook-chia-relay``. allowed_hosts restricts which relay
    hosts the surrogate may be sent to — the provider raises if the
    eventual request target is not listed.
    """
    sock = socket_path or _AUTHD_SOCKET
    hosts = {h.strip().lower() for h in allowed_hosts if h.strip()}

    def _check_host(url: str) -> None:
        if not hosts:
            return
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host not in hosts:
            raise ConnectorError(
                f"refusing connector credential for {host or '<missing>'}; "
                f"allowed: {', '.join(sorted(hosts)) or '<none>'}")

    def provider(url: str = "") -> str:
        if url:
            _check_host(url)
        text = _post_json_unix(
            sock, _SURROGATE_PATH, {"name": connector_name}, timeout)
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as e:
            raise ConnectorError(
                "authd surrogate response was not JSON") from e
        for entry in payload.get("credentials", []):
            if entry.get("name") != entry_name:
                continue
            surrogate = str(entry.get("surrogate", "")).strip()
            if not surrogate.startswith("hsurr:"):
                raise ConnectorError(
                    f"authd returned a non-surrogate value for "
                    f"{connector_name}:{entry_name}")
            # Never log the surrogate; it is bearer-equivalent until swapped.
            return surrogate
        raise ConnectorError(
            f"missing {entry_name} surrogate for connector {connector_name}")

    return provider

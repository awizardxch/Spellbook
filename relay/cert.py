"""TLS certificates for Chia peer connections.

WHY NOT SELF-SIGNED
-------------------
Chia full nodes terminate peer TLS with ``verify_mode=CERT_REQUIRED`` and
verify the wallet's client certificate against the well-known **shared Chia
CA** (``O=Chia, CN=Chia CA, OU=Organic Farming Division``).  A purely
self-signed client certificate is REJECTED at the TLS layer — verified
empirically against chia-blockchain 2.7.4's own server context
(``ssl_context_for_server`` in ``chia/server/server.py``).

The shared CA's key is public by design: it ships inside the open-source
``chia-blockchain`` (``chia/ssl/chia_ca.crt|key``) and ``chia-ssl``
(``chia_ca.crt|key``) packages, and every Chia install signs its wallet
certs with it (``generate_ssl_for_nodes(..., prefix="public", ...)`` in
``chia/ssl/create_ssl.py``).  Presenting a shared-CA-signed cert proves
nothing about identity — real authentication of the peer happens one layer
up, by pinning the handshake ``network_id`` (``peer.py``).  Same trust model
as any Chia wallet.

WHAT THIS MODULE DOES
---------------------
1. Locates the shared Chia CA, in order of preference:
   a. ``RELAY_CHIA_CA_DIR`` — a directory containing ``chia_ca.crt`` and
      ``chia_ca.key`` (e.g. copied from any Chia install's
      ``config/ssl/ca/``), or
   b. an installed ``chia`` Python package (``chia/ssl/chia_ca.crt|key``
      via importlib resources), or
   c. ``chia_ca.crt``/``chia_ca.key`` already provisioned next to the node
      cert in the cert dir (the Docker build does this).
2. Generates a fresh RSA-2048 node key and a node certificate signed by the
   shared CA (subject ``CN=Chia, O=Chia, OU=Organic Farming Division``,
   SAN ``chia.net`` — mirroring ``generate_ca_signed_cert``), valid 10
   years but capped inside the CA's own validity window.
3. Writes ``node.crt`` / ``node.key`` (mode 600) into the cert dir, reusing
   them if they already exist.

If no CA can be found, this raises with instructions instead of silently
producing a cert that real full nodes would reject (fail closed).
"""

from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path

log = logging.getLogger("relay.cert")

CA_CRT_NAME = "chia_ca.crt"
CA_KEY_NAME = "chia_ca.key"
NODE_CRT_NAME = "node.crt"
NODE_KEY_NAME = "node.key"

# The shared CA (shipped in chia-blockchain / chia-ssl) expires 2037-12-31.
# Keep node certs comfortably inside that window.
_NODE_VALID_DAYS = 365 * 8


class CertError(RuntimeError):
    pass


def _load_shared_ca() -> tuple[bytes, bytes]:
    """Return (ca_crt_pem, ca_key_pem) for the shared Chia CA."""
    # 1. Explicit operator-provided directory.
    ca_dir = os.environ.get("RELAY_CHIA_CA_DIR")
    if ca_dir:
        crt_p = Path(ca_dir) / CA_CRT_NAME
        key_p = Path(ca_dir) / CA_KEY_NAME
        if crt_p.is_file() and key_p.is_file():
            log.info("using shared Chia CA from RELAY_CHIA_CA_DIR=%s", ca_dir)
            return crt_p.read_bytes(), key_p.read_bytes()
        raise CertError(
            f"RELAY_CHIA_CA_DIR={ca_dir} does not contain {CA_CRT_NAME} and {CA_KEY_NAME}"
        )

    # 2. Installed `chia` package (chia-blockchain ships both files).
    try:
        import importlib.resources as resources  # noqa: PLC0415

        ssl_pkg = resources.files("chia.ssl")
        crt = (ssl_pkg / CA_CRT_NAME).read_bytes()
        key = (ssl_pkg / CA_KEY_NAME).read_bytes()
        log.info("using shared Chia CA from installed chia package")
        return crt, key
    except Exception:  # noqa: BLE001
        pass

    raise CertError(
        "shared Chia CA not found: set RELAY_CHIA_CA_DIR to a directory containing "
        f"{CA_CRT_NAME} and {CA_KEY_NAME} (copy them from any Chia install's "
        "config/ssl/ca/, or pip-install chia-blockchain). Refusing to generate a "
        "self-signed cert — real full nodes would reject it at the TLS layer."
    )


def _generate_node_cert(ca_crt_pem: bytes, ca_key_pem: bytes) -> tuple[bytes, bytes]:
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    ca_cert = x509.load_pem_x509_certificate(ca_crt_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    node_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Chia"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Chia"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Organic Farming Division"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=_NODE_VALID_DAYS)
    # Stay inside the CA's own validity window.
    if not_after > ca_cert.not_valid_after_utc:
        not_after = ca_cert.not_valid_after_utc - datetime.timedelta(days=30)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(node_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("chia.net")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = node_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def ensure_certs(cert_dir: str | Path) -> tuple[Path, Path]:
    """Ensure a shared-CA-signed node cert+key exist; return (crt, key) paths."""
    d = Path(cert_dir)
    d.mkdir(parents=True, exist_ok=True)
    crt_path = d / NODE_CRT_NAME
    key_path = d / NODE_KEY_NAME

    if crt_path.is_file() and key_path.is_file():
        log.info("reusing existing node cert in %s", d)
        return crt_path, key_path

    # A provisioned CA next to the node cert (option c) takes effect here:
    # if the operator placed chia_ca.crt/key in the cert dir, _load_shared_ca
    # won't find them (it only checks RELAY_CHIA_CA_DIR / installed package),
    # so check the cert dir itself before failing.
    local_crt = d / CA_CRT_NAME
    local_key = d / CA_KEY_NAME
    if local_crt.is_file() and local_key.is_file():
        ca_crt_pem, ca_key_pem = local_crt.read_bytes(), local_key.read_bytes()
        log.info("using shared Chia CA provisioned in cert dir %s", d)
    else:
        ca_crt_pem, ca_key_pem = _load_shared_ca()

    cert_pem, key_pem = _generate_node_cert(ca_crt_pem, ca_key_pem)

    # Write key first with restrictive perms, then cert.
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem)
    crt_path.write_bytes(cert_pem)
    log.info("generated shared-CA-signed node cert in %s", d)
    return crt_path, key_path


def make_peer_ssl_context(cert_path: Path, key_path: Path):
    """Client TLS context for Chia peers.

    Presents our shared-CA-signed cert (required: nodes run CERT_REQUIRED).
    Does NOT verify the peer's certificate — peer authentication is the
    handshake network_id pin in peer.py, not TLS.
    """
    import ssl  # noqa: PLC0415

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx

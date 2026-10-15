"""Hosted ceremony (review 2026-10-15 S-17 / S-18).

The human's pages are hosted; the agent relays only public keys and
ciphertext; only the key holder (daemon user) opens an envelope. These
tests pin the envelope format, its bindings, the key-holder commands and
the removal of every path where the agent decrypted a human secret.
"""
import json
import os
import re

import pytest
from Crypto.PublicKey import RSA

from spellbook import asset_index, ceremony, sealed, seed

ROOT = asset_index.repo_root()
TEST_SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SET1 = " ".join(["abandon"] * 23 + ["art"])   # standard (BIP-39 seed)
SET2 = " ".join(["zoo"] * 23 + ["vote"])      # daemon KDF entropy


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    d = tmp_path_factory.mktemp("ck")
    key = RSA.generate(2048)
    priv = d / "private.pem"
    priv.write_bytes(key.export_key())
    priv.chmod(0o600)
    return str(priv), key.publickey().export_key(format="DER")


@pytest.fixture
def wallet(tmp_path, monkeypatch):
    (tmp_path / "seed.key").write_text(TEST_SEED_HEX)
    (tmp_path / "seed.key").chmod(0o600)
    (tmp_path / "spellbook.json").write_text(json.dumps(
        {"seed_path": str(tmp_path / "seed.key"), "allowed_request_uids": [-1]}))
    monkeypatch.setenv("SPELLBOOK_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("SPELLBOOK_SEALED_PATH", str(tmp_path / "ws" / "seed.sealed"))
    return tmp_path


# ---------------------------------------------------------------- links

def test_hosted_url_carries_public_key_in_fragment_only(keypair):
    _, der = keypair
    url = ceremony.hosted_url("seal", pub_der=der, op="unlock")
    assert url.startswith("https://spellbook.awizard.dev/ceremony/seal.html#k=")
    assert "?" not in url and url.endswith("&op=unlock")
    k = url.split("#k=", 1)[1].split("&", 1)[0]
    assert ceremony.public_der(k) == der
    with pytest.raises(ceremony.CeremonyError):
        ceremony.hosted_url("seal", op="reveal")


def test_public_der_refuses_private_keys(keypair):
    priv, _ = keypair
    with open(priv) as f:
        with pytest.raises(ceremony.CeremonyError, match="PRIVATE"):
            ceremony.public_der(f.read())
    with pytest.raises(ceremony.CeremonyError):
        ceremony.public_der(RSA.generate(1024).publickey().export_key())


# ---------------------------------------------------------------- envelopes

def test_envelope_round_trip_and_bindings(keypair, tmp_path):
    priv, der = keypair
    env = ceremony.seal_envelope("unlock", {"password": "x" * 20}, der)
    assert env.startswith("SPELLBOOK-CEREMONY1.") and "x" * 20 not in env
    assert ceremony.open_envelope(env, priv) == ("unlock", {"password": "x" * 20})
    # Kind is bound: an unlock envelope is not a seal or restore envelope.
    with pytest.raises(ceremony.CeremonyError, match="expected"):
        ceremony.open_envelope(env, priv, ("seal",))
    hdr = json.loads(ceremony._unb64_any(env[len(ceremony.PREFIX):]))
    hdr["kind"] = "seal"  # relabel: the AAD no longer matches
    forged = ceremony.PREFIX + ceremony._b64url(json.dumps(hdr).encode())
    with pytest.raises(ceremony.CeremonyError, match="did not decrypt"):
        ceremony.open_envelope(forged, priv)
    # Another key cannot open it, and says why.
    other = tmp_path / "other.pem"
    other.write_bytes(RSA.generate(2048).export_key())
    other.chmod(0o600)
    with pytest.raises(ceremony.CeremonyError, match="different ceremony key"):
        ceremony.open_envelope(env, str(other))
    # A world-readable key is refused.
    os.chmod(priv, 0o644)
    try:
        with pytest.raises(ceremony.CeremonyError, match="0600"):
            ceremony.open_envelope(env, priv)
    finally:
        os.chmod(priv, 0o600)


def test_password_strength_rule():
    assert ceremony.password_problem("short")
    assert ceremony.password_problem("aaaaaaaaaaaaaaaa")
    assert ceremony.password_problem("password1234")
    assert ceremony.password_problem("abcdefgh1234")
    assert ceremony.password_problem("ab12AB!@cd34CD") is None
    assert ceremony.password_problem(
        "abandon ability able about above absent") is None
    assert ceremony.password_problem(" ".join(["abandon"] * 6))


def test_apply_seals_and_unlocks_without_the_agent(wallet, keypair):
    priv, der = keypair
    weak = ceremony.seal_envelope("seal", {"password": "password1234"}, der)
    with pytest.raises(ceremony.CeremonyError, match="refused"):
        ceremony.apply_password(weak, priv, n=2 ** 10)
    pw = "ab12AB!@cd34CD-seal"
    r = ceremony.apply_password(
        ceremony.seal_envelope("seal", {"password": pw}, der), priv, n=2 ** 10)
    assert r["op"] == "seal" and sealed.status()["state"] == "unlocked"
    os.remove(wallet / "seed.key")
    assert sealed.status()["state"] == "locked"
    # A seal envelope cannot be replayed as an unlock, and vice versa.
    r = ceremony.apply_password(
        ceremony.seal_envelope("unlock", {"password": pw}, der), priv)
    assert r["op"] == "unlock" and sealed.status()["state"] == "unlocked"
    with pytest.raises(ceremony.CeremonyError):
        ceremony.apply_password(
            ceremony.seal_envelope("restore", {"password": pw}, der), priv)


def test_restore_envelope_maps_sets_and_writes_exclusively(keypair, tmp_path):
    priv, der = keypair
    env = ceremony.seal_envelope(
        "restore", {"set1_standard": SET1, "set2_daemon": SET2}, der)
    out = tmp_path / "restore.keys"
    ceremony.apply_restore(env, priv, str(out))
    assert oct(os.stat(out).st_mode & 0o777) == "0o600"
    line1, line2 = out.read_text().split()
    # install.sh --restore: line 1 seed.key (SET 2 entropy), line 2
    # std_seed.key (SET 1 BIP-39 seed) — the paper labels (S-27).
    assert line1 == seed.entropy_from_mnemonic(SET2).hex()
    assert line2 == seed.mnemonic_to_seed(SET1).hex()
    with pytest.raises(ceremony.CeremonyError, match="already exists"):
        ceremony.apply_restore(env, priv, str(out))
    bad = ceremony.seal_envelope(
        "restore", {"set1_standard": SET1.replace("art", "zoo"),
                    "set2_daemon": SET2}, der)
    with pytest.raises(ceremony.CeremonyError, match="SET 1"):
        ceremony.apply_restore(bad, priv, str(tmp_path / "other.keys"))


def test_key_holder_commands_refuse_the_agent_uid(tmp_path, keypair, capsys):
    (tmp_path / "spellbook.json").write_text(
        json.dumps({"allowed_request_uids": [os.getuid()]}))
    env_file = tmp_path / "env.txt"
    priv, der = keypair
    env_file.write_text(ceremony.seal_envelope("unlock", {"password": "p" * 12}, der))
    if os.getuid() == 0:
        pytest.skip("root is always allowed")
    rc = ceremony.main(["apply", str(env_file), "--key", priv,
                        "--config-dir", str(tmp_path)])
    assert rc == 2 and "never by the agent" in capsys.readouterr().err
    rc = ceremony.main(["restore", str(env_file), "--key", priv, "--out",
                        str(tmp_path / "o"), "--config-dir", str(tmp_path)])
    assert rc == 2 and not (tmp_path / "o").exists()


def test_url_command_prints_only_public_material(tmp_path, keypair, capsys):
    priv, der = keypair
    pub = tmp_path / "ceremony.pub.pem"
    pub.write_bytes(RSA.import_key(der).export_key())
    assert ceremony.main(["url", "seal", "--pub", str(pub), "--op", "seal"]) == 0
    out = capsys.readouterr().out
    assert "#k=" in out and "PRIVATE" not in out
    assert ceremony.grouped(ceremony.key_fingerprint(der)) in out


# ---------------------------------------------------------------- removals

def _repo(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_repo_ceremony_pages_no_longer_take_secrets():
    """The old pages had the agent decrypt the seal password and restore
    words (S-17). What remains in ceremony/ is a pointer to the hosted
    pages: no script, no input."""
    for n in os.listdir(os.path.join(ROOT, "ceremony")):
        if not n.endswith(".html"):
            continue
        html = _repo(f"ceremony/{n}")
        assert not re.search(r"<script|<input|<textarea", html, re.I), n
        assert "spellbook.awizard.dev/ceremony/" in html, n


def test_hosted_pages_have_no_agent_decrypt_step():
    for n in os.listdir(os.path.join(ROOT, asset_index.CEREMONY_DIR)):
        text = _repo(f"{asset_index.CEREMONY_DIR}/{n}")
        assert "__SEAL_PUB_B64__" not in text and "__SEED_PUB_B64__" not in text
        assert not re.search(r"agent (decrypts|does)", text, re.I), n


def test_docs_do_not_send_the_agent_to_serve():
    for rel in ("docs/AGENT_ONBOARDING.md", "ceremony/README.md"):
        assert "spellbook-seed serve" not in _repo(rel), rel

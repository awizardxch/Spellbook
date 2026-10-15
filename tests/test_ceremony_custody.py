"""S-16 x S-17/S-18 reconciled: one ceremony key, the daemon's, and hosted
pages for the human.

- `spellbook-ceremony apply|restore` open envelopes with the daemon's own
  key (<prefix>/ceremony/private.pem) by default; spellbook.json
  `ceremony_key_path` is never read as that key (on upgraded installs it
  names the legacy agent-reach key that ceremony-adopt moves).
- The public half is published outside the 0700 prefix and the agent's
  tool finds it there.
- The hosted backup page shows the S-16 confirmation code and handles an
  envelope-only (passwordless) install.
- The local viewer refuses the agent's OS user.

Every key and seed here is a throwaway generated inside the test.
"""
import base64
import json
import os
import re
import subprocess
import sys

import pytest

from spellbook import agent_tools, ceremony, custody, sealed
from spellbook import export as exportmod

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
POSIX = os.name == "posix"
UID = os.getuid() if POSIX else 0
AGENT = UID + 1

posix_only = pytest.mark.skipif(not POSIX, reason="POSIX custody (uids, modes)")

WORDS1 = ("abandon " * 23 + "art").strip()
WORDS2 = ("zoo " * 23 + "vote").strip()


def _w(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(path, mode)


def _prefix(tmp_path, *, agent_uids=(AGENT,), extra=None):
    p = tmp_path / "prefix"
    p.mkdir(mode=0o700)
    os.chmod(p, 0o700)
    cfg = {"key_derivation": "standard", "labels": ["default"],
           "allowed_request_uids": list(agent_uids),
           "allowed_approve_uids": [UID]}
    cfg.update(extra or {})
    _w(os.path.join(str(p), "spellbook.json"), json.dumps(cfg))
    return str(p)


def _legacy_key(tmp_path):
    from Crypto.PublicKey import RSA
    d = tmp_path / "agent-home" / "workspace" / ".spellbook" / "seed-derive"
    d.mkdir(parents=True, mode=0o700)
    key = RSA.generate(2048)
    path = str(d / "private.pem")
    _w(path, key.export_key(format="PEM", pkcs=8).decode())
    return path, key.publickey().export_key(format="DER")


def _daemon_pub_der(prefix):
    info = custody.public_key_info(prefix)
    return base64.b64decode(info["public_key_b64"])


# ---------------------------------------------------------------- the key


@posix_only
def test_restore_defaults_to_the_daemon_key_not_ceremony_key_path(tmp_path, capsys):
    legacy, legacy_der = _legacy_key(tmp_path)
    p = _prefix(tmp_path, extra={"ceremony_key_path": legacy})
    custody.generate_ceremony_key(p)
    env = tmp_path / "restore.env"
    env.write_text(ceremony.seal_envelope(
        "restore", {"set1_standard": WORDS1, "set2_daemon": WORDS2},
        _daemon_pub_der(p)))
    out = tmp_path / "restore.keys"
    assert ceremony.main(["restore", str(env), "--out", str(out),
                          "--config-dir", p]) == 0, capsys.readouterr().err
    lines = out.read_text().split()
    assert len(lines) == 2 and len(lines[0]) == 64 and len(lines[1]) == 128
    assert oct(os.stat(out).st_mode & 0o777) == "0o600"
    # An envelope made for the LEGACY key (the one ceremony_key_path names)
    # does not open: that key is never used as the daemon's.
    env.write_text(ceremony.seal_envelope(
        "restore", {"set1_standard": WORDS1, "set2_daemon": WORDS2}, legacy_der))
    out2 = tmp_path / "restore2.keys"
    assert ceremony.main(["restore", str(env), "--out", str(out2),
                          "--config-dir", p]) == 2
    assert "different ceremony key" in capsys.readouterr().err
    assert not out2.exists()


@posix_only
def test_apply_without_a_daemon_key_names_adopt_not_the_legacy_key(tmp_path, capsys):
    legacy, legacy_der = _legacy_key(tmp_path)
    p = _prefix(tmp_path, extra={"ceremony_key_path": legacy})
    env = tmp_path / "unlock.env"
    env.write_text(ceremony.seal_envelope("unlock", {"password": "x" * 20},
                                          legacy_der))
    assert ceremony.main(["apply", str(env), "--config-dir", p]) == 2
    err = capsys.readouterr().err
    assert "ceremony-adopt" in err and os.path.join("ceremony", "private.pem") in err


@posix_only
def test_daemon_key_is_loaded_strictly(tmp_path, capsys):
    """Default key: owner, mode and no-symlink checks (custody), not just
    a mode check."""
    p = _prefix(tmp_path)
    custody.generate_ceremony_key(p)
    os.chmod(os.path.join(p, "ceremony"), 0o755)
    env = tmp_path / "unlock.env"
    env.write_text(ceremony.seal_envelope("unlock", {"password": "x" * 20},
                                          _daemon_pub_der(p)))
    assert ceremony.main(["apply", str(env), "--config-dir", p]) == 2
    assert "0700" in capsys.readouterr().err


@posix_only
def test_explicit_key_override_still_works(tmp_path, capsys):
    from Crypto.PublicKey import RSA
    p = _prefix(tmp_path)
    key = RSA.generate(2048)
    kp = tmp_path / "other.pem"
    _w(str(kp), key.export_key(format="PEM", pkcs=8).decode())
    env = tmp_path / "restore.env"
    env.write_text(ceremony.seal_envelope(
        "restore", {"set1_standard": WORDS1, "set2_daemon": WORDS2},
        key.publickey().export_key(format="DER")))
    out = tmp_path / "o.keys"
    assert ceremony.main(["restore", str(env), "--out", str(out), "--key",
                          str(kp), "--config-dir", p]) == 0
    assert out.exists()


@posix_only
def test_key_holder_commands_refuse_the_agent(tmp_path):
    """derive_from_envelope.py holds the seed in memory: it refuses a
    daemon user that is the agent's OS user before reading anything."""
    p = _prefix(tmp_path, agent_uids=(UID,))
    if os.geteuid() == 0:
        pytest.skip("root is always allowed")
    with pytest.raises(custody.CustodyError):
        custody.check_key_holder(p)
    r = subprocess.run([sys.executable,
                        os.path.join(ROOT, "ceremony", "derive_from_envelope.py"),
                        "--prefix", p], input="", capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")})
    assert r.returncode == 1 and "Paste" not in r.stdout


# ---------------------------------------------------------------- the public key


@posix_only
def test_public_key_is_published_outside_the_prefix_and_found_by_the_agent(
        tmp_path, monkeypatch):
    p = _prefix(tmp_path)
    custody.generate_ceremony_key(p)
    # What install.sh does: `ceremony-key --pem` into a root-owned path
    # outside the 0700 prefix.
    published = tmp_path / "usr-local-share" / "ceremony.pub.pem"
    published.parent.mkdir()
    published.write_bytes(custody.public_pem(p))
    monkeypatch.setattr(custody, "PUBLISHED_PUB_PATH", str(published))
    monkeypatch.delenv("SPELLBOOK_CEREMONY_PUB", raising=False)
    # The agent cannot read the prefix's spellbook.json; it sees an empty
    # config dir of its own.
    agent_cfg = tmp_path / "agent-cfg"
    agent_cfg.mkdir()
    monkeypatch.setenv("SPELLBOOK_CONFIG_DIR", str(agent_cfg))
    assert ceremony.find_public_key() == str(published)
    der = _daemon_pub_der(p)
    out = agent_tools._seed_viewer({"page": "restore"})
    assert out["url"] == ceremony.hosted_url("restore", pub_der=der, op="restore")
    assert out["key_fingerprint"] == ceremony.grouped(ceremony.key_fingerprint(der))
    # Same fingerprint the daemon reports (status, ceremony-key).
    assert custody.public_key_info(p)["fingerprint"] == ceremony.key_fingerprint(der)


def test_installer_publishes_the_public_key_root_owned_outside_the_prefix():
    sh = open(os.path.join(ROOT, "install.sh"), encoding="utf-8").read()
    assert 'CEREMONY_PUB_PUBLISHED="/usr/local/share/spellbook/ceremony.pub.pem"' in sh
    assert 'chown root:root "${CEREMONY_PUB_PUBLISHED}.tmp"' in sh
    assert custody.PUBLISHED_PUB_PATH == "/usr/local/share/spellbook/ceremony.pub.pem"
    assert not custody.PUBLISHED_PUB_PATH.startswith("/opt/spellbook")
    # The fingerprint goes to the human in the installer log.
    assert 'log "  ${CEREMONY_FPR}"' in sh


def test_installer_points_the_human_at_the_hosted_pages():
    sh = open(os.path.join(ROOT, "install.sh"), encoding="utf-8").read()
    assert "seal-password-encryptor" not in sh
    assert "https://spellbook.awizard.dev/ceremony/backup.html" in sh
    assert "spellbook-ceremony url seal" in sh
    assert '"${STAGE}/ceremony/asset-index.json"' in sh
    # The agent is never told to start the local viewer itself.
    handoff = sh[sh.index("AGENT HANDOFF"):]
    assert "spellbook-seed serve" not in handoff


# ---------------------------------------------------------------- backup page


def _page_code_re():
    js = open(os.path.join(ROOT, "web", "public", "ceremony", "backup.js"),
              encoding="utf-8").read()
    m = re.search(r"var CODE_RE = /(.+)/;", js)
    assert m, "backup.js must carry the confirmation-code pattern"
    return re.compile(m.group(1))


@pytest.mark.parametrize("material", ["words", "envelope-only"])
def test_backup_page_finds_the_confirmation_code(material):
    """The page shows the S-16 code apart from the document, for a normal
    install (words) and for a passwordless one (SET 1 addresses only)."""
    code = "ABCD-EFGH-JKMN-PQRS"
    if material == "words":
        text = exportmod.paper_backup_text(os.urandom(32), os.urandom(32),
                                           with_addresses=False, terminal=False,
                                           confirm_code=code)
    else:
        text = exportmod.paper_backup_text(None, None, terminal=False,
                                           live_std_seed=os.urandom(64),
                                           confirm_code=code)
        assert "Solana" in text and "words are not shown" in text
    m = _page_code_re().search(text)
    assert m and m.group(1) == code
    # The reveal-key backup carries no ceremony fingerprint (the agent knows
    # the reveal key and could forge it); only the terminal shows one.
    assert "FINGERPRINT" not in text


def test_backup_page_tells_the_human_to_hand_the_code_back():
    html = open(os.path.join(ROOT, "web", "public", "ceremony", "backup.html"),
                encoding="utf-8").read()
    assert 'id="codeStep"' in html and 'id="codeOut"' in html
    assert "sudo spellbook backup-confirm" in html
    assert "no words" in html  # envelope-only installs


def test_pages_name_the_daemon_key_and_where_its_fingerprint_comes_from():
    for n in ("seal.html", "restore.html"):
        html = open(os.path.join(ROOT, "web", "public", "ceremony", n),
                    encoding="utf-8").read()
        assert "Spellbook daemon key fingerprint" in html, n
        assert "spellbook export" in html and "ceremony-key" in html, n


def test_asset_index_is_current():
    from spellbook import asset_index
    r = subprocess.run([sys.executable, "-m", "spellbook.asset_index", "check"],
                       cwd=ROOT, capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")})
    assert r.returncode == 0, r.stdout + r.stderr
    assert asset_index  # imported for the module path


# ---------------------------------------------------------------- viewer


@posix_only
def test_local_viewer_refuses_the_agent_uid(tmp_path, capsys):
    if os.geteuid() == 0:
        pytest.skip("root is always allowed")
    p = _prefix(tmp_path, agent_uids=(UID,))
    rc = sealed.main(["--config-dir", p, "--sealed", str(tmp_path / "s"),
                      "serve", "--port", "0"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "never by the agent" in err and "spellbook-ceremony url seal" in err


def test_agent_hints_never_tell_the_agent_to_serve():
    for hint in list(sealed.STATE_HINT.values()) + list(agent_tools.AGENT_HINT.values()):
        assert "seed serve" not in hint

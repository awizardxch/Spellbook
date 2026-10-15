"""Review S-16: the key that decrypts the live seed belongs to the daemon,
and the backup is forced.

- The passwordless ceremony key is made by the daemon user inside the
  daemon's own dir (0600 file, 0700 dir); only its public key leaves.
- A legacy key the old agent-run ceremony left in agent reach is MOVED and
  the agent's copy overwritten and unlinked.
- The daemon still decrypts the envelope at start, with its own key.
- A backup-pending install refuses fund-moving routes and keeps reads; no
  route (so no request token) can write the confirmation; the human's
  confirmation flips the state.

Every seed and key here is a throwaway generated inside the test.
"""
import base64
import json
import os
import re
import select
import stat
import subprocess
import sys

import pytest

from spellbook import custody
from spellbook import export as exportmod
from spellbook import daemon as daemon_mod
from spellbook.daemon import Daemon

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
POSIX = os.name == "posix"
UID = os.getuid() if POSIX else 0
AGENT = UID + 1  # a different OS user: the daemon/agent split install.sh makes

pytestmark = pytest.mark.skipif(not POSIX, reason="POSIX custody (uids, modes)")


def _w(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(path, mode)


def _envelope(pub_b64: str, seed: bytes) -> str:
    """What ceremony/seed-to-addresses.html produces (WebCrypto RSA-OAEP
    SHA-256 + AES-256-GCM, ct = ciphertext || tag)."""
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    pub = RSA.import_key(base64.b64decode(pub_b64))
    aes = os.urandom(32)
    iv = os.urandom(12)
    c = AES.new(aes, AES.MODE_GCM, nonce=iv)
    ct, tag = c.encrypt_and_digest(seed.hex().encode())
    ek = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(aes)
    doc = {"v": 2, "algo": "RSA-OAEP-SHA256+AES-GCM-256",
           "ek": ek.hex(), "iv": iv.hex(), "ct": (ct + tag).hex()}
    return "SPELLBOOK-SEED-ENC2." + base64.b64encode(json.dumps(doc).encode()).decode()


def _legacy_key(home):
    """A key where the OLD ceremony script left it: the agent's workspace."""
    from Crypto.PublicKey import RSA
    d = os.path.join(home, "workspace", ".spellbook", "seed-derive")
    os.makedirs(d, mode=0o700)
    key = RSA.generate(2048)
    path = os.path.join(d, "private.pem")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.export_key(format="PEM", pkcs=8))
    pub = base64.b64encode(key.publickey().export_key(format="DER")).decode()
    return path, pub, key


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "agent-home"
    h.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(h))
    return str(h)


def _prefix(tmp_path, *, agent_uids=(AGENT,), extra=None, envelope_dir=None):
    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o700)
    os.chmod(prefix, 0o700)
    p = str(prefix)
    env_path = os.path.join(envelope_dir or p, "seed.enc")
    cfg = {"key_derivation": "standard", "sealed_envelope_path": env_path,
           "labels": ["default"], "allowed_request_uids": list(agent_uids),
           "allowed_approve_uids": [UID]}
    cfg.update(extra or {})
    _w(os.path.join(p, "spellbook.json"), json.dumps(cfg))
    _w(os.path.join(p, "policy.json"), "{}")
    _w(os.path.join(p, "ledger.jsonl"), "")
    req, app = os.urandom(32).hex(), os.urandom(32).hex()
    _w(os.path.join(p, "request.token"), req)
    _w(os.path.join(p, "approve.token"), app)
    return p, env_path, req, app


def _seal(env_path, pub_b64, seed):
    _w(env_path, _envelope(pub_b64, seed))


# ---------------------------------------------------------------- the key

def test_ceremony_key_is_made_in_the_daemon_dir_0600_and_only_public_leaves(tmp_path, home):
    p, *_ = _prefix(tmp_path)
    info = custody.generate_ceremony_key(p)
    key_path = os.path.join(p, "ceremony", "private.pem")
    st = os.stat(key_path)
    assert st.st_uid == os.geteuid()
    assert stat.S_IMODE(st.st_mode) == 0o600
    d = os.stat(os.path.join(p, "ceremony"))
    assert d.st_uid == os.geteuid() and stat.S_IMODE(d.st_mode) == 0o700
    assert info["created"] and "PRIVATE" not in json.dumps(info)
    assert custody.public_key_info(p)["public_key_b64"] == info["public_key_b64"]
    # Idempotent: a second call reports the same key, never a new one.
    again = custody.generate_ceremony_key(p)
    assert not again["created"] and again["fingerprint"] == info["fingerprint"]
    # Nothing landed in the agent's home.
    assert not os.path.exists(os.path.join(home, "workspace"))
    # The CLI prints the public key and fingerprint only.
    r = subprocess.run([sys.executable, "-m", "spellbook.cli", "ceremony-key",
                        "--prefix", p], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")})
    assert r.returncode == 0, r.stderr
    assert "PRIVATE" not in r.stdout and info["fingerprint"] in r.stdout


def test_ceremony_key_refuses_when_the_daemon_user_is_the_agent(tmp_path, home):
    p, *_ = _prefix(tmp_path, agent_uids=(UID,))
    with pytest.raises(custody.CustodyError):
        custody.generate_ceremony_key(p)
    assert not os.path.exists(os.path.join(p, "ceremony", "private.pem"))


def test_ceremony_script_stamps_the_public_key_and_mints_no_private_key(tmp_path, home):
    from Crypto.PublicKey import RSA
    pub = base64.b64encode(RSA.generate(2048).publickey().export_key(format="DER")).decode()
    page = tmp_path / "page.html"
    page.write_text('<script>const SEED_PUB_B64 = "__SEED_PUB_B64__";</script>')
    r = subprocess.run([sys.executable, os.path.join(ROOT, "ceremony", "new_seed_ceremony_key.py"),
                        "--stdin", str(page)], input=pub, capture_output=True, text=True,
                       env={**os.environ, "HOME": home})
    assert r.returncode == 0, r.stderr
    assert pub in page.read_text()
    for dirpath, _, files in os.walk(home):
        assert "private.pem" not in files, dirpath
    # A private key is refused, not stamped.
    priv = base64.b64encode(RSA.generate(2048).export_key(format="DER")).decode()
    r = subprocess.run([sys.executable, os.path.join(ROOT, "ceremony", "new_seed_ceremony_key.py"),
                        "--stdin", str(page)], input=priv, capture_output=True, text=True,
                       env={**os.environ, "HOME": home})
    assert r.returncode != 0 and priv not in page.read_text()


def test_adopt_moves_the_agent_copy_and_overwrites_it(tmp_path, home):
    p, *_ = _prefix(tmp_path)
    legacy, pub, key = _legacy_key(home)
    original = open(legacy, "rb").read()
    # A second name for the same inode shows the overwrite in place.
    witness = str(tmp_path / "witness")
    os.link(legacy, witness)
    res = custody.adopt_ceremony_key(p, legacy)
    assert res["unlinked"] and res["overwritten"]
    assert not os.path.lexists(legacy)
    assert open(witness, "rb").read() != original
    moved = custody.read_private_key(custody.ceremony_key_path(p), os.geteuid())
    assert moved.publickey().export_key(format="DER") == \
        key.publickey().export_key(format="DER")
    st = os.stat(custody.ceremony_key_path(p))
    assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.geteuid()


def test_adopt_refuses_a_destination_in_agent_reach(tmp_path, home):
    p, *_ = _prefix(tmp_path, agent_uids=(UID,))
    legacy, _, _ = _legacy_key(home)
    with pytest.raises(custody.CustodyError):
        custody.adopt_ceremony_key(p, legacy, check_runner=False)
    assert os.path.exists(legacy)  # never lost


# ---------------------------------------------------------------- the daemon

def test_daemon_decrypts_the_envelope_at_start_with_its_own_key(tmp_path, home):
    p, env_path, *_ = _prefix(tmp_path)
    info = custody.generate_ceremony_key(p)
    seed = os.urandom(64)
    _seal(env_path, info["public_key_b64"], seed)
    d = Daemon(p)
    assert d.std_seed == seed
    assert d.custody_info["key_source"] == "daemon"
    assert d.custody_info["separation"] == "ok"
    # A restart decrypts again: still passwordless.
    assert Daemon(p).std_seed == seed


def test_daemon_moves_a_legacy_key_out_of_agent_reach_at_start(tmp_path, home):
    legacy, pub, _ = _legacy_key(home)
    p, env_path, *_ = _prefix(tmp_path, extra={"ceremony_key_path": legacy})
    seed = os.urandom(64)
    _seal(env_path, pub, seed)
    d = Daemon(p)
    assert d.std_seed == seed
    assert not os.path.lexists(legacy)
    assert os.path.exists(custody.ceremony_key_path(p))
    assert d.custody_info["key_source"] == "daemon"
    assert d.custody_info["key_origin"] == "adopted"
    # An adopted legacy install is not flipped to backup-pending.
    assert d.backup_status()["state"] == "legacy"


def test_single_user_host_keeps_the_key_and_warns(tmp_path, home, capsys):
    legacy, pub, _ = _legacy_key(home)
    p, env_path, *_ = _prefix(tmp_path, agent_uids=(UID,),
                              extra={"ceremony_key_path": legacy})
    seed = os.urandom(64)
    _seal(env_path, pub, seed)
    d = Daemon(p)
    assert d.std_seed == seed  # not bricked
    assert os.path.exists(legacy)  # not moved within the agent's own files
    assert d.custody_info["key_source"] == "agent-reach"
    assert d.custody_info["separation"] != "ok"
    assert "AGENT REACH" in capsys.readouterr().err


def test_daemon_refuses_its_own_key_with_loose_mode(tmp_path, home):
    p, env_path, *_ = _prefix(tmp_path)
    info = custody.generate_ceremony_key(p)
    _seal(env_path, info["public_key_b64"], os.urandom(64))
    os.chmod(custody.ceremony_key_path(p), 0o640)
    with pytest.raises(custody.CustodyError):
        Daemon(p)


# ---------------------------------------------------------------- forced backup

def _pending_daemon(tmp_path):
    p, env_path, req, app = _prefix(tmp_path)
    info = custody.generate_ceremony_key(p)
    seed = os.urandom(64)
    _seal(env_path, info["public_key_b64"], seed)
    return Daemon(p), p, seed, req, app


def _call(d, token, route, params=None, uid=AGENT):
    return d.handle({"token": token, "route": route, "params": params or {},
                     "muse_id": "t"}, uid)


def test_backup_pending_refuses_fund_routes_and_allows_reads(tmp_path, home):
    d, p, seed, req, app = _pending_daemon(tmp_path)
    assert d.backup_status()["state"] == "pending"
    st = _call(d, req, "status")
    assert st["ok"] and st["backup"]["state"] == "pending"
    assert "spellbook export" in st["backup"]["action"]
    assert st["custody"]["ceremony_public_key"]["fingerprint"]
    assert _call(d, req, "addresses")["ok"]
    assert _call(d, req, "queue_read")["ok"]
    r = _call(d, req, "request_spend", {"chain": "evm-46630", "destination":
                                        "0x" + "11" * 20, "asset": "native",
                                        "amount_wei": 1})
    assert not r["ok"] and r.get("backup_pending")
    assert "spellbook export" in r["error"]
    for route in sorted((daemon_mod.REQUEST_ROUTES | daemon_mod.APPROVE_ROUTES)
                        - daemon_mod.BACKUP_PENDING_ROUTES):
        if route in daemon_mod.APPROVE_ROUTES:
            out = _call(d, app, route, uid=UID)
        else:
            out = _call(d, req, route)
        assert out.get("backup_pending"), route


def test_no_route_can_write_the_confirmation(tmp_path, home):
    d, p, seed, req, app = _pending_daemon(tmp_path)
    path = custody.backup_state_path(p)
    before = open(path, "rb").read()
    fp = custody.seed_fingerprint(seed)
    forged = {"backup_confirmed_at": "2026-10-15T00:00:00Z", "fingerprint": fp,
              "code": "AAAA-AAAA-AAAA-AAAA", "required": False}
    for route in sorted(daemon_mod.REQUEST_ROUTES):
        try:
            _call(d, req, route, dict(forged))
        except Exception:
            pass
    for route in ("backup_confirm", "confirm_backup", "backup"):
        assert not _call(d, req, route, dict(forged))["ok"]
    assert open(path, "rb").read() == before
    assert d.backup_status()["state"] == "pending"


def test_a_planted_symlink_record_reads_as_pending(tmp_path, home):
    d, p, seed, req, app = _pending_daemon(tmp_path)
    fake = tmp_path / "fake.json"
    fake.write_text(json.dumps({"required": True, "backup_confirmed_at": "x",
                                "fingerprint": custody.seed_fingerprint(seed)}))
    os.unlink(custody.backup_state_path(p))
    os.symlink(fake, custody.backup_state_path(p))
    assert d.backup_status()["state"] == "pending"


def test_confirmation_flips_the_state_for_this_seed_only(tmp_path, home):
    d, p, seed, req, app = _pending_daemon(tmp_path)
    custody.confirm_backup(p, custody.seed_fingerprint(os.urandom(64)), "terminal-words")
    assert d.backup_status()["state"] == "pending"  # another seed's backup
    custody.confirm_backup(p, custody.seed_fingerprint(seed), "terminal-words")
    st = _call(d, req, "status")["backup"]
    assert st["state"] == "confirmed" and st["backup_confirmed_at"]
    r = _call(d, req, "request_spend", {"chain": "evm-46630", "destination":
                                        "0x" + "11" * 20, "asset": "native",
                                        "amount_wei": 1})
    assert not r.get("backup_pending")


def test_legacy_install_keeps_fund_routes_open_and_says_so(tmp_path, home, capsys):
    p, env_path, req, app = _prefix(tmp_path)
    # An install from before forced backup: a std_seed.key, no backup record.
    cfg = json.load(open(os.path.join(p, "spellbook.json")))
    cfg.pop("sealed_envelope_path")
    cfg["std_seed_path"] = os.path.join(p, "std_seed.key")
    _w(os.path.join(p, "spellbook.json"), json.dumps(cfg))
    _w(cfg["std_seed_path"], os.urandom(64).hex())
    d = Daemon(p)
    assert "predates forced backup" in capsys.readouterr().err
    assert _call(d, req, "status")["backup"]["state"] == "legacy"
    r = _call(d, req, "request_spend", {"chain": "evm-46630", "destination":
                                        "0x" + "11" * 20, "asset": "native",
                                        "amount_wei": 1})
    assert not r.get("backup_pending")


# ---------------------------------------------------------------- the human's proof

def _std_prefix(tmp_path):
    """install.sh layout: words on the machine, standard live keys."""
    prefix = tmp_path / "inst"
    prefix.mkdir(mode=0o700)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "make_standard_wallet.py"),
                        str(prefix)], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")})
    assert r.returncode == 0, r.stderr
    p = str(prefix)
    _w(os.path.join(p, "seed.key"), os.urandom(32).hex())
    _w(os.path.join(p, "spellbook.json"), json.dumps({
        "key_derivation": "standard", "seed_path": os.path.join(p, "seed.key"),
        "std_seed_path": os.path.join(p, "std_seed.key"),
        "allowed_request_uids": [AGENT], "allowed_approve_uids": [UID]}))
    custody.require_backup(p)
    from spellbook.seed import load_std_seed
    return p, load_std_seed(os.path.join(p, "std_seed.key"))


def test_reveal_key_backup_carries_a_one_time_code_that_confirms(tmp_path, capsys):
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    p, live = _std_prefix(tmp_path)
    priv = RSA.generate(2048)
    pub = base64.b64encode(priv.publickey().export_key(format="DER")).decode()
    assert exportmod.run_export(p, reveal_key=pub) == 0
    envelope = capsys.readouterr().out.strip()
    env = json.loads(base64.b64decode(envelope))
    aes = PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(base64.b64decode(env["k"]))
    blob = base64.b64decode(env["c"])
    doc = AES.new(aes, AES.MODE_GCM, nonce=base64.b64decode(env["n"])) \
        .decrypt_and_verify(blob[:-16], blob[-16:]).decode()
    code = re.search(r"BACKUP CONFIRMATION CODE:\s+(\S+)", doc).group(1)
    assert code not in envelope
    fp = custody.seed_fingerprint(live)
    assert custody.backup_status(p, fp)["state"] == "pending"
    assert exportmod.run_backup_confirm(p, "WRONG-CODE-0000-0000") != 0
    assert custody.backup_status(p, fp)["state"] == "pending"
    assert exportmod.run_backup_confirm(p, code.lower()) == 0
    st = custody.backup_status(p, fp)
    assert st["state"] == "confirmed" and st["method"] == "reveal-key-code"
    # One use.
    assert exportmod.run_backup_confirm(p, code) != 0


def test_terminal_export_records_the_confirmation_for_the_live_seed(tmp_path, monkeypatch, capsys):
    from spellbook.seed import mnemonic_from_entropy
    p, live = _std_prefix(tmp_path)
    std_entropy = bytes.fromhex(open(os.path.join(p, "std_entropy.key")).read().strip())
    master, slave = os.openpty()
    words = mnemonic_from_entropy(std_entropy).split()
    os.write(master, ("\n" + "\n".join(words[:3]) + "\n").encode())
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(exportmod, "login_uid", lambda: 4242)
    monkeypatch.setattr(exportmod, "verification_positions", lambda *a, **k: [1, 2, 3])
    monkeypatch.setattr(exportmod.shutil, "which", lambda name: None)
    assert exportmod.run_export(p, tty_path=os.ttyname(slave)) == 0
    while select.select([master], [], [], 0.2)[0]:
        if not os.read(master, 65536):
            break
    os.close(master)
    os.close(slave)
    out = capsys.readouterr().out
    assert "Backup confirmed" in out
    st = custody.backup_status(p, custody.seed_fingerprint(live))
    assert st["state"] == "confirmed" and st["method"] == "terminal-words"


def test_installer_makes_the_key_as_the_daemon_user_and_forces_backup():
    sh = open(os.path.join(ROOT, "install.sh"), encoding="utf-8").read()
    assert 'runuser -u "${SPELLBOOK_USER}" -- "${VENV}/bin/spellbook" ceremony-key' in sh
    assert "ceremony-adopt" in sh
    assert "custody.require_backup" in sh
    assert "backup-confirm" in sh
    assert "INSTALL INCOMPLETE" in sh


def test_envelope_path_uses_only_pinned_crypto():
    """The envelope code imported `cryptography`, which pyproject.toml and
    requirements-lock.txt never declared (an unpinned, unhashed crypto
    dependency in the decrypt path, f-03). It now uses pycryptodome, which
    both pin with hashes."""
    pinned = open(os.path.join(ROOT, "requirements-lock.txt")).read()
    assert "pycryptodome==" in pinned
    for sub in ("src/spellbook", "ceremony"):
        d = os.path.join(ROOT, sub)
        for name in os.listdir(d):
            if name.endswith(".py"):
                text = open(os.path.join(d, name), encoding="utf-8").read()
                assert not re.search(r"^\s*(from|import) cryptography\b", text, re.M), name


# ---------------------------------------------------------------- S-17 alignment

def test_public_half_is_published_as_pem_with_the_full_fingerprint(tmp_path, home):
    import hashlib
    from Crypto.PublicKey import RSA
    p, *_ = _prefix(tmp_path)
    info = custody.generate_ceremony_key(p)
    der = base64.b64decode(info["public_key_b64"])
    assert info["fingerprint"] == hashlib.sha256(der).hexdigest()  # full, as the pages show
    pem_path = os.path.join(p, "ceremony", "ceremony.pub.pem")
    assert stat.S_IMODE(os.stat(pem_path).st_mode) == 0o644
    k = RSA.import_key(open(pem_path, "rb").read())
    assert not k.has_private() and k.export_key(format="DER") == der
    r = subprocess.run([sys.executable, "-m", "spellbook.cli", "ceremony-key",
                        "--prefix", p, "--pem"], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")})
    assert r.returncode == 0, r.stderr
    assert "BEGIN PUBLIC KEY" in r.stdout and "PRIVATE" not in r.stdout


def test_config_naming_the_daemon_key_is_not_treated_as_legacy(tmp_path, home):
    """install.sh sets ceremony_key_path to the daemon's own key (for
    spellbook-ceremony apply); the daemon must neither move nor remove it."""
    p, env_path, *_ = _prefix(tmp_path)
    own = os.path.join(p, "ceremony", "private.pem")
    cfg = json.load(open(os.path.join(p, "spellbook.json")))
    cfg["ceremony_key_path"] = own
    _w(os.path.join(p, "spellbook.json"), json.dumps(cfg))
    info = custody.generate_ceremony_key(p)
    seed = os.urandom(64)
    _seal(env_path, info["public_key_b64"], seed)
    assert Daemon(p).std_seed == seed
    assert Daemon(p).std_seed == seed
    assert os.path.exists(own)
    r = subprocess.run([sys.executable, "-m", "spellbook.cli", "ceremony-adopt",
                        "--prefix", p], capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")})
    assert r.returncode == 0 and "already the daemon's key" in r.stdout
    assert os.path.exists(own)


def test_terminal_export_shows_the_ceremony_fingerprint_to_the_human(tmp_path, monkeypatch, capsys):
    from spellbook.seed import mnemonic_from_entropy
    p, live = _std_prefix(tmp_path)
    info = custody.generate_ceremony_key(p)
    std_entropy = bytes.fromhex(open(os.path.join(p, "std_entropy.key")).read().strip())
    master, slave = os.openpty()
    words = mnemonic_from_entropy(std_entropy).split()
    os.write(master, ("\n" + "\n".join(words[:3]) + "\n").encode())
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(exportmod, "login_uid", lambda: 4242)
    monkeypatch.setattr(exportmod, "verification_positions", lambda *a, **k: [1, 2, 3])
    monkeypatch.setattr(exportmod.shutil, "which", lambda name: None)
    assert exportmod.run_export(p, tty_path=os.ttyname(slave)) == 0
    seen = b""
    while select.select([master], [], [], 0.2)[0]:
        chunk = os.read(master, 65536)
        if not chunk:
            break
        seen += chunk
    os.close(master)
    os.close(slave)
    assert custody.grouped(info["fingerprint"]) in seen.decode(errors="replace")
    assert info["fingerprint"][:16] not in capsys.readouterr().out

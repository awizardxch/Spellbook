"""Tests for the sealed seed (docs/SEALED_SEED.md).

Throwaway seeds only. scrypt runs at a low cost (n=2^10) to keep the
suite fast; the cost is read back from the header on open, so the same
code path serves the production default.
"""
import json
import os
import stat
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from spellbook import sealed

N = 2 ** 10
PW = "correct horse battery"
SEED = bytes(range(32))
STD = bytes(range(64, 128))


def _install(tmp_path, *, standard=True, seed=SEED, std=STD):
    """A config dir laid out like install.sh / the agent-VM testnet home."""
    cfg_dir = tmp_path / "home"
    cfg_dir.mkdir(mode=0o700)
    cfg = {"seed_path": str(cfg_dir / "seed.key")}
    if standard:
        cfg.update(key_derivation="standard",
                   std_seed_path=str(cfg_dir / "std_seed.key"))
    (cfg_dir / "spellbook.json").write_text(json.dumps(cfg))
    if seed is not None:
        sealed._write_private(str(cfg_dir / "seed.key"), seed.hex())
    if standard and std is not None:
        sealed._write_private(str(cfg_dir / "std_seed.key"), std.hex())
    return str(cfg_dir), str(tmp_path / "ws" / "seed.sealed")


def _wipe(cfg_dir):
    for k in ("seed.key", "std_seed.key"):
        p = os.path.join(cfg_dir, k)
        if os.path.exists(p):
            os.remove(p)


def test_roundtrip_bytes():
    doc = sealed.seal_bytes(SEED, STD, PW, n=N)
    assert sealed.open_bytes(doc, PW) == (SEED, STD)
    blob = json.dumps(doc)
    assert SEED.hex() not in blob and STD.hex() not in blob


def test_roundtrip_without_std_seed():
    doc = sealed.seal_bytes(SEED, None, PW, n=N)
    assert sealed.open_bytes(doc, PW) == (SEED, None)


def test_wrong_password_fails_closed():
    doc = sealed.seal_bytes(SEED, STD, PW, n=N)
    with pytest.raises(sealed.WrongPassword):
        sealed.open_bytes(doc, PW + "x")


@pytest.mark.parametrize("field,value", [
    ("fingerprint", "0" * 16),
    ("has_std_seed", False),
    ("created", "2000-01-01T00:00:00Z"),
])
def test_header_is_authenticated(field, value):
    doc = sealed.seal_bytes(SEED, STD, PW, n=N)
    doc[field] = value
    with pytest.raises(sealed.WrongPassword):
        sealed.open_bytes(doc, PW)


def test_scrypt_cost_is_bounded():
    doc = sealed.seal_bytes(SEED, STD, PW, n=N)
    doc["kdf"]["n"] = 2 ** 30
    with pytest.raises(sealed.SealError, match="out-of-range"):
        sealed.open_bytes(doc, PW)


def test_short_password_refused():
    with pytest.raises(sealed.SealError, match="at least"):
        sealed.seal_bytes(SEED, STD, "short", n=N)


def test_seal_wipe_unlock_restores_same_files(tmp_path):
    cfg_dir, sp = _install(tmp_path)
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "unsealed"

    r = sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)
    assert r["has_std_seed"] is True
    assert stat.S_IMODE(os.stat(sp).st_mode) == 0o600
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "unlocked"

    _wipe(cfg_dir)  # the VM wipe
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "locked"

    out = sealed.unlock(PW, config_dir=cfg_dir, path=sp)
    assert len(out["written"]) == 2
    for name, value in (("seed.key", SEED), ("std_seed.key", STD)):
        p = os.path.join(cfg_dir, name)
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
        assert open(p).read() == value.hex()
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "unlocked"

    # Unlocking again is a harmless no-op.
    assert sealed.unlock(PW, config_dir=cfg_dir, path=sp)["already_present"]


def test_unlock_wrong_password_writes_nothing(tmp_path):
    cfg_dir, sp = _install(tmp_path)
    sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)
    _wipe(cfg_dir)
    with pytest.raises(sealed.WrongPassword):
        sealed.unlock("not the password!", config_dir=cfg_dir, path=sp)
    assert not os.path.exists(os.path.join(cfg_dir, "seed.key"))


def test_unlock_never_overwrites_a_different_wallet(tmp_path):
    cfg_dir, sp = _install(tmp_path)
    sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)
    _wipe(cfg_dir)
    other = bytes(32)
    sealed._write_private(os.path.join(cfg_dir, "seed.key"), other.hex())
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "mismatch"
    with pytest.raises(sealed.SealError, match="DIFFERENT seed"):
        sealed.unlock(PW, config_dir=cfg_dir, path=sp)
    assert open(os.path.join(cfg_dir, "seed.key")).read() == other.hex()
    # All-or-nothing: the std seed was not written either.
    assert not os.path.exists(os.path.join(cfg_dir, "std_seed.key"))


def test_seal_refuses_overwrite_and_foreign_replace(tmp_path):
    cfg_dir, sp = _install(tmp_path)
    sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)
    with pytest.raises(sealed.SealError, match="already exists"):
        sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)
    # Same wallet, new password: allowed with replace.
    sealed.seal("a brand new password", config_dir=cfg_dir, path=sp,
                replace=True, n=N)
    _wipe(cfg_dir)
    sealed.unlock("a brand new password", config_dir=cfg_dir, path=sp)
    # A different wallet on disk may not replace the seal.
    _wipe(cfg_dir)
    sealed._write_private(os.path.join(cfg_dir, "seed.key"), bytes(32).hex())
    sealed._write_private(os.path.join(cfg_dir, "std_seed.key"), STD.hex())
    with pytest.raises(sealed.SealError, match="DIFFERENT wallet"):
        sealed.seal(PW, config_dir=cfg_dir, path=sp, replace=True, n=N)


def test_seal_refuses_partial_standard_install(tmp_path):
    cfg_dir, sp = _install(tmp_path, std=None)
    with pytest.raises(sealed.SealError, match="partial seal"):
        sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)


def test_kdf_only_install(tmp_path):
    cfg_dir, sp = _install(tmp_path, standard=False)
    assert sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)["has_std_seed"] is False
    _wipe(cfg_dir)
    assert sealed.unlock(PW, config_dir=cfg_dir, path=sp)["written"] == [
        os.path.join(cfg_dir, "seed.key")]


def test_status_empty_and_cli_exit_codes(tmp_path, capsys):
    cfg_dir, sp = _install(tmp_path, seed=None, std=None)
    args = ["--config-dir", cfg_dir, "--sealed", sp, "status"]
    assert sealed.main(args) == sealed.STATE_EXIT["empty"]
    sealed._write_private(os.path.join(cfg_dir, "seed.key"), SEED.hex())
    sealed._write_private(os.path.join(cfg_dir, "std_seed.key"), STD.hex())
    assert sealed.main(args) == sealed.STATE_EXIT["unsealed"]
    out = capsys.readouterr().out
    assert SEED.hex() not in out


def test_cli_password_stdin(tmp_path, monkeypatch, capsys):
    import io
    cfg_dir, sp = _install(tmp_path)
    sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)
    _wipe(cfg_dir)
    monkeypatch.setattr("sys.stdin", io.StringIO(PW + "\n"))
    rc = sealed.main(["--config-dir", cfg_dir, "--sealed", sp,
                      "unlock", "--password-stdin"])
    assert rc == 0
    out = capsys.readouterr()
    assert PW not in out.out + out.err
    assert SEED.hex() not in out.out + out.err
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "unlocked"


def test_viewer_seal_then_unlock_flow(tmp_path):
    cfg_dir, sp = _install(tmp_path)
    v = sealed.Viewer(config_dir=cfg_dir, path=sp, n=N)
    assert 'action="%sseal"' % v.base in v.page()
    code, body = v.handle_post("seal", {"password": [PW], "confirm": ["nope"]})
    assert code == 400 and "do not match" in body
    code, body = v.handle_post("seal", {"password": [PW], "confirm": [PW]})
    assert code == 200 and v.done

    _wipe(cfg_dir)
    v = sealed.Viewer(config_dir=cfg_dir, path=sp, max_attempts=2)
    assert 'action="%sunlock"' % v.base in v.page()
    code, body = v.handle_post("unlock", {"password": ["wrong password!!"]})
    assert code == 400 and "1 attempts left" in body and not v.done
    code, body = v.handle_post("unlock", {"password": [PW]})
    assert code == 200 and v.done
    assert PW not in body and SEED.hex() not in body
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "unlocked"


def test_viewer_attempt_budget(tmp_path):
    cfg_dir, sp = _install(tmp_path)
    sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)
    _wipe(cfg_dir)
    v = sealed.Viewer(config_dir=cfg_dir, path=sp, max_attempts=1)
    v.handle_post("unlock", {"password": ["wrong password!!"]})
    assert v.done
    code, body = v.handle_post("unlock", {"password": [PW]})
    assert code == 400 and "too many attempts" in body
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "locked"


def test_http_viewer_end_to_end(tmp_path):
    cfg_dir, sp = _install(tmp_path)
    sealed.seal(PW, config_dir=cfg_dir, path=sp, n=N)
    _wipe(cfg_dir)

    from http.server import HTTPServer
    v = sealed.Viewer(config_dir=cfg_dir, path=sp)
    httpd = HTTPServer(("127.0.0.1", 0), sealed._handler(v))
    port = httpd.server_address[1]

    def loop():
        while not v.done:
            httpd.handle_request()
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    root = f"http://127.0.0.1:{port}"
    try:
        # Without the token: nothing.
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(root + "/")
        assert e.value.code == 404
        with urllib.request.urlopen(root + v.base) as r:
            assert r.headers["Cache-Control"] == "no-store"
            assert "default-src 'none'" in r.headers["Content-Security-Policy"]
            assert "locked" in r.read().decode()
        data = urllib.parse.urlencode({"password": PW}).encode()
        with urllib.request.urlopen(root + v.base + "unlock", data=data) as r:
            assert "Seed unlocked" in r.read().decode()
    finally:
        t.join(timeout=5)
        httpd.server_close()
    assert sealed.status(config_dir=cfg_dir, path=sp)["state"] == "unlocked"


def test_serve_refuses_remote_host_without_flag(tmp_path, capsys):
    cfg_dir, sp = _install(tmp_path)
    rc = sealed.main(["--config-dir", cfg_dir, "--sealed", sp,
                      "serve", "--host", "0.0.0.0"])
    assert rc == 2
    assert "--allow-remote" in capsys.readouterr().err


def test_locate_fallback_without_config(tmp_path):
    d = tmp_path / "bare"
    d.mkdir()
    loc = sealed.locate(str(d))
    assert loc["seed_path"] == str(d / "seed.key")
    assert loc["std_seed_path"] is None and loc["key_derivation"] == "kdf"


def test_unreadable_system_install_is_no_access(tmp_path, monkeypatch):
    # A system install's spellbook.json belongs to the daemon user; an agent
    # user must see "no_access", never a false "empty".
    cfg_dir, sp = _install(tmp_path)
    real_open = open

    def guarded(path, *a, **k):
        if str(path).endswith("spellbook.json"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *a, **k)
    monkeypatch.setattr(sealed, "open", guarded, raising=False)
    st = sealed.status(config_dir=cfg_dir, path=sp)
    assert st["state"] == "no_access"
    assert sealed.main(["--config-dir", cfg_dir, "--sealed", sp, "status"]) == 7

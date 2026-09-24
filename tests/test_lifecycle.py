"""Tests for the Spellbook lifecycle tooling (SPEC §12b item 4):

- version identity (VERSION file, package __version__, upgrade_check)
- doctor.py health checks and the repair-plan mapping
- the daemon's spellbook_version in status and the doctor RPC
- the upgrade wrapper's tag/forward-only guards

The doctor's privileged file checks run against a synthetic prefix tree —
never against a real /opt/spellbook.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile

import pytest

from spellbook import version as ver
from spellbook import doctor as doctor_mod
from spellbook import __version__


def _make_prefix(files):
    """Create a fake PREFIX dir; files is {relpath: (content, mode)}."""
    d = tempfile.mkdtemp()
    for rel, (content, mode) in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        os.chmod(p, mode)
    return d


def _make_socket():
    """A fake daemon socket file (presence check only)."""
    fd, p = tempfile.mkstemp()
    os.close(fd)
    return p


HEALTHY = {
    # Healthy = the installed VERSION matches the running package.
    "VERSION": (f"{__version__}\n", 0o644),
    "seed.key": ("aa" * 32, 0o600),
    "std_seed.key": ("bb" * 32, 0o600),
    "spellbook.json": (json.dumps({"seed_path": "/opt/spellbook/seed.key",
                                   "agent_muse_id": "m", "human_muse_id": "h",
                                   "key_derivation": "standard",
                                   "chia_enabled": False}), 0o600),
    "request.token": ("r" * 64, 0o600),
    "approve.token": ("a" * 64, 0o600),
    "ledger.jsonl": ('{"t":"genesis"}\n', 0o600),
}


def _by_id(checks, cid):
    for c in checks:
        if c["id"] == cid:
            return c
    raise AssertionError(f"no check {cid}")


# ---------------------------------------------------------------- version.py

def test_local_version_reads_prefix_file():
    d = _make_prefix({"VERSION": ("1.2.3\n", 0o644)})
    assert ver.local_version(d) == "1.2.3"


def test_local_version_falls_back_to_package():
    # No VERSION file anywhere: the imported package is the honest answer.
    from spellbook import __version__ as pkg_v
    d = tempfile.mkdtemp()
    assert ver.local_version(d) == pkg_v


def test_parse_version_rejects_junk():
    assert ver.parse("0.1.0") == (0, 1, 0)
    assert ver.parse("v1.2.3") == (1, 2, 3)
    assert ver.parse("latest") == (0,)  # unparseable -> zero tuple, never a claim
    assert ver.parse("") == (0,)


def test_upgrade_check_no_releases(monkeypatch):
    monkeypatch.setattr(ver, "latest_release_tag", lambda: None)
    d = _make_prefix({"VERSION": ("0.1.0\n", 0o644)})
    r = ver.upgrade_check(d)
    assert r["local"] == "0.1.0"
    assert r["latest"] is None
    assert r["upgrade_available"] is False
    assert "note" in r  # honest note, not an invented version


def test_upgrade_check_newer_available(monkeypatch):
    monkeypatch.setattr(ver, "latest_release_tag", lambda: "0.2.0")
    d = _make_prefix({"VERSION": ("0.1.0\n", 0o644)})
    r = ver.upgrade_check(d)
    assert r["upgrade_available"] is True


def test_upgrade_check_same_version(monkeypatch):
    monkeypatch.setattr(ver, "latest_release_tag", lambda: "0.1.0")
    d = _make_prefix({"VERSION": ("0.1.0\n", 0o644)})
    r = ver.upgrade_check(d)
    assert r["upgrade_available"] is False


# ---------------------------------------------------------------- doctor.py

def test_doctor_healthy_prefix():
    d = _make_prefix(HEALTHY)
    s = doctor_mod.summary(doctor_mod.run_checks(prefix=d,
                                                 socket_path=_make_socket()))
    assert s["ok"] is True
    assert _by_id(s["checks"], "keys:seed.key")["ok"] is True
    assert _by_id(s["checks"], "config")["ok"] is True
    assert _by_id(s["checks"], "tokens:request.token")["ok"] is True
    # A fully healthy install needs no repair at all.
    plan = doctor_mod.repair_plan(s["checks"])
    assert plan["self_repairable"] == []
    assert plan["manual"] == []


def test_doctor_never_reports_key_contents():
    d = _make_prefix(HEALTHY)
    blob = json.dumps(doctor_mod.summary(doctor_mod.run_checks(prefix=d)))
    assert "aa" * 32 not in blob
    assert "bb" * 32 not in blob


STATE_FILES = ("seed.key", "std_seed.key", "request.token", "approve.token",
               "spellbook.json", "policy.json", "ledger.jsonl")


def _state_free(plan):
    """No repair ACTION may target a state file: every self-repair item must
    be a code reinstall via the wrapper, and its command must not name a
    state file. (Guidance text naming the files is fine — it's advice.)"""
    for item in plan["self_repairable"]:
        if item.get("action") != "reinstall_code":
            return False
        if item.get("via") != "/usr/local/bin/spellbook-upgrade":
            return False
        cmd = (item.get("command") or "").lower()
        if any(f in cmd for f in STATE_FILES):
            return False
    return True


def test_doctor_missing_seed_key_fails_closed():
    files = dict(HEALTHY)
    del files["seed.key"]
    s = doctor_mod.summary(doctor_mod.run_checks(prefix=_make_prefix(files)))
    assert s["ok"] is False
    keys = _by_id(s["checks"], "keys:seed.key")
    assert keys["ok"] is False
    plan = doctor_mod.repair_plan(s["checks"])
    assert _state_free(plan)  # self-repair never touches key material
    assert any("keys" in m["check"] for m in plan["manual"])


def test_doctor_bad_key_mode_fails_closed():
    files = dict(HEALTHY)
    files["seed.key"] = ("aa" * 32, 0o644)  # too open
    s = doctor_mod.summary(doctor_mod.run_checks(prefix=_make_prefix(files)))
    assert s["ok"] is False
    plan = doctor_mod.repair_plan(s["checks"])
    assert _state_free(plan)
    assert any("keys" in m["check"] for m in plan["manual"])


def test_doctor_corrupt_config_fails_closed():
    files = dict(HEALTHY)
    files["spellbook.json"] = ("{not json", 0o600)
    s = doctor_mod.summary(doctor_mod.run_checks(prefix=_make_prefix(files)))
    assert s["ok"] is False
    cfg = _by_id(s["checks"], "config")
    assert "do not hand-edit" in cfg["hint"]
    plan = doctor_mod.repair_plan(s["checks"])
    assert _state_free(plan)
    assert any("config" in m["check"] for m in plan["manual"])


def test_doctor_missing_ledger_fails_closed():
    files = dict(HEALTHY)
    del files["ledger.jsonl"]
    s = doctor_mod.summary(doctor_mod.run_checks(prefix=_make_prefix(files)))
    assert s["ok"] is False
    plan = doctor_mod.repair_plan(s["checks"])
    assert _state_free(plan)
    assert any("ledger" in m["check"] for m in plan["manual"])


def test_doctor_missing_version_is_code_problem():
    """A missing VERSION file is code/installer state: self-repairable via
    a verified release reinstall (same tag, not a downgrade)."""
    files = dict(HEALTHY)
    del files["VERSION"]
    s = doctor_mod.summary(doctor_mod.run_checks(prefix=_make_prefix(files)))
    assert s["ok"] is False
    plan = doctor_mod.repair_plan(s["checks"])
    assert _state_free(plan)
    assert any(i["problem"] == "version_record" if "problem" in i
               else i["action"] == "reinstall_code"
               for i in plan["self_repairable"])


def test_doctor_missing_daemon_socket_is_code_problem():
    files = dict(HEALTHY)
    s = doctor_mod.summary(doctor_mod.run_checks(prefix=_make_prefix(files)))
    assert s["ok"] is False
    sock = _by_id(s["checks"], "daemon_socket")
    assert sock["ok"] is False
    plan = doctor_mod.repair_plan(s["checks"])
    assert _state_free(plan)
    assert any(i["action"] == "reinstall_code"
               for i in plan["self_repairable"])


def test_repair_plan_never_touches_state():
    """Even with everything broken, no repair item may propose regenerating
    keys, minting tokens, editing config, or rebuilding the ledger."""
    s = doctor_mod.summary(doctor_mod.run_checks(prefix=_make_prefix({})))
    plan = doctor_mod.repair_plan(s["checks"])
    assert _state_free(plan)
    # ...and the manual guidance names each broken state file
    manual_checks = {m["check"] for m in plan["manual"]}
    assert {"keys", "tokens", "config", "ledger"} <= manual_checks


def test_repair_plan_tag_is_safe():
    d = _make_prefix(HEALTHY)
    checks = doctor_mod.run_checks(prefix=d)
    plan = doctor_mod.repair_plan(checks)
    items = [i for i in plan["self_repairable"]
             if i["action"] == "reinstall_code"]
    assert items, "expected a reinstall_code action"
    import re
    for i in items:
        assert re.fullmatch(r"\d+\.\d+\.\d+", i["tag"]), i["tag"]
        assert i["via"] == "/usr/local/bin/spellbook-upgrade"
        assert "--from-dir" not in i["command"]


# ---------------------------------------------------------------- wrapper

WRAPPER = os.path.join(os.path.dirname(__file__), "..", "scripts",
                       "spellbook-upgrade")


def _run_wrapper(tag):
    return subprocess.run(["sh", os.path.abspath(WRAPPER), tag],
                          capture_output=True, text=True)


def test_wrapper_requires_root():
    if os.geteuid() == 0:
        pytest.skip("wrapper root-check only testable as non-root")
    r = _run_wrapper("0.2.0")
    assert r.returncode != 0
    assert "run via sudo" in r.stderr


def test_wrapper_rejects_bad_tags():
    # Tag validation runs before the root check, so this works as any user.
    r = _run_wrapper("--from-dir")
    assert r.returncode != 0
    assert "want X.Y.Z" in r.stderr or "bad tag" in r.stderr
    r = _run_wrapper("latest")
    assert r.returncode != 0

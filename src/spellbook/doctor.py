"""`spellbook doctor` — read-only install health checks an agent runs itself.

Every check is presence/permissions/shape only. The doctor NEVER reads key
material, never regenerates keys or tokens, never writes config. When a
check fails, `repair_plan()` maps it to either a safe self-repair (reinstall
code via the privileged upgrade wrapper — signed releases only) or explicit
manual guidance (key/config/ledger problems fail closed: restore from backup,
never re-key).

SPEC §12b item 4.
"""
import json
import os
import stat

from spellbook import version as ver

SPELLBOOK_USER = "spellbook"
UPGRADE_WRAPPER = "/usr/local/bin/spellbook-upgrade"

# Checks whose failure means "code on disk is wrong" -> safe to reinstall.
CODE_CHECKS = {"package", "installed_version", "sage", "daemon_version",
               "daemon_socket", "daemon_status"}
# Checks whose failure means "identity/state is wrong" -> fail closed.
STATE_CHECKS = {"keys", "tokens", "config", "ledger"}


def _check(name, ok, detail="", hint="", skipped=False):
    return {"id": name, "ok": bool(ok), "detail": detail, "hint": hint,
            "skipped": bool(skipped)}


def _mode600_ok(path):
    try:
        st = os.stat(path)
    except OSError as e:
        return False, f"missing: {e.strerror}"
    mode = stat.S_IMODE(st.st_mode)
    if mode != 0o600:
        return False, f"mode is {oct(mode)}, want 0o600"
    return True, "present, 0600"


def _owner_ok(path, user=SPELLBOOK_USER):
    try:
        import pwd
        want = pwd.getpwnam(user).pw_uid
    except KeyError:
        return True, f"user {user} not present on this machine — ownership not checked"
    try:
        st = os.stat(path)
    except OSError as e:
        return False, f"missing: {e.strerror}"
    if st.st_uid != want:
        return False, f"owned by uid {st.st_uid}, want {user} ({want})"
    return True, f"owned by {user}"


def run_checks(prefix=None, request_token=None, socket_path=None):
    """Run all health checks. Never raises; each check reports ok/skipped.

    `prefix` is the install dir (/opt/spellbook). The caller must be able to
    stat it — the daemon (running as the spellbook user) can; a bare agent
    user cannot traverse it, which is why the daemon exposes this via the
    `doctor` RPC instead of the agent running it locally.
    """
    pfx = prefix or ver.prefix()
    checks = []

    # 1. package imports
    try:
        import spellbook
        pkg_v = getattr(spellbook, "__version__", "")
        checks.append(_check("package", bool(pkg_v),
                             f"spellbook {pkg_v} importable" if pkg_v
                             else "importable but version unreadable"))
    except Exception as e:
        checks.append(_check("package", False, f"import failed: {e}"))
        pkg_v = "unknown"

    # 2. installed version record matches the package
    ver_file = os.path.join(pfx, "VERSION")
    try:
        with open(ver_file) as f:
            recorded = f.read().strip()
        checks.append(_check(
            "installed_version",
            recorded == pkg_v and bool(recorded),
            f"PREFIX/VERSION={recorded!r} package={pkg_v!r}"))
    except OSError as e:
        checks.append(_check("installed_version", False,
                             f"cannot read {ver_file}: {e.strerror}"))

    # 3. key material: presence + perms + ownership only — never read.
    # A missing or wrong key file is never auto-repaired: regenerating would
    # strand funds at the old addresses.
    for key in ("seed.key", "std_seed.key"):
        path = os.path.join(pfx, key)
        ok, detail = _mode600_ok(path)
        ook, odetail = _owner_ok(path)
        checks.append(_check(
            f"keys:{key}", ok and ook, f"{detail}; {odetail}",
            hint=f"never regenerate {key} automatically: restore from the paper backup or re-provision with the human"))

    # 4. config parses and has the expected shape
    cfg_path = os.path.join(pfx, "spellbook.json")
    cfg = None
    try:
        with open(cfg_path) as f:
            cfg = json.load(f)
        shape_ok = isinstance(cfg, dict) and "seed_path" in cfg
        checks.append(_check("config", shape_ok,
                             "valid JSON, has seed_path" if shape_ok
                             else "valid JSON but missing seed_path",
                             hint="do not hand-edit: restore spellbook.json from backup or re-provision with the human"))
    except Exception as e:
        checks.append(_check("config", False, f"unreadable/invalid: {e}",
                             hint="do not hand-edit: restore spellbook.json from backup or re-provision with the human"))

    # 5. tokens exist, 0600. Never minted by hand — a missing token is a
    # broken install the human re-provisions.
    for tok in ("request.token", "approve.token"):
        path = os.path.join(pfx, tok)
        ok, detail = _mode600_ok(path)
        checks.append(_check(f"tokens:{tok}", ok, detail,
                             hint=f"never mint {tok} by hand: re-provision with the human"))

    # 6. ledger file exists (rows are read through the API, never the file).
    # Append-only history is never reconstructed.
    ledger_path = os.path.join(pfx, "ledger.jsonl")
    checks.append(_check("ledger", os.path.isfile(ledger_path),
                         "present" if os.path.isfile(ledger_path)
                         else f"missing {ledger_path}",
                         hint="never reconstruct the ledger: restore from backup or re-provision with the human"))

    # 7. sage binary, when Chia is enabled
    if isinstance(cfg, dict) and cfg.get("chia_enabled", True):
        sage_bin = (cfg.get("sage_bin")
                    or os.path.join(pfx, "bin", "sage"))
        if sage_bin:
            ok = os.path.isfile(sage_bin) and os.access(sage_bin, os.X_OK)
            checks.append(_check("sage", ok,
                                 f"{sage_bin} executable" if ok
                                 else f"{sage_bin} missing/not executable"))
        else:
            checks.append(_check("sage", True, "chia enabled, no sage_bin configured",
                                 skipped=True))
    else:
        checks.append(_check("sage", True, "chia not enabled", skipped=True))

    # 8-10. daemon reachability + version (needs the request token)
    sock = socket_path or os.environ.get(
        "SPELLBOOK_SOCKET", "/run/spellbook/spellbook.sock")
    checks.append(_check("daemon_socket", os.path.exists(sock),
                         f"{sock} present" if os.path.exists(sock)
                         else f"{sock} missing — daemon not running?"))
    if request_token:
        try:
            from spellbook.client import AgentClient
            st = AgentClient(sock, request_token).status()
            ok = bool(st.get("ok"))
            checks.append(_check("daemon_status", ok,
                                 f"status ok, queue_depth={st.get('queue_depth')}"
                                 if ok else f"status returned {st!r}"))
            dver = st.get("spellbook_version", "")
            checks.append(_check(
                "daemon_version", dver == pkg_v and bool(dver),
                f"daemon={dver!r} local={pkg_v!r}"))
        except Exception as e:
            checks.append(_check("daemon_status", False, f"RPC failed: {e}"))
            checks.append(_check("daemon_version", False, "unknown (status failed)",
                                 skipped=True))
    else:
        checks.append(_check("daemon_status", False, "no request token available",
                             skipped=True))
        checks.append(_check("daemon_version", False, "no request token available",
                             skipped=True))

    return checks


def _failing(checks):
    return [c for c in checks if not c["ok"] and not c["skipped"]]


def repair_plan(checks):
    """Map failing checks to repair actions.

    Returns {"self_repairable": [actions], "manual": [guidance]}.
    Self-repair only ever reinstalls CODE via the signed-release upgrade
    wrapper — it never touches keys, tokens, config, or the ledger.
    """
    failing = _failing(checks)
    names = {c["id"].split(":")[0] for c in failing}
    plan = {"self_repairable": [], "manual": []}

    code_bad = bool(names & CODE_CHECKS)
    state_bad = names & STATE_CHECKS

    if code_bad:
        tag = ver.local_version()
        if tag == "unknown":
            tag = None
        plan["self_repairable"].append({
            "action": "reinstall_code",
            "via": UPGRADE_WRAPPER,
            "tag": tag,
            "why": ("re-fetch and reinstall the signed release for the "
                    "installed version; keys/config/ledger untouched"),
            "command": (f"sudo -n {UPGRADE_WRAPPER} {tag}"
                        if tag else f"sudo -n {UPGRADE_WRAPPER} <tag>"),
        })

    guidance = {
        "keys": ("key material missing or wrong perms — NEVER regenerate. "
                 "Restore from the paper backup (§6 of install) or re-provision "
                 "the machine with the human."),
        "tokens": ("token file missing — NEVER mint replacements by hand. "
                   "Re-provision with the human; the approve token lives on the "
                   "human's separate device (O5)."),
        "config": ("spellbook.json invalid — do not hand-edit. Restore from "
                   "backup or re-provision with the human."),
        "ledger": ("ledger.jsonl missing — the decision history is append-only "
                   "and never reconstructed. Re-provision with the human."),
    }
    for name in sorted(state_bad):
        plan["manual"].append({"check": name,
                              "guidance": guidance.get(name, "manual fix needed")})
    return plan


def summary(checks):
    failing = _failing(checks)
    skipped = [c for c in checks if c["skipped"]]
    return {
        "ok": not failing,
        "passed": len(checks) - len(failing) - len(skipped),
        "failed": [c["id"] for c in failing],
        "skipped": [c["id"] for c in skipped],
        "checks": checks,
    }

"""Sealed seed — password-locked copy of the wallet seed that survives VM wipes.

The problem (docs/SEALED_SEED.md): agent VMs lose everything outside
~/workspace on a wipe or session reset, including the daemon's seed files.
The paper backup recovers the wallet, but only by a human re-typing 24
words into the machine. The sealed seed makes that routine:

  seal    the human picks a password; the daemon's seed files are encrypted
          into ONE file under ~/workspace (which persists across wipes).
  unlock  after a wipe, the human enters the password; the seed files are
          written back exactly as they were (0600), and the daemon starts
          with the same wallet.
  serve   a one-time local web page (the "human viewer") for seal/unlock,
          so the password goes from the human's browser straight to this
          process — never through the agent's conversation.

Format (JSON, version 1):
  header  {format, version, kdf: {name: "scrypt", n, r, p, salt},
           cipher: "aes-256-gcm", nonce, created, fingerprint}
  body    ciphertext + 16-byte GCM tag (base64), AAD = canonical header.
The plaintext is {"seed": <64 hex>, "std_seed": <128 hex> | null}: exactly
the two files the daemon loads (SPEC §2 / §2b). A wrong password or any
edit to the header fails the GCM tag — nothing is written.

`fingerprint` is sha256("spellbook-sealed-fp/v1" || seed)[:8] — enough to
tell, without the password, whether the seed on disk is the one sealed
here; it reveals nothing usable about a 256-bit seed.

Hard rules (seed.py): no seed material or password in logs, stdout, error
messages, or argv. The password is read from a TTY prompt, from stdin
(--password-stdin), or from the viewer page's POST body — never argv/env.
Honest limit: the seal protects the seed AT REST (a leaked or synced
workspace). It cannot protect against a hostile process running as the
same OS user while the seed is unlocked; that is the daemon-user split's
job (install.sh, S2).
"""
import argparse
import base64
import datetime
import getpass
import hashlib
import hmac
import html
import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from Crypto.Cipher import AES

from spellbook.seed import load_seed, load_std_seed

FORMAT = "spellbook-sealed-seed"
VERSION = 1
MIN_PASSWORD_LEN = 12
# scrypt cost: 2^17 * 128 * r = 128 MiB, ~0.5 s. Stored in the header so it
# can be raised later; bounded on open so a crafted file cannot exhaust RAM.
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
_N_MIN, _N_MAX = 2 ** 10, 2 ** 20
_FP_TAG = b"spellbook-sealed-fp/v1"

DEFAULT_SEALED_PATH = os.path.join(
    os.path.expanduser("~"), "workspace", ".spellbook", "seed.sealed")
# Where spellbook.json may live, in lookup order (after an explicit
# --config-dir / SPELLBOOK_CONFIG_DIR): the agent-VM testnet home, then a
# system install (install.sh PREFIX).
_CONFIG_CANDIDATES = (
    os.path.join(os.path.expanduser("~"), ".spellbook-testnet"),
    "/opt/spellbook",
)


class SealError(Exception):
    """Refusal with a message safe to show (never carries key material)."""


class WrongPassword(SealError):
    pass


# ---------------------------------------------------------------- locations

def sealed_path(path: str | None = None) -> str:
    return path or os.environ.get("SPELLBOOK_SEALED_PATH") or DEFAULT_SEALED_PATH


def locate(config_dir: str | None = None) -> dict:
    """Where the daemon's seed files live, per its spellbook.json.

    Returns {config_dir, seed_path, std_seed_path, key_derivation,
    access_denied}. std_seed_path is None when the config does not use one
    (kdf mode). Without any spellbook.json, falls back to the agent-VM
    testnet home (~/.spellbook-testnet/seed.key). A config that exists but
    this user may not read (a system install owned by the daemon user) is
    reported as access_denied — never silently skipped, or a live wallet
    would look "empty".
    """
    explicit = config_dir or os.environ.get("SPELLBOOK_CONFIG_DIR")
    candidates = (explicit,) if explicit else _CONFIG_CANDIDATES
    for d in candidates:
        cfg_path = os.path.join(d, "spellbook.json")
        try:
            with open(cfg_path) as f:
                cfg = json.load(f)
        except PermissionError:
            return {"config_dir": d, "seed_path": os.path.join(d, "seed.key"),
                    "std_seed_path": None, "key_derivation": None,
                    "access_denied": True}
        except FileNotFoundError:
            if os.path.isdir(d) and not os.access(d, os.R_OK | os.X_OK):
                return {"config_dir": d,
                        "seed_path": os.path.join(d, "seed.key"),
                        "std_seed_path": None, "key_derivation": None,
                        "access_denied": True}
            continue
        except (OSError, ValueError):
            continue
        kd = cfg.get("key_derivation", "kdf")
        return {
            "config_dir": d,
            "seed_path": cfg.get("seed_path") or os.path.join(d, "seed.key"),
            "std_seed_path": cfg.get("std_seed_path") if kd == "standard"
            else None,
            "key_derivation": kd,
            "access_denied": False,
        }
    d = explicit or _CONFIG_CANDIDATES[0]
    std = os.path.join(d, "std_seed.key")
    return {
        "config_dir": d,
        "seed_path": os.path.join(d, "seed.key"),
        "std_seed_path": std if os.path.exists(std) else None,
        "key_derivation": "standard" if os.path.exists(std) else "kdf",
        "access_denied": False,
    }


# ---------------------------------------------------------------- crypto

def fingerprint(seed: bytes) -> str:
    return hashlib.sha256(_FP_TAG + seed).hexdigest()[:16]


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def _derive(password: str, kdf: dict) -> bytes:
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    if n < _N_MIN or n > _N_MAX or n & (n - 1) or not (1 <= r <= 16) \
            or not (1 <= p <= 4):
        raise SealError("sealed file has out-of-range scrypt parameters")
    return hashlib.scrypt(password.encode("utf-8"), salt=_unb64(kdf["salt"]),
                          n=n, r=r, p=p, dklen=32,
                          maxmem=256 * 1024 * 1024)


def check_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise SealError(
            f"password must be at least {MIN_PASSWORD_LEN} characters")


def seal_bytes(seed: bytes, std_seed: bytes | None, password: str,
               *, n: int = SCRYPT_N) -> dict:
    """Encrypt the seed pair; returns the sealed document (a dict)."""
    if len(seed) != 32:
        raise SealError("seed must be exactly 32 bytes")
    if std_seed is not None and len(std_seed) != 64:
        raise SealError("std seed must be exactly 64 bytes")
    check_password(password)
    header = {
        "format": FORMAT,
        "version": VERSION,
        "kdf": {"name": "scrypt", "n": n, "r": SCRYPT_R, "p": SCRYPT_P,
                "salt": _b64(os.urandom(16))},
        "cipher": "aes-256-gcm",
        "nonce": _b64(os.urandom(12)),
        "created": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fingerprint": fingerprint(seed),
        "has_std_seed": std_seed is not None,
    }
    key = _derive(password, header["kdf"])
    plain = json.dumps({"seed": seed.hex(),
                        "std_seed": std_seed.hex() if std_seed else None})
    c = AES.new(key, AES.MODE_GCM, nonce=_unb64(header["nonce"]))
    c.update(_aad(header))
    ct, tag = c.encrypt_and_digest(plain.encode())
    return {**header, "ciphertext": _b64(ct + tag)}


def open_bytes(doc: dict, password: str) -> tuple[bytes, bytes | None]:
    """Decrypt a sealed document -> (seed, std_seed | None)."""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise SealError("not a Spellbook sealed seed file")
    if doc.get("version") != VERSION:
        raise SealError(f"unsupported sealed seed version {doc.get('version')!r}")
    if doc.get("cipher") != "aes-256-gcm" or \
            (doc.get("kdf") or {}).get("name") != "scrypt":
        raise SealError("unsupported sealed seed cipher/kdf")
    header = {k: v for k, v in doc.items() if k != "ciphertext"}
    try:
        blob = _unb64(doc["ciphertext"])
        nonce = _unb64(header["nonce"])
    except (KeyError, ValueError):
        raise SealError("sealed seed file is corrupt")
    if len(blob) < 17:
        raise SealError("sealed seed file is corrupt")
    key = _derive(password, header["kdf"])
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.update(_aad(header))
    try:
        plain = c.decrypt_and_verify(blob[:-16], blob[-16:])
    except ValueError:
        # Wrong password and a tampered file are indistinguishable by design.
        raise WrongPassword("wrong password (or the sealed file was altered)")
    body = json.loads(plain)
    seed = bytes.fromhex(body["seed"])
    std = bytes.fromhex(body["std_seed"]) if body.get("std_seed") else None
    if len(seed) != 32 or (std is not None and len(std) != 64):
        raise SealError("sealed seed file is corrupt")
    if not hmac.compare_digest(fingerprint(seed), str(doc.get("fingerprint"))):
        raise SealError("sealed seed fingerprint mismatch")
    return seed, std


# ---------------------------------------------------------------- files

def _write_private(path: str, text: str) -> None:
    """Create `path` 0600 with no loose-permission window; never overwrite."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    # Running as root for a system install: hand the file to whoever owns
    # the directory (the daemon user), or the daemon cannot read it.
    if os.geteuid() == 0:
        st = os.stat(parent)
        os.chown(path, st.st_uid, st.st_gid)


def read_sealed(path: str | None = None) -> dict:
    p = sealed_path(path)
    try:
        with open(p) as f:
            return json.load(f)
    except FileNotFoundError:
        raise SealError(f"no sealed seed at {p}")
    except ValueError:
        raise SealError(f"{p} is not valid JSON")


def write_sealed(doc: dict, path: str | None = None, *,
                 replace: bool = False) -> str:
    p = sealed_path(path)
    if os.path.exists(p) and not replace:
        raise SealError(f"{p} already exists (use --replace to re-seal)")
    tmp = f"{p}.tmp-{secrets.token_hex(4)}"
    _write_private(tmp, json.dumps(doc, indent=1) + "\n")
    os.replace(tmp, p)
    return p


def _file_seed(path: str | None, loader) -> bytes | None:
    if not path or not os.path.exists(path):
        return None
    return loader(path)


def seal(password: str, *, config_dir: str | None = None,
         path: str | None = None, replace: bool = False,
         n: int = SCRYPT_N) -> dict:
    """Seal the daemon's current seed files. Returns public status info."""
    loc = locate(config_dir)
    seed = _file_seed(loc["seed_path"], load_seed)
    if seed is None:
        raise SealError(
            f"no seed at {loc['seed_path']} — nothing to seal (a locked "
            "wallet is unlocked first, a lost one is restored from paper)")
    std = None
    if loc["std_seed_path"]:
        std = _file_seed(loc["std_seed_path"], load_std_seed)
        if std is None:
            raise SealError(
                f"config uses key_derivation=standard but "
                f"{loc['std_seed_path']} is missing — refusing a partial seal")
    p = sealed_path(path)
    if os.path.exists(p) and replace:
        # Re-sealing (password change) must never swap in a different
        # wallet over the backup of the live one.
        old = read_sealed(p)
        if old.get("fingerprint") != fingerprint(seed):
            raise SealError(
                "the existing seal holds a DIFFERENT wallet than the seed on "
                "disk — refusing to replace it; move it aside by hand first")
    doc = seal_bytes(seed, std, password, n=n)
    write_sealed(doc, p, replace=replace)
    return {"sealed_path": p, "fingerprint": doc["fingerprint"],
            "has_std_seed": doc["has_std_seed"]}


def unlock(password: str, *, config_dir: str | None = None,
           path: str | None = None) -> dict:
    """Decrypt the seal and write the daemon's seed files back (0600).

    Never overwrites a different seed: if a seed file already exists it
    must match the sealed one byte-for-byte (then this is a no-op).
    """
    doc = read_sealed(path)
    seed, std = open_bytes(doc, password)
    loc = locate(config_dir)
    targets = [(loc["seed_path"], seed.hex(), load_seed)]
    if std is not None:
        std_path = loc["std_seed_path"] or os.path.join(
            os.path.dirname(loc["seed_path"]), "std_seed.key")
        targets.append((std_path, std.hex(), load_std_seed))
    elif loc["std_seed_path"]:
        raise SealError(
            "config needs a std seed (key_derivation=standard) but this seal "
            "has none — it was made for a different install")
    # Check everything before writing anything.
    todo = []
    for p, hex_value, loader in targets:
        if os.path.exists(p):
            if loader(p).hex() != hex_value:
                raise SealError(
                    f"{p} already holds a DIFFERENT seed — refusing to "
                    "overwrite a live wallet")
        else:
            todo.append((p, hex_value))
    for p, hex_value in todo:
        _write_private(p, hex_value)
    return {"written": [p for p, _ in todo],
            "already_present": len(todo) == 0,
            "fingerprint": doc["fingerprint"]}


def status(*, config_dir: str | None = None, path: str | None = None) -> dict:
    """Public state for the agent and the viewer — never needs the password.

    state:
      unlocked  seed on disk AND it matches the seal (the normal state)
      locked    seal present, seed missing (after a wipe: ask the human)
      unsealed  seed on disk, no seal yet (a wipe now would need paper)
      mismatch  seed on disk differs from the seal (re-seal or investigate)
      empty     neither (fresh machine: install, or restore from paper)
      no_access the install belongs to another OS user (system install);
                run as that user or root — never guess
    """
    loc = locate(config_dir)
    p = sealed_path(path)
    if loc.get("access_denied"):
        return {"state": "no_access", "sealed_path": p, "sealed": None,
                "seal_error": None, "sealed_at": None, "fingerprint": None,
                "seed_path": loc["seed_path"], "std_seed_path": None,
                "seed_present": None, "config_dir": loc["config_dir"]}
    seed_present = os.path.exists(loc["seed_path"])
    doc = None
    seal_error = None
    if os.path.exists(p):
        try:
            doc = read_sealed(p)
            if doc.get("format") != FORMAT:
                seal_error = "not a Spellbook sealed seed file"
        except SealError as e:
            seal_error = str(e)
    if doc is not None and seal_error is None:
        if seed_present:
            try:
                fp = fingerprint(load_seed(loc["seed_path"]))
            except (OSError, ValueError) as e:
                seal_error = f"seed file unreadable: {e.__class__.__name__}"
                fp = None
            state = "unlocked" if fp == doc.get("fingerprint") else "mismatch"
        else:
            state = "locked"
    else:
        state = "unsealed" if seed_present else "empty"
    return {
        "state": state,
        "sealed_path": p,
        "sealed": doc is not None and seal_error is None,
        "seal_error": seal_error,
        "sealed_at": (doc or {}).get("created"),
        "fingerprint": (doc or {}).get("fingerprint"),
        "seed_path": loc["seed_path"],
        "std_seed_path": loc["std_seed_path"],
        "seed_present": seed_present,
        "config_dir": loc["config_dir"],
    }


STATE_HINT = {
    "unlocked": "seed present and matches the seal — nothing to do",
    "locked": "seed is SEALED and not loaded: ask your human to unlock it "
              "(spellbook-seed serve, then they open the link and enter "
              "their password). Never ask for the password in chat.",
    "unsealed": "seed present but NOT sealed: a VM wipe now needs the paper "
                "backup. Ask your human to seal it (spellbook-seed serve).",
    "mismatch": "seed on disk differs from the seal — do not unlock over it; "
                "tell your human (re-seal only if the disk seed is the right one)",
    "empty": "no seed and no seal: fresh install, or restore from the paper "
             "backup (python3 -m spellbook.recovery restore)",
    "no_access": "the wallet belongs to the daemon's own OS user (system "
                 "install) — this user cannot see it, by design. Ask your "
                 "human to run spellbook-seed as that user (sudo -u spellbook).",
}
STATE_EXIT = {"unlocked": 0, "locked": 3, "unsealed": 4, "mismatch": 5,
              "empty": 6, "no_access": 7}


# ---------------------------------------------------------------- viewer

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Spellbook seed lock</title>
<style>
:root{{--bg:#0d0b16;--panel:#171327;--text:#e8e4f6;--muted:#a49cc4;
--accent:#9b7bff;--ok:#5ad19a;--warn:#f0b35a;--bad:#ff6b7d}}
@media (prefers-color-scheme: light){{:root{{--bg:#f6f4fb;--panel:#fff;
--text:#1d1830;--muted:#5d5678;--accent:#6a4bd6;--ok:#1d8a57;--warn:#9a5d00;
--bad:#c02639}}}}
body{{margin:0;background:var(--bg);color:var(--text);
font:16px/1.5 system-ui,sans-serif;padding:24px 16px}}
main{{max-width:560px;margin:0 auto;background:var(--panel);
border-radius:12px;padding:24px}}
h1{{font-size:1.3rem;margin:0 0 4px}} .muted{{color:var(--muted)}}
.state{{font-weight:600}} .unlocked{{color:var(--ok)}}
.locked,.unsealed{{color:var(--warn)}} .mismatch,.empty,.err{{color:var(--bad)}}
label{{display:block;margin:12px 0 4px}}
input{{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;
border:1px solid var(--muted);background:transparent;color:var(--text);
font-size:1rem}}
button{{margin-top:16px;padding:10px 18px;border:0;border-radius:8px;
background:var(--accent);color:#fff;font-size:1rem;cursor:pointer}}
code{{font-size:.85em;word-break:break-all}}
</style></head><body><main>
<h1>Spellbook seed lock</h1>
<p class="muted">A one-time page served by your agent's machine. Your password
goes from this browser to that machine only — never to the agent's chat,
never to the hosted dashboard.</p>
{message}
<p>State: <span class="state {state}">{state}</span><br>
<span class="muted">{hint}</span></p>
{form}
<p class="muted">Sealed file: <code>{sealed_path}</code><br>
Fingerprint: <code>{fingerprint}</code></p>
</main></body></html>
"""

_UNLOCK_FORM = """<form method="post" action="{base}unlock">
<label for="pw">Seal password</label>
<input id="pw" name="password" type="password" autocomplete="current-password"
 required minlength="{minlen}" autofocus>
<button type="submit">Unlock seed</button></form>"""

_SEAL_FORM = """<form method="post" action="{base}seal">
<p>Choose a password to seal this wallet's seed. After a VM wipe, this
password (plus this page) restores the seed. <strong>If you lose the password,
only your paper backup can recover the wallet</strong> — keep the paper too.</p>
<label for="pw">New password (at least {minlen} characters)</label>
<input id="pw" name="password" type="password" autocomplete="new-password"
 required minlength="{minlen}" autofocus>
<label for="pw2">Repeat password</label>
<input id="pw2" name="confirm" type="password" autocomplete="new-password"
 required minlength="{minlen}">
<button type="submit">Seal seed</button></form>"""


class Viewer:
    """State for one `serve` run: the URL token, attempt budget, targets."""

    def __init__(self, *, config_dir=None, path=None, max_attempts=5,
                 once=True, n=SCRYPT_N):
        self.config_dir = config_dir
        self.path = path
        self.token = secrets.token_urlsafe(24)
        self.attempts_left = max_attempts
        self.once = once
        self.n = n
        self.done = False

    @property
    def base(self) -> str:
        return f"/{self.token}/"

    def page(self, message: str = "") -> str:
        st = status(config_dir=self.config_dir, path=self.path)
        form = ""
        if st["state"] == "locked":
            form = _UNLOCK_FORM.format(base=self.base, minlen=MIN_PASSWORD_LEN)
        elif st["state"] == "unsealed":
            form = _SEAL_FORM.format(base=self.base, minlen=MIN_PASSWORD_LEN)
        e = html.escape
        return _PAGE.format(
            message=message, state=e(st["state"]),
            hint=e(STATE_HINT[st["state"]]), form=form,
            sealed_path=e(st["sealed_path"]),
            fingerprint=e(st["fingerprint"] or "—"))

    def handle_post(self, action: str, form: dict) -> tuple[int, str]:
        pw = (form.get("password") or [""])[0]
        e = html.escape
        try:
            if action == "unlock":
                if self.attempts_left <= 0:
                    raise SealError("too many attempts — restart the viewer")
                try:
                    unlock(pw, config_dir=self.config_dir, path=self.path)
                except WrongPassword:
                    self.attempts_left -= 1
                    if self.attempts_left <= 0:
                        self.done = True
                    raise
                self.done = self.once
                msg = ("<p class='state unlocked'>Seed unlocked. You can close "
                       "this page; the agent can start the daemon now.</p>")
            elif action == "seal":
                if pw != (form.get("confirm") or [""])[0]:
                    raise SealError("passwords do not match")
                seal(pw, config_dir=self.config_dir, path=self.path, n=self.n)
                self.done = self.once
                msg = ("<p class='state unlocked'>Seed sealed. After a VM wipe, "
                       "this password unlocks it again.</p>")
            else:
                return 404, "not found"
        except SealError as ex:
            left = (f" ({self.attempts_left} attempts left)"
                    if isinstance(ex, WrongPassword) else "")
            return 400, self.page(f"<p class='err'>{e(str(ex))}{left}</p>")
        return 200, self.page(msg)


def _handler(viewer: Viewer):
    class H(BaseHTTPRequestHandler):
        server_version = "spellbook-seed"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Never log the path: it carries the one-time token.
            sys.stderr.write(f"[spellbook-seed] {self.command} "
                             f"{self.client_address[0]}\n")

        def _send(self, code: int, body: str):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path != viewer.base:
                return self._send(404, "not found")
            self._send(200, viewer.page())

        def do_POST(self):
            if not self.path.startswith(viewer.base):
                return self._send(404, "not found")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > 4096:
                return self._send(413, "too large")
            raw = self.rfile.read(length).decode("utf-8", "replace")
            code, body = viewer.handle_post(
                self.path[len(viewer.base):], parse_qs(raw))
            self._send(code, body)

    return H


def serve(*, host="127.0.0.1", port=8787, config_dir=None, path=None,
          once=True, out=sys.stdout) -> None:
    viewer = Viewer(config_dir=config_dir, path=path, once=once)
    httpd = HTTPServer((host, port), _handler(viewer))
    shown_host = "127.0.0.1" if host in ("0.0.0.0", "") else host
    st = status(config_dir=config_dir, path=path)
    print(f"spellbook-seed viewer ({st['state']}): "
          f"http://{shown_host}:{httpd.server_address[1]}{viewer.base}",
          file=out, flush=True)
    print("Give this link to your human. It stops after one successful "
          "seal/unlock or 5 wrong passwords. Ctrl-C to cancel.",
          file=out, flush=True)
    try:
        while not viewer.done:
            httpd.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


# ---------------------------------------------------------------- CLI

def _read_password(a, confirm: bool) -> str:
    if a.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    if not sys.stdin.isatty():
        raise SealError("no TTY: pass --password-stdin, or use "
                        "`spellbook-seed serve` for the browser viewer")
    pw = getpass.getpass("Seal password: ")
    if confirm and getpass.getpass("Repeat password: ") != pw:
        raise SealError("passwords do not match")
    return pw


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="spellbook-seed",
        description="Password-sealed seed that survives agent VM wipes "
                    "(docs/SEALED_SEED.md).")
    ap.add_argument("--config-dir", help="dir holding spellbook.json "
                    "(default: $SPELLBOOK_CONFIG_DIR, ~/.spellbook-testnet, "
                    "/opt/spellbook)")
    ap.add_argument("--sealed", help="sealed file (default: "
                    "$SPELLBOOK_SEALED_PATH or ~/workspace/.spellbook/seed.sealed)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status", help="public state; exit 0 unlocked, 7 no_access, "
                       "3 locked, 4 unsealed, 5 mismatch, 6 empty")
    s.add_argument("--json", action="store_true")
    for name in ("seal", "unlock"):
        p = sub.add_parser(name)
        p.add_argument("--password-stdin", action="store_true",
                       help="read the password from one stdin line "
                            "(for a human's own pipe — never an agent's)")
        if name == "seal":
            p.add_argument("--replace", action="store_true",
                           help="re-seal the SAME wallet (password change)")
    v = sub.add_parser("serve", help="one-time local web page for the human")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8787)
    v.add_argument("--allow-remote", action="store_true",
                   help="allow a non-loopback --host (only behind TLS or an "
                        "SSH/port-forward tunnel: the page is plain HTTP)")
    v.add_argument("--stay", action="store_true",
                   help="keep serving after a successful seal/unlock")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "status":
            st = status(config_dir=a.config_dir, path=a.sealed)
            if a.json:
                print(json.dumps(st, indent=1))
            else:
                print(f"spellbook seed: {st['state']} — {STATE_HINT[st['state']]}")
                if st["seal_error"]:
                    print(f"  seal problem: {st['seal_error']}")
            return STATE_EXIT[st["state"]]
        if a.cmd == "seal":
            r = seal(_read_password(a, confirm=not a.password_stdin),
                     config_dir=a.config_dir, path=a.sealed, replace=a.replace)
            print(f"sealed -> {r['sealed_path']} (fingerprint {r['fingerprint']})")
            return 0
        if a.cmd == "unlock":
            r = unlock(_read_password(a, confirm=False),
                       config_dir=a.config_dir, path=a.sealed)
            if r["already_present"]:
                print("seed already present and matches the seal — nothing written")
            else:
                print("unlocked -> " + ", ".join(r["written"]))
            return 0
        if a.cmd == "serve":
            if a.host not in ("127.0.0.1", "localhost", "::1") \
                    and not a.allow_remote:
                raise SealError("non-loopback --host needs --allow-remote "
                                "(and TLS or a tunnel in front)")
            serve(host=a.host, port=a.port, config_dir=a.config_dir,
                  path=a.sealed, once=not a.stay)
            return 0
    except SealError as e:
        print(f"spellbook-seed: {e}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())

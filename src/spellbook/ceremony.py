"""Hosted ceremony — the human's pages live on the front end, not with the agent.

Review 2026-10-15 S-17 / S-18: the old ceremony pages had the agent decrypt
the human's seal password and restore words, and the seal viewer was a web
server the agent's own process started. Now:

  - The pages the HUMAN types secrets into are static files on the hosted
    front end (https://spellbook.awizard.dev/ceremony/, web/public/ceremony
    in this repo). All crypto runs in the human's browser; the pages carry
    a CSP with connect-src 'none' and load only same-origin assets pinned
    by SRI hashes (web/public/asset-index.json, mirrored at
    ceremony/asset-index.json; spellbook.asset_index checks both).
  - The agent relays only PUBLIC material and CIPHERTEXT: it builds the
    page link with the key holder's public key in the URL FRAGMENT (never
    the query string, so no server log ever sees it), and it carries the
    envelope the page prints back to the key holder.
  - Only the key holder opens an envelope: `spellbook-ceremony apply` /
    `restore` run as the daemon user (or root) with the ceremony PRIVATE
    key, which the agent never holds (S-16). They refuse the agent's OS
    user outright.

Envelope (what seal.html / restore.html print):

  SPELLBOOK-CEREMONY1.<base64url(JSON)>
  JSON {v: 1, kind: "seal" | "unlock" | "restore",
        kfp: sha256 hex of the recipient's SPKI DER,
        alg: "RSA-OAEP-SHA256+A256GCM",
        ek: b64 RSA-OAEP-SHA256(aes key), iv: b64 12 bytes,
        ct: b64 AES-256-GCM(ciphertext || tag)}
  AAD = canonical JSON of {alg, kfp, kind, v} (sorted keys, no spaces), so
  a seal envelope cannot be replayed as an unlock, nor opened by a key
  with another fingerprint.
  Plaintext JSON: {"password": ...} for seal/unlock;
  {"set1_standard": words, "set2_daemon": words} for restore (SET 1 is the
  standard BIP-39 recovery, SET 2 the daemon's KDF seed: the paper labels).

Hard rules (seed.py): no password, word or key in logs, stdout, error
messages or argv. Envelopes are read from a file or stdin.
"""
import argparse
import base64
import hashlib
import json
import math
import os
import string
import sys

HOSTED_ORIGIN = "https://spellbook.awizard.dev"
PAGES = {
    "seal": "/ceremony/seal.html",       # seal + unlock (op in the fragment)
    "restore": "/ceremony/restore.html",  # paper words -> envelope
    "backup": "/ceremony/backup.html",    # reveal key + export envelope
    "integrity": "/onboard/integrity",    # the published asset index
}
OPS = ("seal", "unlock", "restore")
PREFIX = "SPELLBOOK-CEREMONY1."
ALG = "RSA-OAEP-SHA256+A256GCM"
MAX_ENVELOPE = 16384
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 512
_COMMON = ("password", "qwerty", "letmein", "welcome", "admin", "iloveyou",
           "spellbook", "123456", "abcdef")


class CeremonyError(Exception):
    """Refusal with a message safe to show (never carries a secret)."""


# ---------------------------------------------------------------- keys

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _unb64_any(s: str) -> bytes:
    s = "".join(s.split()).replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def public_der(material) -> bytes:
    """SPKI DER of an RSA PUBLIC key given as PEM, base64 / base64url DER or
    raw DER. Refuses private keys and anything under 2048 bits."""
    from Crypto.PublicKey import RSA
    if isinstance(material, str):
        material = material.strip()
        raw = material.encode() if material.startswith("-----") else None
    else:
        raw = bytes(material)
        material = None
    try:
        if raw is None:
            raw = _unb64_any(material)
        key = RSA.import_key(raw)
    except Exception:
        raise CeremonyError("not an RSA public key (PEM or base64 SPKI DER)")
    if key.has_private():
        raise CeremonyError("that is a PRIVATE key — the agent and the page "
                            "only ever get the public half")
    if key.size_in_bits() < 2048:
        raise CeremonyError("ceremony key must be RSA-2048 or larger")
    return key.export_key(format="DER")


def key_fingerprint(der: bytes) -> str:
    """sha256 hex of the SPKI DER — what the page shows the human."""
    return hashlib.sha256(der).hexdigest()


def grouped(fp: str) -> str:
    return " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))


def find_public_key(config_dir: str | None = None) -> str | None:
    """Path of the ceremony PUBLIC key the daemon user publishes.

    Lookup: $SPELLBOOK_CEREMONY_PUB, then `ceremony_pub_path` in the
    config's spellbook.json, then <config_dir>/ceremony.pub.pem. Never a
    private key path; the agent's tools only read this file."""
    env = os.environ.get("SPELLBOOK_CEREMONY_PUB", "").strip()
    if env:
        return env
    from spellbook import sealed
    loc = sealed.locate(config_dir)
    d = loc["config_dir"]
    try:
        with open(os.path.join(d, "spellbook.json")) as f:
            p = json.load(f).get("ceremony_pub_path")
        if p:
            return os.path.expanduser(p)
    except (OSError, ValueError):
        pass
    p = os.path.join(d, "ceremony.pub.pem")
    return p if os.path.exists(p) else None


def hosted_url(page: str, *, pub_der: bytes | None = None,
               op: str | None = None, origin: str = HOSTED_ORIGIN) -> str:
    """The page link the agent hands the human. Public key and op ride in
    the FRAGMENT: browsers never send it to the server."""
    if page not in PAGES:
        raise CeremonyError(f"unknown ceremony page {page!r}")
    frag = []
    if pub_der is not None:
        frag.append("k=" + _b64url(pub_der))
    if op is not None:
        if op not in OPS:
            raise CeremonyError(f"unknown op {op!r}")
        frag.append("op=" + op)
    return origin + PAGES[page] + ("#" + "&".join(frag) if frag else "")


# ---------------------------------------------------------------- envelopes

def _aad(kind: str, kfp: str) -> bytes:
    return json.dumps({"alg": ALG, "kfp": kfp, "kind": kind, "v": 1},
                      sort_keys=True, separators=(",", ":")).encode()


def seal_envelope(kind: str, payload: dict, pub_der: bytes) -> str:
    """What the hosted page does in the browser (kept here for tests and
    for a human who wants to build an envelope locally)."""
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    if kind not in OPS:
        raise CeremonyError(f"unknown envelope kind {kind!r}")
    kfp = key_fingerprint(pub_der)
    aes_key, iv = os.urandom(32), os.urandom(12)
    c = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    c.update(_aad(kind, kfp))
    ct, tag = c.encrypt_and_digest(json.dumps(payload).encode())
    ek = PKCS1_OAEP.new(RSA.import_key(pub_der), hashAlgo=SHA256).encrypt(aes_key)
    env = {"v": 1, "kind": kind, "kfp": kfp, "alg": ALG,
           "ek": base64.b64encode(ek).decode(),
           "iv": base64.b64encode(iv).decode(),
           "ct": base64.b64encode(ct + tag).decode()}
    return PREFIX + _b64url(json.dumps(env, separators=(",", ":")).encode())


def parse_envelope(text: str) -> dict:
    """Public header of an envelope — no key needed, nothing secret inside.
    The agent may call this to check what it is relaying."""
    text = "".join((text or "").split())
    if len(text) > MAX_ENVELOPE:
        raise CeremonyError("envelope too large")
    if not text.startswith(PREFIX):
        raise CeremonyError(f"not a ceremony envelope (expected {PREFIX}...)")
    try:
        env = json.loads(_unb64_any(text[len(PREFIX):]))
    except Exception:
        raise CeremonyError("envelope is not valid base64 JSON")
    if not isinstance(env, dict) or env.get("v") != 1 or env.get("alg") != ALG \
            or env.get("kind") not in OPS:
        raise CeremonyError("unsupported envelope version, algorithm or kind")
    for f in ("kfp", "ek", "iv", "ct"):
        if not isinstance(env.get(f), str):
            raise CeremonyError(f"envelope field {f!r} missing")
    return env


def _load_private(key_path: str):
    from Crypto.PublicKey import RSA
    try:
        st = os.stat(key_path)
    except OSError:
        raise CeremonyError(f"ceremony private key not found at {key_path}")
    if st.st_mode & 0o077:
        raise CeremonyError(f"ceremony private key {key_path} is not 0600 — "
                            "refusing to use it")
    with open(key_path, "rb") as f:
        try:
            key = RSA.import_key(f.read())
        except Exception:
            raise CeremonyError("ceremony private key is not a readable RSA key")
    if not key.has_private():
        raise CeremonyError("ceremony key file holds no private key")
    return key


def open_envelope(text: str, key_path: str, kinds=OPS) -> tuple[str, dict]:
    """Decrypt with the key holder's private key. Returns (kind, payload)."""
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    env = parse_envelope(text)
    if env["kind"] not in kinds:
        raise CeremonyError(f"this is a {env['kind']!r} envelope; expected "
                            + " or ".join(repr(k) for k in kinds))
    key = _load_private(key_path)
    mine = key_fingerprint(key.publickey().export_key(format="DER"))
    if env["kfp"] != mine:
        raise CeremonyError("envelope was made for a different ceremony key "
                            "(fingerprint mismatch) — the page was given the "
                            "wrong public key")
    try:
        aes_key = PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(_unb64_any(env["ek"]))
        blob = _unb64_any(env["ct"])
        c = AES.new(aes_key, AES.MODE_GCM, nonce=_unb64_any(env["iv"]))
        c.update(_aad(env["kind"], env["kfp"]))
        payload = json.loads(c.decrypt_and_verify(blob[:-16], blob[-16:]))
    except Exception:
        raise CeremonyError("envelope did not decrypt (edited, truncated or "
                            "for another key)")
    if not isinstance(payload, dict):
        raise CeremonyError("envelope payload is not an object")
    return env["kind"], payload


# ---------------------------------------------------------------- passwords

def password_problem(pw: str) -> str | None:
    """Strength rule shared with seal.js (S-18: more than a length check).
    None means acceptable. Mirrors the page exactly."""
    from spellbook.seed import bip39_wordlist
    n = len(pw)
    if n < MIN_PASSWORD_LEN:
        return f"use at least {MIN_PASSWORD_LEN} characters"
    if n > MAX_PASSWORD_LEN:
        return f"keep it under {MAX_PASSWORD_LEN} characters"
    low = pw.lower()
    words = low.split()
    if len(words) >= 6 and len(set(words)) >= 6 \
            and all(w in set(bip39_wordlist()) for w in words):
        return None
    distinct = len(set(pw))
    if distinct < 8:
        return "too repetitive: use at least 8 different characters"
    if n < 20 and any(c in low for c in _COMMON):
        return "contains a common password pattern"
    pool = 0
    if any(c in string.ascii_lowercase for c in pw):
        pool += 26
    if any(c in string.ascii_uppercase for c in pw):
        pool += 26
    if any(c in string.digits for c in pw):
        pool += 10
    if any(c not in string.ascii_letters + string.digits for c in pw):
        pool += 33
    bits = min(n, 2 * distinct) * math.log2(pool)
    if bits < 60:
        return ("too weak: make it longer or mix character types "
                "(or use 6+ generated words)")
    return None


# ---------------------------------------------------------------- key holder

def refuse_agent_uid(config_dir: str | None = None) -> None:
    """The key-holder commands open a human secret: never as the agent.
    The agent's OS users are the request-token UIDs in spellbook.json."""
    from spellbook import sealed
    if os.getuid() == 0:
        return
    d = sealed.locate(config_dir)["config_dir"]
    try:
        with open(os.path.join(d, "spellbook.json")) as f:
            uids = json.load(f).get("allowed_request_uids") or []
    except (OSError, ValueError):
        return
    if os.getuid() in uids:
        raise CeremonyError(
            "refusing: this OS user holds the agent's request token. Envelopes "
            "are opened by the daemon user (sudo -u spellbook ...) or root, "
            "never by the agent")


def apply_password(envelope: str, key_path: str, *, config_dir=None,
                   sealed_path=None, replace=False, n=None) -> dict:
    """Seal or unlock with the password inside a seal/unlock envelope."""
    from spellbook import sealed
    kind, payload = open_envelope(envelope, key_path, ("seal", "unlock"))
    pw = payload.get("password")
    if not isinstance(pw, str):
        raise CeremonyError("envelope carries no password")
    try:
        if kind == "seal":
            problem = password_problem(pw)
            if problem:
                raise CeremonyError("seal password refused: " + problem)
            kw = {"n": n} if n else {}
            r = sealed.seal(pw, config_dir=config_dir, path=sealed_path,
                            replace=replace, **kw)
        else:
            r = sealed.unlock(pw, config_dir=config_dir, path=sealed_path)
    finally:
        pw = None
        payload.clear()
    r["op"] = kind
    return r


def apply_restore(envelope: str, key_path: str, out_path: str) -> dict:
    """Write the install.sh --restore key file from a restore envelope:
    line 1 seed.key hex (SET 2, daemon KDF entropy), line 2 std_seed.key
    hex (SET 1, standard BIP-39 seed). O_EXCL | O_NOFOLLOW, 0600 (S-27)."""
    from spellbook.seed import entropy_from_mnemonic, mnemonic_to_seed
    _, payload = open_envelope(envelope, key_path, ("restore",))
    try:
        s1, s2 = payload.get("set1_standard"), payload.get("set2_daemon")
        if not isinstance(s1, str) or not isinstance(s2, str):
            raise CeremonyError("restore envelope needs both SET 1 and SET 2")
        s1 = " ".join(s1.lower().split())
        s2 = " ".join(s2.lower().split())
        try:
            entropy_from_mnemonic(s1)  # checksum SET 1 before using it
            std = mnemonic_to_seed(s1)
        except ValueError:
            raise CeremonyError("SET 1 (standard) words do not check out")
        try:
            kdf_seed = entropy_from_mnemonic(s2)
        except ValueError:
            raise CeremonyError("SET 2 (daemon) words do not check out")
        if len(kdf_seed) != 32 or len(std) != 64:
            raise CeremonyError("both sets must be 24 words")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(out_path, flags, 0o600)
        except FileExistsError:
            raise CeremonyError(f"{out_path} already exists — refusing to "
                                "overwrite; pick a new path")
        with os.fdopen(fd, "w") as f:
            f.write(kdf_seed.hex() + "\n" + std.hex() + "\n")
    finally:
        payload.clear()
    return {"written": out_path}


def _read_envelope(path: str) -> str:
    if path == "-":
        return sys.stdin.read(MAX_ENVELOPE + 1)
    with open(path) as f:
        return f.read(MAX_ENVELOPE + 1)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="spellbook-ceremony",
        description="Hosted seed ceremony: page links (public) and envelope "
                    "opening (key holder only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("url", help="page link with the PUBLIC key in the "
                       "fragment (safe for the agent)")
    u.add_argument("page", choices=sorted(PAGES))
    u.add_argument("--pub", help="public key file (default: the published one)")
    u.add_argument("--op", choices=OPS)
    u.add_argument("--config-dir")
    u.add_argument("--origin", default=HOSTED_ORIGIN)
    fp = sub.add_parser("fingerprint", help="the public key's fingerprint, "
                        "as the page shows it")
    fp.add_argument("--pub")
    fp.add_argument("--config-dir")
    ins = sub.add_parser("inspect", help="public header of an envelope")
    ins.add_argument("envelope", help="file, or - for stdin")
    for name in ("apply", "restore"):
        p = sub.add_parser(name, help=("seal/unlock from an envelope"
                                       if name == "apply" else
                                       "restore key file from an envelope")
                           + " — daemon user or root only")
        p.add_argument("envelope", help="file holding the envelope, or - for stdin")
        p.add_argument("--key", help="ceremony PRIVATE key (default: "
                       "ceremony_key_path in spellbook.json)")
        p.add_argument("--config-dir")
        if name == "apply":
            p.add_argument("--sealed")
            p.add_argument("--replace", action="store_true")
        else:
            p.add_argument("--out", required=True,
                           help="new file for install.sh --restore (created 0600)")
    a = ap.parse_args(argv)
    try:
        if a.cmd in ("url", "fingerprint"):
            pub = a.pub or find_public_key(a.config_dir)
            if not pub and a.cmd == "fingerprint":
                raise CeremonyError("no ceremony public key published")
            der = None
            if pub:
                with open(pub, "rb") as f:
                    der = public_der(f.read())
            if a.cmd == "fingerprint":
                print(grouped(key_fingerprint(der)))
            else:
                if a.page in ("seal", "restore") and der is None:
                    raise CeremonyError("no ceremony public key published "
                                        "(SPELLBOOK_CEREMONY_PUB / ceremony_pub_path)")
                op = a.op or ("restore" if a.page == "restore" else
                              "unlock" if a.page == "seal" else None)
                print(hosted_url(a.page, pub_der=der if a.page in ("seal", "restore") else None,
                                 op=op if a.page in ("seal", "restore") else None,
                                 origin=a.origin))
                if der is not None and a.page in ("seal", "restore"):
                    print("key fingerprint: " + grouped(key_fingerprint(der)))
            return 0
        if a.cmd == "inspect":
            env = parse_envelope(_read_envelope(a.envelope))
            print(json.dumps({"kind": env["kind"], "key_fingerprint": env["kfp"]}))
            return 0
        refuse_agent_uid(a.config_dir)
        key = a.key
        if not key:
            from spellbook import sealed
            d = sealed.locate(a.config_dir)["config_dir"]
            try:
                with open(os.path.join(d, "spellbook.json")) as f:
                    key = json.load(f).get("ceremony_key_path")
            except (OSError, ValueError):
                key = None
            if not key:
                raise CeremonyError("no --key and no ceremony_key_path in spellbook.json")
            key = os.path.expanduser(key)
        text = _read_envelope(a.envelope)
        if a.cmd == "apply":
            r = apply_password(text, key, config_dir=a.config_dir,
                               sealed_path=a.sealed, replace=a.replace)
            print(json.dumps({k: r[k] for k in r if k != "written"} |
                             {"written": len(r.get("written", []))}, default=str))
        else:
            r = apply_restore(text, key, a.out)
            print(f"wrote {r['written']} (0600) — pass it to install.sh --restore, "
                  "which shreds it")
        return 0
    except CeremonyError as e:
        print(f"spellbook-ceremony: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # sealed.SealError and friends: messages are safe
        if e.__class__.__name__ in ("SealError", "WrongPassword"):
            print(f"spellbook-ceremony: {e}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())

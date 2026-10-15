"""Asset index — every hosted ceremony asset and API route, by hash.

The human's ceremony pages are served from the front end
(web/public/ceremony). This module builds and checks the index that pins
them: web/public/asset-index.json (published at /asset-index.json and
rendered at /onboard/integrity) and its byte-identical mirror
ceremony/asset-index.json, so a human or `spellbook-asset-index verify`
can compare what the site serves with what the repo holds.

  python -m spellbook.asset_index write          regenerate (repo root)
  python -m spellbook.asset_index check          fail if anything is stale
  python -m spellbook.asset_index verify --dir D compare downloaded copies
  python -m spellbook.asset_index verify --fetch compare the live site

`write` also stamps each page's <script>/<link> integrity= attributes and
its CSP meta tag, then hashes the stamped page, so the index, the pages and
their SRI attributes always agree. `check` (tests/test_asset_index.py and
the web build's prebuild step, web/scripts/check-asset-index.mjs) fails
when any asset changed without the index being regenerated.

Page rules, enforced here: same-origin /ceremony/ scripts and stylesheets
only, each with integrity=; no inline <script> or <style>, no style= or
on*= attributes, no images, frames, forms or <base>; and the JS never
touches the network, storage or the console.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.request

ORIGIN = "https://spellbook.awizard.dev"
CEREMONY_DIR = "web/public/ceremony"
WEB_INDEX = "web/public/asset-index.json"
REPO_INDEX = "ceremony/asset-index.json"
API_DIR = "web/app/api"

# The ceremony pages' policy. The meta copy cannot carry frame-ancestors
# (browsers ignore it there); the header copy (web/next.config.js reads it
# from the index) adds it. default-src 'none' also shuts same-origin image,
# font and media requests, which could otherwise smuggle a secret into a
# server log as a query string.
META_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'none'; img-src 'none'; font-src 'none'; "
            "media-src 'none'; object-src 'none'; frame-src 'none'; "
            "worker-src 'none'; manifest-src 'none'; form-action 'none'; "
            "base-uri 'none'")
HEADER_CSP = META_CSP + "; frame-ancestors 'none'"

_TAG = re.compile(r"<(script|link)\b([^>]*)>", re.I)
_ATTR = re.compile(r'([a-zA-Z][\w-]*)\s*=\s*"([^"]*)"')
_META_CSP = re.compile(
    r'(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")', re.I)
_BANNED_HTML = [
    (re.compile(r"<script\b(?![^>]*\bsrc=)[^>]*>", re.I), "inline <script>"),
    (re.compile(r"<style\b", re.I), "<style> block"),
    (re.compile(r"\sstyle\s*=", re.I), "style= attribute"),
    (re.compile(r"\son[a-z]+\s*=", re.I), "on*= event attribute"),
    (re.compile(r"<(img|iframe|frame|object|embed|form|base|audio|video)\b", re.I),
     "disallowed element"),
]
_BANNED_JS = [
    (re.compile(r"\bfetch\s*\("), "fetch("),
    (re.compile(r"XMLHttpRequest"), "XMLHttpRequest"),
    (re.compile(r"sendBeacon"), "sendBeacon"),
    (re.compile(r"WebSocket|EventSource"), "socket"),
    (re.compile(r"localStorage|sessionStorage|indexedDB|document\.cookie"),
     "web storage"),
    (re.compile(r"\bconsole\."), "console logging"),
    (re.compile(r"\beval\s*\(|new\s+Function\b"), "eval"),
    (re.compile(r"\.innerHTML\b|insertAdjacentHTML|document\.write"),
     "HTML injection sink"),
]
_METHOD = re.compile(
    r"export\s+(?:async\s+)?(?:function\s+|const\s+)"
    r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")


class IndexError_(Exception):
    pass


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sri(b: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(b).digest()).decode()


def repo_root() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", ".."))


def _read(root, rel) -> bytes:
    with open(os.path.join(root, rel), "rb") as f:
        return f.read()


def _web_path(rel: str) -> str:
    """repo path under web/public -> served path."""
    assert rel.startswith("web/public/")
    return "/" + rel[len("web/public/"):]


def _stamp_page(html: str, assets: dict, problems: list, name: str) -> tuple[str, list]:
    """Rewrite integrity= of each script/stylesheet and the CSP meta tag.
    Returns (stamped html, served paths it loads)."""
    for rx, what in _BANNED_HTML:
        if rx.search(html):
            problems.append(f"{name}: {what} is not allowed on a ceremony page")
    if not _META_CSP.search(html):
        problems.append(f"{name}: missing the Content-Security-Policy meta tag")
    html = _META_CSP.sub(lambda m: m.group(1) + META_CSP + m.group(3), html)
    loads: list[str] = []

    def fix(m):
        tag, attrs = m.group(1).lower(), m.group(2)
        a = dict(_ATTR.findall(attrs))
        if tag == "link":
            if a.get("rel") != "stylesheet":
                problems.append(f"{name}: only stylesheet <link>s are allowed")
                return m.group(0)
            ref = a.get("href")
        else:
            ref = a.get("src")
        if not ref or not ref.startswith("/ceremony/") or "//" in ref or "?" in ref:
            problems.append(f"{name}: {tag} must load a same-origin /ceremony/ "
                            f"path, got {ref!r}")
            return m.group(0)
        if ref not in assets:
            problems.append(f"{name}: loads {ref}, which is not a ceremony asset")
            return m.group(0)
        if "integrity" not in a:
            problems.append(f"{name}: {ref} has no integrity= attribute")
            return m.group(0)
        loads.append(ref)
        return m.group(0).replace(f'integrity="{a["integrity"]}"',
                                  f'integrity="{assets[ref]["sri"]}"')

    html = _TAG.sub(fix, html)
    return html, loads


def _api_routes(root: str) -> list[dict]:
    out = []
    base = os.path.join(root, API_DIR)
    for dirpath, _dirs, files in os.walk(base):
        for fn in files:
            if fn not in ("route.ts", "route.js", "route.tsx"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            seg = os.path.relpath(dirpath, os.path.join(root, "web/app"))
            # Git's canonical bytes (LF), so a Windows checkout with
            # autocrlf hashes the same as Linux and the Vercel build.
            src = _read(root, rel).replace(b"\r\n", b"\n")
            out.append({
                "path": "/" + seg.replace(os.sep, "/"),
                "methods": sorted(set(_METHOD.findall(src.decode("utf-8", "replace")))),
                "source": rel,
                "sha256": sha256_hex(src),
            })
    return sorted(out, key=lambda r: r["path"])


def build(root: str | None = None) -> tuple[bytes, dict, list]:
    """Compute the index from the tree. Returns (index bytes, {rel: stamped
    page bytes}, problems)."""
    root = root or repo_root()
    problems: list[str] = []
    cdir = os.path.join(root, CEREMONY_DIR)
    names = sorted(os.listdir(cdir))
    assets = {}
    for n in names:
        if n.endswith(".html"):
            continue
        if not n.endswith((".js", ".css")):
            problems.append(f"{CEREMONY_DIR}/{n}: only .html, .js and .css belong here")
            continue
        rel = f"{CEREMONY_DIR}/{n}"
        b = _read(root, rel)
        if b"\r\n" in b:
            problems.append(f"{rel}: CRLF line endings (hashes must match the LF repo)")
        if n.endswith(".js"):
            text = b.decode("utf-8", "replace")
            for rx, what in _BANNED_JS:
                if rx.search(text):
                    problems.append(f"{rel}: {what} is not allowed in ceremony JS")
        assets[_web_path(rel)] = {"path": _web_path(rel), "sha256": sha256_hex(b),
                                  "sri": sri(b), "bytes": len(b)}
    pages, stamped = [], {}
    used = set()
    for n in names:
        if not n.endswith(".html"):
            continue
        rel = f"{CEREMONY_DIR}/{n}"
        raw = _read(root, rel)
        if b"\r\n" in raw:
            problems.append(f"{rel}: CRLF line endings")
        html, loads = _stamp_page(raw.decode("utf-8"), assets, problems, rel)
        b = html.encode("utf-8")
        stamped[rel] = b
        used.update(loads)
        pages.append({"path": _web_path(rel), "sha256": sha256_hex(b),
                      "sri": sri(b), "bytes": len(b), "loads": loads})
    for p in sorted(set(assets) - used):
        problems.append(f"{p}: asset loaded by no ceremony page")
    index = {
        "format": "spellbook-asset-index",
        "version": 1,
        "origin": ORIGIN,
        "ceremony_csp": HEADER_CSP,
        "ceremony_meta_csp": META_CSP,
        "pages": pages,
        "assets": [assets[k] for k in sorted(assets)],
        "api_routes": _api_routes(root),
    }
    data = (json.dumps(index, indent=1, sort_keys=True) + "\n").encode()
    return data, stamped, problems


def write(root: str | None = None) -> list:
    root = root or repo_root()
    data, stamped, problems = build(root)
    if problems:
        return problems
    for rel, b in stamped.items():
        if _read(root, rel) != b:
            with open(os.path.join(root, rel), "wb") as f:
                f.write(b)
    # Pages changed only in their integrity attributes; rebuild to be sure.
    data, stamped, problems = build(root)
    for rel in (WEB_INDEX, REPO_INDEX):
        with open(os.path.join(root, rel), "wb") as f:
            f.write(data)
    return problems


def check(root: str | None = None) -> list:
    """Problems that mean the index is stale or a page breaks the rules."""
    root = root or repo_root()
    data, stamped, problems = build(root)
    for rel, b in stamped.items():
        if _read(root, rel) != b:
            problems.append(f"{rel}: integrity= attributes or CSP are stale "
                            "(run: python -m spellbook.asset_index write)")
    for rel in (WEB_INDEX, REPO_INDEX):
        try:
            on_disk = _read(root, rel)
        except FileNotFoundError:
            problems.append(f"{rel}: missing")
            continue
        if on_disk != data:
            problems.append(f"{rel}: stale — an asset or API route changed "
                            "without the index being regenerated "
                            "(run: python -m spellbook.asset_index write)")
    return problems


def default_index_path() -> str:
    for p in (os.path.join(repo_root(), REPO_INDEX),
              "/opt/spellbook/share/ceremony/asset-index.json"):
        if os.path.exists(p):
            return p
    return os.path.join(repo_root(), REPO_INDEX)


def verify_files(index: dict, get) -> list:
    """Compare served bytes with the index. `get(path)` returns bytes or
    None; paths are the served paths (/ceremony/seal.html ...)."""
    bad = []
    for entry in index["pages"] + index["assets"]:
        b = get(entry["path"])
        if b is None:
            bad.append(f"{entry['path']}: missing")
        elif sha256_hex(b) != entry["sha256"]:
            bad.append(f"{entry['path']}: sha256 {sha256_hex(b)} != index "
                       f"{entry['sha256']}")
    return bad


def _fetcher(origin: str):
    def get(path):
        req = urllib.request.Request(origin + path,
                                     headers={"Cache-Control": "no-cache"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                if r.geturl() != origin + path:
                    return None  # redirected somewhere else: not the page
                return r.read()
        except OSError:
            return None
    return get


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spellbook-asset-index",
                                 description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("write", "check"):
        p = sub.add_parser(n)
        p.add_argument("--root", default=None, help="repo root")
    v = sub.add_parser("verify", help="compare hosted or downloaded copies "
                       "with the repo's index")
    v.add_argument("--index", default=None, help="index file (default: the "
                   "repo's ceremony/asset-index.json)")
    g = v.add_mutually_exclusive_group(required=True)
    g.add_argument("--dir", help="directory holding downloaded copies at "
                   "their served paths (DIR/ceremony/seal.html, ...)")
    g.add_argument("--fetch", nargs="?", const=ORIGIN, metavar="ORIGIN",
                   help=f"download from the live site (default {ORIGIN})")
    a = ap.parse_args(argv)
    if a.cmd in ("write", "check"):
        problems = (write if a.cmd == "write" else check)(a.root)
        for p in problems:
            print("asset-index: " + p, file=sys.stderr)
        if not problems:
            data = _read(a.root or repo_root(), WEB_INDEX)
            print(f"asset index {'written' if a.cmd == 'write' else 'current'}: "
                  f"sha256 {sha256_hex(data)}")
        return 1 if problems else 0
    path = a.index or default_index_path()
    with open(path, "rb") as f:
        raw = f.read()
    index = json.loads(raw)
    if a.dir:
        def get(p):
            try:
                with open(os.path.join(a.dir, p.lstrip("/")), "rb") as f:
                    return f.read()
            except OSError:
                return None
    else:
        get = _fetcher(a.fetch.rstrip("/"))
    bad = verify_files(index, get)
    served = get("/asset-index.json")
    if served is not None and served != raw:
        bad.append("/asset-index.json: the published index differs from "
                   f"{path}")
    for b in bad:
        print("verify: " + b, file=sys.stderr)
    if not bad:
        print(f"all {len(index['pages']) + len(index['assets'])} ceremony "
              f"files match {path} (index sha256 {sha256_hex(raw)})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

"""Asset index: every hosted ceremony asset and API route, pinned by hash.

The check fails when an asset changes without the index being regenerated
(python -m spellbook.asset_index write), when a page loads something
without an SRI hash or from another origin, or when ceremony JS reaches
for the network, storage or the console.
"""
import json
import os
import re
import shutil

import pytest

from spellbook import asset_index

ROOT = asset_index.repo_root()


def _read(rel, mode="r"):
    with open(os.path.join(ROOT, rel), mode) as f:
        return f.read()


def test_index_is_current():
    assert asset_index.check(ROOT) == []


def test_repo_mirror_is_byte_identical():
    assert _read(asset_index.WEB_INDEX, "rb") == _read(asset_index.REPO_INDEX, "rb")


def test_index_lists_every_page_asset_and_api_route():
    idx = json.loads(_read(asset_index.WEB_INDEX))
    served = {e["path"] for e in idx["pages"] + idx["assets"]}
    on_disk = {"/ceremony/" + n for n in
               os.listdir(os.path.join(ROOT, asset_index.CEREMONY_DIR))}
    assert served == on_disk
    assert {"/ceremony/seal.html", "/ceremony/restore.html",
            "/ceremony/backup.html"} <= served
    routes = set()
    for d, _s, files in os.walk(os.path.join(ROOT, asset_index.API_DIR)):
        if "route.ts" in files:
            routes.add("/" + os.path.relpath(d, os.path.join(ROOT, "web/app"))
                       .replace(os.sep, "/"))
    assert {r["path"] for r in idx["api_routes"]} == routes
    for r in idx["api_routes"]:
        assert r["methods"] and re.fullmatch(r"[0-9a-f]{64}", r["sha256"])


def test_pages_pin_every_asset_with_sri_and_a_strict_csp():
    idx = json.loads(_read(asset_index.WEB_INDEX))
    sri = {a["path"]: a["sri"] for a in idx["assets"]}
    assert "connect-src 'none'" in idx["ceremony_csp"]
    assert "default-src 'none'" in idx["ceremony_csp"]
    assert "frame-ancestors 'none'" in idx["ceremony_csp"]
    assert "unsafe-inline" not in idx["ceremony_csp"]
    for page in idx["pages"]:
        html = _read("web/public" + page["path"])
        assert f'content="{idx["ceremony_meta_csp"]}"' in html
        tags = re.findall(r"<(?:script|link)\b[^>]*>", html)
        assert tags and len(tags) == len(page["loads"])
        for t in tags:
            ref = re.search(r'(?:src|href)="([^"]+)"', t).group(1)
            assert ref.startswith("/ceremony/")
            assert f'integrity="{sri[ref]}"' in t


def test_next_config_serves_the_index_csp_on_ceremony_paths():
    cfg = _read("web/next.config.js")
    assert 'require("./public/asset-index.json")' in cfg
    assert "assetIndex.ceremony_csp" in cfg and '"/ceremony/:path*"' in cfg
    pkg = json.loads(_read("web/package.json"))
    assert pkg["scripts"]["prebuild"] == "node scripts/check-asset-index.mjs"


@pytest.fixture
def tree(tmp_path):
    """A copy of the parts of the repo the index covers."""
    for rel in (asset_index.CEREMONY_DIR, asset_index.API_DIR):
        shutil.copytree(os.path.join(ROOT, rel), tmp_path / rel)
    for rel in (asset_index.WEB_INDEX, asset_index.REPO_INDEX):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(os.path.join(ROOT, rel), tmp_path / rel)
    assert asset_index.check(str(tmp_path)) == []
    return tmp_path


def test_changed_asset_without_regeneration_fails(tree):
    js = tree / asset_index.CEREMONY_DIR / "seal.js"
    js.write_bytes(js.read_bytes() + b"/* changed */\n")
    problems = asset_index.check(str(tree))
    assert any("seal.html" in p and "stale" in p for p in problems)
    assert any(asset_index.WEB_INDEX in p for p in problems)
    assert asset_index.write(str(tree)) == []
    assert asset_index.check(str(tree)) == []


def test_changed_api_route_without_regeneration_fails(tree):
    r = tree / asset_index.API_DIR / "holdings" / "route.ts"
    r.write_bytes(r.read_bytes() + b"\n// changed\n")
    assert any(asset_index.REPO_INDEX in p for p in asset_index.check(str(tree)))


@pytest.mark.parametrize("snippet,why", [
    ('<script>alert(1)</script>', "inline <script>"),
    ('<div style="x"></div>', "style= attribute"),
    ('<button onclick="x()"></button>', "on*= event attribute"),
    ('<img src="/x.png">', "disallowed element"),
    ('<script src="https://cdn.example/x.js" integrity="sha384-x"></script>',
     "same-origin"),
])
def test_page_rules(tree, snippet, why):
    p = tree / asset_index.CEREMONY_DIR / "seal.html"
    p.write_text(p.read_text().replace("</main>", snippet + "</main>"))
    assert any(why in x for x in asset_index.build(str(tree))[2])


@pytest.mark.parametrize("snippet", [
    "fetch('/x')", "navigator.sendBeacon('/x')", "localStorage.x=1",
    "console.log(pw)", "el.innerHTML = s", "new XMLHttpRequest()",
])
def test_ceremony_js_rules(tree, snippet):
    p = tree / asset_index.CEREMONY_DIR / "common.js"
    p.write_text(p.read_text() + snippet + "\n")
    assert asset_index.build(str(tree))[2]


def test_verify_files_compares_served_bytes(tree):
    idx = json.loads((tree / asset_index.WEB_INDEX).read_text())
    pub = tree / "web" / "public"
    get = lambda p: (pub / p.lstrip("/")).read_bytes()  # noqa: E731
    assert asset_index.verify_files(idx, get) == []
    (pub / "ceremony" / "restore.js").write_bytes(b"tampered")
    bad = asset_index.verify_files(idx, get)
    assert len(bad) == 1 and "restore.js" in bad[0]
    rc = asset_index.main(["verify", "--index", str(tree / asset_index.REPO_INDEX),
                           "--dir", str(pub)])
    assert rc == 1

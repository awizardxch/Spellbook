"""Version identity and latest-release checks (SPEC §12b item 4).

One rule: the version is a fact, never a claim. `local_version()` reads the
version the installer recorded at ${PREFIX}/VERSION first (what is actually
on disk), then falls back to the imported package. `latest_release_tag()`
asks the GitHub releases API — when no releases exist yet it says so
plainly instead of inventing one.
"""
import json
import os
import urllib.request

REPO = "awizardxch/Spellbook"
DEFAULT_PREFIX = "/opt/spellbook"
VERSION_FILENAME = "VERSION"


def prefix() -> str:
    return os.environ.get("SPELLBOOK_PREFIX", DEFAULT_PREFIX)


def local_version(prefix_override=None) -> str:
    """The version installed on this machine, or "unknown"."""
    ver_file = os.path.join(prefix_override or prefix(), VERSION_FILENAME)
    try:
        with open(ver_file) as f:
            v = f.read().strip()
            if v:
                return v
    except OSError:
        pass
    try:
        from spellbook import __version__ as pkg_version
        if pkg_version:
            return pkg_version
    except Exception:
        pass
    return "unknown"


def parse(v: str) -> tuple:
    """Rough semver tuple for comparison; unparseable -> (0,)."""
    parts = []
    for piece in v.strip().lstrip("v").split("."):
        digits = "".join(c for c in piece if c.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else (0,)


def latest_release_tag() -> str | None:
    """Latest GitHub release tag, or None (no releases yet / network down)."""
    url = f"https://api.github.com/repos/{REPO}/releases/latest"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": f"spellbook/{local_version()}",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return None
    tag = (data.get("tag_name") or "").strip()
    return tag or None


def upgrade_check(prefix_override=None) -> dict:
    """{local, latest, upgrade_available, note} — never raises."""
    local = local_version(prefix_override)
    latest = latest_release_tag()
    if latest is None:
        return {
            "local": local,
            "latest": None,
            "upgrade_available": False,
            "note": ("no releases published yet (or unreachable) — dev installs "
                     "track the repo via install.sh --upgrade --from-dir"),
        }
    available = parse(latest) > parse(local)
    return {
        "local": local,
        "latest": latest,
        "upgrade_available": available,
        "note": "upgrade available" if available else "already on the latest release",
    }

"""End-to-end tests for scripts/spellbook-upgrade (review S-22, S-29, S-31).

The release key alone must not be enough to get code installed as root.
These tests run the real wrapper (a copy with its fixed-configuration
lines pointed at temp dirs and the root check pointed at this uid) against
a local bare git repo standing in for the canonical GitHub repo, with
throwaway gpg keys in a temp GNUPGHOME. The installer the wrapper runs is a
stub that records its arguments and environment.

Linux only (stat -c, sort -V, gpg, git). Nothing here touches a real key,
the network, /usr/local or /var/lib.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not shutil.which("gpg") or not shutil.which("git"),
    reason="wrapper tests need Linux with gpg and git")

WRAPPER = os.path.join(os.path.dirname(__file__), "..", "scripts",
                       "spellbook-upgrade")
TAG = "0.5.0"
INSTALLED = "0.4.0"
SHA = "ab" * 32
DAY = 86400
OLD = int(time.time()) - 3 * DAY          # past the 24 h delay window
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def _run(cmd, env=None, cwd=None, check=True):
    r = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise AssertionError(f"{cmd} failed: {r.stdout}\n{r.stderr}")
    return r


# ---------------------------------------------------------------- gpg keys

class Gpg:
    def __init__(self):
        # Short path: gpg-agent's socket path has a length limit.
        self.home = tempfile.mkdtemp(prefix="sbg", dir="/tmp")
        os.chmod(self.home, 0o700)
        self.env = dict(CLEAN_ENV, GNUPGHOME=self.home, HOME=self.home)

    def gpg(self, *args, faked=None):
        cmd = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
               "--passphrase", ""]
        if faked:
            cmd += ["--faked-system-time", faked]
        return _run(cmd + list(args), env=self.env)

    def new_key(self, uid, expire="0", faked=None):
        self.gpg("--quick-gen-key", uid, "ed25519", "sign", expire, faked=faked)
        out = _run(["gpg", "--batch", "--with-colons", "--list-keys", uid],
                   env=self.env).stdout
        return [l.split(":")[9] for l in out.splitlines()
                if l.startswith("fpr:")][0]

    def export(self, fpr):
        return _run(["gpg", "--batch", "--armor", "--export", fpr],
                    env=self.env).stdout

    def revoke(self, fpr):
        rev = os.path.join(self.home, "openpgp-revocs.d", f"{fpr}.rev")
        text = open(rev).read().replace(":-----BEGIN", "-----BEGIN")
        p = os.path.join(self.home, "rev.asc")
        open(p, "w").write(text)
        self.gpg("--import", p)

    def program(self, faked=None):
        """A gpg.program for git; `faked` freezes gpg's clock."""
        p = os.path.join(self.home, f"gpg-{faked or 'now'}.sh".replace(":", ""))
        extra = f" --faked-system-time {faked}" if faked else ""
        open(p, "w").write(f'#!/bin/sh\nexec gpg{extra} "$@"\n')
        os.chmod(p, 0o755)
        return p

    def close(self):
        subprocess.run(["gpgconf", "--kill", "all"], env=self.env,
                       capture_output=True)
        shutil.rmtree(self.home, ignore_errors=True)


@pytest.fixture(scope="module")
def keys():
    g = Gpg()
    g.release = g.new_key("Release Test <release@example.invalid>")
    g.other = g.new_key("Other Test <other@example.invalid>")
    # Created and valid for two days in 2020, so expired now.
    g.expired = g.new_key("Expired Test <expired@example.invalid>", "2d",
                          faked="20200101T000000!")
    yield g
    g.close()


# ---------------------------------------------------------------- canonical repo

class Canon:
    """A working repo + bare 'canonical' repo the wrapper fetches from."""

    def __init__(self, keys, tmp):
        self.keys = keys
        self.work = os.path.join(tmp, "work")
        self.bare = os.path.join(tmp, "canonical.git")
        os.makedirs(self.work)
        self.env = dict(keys.env, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x",
                        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
        self.git("init", "-q", "-b", "main")
        _run(["git", "init", "-q", "--bare", self.bare], env=self.env)

    def git(self, *args, date=None):
        env = dict(self.env)
        if date is not None:
            env["GIT_COMMITTER_DATE"] = f"{date} +0000"
            env["GIT_AUTHOR_DATE"] = f"{date} +0000"
        return _run(["git", *args], env=env, cwd=self.work)

    def write(self, rel, text):
        p = os.path.join(self.work, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
        self.git("add", rel)

    def commit(self, msg, date=None):
        self.git("commit", "-q", "-m", msg, date=date)

    def release_commit(self, version=TAG, key=None, date=OLD):
        self.write("VERSION", version + "\n")
        self.write("docs/release-key.asc", self.keys.export(key or self.keys.release))
        self.commit(f"release {version}", date=date)

    def tag(self, name=TAG, key=None, date=OLD, faked=None, signed=True):
        key = key or self.keys.release
        if signed:
            self.git("-c", f"gpg.program={self.keys.program(faked)}",
                     "-c", f"user.signingkey={key}",
                     "tag", "-s", name, "-m", f"Spellbook {name}", date=date)
        else:
            self.git("tag", "-a", name, "-m", f"Spellbook {name}", date=date)

    def manifest(self, version=TAG, sha=SHA, date=OLD):
        self.write(f"releases/{version}/spellbook-{version}.tar.gz.sha256",
                   f"{sha}  spellbook-{version}.tar.gz\n")
        self.commit(f"vendor signed {version} artifacts", date=date)

    def publish(self):
        self.git("push", "-q", "--force", self.bare, "main", "--tags")

    def commit_of(self, name=TAG):
        return self.git("rev-parse", f"{name}^{{commit}}").stdout.strip()

    def good_release(self, key=None):
        self.release_commit(key=key)
        self.tag(key=key)
        self.manifest()
        self.publish()


# ---------------------------------------------------------------- the wrapper under test

class Host:
    """A fake root-owned layout: conf dir, state dir, stub installer."""

    def __init__(self, tmp, canon, fpr, delay="24", installed=INSTALLED):
        self.conf = os.path.join(tmp, "conf")
        self.state = os.path.join(tmp, "state")
        os.makedirs(self.conf)
        os.chmod(self.conf, 0o755)
        self.ran = os.path.join(tmp, "ran")
        installer = os.path.join(self.conf, "install.sh")
        open(installer, "w").write(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > '{self.ran}.args'\n"
            f"env > '{self.ran}.env'\n")
        os.chmod(installer, 0o755)
        env_file = os.path.join(self.conf, "install.env")
        open(env_file, "w").write(
            'SPELLBOOK_AGENT_USER="agent"\n'
            'SPELLBOOK_HUMAN_USER="human"\n'
            'SPELLBOOK_NO_SAGE="0"\n'
            f'SPELLBOOK_RELEASE_KEY_FPR="{fpr}"\n'
            f'SPELLBOOK_CANONICAL_REPO="{canon.bare}"\n'
            f'SPELLBOOK_UPGRADE_DELAY_HOURS="{delay}"\n')
        os.chmod(env_file, 0o600)
        vf = os.path.join(self.conf, "VERSION")
        open(vf, "w").write(installed + "\n")
        os.chmod(vf, 0o644)
        src = open(WRAPPER, newline="").read().replace("\r\n", "\n")
        for old, new in (
                ("REQUIRED_UID=0\n", f"REQUIRED_UID={os.geteuid()}\n"),
                ('CONF_DIR="/usr/local/lib/spellbook"\n', f'CONF_DIR="{self.conf}"\n'),
                ('STATE_DIR="/var/lib/spellbook-upgrade"\n', f'STATE_DIR="{self.state}"\n')):
            assert src.count(old) == 1, f"wrapper has no fixed line {old!r}"
            src = src.replace(old, new)
        self.wrapper = os.path.join(tmp, "spellbook-upgrade")
        open(self.wrapper, "w").write(src)
        os.chmod(self.wrapper, 0o755)

    def seen(self, commit, ts=OLD, tag=TAG):
        os.makedirs(self.state, mode=0o700, exist_ok=True)
        open(os.path.join(self.state, f"seen-{tag}"), "w").write(f"{ts} {commit}\n")

    def run(self, *args, env=None):
        return subprocess.run(["sh", self.wrapper, *args],
                              env=env if env is not None else dict(CLEAN_ENV),
                              capture_output=True, text=True)

    def installed_args(self):
        p = self.ran + ".args"
        return open(p).read().split("\n") if os.path.exists(p) else None


def _refused(r, host, why):
    assert r.returncode != 0, r.stdout + r.stderr
    assert why in r.stderr, r.stderr
    assert host.installed_args() is None, "installer ran on a refused release"


@pytest.fixture
def tmp(tmp_path):
    # tmp_path's parents are /tmp (root, sticky) and pytest's 0700 dirs.
    os.chmod(tmp_path, 0o755)
    return str(tmp_path)


# ---------------------------------------------------------------- accept

def test_accepts_signed_tag_on_main_past_delay(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    r = h.run(TAG)
    assert r.returncode == 0, r.stderr
    args = h.installed_args()
    assert args[:4] == ["--upgrade", TAG, "--expect-sha256", SHA]
    assert "--agent-user" in args and "agent" in args
    env = open(h.ran + ".env").read()
    # the installer gets a scrubbed environment plus the pinned key and
    # the keyring built from main's release-key.asc
    assert f"SPELLBOOK_RELEASE_KEY_FPR={keys.release}" in env
    assert "GNUPGHOME=" in env
    assert keys.home not in env


def test_accepts_v_prefix(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    r = h.run("v" + TAG)
    assert r.returncode == 0, r.stderr


# ---------------------------------------------------------------- the release key alone

def test_refuses_signed_tag_not_on_main(keys, tmp):
    c = Canon(keys, tmp)
    c.release_commit(version="0.4.0")
    c.manifest(version=TAG)            # even with a hash on main
    c.git("checkout", "-q", "-b", "evil")
    c.release_commit()                 # VERSION 0.5.0, only on a side branch
    c.tag()                            # validly signed by the release key
    c.git("checkout", "-q", "main")
    c.publish()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, "is not on main")


def test_refuses_without_hash_published_on_main(keys, tmp):
    c = Canon(keys, tmp)
    c.release_commit()
    c.tag()
    c.publish()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, "has no releases/0.5.0/spellbook-0.5.0.tar.gz.sha256")


def test_refuses_tag_inside_delay_window(keys, tmp):
    now = int(time.time())
    c = Canon(keys, tmp)
    c.release_commit(date=now)
    c.tag(date=now)
    c.manifest(date=now)
    c.publish()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())              # seen long ago, but signed just now
    r = h.run(TAG)
    assert r.returncode == 75, r.stderr
    assert "delay window" in r.stderr
    assert h.installed_args() is None


def test_first_sight_starts_the_window_even_for_a_backdated_tag(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()                   # tagger date three days ago
    h = Host(tmp, c, keys.release)
    r = h.run(TAG)                     # this machine has never seen it
    assert r.returncode == 75, r.stderr
    assert h.installed_args() is None
    seen = open(os.path.join(h.state, f"seen-{TAG}")).read().split()
    assert seen[1] == c.commit_of()
    assert int(seen[0]) >= int(time.time()) - 60


def test_refuses_yanked_tag(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    c.write("releases/YANKED", f"# yanked releases\n{TAG} malicious payload\n")
    c.commit("yank")
    c.publish()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, "releases/YANKED")


def test_refuses_yanked_key(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    c.write("releases/YANKED", f"{keys.release.lower()} key compromised\n")
    c.commit("revoke key")
    c.publish()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, "releases/YANKED")


def test_refuses_expired_key(keys, tmp):
    c = Canon(keys, tmp)
    c.release_commit(key=keys.expired)
    c.tag(key=keys.expired, faked="20200101T120000!")
    c.manifest()
    c.publish()
    h = Host(tmp, c, keys.expired)
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, "EXPKEYSIG")


def test_refuses_revoked_key(tmp):
    g = Gpg()
    try:
        g.release = g.new_key("Revoked Test <revoked@example.invalid>")
        c = Canon(g, tmp)
        c.release_commit()
        c.tag()
        c.manifest()
        g.revoke(g.release)
        # The owner publishes the revocation on main.
        c.write("docs/release-key.asc", g.export(g.release))
        c.commit("revoke the release key")
        c.publish()
        h = Host(tmp, c, g.release)
        h.seen(c.commit_of())
        _refused(h.run(TAG), h, "REVKEYSIG")
    finally:
        g.close()


@pytest.mark.parametrize("key_on_main,why", [
    ("release", "ERRSIG"),                      # signer unknown to main's key file
    ("other", "not the pinned release key"),    # known key, wrong fingerprint
])
def test_refuses_tag_signed_by_another_key(keys, tmp, key_on_main, why):
    c = Canon(keys, tmp)
    c.release_commit(key=getattr(keys, key_on_main))
    c.tag(key=keys.other)
    c.manifest()
    c.publish()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, why)


def test_refuses_unsigned_annotated_tag(keys, tmp):
    c = Canon(keys, tmp)
    c.release_commit()
    c.tag(signed=False)
    c.manifest()
    c.publish()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, "no good signature")


def test_refuses_tag_object_published_under_another_name(keys, tmp):
    c = Canon(keys, tmp)
    c.release_commit()
    c.tag("0.4.9")                     # signed tag object names itself 0.4.9
    c.git("update-ref", f"refs/tags/{TAG}", "refs/tags/0.4.9")
    c.manifest()
    c.publish()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, "names itself")


def test_refuses_downgrade(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    h = Host(tmp, c, keys.release, installed="0.6.0")
    h.seen(c.commit_of())
    _refused(h.run(TAG), h, "forward only")


# ---------------------------------------------------------------- arguments and environment

@pytest.mark.parametrize("arg", [
    "--from-dir", "latest", "", "1.2", "1.2.3.4", "1.2.3\n4.5.6", "1.2.3;id",
    "../1.2.3", "1.2.3 ", "vv1.2.3", "1234567.0.0",
])
def test_refuses_malformed_tag(keys, tmp, arg):
    c = Canon(keys, tmp)
    h = Host(tmp, c, keys.release)
    r = h.run(arg)
    assert r.returncode != 0
    assert "want X.Y.Z" in r.stderr, r.stderr
    assert h.installed_args() is None


def test_refuses_two_arguments(keys, tmp):
    c = Canon(keys, tmp)
    h = Host(tmp, c, keys.release)
    r = h.run(TAG, "--from-dir")
    assert r.returncode != 0 and "exactly one" in r.stderr
    assert h.installed_args() is None


@pytest.mark.parametrize("var,val", [
    ("LD_PRELOAD", "/tmp/evil.so"),
    ("BASH_ENV", "/tmp/evil.sh"),
    ("GNUPGHOME", "/tmp/attacker-keyring"),
    ("GIT_DIR", "/tmp/evil.git"),
    ("SPELLBOOK_CANONICAL_REPO", "/tmp/evil.git"),
    ("SPELLBOOK_RELEASE_KEY_FPR", "0" * 40),
    ("PYTHONPATH", "/tmp/evil"),
])
def test_refuses_poisoned_environment(keys, tmp, var, val):
    c = Canon(keys, tmp)
    c.good_release()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    _refused(h.run(TAG, env=dict(CLEAN_ENV, **{var: val})), h,
             f"environment carries {var}")


# ---------------------------------------------------------------- root-trusted files (S-29)

def test_refuses_writable_install_env(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    os.chmod(os.path.join(h.conf, "install.env"), 0o620)
    _refused(h.run(TAG), h, "writable by others")


def test_refuses_writable_conf_dir(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    os.chmod(h.conf, 0o777)
    _refused(h.run(TAG), h, "writable by others")


def test_refuses_symlinked_installer(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    inst = os.path.join(h.conf, "install.sh")
    real = os.path.join(tmp, "elsewhere.sh")
    os.rename(inst, real)
    os.symlink(real, inst)
    _refused(h.run(TAG), h, "symlink")


def test_install_env_is_parsed_not_sourced(keys, tmp):
    c = Canon(keys, tmp)
    c.good_release()
    h = Host(tmp, c, keys.release)
    h.seen(c.commit_of())
    marker = os.path.join(tmp, "sourced")
    with open(os.path.join(h.conf, "install.env"), "a") as f:
        f.write(f"touch '{marker}'\n")
    r = h.run(TAG)
    assert r.returncode == 0, r.stderr
    assert not os.path.exists(marker)


# ---------------------------------------------------------------- install.sh (S-25, S-29, S-31)

INSTALL_SH = os.path.join(os.path.dirname(__file__), "..", "install.sh")


def _install_sh():
    return open(INSTALL_SH, newline="").read().replace("\r\n", "\n")


def _shell_function(src, name):
    start = src.index(f"{name}() {{")
    end = src.index("\n}\n", start) + 3
    return src[start:end]


@pytest.mark.parametrize("signer,faked,ok", [
    ("release", None, True),
    ("other", None, False),
    ("expired", "20200101T120000!", False),
])
def test_installer_signature_rule_refuses_expired_and_foreign_keys(keys, tmp, signer, faked, ok):
    src = _install_sh()
    data = os.path.join(tmp, "release.tar.gz")
    open(data, "w").write("payload\n")
    keys.gpg("--local-user", getattr(keys, signer), "--armor", "--detach-sign",
             "-o", data + ".asc", data, faked=faked)
    pinned = getattr(keys, signer) if signer != "other" else keys.release
    script = ("norm_fpr() { echo \"$1\" | tr -d ' ' | tr 'a-f' 'A-F'; }\n"
              + _shell_function(src, "verify_release_sig")
              + f'RELEASE_KEY_FPR={pinned}\n'
              + f'verify_release_sig "{data}.asc" "{data}"\n')
    r = subprocess.run(["bash", "-c", script], env=keys.env,
                       capture_output=True, text=True)
    assert (r.returncode == 0) is ok, r.stderr


def test_installer_validates_expect_sha256_before_anything():
    for args in (["0.5.0", "--expect-sha256", "XYZ"],
                 ["--from-dir", "/nonexistent", "--expect-sha256", "ab" * 32]):
        r = subprocess.run(["bash", INSTALL_SH, *args], capture_output=True,
                           text=True, env=dict(CLEAN_ENV))
        assert r.returncode != 0
        assert "--expect-sha256" in r.stderr, r.stderr


def test_installer_pins_root_trusted_copies_from_the_verified_tree():
    src = _install_sh()
    # S-25: never copies the running installer onto itself; the pinned copy
    # comes from the release tree and lands by rename.
    assert 'cp "$INSTALLER_SRC" "${PREFIX}/lib/install.sh"' not in src
    assert 'NEW_INSTALLER="${SRC}/install.sh"' in src
    assert 'root_install "$NEW_INSTALLER" "${ROOT_LIB}/install.sh" 0755' in src
    assert 'RESTORE_FILE=""' in src
    # S-29: nothing root-trusted is copied from the spellbook-owned stage,
    # and the record lives outside the spellbook-owned prefix.
    assert '"${STAGE}/scripts/spellbook-upgrade"' not in src
    assert 'root_install "${SRC}/scripts/spellbook-upgrade" /usr/local/bin/spellbook-upgrade' in src
    assert 'cat > "${PREFIX}/install.env"' not in src
    assert 'ROOT_LIB="/usr/local/lib/spellbook"' in src
    # The wrapper and the installer agree on the root-trusted location.
    wrapper = open(WRAPPER, newline="").read()
    assert 'CONF_DIR="/usr/local/lib/spellbook"' in wrapper
    # S-22: a wrapper-driven upgrade never takes a Sage prebuilt that only
    # the release key vouches for (GitHub Release assets).
    fn = src[src.index("fetch_prebuilt_file() {"):src.index("fetch_prebuilt_file \"${tgz}\"")]
    assert '[ -z "$EXPECT_SHA256" ]' in fn

"""S-04: the identity seed must not be the KDF wallet root; dashboard
sign-in is a daemon route under its own domain.

Pure-function tests plus in-process daemons over throwaway config dirs:
no socket, no real seed. Every key and seed here is generated inside the
test.
"""
import json
import os
import tempfile

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from spellbook import seed as seedmod
from spellbook import seedrole
from spellbook import sign as spellsign
from spellbook.config import load_config
from spellbook.daemon import Daemon, DashboardSignWindow
from spellbook.seedrole import IdentitySeedAsWalletRoot

POSIX = os.name == "posix"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")


def _cfg(**over):
    cfg = {"seed_path": "/opt/spellbook/seed.key", "musebook_signing_mode": "disabled"}
    cfg.update(over)
    return cfg


# ------------------------------------------------------------ refusal

def test_plain_wallet_seed_under_kdf_starts():
    assert seedrole.check_wallet_root(_cfg()) == []


def test_no_seed_path_is_not_checked():
    assert seedrole.check_wallet_root({"musebook_signing_mode": "daemon"}) == []


@pytest.mark.parametrize("marker_cfg", [
    {"seed_role": "identity"},
    {"musebook_signing_mode": "daemon"},
    {"seed_path": "/home/agent/projects/musebook/seed.key"},
    {"seed_path": "/home/agent/projects/Musebook/.env"},
    {"seed_path": "/srv/muse/.env"},
    {"seed_path": "C:\\Users\\x\\musebook\\seed.key"},
    {"seed_path": "/home/agent/.config/spellbook/agent_ed25519.key"},
])
def test_identity_markers_refuse_under_kdf(marker_cfg):
    with pytest.raises(IdentitySeedAsWalletRoot) as ei:
        seedrole.check_wallet_root(_cfg(**marker_cfg))
    msg = str(ei.value)
    assert "S1" in msg and "S-04" in msg and seedrole.ALLOW_KEY in msg


def test_identity_markers_refuse_when_kdf_is_explicit():
    with pytest.raises(IdentitySeedAsWalletRoot):
        seedrole.check_wallet_root(_cfg(key_derivation="kdf", seed_role="identity"))


def test_seed_file_header_marks_identity():
    text = seedrole.IDENTITY_ROLE_HEADER + "\n" + "00" * 32 + "\n"
    with pytest.raises(IdentitySeedAsWalletRoot, match="header"):
        seedrole.check_wallet_root(_cfg(), text)
    assert seedrole.seed_file_role(text) == "identity"
    assert seedrole.seed_file_role("00" * 32) is None
    assert seedrole.seed_file_role(seedrole.WALLET_ROLE_HEADER + "\n" + "00" * 32) == "wallet"


def test_header_must_match_exactly_not_a_comment_mentioning_identity():
    assert seedrole.seed_file_role("# identity seed? no\n" + "00" * 32) is None


def test_explicit_allow_true_starts_and_returns_the_markers():
    markers = seedrole.check_wallet_root(
        _cfg(musebook_signing_mode="daemon", **{seedrole.ALLOW_KEY: True}))
    assert markers and any("musebook_signing_mode" in m for m in markers)


@pytest.mark.parametrize("bad", ["true", 1, "yes", None])
def test_allow_must_be_a_real_boolean(bad):
    with pytest.raises(ValueError):
        seedrole.check_wallet_root(_cfg(**{seedrole.ALLOW_KEY: bad}))


def test_standard_derivation_tolerates_identity_seed():
    # Option B shape: the BIP-39 std seed is the wallet root, the KDF seed
    # only signs identity. Allowed; markers reported.
    markers = seedrole.check_wallet_root(
        _cfg(key_derivation="standard", musebook_signing_mode="daemon",
             std_seed_path="/opt/spellbook/std_seed.key"))
    assert markers


def test_seed_role_wallet_cannot_silence_a_contradicting_marker():
    with pytest.raises(IdentitySeedAsWalletRoot, match="contradicts"):
        seedrole.check_wallet_root(_cfg(seed_role="wallet", musebook_signing_mode="daemon"))
    with pytest.raises(IdentitySeedAsWalletRoot, match="contradicts"):
        seedrole.check_wallet_root(
            _cfg(seed_role="wallet", key_derivation="standard",
                 seed_path="/x/musebook/.env"))


def test_unknown_seed_role_is_an_error():
    with pytest.raises(ValueError):
        seedrole.check_wallet_root(_cfg(seed_role="both"))


def test_load_seed_tolerates_the_role_header(tmp_path):
    p = tmp_path / "seed.key"
    entropy = os.urandom(32)
    p.write_text(seedrole.IDENTITY_ROLE_HEADER + "\n" + entropy.hex() + "\n")
    if POSIX:
        os.chmod(p, 0o600)
        assert seedmod.load_seed(str(p)) == entropy
    assert bytes.fromhex(seedmod.strip_comments(p.read_text())) == entropy
    # header_lines hands over the comments only, never the payload
    assert entropy.hex() not in seedmod.header_lines(p.read_text())


@pytest.mark.skipif(not POSIX, reason="load_config needs POSIX 0600 modes")
def test_load_config_validates_the_new_keys(tmp_path):
    cfg_path = tmp_path / "spellbook.json"

    def write(cfg):
        cfg_path.write_text(json.dumps(cfg))
        os.chmod(cfg_path, 0o600)

    write({"seed_role": "identity"})
    cfg = load_config(str(tmp_path))
    assert cfg[seedrole.ALLOW_KEY] is False
    assert cfg["dashboard_sign_per_minute"] == 30
    for bad in ({seedrole.ALLOW_KEY: "true"}, {"seed_role": "money"},
                {"dashboard_sign_per_minute": 0},
                {"dashboard_sign_per_minute": True}):
        write(bad)
        with pytest.raises(ValueError):
            load_config(str(tmp_path))


# ------------------------------------------------------------ daemon start

def _write(p, data):
    with open(p, "w") as f:
        f.write(data)
    os.chmod(p, 0o600)


def _daemon_dir(cfg_extra=None, seed_text=None):
    tmp = tempfile.mkdtemp(prefix="spellbook-s04-")
    seed_path = os.path.join(tmp, "seed.key")
    _write(seed_path, seed_text if seed_text is not None else os.urandom(32).hex())
    uid = os.getuid()
    cfg = {"seed_path": seed_path,
           "allowed_request_uids": [uid], "allowed_approve_uids": [uid]}
    cfg.update(cfg_extra or {})
    _write(os.path.join(tmp, "spellbook.json"), json.dumps(cfg))
    _write(os.path.join(tmp, "policy.json"), "{}")
    _write(os.path.join(tmp, "request.token"), "aa" * 32)
    _write(os.path.join(tmp, "approve.token"), "bb" * 32)
    _write(os.path.join(tmp, "ledger.jsonl"), "")
    return tmp


@pytest.mark.skipif(not POSIX, reason="daemon needs POSIX")
def test_daemon_refuses_identity_seed_as_kdf_root():
    with pytest.raises(IdentitySeedAsWalletRoot):
        Daemon(_daemon_dir({"musebook_signing_mode": "daemon"}))


@pytest.mark.skipif(not POSIX, reason="daemon needs POSIX")
def test_daemon_refuses_a_labelled_identity_seed_file():
    text = seedrole.IDENTITY_ROLE_HEADER + "\n" + os.urandom(32).hex() + "\n"
    with pytest.raises(IdentitySeedAsWalletRoot, match="header"):
        Daemon(_daemon_dir(seed_text=text))


@pytest.mark.skipif(not POSIX, reason="daemon needs POSIX")
def test_daemon_starts_with_a_plain_wallet_seed():
    d = Daemon(_daemon_dir())
    assert d.identity_seed_markers == []


# ------------------------------------------------------------ dashboard route

CHALLENGE = "eyJ2IjoxLCJub25jZSI6ImFiYyIsImV4cCI6MX0.0a1b2c3d4e5f"


def _signing_daemon(per_minute=30):
    return Daemon(_daemon_dir({"musebook_signing_mode": "daemon",
                               seedrole.ALLOW_KEY: True,
                               "dashboard_sign_per_minute": per_minute}))


def _req(params):
    return {"token": "aa" * 32, "route": "sign_dashboard_challenge",
            "params": params, "muse_id": "test"}


@pytest.mark.skipif(not POSIX, reason="daemon needs POSIX")
def test_dashboard_route_signs_prefix_plus_challenge():
    d = _signing_daemon()
    out = d.handle(_req({"challenge": CHALLENGE}), os.getuid())
    assert out["ok"] is True, out
    assert out["prefix"] == "musebook-dashboard-v1:"
    vk = VerifyKey(bytes.fromhex(out["pubkey_hex"]))
    sig = bytes.fromhex(out["signature_hex"])
    vk.verify(("musebook-dashboard-v1:" + CHALLENGE).encode(), sig)
    with pytest.raises(BadSignatureError):
        vk.verify(CHALLENGE.encode(), sig)
    assert out["pubkey_hex"] == bytes(d._identity_key.verify_key).hex()
    rows = d.ledger.read_all()
    assert rows[-1]["decision"] == "dashboard-challenge-sign"


@pytest.mark.skipif(not POSIX, reason="daemon needs POSIX")
def test_dashboard_route_refuses_arbitrary_bytes():
    d = _signing_daemon()
    for bad in ("not a challenge", spellsign.MUSEBOOK_SIGN_PREFIX + "x.00", 42):
        out = d.handle(_req({"challenge": bad}), os.getuid())
        assert out["ok"] is False
    out = d.handle(_req({}), os.getuid())
    assert out["ok"] is False and "challenge" in out["error"]
    assert all(r["decision"] != "dashboard-challenge-sign"
               for r in d.ledger.read_all())


@pytest.mark.skipif(not POSIX, reason="daemon needs POSIX")
def test_dashboard_route_is_rate_capped():
    d = _signing_daemon(per_minute=2)
    outs = [d.handle(_req({"challenge": CHALLENGE}), os.getuid()) for _ in range(3)]
    assert [o["ok"] for o in outs] == [True, True, False]
    assert "rate cap" in outs[2]["error"]


@pytest.mark.skipif(not POSIX, reason="daemon needs POSIX")
def test_dashboard_route_behind_the_s1_gate():
    d = Daemon(_daemon_dir())
    out = d.handle(_req({"challenge": CHALLENGE}), os.getuid())
    assert out["ok"] is False and "S1" in out["error"]


# ------------------------------------------------------------ dashboard prefix

def test_prefixes_are_pairwise_non_nesting():
    ps = (spellsign.MUSEBOOK_SIGN_PREFIX, spellsign.DIRECTORY_ENTRY_PREFIX,
          spellsign.DASHBOARD_CHALLENGE_PREFIX)
    assert len(set(ps)) == 3
    for a in ps:
        for b in ps:
            assert a == b or not b.startswith(a)
    assert spellsign.DASHBOARD_CHALLENGE_PREFIX == "musebook-dashboard-v1:"


def test_dashboard_canonical_is_prefix_plus_verbatim_challenge():
    c = spellsign.build_dashboard_challenge_canonical(CHALLENGE)
    assert c == ("musebook-dashboard-v1:" + CHALLENGE).encode()


@pytest.mark.parametrize("bad", [
    "", "a" * 513, "no-dot", "two.dots.here", "spaces in.00",
    "new\nline.00", "x.zz", "\u00fc.00", ".00", "abc.",
    spellsign.MUSEBOOK_SIGN_PREFIX + "POST\n/api\n{}",
    spellsign.DIRECTORY_ENTRY_PREFIX + '{"a":1}',
    None, 42, b"bytes.00",
])
def test_dashboard_route_cannot_sign_arbitrary_bytes(bad):
    with pytest.raises(ValueError):
        spellsign.build_dashboard_challenge_canonical(bad)


def test_dashboard_signature_does_not_verify_as_any_other_domain():
    key = SigningKey.generate()  # throwaway, made here
    vk = key.verify_key
    sig = key.sign(spellsign.build_dashboard_challenge_canonical(CHALLENGE)).signature
    vk.verify(("musebook-dashboard-v1:" + CHALLENGE).encode(), sig)
    for other in (
        CHALLENGE.encode(),
        spellsign.build_musebook_canonical("POST", "/api/post", CHALLENGE),
        spellsign.build_directory_canonical({"challenge": CHALLENGE}),
    ):
        with pytest.raises(BadSignatureError):
            vk.verify(other, sig)


def test_web_verifier_checks_the_prefixed_challenge():
    text = open(os.path.join(ROOT, "web", "lib", "auth.ts"), encoding="utf-8").read()
    assert ('DASHBOARD_CHALLENGE_PREFIX = "%s"'
            % spellsign.DASHBOARD_CHALLENGE_PREFIX) in text
    assert "Buffer.from(DASHBOARD_CHALLENGE_PREFIX + challenge" in text
    assert 'Buffer.from(challenge, "utf8")' not in text


def test_onboarding_doc_no_longer_puts_the_seed_in_the_agent():
    doc = open(os.path.join(ROOT, "docs", "AGENT_ONBOARDING.md"), encoding="utf-8").read()
    for gone in ("MY_ED25519_SEED_HEX", "from_private_bytes", "createPrivateKey",
                 "agent_ed25519.json", 'key["seed_hex"]'):
        assert gone not in doc, gone
    assert "sign-dashboard-challenge" in doc


# ------------------------------------------------------------ sealed seed

def test_role_header_survives_seal_and_unlock(tmp_path):
    from spellbook import sealed
    cfg_dir = tmp_path / "home"
    cfg_dir.mkdir(mode=0o700)
    seed_path = cfg_dir / "seed.key"
    (cfg_dir / "spellbook.json").write_text(json.dumps({"seed_path": str(seed_path)}))
    seed = os.urandom(32)
    sealed._write_private(str(seed_path), seedrole.IDENTITY_ROLE_HEADER + "\n" + seed.hex())
    sp = str(tmp_path / "ws" / "seed.sealed")
    pw = "throwaway-" + os.urandom(8).hex()
    sealed.seal(pw, config_dir=str(cfg_dir), path=sp, n=2 ** 10)
    os.remove(seed_path)
    sealed.unlock(pw, config_dir=str(cfg_dir), path=sp)
    text = seed_path.read_text()
    assert seedrole.seed_file_role(text) == "identity"
    assert bytes.fromhex(seedmod.strip_comments(text)) == seed
    # the old two-tuple API is unchanged
    assert sealed.open_bytes(sealed.read_sealed(sp), pw) == (seed, None)


# ------------------------------------------------------------ rate cap

def test_dashboard_sign_window_caps_per_minute():
    now = [1000.0]
    w = DashboardSignWindow(3, clock=lambda: now[0])
    assert [w.allow() for _ in range(4)] == [True, True, True, False]
    now[0] += 59.0
    assert w.allow() is False
    now[0] += 1.5
    assert w.allow() is True


@pytest.mark.parametrize("bad", [0, -1, "3", 2.5, True])
def test_dashboard_sign_window_rejects_bad_caps(bad):
    with pytest.raises(ValueError):
        DashboardSignWindow(bad)

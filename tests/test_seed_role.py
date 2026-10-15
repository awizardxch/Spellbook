"""S-04: the identity seed must not be the wallet root; dashboard sign-in
is a daemon route under its own domain.

Pure-function tests: no daemon, no socket, no real seed. Every key here is
generated inside the test.
"""
import os

import pytest
from nacl.signing import SigningKey

from spellbook import seed as seedmod
from spellbook import seedrole
from spellbook import sign as spellsign
from spellbook.config import load_config
from spellbook.daemon import DashboardSignWindow
from spellbook.seedrole import IdentitySeedAsWalletRoot


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
    # A stray comment is not a label; only the exact header line is.
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
    # Option B shape: the BIP-39 std seed is the wallet root, the identity
    # seed only signs identity. Allowed, markers reported for status.
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
    if os.name == "posix":
        os.chmod(p, 0o600)
        assert seedmod.load_seed(str(p)) == entropy
    assert bytes.fromhex(seedmod.strip_comments(p.read_text())) == entropy


def test_load_config_validates_the_new_keys(tmp_path):
    import json
    cfg_path = tmp_path / "spellbook.json"

    def write(cfg):
        cfg_path.write_text(json.dumps(cfg))
        if os.name == "posix":
            os.chmod(cfg_path, 0o600)

    write({"seed_role": "identity"})
    if os.name != "posix":
        pytest.skip("load_config needs POSIX 0600 modes")
    cfg = load_config(str(tmp_path))
    assert cfg[seedrole.ALLOW_KEY] is False
    assert cfg["dashboard_sign_per_minute"] == 30
    write({seedrole.ALLOW_KEY: "true"})
    with pytest.raises(ValueError):
        load_config(str(tmp_path))
    write({"seed_role": "money"})
    with pytest.raises(ValueError):
        load_config(str(tmp_path))
    write({"dashboard_sign_per_minute": 0})
    with pytest.raises(ValueError):
        load_config(str(tmp_path))


# ------------------------------------------------------------ dashboard prefix

CHALLENGE = "eyJ2IjoxLCJub25jZSI6ImFiYyIsImV4cCI6MX0.0a1b2c3d4e5f"


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
    "new\nline.00", "x.zz", "ü.00", ".00", "abc.",
    # a Musebook canonical string and a directory entry can never pass
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
    # verifies under the dashboard domain only
    vk.verify(("musebook-dashboard-v1:" + CHALLENGE).encode(), sig)
    from nacl.exceptions import BadSignatureError
    for other in (
        CHALLENGE.encode(),  # the bare challenge (what the docs used to ask for)
        spellsign.build_musebook_canonical("POST", "/api/post", CHALLENGE),
        spellsign.build_directory_canonical({"challenge": CHALLENGE}),
    ):
        with pytest.raises(BadSignatureError):
            vk.verify(other, sig)


def test_dashboard_signature_matches_what_the_web_verifier_checks():
    # web/lib/auth.ts verifies UTF-8(DASHBOARD_CHALLENGE_PREFIX + challenge).
    key = SigningKey.generate()
    sig = key.sign(spellsign.build_dashboard_challenge_canonical(CHALLENGE)).signature
    key.verify_key.verify(("musebook-dashboard-v1:" + CHALLENGE).encode("utf-8"), sig)


def test_web_prefix_constant_is_the_same_string():
    here = os.path.dirname(os.path.abspath(__file__))
    auth_ts = os.path.join(here, "..", "web", "lib", "auth.ts")
    text = open(auth_ts, encoding="utf-8").read()
    assert 'DASHBOARD_CHALLENGE_PREFIX = "%s"' % spellsign.DASHBOARD_CHALLENGE_PREFIX in text
    assert "Buffer.from(DASHBOARD_CHALLENGE_PREFIX + challenge" in text


def test_onboarding_doc_no_longer_puts_the_seed_in_the_environment():
    here = os.path.dirname(os.path.abspath(__file__))
    doc = open(os.path.join(here, "..", "docs", "AGENT_ONBOARDING.md"), encoding="utf-8").read()
    assert "MY_ED25519_SEED_HEX" not in doc
    assert "from_private_bytes" not in doc
    assert "sign-dashboard-challenge" in doc


# ------------------------------------------------------------ rate cap

def test_dashboard_sign_window_caps_per_minute():
    now = [1000.0]
    w = DashboardSignWindow(3, clock=lambda: now[0])
    assert [w.allow() for _ in range(4)] == [True, True, True, False]
    now[0] += 59.0
    assert w.allow() is False
    now[0] += 1.5
    assert w.allow() is True


@pytest.mark.parametrize("bad", [0, -1, "3", 2.5])
def test_dashboard_sign_window_rejects_bad_caps(bad):
    with pytest.raises(ValueError):
        DashboardSignWindow(bad)

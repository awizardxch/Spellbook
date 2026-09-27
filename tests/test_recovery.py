"""Tests for spellbook.recovery — throwaway seeds only.

The key shown for backup/reveal must be the key the daemon actually signs
with: standard derivation (std_seed.key) on install.sh installs, the
labeled KDF (seed.key) on kdf-mode installs.
"""
import json
import os

import pytest

from spellbook import kdf, recovery, sealed, stdkeys
from spellbook.daemon import _refuse_if_locked
from spellbook.seed import mnemonic_from_entropy, mnemonic_to_seed

SEED = bytes(range(32))
STD_WORDS = " ".join(["abandon"] * 23 + ["art"])
STD = mnemonic_to_seed(STD_WORDS)


def _home(tmp_path, standard):
    d = tmp_path / "home"
    d.mkdir()
    cfg = {"seed_path": str(d / "seed.key")}
    if standard:
        cfg.update(key_derivation="standard", std_seed_path=str(d / "std_seed.key"))
        sealed._write_private(str(d / "std_seed.key"), STD.hex())
    (d / "spellbook.json").write_text(json.dumps(cfg))
    sealed._write_private(str(d / "seed.key"), SEED.hex())
    return str(d)


def test_live_evm_standard_is_the_bip32_key(tmp_path):
    loc = sealed.locate(_home(tmp_path, standard=True))
    priv, addr = recovery.live_evm(loc)
    want = stdkeys.evm_privkey(STD)
    assert priv == want.hex() and addr == stdkeys.evm_address(want)


def test_live_evm_kdf_is_the_labeled_key(tmp_path):
    loc = sealed.locate(_home(tmp_path, standard=False))
    priv, addr = recovery.live_evm(loc, "evm-4663")
    d = kdf.derive_labeled(SEED, "evm-4663", "default")
    assert (priv, addr) == (d["scalar_hex"], d["address"])


def test_reveal_mnemonic_is_the_daemon_seed(tmp_path, capsys):
    recovery.main(["--config-dir", _home(tmp_path, True), "reveal", "mnemonic"])
    assert capsys.readouterr().out.strip() == mnemonic_from_entropy(SEED)


def test_reveal_evm_key_follows_live_derivation(tmp_path, capsys):
    recovery.main(["--config-dir", _home(tmp_path, True),
                   "reveal", "evm-key", "--chain", "evm-4663"])
    assert capsys.readouterr().out.strip() == "0x" + stdkeys.evm_privkey(STD).hex()


@pytest.mark.parametrize("standard", [False, True])
def test_restore_from_words(tmp_path, monkeypatch, standard):
    d = _home(tmp_path, standard=True)
    target = os.path.join(d, "std_seed.key" if standard else "seed.key")
    os.remove(target)
    words = STD_WORDS if standard else mnemonic_from_entropy(SEED)
    monkeypatch.setattr(recovery.getpass, "getpass", lambda _p="": words.upper())
    argv = ["--config-dir", d, "restore"] + (["--standard"] if standard else [])
    recovery.main(argv)
    assert open(target).read() == (STD if standard else SEED).hex()
    assert os.stat(target).st_mode & 0o077 == 0


def test_restore_never_overwrites(tmp_path):
    with pytest.raises(SystemExit):
        recovery.main(["--config-dir", _home(tmp_path, True), "restore"])


def test_daemon_names_a_locked_seed(tmp_path, monkeypatch):
    sp = tmp_path / "seed.sealed"
    monkeypatch.setenv("SPELLBOOK_SEALED_PATH", str(sp))
    missing = str(tmp_path / "gone" / "seed.key")
    _refuse_if_locked(missing, None)  # no seal: the plain loader error applies
    sp.write_text("{}")
    with pytest.raises(FileNotFoundError, match="spellbook-seed serve"):
        _refuse_if_locked(missing, None)

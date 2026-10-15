"""The hosted ceremony JS (web/public/ceremony/common.js) against the
Python side that opens its envelopes (spellbook.ceremony) — run with Node
when it is on PATH (skipped otherwise; the format is also pinned by
tests/test_ceremony.py from the Python side)."""
import json
import os
import shutil
import subprocess

import pytest

from spellbook import asset_index, ceremony, seed

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not on PATH")

TEST_SET1 = " ".join(["abandon"] * 23 + ["art"])  # published BIP-39 vector
TEST_SET2 = " ".join(["zoo"] * 23 + ["vote"])

HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const [, , dir, inPath] = process.argv;
const ctx = { TextEncoder, TextDecoder, atob, btoa, crypto: globalThis.crypto };
ctx.window = ctx;
vm.createContext(ctx);
for (const f of ["bip39.js", "common.js"])
  vm.runInContext(fs.readFileSync(dir + "/" + f, "utf8"), ctx, { filename: f });
const SB = ctx.SB;
const inp = JSON.parse(fs.readFileSync(inPath, "utf8"));
(async () => {
  const frag = SB.readFragment(inp.fragment);
  const der = frag.key;
  const out = {
    op: frag.op,
    seal: await SB.sealEnvelope("seal", { password: inp.password }, der),
    restore: await SB.sealEnvelope("restore", { set1_standard: inp.set1, set2_daemon: inp.set2 }, der),
    enc2: await SB.sealEnc2(inp.seedHex, der),
    fp: await SB.fingerprint(der),
    problems: inp.passwords.map(p => SB.passwordProblem(p)),
    entropy: SB.bytesToHex((await SB.mnemonicEntropy(inp.set2, "SET 2")).entropy),
    seed: await SB.mnemonicToSeedHex(inp.set1),
  };
  let bad = null;
  try { await SB.mnemonicEntropy(inp.set1.replace(/art$/, "zoo"), "SET 1"); } catch (e) { bad = e.message; }
  out.badChecksum = bad;
  process.stdout.write(JSON.stringify(out));
})().catch(e => { process.stderr.write(String(e.stack)); process.exit(1); });
"""

PASSWORDS = [
    "short", "aaaaaaaaaaaaaaaa", "password1234", "correct horse battery",
    "Tr0ub4dor&3xyz!", "abandon ability able about above absent",
    "abandon abandon abandon abandon abandon abandon", "zxcvbnmasdfg",
    "ab12AB!@cd34CD", "qwertyuiopasdfghjklzxcvbnm", "çàéü€ñøßπ漢字かなカナ",
]


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    from Crypto.PublicKey import RSA
    tmp = tmp_path_factory.mktemp("cjs")
    key = RSA.generate(2048)
    keyfile = tmp / "private.pem"
    keyfile.write_bytes(key.export_key())
    keyfile.chmod(0o600)
    der = key.publickey().export_key(format="DER")
    url = ceremony.hosted_url("seal", pub_der=der, op="seal")
    (tmp / "harness.js").write_text(HARNESS)
    (tmp / "in.json").write_text(json.dumps({
        "fragment": url.split("#", 1)[1], "password": "a test seal password!",
        "set1": TEST_SET1, "set2": TEST_SET2,
        "seedHex": seed.mnemonic_to_seed(TEST_SET1).hex(),
        "passwords": PASSWORDS}))
    cdir = f"{asset_index.repo_root()}/{asset_index.CEREMONY_DIR}"
    r = subprocess.run([NODE, str(tmp / "harness.js"), cdir, str(tmp / "in.json")],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout), str(keyfile), der


def test_js_envelopes_open_in_python(run, monkeypatch):
    out, keyfile, der = run
    if os.name == "nt":  # no POSIX modes: the 0600 check is a Linux check
        monkeypatch.setattr(ceremony.os, "stat",
                            lambda p: type("S", (), {"st_mode": 0o100600})())
    assert out["op"] == "seal"
    assert out["fp"] == ceremony.key_fingerprint(der)
    kind, p = ceremony.open_envelope(out["seal"], keyfile)
    assert kind == "seal" and p == {"password": "a test seal password!"}
    kind, p = ceremony.open_envelope(out["restore"], keyfile)
    assert kind == "restore" and p["set1_standard"] == TEST_SET1


def test_js_enc2_matches_daemon_format(run):
    import base64
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    out, keyfile, _ = run
    env = json.loads(base64.b64decode(out["enc2"].split(".", 1)[1]))
    assert env["v"] == 2 and env["algo"] == "RSA-OAEP-SHA256+AES-GCM-256"
    key = RSA.import_key(open(keyfile, "rb").read())
    aes = PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(bytes.fromhex(env["ek"]))
    ct = bytes.fromhex(env["ct"])
    pt = AES.new(aes, AES.MODE_GCM, nonce=bytes.fromhex(env["iv"])) \
        .decrypt_and_verify(ct[:-16], ct[-16:])
    assert pt.decode() == seed.mnemonic_to_seed(TEST_SET1).hex()


def test_js_bip39_and_strength_rule_match_python(run):
    out, _, _ = run
    assert out["entropy"] == seed.entropy_from_mnemonic(TEST_SET2).hex()
    assert out["seed"] == seed.mnemonic_to_seed(TEST_SET1).hex()
    assert "checksum" in out["badChecksum"]
    assert out["problems"] == [ceremony.password_problem(p) for p in PASSWORDS]

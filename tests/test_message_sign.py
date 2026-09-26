"""Wallet message signatures on all chains (SPEC §10).

EIP-191 personal_sign + EIP-712 typed data (EVM), ed25519 off-chain signing
(Solana), and the daemon's request/execution gating for message_sign.

sign.py is cross-verified byte-identical against eth-account — a TEST-ONLY
oracle (pip eth-account); src/ never imports it. Daemon tests reuse
_daemon_with_seed from test_chia, the same pattern as
tests/test_sage_surface.py. Test keys only; no network.
"""
import json
import sys

import pytest

sys.path.insert(0, "tests")

from test_chia import _daemon_with_seed  # noqa: E402

from spellbook import evm, sign  # noqa: E402
from spellbook import solana as solana_mod  # noqa: E402
from spellbook.policy import Policy  # noqa: E402

# Test-only oracle: NEVER imported by src/.
from eth_account import Account  # noqa: E402
from eth_account.messages import encode_defunct, encode_typed_data  # noqa: E402

PRIV = bytes.fromhex("11" * 32)
ADDR = evm.address_from_privkey(PRIV)  # lowercase 0x hex


def _oracle_personal_sig(msg: str) -> bytes:
    return bytes(Account.sign_message(encode_defunct(text=msg),
                                      private_key=PRIV).signature)


def _typed_data_envelope() -> dict:
    """EIP-712 envelope exercising nested custom types, dynamic + fixed
    arrays, and every atomic type Spellbook encodes."""
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"},
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"},
                {"name": "nonce", "type": "uint256"},
                {"name": "delta", "type": "int8"},
                {"name": "flag", "type": "bool"},
                {"name": "ref", "type": "bytes32"},
                {"name": "blob", "type": "bytes"},
                {"name": "tags", "type": "string[]"},
                {"name": "recipients", "type": "Person[]"},
                {"name": "scores", "type": "uint256[3]"},
            ],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Spellbook",
            "version": "1",
            "chainId": 4663,
            "verifyingContract": "0x" + "00" * 19 + "Cc",
        },
        "message": {
            "from": {"name": "Alice",
                     "wallet": "0x" + "00" * 19 + "a1"},
            "to": {"name": "Bob",
                   "wallet": "0x" + "00" * 19 + "b2"},
            "contents": "hello bob",
            "nonce": 42,
            "delta": -7,
            "flag": True,
            "ref": "0x" + "ab" * 32,
            "blob": "0xdeadbeef",
            "tags": ["a", "b"],
            "recipients": [{"name": "C",
                            "wallet": "0x" + "00" * 19 + "c3"}],
            "scores": [1, 2, 3],
        },
    }


# ------------------------------------------------- EIP-191 personal_sign

@pytest.mark.parametrize("msg", [
    "hello spellbook",
    "",
    "x" * 1000,
    "héllo wörld 🌙",  # unicode -> utf-8 preimage
    "a" * 9 + "b",     # length-prefix boundary shapes
])
def test_evm_personal_sign_matches_oracle(msg):
    sig = sign.evm_personal_sign(PRIV, msg)
    assert len(sig) == 65
    assert sig[64] in (27, 28)
    assert sign.is_low_s(sig[:64])
    assert sig == _oracle_personal_sig(msg)
    # recovery round-trip
    assert sign.evm_recover_personal_address(msg, sig).lower() == ADDR.lower()


def test_evm_personal_sign_rejects_bad_input():
    with pytest.raises(ValueError):
        sign.evm_personal_sign(PRIV, b"bytes not str")
    with pytest.raises(ValueError):
        sign.evm_personal_sign(b"short", "hi")
    with pytest.raises(ValueError):
        sign.evm_recover_personal_address("hi", b"short")
    bad_v = bytearray(sign.evm_personal_sign(PRIV, "hi"))
    bad_v[64] = 29
    with pytest.raises(ValueError):
        sign.evm_recover_personal_address("hi", bytes(bad_v))


def test_evm_checksum_address():
    assert sign.evm_to_checksum_address(
        "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a") == \
        "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"
    with pytest.raises(ValueError):
        sign.evm_to_checksum_address("0x1234")


# ------------------------------------------------------------- EIP-712

def test_eip712_digest_matches_oracle():
    from Crypto.Hash import keccak
    td = _typed_data_envelope()
    enc = encode_typed_data(full_message=td)
    oracle = keccak.new(
        data=b"\x19" + enc.version + enc.header + enc.body,
        digest_bits=256).digest()
    assert sign.eip712_digest(td) == oracle


def test_evm_sign_typed_data_matches_oracle_and_recovers():
    td = _typed_data_envelope()
    sig = sign.evm_sign_typed_data(PRIV, td)
    assert len(sig) == 65 and sig[64] in (27, 28)
    assert sign.is_low_s(sig[:64])
    enc = encode_typed_data(full_message=td)
    oracle = bytes(Account.sign_message(enc, private_key=PRIV).signature)
    assert sig == oracle
    assert Account.recover_message(enc, signature=sig).lower() == \
        ADDR.lower()


def test_eip712_digest_rejects_bad_envelopes():
    td = _typed_data_envelope()
    for mutate in (
        lambda t: {k: v for k, v in t.items() if k != "types"},
        lambda t: {**t, "primaryType": "Nope"},
        lambda t: {**t, "types": {k: v for k, v in t["types"].items()
                                  if k != "EIP712Domain"}},
        lambda t: {**t, "message": {**t["message"],
                                    "scores": [1, 2]}},  # fixed-len wrong
        lambda t: {**t, "message": {**t["message"],
                                    "delta": 200}},  # int8 overflow
        lambda t: "not a dict",
    ):
        with pytest.raises(ValueError):
            sign.eip712_digest(mutate(td))
    # unknown atomic type inside a custom struct
    bad = _typed_data_envelope()
    bad["types"]["Mail"].append({"name": "weird", "type": "float64"})
    bad["message"]["weird"] = 1.5
    with pytest.raises(ValueError):
        sign.eip712_digest(bad)


# ------------------------------------------------- Solana off-chain sign

def test_solana_sign_message_roundtrip():
    from solders.keypair import Keypair
    kp = Keypair.from_seed(bytes(range(32)))
    msg = "hello solana".encode()
    sig = sign.solana_sign_message(kp, msg)
    assert len(sig) == 64
    assert solana_mod.signature_valid(
        solana_mod.pubkey_bytes(kp), msg, sig)
    assert not solana_mod.signature_valid(
        solana_mod.pubkey_bytes(kp), b"tampered", sig)
    with pytest.raises(ValueError):
        sign.solana_sign_message(kp, "not bytes")


# ------------------------------------------- daemon request-time gating

_ABSENT = object()


def _req(d, chain, message, sign_type=_ABSENT, **kw):
    p = {"chain": chain, "message": message, "address": "0xabc"}
    if sign_type is not _ABSENT:
        p["sign_type"] = sign_type
    p.update(kw)
    return d.rt_message_sign(p, "m")


def test_rt_sign_type_chain_gating(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    td_json = json.dumps(_typed_data_envelope())
    # EVM accepts personal + typed_data
    r = _req(d, "evm-4663", "hi", "personal")
    assert r["ok"] is True and r["decision"] == "queued"
    r = _req(d, "evm-46630", td_json, "typed_data")
    assert r["ok"] is True and r["decision"] == "queued"
    # EVM rejects plain
    assert _req(d, "evm-4663", "hi", "plain")["ok"] is False
    # Chia/Solana accept only plain
    assert _req(d, "chia-testnet", "hi", "plain")["ok"] is True
    assert _req(d, "solana-devnet", "hi", "plain")["ok"] is True
    assert _req(d, "chia-testnet", "hi", "personal")["ok"] is False
    assert _req(d, "solana-devnet", "hi", "typed_data")["ok"] is False
    assert _req(d, "chia-testnet", td_json, "typed_data")["ok"] is False
    # unknown families / unknown chains fail closed
    assert _req(d, "evm-9999", "hi", "personal")["ok"] is False
    assert _req(d, "bitcoin-mainnet", "hi", "plain")["ok"] is False
    assert _req(d, "solana-unknown", "hi", "plain")["ok"] is False


def test_rt_sign_type_value_validation(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    # missing sign_type keeps the v1 default (plain) for backward compat
    r = _req(d, "chia-testnet", "hi")
    assert r["ok"] is True and r["decision"] == "queued"
    assert d.queue[r["queue_id"]]["params"]["sign_type"] == "plain"
    # present-but-invalid values are schema violations
    assert _req(d, "chia-testnet", "hi", None)["ok"] is False
    assert _req(d, "chia-testnet", "hi", "")["ok"] is False
    assert _req(d, "evm-4663", "hi", "bogus")["ok"] is False


def test_rt_typed_data_message_shape(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    assert _req(d, "evm-4663", "not json", "typed_data")["ok"] is False
    assert _req(d, "evm-4663", json.dumps({"a": 1}),
               "typed_data")["ok"] is False
    assert _req(d, "evm-4663", json.dumps({"types": {}, "primaryType": "M",
                                           "domain": {}, "message": {}}),
               "typed_data")["ok"] is True  # shape ok; envelope validated later


def test_rt_message_sign_still_always_queues(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    # Even a permissive auto-approve policy must not execute signing.
    d.policy = Policy(auto_approve_below={("evm-4663", "native"): 10**30})
    r = _req(d, "evm-4663", "hi", "personal")
    assert r["ok"] is True and r["decision"] == "queued"
    shown = {q["queue_id"]: q for q in d._decoded_queue()}
    assert shown[r["queue_id"]]["sign_type"] == "personal"
    assert shown[r["queue_id"]]["message"] == "hi"


def test_rt_solana_network_mismatch_refuses(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    # default config is devnet; mainnet-beta is refused at request time
    assert _req(d, "solana-mainnet", "hi", "plain")["ok"] is False


# ------------------------------------------- daemon execution (EVM)

def _evm_daemon(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    monkeypatch.setattr(d, "_evm_key", lambda chain: (PRIV, ADDR))
    return d


def _params(chain, message, sign_type, **kw):
    p = {"intent": "message_sign", "chain": chain, "message": message,
         "sign_type": sign_type, "address": ADDR}
    p.update(kw)
    return p


def test_execute_evm_personal_via_spend_dispatch(tmp_path, monkeypatch):
    d = _evm_daemon(tmp_path, monkeypatch)
    out = d._execute_spend(_params("evm-4663", "hello spellbook", "personal"))
    assert out["submitted"] is False
    assert out["sign_type"] == "personal"
    assert out["signed_by"] == ADDR
    assert out["signature"] == "0x" + _oracle_personal_sig(
        "hello spellbook").hex()
    assert sign.evm_recover_personal_address(
        "hello spellbook", bytes.fromhex(out["signature"][2:])).lower() == \
        ADDR.lower()


def test_execute_evm_personal_public_key_identity(tmp_path, monkeypatch):
    d = _evm_daemon(tmp_path, monkeypatch)
    pub = sign.secp256k1_pubkey_uncompressed_hex(PRIV)
    # with and without 04 / 0x prefixes
    for pk in (pub, pub[2:], "0x" + pub):
        out = d._execute_spend(_params("evm-4663", "hi", "personal",
                                       public_key=pk, address=None))
        assert out["signed_by"] == ADDR
    # wrong key refuses
    other = sign.secp256k1_pubkey_uncompressed_hex(bytes.fromhex("22" * 32))
    with pytest.raises(evm.EvmError):
        d._execute_spend(_params("evm-4663", "hi", "personal",
                                 public_key=other, address=None))


def test_execute_evm_typed_data(tmp_path, monkeypatch):
    d = _evm_daemon(tmp_path, monkeypatch)
    td_json = json.dumps(_typed_data_envelope())
    out = d._execute_spend(_params("evm-4663", td_json, "typed_data"))
    assert out["submitted"] is False
    assert out["sign_type"] == "typed_data"
    sig = bytes.fromhex(out["signature"][2:])
    enc = encode_typed_data(full_message=_typed_data_envelope())
    assert Account.recover_message(enc, signature=sig).lower() == \
        ADDR.lower()


def test_execute_evm_typed_data_chainid_mismatch_refuses(tmp_path,
                                                         monkeypatch):
    d = _evm_daemon(tmp_path, monkeypatch)
    td = _typed_data_envelope()
    td["domain"]["chainId"] = 1  # mainnet envelope, evm-4663 signer
    with pytest.raises(evm.EvmError, match="chainId"):
        d._execute_spend(_params("evm-4663", json.dumps(td), "typed_data"))


def test_execute_evm_identity_mismatch_refuses(tmp_path, monkeypatch):
    d = _evm_daemon(tmp_path, monkeypatch)
    with pytest.raises(evm.EvmError):
        d._execute_spend(_params("evm-4663", "hi", "personal",
                                 address="0x" + "99" * 20))
    # address AND public_key is rejected
    with pytest.raises(evm.EvmError):
        d._execute_spend(_params("evm-4663", "hi", "personal",
                                 address=ADDR,
                                 public_key="0x" + "11" * 32))
    # neither identity is rejected
    p = _params("evm-4663", "hi", "personal")
    del p["address"]
    with pytest.raises(evm.EvmError):
        d._execute_spend(p)
    # unsupported sign_type for EVM fails closed
    with pytest.raises(evm.EvmError):
        d._execute_spend(_params("evm-4663", "hi", "plain"))


# ------------------------------------------- daemon execution (Solana)

def _sol_daemon(tmp_path, monkeypatch):
    from solders.keypair import Keypair
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    kp = Keypair.from_seed(bytes(range(32)))
    monkeypatch.setattr(d, "_solana_keypair", lambda chain: kp)
    return d, kp


def test_execute_solana_plain(tmp_path, monkeypatch):
    d, kp = _sol_daemon(tmp_path, monkeypatch)
    addr = solana_mod.address_of_keypair(kp)
    out = d._execute_spend({"intent": "message_sign", "chain": "solana-devnet",
                            "message": "hello solana", "sign_type": "plain",
                            "address": addr})
    assert out["submitted"] is False
    assert out["sign_type"] == "plain"
    assert out["signed_by"] == addr
    sig = solana_mod.b58decode(out["signature"])
    assert len(sig) == 64
    assert solana_mod.signature_valid(
        solana_mod.pubkey_bytes(kp), b"hello solana", sig)


def test_execute_solana_identity_mismatch_refuses(tmp_path, monkeypatch):
    d, kp = _sol_daemon(tmp_path, monkeypatch)
    addr = solana_mod.address_of_keypair(kp)
    with pytest.raises(solana_mod.SolanaError):
        d._execute_spend({"intent": "message_sign", "chain": "solana-devnet",
                          "message": "hi", "sign_type": "plain",
                          "address": "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJzE"})
    # public_key path works too (base58)
    out = d._execute_spend({"intent": "message_sign", "chain": "solana-devnet",
                            "message": "hi", "sign_type": "plain",
                            "public_key": solana_mod.b58encode(
                                solana_mod.pubkey_bytes(kp))})
    assert out["signed_by"] == addr
    # wrong pubkey refuses
    with pytest.raises(solana_mod.SolanaError):
        d._execute_spend({"intent": "message_sign", "chain": "solana-devnet",
                          "message": "hi", "sign_type": "plain",
                          "public_key": "1" * 44})


def test_execute_unknown_chain_fails_closed(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    out = d._execute_spend({"intent": "message_sign", "chain": "evm-1",
                            "message": "hi", "sign_type": "personal",
                            "address": ADDR})
    assert out["submitted"] is False and "not configured" in out["note"]


# ------------------------------------------- fee_mojos schema parity
# (2026-09-25: the client's _tx_params always sends fee_mojos=0, but
# MESSAGE_SIGN_FIELDS rejected it — the CLI could not queue signatures.)

def test_rt_message_sign_accepts_zero_fee_mojos(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    r = _req(d, "evm-4663", "hi", "personal", fee_mojos=0)
    assert r["ok"] is True and r["decision"] == "queued"


def test_rt_message_sign_rejects_nonzero_fee_mojos(tmp_path, monkeypatch):
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    for bad in (1, 1000, True, "0"):
        r = _req(d, "evm-4663", "hi", "personal", fee_mojos=bad)
        assert r["ok"] is False, bad
        assert "fee_mojos" in r["error"], bad


def test_client_message_sign_params_pass_daemon_validation(tmp_path,
                                                           monkeypatch):
    """End-to-end shape check: capture exactly what AgentClient.message_sign
    (the CLI path) sends and run it through the daemon's validation."""
    from spellbook.client import AgentClient

    class _Probe(AgentClient):
        def __init__(self):
            super().__init__("/nonexistent.sock", "00" * 32)
            self.seen = None

        def _call(self, route, params=None, timeout=None):
            self.seen = {"route": route, "params": params}
            return {"ok": True}

    probe = _Probe()
    probe.message_sign(chain="evm-4663", message="hi", address="0xabc",
                       sign_type="personal", purpose="test")
    params = probe.seen["params"]
    assert probe.seen["route"] == "message_sign"
    assert params["fee_mojos"] == 0  # _tx_params always includes it
    d, _ = _daemon_with_seed(tmp_path, monkeypatch)
    out = d.rt_message_sign(params, "m")
    assert out["ok"] is True and out["decision"] == "queued"

"""Tests for Solana transfer building/signing — all offline.

Covers:
  - build_transfer produces a well-formed signed SOL transfer: one
    SystemProgram transfer instruction, fee payer + recent blockhash set,
    base64 wire payload decodes back to the same bytes.
  - The signature verifies against the serialized message (solders
    tx.verify() and per-signature signature_valid).
  - A tampered message fails verification (byte flip in the message
    region -> signature invalid, tx.verify() raises).
  - Fee payer, destination, lamports, and blockhash in the decoded
    message match the approved intent exactly.
  - Fail-closed inputs: bad address, bad blockhash, non-positive lamports.

Only throwaway keys are used — no real wallet material.
"""

import base64

import pytest
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from spellbook import solana

SEED = bytes.fromhex("cd" * 32)
TO = "CiDwVBFgWV9E5MvXWoLgnEgn3hK7rJik46f9h4JAxnug"  # random 32-byte pubkey, base58
BLOCKHASH = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"
LAMPORTS = 1_234_567


def _built():
    kp = solana.keypair_from_seed(SEED)
    return kp, solana.build_transfer(kp, TO, LAMPORTS, BLOCKHASH)


def test_build_transfer_shape():
    kp, out = _built()
    assert out["from"] == solana.address_of_keypair(kp)
    assert out["to"] == TO
    assert out["lamports"] == LAMPORTS
    assert out["recent_blockhash"] == BLOCKHASH
    assert out["signature"]  # non-empty base58 signature
    # base64 wire payload decodes to a parseable transaction.
    wire = base64.b64decode(out["raw_b64"])
    tx = Transaction.from_bytes(wire)
    assert len(tx.signatures) == 1
    assert str(tx.signatures[0]) == out["signature"]


def test_signature_verifies_against_message():
    kp, out = _built()
    wire = base64.b64decode(out["raw_b64"])
    tx = Transaction.from_bytes(wire)
    tx.verify()  # raises on any signature failure
    msg = tx.message_data()
    sig = bytes(tx.signatures[0])
    assert solana.signature_valid(solana.pubkey_bytes(kp), msg, sig)


def test_tampered_message_fails_verification():
    kp, out = _built()
    wire = bytearray(base64.b64decode(out["raw_b64"]))
    # 64-byte signature first, then the message: flip a byte in the message.
    wire[70] ^= 0x01
    bad = Transaction.from_bytes(bytes(wire))
    with pytest.raises(Exception):
        bad.verify()
    sig = bytes(bad.signatures[0])
    assert not solana.signature_valid(
        solana.pubkey_bytes(kp), bad.message_data(), sig)


def test_tampered_signature_fails_verification():
    kp, out = _built()
    wire = bytearray(base64.b64decode(out["raw_b64"]))
    # Byte 0 is the compact-u16 signature count — flip inside the
    # 64-byte signature body instead so the tx still deserializes.
    wire[10] ^= 0x01
    bad = Transaction.from_bytes(bytes(wire))
    with pytest.raises(Exception):
        bad.verify()
    assert not solana.signature_valid(
        solana.pubkey_bytes(kp), bad.message_data(), bytes(bad.signatures[0]))


def test_fee_payer_and_blockhash_set():
    kp, out = _built()
    wire = base64.b64decode(out["raw_b64"])
    msg = Message.from_bytes(Transaction.from_bytes(wire).message_data())
    # Fee payer is account 0 of the legacy message.
    assert str(msg.account_keys[0]) == solana.address_of_keypair(kp)
    assert str(msg.recent_blockhash) == BLOCKHASH


def test_instruction_decodes_to_intent():
    kp, out = _built()
    wire = base64.b64decode(out["raw_b64"])
    msg = Message.from_bytes(Transaction.from_bytes(wire).message_data())
    assert len(msg.instructions) == 1
    ins = msg.instructions[0]
    assert str(msg.account_keys[ins.program_id_index]) == solana.SYSTEM_PROGRAM_ID
    acct = bytes(ins.accounts)
    assert len(acct) == 2
    assert str(msg.account_keys[acct[0]]) == solana.address_of_keypair(kp)
    assert str(msg.account_keys[acct[1]]) == TO
    # SystemProgram transfer: discriminator 2 (u32 LE) || lamports (u64 LE).
    assert bytes(ins.data) == b"\x02\x00\x00\x00" + LAMPORTS.to_bytes(8, "little")


def test_deterministic_signing():
    kp = solana.keypair_from_seed(SEED)
    a = solana.build_transfer(kp, TO, LAMPORTS, BLOCKHASH)
    b = solana.build_transfer(kp, TO, LAMPORTS, BLOCKHASH)
    assert a["raw_b64"] == b["raw_b64"]
    assert a["signature"] == b["signature"]


def test_different_blockhash_different_signature():
    kp = solana.keypair_from_seed(SEED)
    other_bh = solana.b58encode(bytes.fromhex("ee" * 32))
    a = solana.build_transfer(kp, TO, LAMPORTS, BLOCKHASH)
    b = solana.build_transfer(kp, TO, LAMPORTS, other_bh)
    assert a["signature"] != b["signature"]


def test_rejects_bad_inputs():
    kp = solana.keypair_from_seed(SEED)
    with pytest.raises(solana.SolanaError):
        solana.build_transfer(kp, "not-an-address", LAMPORTS, BLOCKHASH)
    with pytest.raises(solana.SolanaError):
        solana.build_transfer(kp, "1" * 31, LAMPORTS, BLOCKHASH)  # 31 bytes
    with pytest.raises(solana.SolanaError):
        solana.build_transfer(kp, TO, LAMPORTS, "nope")
    with pytest.raises(solana.SolanaError):
        solana.build_transfer(kp, TO, 0, BLOCKHASH)
    with pytest.raises(solana.SolanaError):
        solana.build_transfer(kp, TO, -5, BLOCKHASH)


def test_rpc_rejects_unknown_network():
    with pytest.raises(solana.SolanaError):
        solana.SolanaRpc("solana-bogus")


def test_rpc_defaults():
    rpc = solana.SolanaRpc("solana-devnet")
    assert rpc.url == "https://api.devnet.solana.com"
    rpc2 = solana.SolanaRpc("solana-mainnet")
    assert rpc2.url == "https://api.mainnet-beta.solana.com"


def test_chrome_ua_configured():
    assert "Chrome/" in solana.CHROME_UA

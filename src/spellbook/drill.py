#!/usr/bin/env python3
"""The §10 install drill — off-chain phases. SPEC §10, S14.

Runs with a THROWAWAY seed generated fresh in a temp dir — never the real
muse key. The on-chain phases (testnet sends, then mainnet dust) are NOT
run here: they print as a checklist and need their own explicit
authorization. drill-status.json records exactly what ran.

  python -m spellbook.drill --vectors ./vectors/vectors.json \
      --status-out /opt/spellbook/drill-status.json
"""
import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time

from spellbook import kdf
from spellbook.client import AgentClient, HumanClient, SpellbookError
from spellbook.seed import generate_entropy, entropy_from_mnemonic, mnemonic_from_entropy


def _write(path, data, mode=0o600):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)


def phase_kdf(vectors_path):
    """Phase A: the installed daemon's KDF reproduces every vector."""
    vectors = json.load(open(vectors_path))["vectors"]
    n = 0
    for v in vectors:
        if "expected_failure" in v:
            vid = v["vector_id"]
            try:
                if vid == "kdf-negative-short-seed":
                    kdf.derive_scalar(bytes.fromhex(v["test_seed_hex"]), "evm-4663", "d")
                elif vid == "kdf-negative-secp256k1-scalar-at-order":
                    kdf.secp256k1_pubkey_uncompressed(int(v["scalar_hex"], 16))
                elif vid == "kdf-negative-bls-scalar-zero":
                    kdf.bls_g1_pubkey(0)
                elif vid == "kdf-negative-bip39-checksum":
                    entropy_from_mnemonic(v["mnemonic"])
                else:
                    raise AssertionError(f"unknown negative vector {vid}")
            except ValueError:
                n += 1
                continue
            raise AssertionError(f"negative vector {vid} did NOT fail")
        seed = bytes.fromhex(v["test_seed_hex"])
        d = kdf.derive_labeled(seed, v["chain"], v["label"])
        assert d["scalar_hex"] == v["expected_scalar_hex"], v["vector_id"]
        assert d["ctr_used"] == v["ctr_used"], v["vector_id"]
        if v["chain"].startswith("evm-"):
            assert d["pubkey_hex"] == v["expected_pubkey_hex"], v["vector_id"]
            assert d["address"] == v["expected_address"], v["vector_id"]
        else:
            assert d["pubkey_hex"] == v["expected_master_pubkey_hex"], v["vector_id"]
        n += 1
    # Paper-backup round-trip on throwaway entropy.
    ent = generate_entropy()
    assert entropy_from_mnemonic(mnemonic_from_entropy(ent)) == ent
    print(f"phase A (KDF vectors): {n}/{len(vectors)} reproduce — green")
    return n


def _wait_sock(sock):
    for _ in range(100):
        if os.path.exists(sock):
            return
        time.sleep(0.1)
    raise RuntimeError("drill daemon did not come up")


def phase_daemon():
    """Phase B: throwaway daemon lifecycle through the agent client."""
    tmp = tempfile.mkdtemp(prefix="spellbook-drill-")
    req_token, app_token = secrets.token_hex(32), secrets.token_hex(32)
    _write(os.path.join(tmp, "request.token"), req_token)
    _write(os.path.join(tmp, "approve.token"), app_token)
    _write(os.path.join(tmp, "seed.key"), generate_entropy().hex())
    _write(os.path.join(tmp, "spellbook.json"), json.dumps({"seed_path": os.path.join(tmp, "seed.key")}))
    _write(os.path.join(tmp, "policy.json"), json.dumps({
        "approval_threshold": {"evm-4663:native": 100},
    }))
    _write(os.path.join(tmp, "ledger.jsonl"), "")
    sock = os.path.join(tmp, "spellbook.sock")

    proc = subprocess.Popen([sys.executable, "-m", "spellbook.daemon",
                             "--socket", sock, "--config", tmp],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        _wait_sock(sock)
        agent = AgentClient(sock, req_token, muse_id="drill")
        human = HumanClient(sock, app_token, muse_id="drill-human")

        # request -> queued -> approve -> gone from queue, in ledger.
        qid = agent.request_spend(chain="evm-4663", destination="0x" + "ab" * 20,
                                  amount_wei=10 ** 15, purpose="drill")["queue_id"]
        assert any(i["queue_id"] == qid for i in agent.queue())
        assert human.approve(qid)["ok"] is True
        assert all(i["queue_id"] != qid for i in agent.queue())

        # request -> queued -> reject.
        qid2 = agent.request_spend(chain="evm-4663", destination="0x" + "cd" * 20,
                                   amount_wei=10 ** 15, purpose="drill")["queue_id"]
        assert human.reject(qid2)["ok"] is True

        # S7: the request token cannot approve.
        try:
            agent._call("queue_approve", {"queue_id": qid2})
            raise AssertionError("request token approved!")
        except SpellbookError:
            pass

        # Restart survival of the queue.
        qid3 = agent.request_spend(chain="evm-4663", destination="0x" + "ef" * 20,
                                   amount_wei=10 ** 15, purpose="persist")["queue_id"]
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    if os.path.exists(sock):
        os.unlink(sock)
    proc = subprocess.Popen([sys.executable, "-m", "spellbook.daemon",
                             "--socket", sock, "--config", tmp],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        _wait_sock(sock)
        agent = AgentClient(sock, req_token, muse_id="drill")
        assert any(i["queue_id"] == qid3 for i in agent.queue()), "queue did not survive restart"
        assert agent.addresses()["default"]["evm-4663"].startswith("0x")
        assert len(agent.ledger()) >= 4
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    print("phase B (daemon lifecycle): request/queue/approve/reject/restart — green")


ONCHAIN_CHECKLIST = """\
phase C (on-chain drill) — NOT RUN. Each step needs explicit authorization:
  [ ] 10.3  fund throwaway EVM address on Sepolia, request 0.001 ETH spend
  [ ] 10.4  human approves from the separate device; daemon submits
  [ ] 10.5  confirm inclusion + ledger sighash, balances read back
  [ ] 10.6  Sage testnet: same loop for XCH via pinned Sage CLI
  [ ] 10.7  rotation drill on the MAINTAINER's machine only (§6/O2)
  [ ] 10.14-17 mainnet dust: SEPARATE authorization + Speechless-approved amounts
"""


def main():
    ap = argparse.ArgumentParser(prog="spellbook-drill")
    ap.add_argument("--vectors", required=True)
    ap.add_argument("--status-out", required=True)
    args = ap.parse_args()

    n = phase_kdf(args.vectors)
    phase_daemon()
    print(ONCHAIN_CHECKLIST)

    status = {"ts": time.time(), "kdf_vectors_reproduced": n,
              "off_chain": "green",
              "on_chain": "pending-explicit-authorization"}
    with open(args.status_out, "w") as f:
        json.dump(status, f, indent=2, sort_keys=True)
    print(f"drill status written to {args.status_out}")
    print("OFF-CHAIN DRILL GREEN — on-chain phases need explicit authorization.")


if __name__ == "__main__":
    main()

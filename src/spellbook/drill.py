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
phase C (on-chain drill) — EVM path on Robinhood Chain testnet (46630).
Sage/XCH steps: pinned-commit build path implemented 2026-09-20; live drill
run still pending.
  [x] 10.3  fund throwaway EVM address (faucet), request small-wei spend
  [x] 10.4  below-threshold auto-approve submits; queued spend approved via
            the approve token (human-client stand-in), daemon submits
  [x] 10.5  confirm inclusion + ledger sighash, balances read back live
  [ ] 10.6  Sage testnet: same loop for XCH via pinned Sage CLI
  [ ] 10.7  rotation drill on the MAINTAINER's machine only (§6/O2)
  [ ] 10.14-17 mainnet dust: SEPARATE authorization + Speechless-approved amounts
"""


ONCHAIN_RPC = "https://rpc.testnet.chain.robinhood.com"
ONCHAIN_CHAIN = "evm-46630"  # Robinhood Chain testnet (SPEC §10 step 9)
ONCHAIN_FAUCET = "https://faucet.testnet.chain.robinhood.com"
ONCHAIN_EXPLORER = "https://explorer.testnet.chain.robinhood.com"


def _kill9(proc):
    import signal
    proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=5)


def phase_onchain_testnet():
    """Phase C: §10 steps 3-7, 9, 11-13 on Robinhood testnet (EVM path).

    Throwaway seed, throwaway daemon, worthless testnet funds. Blocks waiting
    for the faucet (up to 30 min) — fund the printed address and it proceeds.
    The Chia/Sage steps (§10 steps 1, 8 and the XCH half of 5-7) await a live
    drill run; the pinned-commit build path (install.sh §2) is implemented.
    """
    tmp = tempfile.mkdtemp(prefix="spellbook-onchain-")
    req_token, app_token = secrets.token_hex(32), secrets.token_hex(32)
    seed_hex = generate_entropy().hex()
    _write(os.path.join(tmp, "request.token"), req_token)
    _write(os.path.join(tmp, "approve.token"), app_token)
    _write(os.path.join(tmp, "seed.key"), seed_hex)
    _write(os.path.join(tmp, "spellbook.json"), json.dumps({
        "seed_path": os.path.join(tmp, "seed.key"),
        "evm": {"chains": {ONCHAIN_CHAIN:
                            {"rpc_url": ONCHAIN_RPC, "enabled": True}}},
    }))
    unit = 10 ** 15  # 0.001 test ETH, in wei
    _write(os.path.join(tmp, "policy.json"), json.dumps({
        "auto_approve_below": {f"{ONCHAIN_CHAIN}:native": unit // 10},
        "approval_threshold": {f"{ONCHAIN_CHAIN}:native": unit},
        "per_spend_cap": {f"{ONCHAIN_CHAIN}:native": 12 * unit},
        "daily_velocity_cap": {f"{ONCHAIN_CHAIN}:native": 16 * unit},
    }))
    _write(os.path.join(tmp, "ledger.jsonl"), "")
    sock = os.path.join(tmp, "spellbook.sock")
    results = {}

    def start():
        p = subprocess.Popen(
            [sys.executable, "-m", "spellbook.daemon",
             "--socket", sock, "--config", tmp],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        _wait_sock(sock)
        return p

    proc = start()
    try:
        agent = AgentClient(sock, req_token, muse_id="drill")
        human = HumanClient(sock, app_token, muse_id="drill-human")
        addr = agent.addresses()["default"][ONCHAIN_CHAIN]
        print(f"\nphase C address ({ONCHAIN_CHAIN}): {addr}")
        print(f"fund it at {ONCHAIN_FAUCET} — waiting up to 30 min ...")
        bal = 0
        for i in range(120):
            try:
                bal = agent.status()["balances"][ONCHAIN_CHAIN]["balance_wei"]
            except Exception:
                pass
            if bal and bal > 0:
                break
            if i % 4 == 0:
                print(f"  ... still waiting ({i * 15}s)")
            time.sleep(15)
        assert bal and bal > 0, "no faucet funds arrived — aborting phase C"
        print(f"funded: {bal} wei")
        results["funded_wei"] = bal

        # §10.4: below auto-approve threshold -> executes on-chain.
        r = agent.request_spend(chain=ONCHAIN_CHAIN,
                                destination="0x" + "11" * 20,
                                amount_wei=unit // 20, purpose="drill-10.4")
        assert r["decision"] == "approved" and r.get("tx_hash"), r
        print(f"  10.4 auto-approve executed: {r['tx_hash']}")
        results["tx_auto"] = r["tx_hash"]

        # §10.5: above threshold -> queued -> human approves -> executes.
        qid = agent.request_spend(chain=ONCHAIN_CHAIN,
                                  destination="0x" + "22" * 20,
                                  amount_wei=5 * unit,
                                  purpose="drill-10.5")["queue_id"]
        qi = [i for i in agent.queue() if i["queue_id"] == qid][0]
        assert qi["destination"] == "0x" + "22" * 20 and qi["amount"] == 5 * unit
        ap = human.approve(qid)
        assert ap["ok"] and ap.get("tx_hash"), ap
        print(f"  10.5 queued->approved executed: {ap['tx_hash']}")
        results["tx_queued"] = ap["tx_hash"]

        # §10.6: above per-spend cap -> denied with reason.
        d = agent.request_spend(chain=ONCHAIN_CHAIN,
                                destination="0x" + "33" * 20,
                                amount_wei=100 * unit, purpose="drill-10.6")
        assert d["decision"] == "denied", d
        print(f"  10.6 over-cap denied: {d['reason']}")

        # §10.7: velocity — 0.05 + 5 = 5.05 units spent; cap is 16; an 11-unit
        # request fits the per-spend cap (12) but breaks the velocity window.
        v = agent.request_spend(chain=ONCHAIN_CHAIN,
                                destination="0x" + "44" * 20,
                                amount_wei=11 * unit, purpose="drill-10.7")
        assert v["decision"] == "denied", v
        print(f"  10.7 velocity denied: {v['reason']}")

        # §10.5 balances read back through the API.
        st = agent.status()
        bal_after = st["balances"][ONCHAIN_CHAIN]["balance_wei"]
        spent = bal - bal_after
        assert spent >= 5 * unit + unit // 20, (bal, bal_after)
        print(f"  balances read back: {bal_after} wei (spent ~{spent})")
        results["balance_after_wei"] = bal_after

        # Ledger carries both sighashes (tx hashes), never the seed.
        rows = agent.ledger()
        hashes = [row.get("sighash") for row in rows]
        assert results["tx_auto"] in hashes and results["tx_queued"] in hashes
        blob = open(os.path.join(tmp, "ledger.jsonl")).read()
        assert seed_hex not in blob, "SEED LEAKED INTO LEDGER"
        print("  ledger: both tx hashes present as sighash; no seed material")

        # §10.13 seed hygiene: the seed appears in no API response.
        seen = json.dumps(agent.queue()) + json.dumps(rows) + json.dumps(st)
        assert seed_hex not in seen, "SEED LEAKED THROUGH THE API"
        print("  seed hygiene: seed in no API surface")

        # §10.12 boundary (drill-scoped): bad token, and the request token
        # attempting an approve route, both denied.
        try:
            AgentClient(sock, "00" * 32, muse_id="x").status()
            raise AssertionError("bad token accepted!")
        except SpellbookError:
            pass
        try:
            agent._call("queue_approve", {"queue_id": "999"})
            raise AssertionError("request token approved!")
        except SpellbookError:
            pass
        print("  boundary: bad token + privilege escalation denied")

        # §10.11: kill -9 mid-queue — queue, ledger, velocity survive.
        # 5 units: above threshold (queued), fits the remaining window.
        qid9 = agent.request_spend(chain=ONCHAIN_CHAIN,
                                   destination="0x" + "55" * 20,
                                   amount_wei=5 * unit,
                                   purpose="drill-10.11")["queue_id"]
    finally:
        _kill9(proc)
    if os.path.exists(sock):
        os.unlink(sock)
    proc = start()
    try:
        agent = AgentClient(sock, req_token, muse_id="drill")
        assert any(i["queue_id"] == qid9 for i in agent.queue()), \
            "queue did not survive kill -9"
        assert len(agent.ledger()) >= 4, "ledger did not survive kill -9"
        # Velocity survived too: the 11-unit request is still denied.
        v2 = agent.request_spend(chain=ONCHAIN_CHAIN,
                                 destination="0x" + "66" * 20,
                                 amount_wei=11 * unit, purpose="drill-10.11b")
        assert v2["decision"] == "denied", v2
        print("  kill -9: queue, ledger, and velocity window all survived")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    results["kill9_survival"] = True
    print("phase C (on-chain testnet drill): GREEN")
    return results


def main():
    ap = argparse.ArgumentParser(prog="spellbook-drill")
    ap.add_argument("--vectors", required=True)
    ap.add_argument("--status-out", required=True)
    ap.add_argument("--onchain-testnet", action="store_true",
                    help="run phase C: the §10 on-chain testnet drill (EVM path). "
                         "Needs explicit authorization — it moves (worthless) funds.")
    args = ap.parse_args()

    n = phase_kdf(args.vectors)
    phase_daemon()
    status = {"ts": time.time(), "kdf_vectors_reproduced": n,
              "off_chain": "green"}
    if args.onchain_testnet:
        results = phase_onchain_testnet()
        status["on_chain_testnet"] = "green"
        status["on_chain_results"] = results
    else:
        print(ONCHAIN_CHECKLIST)
        status["on_chain"] = "pending-explicit-authorization"
    with open(args.status_out, "w") as f:
        json.dump(status, f, indent=2, sort_keys=True)
    print(f"drill status written to {args.status_out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Smoke-test the spellbookd scaffold: socket up, token auth, policy, ledger,
queue approve/reject, S1 gate. Uses throwaway tokens in a temp dir. No secrets.
"""
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time

DAEMON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spellbookd.py")


def write(path, data, mode=0o600):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, mode)


def main():
    tmp = tempfile.mkdtemp(prefix="spellbook-smoke-")
    req_token = secrets.token_hex(32)
    app_token = secrets.token_hex(32)
    write(os.path.join(tmp, "request.token"), req_token)
    write(os.path.join(tmp, "approve.token"), app_token)
    write(os.path.join(tmp, "spellbook.json"), json.dumps({}))
    write(os.path.join(tmp, "policy.json"), json.dumps({
        "per_spend_cap": {"evm-4663:native": 1000},
        "approval_threshold": {"evm-4663:native": 100},
        "auto_approve_below": {"evm-4663:native": 10},
    }))
    write(os.path.join(tmp, "ledger.jsonl"), "")
    sock = os.path.join(tmp, "spellbook.sock")

    proc = subprocess.Popen([sys.executable, DAEMON, "--socket", sock, "--config", tmp],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    else:
        print("daemon did not come up"); print(proc.stdout.read().decode()); sys.exit(1)

    def call(token, route, params=None, muse_id="muse_smoke"):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(sock)
        c.sendall((json.dumps({"token": token, "route": route,
                               "params": params or {}, "muse_id": muse_id}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            buf += c.recv(65536)
        c.close()
        return json.loads(buf.decode())

    fails = []
    def check(name, cond, detail=""):
        print(("ok   " if cond else "FAIL ") + name, detail)
        if not cond:
            fails.append(name)

    # 1. bad token rejected
    r = call("00" * 32, "status")
    check("bad token rejected", r["ok"] is False)

    # 2. request token: status works
    r = call(req_token, "status")
    check("request token status", r["ok"] is True)

    # 3. request token cannot touch approve routes (S7)
    r = call(req_token, "queue_approve", {"queue_id": "1"})
    check("request token blocked from approve", r["ok"] is False and "approve token" in r["error"])

    # 4. default policy knobs: tiny spend auto-approves-path, big queues, huge denies
    tiny = {"chain": "evm-4663", "destination": "0xabc", "asset": "native", "amount_mojos": 5, "purpose": "tip"}
    big = dict(tiny, amount_mojos=500)
    huge = dict(tiny, amount_mojos=5000)
    r = call(req_token, "request_spend", tiny)
    check("tiny spend approved-path", r.get("decision") == "approved", str(r)[:80])
    r = call(req_token, "request_spend", big)
    check("over-threshold queued", r.get("decision") == "queued" and "queue_id" in r, str(r)[:80])
    qid = r.get("queue_id")
    r = call(req_token, "request_spend", huge)
    check("over-cap denied", r.get("decision") == "denied", str(r)[:80])

    # 5. contract-call shaped request rejected at the schema (S13)
    evil = dict(tiny, calldata="0xdeadbeef")
    r = call(req_token, "request_spend", evil)
    check("calldata schema-rejected", r["ok"] is False and "schema violation" in r["error"], str(r)[:80])

    # 6. approve token can approve the queued spend
    r = call(app_token, "queue_approve", {"queue_id": qid})
    check("approve token approves", r["ok"] is True, str(r)[:80])

    # 7. ledger readable via API (P6), rows present
    r = call(req_token, "ledger_read")
    rows = r.get("rows", [])
    check("ledger has rows", r["ok"] is True and len(rows) >= 5, f"{len(rows)} rows")
    check("ledger rows canonical", all(set(x) == {"ts", "requester_muse", "canon_digest", "sighash", "decision"} for x in rows))

    # 8. S1 gate: musebook signing disabled by default
    r = call(req_token, "sign_musebook_request", {"method": "POST", "path": "/api/post", "body": "{}"})
    check("S1 gate closed by default", r["ok"] is False and "S1" in r["error"], r["error"][:80])

    # 9. unknown route rejected
    r = call(req_token, "nope")
    check("unknown route rejected", r["ok"] is False)

    proc.terminate()
    proc.wait(timeout=5)
    print(f"\n{len(fails)} failures" if fails else "\nsmoke green.")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()

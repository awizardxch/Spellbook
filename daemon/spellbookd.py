#!/usr/bin/env python3
"""spellbookd — the Spellbook policy daemon (scaffold). SPEC §4.

Listens on a Unix domain socket (peer-credential checks). Localhost HTTP
is the specified fallback; this scaffold implements the socket path.

Protocol: newline-delimited JSON per connection.
  request:  {"token": "<hex>", "route": "<name>", "params": {...}}
  response: {"ok": true, ...} | {"ok": false, "error": "..."}

Everything chain-touching (balances, signing, broadcast, Sage RPC) is an
explicit TODO(build). Token auth, routing, policy evaluation, the ledger,
and the queue are real.
"""
import argparse
import json
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import load_config, load_policy
from ledger import Ledger
from policy import evaluate
import tokens as token_auth

# Fixed domain prefixes (P1): a Musebook signing string can never parse as a
# directory entry, and the daemon never signs caller-supplied raw bytes.
MUSEBOOK_SIGN_PREFIX = "spellbook-musebook-request/v1/"
DIRECTORY_ENTRY_PREFIX = "spellbook-directory-entry/v1/"

REQUEST_ROUTES = {
    "request_spend", "queue_read", "status", "addresses",
    "ledger_read", "sign_musebook_request",
}
APPROVE_ROUTES = {
    "queue_approve", "queue_reject", "publish_directory_entry",
}

# v1 transfer schema — plain transfers only (S13). Unknown fields are
# rejected; anything shaped like a contract call is denied, not coerced.
SPEND_FIELDS = {"chain", "destination", "asset", "purpose"}
AMOUNT_FIELDS = {"amount_mojos", "amount_wei"}


class Daemon:
    def __init__(self, config_dir):
        self.cfg = load_config(config_dir)
        self.policy = load_policy(config_dir)
        self.request_token = token_auth.load_token(os.path.join(config_dir, "request.token"))
        self.approve_token = token_auth.load_token(os.path.join(config_dir, "approve.token"))
        self.ledger = Ledger(os.path.join(config_dir, "ledger.jsonl"))
        self.queue = {}          # queue_id -> request (restart survival: TODO(build) persist)
        self.next_qid = 1

    # ------------------------------------------------------------ auth
    def _auth(self, presented_hex: str):
        try:
            presented = bytes.fromhex(presented_hex)
        except ValueError:
            return None
        if token_auth.check(presented, self.request_token):
            return "request"
        if token_auth.check(presented, self.approve_token):
            return "approve"
        return None

    # ------------------------------------------------------------ routes
    def handle(self, req: dict, peer_uid: int) -> dict:
        role = self._auth(req.get("token", ""))
        if role is None:
            return {"ok": False, "error": "bad token"}
        route = req.get("route")
        params = req.get("params", {}) or {}

        if route in APPROVE_ROUTES and role != "approve":
            # S7: an approval the requester can grant is not an approval.
            self.ledger.append(req.get("muse_id", "?"), json.dumps(req).encode(),
                               None, "denied:privilege-escalation-attempt")
            return {"ok": False, "error": "approve token required"}
        if route not in REQUEST_ROUTES and route not in APPROVE_ROUTES:
            return {"ok": False, "error": f"unknown route {route!r}"}

        handler = getattr(self, "rt_" + route, None)
        if handler is None:
            return {"ok": False, "error": "not implemented"}
        return handler(params, req.get("muse_id", "?"))

    def rt_request_spend(self, p: dict, muse_id: str) -> dict:
        fields = set(p)
        amounts = fields & AMOUNT_FIELDS
        if (not fields.issubset(SPEND_FIELDS | AMOUNT_FIELDS)
                or "chain" not in p or len(amounts) != 1):
            return {"ok": False, "error": "schema violation: v1 is plain transfers only"}
        amount = p.get("amount_mojos", p.get("amount_wei"))
        if not isinstance(amount, int) or amount <= 0:
            return {"ok": False, "error": "amount must be a positive integer in base units"}
        # Note: contract-call-shaped requests never reach here — "calldata"/"data"
        # are not in the v1 schema, so they fail the subset check above (S13).
        # TODO(build): spent_last_24h from the persisted ledger window.
        d = evaluate(self.policy, p["chain"], p.get("asset", "native"),
                     amount, p.get("destination", ""), 0)
        row = self.ledger.append(muse_id, json.dumps(p, sort_keys=True).encode(),
                                 None, d.verdict)
        if d.verdict == "queued":
            qid = str(self.next_qid); self.next_qid += 1
            self.queue[qid] = {"params": p, "muse_id": muse_id}
            return {"ok": True, "decision": "queued", "queue_id": qid,
                    "reason": d.reason}
        if d.verdict == "denied":
            return {"ok": True, "decision": "denied", "reason": d.reason}
        # TODO(build): build, sign (daemon-held key), and submit the transfer;
        # verify the built tx matches the approved intent before signing.
        return {"ok": True, "decision": "approved",
                "note": "TODO(build): chain submission not yet implemented"}

    def rt_queue_read(self, p: dict, muse_id: str) -> dict:
        # TODO(build): surface full decoded intent (to/value/chain-id/asset),
        # never just a hash (Zuckbot).
        return {"ok": True, "queue": self.queue}

    def rt_queue_approve(self, p: dict, muse_id: str) -> dict:
        qid = p.get("queue_id")
        if qid not in self.queue:
            return {"ok": False, "error": "unknown queue_id"}
        item = self.queue.pop(qid)
        self.ledger.append(muse_id, json.dumps(item["params"], sort_keys=True).encode(),
                           None, "approved-by-human")
        # TODO(build): build/sign/submit, then record sighash in the ledger.
        return {"ok": True, "queue_id": qid, "note": "TODO(build): chain submission"}

    def rt_queue_reject(self, p: dict, muse_id: str) -> dict:
        qid = p.get("queue_id")
        if qid not in self.queue:
            return {"ok": False, "error": "unknown queue_id"}
        item = self.queue.pop(qid)
        self.ledger.append(muse_id, json.dumps(item["params"], sort_keys=True).encode(),
                           None, "rejected-by-human")
        return {"ok": True, "queue_id": qid}

    def rt_status(self, p: dict, muse_id: str) -> dict:
        # TODO(build): balances via Sage RPC / EVM node; velocity windows
        # from the persisted ledger.
        return {"ok": True, "queue_depth": len(self.queue),
                "note": "TODO(build): live balances"}

    def rt_addresses(self, p: dict, muse_id: str) -> dict:
        # TODO(build): derived labeled addresses (§2 KDF + §5).
        return {"ok": True, "addresses": {},
                "note": "TODO(build): KDF not yet wired"}

    def rt_ledger_read(self, p: dict, muse_id: str) -> dict:
        # P6: the ledger is read through the API, never the file.
        return {"ok": True, "rows": self.ledger.read_all()}

    def rt_sign_musebook_request(self, p: dict, muse_id: str) -> dict:
        # S1 (recommended, pending Speechless's call) + P1.
        if self.cfg.get("musebook_signing_mode") != "daemon":
            return {"ok": False,
                    "error": "daemon-side Musebook signing is disabled pending the S1 decision"}
        for f in ("method", "path", "body"):
            if f not in p:
                return {"ok": False, "error": f"missing field {f}"}
        # The daemon builds the canonical string itself — it never signs
        # caller-supplied raw bytes (P1).
        canonical = (MUSEBOOK_SIGN_PREFIX + p["method"] + "\n"
                     + p["path"] + "\n" + p["body"])
        # TODO(build): ed25519 sign `canonical` with the identity seed
        # (vendored ed25519; stdlib has none). Log the request digest.
        self.ledger.append(muse_id, canonical.encode(), None, "musebook-sign")
        return {"ok": False, "error": "TODO(build): identity signing not yet wired"}

    def rt_publish_directory_entry(self, p: dict, muse_id: str) -> dict:
        # Approve token only (checked in handle()). Distinct prefix (P1).
        entry = p.get("entry")
        if not isinstance(entry, dict):
            return {"ok": False, "error": "entry must be an object"}
        canonical = DIRECTORY_ENTRY_PREFIX + json.dumps(entry, sort_keys=True,
                                                        separators=(",", ":"))
        # TODO(build): ed25519 sign `canonical`; publish per §8/O3.
        self.ledger.append(muse_id, canonical.encode(), None, "directory-entry")
        return {"ok": False, "error": "TODO(build): identity signing not yet wired"}


def peer_uid(conn: socket.socket) -> int:
    # SO_PEERCRED: the kernel tells us who is on the other end of the socket.
    try:
        data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", data)
        return uid
    except OSError:
        return -1


def serve(sock_path: str, daemon: Daemon):
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o700)
    srv.listen(16)
    print(f"spellbookd listening on {sock_path}", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            uid = peer_uid(conn)
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            try:
                req = json.loads(buf.decode())
            except (ValueError, UnicodeDecodeError):
                conn.sendall(b'{"ok": false, "error": "bad json"}\n')
                continue
            resp = daemon.handle(req, uid)
            conn.sendall((json.dumps(resp) + "\n").encode())
        finally:
            conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    daemon = Daemon(args.config)
    serve(args.socket, daemon)


if __name__ == "__main__":
    main()

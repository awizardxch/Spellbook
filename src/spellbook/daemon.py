#!/usr/bin/env python3
"""spellbookd — the Spellbook policy daemon. SPEC §4, O10.

Listens on a Unix domain socket (peer-credential checks). Localhost HTTP
is the specified fallback; this build implements the socket path.

Protocol: newline-delimited JSON per connection.
  request:  {"token": "<hex>", "route": "<name>", "params": {...}}
  response: {"ok": true, ...} | {"ok": false, "error": "..."}

Real in this build: token auth, per-role peer-UID enforcement (when
configured), routing, policy evaluation, the decision ledger, a persistent
spend queue, 24h velocity accounting rebuilt from disk, the §2 KDF
(third implementation — reproduces vectors/vectors.json), labeled
addresses, and Ed25519 identity signing behind the S1 gate.

Still TODO (SPEC §10 phase 1): chain RPC (balances, tx build/submit via
EVM node and Sage). Nothing here touches a chain.
"""
import argparse
import json
import os
import socket
import struct
import sys
import time

from spellbook import kdf, sign as spellsign
from spellbook.config import load_config, load_policy
from spellbook.ledger import Ledger
from spellbook.policy import evaluate
from spellbook.seed import load_seed
from spellbook import tokens as token_auth

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

VELOCITY_WINDOW_S = 24 * 3600


def _redacted(req: dict) -> str:
    """Ledger-safe request summary: the bearer token is never written to disk."""
    return json.dumps({"route": req.get("route"), "muse_id": req.get("muse_id"),
                       "params_keys": sorted((req.get("params") or {}).keys())})


def _atomic_write_json(path: str, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.rename(tmp, path)


class Daemon:
    def __init__(self, config_dir):
        self.config_dir = config_dir
        self.cfg = load_config(config_dir)
        self.policy = load_policy(config_dir)
        self.request_token = token_auth.load_token(os.path.join(config_dir, "request.token"))
        self.approve_token = token_auth.load_token(os.path.join(config_dir, "approve.token"))
        self.ledger = Ledger(os.path.join(config_dir, "ledger.jsonl"))
        self.queue_path = os.path.join(config_dir, "queue.json")
        self.velocity_path = os.path.join(config_dir, "velocity.jsonl")
        self._load_queue()
        self._load_velocity()
        # The seed is loaded only to derive addresses/signing keys in-process.
        # It is never logged, never returned by any route, never leaves this
        # process. Real seeds enter only after the §10 phase-1 authorization.
        seed_path = self.cfg.get("seed_path")
        self.seed = load_seed(seed_path) if seed_path else None
        if self.seed and self.cfg.get("musebook_signing_mode") == "daemon":
            from nacl.signing import SigningKey
            self._identity_key = SigningKey(self.seed)
        else:
            self._identity_key = None

    # ------------------------------------------------------------ state
    def _load_queue(self):
        if os.path.exists(self.queue_path):
            with open(self.queue_path) as f:
                data = json.load(f)
            self.queue = data.get("items", {})
            self.next_qid = data.get("next_qid", 1)
        else:
            self.queue = {}
            self.next_qid = 1

    def _save_queue(self):
        _atomic_write_json(self.queue_path,
                           {"next_qid": self.next_qid, "items": self.queue})

    def _load_velocity(self):
        """Rebuild the 24h spend window from the sidecar (SPEC §10 step 11).

        The decision ledger itself carries only digests (P6), so executed/
        approved amounts live in this daemon-local sidecar — never in the API.
        """
        self.velocity = []  # [(ts, chain, asset, amount)]
        if os.path.exists(self.velocity_path):
            with open(self.velocity_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        r = json.loads(line)
                        self.velocity.append((r["ts"], r["chain"], r["asset"], r["amount"]))
        self._prune_velocity()

    def _prune_velocity(self):
        cutoff = time.time() - VELOCITY_WINDOW_S
        kept = [row for row in self.velocity if row[0] >= cutoff]
        if len(kept) != len(self.velocity):
            self.velocity = kept
            with open(self.velocity_path, "w") as f:
                for ts, chain, asset, amount in kept:
                    f.write(json.dumps({"ts": ts, "chain": chain, "asset": asset,
                                        "amount": amount}, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())

    def _record_velocity(self, chain: str, asset: str, amount: int):
        self.velocity.append((time.time(), chain, asset, amount))
        with open(self.velocity_path, "a") as f:
            f.write(json.dumps({"ts": time.time(), "chain": chain, "asset": asset,
                                "amount": amount}, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def spent_last_24h(self, chain: str, asset: str) -> int:
        cutoff = time.time() - VELOCITY_WINDOW_S
        return sum(a for ts, c, at, a in self.velocity
                   if c == chain and at == asset and ts >= cutoff)

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
        # Peer-UID enforcement (S2): when the config names the UIDs allowed
        # per role, the kernel's credential is ENFORCED — a stolen token from
        # the wrong OS user is denied and the attempt is ledgered.
        allowed_key = ("allowed_request_uids" if role == "request"
                       else "allowed_approve_uids")
        allowed = self.cfg.get(allowed_key)
        if allowed is not None and peer_uid not in allowed:
            self.ledger.append(req.get("muse_id", "?"),
                               _redacted(req).encode(),
                               None, "denied:uid-not-allowed")
            return {"ok": False, "error": "peer UID not allowed for this role"}
        route = req.get("route")
        params = req.get("params", {}) or {}

        if route in APPROVE_ROUTES and role != "approve":
            # S7: an approval the requester can grant is not an approval.
            self.ledger.append(req.get("muse_id", "?"), _redacted(req).encode(),
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
        asset = p.get("asset", "native")
        d = evaluate(self.policy, p["chain"], asset,
                     amount, p.get("destination", ""),
                     self.spent_last_24h(p["chain"], asset))
        canon = json.dumps(p, sort_keys=True).encode()
        if d.verdict == "queued":
            qid = str(self.next_qid); self.next_qid += 1
            self.queue[qid] = {"params": p, "muse_id": muse_id,
                               "queued_at": time.time()}
            self._save_queue()
            self.ledger.append(muse_id, canon, None, f"queued:{qid}")
            return {"ok": True, "decision": "queued", "queue_id": qid,
                    "reason": d.reason}
        if d.verdict == "denied":
            self.ledger.append(muse_id, canon, None, "denied:" + d.reason)
            return {"ok": True, "decision": "denied", "reason": d.reason}
        self._record_velocity(p["chain"], asset, amount)
        self.ledger.append(muse_id, canon, None, "approved")
        # TODO(phase-1): build, sign (daemon-held key), and submit the transfer;
        # verify the built tx matches the approved intent before signing.
        return {"ok": True, "decision": "approved",
                "note": "TODO(phase-1): chain submission not yet implemented"}

    def _decoded_queue(self):
        # Full decoded intent (to/value/chain/asset), never just a hash.
        out = []
        for qid, item in sorted(self.queue.items(), key=lambda kv: int(kv[0])):
            p = item["params"]
            out.append({
                "queue_id": qid,
                "chain": p.get("chain"),
                "destination": p.get("destination"),
                "asset": p.get("asset", "native"),
                "amount": p.get("amount_mojos", p.get("amount_wei")),
                "purpose": p.get("purpose", ""),
                "muse_id": item.get("muse_id"),
                "queued_at": item.get("queued_at"),
            })
        return out

    def rt_queue_read(self, p: dict, muse_id: str) -> dict:
        return {"ok": True, "queue": self._decoded_queue()}

    def rt_queue_approve(self, p: dict, muse_id: str) -> dict:
        qid = p.get("queue_id")
        if qid not in self.queue:
            return {"ok": False, "error": "unknown queue_id"}
        item = self.queue.pop(qid)
        self._save_queue()
        params = item["params"]
        asset = params.get("asset", "native")
        amount = params.get("amount_mojos", params.get("amount_wei"))
        self._record_velocity(params["chain"], asset, amount)
        self.ledger.append(muse_id, json.dumps(params, sort_keys=True).encode(),
                           None, "approved-by-human")
        # TODO(phase-1): build/sign/submit, then record sighash in the ledger.
        return {"ok": True, "queue_id": qid,
                "note": "TODO(phase-1): chain submission not yet implemented"}

    def rt_queue_reject(self, p: dict, muse_id: str) -> dict:
        qid = p.get("queue_id")
        if qid not in self.queue:
            return {"ok": False, "error": "unknown queue_id"}
        item = self.queue.pop(qid)
        self._save_queue()
        self.ledger.append(muse_id, json.dumps(item["params"], sort_keys=True).encode(),
                           None, "rejected-by-human")
        return {"ok": True, "queue_id": qid}

    def rt_status(self, p: dict, muse_id: str) -> dict:
        # TODO(phase-1): balances via Sage RPC / EVM node.
        return {"ok": True, "queue_depth": len(self.queue),
                "seed_loaded": self.seed is not None,
                "note": "TODO(phase-1): live balances"}

    def rt_addresses(self, p: dict, muse_id: str) -> dict:
        if self.seed is None:
            return {"ok": True, "addresses": {},
                    "note": "no seed configured — daemon serves policy/queue/ledger only"}
        out = {}
        for label in self.cfg.get("labels", ["default"]):
            per_label = {}
            for chain in kdf.CHAINS:
                if chain.startswith("chia-") and not self.cfg.get("chia_enabled", True):
                    continue
                d = kdf.derive_labeled(self.seed, chain, label)
                per_label[chain] = d.get("address", d["pubkey_hex"])
            out[label] = per_label
        return {"ok": True, "addresses": out}

    def rt_ledger_read(self, p: dict, muse_id: str) -> dict:
        # P6: the ledger is read through the API, never the file.
        return {"ok": True, "rows": self.ledger.read_all()}

    def rt_sign_musebook_request(self, p: dict, muse_id: str) -> dict:
        # S1 gate (recommended Option B direction, pending Speechless's call).
        if self._identity_key is None:
            return {"ok": False,
                    "error": "daemon-side Musebook signing is disabled pending the S1 decision"}
        for f in ("method", "path", "body"):
            if f not in p:
                return {"ok": False, "error": f"missing field {f}"}
        # The daemon builds the canonical string itself — it never signs
        # caller-supplied raw bytes (P1).
        canonical = spellsign.build_musebook_canonical(p["method"], p["path"], p["body"])
        signed = self._identity_key.sign(canonical)
        self.ledger.append(muse_id, canonical, None, "musebook-sign")
        return {"ok": True, "signature_hex": signed.signature.hex()}

    def rt_publish_directory_entry(self, p: dict, muse_id: str) -> dict:
        # Approve token only (checked in handle()). Distinct prefix (P1).
        if self._identity_key is None:
            return {"ok": False,
                    "error": "identity signing is disabled pending the S1 decision"}
        canonical = spellsign.build_directory_canonical(p.get("entry"))
        signed = self._identity_key.sign(canonical)
        self.ledger.append(muse_id, canonical, None, "directory-entry")
        # TODO(phase-1): publish per §8/O3.
        return {"ok": True, "signature_hex": signed.signature.hex(),
                "note": "TODO(phase-1): directory publication not yet implemented"}


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
    # S2: the agent runs as its own OS user, not the daemon's. When the
    # config names a socket group, group members may connect (the token is
    # still the authentication; peer-UID allowlists are the authorization).
    group = daemon.cfg.get("socket_group")
    if group:
        import shutil
        shutil.chown(sock_path, group=group)
        os.chmod(sock_path, 0o770)
    else:
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
    ap = argparse.ArgumentParser(prog="spellbookd")
    ap.add_argument("--socket", required=True)
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    daemon = Daemon(args.config)
    serve(args.socket, daemon)


if __name__ == "__main__":
    main()

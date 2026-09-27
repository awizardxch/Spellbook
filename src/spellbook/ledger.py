"""Spellbook decision ledger — SPEC §4 (S10, Turbo, ARION; P6).

Append-only. Every intent and decision is appended — never secrets.
Row shape (canonical): {ts, requester_muse, canon_digest(request_bytes_stored),
sighash?, decision}. The digest is over the stored bytes, never a quote.
`sighash` is present only once a signature exists (null for denied/queued).

The ledger file is daemon-user-owned, mode 600. Agents read it through
GET /v1/ledger, never the file. It survives restarts — the velocity window
and queue with it (SPEC §10 step 11).
"""
import hashlib
import json
import os
import time


def canonical_row(ts: float, requester_muse: str, request_bytes: bytes,
                  sighash: str | None, decision: str) -> dict:
    digest = hashlib.sha256(request_bytes).hexdigest()
    return {
        "ts": ts,
        "requester_muse": requester_muse,
        "canon_digest": digest,
        "sighash": sighash,          # null until a signature exists (P6)
        "decision": decision,
    }


class Ledger:
    def __init__(self, path: str):
        self.path = path
        # Fail closed if the ledger is readable by anyone but the daemon user.
        st = os.stat(path) if os.path.exists(path) else None
        if st is not None and st.st_mode & 0o077:
            raise PermissionError(f"ledger {path} is not 0600 — refusing to start")

    def append(self, requester_muse: str, request_bytes: bytes,
               sighash: str | None, decision: str) -> dict:
        row = canonical_row(time.time(), requester_muse, request_bytes, sighash, decision)
        # Canonical JSON: sorted keys, no whitespace (matches vectors/ convention).
        line = json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        # Create mode 0600 at birth (os.open mode applies only on O_CREAT) so a
        # fresh ledger never starts life group/world-readable under a lax umask.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        return row

    def read_all(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            return [json.loads(line) for line in f if line.strip()]

"""Token loading + verification — SPEC §4 (S7), §1 (P5).

Two tokens from day one:
  - request token: lives in the agent's environment (agent's own OS user).
  - approve token: held ONLY by the human's own tooling (human's login user).
    The agent must not run under the human's login user; where accounts are
    shared, the approve token is never at rest — the human's tooling prompts
    per use (P5).

Both files are daemon-user-owned, mode 600. Comparison is constant-time.
"""
import hmac
import os


def load_token(path: str) -> bytes:
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise PermissionError(f"token file {path} is not 0600 — refusing to start")
    with open(path) as f:
        token_hex = f.read().strip()
    try:
        token = bytes.fromhex(token_hex)
    except ValueError:
        raise ValueError(f"token file {path} is not hex")
    if len(token) < 32:
        raise ValueError(f"token file {path} holds < 32 bytes of entropy")
    return token


def check(presented: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(presented, expected)

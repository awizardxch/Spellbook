#!/usr/bin/env python3
"""Create the daemon's two bearer tokens for an install (one-time; S7, S-05).

Writes, each 0600 and exclusive (never overwritten):

  <prefix>/request.token   the daemon's copy of the agent's token
  <prefix>/approve.token   the daemon's copy of the human's token
  <agent_token_path>       the AGENT's copy of the request token

NOTHING secret is printed: the installer used to echo the request token
into its stdout "for the agent's environment", and an agent's stdout is a
transcript. The agent reads its copy from the file (the installer chowns
it to the agent user). The approve token has no copy anywhere but the
daemon's: the human moves it to their own device out-of-band (O5).

Usage: make_tokens.py <prefix> <agent_token_path>
Prints the three file paths only.
"""
import os
import secrets
import sys


def fail(msg: str) -> None:
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(1)


def write_secret_file(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    if os.name == "posix" and os.stat(path).st_mode & 0o077:
        fail(f"{path} permissions are not 0600")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: make_tokens.py <prefix> <agent_token_path>")
    prefix, agent_path = sys.argv[1], sys.argv[2]
    req_path = os.path.join(prefix, "request.token")
    app_path = os.path.join(prefix, "approve.token")
    for p in (req_path, app_path, agent_path):
        if os.path.exists(p):
            fail(f"{p} already exists — will not overwrite")
    req = secrets.token_hex(32)
    app = secrets.token_hex(32)
    write_secret_file(req_path, req)
    write_secret_file(app_path, app)
    write_secret_file(agent_path, req)
    print("tokens written (never printed):")
    print(f"  request token (daemon copy): {req_path}")
    print(f"  approve token (daemon copy): {app_path}")
    print(f"  request token (agent copy):  {agent_path}")


if __name__ == "__main__":
    main()

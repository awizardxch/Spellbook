#!/usr/bin/env python3
"""`spellbook` — operator CLI for the Spellbook daemon.

Request-token commands (the agent's side):
  spellbook status | queue | ledger | addresses
  spellbook request-spend --chain evm-4663 --to 0x... --amount-wei N [--purpose ..]

Approve-token commands (the human's own tooling — separate device per O5):
  spellbook approve <queue_id>
  spellbook reject <queue_id>

Token resolution per subcommand:
  request side: --token-file, else $SPELLBOOK_REQUEST_TOKEN
  approve side: --token-file, else $SPELLBOOK_APPROVE_TOKEN
Socket: --socket, else $SPELLBOOK_SOCKET (default /run/spellbook/spellbook.sock)
"""
import argparse
import json
import os
import sys

from spellbook.client import AgentClient, HumanClient, SpellbookError

DEFAULT_SOCKET = "/run/spellbook/spellbook.sock"


def _token(args, env_name: str) -> str:
    if args.token_file:
        with open(args.token_file) as f:
            return f.read().strip()
    tok = os.environ.get(env_name, "").strip()
    if not tok:
        raise SystemExit(f"no token: pass --token-file or set ${env_name}")
    return tok


def _socket(args) -> str:
    return args.socket or os.environ.get("SPELLBOOK_SOCKET", DEFAULT_SOCKET)


def _muse_id(args) -> str:
    return args.muse_id or os.environ.get("SPELLBOOK_MUSE_ID", "operator")


def _show(obj):
    print(json.dumps(obj, indent=2, sort_keys=True))


def cmd_status(a, client):
    _show(client.status())


def cmd_queue(a, client):
    _show(client.queue())


def cmd_ledger(a, client):
    _show(client.ledger())


def cmd_addresses(a, client):
    _show(client.addresses())


def cmd_request_spend(a, client: AgentClient):
    if (a.amount_wei is None) == (a.amount_mojos is None):
        raise SystemExit("pass exactly one of --amount-wei / --amount-mojos")
    _show(client.request_spend(
        chain=a.chain, destination=a.to, asset=a.asset,
        amount_wei=a.amount_wei, amount_mojos=a.amount_mojos,
        purpose=a.purpose or ""))


def cmd_approve(a, client: HumanClient):
    _show(client.approve(a.queue_id))


def cmd_reject(a, client: HumanClient):
    _show(client.reject(a.queue_id))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="spellbook")
    ap.add_argument("--socket")
    ap.add_argument("--token-file")
    ap.add_argument("--muse-id")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status")
    sub.add_parser("queue")
    sub.add_parser("ledger")
    sub.add_parser("addresses")

    rs = sub.add_parser("request-spend")
    rs.add_argument("--chain", required=True)
    rs.add_argument("--to", required=True)
    rs.add_argument("--asset", default="native")
    rs.add_argument("--amount-wei", type=int, default=None)
    rs.add_argument("--amount-mojos", type=int, default=None)
    rs.add_argument("--purpose", default="")

    apv = sub.add_parser("approve")
    apv.add_argument("queue_id")
    rj = sub.add_parser("reject")
    rj.add_argument("queue_id")

    a = ap.parse_args(argv)

    try:
        if a.cmd in ("approve", "reject"):
            client: HumanClient = HumanClient(_socket(a), _token(a, "SPELLBOOK_APPROVE_TOKEN"),
                                              muse_id=_muse_id(a))
            {"approve": cmd_approve, "reject": cmd_reject}[a.cmd](a, client)
        else:
            client2: AgentClient = AgentClient(_socket(a), _token(a, "SPELLBOOK_REQUEST_TOKEN"),
                                               muse_id=_muse_id(a))
            {"status": cmd_status, "queue": cmd_queue, "ledger": cmd_ledger,
             "addresses": cmd_addresses, "request-spend": cmd_request_spend}[a.cmd](a, client2)
    except SpellbookError as e:
        raise SystemExit(f"spellbook: {e}")


if __name__ == "__main__":
    main()

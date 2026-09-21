#!/usr/bin/env python3
"""`spellbook` — operator CLI for the Spellbook daemon.

Request-token commands (the agent's side):
  spellbook status | queue | ledger | addresses
  spellbook request-spend --chain evm-4663 --to 0x... --amount-wei N [--purpose ..]
  spellbook offer-make --chain chia-testnet --offered native:1000 --requested <cat>:500
  spellbook offer-take --chain chia-testnet --offer <offer-string>
  spellbook offer-cancel --chain chia-testnet --offer-id <id> [--offer-id <id>...]
  spellbook chia-read --chain chia-testnet --op get_offers

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


def _parse_leg(spec: str) -> dict:
    """CLI leg spec: asset:amount_mojos — asset "native" or 64-hex CAT id."""
    asset, _, amount = spec.partition(":")
    if not asset or not amount.isdigit():
        raise SystemExit(f"bad leg {spec!r}: expected asset:amount_mojos")
    return {"asset": asset, "amount_mojos": int(amount)}


def cmd_offer_make(a, client: AgentClient):
    _show(client.offer_make(
        chain=a.chain,
        offered=[_parse_leg(s) for s in a.offered],
        requested=[_parse_leg(s) for s in a.requested],
        fee_mojos=a.fee_mojos or 0, purpose=a.purpose or "",
        expires_at_second=a.expires_at_second,
        receive_address=a.receive_address))


def cmd_offer_take(a, client: AgentClient):
    _show(client.offer_take(chain=a.chain, offer=a.offer,
                            fee_mojos=a.fee_mojos or 0,
                            purpose=a.purpose or ""))


def cmd_offer_cancel(a, client: AgentClient):
    _show(client.offer_cancel(chain=a.chain, offer_ids=a.offer_id,
                              fee_mojos=a.fee_mojos or 0,
                              purpose=a.purpose or ""))


def cmd_chia_read(a, client: AgentClient):
    kwargs = {}
    for spec in a.arg or []:
        k, sep, v = spec.partition("=")
        if not k or not sep:
            raise SystemExit(f"bad --arg {spec!r}: expected key=value")
        kwargs[k] = v
    _show(client.chia_read(chain=a.chain, op=a.op, **kwargs))


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

    mk = sub.add_parser("offer-make")
    mk.add_argument("--chain", required=True)
    mk.add_argument("--offered", required=True, nargs="+",
                    help="asset:amount_mojos, repeatable")
    mk.add_argument("--requested", required=True, nargs="+",
                    help="asset:amount_mojos, repeatable")
    mk.add_argument("--fee-mojos", type=int, default=0)
    mk.add_argument("--purpose", default="")
    mk.add_argument("--expires-at-second", type=int, default=None)
    mk.add_argument("--receive-address", default=None)

    tk = sub.add_parser("offer-take")
    tk.add_argument("--chain", required=True)
    tk.add_argument("--offer", required=True)
    tk.add_argument("--fee-mojos", type=int, default=0)
    tk.add_argument("--purpose", default="")

    cn = sub.add_parser("offer-cancel")
    cn.add_argument("--chain", required=True)
    cn.add_argument("--offer-id", required=True, action="append")
    cn.add_argument("--fee-mojos", type=int, default=0)
    cn.add_argument("--purpose", default="")

    cr = sub.add_parser("chia-read")
    cr.add_argument("--chain", required=True)
    cr.add_argument("--op", required=True)
    cr.add_argument("--arg", action="append",
                    help="key=value, repeatable")

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
             "addresses": cmd_addresses, "request-spend": cmd_request_spend,
             "offer-make": cmd_offer_make, "offer-take": cmd_offer_take,
             "offer-cancel": cmd_offer_cancel, "chia-read": cmd_chia_read}[a.cmd](a, client2)
    except SpellbookError as e:
        raise SystemExit(f"spellbook: {e}")


if __name__ == "__main__":
    main()

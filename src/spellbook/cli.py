#!/usr/bin/env python3
"""`spellbook` — operator CLI for the Spellbook daemon.

Request-token commands (the agent's side):
  spellbook status | queue | ledger | addresses
  spellbook request-spend --chain evm-4663 --to 0x... --amount-wei N [--purpose ..]
  spellbook offer-make --chain chia-testnet --offered native:1000 --requested <cat>:500
  spellbook offer-take --chain chia-testnet --offer <offer-string>
  spellbook offer-cancel --chain chia-testnet --offer-id <id> [--offer-id <id>...]
  spellbook chia-read --chain chia-testnet --op get_offers
  spellbook nft-mint --chain chia-testnet --did-id did:chia:1... --mint '{...}'
  spellbook did-create --chain chia-testnet --name my-did
  spellbook cat-issue --chain chia-testnet --name T --ticker T --amount-mojos N
  spellbook bulk-send --chain chia-testnet --to <addr> --amount-mojos N
  spellbook message-sign --chain chia-testnet --message <text> --address <addr>
  (plus did-transfer/normalize, option-mint/transfer/exercise, coin-combine/
  split/autocombine, clawback-finalize, multi-send, offer-import/delete/
  combine, cat-update, did-update, nft-update, nft-collection-update,
  nft-redownload, option-update)

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


def _json_arg(spec: str, what: str) -> dict:
    try:
        v = json.loads(spec)
    except json.JSONDecodeError as e:
        raise SystemExit(f"bad {what} JSON: {e}")
    if not isinstance(v, dict):
        raise SystemExit(f"bad {what}: expected a JSON object")
    return v


def cmd_nft_mint(a, client: AgentClient):
    _show(client.nft_mint(
        chain=a.chain, mints=[_json_arg(s, "--mint") for s in a.mint],
        did_id=a.did_id, fee_mojos=a.fee_mojos or 0,
        purpose=a.purpose or ""))


def cmd_nft_assign_did(a, client: AgentClient):
    _show(client.nft_assign_did(
        chain=a.chain, nft_ids=a.nft_id, did_id=a.did_id,
        fee_mojos=a.fee_mojos or 0, purpose=a.purpose or ""))


def cmd_did_create(a, client: AgentClient):
    _show(client.did_create(chain=a.chain, name=a.name,
                            fee_mojos=a.fee_mojos or 0,
                            purpose=a.purpose or ""))


def cmd_did_transfer(a, client: AgentClient):
    _show(client.did_transfer(chain=a.chain, did_ids=a.did_id,
                              destination=a.to, fee_mojos=a.fee_mojos or 0,
                              purpose=a.purpose or ""))


def cmd_did_normalize(a, client: AgentClient):
    _show(client.did_normalize(chain=a.chain, did_ids=a.did_id,
                               fee_mojos=a.fee_mojos or 0,
                               purpose=a.purpose or ""))


def _parse_option_leg(spec: str) -> dict:
    asset, _, amount = spec.partition(":")
    if not asset or not amount.isdigit():
        raise SystemExit(f"bad leg {spec!r}: expected asset:amount "
                         "(asset 'native' or 64-hex)")
    return {"asset_id": None if asset == "native" else asset,
            "amount": int(amount)}


def cmd_option_mint(a, client: AgentClient):
    _show(client.option_mint(
        chain=a.chain, expiration_seconds=a.expiration_seconds,
        underlying=_parse_option_leg(a.underlying),
        strike=_parse_option_leg(a.strike),
        fee_mojos=a.fee_mojos or 0, purpose=a.purpose or ""))


def cmd_option_transfer(a, client: AgentClient):
    _show(client.option_transfer(chain=a.chain, option_ids=a.option_id,
                                 destination=a.to,
                                 fee_mojos=a.fee_mojos or 0,
                                 purpose=a.purpose or ""))


def cmd_option_exercise(a, client: AgentClient):
    _show(client.option_exercise(chain=a.chain, option_ids=a.option_id,
                                 fee_mojos=a.fee_mojos or 0,
                                 purpose=a.purpose or ""))


def cmd_cat_issue(a, client: AgentClient):
    _show(client.cat_issue(chain=a.chain, name=a.name, ticker=a.ticker,
                           amount_mojos=a.amount_mojos,
                           revocable=a.revocable,
                           fee_mojos=a.fee_mojos or 0,
                           purpose=a.purpose or ""))


def cmd_clawback_finalize(a, client: AgentClient):
    _show(client.clawback_finalize(chain=a.chain, coin_ids=a.coin_id,
                                   fee_mojos=a.fee_mojos or 0,
                                   purpose=a.purpose or ""))


def cmd_coin_combine(a, client: AgentClient):
    _show(client.coin_combine(chain=a.chain, coin_ids=a.coin_id,
                              fee_mojos=a.fee_mojos or 0,
                              purpose=a.purpose or ""))


def cmd_coin_split(a, client: AgentClient):
    _show(client.coin_split(chain=a.chain, coin_ids=a.coin_id,
                            output_count=a.output_count,
                            fee_mojos=a.fee_mojos or 0,
                            purpose=a.purpose or ""))


def cmd_coin_autocombine(a, client: AgentClient):
    _show(client.coin_autocombine(
        chain=a.chain, max_coins=a.max_coins, asset=a.asset,
        max_coin_amount=a.max_coin_amount, fee_mojos=a.fee_mojos or 0,
        purpose=a.purpose or ""))


def cmd_bulk_send(a, client: AgentClient):
    _show(client.bulk_send(chain=a.chain, addresses=a.to,
                           amount_mojos=a.amount_mojos, asset=a.asset,
                           fee_mojos=a.fee_mojos or 0,
                           purpose=a.purpose or ""))


def cmd_multi_send(a, client: AgentClient):
    _show(client.multi_send(
        chain=a.chain,
        payments=[_json_arg(s, "--payment") for s in a.payment],
        fee_mojos=a.fee_mojos or 0, purpose=a.purpose or ""))


def cmd_message_sign(a, client: AgentClient):
    _show(client.message_sign(chain=a.chain, message=a.message,
                              address=a.address or "",
                              public_key=a.public_key or "",
                              purpose=a.purpose or ""))


def cmd_offer_import(a, client: AgentClient):
    _show(client.offer_import(chain=a.chain, offer=a.offer))


def cmd_offer_delete(a, client: AgentClient):
    _show(client.offer_delete(chain=a.chain, offer_id=a.offer_id))


def cmd_offer_combine(a, client: AgentClient):
    _show(client.offer_combine(chain=a.chain, offers=a.offer))


def cmd_cat_update(a, client: AgentClient):
    _show(client.cat_update(chain=a.chain,
                            record=_json_arg(a.record, "--record")))


def cmd_did_update(a, client: AgentClient):
    _show(client.did_update(chain=a.chain, did_id=a.did_id, name=a.name,
                            visible=not a.hidden))


def cmd_nft_update(a, client: AgentClient):
    _show(client.nft_update(chain=a.chain, nft_id=a.nft_id,
                            visible=not a.hidden))


def cmd_nft_collection_update(a, client: AgentClient):
    _show(client.nft_collection_update(chain=a.chain,
                                       collection_id=a.collection_id,
                                       visible=not a.hidden))


def cmd_nft_redownload(a, client: AgentClient):
    _show(client.nft_redownload(chain=a.chain, nft_id=a.nft_id))


def cmd_option_update(a, client: AgentClient):
    _show(client.option_update(chain=a.chain, option_id=a.option_id,
                               visible=not a.hidden))


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

    def _tx_args(p, purpose=True):
        p.add_argument("--chain", required=True)
        p.add_argument("--fee-mojos", type=int, default=0)
        if purpose:
            p.add_argument("--purpose", default="")
        return p

    nm = sub.add_parser(
        "nft-mint",
        help="queue NFT minting (execution also needs the six-gate "
             "mint/issuance authorization)")
    _tx_args(nm)
    nm.add_argument("--did-id", required=True)
    nm.add_argument("--mint", required=True, action="append",
                    help="NftMint JSON, repeatable")

    na = sub.add_parser("nft-assign-did")
    _tx_args(na)
    na.add_argument("--nft-id", required=True, action="append")
    na.add_argument("--did-id", default=None,
                    help="omit/null to unassign")

    dc = sub.add_parser("did-create")
    _tx_args(dc)
    dc.add_argument("--name", required=True)

    dt = sub.add_parser("did-transfer")
    _tx_args(dt)
    dt.add_argument("--did-id", required=True, action="append")
    dt.add_argument("--to", required=True)

    dn = sub.add_parser("did-normalize")
    _tx_args(dn)
    dn.add_argument("--did-id", required=True, action="append")

    om = sub.add_parser(
        "option-mint",
        help="queue option minting (execution also needs the six-gate "
             "mint/issuance authorization)")
    _tx_args(om)
    om.add_argument("--expiration-seconds", type=int, required=True)
    om.add_argument("--underlying", required=True,
                    help="asset:amount (asset 'native' or 64-hex)")
    om.add_argument("--strike", required=True,
                    help="asset:amount (asset 'native' or 64-hex)")

    ot = sub.add_parser("option-transfer")
    _tx_args(ot)
    ot.add_argument("--option-id", required=True, action="append")
    ot.add_argument("--to", required=True)

    oe = sub.add_parser("option-exercise")
    _tx_args(oe)
    oe.add_argument("--option-id", required=True, action="append")

    ci = sub.add_parser(
        "cat-issue",
        help="queue CAT issuance (execution also needs the six-gate "
             "mint/issuance authorization)")
    _tx_args(ci)
    ci.add_argument("--name", required=True)
    ci.add_argument("--ticker", required=True)
    ci.add_argument("--amount-mojos", type=int, required=True)
    ci.add_argument("--revocable", action="store_true")

    cf = sub.add_parser("clawback-finalize")
    _tx_args(cf)
    cf.add_argument("--coin-id", required=True, action="append")

    cc = sub.add_parser("coin-combine")
    _tx_args(cc)
    cc.add_argument("--coin-id", required=True, action="append")

    cs = sub.add_parser("coin-split")
    _tx_args(cs)
    cs.add_argument("--coin-id", required=True, action="append")
    cs.add_argument("--output-count", type=int, required=True)

    ca = sub.add_parser("coin-autocombine")
    _tx_args(ca)
    ca.add_argument("--asset", default="native")
    ca.add_argument("--max-coins", type=int, required=True)
    ca.add_argument("--max-coin-amount", type=int, default=None)

    bs = sub.add_parser("bulk-send")
    _tx_args(bs)
    bs.add_argument("--to", required=True, action="append")
    bs.add_argument("--amount-mojos", type=int, required=True)
    bs.add_argument("--asset", default="native")

    ms = sub.add_parser("multi-send")
    _tx_args(ms)
    ms.add_argument("--payment", required=True, action="append",
                    help="{asset_id,address,amount} JSON, repeatable")

    sg = sub.add_parser("message-sign")
    _tx_args(sg)
    sg.add_argument("--message", required=True)
    sg.add_argument("--address", default=None)
    sg.add_argument("--public-key", default=None)

    oi = sub.add_parser("offer-import")
    oi.add_argument("--chain", required=True)
    oi.add_argument("--offer", required=True)

    od = sub.add_parser("offer-delete")
    od.add_argument("--chain", required=True)
    od.add_argument("--offer-id", required=True)

    oc = sub.add_parser("offer-combine")
    oc.add_argument("--chain", required=True)
    oc.add_argument("--offer", required=True, action="append")

    cu = sub.add_parser("cat-update")
    cu.add_argument("--chain", required=True)
    cu.add_argument("--record", required=True, help="TokenRecord JSON")

    du = sub.add_parser("did-update")
    du.add_argument("--chain", required=True)
    du.add_argument("--did-id", required=True)
    du.add_argument("--name", default=None)
    du.add_argument("--hidden", action="store_true")

    nu = sub.add_parser("nft-update")
    nu.add_argument("--chain", required=True)
    nu.add_argument("--nft-id", required=True)
    nu.add_argument("--hidden", action="store_true")

    ncu = sub.add_parser("nft-collection-update")
    ncu.add_argument("--chain", required=True)
    ncu.add_argument("--collection-id", required=True)
    ncu.add_argument("--hidden", action="store_true")

    nr = sub.add_parser("nft-redownload")
    nr.add_argument("--chain", required=True)
    nr.add_argument("--nft-id", required=True)

    ou = sub.add_parser("option-update")
    ou.add_argument("--chain", required=True)
    ou.add_argument("--option-id", required=True)
    ou.add_argument("--hidden", action="store_true")

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
             "offer-cancel": cmd_offer_cancel, "chia-read": cmd_chia_read,
             "nft-mint": cmd_nft_mint,
             "nft-assign-did": cmd_nft_assign_did,
             "did-create": cmd_did_create, "did-transfer": cmd_did_transfer,
             "did-normalize": cmd_did_normalize,
             "option-mint": cmd_option_mint,
             "option-transfer": cmd_option_transfer,
             "option-exercise": cmd_option_exercise,
             "cat-issue": cmd_cat_issue,
             "clawback-finalize": cmd_clawback_finalize,
             "coin-combine": cmd_coin_combine, "coin-split": cmd_coin_split,
             "coin-autocombine": cmd_coin_autocombine,
             "bulk-send": cmd_bulk_send, "multi-send": cmd_multi_send,
             "message-sign": cmd_message_sign,
             "offer-import": cmd_offer_import,
             "offer-delete": cmd_offer_delete,
             "offer-combine": cmd_offer_combine,
             "cat-update": cmd_cat_update, "did-update": cmd_did_update,
             "nft-update": cmd_nft_update,
             "nft-collection-update": cmd_nft_collection_update,
             "nft-redownload": cmd_nft_redownload,
             "option-update": cmd_option_update}[a.cmd](a, client2)
    except SpellbookError as e:
        raise SystemExit(f"spellbook: {e}")


if __name__ == "__main__":
    main()

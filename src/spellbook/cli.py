#!/usr/bin/env python3
"""`spellbook` — operator CLI for the Spellbook daemon.

Request-token commands (the agent's side):
  spellbook status | queue | ledger | addresses
  spellbook doctor [--repair]            # read-only install health, self-repair
  spellbook version                      # local vs daemon version
  spellbook upgrade --check              # latest release vs local
  spellbook upgrade 0.2.0                # agent self-upgrade (signed release)
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


# ---------------------------------------------------------------- lifecycle:
# version / upgrade / doctor (SPEC §12b item 4). These are local-first: they
# never need the approve token, and version/upgrade --check work with no
# token at all. The agent runs these itself — no human in the loop.

def _optional_token(a, env_name: str):
    if a.token_file:
        with open(a.token_file) as f:
            return f.read().strip()
    return os.environ.get(env_name, "").strip() or None


def cmd_version(a, client=None):
    from spellbook import version as ver
    local = ver.local_version()
    try:
        import spellbook
        pkg = getattr(spellbook, "__version__", "unknown")
    except Exception:
        pkg = "unknown"
    daemon_v = None
    tok = _optional_token(a, "SPELLBOOK_REQUEST_TOKEN")
    if tok:
        try:
            daemon_v = AgentClient(_socket(a), tok,
                                   muse_id=_muse_id(a)).status().get("spellbook_version")
        except Exception:
            daemon_v = None
    _show({"local": local, "package": pkg, "daemon": daemon_v,
           "daemon_matches_local": bool(daemon_v) and daemon_v == local})


def _valid_tag(tag: str) -> bool:
    import re
    return bool(re.fullmatch(r"\d+\.\d+\.\d+", tag or ""))


def cmd_upgrade(a, client=None):
    from spellbook import version as ver
    from spellbook.doctor import UPGRADE_WRAPPER
    if a.check or not a.tag:
        _show(ver.upgrade_check())
        return
    tag = a.tag
    if not _valid_tag(tag):
        raise SystemExit(f"spellbook: bad tag {tag!r} — want X.Y.Z")
    if a.from_dir:
        # Human-driven dev path: no signature to verify, so the privileged
        # wrapper refuses it. Needs a root shell.
        installer = os.path.join(ver.prefix(), "lib", "install.sh")
        if os.geteuid() != 0:
            raise SystemExit(
                "spellbook: --from-dir upgrades need a root shell (no release "
                "signature to verify, so the agent self-serve path refuses it).\n"
                f"Run as root: bash {installer} --upgrade --from-dir {a.from_dir} "
                "--agent-user <agent> --human-user <human>")
        os.execvp("bash", ["bash", installer, "--upgrade", "--from-dir",
                           a.from_dir, "--agent-user", a.agent_user or "",
                           "--human-user", a.human_user or ""])
    if not os.path.isfile(UPGRADE_WRAPPER):
        raise SystemExit(
            "spellbook: no privileged upgrade wrapper installed "
            f"({UPGRADE_WRAPPER} missing) — this install predates self-serve "
            "upgrades. Ask your human to re-run install.sh once, then retry.")
    os.execvp("sudo", ["sudo", "-n", UPGRADE_WRAPPER, tag])


def cmd_doctor(a, client=None):
    from spellbook import version as ver
    from spellbook import doctor as doctor_mod
    try:
        import spellbook
        pkg_v = getattr(spellbook, "__version__", "unknown")
    except Exception as e:
        pkg_v = "unknown"
        pkg_err = str(e)
    else:
        pkg_err = ""
    report = {"local_package": pkg_v, "daemon": None, "repair": None}

    tok = _optional_token(a, "SPELLBOOK_REQUEST_TOKEN")
    if tok:
        try:
            client = AgentClient(_socket(a), tok, muse_id=_muse_id(a))
            d = client.doctor()
            report["daemon"] = d
            dv = None
            try:
                dv = client.status().get("spellbook_version")
            except Exception:
                pass
            report["daemon_version"] = dv
            report["daemon_matches_local"] = bool(dv) and dv == pkg_v
        except Exception as e:
            report["daemon"] = {"ok": False, "error": f"doctor RPC failed: {e}"}
    else:
        report["daemon"] = {"ok": False,
                            "error": "no request token — daemon-side checks skipped; "
                                     "set SPELLBOOK_REQUEST_TOKEN or pass --token-file"}

    if pkg_err:
        report["local_package_error"] = pkg_err

    if a.repair:
        plan = doctor_mod.repair_plan(
            (report["daemon"] or {}).get("checks", []))
        report["repair"] = plan
        for item in plan["self_repairable"]:
            _run_self_repair(item, report)
        # Re-check after repair so the report says what is true now.
        if tok and plan["self_repairable"]:
            try:
                d2 = AgentClient(_socket(a), tok,
                                 muse_id=_muse_id(a)).doctor()
                report["daemon_after_repair"] = d2
            except Exception as e:
                report["daemon_after_repair"] = {"error": str(e)}
    _show(report)
    ok = (report["daemon"] or {}).get("ok", False) and not pkg_err
    if a.repair:
        ok = (report.get("daemon_after_repair") or {}).get("ok", ok)
    raise SystemExit(0 if ok else 1)


def _run_self_repair(item, report):
    import subprocess
    cmd = item["command"].split()
    print(f"[spellbook-doctor] self-repair: {' '.join(cmd)} ({item['why']})")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        item["result"] = {"rc": r.returncode,
                          "tail": (r.stdout + r.stderr)[-2000:]}
    except Exception as e:
        item["result"] = {"rc": -1, "tail": str(e)}


def cmd_dex_quote(a, client=None):
    """Read-only DEX quotes across venues. No daemon, no signing, no
    broadcast — safe to run any time. Needs ZERO_EX_API_KEY and/or
    UNISWAP_API_KEY in the environment (free keys, see docs)."""
    import os
    from spellbook import dex as dexmod

    venues = (["matcha", "uniswap"] if a.venue == "both"
              else [dexmod.normalize_venue(a.venue)])
    quotes = []
    if "matcha" in venues:
        key = os.environ.get("ZERO_EX_API_KEY")
        if not key:
            raise SystemExit("spellbook: ZERO_EX_API_KEY not set "
                             "(free at dashboard.0x.org)")
        c = dexmod.ZeroExClient(key)
        if a.firm:
            if not a.taker:
                raise SystemExit("spellbook: --taker is required for "
                                 "firm 0x quotes")
            quotes.append(c.quote(a.chain, a.sell_token, a.buy_token,
                                  a.amount, a.taker,
                                  slippage_bps=a.slippage_bps))
        else:
            quotes.append(c.price(a.chain, a.sell_token, a.buy_token,
                                  a.amount, a.taker))
    if "uniswap" in venues:
        key = os.environ.get("UNISWAP_API_KEY")
        if not key:
            raise SystemExit("spellbook: UNISWAP_API_KEY not set "
                             "(free at developers.uniswap.org/dashboard)")
        c = dexmod.UniswapClient(key)
        taker = a.taker or "0x0000000000000000000000000000000000000000"
        q = c.quote(a.chain, a.sell_token, a.buy_token, a.amount, taker,
                    slippage_pct=a.slippage_bps / 100)
        if a.firm:
            if not a.taker:
                raise SystemExit("spellbook: --taker is required for "
                                 "firm Uniswap quotes")
            q = c.swap(q["raw"], a.chain, a.sell_token, a.buy_token,
                       a.amount, a.taker, slippage_pct=a.slippage_bps / 100)
        quotes.append(q)
    _show(dexmod.compare_quotes(quotes))


def cmd_request_spend(a, client: AgentClient):
    if (a.amount_wei is None) == (a.amount_mojos is None):
        raise SystemExit("pass exactly one of --amount-wei / --amount-mojos")
    _show(client.request_spend(
        chain=a.chain, destination=a.to, asset=a.asset,
        amount_wei=a.amount_wei, amount_mojos=a.amount_mojos,
        purpose=a.purpose or ""))


def cmd_dex_venues(a, client: AgentClient):
    """Show the user's recommended swap venues (read-only). The list is
    advisory — other venues trigger a warning, and the human's approval
    authorizes the venue. To change it, edit dex.recommended_venues in
    spellbook.json and restart the daemon."""
    _show(client.dex_venues())


def cmd_dex_swap(a, client: AgentClient):
    _show(client.dex_swap(
        chain=a.chain, venue=a.venue, sell_token=a.sell_token,
        buy_token=a.buy_token, sell_amount_wei=a.sell_amount_wei,
        min_buy_amount_wei=a.min_buy_amount_wei,
        max_slippage_bps=a.max_slippage_bps,
        purpose=a.purpose or "", deadline_sec=a.deadline_sec))


def cmd_dex_lp_add(a, client: AgentClient):
    _show(client.dex_lp_add(
        chain=a.chain, protocol=a.protocol, router=a.router,
        token_a=a.token_a, token_b=a.token_b,
        amount_a_wei=a.amount_a_wei, amount_b_wei=a.amount_b_wei,
        amount_a_min_wei=a.amount_a_min_wei,
        amount_b_min_wei=a.amount_b_min_wei, fee=a.fee,
        tick_lower=a.tick_lower, tick_upper=a.tick_upper,
        purpose=a.purpose or "", deadline_sec=a.deadline_sec))


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
                              sign_type=a.sign_type,
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

    # Lifecycle (SPEC §12b item 4): local-first, no approve token ever.
    sub.add_parser("version")
    up = sub.add_parser("upgrade")
    up.add_argument("tag", nargs="?",
                    help="release tag X.Y.Z to upgrade to (default: --check)")
    up.add_argument("--check", action="store_true",
                    help="compare local version against the latest release")
    up.add_argument("--from-dir", metavar="DIR",
                    help="human-driven dev upgrade from a source checkout "
                         "(no signature; the agent self-serve path refuses it)")
    up.add_argument("--agent-user", help="with --from-dir: agent OS user")
    up.add_argument("--human-user", help="with --from-dir: human OS user")
    dc = sub.add_parser("doctor")
    dc.add_argument("--repair", action="store_true",
                    help="self-repair code problems via the signed-release "
                         "upgrade path; state problems (keys/tokens/config) "
                         "fail closed with guidance")

    # DEX quotes (read-only, local-first: no daemon, no signing, no broadcast).
    dq = sub.add_parser("dex-quote")
    dq.add_argument("--venue", choices=["matcha", "0x", "uniswap", "both"],
                    default="both",
                    help="quote venue(s); \"0x\" is an alias for matcha")
    dq.add_argument("--chain", type=int, required=True,
                    help="EVM chain id (e.g. 8453 Base, 1 Ethereum)")
    dq.add_argument("--sell-token", required=True,
                    help="token to sell (contract address)")
    dq.add_argument("--buy-token", required=True,
                    help="token to buy (contract address)")
    dq.add_argument("--amount", type=int, required=True,
                    help="sell amount in base units (wei etc.)")
    dq.add_argument("--taker",
                    help="wallet address receiving the output "
                         "(required for firm 0x quotes)")
    dq.add_argument("--slippage-bps", type=int, default=50,
                    help="max slippage in bps, 1..500 (default 50 = 0.5%%)")
    dq.add_argument("--firm", action="store_true",
                    help="fetch FIRM executable quotes (short-lived calldata); "
                         "default is indicative prices only")

    dv = sub.add_parser("dex-venues",
                        help="show your recommended swap venues (read-only)")
    dv.description = (
        "Show your recommended DEX venues. The list lives in spellbook.json "
        "as dex.recommended_venues (default: matcha + uniswap). It is "
        "advisory, not a gate: a swap naming another venue is queued with "
        "a warning, and your approval authorizes the venue. To change the "
        "list, edit that file (daemon-user-owned, 0600) and restart the "
        "daemon.")

    rs = sub.add_parser("request-spend")
    rs.add_argument("--chain", required=True)
    rs.add_argument("--to", required=True)
    rs.add_argument("--asset", default="native")
    rs.add_argument("--amount-wei", type=int, default=None)
    rs.add_argument("--amount-mojos", type=int, default=None)
    rs.add_argument("--purpose", default="")

    dsw = sub.add_parser("dex-swap",
                         help="request a bounded swap (matcha/uniswap); the "
                              "daemon fetches the firm quote at execution "
                              "and only signs inside the approved bounds")
    dsw.add_argument("--chain", required=True,
                     help="daemon chain name, e.g. evm-8453")
    dsw.add_argument("--venue", required=True,
                     choices=["matcha", "0x", "uniswap"],
                     help="swap venue (\"0x\" is an alias for matcha). "
                          "Venues outside your dex.recommended_venues list "
                          "are not blocked — the queued intent carries a "
                          "warning and your approval authorizes the venue.")
    dsw.add_argument("--sell-token", required=True,
                     help="ERC-20 address, or 0xeeee...eeee for native")
    dsw.add_argument("--buy-token", required=True)
    dsw.add_argument("--sell-amount-wei", type=int, required=True)
    dsw.add_argument("--min-buy-amount-wei", type=int, required=True,
                     help="execution refuses below this")
    dsw.add_argument("--max-slippage-bps", type=int, default=50)
    dsw.add_argument("--deadline-sec", type=int, default=None)
    dsw.add_argument("--purpose", default="")

    dlp = sub.add_parser("dex-lp-add",
                         help="request a bounded LP add (v2/v3); calldata "
                              "is built daemon-side from the approved bounds")
    dlp.add_argument("--chain", required=True)
    dlp.add_argument("--protocol", required=True, choices=["v2", "v3"])
    dlp.add_argument("--router", required=True,
                     help="v2 router or v3 NonfungiblePositionManager")
    dlp.add_argument("--token-a", required=True)
    dlp.add_argument("--token-b", required=True)
    dlp.add_argument("--amount-a-wei", type=int, required=True)
    dlp.add_argument("--amount-b-wei", type=int, required=True)
    dlp.add_argument("--amount-a-min-wei", type=int, default=0)
    dlp.add_argument("--amount-b-min-wei", type=int, default=0)
    dlp.add_argument("--fee", type=int, default=None,
                     help="v3 fee tier: 100/500/3000/10000")
    dlp.add_argument("--tick-lower", type=int, default=None)
    dlp.add_argument("--tick-upper", type=int, default=None)
    dlp.add_argument("--deadline-sec", type=int, default=None)
    dlp.add_argument("--purpose", default="")

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
    sg.add_argument("--sign-type", default="plain",
                    choices=("plain", "personal", "typed_data"),
                    help="plain (Chia/Solana), personal (EIP-191) or "
                         "typed_data (EIP-712) on EVM chains; for "
                         "typed_data --message is the JSON envelope")

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
        if a.cmd in ("version", "upgrade", "doctor", "dex-quote"):
            # Lifecycle + read-only commands are local-first and never take
            # the approve token; they build their own clients as needed.
            {"version": cmd_version, "upgrade": cmd_upgrade,
             "doctor": cmd_doctor, "dex-quote": cmd_dex_quote}[a.cmd](a)
            return
        if a.cmd in ("approve", "reject"):
            client: HumanClient = HumanClient(_socket(a), _token(a, "SPELLBOOK_APPROVE_TOKEN"),
                                              muse_id=_muse_id(a))
            {"approve": cmd_approve, "reject": cmd_reject}[a.cmd](a, client)
        else:
            client2: AgentClient = AgentClient(_socket(a), _token(a, "SPELLBOOK_REQUEST_TOKEN"),
                                               muse_id=_muse_id(a))
            {"status": cmd_status, "queue": cmd_queue, "ledger": cmd_ledger,
             "addresses": cmd_addresses, "request-spend": cmd_request_spend,
             "dex-swap": cmd_dex_swap, "dex-lp-add": cmd_dex_lp_add,
             "dex-venues": cmd_dex_venues,
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

"""Agent tools — one registry that every agent framework can use.

Spellbook's agent surface is `AgentClient` (request token, Unix socket).
That serves any agent that can run Python or a shell. This module adds the
same surface as TOOLS: named, JSON-Schema-described functions. Adapters:

  - MCP (Claude Code / Desktop, Cursor, Codex CLI, Gemini CLI, VS Code,
    OpenAI Agents SDK, ...): `spellbook-mcp` (spellbook.mcp_server).
  - Function calling without MCP: `openai_tools()` / `anthropic_tools()`
    return the schemas; `call_tool(name, args)` runs one and returns JSON.
    `spellbook-mcp --list-tools --format openai|anthropic|mcp` prints them.

Security is the daemon's, unchanged (SPEC S7): these tools hold the
REQUEST token only. There is no approve, reject, reveal, seal-password or
unlock-password tool, no tool starts or serves a page (the human's
ceremony pages are hosted; review S-17/S-18), and none can be added
through `spellbook_call`
(it dispatches to AgentClient methods only, which have no approve path).
Spends come back approved / queued / denied per the HUMAN's policy.

Configuration (environment of the process running the tools):
  SPELLBOOK_SOCKET              daemon socket (default /run/spellbook/spellbook.sock)
  SPELLBOOK_REQUEST_TOKEN       request token, or
  SPELLBOOK_REQUEST_TOKEN_FILE  path to a file holding it
  SPELLBOOK_MUSE_ID             who is asking, for the ledger (default "agent")
  SPELLBOOK_CONFIG_DIR / SPELLBOOK_SEALED_PATH   seed-lock tools (sealed.py)
"""
import inspect
import json
import os

from spellbook import ceremony, sealed
from spellbook.client import AgentClient, SpellbookError

DEFAULT_SOCKET = "/run/spellbook/spellbook.sock"


class ToolError(Exception):
    """A tool-level failure whose message is safe to show the model."""


# ---------------------------------------------------------------- context

def _client() -> AgentClient:
    tok = os.environ.get("SPELLBOOK_REQUEST_TOKEN", "").strip()
    tok_file = os.environ.get("SPELLBOOK_REQUEST_TOKEN_FILE", "").strip()
    if not tok and tok_file:
        try:
            with open(tok_file) as f:
                tok = f.read().strip()
        except OSError as e:
            raise ToolError(f"cannot read SPELLBOOK_REQUEST_TOKEN_FILE: {e.strerror}")
    if not tok:
        raise ToolError("no request token: set SPELLBOOK_REQUEST_TOKEN or "
                        "SPELLBOOK_REQUEST_TOKEN_FILE for the tool process")
    return AgentClient(os.environ.get("SPELLBOOK_SOCKET", DEFAULT_SOCKET), tok,
                       muse_id=os.environ.get("SPELLBOOK_MUSE_ID", "agent"))


def _int(value, field: str) -> int:
    """Base-unit amounts: accept integers or digit strings (wei exceeds
    the 2^53 that JSON numbers survive in most agent runtimes)."""
    if isinstance(value, bool):
        raise ToolError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    raise ToolError(f"{field} must be a non-negative integer (or a string of digits)")


# A digit string, not a JSON number: wei amounts exceed 2^53, and a single
# scalar type keeps the schema valid for every function-calling dialect.
_AMOUNT = {"type": "string", "pattern": "^[0-9]+$",
           "description": "Amount in base units, as a string of digits "
                          "(wei / mojos / lamports)."}
_CHAIN = {"type": "string",
          "description": "Chain id, e.g. evm-4663, evm-8453, chia-testnet, "
                         "chia-mainnet, solana-devnet, solana-mainnet."}


# ---------------------------------------------------------------- handlers

# Review 2026-10-15 S-17/S-18: the agent never runs or serves a page the
# human types a secret into, and never holds a key that opens one. The
# seed tools only hand out the HOSTED page link (public key in the URL
# fragment) and inspect envelope headers; the daemon user opens envelopes.
_RELAY = ("Save the envelope your human sends you to a file and have the "
          "daemon user open it: `sudo -u spellbook spellbook-ceremony {cmd}`. "
          "You cannot open it yourself: you never hold the ceremony private "
          "key.")
AGENT_HINT = dict(sealed.STATE_HINT)
AGENT_HINT.update({
    "locked": "seed is SEALED and not loaded: call spellbook_seed_viewer and "
              "give your human the hosted link it returns. They type the "
              "password in their own browser and give you an encrypted "
              "envelope; relay it to the daemon user. Never ask for the "
              "password in chat.",
    "unsealed": "seed present but NOT sealed: a VM wipe now needs the paper "
                "backup. Call spellbook_seed_viewer and give your human the "
                "hosted seal link; relay the envelope they return.",
})


def _relay(kind: str) -> str:
    return _RELAY.format(cmd="restore <file> --out <new path>"
                         if kind == "restore" else "apply <file>")


def _seed_status(_args):
    st = sealed.status()
    st["hint"] = AGENT_HINT[st["state"]]
    return st


def _seed_viewer(args):
    page = args.get("page") or "seal"
    if page not in ("seal", "restore", "backup"):
        raise ToolError("page must be seal, restore or backup")
    st = sealed.status()
    out = {"state": st["state"], "page": page, "started": False}
    if page == "backup":
        out.update({
            "url": ceremony.hosted_url("backup"),
            "tell_your_human": (
                "Open this page in your own browser, press 'Make reveal key' "
                "and paste me the public key it shows. Keep the tab open: I "
                "will send back an envelope only that tab can decrypt. When "
                "the words are on paper, send me the BACKUP CONFIRMATION "
                "CODE the page shows: until then the wallet cannot move "
                "funds."),
            "then": ("run `sudo spellbook export --reveal-key <their public "
                     "key>` and paste them the envelope it prints. It is "
                     "ciphertext to you. When they send the confirmation "
                     "code, pipe it on stdin (never argv) to `sudo spellbook "
                     "backup-confirm`."),
        })
        return out
    if page == "seal" and st["state"] not in ("locked", "unsealed"):
        out.update({"url": None, "hint": AGENT_HINT[st["state"]]})
        return out
    op = "restore" if page == "restore" else \
        "unlock" if st["state"] == "locked" else "seal"
    pub = ceremony.find_public_key()
    if not pub:
        raise ToolError(
            "no ceremony public key is published (SPELLBOOK_CEREMONY_PUB, "
            "ceremony_pub_path in spellbook.json, or the installer's "
            "root-owned copy at /usr/local/share/spellbook/ceremony.pub.pem). "
            "The daemon user makes the key pair (`sudo spellbook "
            "ceremony-key`) and only the public half is published; ask your "
            "human.")
    try:
        with open(pub, "rb") as f:
            der = ceremony.public_der(f.read())
    except OSError as e:
        raise ToolError(f"cannot read the ceremony public key: {e.strerror}")
    fp = ceremony.grouped(ceremony.key_fingerprint(der))
    what = {"unlock": "enter your seal password to unlock the wallet",
            "seal": "choose a password to seal the wallet's seed",
            "restore": "type your paper words to restore the wallet"}[op]
    out.update({
        "op": op,
        "url": ceremony.hosted_url(page, pub_der=der, op=op),
        "key_fingerprint": fp,
        "tell_your_human": (
            f"Open this link in your own browser and {what}. It runs only "
            "in your browser and encrypts to your daemon's key. First compare "
            "the Spellbook daemon key fingerprint the page shows with the one "
            "your daemon printed for you (the installer log, your terminal "
            "`spellbook export` screen, or `sudo spellbook ceremony-key` in "
            "your own shell), not only the one I quote. Then paste me the "
            "envelope "
            "it makes. Never paste the password or words into this chat."),
        "then": _relay(op) + (" Then call spellbook_seed_status until it "
                              "reports 'unlocked'." if op != "restore" else ""),
    })
    return out


def _ceremony_inspect(args):
    """Public header of an envelope: what it is and which key opens it."""
    env = ceremony.parse_envelope(args["envelope"])
    return {"kind": env["kind"],
            "key_fingerprint": ceremony.grouped(env["kfp"]),
            "relay_to": _relay(env["kind"])}


def _status(_a):
    return _client().status()


def _version(_a):
    """Local version vs the latest signed release — no daemon, no token."""
    from spellbook import version as ver
    return ver.upgrade_check()


def _doctor(_a):
    return _client().doctor()


def _addresses(_a):
    return _client().addresses()


def _queue(_a):
    return _client().queue()


def _ledger(args):
    rows = _client().ledger()
    limit = int(args.get("limit") or 20)
    return rows[-limit:]


def _request_spend(a):
    chain = a["chain"]
    kind = ("amount_wei" if chain.startswith("evm-") else
            "amount_mojos" if chain.startswith("chia-") else
            "amount_lamports" if chain.startswith("solana-") else None)
    if not kind:
        raise ToolError(f"unknown chain family for {chain!r}")
    return _client().request_spend(
        chain=chain, destination=a["destination"],
        asset=a.get("asset") or "native", purpose=a.get("purpose", ""),
        **{kind: _int(a["amount"], "amount")})


def _dex_venues(_a):
    return _client().dex_venues()


def _dex_swap(a):
    return _client().dex_swap(
        chain=a["chain"], venue=a["venue"], sell_token=a["sell_token"],
        buy_token=a["buy_token"],
        sell_amount_wei=_int(a["sell_amount"], "sell_amount"),
        min_buy_amount_wei=_int(a["min_buy_amount"], "min_buy_amount"),
        max_slippage_bps=_int(a["max_slippage_bps"], "max_slippage_bps"),
        purpose=a.get("purpose", ""), deadline_sec=a.get("deadline_sec"))


def _forge_swap(a):
    return _client().forge_swap(
        chain=a["chain"], asset_in=a["asset_in"], asset_out=a["asset_out"],
        amount_in_mojos=_int(a["amount_in"], "amount_in"),
        min_amount_out_mojos=_int(a["min_amount_out"], "min_amount_out"),
        fee_mojos=_int(a["fee"], "fee"), purpose=a.get("purpose", ""))


def _forge_status(a):
    return _client().forge_status(chain=a["chain"], watch=a["watch"])


def _message_sign(a):
    return _client().message_sign(
        chain=a["chain"], message=a["message"], address=a.get("address", ""),
        public_key=a.get("public_key", ""), purpose=a.get("purpose", ""),
        sign_type=a.get("sign_type", "plain"))


def _chia_read(a):
    return _client().chia_read(chain=a["chain"], op=a["op"],
                               **(a.get("params") or {}))


def _agent_methods() -> dict:
    """Every public AgentClient method — the request-token surface."""
    return {n: m for n, m in inspect.getmembers(AgentClient, inspect.isfunction)
            if not n.startswith("_")}


def _call(a):
    method = a["method"]
    methods = _agent_methods()
    if method not in methods:
        raise ToolError(f"unknown method {method!r}; one of: "
                        + ", ".join(sorted(methods)))
    params = a.get("params") or {}
    if not isinstance(params, dict):
        raise ToolError("params must be an object of keyword arguments")
    sig = inspect.signature(methods[method])
    try:
        sig.bind(None, **params)
    except TypeError as e:
        raise ToolError(f"{method}{sig}: {e}".replace("(self, ", "("))
    for k, v in list(params.items()):
        if k.startswith("amount_") or k.endswith(("_wei", "_mojos", "_lamports")):
            params[k] = _int(v, k) if v is not None else None
    return getattr(_client(), method)(**params)


# ---------------------------------------------------------------- registry

def _tool(name, description, handler, props=None, required=(), read_only=False):
    return {
        "name": name,
        "description": description,
        "input_schema": {"type": "object", "properties": props or {},
                         "required": list(required),
                         "additionalProperties": False},
        "read_only": read_only,
        "handler": handler,
    }


TOOLS = [
    _tool("spellbook_seed_status",
          "Check the wallet's seed lock. Call at the START OF EVERY SESSION "
          "(including after context compaction). States: unlocked (ready), "
          "locked (sealed seed not loaded — get your human the seal link), "
          "unsealed (not yet sealed — get your human the seal link), "
          "mismatch, empty. Needs no password and no daemon.",
          _seed_status, read_only=True),
    _tool("spellbook_seed_viewer",
          "Link to the HOSTED ceremony page your human opens in their own "
          "browser: seal or unlock (page=seal, the default), restore from "
          "paper (restore) or see the paper backup (backup). Starts nothing "
          "locally. The link carries only the daemon's PUBLIC key; your "
          "human returns an encrypted envelope, which you relay to the "
          "daemon user. You never see, ask for, or decrypt a password or "
          "recovery word.",
          _seed_viewer,
          {"page": {"type": "string", "enum": ["seal", "restore", "backup"],
                    "description": "Which page (default seal)."}},
          read_only=True),
    _tool("spellbook_ceremony_inspect",
          "Read the public header of a ceremony envelope your human pasted "
          "(its kind and the key fingerprint that opens it) and how to relay "
          "it. Decrypts nothing.",
          _ceremony_inspect,
          {"envelope": {"type": "string",
                        "description": "The SPELLBOOK-CEREMONY1. envelope."}},
          ("envelope",), read_only=True),
    _tool("spellbook_status", "Daemon status: version, networks, gates.",
          _status, read_only=True),
    _tool("spellbook_version",
          "Installed Spellbook version vs the latest signed release. If "
          "upgrade_available, read upgrade_notes, then upgrade with the "
          "`how` command (signed releases only, forward-only, keys never "
          "touched) and follow the notes' after-upgrade steps. The root "
          "wrapper installs only a signed tag that is on main, not yanked "
          "and past the delay window; a NOT YET or REFUSED answer is "
          "final for this session, never work around it.",
          _version, read_only=True),
    _tool("spellbook_doctor",
          "Install health check (presence/permissions only, never key contents).",
          _doctor, read_only=True),
    _tool("spellbook_addresses",
          "The wallet's addresses: {label: {chain: address}}.",
          _addresses, read_only=True),
    _tool("spellbook_queue",
          "Spends waiting for the human's approval, as decoded intent. Show "
          "these to your human; only they can approve (from their own tools).",
          _queue, read_only=True),
    _tool("spellbook_ledger", "Recent decision-ledger rows (newest last).",
          _ledger, {"limit": {"type": "integer",
                              "description": "Rows to return (default 20)."}},
          read_only=True),
    _tool("spellbook_request_spend",
          "Request a plain transfer. The daemon answers approved / queued / "
          "denied under the human's policy; queued spends wait for the human. "
          "Amount is in base units of the chain (wei / mojos / lamports).",
          _request_spend,
          {"chain": _CHAIN,
           "destination": {"type": "string", "description": "Recipient address."},
           "amount": _AMOUNT,
           "asset": {"type": "string",
                     "description": "'native' (default) or a token id/contract."},
           "purpose": {"type": "string",
                       "description": "Why — shown to the human on approval."}},
          ("chain", "destination", "amount")),
    _tool("spellbook_dex_venues",
          "Swap venues: the human's recommended list and every known venue.",
          _dex_venues, read_only=True),
    _tool("spellbook_dex_swap",
          "Request a bounded token swap (exact sell amount, minimum buy, max "
          "slippage). The daemon fetches the firm quote at execution and "
          "refuses to sign outside the bounds. Use "
          "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee for the native side.",
          _dex_swap,
          {"chain": _CHAIN,
           "venue": {"type": "string", "description": "matcha (0x) or uniswap."},
           "sell_token": {"type": "string"}, "buy_token": {"type": "string"},
           "sell_amount": _AMOUNT, "min_buy_amount": _AMOUNT,
           "max_slippage_bps": {"type": "integer"},
           "deadline_sec": {"type": "integer"},
           "purpose": {"type": "string"}},
          ("chain", "venue", "sell_token", "buy_token", "sell_amount",
           "min_buy_amount", "max_slippage_bps")),
    _tool("spellbook_forge_swap",
          "Request a swap on the Forge, the Chia AMM (chia-mainnet or "
          "chia-testnet). Bounds only: sell exactly amount_in of asset_in, "
          "take at least min_amount_out of asset_out, pay fee. Assets are "
          "'native' (XCH) or a 64-hex CAT id. The daemon quotes from its own "
          "configured router and always queues for the human; on approval "
          "the wallet makes the offer and the daemon settles it once. Poll "
          "spellbook_forge_status with the returned watch; never re-request "
          "a swap whose outcome is unknown.",
          _forge_swap,
          {"chain": _CHAIN,
           "asset_in": {"type": "string",
                        "description": "'native' or a 64-hex CAT asset id."},
           "asset_out": {"type": "string",
                         "description": "'native' or a 64-hex CAT asset id."},
           "amount_in": _AMOUNT, "min_amount_out": _AMOUNT, "fee": _AMOUNT,
           "purpose": {"type": "string",
                       "description": "Why — shown to the human on approval."}},
          ("chain", "asset_in", "asset_out", "amount_in", "min_amount_out",
           "fee")),
    _tool("spellbook_forge_status",
          "Has an approved Forge swap landed? Pass the watch the swap "
          "returned. confirmed is true only once the pool coins it spent are "
          "spent on chain.",
          _forge_status,
          {"chain": _CHAIN, "watch": {"type": "object"}},
          ("chain", "watch"), read_only=True),
    _tool("spellbook_message_sign",
          "Queue signing a message (always needs human approval). sign_type: "
          "plain (Chia/Solana), personal (EIP-191) or typed_data (EIP-712 JSON).",
          _message_sign,
          {"chain": _CHAIN, "message": {"type": "string"},
           "address": {"type": "string"}, "public_key": {"type": "string"},
           "sign_type": {"type": "string",
                         "enum": ["plain", "personal", "typed_data"]},
           "purpose": {"type": "string"}},
          ("chain", "message")),
    _tool("spellbook_chia_read",
          "Read-only Chia query (daemon-allowlisted ops: get_offers, "
          "get_offer, view_offer, get_coins, get_pending_transactions, "
          "sync_status, ...).",
          _chia_read,
          {"chain": _CHAIN, "op": {"type": "string"},
           "params": {"type": "object", "description": "Extra op arguments."}},
          ("chain", "op"), read_only=True),
    _tool("spellbook_call",
          "Any other agent operation, by AgentClient method name with keyword "
          "params (e.g. offer_make, nft_mint, dex_lp_add, contract_call, "
          "cat_issue, coin_split). Same policy and human approval as every "
          "spend. See docs/AGENT_ONBOARDING.md for each method's params.",
          _call,
          {"method": {"type": "string", "enum": sorted(_agent_methods())},
           "params": {"type": "object"}},
          ("method",)),
]
_BY_NAME = {t["name"]: t for t in TOOLS}


def call_tool(name: str, args: dict | None = None) -> tuple[bool, str]:
    """Run one tool. Returns (ok, text) — text is JSON on success, a safe
    message on failure. Never raises for tool-level errors."""
    tool = _BY_NAME.get(name)
    if tool is None:
        return False, f"unknown tool {name!r}"
    args = args or {}
    missing = [r for r in tool["input_schema"]["required"] if r not in args]
    if missing:
        return False, f"missing required argument(s): {', '.join(missing)}"
    try:
        result = tool["handler"](args)
    except (ToolError, SpellbookError, sealed.SealError,
            ceremony.CeremonyError, ValueError) as e:
        return False, str(e)
    except KeyError as e:
        return False, f"missing argument {e}"
    return True, json.dumps(result, indent=1, default=str)


def mcp_tools() -> list[dict]:
    return [{"name": t["name"], "description": t["description"],
             "inputSchema": t["input_schema"],
             "annotations": {"readOnlyHint": t["read_only"],
                             "destructiveHint": False,
                             "openWorldHint": not t["read_only"]}}
            for t in TOOLS]


def openai_tools() -> list[dict]:
    """Chat Completions / Responses-style function definitions."""
    return [{"type": "function",
             "function": {"name": t["name"], "description": t["description"],
                          "parameters": t["input_schema"]}}
            for t in TOOLS]


def anthropic_tools() -> list[dict]:
    """Claude Messages API tool definitions."""
    return [{"name": t["name"], "description": t["description"],
             "input_schema": t["input_schema"]} for t in TOOLS]

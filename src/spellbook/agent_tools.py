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
unlock-password tool, and none can be added through `spellbook_call`
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
import select
import subprocess
import sys
import time

from spellbook import sealed
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

def _seed_status(_args):
    st = sealed.status()
    st["hint"] = sealed.STATE_HINT[st["state"]]
    return st


_VIEWERS: list = []  # running viewer processes, reaped on the next call


def _seed_viewer(args):
    _VIEWERS[:] = [p for p in _VIEWERS if p.poll() is None]
    st = sealed.status()
    if st["state"] not in ("locked", "unsealed"):
        return {"state": st["state"], "started": False,
                "hint": sealed.STATE_HINT[st["state"]]}
    port = args.get("port")
    port = 8787 if port is None else int(port)
    cmd = [sys.executable, "-m", "spellbook.sealed", "serve", "--port", str(port)]
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            start_new_session=True, bufsize=0)
    # serve prints exactly two lines at startup (the link, then guidance);
    # read both (raw, so select sees every byte) so the pipe never breaks
    # under it.
    buf, deadline = b"", time.monotonic() + 10
    fd = proc.stdout.fileno()
    while buf.count(b"\n") < 2 and time.monotonic() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            buf += chunk
    lines = buf.decode("utf-8", "replace").splitlines()
    url = next((w for ln in lines for w in ln.split() if w.startswith("http")), None)
    if not url:
        proc.kill()
        raise ToolError(f"seed viewer did not start (port {port} busy? a "
                        "viewer may already be running — reuse its link)")
    _VIEWERS.append(proc)
    return {
        "state": st["state"], "started": True, "url": url,
        "tell_your_human": (
            "Open this one-time link on the machine running the agent (or "
            "through an SSH tunnel to it) and "
            + ("enter your seal password to unlock the wallet."
               if st["state"] == "locked" else
               "choose a password to seal the wallet's seed.")
            + " Never paste the password into this chat."),
        "then": "call spellbook_seed_status until it reports 'unlocked'",
    }


def _status(_a):
    return _client().status()


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
          "locked (sealed seed not loaded — start the viewer for your human), "
          "unsealed (not yet sealed — start the viewer so your human can "
          "seal it), mismatch, empty. Needs no password and no daemon.",
          _seed_status, read_only=True),
    _tool("spellbook_seed_viewer",
          "Start the one-time local page where your HUMAN seals or unlocks "
          "the seed with their password. Returns a link to give them. You "
          "never see, ask for, or relay the password.",
          _seed_viewer,
          {"port": {"type": "integer", "description": "Local port (default 8787)."}}),
    _tool("spellbook_status", "Daemon status: version, networks, gates.",
          _status, read_only=True),
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
    except (ToolError, SpellbookError, sealed.SealError, ValueError) as e:
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

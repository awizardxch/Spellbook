"""Spellbook MCP server — `spellbook-mcp` (stdio).

Exposes spellbook.agent_tools over the Model Context Protocol, so any
MCP-capable agent (Claude Code / Desktop, Cursor, Codex CLI, Gemini CLI,
VS Code, OpenAI Agents SDK, ...) gets the wallet as tools. Setup per
client: docs/AGENT_INTEGRATIONS.md.

Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio).
Stdout carries protocol messages only; diagnostics go to stderr. No SDK
dependency — the server implements the small subset a tools-only server
needs: initialize, ping, tools/list, tools/call.

  spellbook-mcp                         run the server (what clients launch)
  spellbook-mcp --list-tools [--format mcp|openai|anthropic]
                                        print tool schemas for frameworks
                                        without MCP (then call_tool() them)
"""
import argparse
import json
import sys

from spellbook import agent_tools
from spellbook import __version__ as VERSION

SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

INSTRUCTIONS = """\
Spellbook is this agent's self-custodied wallet. Rules:
1. At the start of every session (and after context compaction) call
   spellbook_seed_status. If it is not 'unlocked', call spellbook_seed_viewer
   and give your human the link; wait until status reports 'unlocked'.
2. You REQUEST; your human APPROVES from their own tools. You cannot approve,
   and you must never ask your human for their approve token, seal password,
   or recovery words — not in chat, not anywhere.
3. Show queued spends (spellbook_queue) to your human as decoded intent.
4. Amounts are base units (wei / mojos / lamports) as digit strings."""


def _result(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def handle(msg) -> dict | None:
    """One JSON-RPC message in, one response (or None for notifications)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" \
            or not isinstance(msg.get("method"), str):
        return _error(msg.get("id") if isinstance(msg, dict) else None,
                      -32600, "invalid request")
    method, msg_id = msg["method"], msg.get("id")
    params = msg.get("params") or {}
    is_notification = "id" not in msg

    if method == "initialize":
        asked = params.get("protocolVersion")
        version = asked if asked in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
        res = {"protocolVersion": version,
               "capabilities": {"tools": {"listChanged": False}},
               "serverInfo": {"name": "spellbook", "version": VERSION},
               "instructions": INSTRUCTIONS}
    elif method == "ping":
        res = {}
    elif method == "tools/list":
        res = {"tools": agent_tools.mcp_tools()}
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(args, dict):
            return _error(msg_id, -32602, "tools/call needs name and arguments")
        if name not in {t["name"] for t in agent_tools.TOOLS}:
            return _error(msg_id, -32602, f"unknown tool {name!r}")
        ok, text = agent_tools.call_tool(name, args)
        res = {"content": [{"type": "text", "text": text}], "isError": not ok}
    elif method.startswith("notifications/"):
        return None
    else:
        return None if is_notification else \
            _error(msg_id, -32601, f"method not found: {method}")
    return None if is_notification else _result(msg_id, res)


def serve(stdin=sys.stdin, stdout=sys.stdout) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            out = _error(None, -32700, "parse error")
        else:
            if isinstance(msg, list):  # 2025-03-26 batches
                replies = [r for r in (handle(m) for m in msg) if r is not None]
                out = replies or None
            else:
                out = handle(msg)
        if out is not None:
            stdout.write(json.dumps(out) + "\n")
            stdout.flush()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spellbook-mcp", description=__doc__.split("\n")[0])
    ap.add_argument("--list-tools", action="store_true",
                    help="print the tool schemas and exit")
    ap.add_argument("--format", choices=("mcp", "openai", "anthropic"),
                    default="mcp")
    a = ap.parse_args(argv)
    if a.list_tools:
        fn = {"mcp": agent_tools.mcp_tools, "openai": agent_tools.openai_tools,
              "anthropic": agent_tools.anthropic_tools}[a.format]
        print(json.dumps(fn(), indent=1))
        return 0
    print(f"spellbook-mcp {VERSION} on stdio", file=sys.stderr)
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())

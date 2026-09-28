# Using Spellbook from any agent

Spellbook works with any agent that can do one of these:

| Your agent can… | Use | Examples |
|---|---|---|
| speak **MCP** (most agents today) | `spellbook-mcp`, a stdio MCP server | Claude Code, Claude Desktop, Cursor, VS Code / Copilot, OpenAI Codex CLI, Gemini CLI, OpenAI Agents SDK, Windsurf, Zed |
| do **function calling** without MCP | `openai_tools()` / `anthropic_tools()` plus `call_tool()` | a custom loop on the OpenAI or Claude API, LangChain, LlamaIndex |
| run **Python or a shell** | `AgentClient` / the `spellbook` CLI | any agent with a terminal |

Every route uses the **same** tools (`src/spellbook/agent_tools.py`) and
the same guarantees:
- The agent holds the **request token** only. There is no approve, reject,
  key-reveal or seed-password tool.
- Spends come back `approved`, `queued` or `denied` under **your human's**
  policy.
- Queued spends wait for your human to approve them from their own tools
  ([HUMAN_GUIDE.md](HUMAN_GUIDE.md)).

## Where it runs

`spellbook-mcp` talks to `spellbookd` over its Unix socket, so it runs on
**the machine where the daemon runs**:
- If the agent runs on that machine, point the agent's MCP config at
  `spellbook-mcp`.
- If the agent runs somewhere else (a desktop app, say, with the wallet on
  a VM), stdio travels over SSH. Use `ssh <vm> spellbook-mcp` as the
  command, with the same env set on the VM, for example in `~/.ssh/environment` or a
  wrapper script.

## Configuration

These environment variables are read by the tool process:

| Variable | Meaning |
|---|---|
| `SPELLBOOK_SOCKET` | daemon socket (default `/run/spellbook/spellbook.sock`) |
| `SPELLBOOK_REQUEST_TOKEN_FILE` | file holding the request token (**preferred**: it keeps the token out of config files) |
| `SPELLBOOK_REQUEST_TOKEN` | the token itself (alternative) |
| `SPELLBOOK_MUSE_ID` | name recorded in the ledger (default `agent`) |
| `SPELLBOOK_CONFIG_DIR`, `SPELLBOOK_SEALED_PATH` | seed-lock tools ([SEALED_SEED.md](SEALED_SEED.md)) |

Never give the agent the **approve** token. `install.sh` delivers that to
the human only.

## MCP clients

In each snippet below, replace `/path/to/request.token` with your token
file.

**Claude Code**
```bash
claude mcp add spellbook \
  -e SPELLBOOK_SOCKET=/run/spellbook/spellbook.sock \
  -e SPELLBOOK_REQUEST_TOKEN_FILE=/path/to/request.token \
  -- spellbook-mcp
```

**Claude Desktop** (`claude_desktop_config.json`), **Cursor**
(`.cursor/mcp.json`), **Gemini CLI** (`~/.gemini/settings.json`) and
**Windsurf** all use the same shape:
```json
{
  "mcpServers": {
    "spellbook": {
      "command": "spellbook-mcp",
      "env": {
        "SPELLBOOK_SOCKET": "/run/spellbook/spellbook.sock",
        "SPELLBOOK_REQUEST_TOKEN_FILE": "/path/to/request.token"
      }
    }
  }
}
```

**VS Code / GitHub Copilot** (`.vscode/mcp.json`)
```json
{
  "servers": {
    "spellbook": {
      "type": "stdio",
      "command": "spellbook-mcp",
      "env": { "SPELLBOOK_REQUEST_TOKEN_FILE": "/path/to/request.token" }
    }
  }
}
```

**OpenAI Codex CLI** (`~/.codex/config.toml`)
```toml
[mcp_servers.spellbook]
command = "spellbook-mcp"
env = { SPELLBOOK_REQUEST_TOKEN_FILE = "/path/to/request.token" }
```

**OpenAI Agents SDK** (Python)
```python
from agents import Agent
from agents.mcp import MCPServerStdio

async with MCPServerStdio(params={
        "command": "spellbook-mcp",
        "env": {"SPELLBOOK_REQUEST_TOKEN_FILE": "/path/to/request.token"}}) as sb:
    agent = Agent(name="wallet", mcp_servers=[sb])
```

If `spellbook-mcp` isn't on the client's `PATH`, use its full path, for
example `/opt/spellbook/venv/bin/spellbook-mcp`.

## Function calling without MCP

```python
from spellbook.agent_tools import anthropic_tools, openai_tools, call_tool

tools = anthropic_tools()          # or openai_tools() for OpenAI-style APIs
# ... pass `tools` to your model; for each tool call it makes:
ok, text = call_tool(name, arguments)   # text is JSON on success
# send `text` back as the tool result (mark it an error when not ok)
```

To dump the schemas: `spellbook-mcp --list-tools --format openai|anthropic|mcp`.

## The tools

| Tool | Does |
|---|---|
| `spellbook_seed_status` | seed lock state. **Call it first, every session** |
| `spellbook_seed_viewer` | starts the one-time password page and returns the link for the human |
| `spellbook_status`, `spellbook_doctor` | daemon status, install health |
| `spellbook_version` | installed version compared with the latest signed release, and a link to the upgrade notes |
| `spellbook_addresses`, `spellbook_queue`, `spellbook_ledger` | reads |
| `spellbook_request_spend` | plain transfer (amount as a digit string in base units) |
| `spellbook_dex_venues`, `spellbook_dex_swap` | swaps with bounds |
| `spellbook_message_sign` | message signature (always needs human approval) |
| `spellbook_chia_read` | read-only Chia queries |
| `spellbook_call` | any other `AgentClient` method (offers, NFTs, LP, contracts, CATs…) |

## Session-start rule (for any agent's system prompt)

MCP clients receive these rules automatically as server instructions.
For any other agent, paste them into its system prompt:

> At the start of every session and after context compaction, check
> `spellbook_seed_status` (or `spellbook-seed status`). If it is not
> `unlocked`, start `spellbook_seed_viewer` (or `spellbook-seed serve`),
> give your human the link, and wait until it is. You request and your
> human approves. Never ask for their approve token, seal password or
> recovery words. Once per session, check `spellbook_version` (or
> `spellbook upgrade --check`). If an upgrade is available, follow its
> upgrade notes.

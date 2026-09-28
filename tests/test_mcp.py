"""Agent tools + MCP server, end to end against a live daemon.

Drives `python -m spellbook.mcp_server` over stdio exactly as an MCP
client (Claude Code, Cursor, Codex, ...) would, with the published TEST
seed and throwaway tokens only.
"""
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

import pytest

from spellbook import agent_tools, mcp_server, sealed

TEST_SEED_HEX = ("000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f")
UID = os.getuid()


def _write(path, data):
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, 0o600)


@pytest.fixture(scope="module")
def live():
    tmp = tempfile.mkdtemp(prefix="spellbook-mcp-")
    req = secrets.token_hex(32)
    _write(os.path.join(tmp, "request.token"), req)
    _write(os.path.join(tmp, "approve.token"), secrets.token_hex(32))
    _write(os.path.join(tmp, "seed.key"), TEST_SEED_HEX)
    _write(os.path.join(tmp, "spellbook.json"), json.dumps({
        "seed_path": os.path.join(tmp, "seed.key"), "labels": ["default"],
        "allowed_request_uids": [UID], "allowed_approve_uids": [UID]}))
    _write(os.path.join(tmp, "policy.json"), json.dumps({
        "approval_threshold": {"evm-4663:native": 100}}))
    _write(os.path.join(tmp, "ledger.jsonl"), "")
    sock = os.path.join(tmp, "spellbook.sock")
    proc = subprocess.Popen([sys.executable, "-m", "spellbook.daemon",
                             "--socket", sock, "--config", tmp],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    else:
        raise RuntimeError(proc.stdout.read().decode())
    env = {**os.environ, "SPELLBOOK_SOCKET": sock,
           "SPELLBOOK_REQUEST_TOKEN_FILE": os.path.join(tmp, "request.token"),
           "SPELLBOOK_MUSE_ID": "mcp_test",
           "SPELLBOOK_CONFIG_DIR": tmp,
           "SPELLBOOK_SEALED_PATH": os.path.join(tmp, "ws", "seed.sealed")}
    env.pop("SPELLBOOK_REQUEST_TOKEN", None)
    yield {"tmp": tmp, "env": env}
    proc.terminate()
    proc.wait(timeout=5)


class Mcp:
    """A minimal MCP stdio client."""

    def __init__(self, env):
        self.p = subprocess.Popen([sys.executable, "-m", "spellbook.mcp_server"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=env, text=True)
        self.n = 0

    def send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self.n += 1
            msg["id"] = self.n
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        return None if notify else json.loads(self.p.stdout.readline())

    def tool(self, name, **args):
        r = self.send("tools/call", {"name": name, "arguments": args})["result"]
        text = r["content"][0]["text"]
        return r["isError"], (text if r["isError"] else json.loads(text))

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=5)


@pytest.fixture
def mcp(live):
    c = Mcp(live["env"])
    init = c.send("initialize", {"protocolVersion": "2025-06-18",
                                 "capabilities": {},
                                 "clientInfo": {"name": "test", "version": "0"}})
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert "spellbook_seed_status" in init["result"]["instructions"]
    c.send("notifications/initialized", notify=True)
    yield c
    c.close()


def test_tools_list_is_request_side_only(mcp):
    tools = {t["name"]: t for t in mcp.send("tools/list")["result"]["tools"]}
    assert "spellbook_request_spend" in tools and "spellbook_seed_status" in tools
    for name in tools:
        assert not any(w in name for w in ("approve", "reject", "reveal", "unlock"))
    call_methods = tools["spellbook_call"]["inputSchema"]["properties"]["method"]["enum"]
    assert "approve" not in call_methods and "reject" not in call_methods
    assert tools["spellbook_addresses"]["annotations"]["readOnlyHint"] is True


def test_reads_and_spend_through_mcp(mcp):
    err, addrs = mcp.tool("spellbook_addresses")
    assert not err and "default" in addrs
    err, st = mcp.tool("spellbook_status")
    assert not err
    # A wei amount past 2^53 travels as a digit string.
    err, big = mcp.tool("spellbook_request_spend", chain="evm-4663",
                        destination="0xabc", amount=str(10 ** 24),
                        purpose="mcp test")
    assert not err and big["decision"] in ("queued", "denied")
    err, res = mcp.tool("spellbook_request_spend", chain="evm-4663",
                        destination="0xabc", amount="500", purpose="mcp test")
    assert not err and res["decision"] == "queued"
    err, q = mcp.tool("spellbook_queue")
    assert not err and any(r.get("purpose") == "mcp test" for r in q)
    err, rows = mcp.tool("spellbook_ledger", limit=2)
    assert not err and len(rows) <= 2


def test_generic_call_and_errors(mcp):
    err, addrs = mcp.tool("spellbook_call", method="addresses")
    assert not err and "default" in addrs
    err, msg = mcp.tool("spellbook_call", method="approve",
                        params={"queue_id": "1"})
    assert err and "unknown method" in msg
    err, msg = mcp.tool("spellbook_call", method="request_spend",
                        params={"chain": "evm-4663", "destination": "0xabc",
                                "amount_wei": "1", "bogus": 1})
    assert err and "bogus" in msg
    err, msg = mcp.tool("spellbook_request_spend", chain="evm-4663",
                        destination="0xabc", amount="-5")
    assert err and "integer" in msg
    err, msg = mcp.tool("spellbook_request_spend", chain="evm-4663")
    assert err and "missing" in msg
    bad = mcp.send("tools/call", {"name": "nope", "arguments": {}})
    assert bad["error"]["code"] == -32602
    assert mcp.send("no/such")["error"]["code"] == -32601
    assert mcp.send("ping")["result"] == {}


def test_missing_token_is_a_tool_error(live):
    env = {k: v for k, v in live["env"].items()
           if not k.startswith("SPELLBOOK_REQUEST_TOKEN")}
    c = Mcp(env)
    c.send("initialize", {"protocolVersion": "1999-01-01"})
    err, msg = c.tool("spellbook_status")
    assert err and "request token" in msg
    c.close()


def test_parse_error_and_batch():
    import io
    out = io.StringIO()
    mcp_server.serve(io.StringIO('not json\n[{"jsonrpc":"2.0","id":1,"method":"ping"},'
                                 '{"jsonrpc":"2.0","method":"notifications/x"}]\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1] == [{"jsonrpc": "2.0", "id": 1, "result": {}}]


def test_seed_tools_drive_the_human_viewer(live, monkeypatch):
    for k, v in live["env"].items():
        monkeypatch.setenv(k, v)
    tmp = live["tmp"]
    ok, text = agent_tools.call_tool("spellbook_seed_status")
    assert ok and json.loads(text)["state"] == "unsealed"
    pw = "an mcp test password"
    sealed.seal(pw, n=2 ** 10)
    os.rename(os.path.join(tmp, "seed.key"), os.path.join(tmp, "seed.key.bak"))
    try:
        ok, text = agent_tools.call_tool("spellbook_seed_status")
        assert ok and json.loads(text)["state"] == "locked"
        ok, text = agent_tools.call_tool("spellbook_seed_viewer", {"port": 0})
        assert ok, text
        info = json.loads(text)
        assert info["started"] and "password" in info["tell_your_human"]
        assert pw not in text
        # The human's side: open the link, enter the password.
        data = urllib.parse.urlencode({"password": pw}).encode()
        with urllib.request.urlopen(info["url"] + "unlock", data=data) as r:
            assert "Seed unlocked" in r.read().decode()
        ok, text = agent_tools.call_tool("spellbook_seed_status")
        assert json.loads(text)["state"] == "unlocked"
    finally:
        os.replace(os.path.join(tmp, "seed.key.bak"), os.path.join(tmp, "seed.key"))


def test_schema_exports():
    names = [t["name"] for t in agent_tools.TOOLS]
    assert len(names) == len(set(names))
    oa = agent_tools.openai_tools()
    an = agent_tools.anthropic_tools()
    assert [t["function"]["name"] for t in oa] == names == [t["name"] for t in an]
    for t in an:
        assert t["input_schema"]["type"] == "object"
        json.dumps(t)


def test_version_tool_points_at_upgrade_notes(monkeypatch):
    from spellbook import version as ver
    monkeypatch.setattr(ver, "latest_release_tag", lambda: "99.0.0")
    ok, text = agent_tools.call_tool("spellbook_version")
    r = json.loads(text)
    assert ok and r["upgrade_available"] is True
    assert r["how"] == "spellbook upgrade 99.0.0"
    assert r["upgrade_notes"].endswith("/99.0.0/docs/AGENT_LIFECYCLE.md#upgrade-notes")
    monkeypatch.setattr(ver, "latest_release_tag", lambda: None)
    ok, text = agent_tools.call_tool("spellbook_version")
    assert ok and "upgrade_notes" not in json.loads(text)

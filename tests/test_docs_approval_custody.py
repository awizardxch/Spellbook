"""No doc or agent-facing text tells the agent to use the approve token (S-19).

The approve token is the human's. The documented "agent conveys the human's
chat approval via the approve-token path as the human's delegate" model put
it in the agent's hands, which undoes queue approval and the f-01 signed
refs (an injected agent can cite any "chat approval"). Approvals are made by
the human's own tooling, and signed refs are minted only with the approve
token on the human's side.
"""
import glob
import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")

FORBIDDEN = [
    r"as the human'?s delegate",
    r"delegate conveys",
    r"human delegation",
    r"conveys? (that|the|their|this) approval",
    r"chat-approved",
    r"human approves\W{0,3}in chat",
    r"approves? from (their own |your own )?chat",
    r"on the human'?s behalf",
]


def _surfaces():
    pats = ["README.md", "SPEC_V1.md", "docs/*.md", "web/AGENTS.md",
            "web/README.md", "web/app/**/*.tsx", "web/app/**/*.ts",
            "src/spellbook/mcp_server.py", "src/spellbook/agent_tools.py"]
    out = []
    for p in pats:
        out += glob.glob(os.path.join(ROOT, p), recursive=True)
    return [f for f in out if "node_modules" not in f]


def test_surfaces_exist():
    names = {os.path.relpath(f, ROOT).replace(os.sep, "/") for f in _surfaces()}
    assert "docs/AGENT_ONBOARDING.md" in names
    assert "src/spellbook/mcp_server.py" in names


def test_no_doc_tells_the_agent_to_use_the_approve_token():
    hits = []
    for f in _surfaces():
        text = open(f, encoding="utf-8").read()
        flat = re.sub(r"\s+", " ", text)          # phrases broken across lines
        for pat in FORBIDDEN:
            for m in re.finditer(pat, flat, re.IGNORECASE):
                hits.append(f"{os.path.relpath(f, ROOT)}: {m.group(0)!r}")
    assert not hits, "agent-held approval instructions:\n" + "\n".join(hits)


def test_onboarding_states_the_agent_never_holds_the_approve_token():
    text = re.sub(r"\s+", " ", open(os.path.join(ROOT, "docs", "AGENT_ONBOARDING.md"),
                                    encoding="utf-8").read())
    assert "never holds, reads or uses the approve token" in text
    assert "minted only with the approve token" in text

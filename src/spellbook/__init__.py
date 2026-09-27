"""Spellbook — per-agent self-custodied wallets.

The wallet belongs to the agent; the human approves spends through their own
tooling. The loop (SPEC_V1.md O10):

    agent surfaces intent  ->  human approves  ->  daemon executes  ->  agent reports

Public API for agents::

    from spellbook.client import AgentClient

    daemon = AgentClient("/run/spellbook/spellbook.sock", request_token_hex)
    daemon.request_spend(chain="evm-4663", destination="0x...",
                         amount_wei=1_000_000_000_000_000, purpose="tip")

Humans approve with their own tooling (separate device per O5)::

    from spellbook.client import HumanClient

    human = HumanClient("/run/spellbook/spellbook.sock", approve_token_hex)
    human.approve(queue_id)

The conversational agent can request and relay, but must never approve —
the two-token split (SPEC §4 S7) is enforced by the daemon, not by convention.
"""

__version__ = "0.2.0"  # fallback; VERSION file at repo root is canonical


def _read_version_file() -> str | None:
    try:
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        # src/spellbook/__init__.py -> repo root is two levels up
        for candidate in (
            os.path.join(here, "..", "..", "VERSION"),
            os.path.join("/opt/spellbook", "VERSION"),
        ):
            candidate = os.path.normpath(candidate)
            if os.path.isfile(candidate):
                with open(candidate) as f:
                    v = f.read().strip()
                    if v:
                        return v
    except Exception:
        pass
    return None


__version__ = _read_version_file() or __version__
del _read_version_file

from spellbook.client import AgentClient, HumanClient, SpellbookError  # noqa: F401

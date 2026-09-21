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

__version__ = "0.1.0"

from spellbook.client import AgentClient, HumanClient, SpellbookError  # noqa: F401

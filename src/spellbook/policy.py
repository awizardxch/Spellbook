"""Spellbook policy evaluation — SPEC §4, D9.

Defaults: EVERYTHING OFF. The default daemon is a signer, not a policy
engine (S4). A prompt-injected agent with the request token can empty the
hot wallet in one call under the default config — the hot wallet must hold
nothing the agent may not lose, and the installer says so out loud.

Pure logic, no I/O. Amounts are in base units (mojos / wei).
"""
from dataclasses import dataclass, field


@dataclass
class Policy:
    per_spend_cap: dict = field(default_factory=dict)        # {(chain, asset): int}
    approval_threshold: dict = field(default_factory=dict)   # {(chain, asset): int}
    auto_approve_below: dict = field(default_factory=dict)   # {(chain, asset): int}
    daily_velocity_cap: dict = field(default_factory=dict)   # {(chain, asset): int}
    destination_allowlist: dict = field(default_factory=dict)  # {(chain, asset): set[str]}


@dataclass
class Decision:
    verdict: str          # "approved" | "queued" | "denied"
    reason: str = ""


def evaluate(policy: Policy, chain: str, asset: str, amount: int,
             destination: str, spent_last_24h: int) -> Decision:
    """Decide a single plain-transfer spend request (v1 scope: no contract calls)."""
    key = (chain, asset)

    cap = policy.per_spend_cap.get(key)
    if cap is not None and amount > cap:
        return Decision("denied", f"amount {amount} exceeds per-spend cap {cap}")

    vcap = policy.daily_velocity_cap.get(key)
    if vcap is not None and spent_last_24h + amount > vcap:
        return Decision("denied", "daily velocity cap would be breached")

    allow = policy.destination_allowlist.get(key)
    auto = policy.auto_approve_below.get(key)
    threshold = policy.approval_threshold.get(key)

    if allow is not None and destination not in allow:
        # Non-allowlisted destinations above the auto-approve level are
        # denied rather than queued (SPEC §4).
        if auto is None or amount > auto:
            return Decision("denied", "destination not on allowlist")

    if threshold is not None and amount > threshold:
        return Decision("queued", f"amount {amount} exceeds approval threshold {threshold}")

    # Default-off means: nothing configured -> approved (signer behavior).
    # This is the deliberate D9 default, stated out loud.
    return Decision("approved", "default signer behavior (no policy configured)")

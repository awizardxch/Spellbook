"""Spellbook policy evaluation — SPEC §4, D9 + S4.

Defaults: EVERYTHING OFF (D9) — with the town-adopted S4 exception: **all
spends queue for human approval until the human configures policy.** A
prompt-injected agent with the request token could otherwise empty the hot
wallet in one call. The queue is a *delay*, not a cap: no amounts are
forbidden by default; the first spends are simply not instant. The human
lifts the queue by configuring policy (e.g. auto_approve_below).

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

    # The human lifts the S4 queue by configuring policy: amounts at or
    # below auto_approve_below are approved without human intervention.
    if auto is not None and amount <= auto:
        return Decision("approved",
                        f"amount {amount} at/below auto-approve level {auto}")

    if threshold is not None and amount > threshold:
        return Decision("queued", f"amount {amount} exceeds approval threshold {threshold}")

    # S4 (town-adopted, thread 37143): nothing configured -> queued, never
    # auto-approved. The queue is a delay, not a cap (D9 clarifier) — no
    # amounts are forbidden by default; spends simply aren't instant until
    # the human configures policy (e.g. auto_approve_below).
    return Decision("queued",
                    "no policy configured — human approval required (S4)")

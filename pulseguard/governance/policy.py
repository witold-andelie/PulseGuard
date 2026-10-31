"""Tiered approval policy (framework 5 Sprint 2).

P2/P3 + verified → automatic approval (actor ``policy:auto``).
P0/P1 → human.
Bus stale/stalled → advise-only (no automatic approval; the case waits for a human).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from pulseguard.contracts.models import BusHealth, PolicyTier, Priority

P0_P1 = frozenset({Priority.P0, Priority.P1, "P0", "P1"})
P2_P3 = frozenset({Priority.P2, Priority.P3, "P2", "P3"})
DEGRADED = frozenset({BusHealth.STALE, BusHealth.STALLED, "stale", "stalled"})


@dataclass(frozen=True)
class PolicyDecision:
    tier: str
    reason: str
    actor: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def decide(
    priority: str | Priority | None, *, verified: bool, bus_health: str = BusHealth.FRESH,
) -> PolicyDecision:
    """Return the policy tier for one case. Never raises; degrade instead of fail."""
    health = str(bus_health)
    if health in DEGRADED:
        return PolicyDecision(
            tier=PolicyTier.ADVISE_ONLY,
            reason=f"bus {health}: no automatic approval; case waits for a human",
            actor=None,
        )
    pri = str(priority or "")
    if pri in P0_P1:
        return PolicyDecision(
            tier=PolicyTier.HUMAN,
            reason=f"priority {pri} requires a human",
            actor=None,
        )
    if pri in P2_P3 and verified:
        return PolicyDecision(
            tier=PolicyTier.AUTO,
            reason=f"priority {pri} and verified: automatic approval",
            actor="policy:auto",
        )
    if pri in P2_P3:
        return PolicyDecision(
            tier=PolicyTier.HUMAN,
            reason=f"priority {pri} is not verified for automatic approval",
            actor=None,
        )
    return PolicyDecision(
        tier=PolicyTier.HUMAN,
        reason="unscored case requires a human",
        actor=None,
    )

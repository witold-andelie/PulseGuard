"""Approving: decision semantics from revio ``src/revio/cli/fix.py``.

Tiered policy lives in ``pulseguard.governance.policy`` (P2/P3 + verified → auto;
P0/P1 → human; stale bus → advise-only). This module records the decision and the
policy tier on the approval row.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

Decision = Literal["approve", "reject"]
DECISIONS: tuple[str, ...] = ("approve", "reject")
POLICY_TIER = "human"


class ApprovalError(ValueError):
    pass


@dataclass(frozen=True)
class ApprovalRequest:
    case_id: str
    patch_attempt: int
    sandbox_passed: bool
    policy_tier: str = POLICY_TIER
    reason: str = "human approval required"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Approval:
    case_id: str
    decision: Decision
    actor: str
    policy_tier: str = POLICY_TIER
    simulated: bool = False
    comment: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def approved(self) -> bool:
        return self.decision == "approve"


def requires_human(patchset: Any = None, *, sandbox_passed: bool = True,
                   policy_tier: str = POLICY_TIER) -> bool:
    """True unless the policy tier is automatic approval."""
    return policy_tier != "auto"


def can_request_approval(sandbox_passed: bool) -> bool:
    """Only sandbox-passed patches reach the approval card."""
    return bool(sandbox_passed)


def make_request(
    case_id: str, attempt: int, sandbox_passed: bool, *,
    policy_tier: str = POLICY_TIER, reason: str = "human approval required",
) -> ApprovalRequest:
    if not can_request_approval(sandbox_passed):
        raise ApprovalError("patch has not passed the sandbox gate")
    return ApprovalRequest(
        case_id=case_id, patch_attempt=attempt, sandbox_passed=True,
        policy_tier=policy_tier, reason=reason,
    )


def record_decision(
    case_id: str, decision: str, actor: str, *, mode: str = "live", comment: str = "",
    policy_tier: str = POLICY_TIER,
) -> Approval:
    """Validate and build an :class:`Approval`. In REPLAY mode the decision is simulated."""
    if decision not in DECISIONS:
        raise ApprovalError(f"decision must be one of {DECISIONS}, got {decision!r}")
    if not actor or not actor.strip():
        raise ApprovalError("actor is required")
    return Approval(
        case_id=case_id,
        decision=decision,  # type: ignore[arg-type]
        actor=actor.strip()[:80],
        policy_tier=policy_tier,
        simulated=mode.lower() == "replay",
        comment=comment[:500],
    )

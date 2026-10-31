"""Pydantic mirrors of the JSON Schema contracts in ``contracts/``.

Adapted from revio ``src/revio/output/models.py`` (Finding / Evidence / Severity), with
``case_id``, ``state``, ``trace`` and ``evidence_ids`` added (framework section 7.1).
The JSON Schema files stay authoritative; ``tests/test_contracts.py`` checks that model dumps
validate against them.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FindingState(StrEnum):
    RAW = "raw"
    NORMALIZED = "normalized"
    QUARANTINED = "quarantined"
    CONFIRMED = "confirmed"
    UNCERTAIN = "uncertain"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ESCALATED = "escalated"  # [S2] - present in the enum, not produced in S1


Severity = Literal["info", "low", "medium", "high", "critical"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TraceStep(_Strict):
    kind: Literal["source", "intermediate", "sink"]
    line: int = Field(ge=0)
    content: str


class Finding(_Strict):
    case_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{16,64}$")
    rule_id: str = Field(min_length=1)
    scanner: Literal["semgrep", "trivy", "bandit"] | None = None
    severity: Severity | None = None
    message: str | None = None
    file: str = Field(min_length=1)
    line: int = Field(ge=0)
    state: FindingState = FindingState.RAW
    evidence_ids: list[str] = Field(default_factory=list)
    trace: list[TraceStep] = Field(default_factory=list)
    cve_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class EvidenceItem(_Strict):
    """One line of the Hard Evidence Block (framework 4.2). ``evidence_id`` is E1, E2, ..."""

    evidence_id: str = Field(pattern=r"^E[0-9]+$")
    kind: Literal["rule_source", "dataflow", "sanitizer", "exposure", "poc", "constraint"]
    text: str
    payload: dict[str, Any] = Field(default_factory=dict)


Band = Literal["confirmed", "uncertain", "false_positive", "abstained"]
Role = Literal["adjudicator", "skeptic", "verifier", "counterfactual"]


class Verdict(_Strict):
    # Decision fields first (framework 4.3).
    is_exploitable: bool
    score: float = Field(ge=0.0, le=1.0)
    band: Band
    cited_evidence: list[str] = Field(default_factory=list)
    step1_dataflow: str = ""
    step2_constraint: str = ""
    step3_context: str = ""
    step4_verdict: str = ""
    role: Role = "adjudicator"
    model: str = "unknown"
    case_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class PatchOpModel(_Strict):
    path: str = Field(min_length=1)
    old: str = Field(min_length=1)
    new: str


PatchState = Literal[
    "proposed", "sandbox_failed", "sandbox_passed", "approved", "applied", "rolled_back"
]


class PatchSetModel(_Strict):
    case_id: str | None = None
    ops: list[PatchOpModel] = Field(min_length=1)
    rationale: str = Field(min_length=1)
    attempt: int = Field(ge=1, le=3)
    state: PatchState | None = None

    def to_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class Event(_Strict):
    seq: int = Field(ge=0)
    case_id: str = Field(min_length=1)
    activity: str
    ts: str
    resource: str = Field(min_length=1)
    attributes: dict[str, Any] = Field(default_factory=dict)

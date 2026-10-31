"""LangGraph state for one security case.

Adapted from revio ``src/revio/agent/state.py`` (``AgentState`` TypedDict with reducers),
renamed ``SecOpsState``.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict

RunMode = Literal["replay", "live"]


class SecOpsState(TypedDict, total=False):
    """State flowing through guard -> evidence -> adjudicate -> ... -> bundle.

    Payload-valued keys hold contract-shaped dicts (``finding.schema.json`` etc.) so that the
    state can be checkpointed by ``AsyncSqliteSaver`` without custom serialisers.
    """

    run_id: str
    mode: RunMode
    case_id: str
    target_root: str
    output_dir: str
    review_status: str               # human_review | awaiting_approval | dropped | closed
    review_reason: str

    finding: dict[str, Any]          # Finding payload (state updated in place by nodes)
    code: str                        # code excerpt shown to the model (guard-stripped)
    trace: list[dict[str, Any]]      # dataflow trace steps (finding.schema.json "trace")

    guard_flags: list[str]           # guard pattern names that matched
    evidence: list[dict[str, Any]]   # EvidenceItem dumps (E1..E3)
    evidence_block: str              # rendered Hard Evidence Block
    analysis_limits: list[dict[str, Any]]  # L-ids, never citable evidence

    verdict: dict[str, Any]          # Verdict payload (adjudicator)
    band: str                        # confirmed | uncertain | false_positive | abstained
    verdict_metadata: dict[str, Any]
    skeptic: dict[str, Any]
    verification: dict[str, Any]
    counterfactual: dict[str, Any]
    counterfactual_verdict: dict[str, Any]
    poc: dict[str, Any]               # bounded demo-only before/after PoC witness [S3]
    blast_radius: dict[str, Any]
    priority: str                    # P0..P3
    policy: dict[str, Any]
    bus_health: str                  # fresh | stale | stalled
    topology_extraction: dict[str, Any]  # run-level proposal/validation, never image bytes
    z3_veto: str                     # not_applicable | passed | applied
    verified: bool
    fix_snapshots: list[dict[str, str]]
    rolled_back: bool
    patch_rejected: bool

    patchset: dict[str, Any]         # PatchSet payload (latest attempt)
    attempt: int                     # remediation attempt counter, max 3
    sandbox_report: dict[str, Any]
    sandbox_feedback: str            # fed back to the Remediator on sandbox failure
    patch_error: str
    patch_metadata: dict[str, Any]
    model_calls: Annotated[list[dict[str, Any]], operator.add]

    approval: dict[str, Any]         # Approval decision payload
    bundle: dict[str, Any]           # Remediation Bundle (patch + PR description)

    # Append-only process events (activity names from framework 10.1).
    events: Annotated[list[dict[str, Any]], operator.add]

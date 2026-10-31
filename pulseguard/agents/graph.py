"""S1 case graph adapted from revio ``src/revio/agent/graph.py``.

Guard -> evidence -> adjudication -> bounded remediation/sandbox -> manual interrupt -> bundle.
Nonconfirmed or quarantined findings stop for review; false positives are retained and dropped.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from pulseguard import guard as guard_mod
from pulseguard.agents.adjudicator import adjudicate as model_adjudicate
from pulseguard.agents.adjudicator import uncertain_verdict
from pulseguard.agents.bands import BAND_ACTIVITY, DEFAULT_BANDS, Bands
from pulseguard.agents.llm import LLMClient
from pulseguard.agents.remediator import propose_patch, validate_patch_scope
from pulseguard.agents.state import SecOpsState
from pulseguard.contracts.models import Finding
from pulseguard.contracts.validate import assert_payload
from pulseguard.evidence import build_hard_evidence, render_block
from pulseguard.governance.approval import make_request, record_decision
from pulseguard.patching.patch import (
    PatchApplier,
    PatchSet,
    build_bundle,
    unified_diff,
    write_bundle,
)
from pulseguard.patching.sandbox import SandboxVerifier, Scanner
from pulseguard.scanners.semgrep import DataflowTrace, TraceLine

MAX_ATTEMPTS = 3
NodeFn = Callable[[SecOpsState], dict[str, Any]]


def _ev(state: SecOpsState, activity: str, resource: str, **attrs: Any) -> dict[str, Any]:
    return {
        "case_id": state.get("case_id") or state["finding"]["case_id"],
        "activity": activity, "ts": datetime.now(UTC).isoformat(),
        "resource": resource, "attributes": attrs,
    }


@dataclass
class GraphDeps:
    """Optional node overrides; default behaviour uses the real model and sandbox adapters."""

    adjudicate: NodeFn | None = None
    remediate: NodeFn | None = None
    sandbox: NodeFn | None = None
    bands: Bands = field(default_factory=lambda: DEFAULT_BANDS)
    target_root: Path | None = None
    output_dir: Path | None = None
    llm: LLMClient | None = None
    scanner: Scanner | None = None
    mode: str = "live"


def _trace_from_steps(steps: list[dict[str, Any]]) -> DataflowTrace:
    trace = DataflowTrace()
    for step in steps:
        line = TraceLine(int(step["line"]), str(step["content"]))
        if step["kind"] == "source":
            trace.source = line
        elif step["kind"] == "sink":
            trace.sink = line
        else:
            trace.intermediates.append(line)
    return trace


def build_graph(deps: GraphDeps | None = None) -> StateGraph:
    """Return an uncompiled graph; the runner supplies durable SQLite checkpoints."""
    deps = deps or GraphDeps()

    def target_root(state: SecOpsState) -> Path:
        root = state.get("target_root") or deps.target_root
        if root is None:
            raise ValueError("LIVE sandbox and bundle require target_root")
        return Path(root)

    def guard(state: SecOpsState) -> dict[str, Any]:
        finding = dict(state["finding"])
        assert_payload("finding", finding)
        text = "\n".join([json.dumps(finding), state.get("code", "")])
        result = guard_mod.screen(text)
        events = [_ev(state, "FINDING_INGESTED", "guard", rule_id=finding["rule_id"])]
        update: dict[str, Any] = {"case_id": finding["case_id"], "guard_flags": result.patterns}
        if result.flagged:
            finding["state"] = "quarantined"
            update.update(code=guard_mod.strip_flagged_lines(state.get("code", "")),
                          review_status="human_review", review_reason="suspected manipulation")
            events.append(_ev(state, "FINDING_QUARANTINED", "guard",
                              patterns=result.patterns, note="suspected manipulation"))
        else:
            finding["state"] = "normalized"
        update.update(finding=finding, events=events)
        return update

    def evidence(state: SecOpsState) -> dict[str, Any]:
        finding = Finding.model_validate(state["finding"])
        steps = state.get("trace") or [s.model_dump() for s in finding.trace]
        items = build_hard_evidence(finding, _trace_from_steps(steps))
        ids = [item.evidence_id for item in items]
        return {
            "finding": dict(state["finding"], evidence_ids=ids),
            "evidence": [item.model_dump() for item in items],
            "evidence_block": render_block(
                items, state.get("code") or None,
                sink_line=next((s["line"] for s in steps if s["kind"] == "sink"), finding.line),
            ),
            "events": [_ev(state, "EVIDENCE_BUILT", "evidence", evidence_ids=ids)],
        }

    def adjudicate(state: SecOpsState) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        try:
            if deps.adjudicate:
                verdict = dict(deps.adjudicate(state))
            else:
                verdict = model_adjudicate(
                    Finding.model_validate(state["finding"]), state["evidence_block"],
                    llm=deps.llm, metadata=metadata,
                ).to_payload()
            verdict["band"] = deps.bands.band_for(verdict["score"])
            assert_payload("verdict", verdict)
        except Exception:
            verdict = uncertain_verdict("unknown", state["case_id"],
                                        "Unusable model result; human review.").to_payload()
        band = verdict["band"]
        return {
            "verdict": verdict, "verdict_metadata": metadata, "band": band,
            "model_calls": [{"role": "adjudicator", **metadata}] if metadata else [],
            "finding": dict(state["finding"], state=band),
            "review_status": {"confirmed": "remediating", "uncertain": "human_review",
                              "false_positive": "dropped"}[band],
            "review_reason": "adjudication requires human review" if band == "uncertain" else "",
            "events": [_ev(state, BAND_ACTIVITY[band], "adjudicator", score=verdict["score"],
                           cited_evidence=verdict.get("cited_evidence", []))],
        }

    def remediate(state: SecOpsState) -> dict[str, Any]:
        attempt = state.get("attempt", 0) + 1
        metadata: dict[str, Any] = {}
        try:
            finding = Finding.model_validate(state["finding"])
            if deps.remediate:
                patch = dict(deps.remediate({**state, "attempt": attempt}))
                patch.update(attempt=attempt, state="proposed", case_id=state["case_id"])
                assert_payload("patchset", patch)
                validate_patch_scope(PatchSet.from_payload(patch), finding)
            else:
                patch = propose_patch(
                    finding, state["evidence_block"], attempt=attempt,
                    sandbox_feedback=state.get("sandbox_feedback"), llm=deps.llm, metadata=metadata,
                ).to_payload()
            return {"attempt": attempt, "patchset": patch, "patch_error": "",
                    "patch_metadata": metadata,
                    "model_calls": [{"role": "remediator", "attempt": attempt, **metadata}]
                    if metadata else [],
                    "events": [_ev(state, "PATCH_PROPOSED", "remediator", attempt=attempt)]}
        except Exception as exc:
            # Invalid or out-of-scope proposals consume the same bounded retry budget.
            return {"attempt": attempt, "patch_error": type(exc).__name__,
                    "patch_metadata": metadata, "patchset": {},
                    "model_calls": [{"role": "remediator", "attempt": attempt, **metadata}]
                    if metadata else [],
                    "events": [_ev(state, "PATCH_PROPOSED", "remediator", attempt=attempt,
                                   rejected=True, reason=type(exc).__name__)]}

    def sandbox(state: SecOpsState) -> dict[str, Any]:
        try:
            if state.get("patch_error"):
                report = {"passed": False, "errors": [state["patch_error"]],
                          "feedback": "Patch rejected: invalid JSON, contract or trace scope."}
            elif deps.sandbox:
                report = dict(deps.sandbox(state))
            else:
                report = SandboxVerifier(
                    target_root(state), state["finding"]["rule_id"], runner=deps.scanner,
                ).verify(PatchSet.from_payload(state["patchset"])).to_dict()
        except Exception as exc:
            report = {"passed": False, "errors": [type(exc).__name__]}
        passed = report.get("passed") is True
        patch = (dict(state["patchset"], state="sandbox_passed" if passed else "sandbox_failed")
                 if state.get("patchset") else {})
        exhausted = not passed and state["attempt"] >= MAX_ATTEMPTS
        return {
            "sandbox_report": report, "patchset": patch,
            "sandbox_feedback": "" if passed else json.dumps(report),
            "review_status": "human_review" if exhausted else "remediating",
            "review_reason": "sandbox failed after 3 attempts" if exhausted else "",
            "events": [_ev(state, "SANDBOX_PASSED" if passed else "SANDBOX_FAILED", "sandbox",
                           attempt=state["attempt"], human_review=exhausted)],
        }

    def request_approval(state: SecOpsState) -> dict[str, Any]:
        make_request(state["case_id"], state["attempt"],
                     sandbox_passed=state["sandbox_report"].get("passed") is True)
        return {"review_status": "awaiting_approval", "events": [
            _ev(state, "APPROVAL_REQUESTED", "governance", policy_tier="manual")]}

    def approve(state: SecOpsState) -> dict[str, Any]:
        request = make_request(state["case_id"], state["attempt"],
                               sandbox_passed=state["sandbox_report"].get("passed") is True)
        answer = interrupt(request.to_dict())
        approval = record_decision(
            state["case_id"], answer["decision"], answer["actor"],
            mode=deps.mode, comment=answer.get("comment", ""),
        )
        patch = dict(state["patchset"])
        if approval.approved:
            patch["state"] = "approved"
        events = [_ev(state, "APPROVED" if approval.approved else "REJECTED", approval.actor,
                      simulated=approval.simulated)]
        if not approval.approved:
            events.append(_ev(state, "CASE_CLOSED", "governance", outcome="rejected"))
        return {"approval": approval.to_dict(), "patchset": patch, "events": events,
                "review_status": "approved" if approval.approved else "closed"}

    def bundle(state: SecOpsState) -> dict[str, Any]:
        patchset = PatchSet.from_payload(state["patchset"])
        live = deps.mode.lower() == "live"
        if live:
            output = state.get("output_dir") or deps.output_dir or (
                Path(tempfile.gettempdir()) / "pulseguard-bundles" / state["case_id"])
            result = write_bundle(
                target_root=target_root(state), output_dir=Path(output), patchset=patchset,
                finding=state["finding"], verdict=state.get("verdict"),
                sandbox_report=state["sandbox_report"], approval=state["approval"],
            )
        else:
            diff = unified_diff(PatchApplier(target_root(state)).plan(patchset))
            result = build_bundle(
                case_id=state["case_id"], finding=state["finding"], patchset=patchset,
                diff=diff, verdict=state.get("verdict"), sandbox_report=state["sandbox_report"],
                approval=state["approval"], mode="replay",
            )
        return {
            "bundle": result,
            "patchset": dict(state["patchset"], state="applied" if live else "approved"),
            "finding": dict(state["finding"], state="remediated" if live else "confirmed"),
            "review_status": "closed",
            "events": [_ev(state, "PATCH_APPLIED", "bundler", target="remediation bundle"),
                       _ev(state, "CASE_CLOSED", "bundler", outcome="remediated")] if live else [],
        }

    def after_sandbox(state: SecOpsState) -> str:
        if state["sandbox_report"].get("passed") is True:
            return "request_approval"
        return "remediate" if state["attempt"] < MAX_ATTEMPTS else END

    graph = StateGraph(SecOpsState)
    for name, fn in [("guard", guard), ("evidence", evidence), ("adjudicate", adjudicate),
                     ("remediate", remediate), ("sandbox", sandbox),
                     ("request_approval", request_approval), ("approve", approve),
                     ("bundle", bundle)]:
        graph.add_node(name, fn)
    graph.add_edge(START, "guard")
    graph.add_conditional_edges("guard", lambda s: END if s["finding"]["state"] == "quarantined"
                                else "evidence", ["evidence", END])
    graph.add_edge("evidence", "adjudicate")
    graph.add_conditional_edges("adjudicate", lambda s: "remediate" if s["band"] == "confirmed"
                                else END, ["remediate", END])
    graph.add_edge("remediate", "sandbox")
    graph.add_conditional_edges("sandbox", after_sandbox, ["request_approval", "remediate", END])
    graph.add_edge("request_approval", "approve")
    graph.add_conditional_edges("approve", lambda s: (
        "bundle" if s["approval"]["decision"] == "approve" else END), ["bundle", END])
    graph.add_edge("bundle", END)
    return graph

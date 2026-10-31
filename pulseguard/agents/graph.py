"""LangGraph ``StateGraph`` for one security case.

Skeleton adapted from revio ``src/revio/agent/graph.py`` (plan -> react -> reflect), with the
nodes replaced by the SD1 subprocesses::

    guard ─┬─(quarantined)──────────────────────────────────────────────► END (human review)
           └─► evidence ─► adjudicate ─┬─(confirmed)─► remediate ─► sandbox ─┬─(passed)─► approve
                                       ├─(uncertain)──► END (human review)
                                       └─(false_positive)► END (dropped)     └─(failed, =3)─► END
    approve (LangGraph interrupt; S1: manual for every patch) ─┬─(approve)─► bundle ─► END
                                                               └─(reject)──► END

The neural steps (adjudicate, remediate) and the sandbox are injected through
:class:`GraphDeps`; the default LIVE deps raise ``NotImplementedError`` in S1.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from pulseguard import guard as guard_mod
from pulseguard.agents.bands import BAND_ACTIVITY, DEFAULT_BANDS, Bands
from pulseguard.agents.state import SecOpsState
from pulseguard.contracts.models import Finding
from pulseguard.contracts.validate import assert_payload
from pulseguard.evidence import build_hard_evidence, render_block
from pulseguard.governance.approval import make_request, record_decision
from pulseguard.patching.patch import PatchApplier, PatchSet, build_bundle, unified_diff
from pulseguard.scanners.semgrep import DataflowTrace, TraceLine

MAX_ATTEMPTS = 3

NodeFn = Callable[[SecOpsState], dict[str, Any]]


def _ev(state: SecOpsState, activity: str, resource: str, **attrs: Any) -> dict[str, Any]:
    """Process event in the ``event.schema.json`` shape (``seq`` is assigned by the store)."""
    return {
        "case_id": state.get("case_id") or state["finding"]["case_id"],
        "activity": activity,
        "ts": datetime.now(UTC).isoformat(),
        "resource": resource,
        "attributes": attrs,
    }


def _live_adjudicate(state: SecOpsState) -> dict[str, Any]:
    from pulseguard.agents.adjudicator import adjudicate

    verdict = adjudicate(Finding.model_validate(state["finding"]), state["evidence_block"])
    return verdict.to_payload()


def _live_remediate(state: SecOpsState) -> dict[str, Any]:
    from pulseguard.agents.remediator import propose_patch

    return propose_patch(
        Finding.model_validate(state["finding"]), state["evidence_block"],
        attempt=state.get("attempt", 1), sandbox_feedback=state.get("sandbox_feedback"),
    ).to_payload()


def _live_sandbox(state: SecOpsState) -> dict[str, Any]:
    raise NotImplementedError(
        "LIVE sandbox wiring is a Sprint 1 stub; see pulseguard.patching.sandbox.SandboxVerifier"
    )


@dataclass
class GraphDeps:
    """Injected behaviour. Each callable receives the current state and returns a payload."""

    adjudicate: NodeFn = _live_adjudicate     # -> Verdict payload
    remediate: NodeFn = _live_remediate       # -> PatchSet payload
    sandbox: NodeFn = _live_sandbox           # -> {"passed": bool, ...}
    bands: Bands = field(default_factory=lambda: DEFAULT_BANDS)
    target_root: Path | None = None           # where PatchSet paths resolve for the bundle
    mode: str = "live"


def _trace_from_steps(steps: list[dict[str, Any]]) -> DataflowTrace:
    trace = DataflowTrace()
    for s in steps:
        tl = TraceLine(int(s["line"]), str(s["content"]))
        if s["kind"] == "source":
            trace.source = tl
        elif s["kind"] == "sink":
            trace.sink = tl
        else:
            trace.intermediates.append(tl)
    return trace


def build_graph(deps: GraphDeps | None = None) -> StateGraph:
    """Return the (uncompiled) graph. Compile with a checkpointer: ``approve`` interrupts."""
    deps = deps or GraphDeps()

    def guard(state: SecOpsState) -> dict[str, Any]:
        finding = dict(state["finding"])
        assert_payload("finding", finding)
        text = "\n".join([json.dumps(finding), state.get("code", "")])
        result = guard_mod.screen(text)
        events = [_ev(state, "FINDING_INGESTED", "guard", rule_id=finding["rule_id"])]
        update: dict[str, Any] = {"case_id": finding["case_id"], "guard_flags": result.patterns}
        if result.flagged:
            finding["state"] = "quarantined"
            update["code"] = guard_mod.strip_flagged_lines(state.get("code", ""))
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
        ids = [i.evidence_id for i in items]
        f = dict(state["finding"], evidence_ids=ids)
        return {
            "finding": f,
            "evidence": [i.model_dump() for i in items],
            "evidence_block": render_block(items, state.get("code") or None),
            "events": [_ev(state, "EVIDENCE_BUILT", "evidence", evidence_ids=ids)],
        }

    def adjudicate(state: SecOpsState) -> dict[str, Any]:
        verdict = dict(deps.adjudicate(state))
        band = deps.bands.band_for(float(verdict["score"]))
        verdict["band"] = band
        assert_payload("verdict", verdict)
        return {
            "verdict": verdict,
            "band": band,
            "finding": dict(state["finding"], state=band),
            "events": [_ev(state, BAND_ACTIVITY[band], "adjudicator", score=verdict["score"],
                           cited_evidence=verdict.get("cited_evidence", []))],
        }

    def remediate(state: SecOpsState) -> dict[str, Any]:
        attempt = state.get("attempt", 0) + 1
        patch = dict(deps.remediate({**state, "attempt": attempt}))
        patch.update(attempt=attempt, state="proposed")
        assert_payload("patchset", patch)
        return {"attempt": attempt, "patchset": patch,
                "events": [_ev(state, "PATCH_PROPOSED", "remediator", attempt=attempt)]}

    def sandbox(state: SecOpsState) -> dict[str, Any]:
        report = dict(deps.sandbox(state))
        passed = bool(report.get("passed"))
        patch = dict(state["patchset"], state="sandbox_passed" if passed else "sandbox_failed")
        return {
            "sandbox_report": report,
            "patchset": patch,
            "sandbox_feedback": "" if passed else str(report.get("feedback", "sandbox failed")),
            "events": [_ev(state, "SANDBOX_PASSED" if passed else "SANDBOX_FAILED", "sandbox",
                           attempt=state.get("attempt"))],
        }

    def request_approval(state: SecOpsState) -> dict[str, Any]:
        make_request(state["case_id"], state.get("attempt", 1),
                     sandbox_passed=state["sandbox_report"].get("passed") is True)
        return {"events": [_ev(state, "APPROVAL_REQUESTED", "governance", policy_tier="manual")]}

    def approve(state: SecOpsState) -> dict[str, Any]:
        request = make_request(state["case_id"], state.get("attempt", 1),
                               sandbox_passed=state["sandbox_report"].get("passed") is True)
        answer = interrupt(request.to_dict())  # pauses here until resumed with a decision
        if isinstance(answer, str):
            answer = {"decision": answer}
        approval = record_decision(
            state["case_id"], str(answer.get("decision")), str(answer.get("actor", "human")),
            mode=deps.mode, comment=str(answer.get("comment", "")),
        )
        patch = dict(state["patchset"])
        if approval.approved:
            patch["state"] = "approved"
        return {
            "approval": approval.to_dict(),
            "patchset": patch,
            "events": [
                _ev(state, "APPROVED" if approval.approved else "REJECTED", approval.actor,
                    simulated=approval.simulated),
            ],
        }

    def bundle(state: SecOpsState) -> dict[str, Any]:
        ps = PatchSet.from_payload(state["patchset"])
        diff = ""
        applied = False
        if deps.target_root is not None:
            applier = PatchApplier(deps.target_root)
            results = applier.apply(ps, dry_run=deps.mode.lower() == "replay")
            diff = unified_diff(results)
            applied = deps.mode.lower() != "replay"
        elif deps.mode.lower() != "replay":
            raise ValueError("LIVE bundling requires a local target_root")
        b = build_bundle(case_id=state["case_id"], finding=state["finding"], patchset=ps,
                         diff=diff, verdict=state.get("verdict"),
                         sandbox_report=state.get("sandbox_report"),
                         approval=state.get("approval"), mode=deps.mode)
        return {
            "bundle": b,
            "patchset": dict(state["patchset"], state="applied" if applied else "approved"),
            "finding": dict(state["finding"], state="remediated" if applied else "confirmed"),
            "events": [
                _ev(state, "PATCH_APPLIED", "bundler", target="remediation bundle"),
                _ev(state, "CASE_CLOSED", "bundler", outcome="remediated"),
            ] if applied else [],
        }

    def after_guard(state: SecOpsState) -> str:
        return END if state["finding"]["state"] == "quarantined" else "evidence"

    def band_route(state: SecOpsState) -> str:
        return "remediate" if state["band"] == "confirmed" else END

    def after_sandbox(state: SecOpsState) -> str:
        if state["patchset"]["state"] == "sandbox_passed":
            return "request_approval"
        return "remediate" if state.get("attempt", 0) < MAX_ATTEMPTS else END

    def after_approve(state: SecOpsState) -> str:
        return "bundle" if state["approval"]["decision"] == "approve" else END

    g = StateGraph(SecOpsState)
    for name, fn in [("guard", guard), ("evidence", evidence), ("adjudicate", adjudicate),
                     ("remediate", remediate), ("sandbox", sandbox),
                     ("request_approval", request_approval), ("approve", approve),
                     ("bundle", bundle)]:
        g.add_node(name, fn)
    g.add_edge(START, "guard")
    g.add_conditional_edges("guard", after_guard, ["evidence", END])
    g.add_edge("evidence", "adjudicate")
    g.add_conditional_edges("adjudicate", band_route, ["remediate", END])
    g.add_edge("remediate", "sandbox")
    g.add_conditional_edges("sandbox", after_sandbox, ["request_approval", "remediate", END])
    g.add_edge("request_approval", "approve")
    g.add_conditional_edges("approve", after_approve, ["bundle", END])
    g.add_edge("bundle", END)
    return g

"""S3 case graph adapted from revio ``src/revio/agent/graph.py``.

Guard → evidence (E1–E4) → adjudicate → (uncertain → skeptic) → verify → blast radius
→ remediate (LLM) or deterministic bump → screen destructive intent → sandbox
→ counterfactual + PoC witness (code only) → policy → approval (auto or interrupt) → bundle.
Max 3 remediation attempts. Rollback is available after an applied LIVE bundle.
"""

from __future__ import annotations

import json
import shutil
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
from pulseguard.agents.skeptic import abstained_verdict, challenge, resolution
from pulseguard.agents.state import SecOpsState
from pulseguard.contracts.models import Finding
from pulseguard.contracts.validate import assert_payload
from pulseguard.evidence import CODE_HEADER, build_hard_evidence, render_block
from pulseguard.falsify.counterfactual import consistent
from pulseguard.falsify.poc import witness
from pulseguard.governance.approval import Approval, make_request, record_decision
from pulseguard.governance.policy import decide as policy_decide
from pulseguard.patching.bump import deterministic_bump
from pulseguard.patching.history import FixHistoryStore
from pulseguard.patching.patch import (
    PatchApplier,
    PatchSet,
    build_bundle,
    unified_diff,
    write_bundle,
)
from pulseguard.patching.sandbox import SandboxVerifier, Scanner
from pulseguard.paths import REPO_ROOT
from pulseguard.risk.blast_radius import exposure_text, is_dependency, score_finding
from pulseguard.scanners.semgrep import DataflowTrace, TraceLine
from pulseguard.verify import verify_finding

MAX_ATTEMPTS = 3
NodeFn = Callable[[SecOpsState], dict[str, Any]]


def _ev(state: SecOpsState, activity: str, resource: str, **attrs: Any) -> dict[str, Any]:
    mode = str(state.get("mode") or "live").upper()
    if mode not in ("REPLAY", "LIVE"):
        mode = "LIVE"
    attributes: dict[str, Any] = {"run_mode": mode}
    if state.get("priority"):
        attributes["priority"] = state["priority"]
    attributes.update({key: value for key, value in attrs.items() if value is not None})
    return {
        "case_id": state.get("case_id") or state["finding"]["case_id"],
        "activity": activity, "ts": datetime.now(UTC).isoformat(),
        "resource": resource, "attributes": attributes,
    }


@dataclass
class GraphDeps:
    """Optional node overrides; default behaviour uses the real model and sandbox adapters."""

    adjudicate: NodeFn | None = None
    skeptic: NodeFn | None = None
    remediate: NodeFn | None = None
    sandbox: NodeFn | None = None
    counterfactual: NodeFn | None = None
    bands: Bands = field(default_factory=lambda: DEFAULT_BANDS)
    target_root: Path | None = None
    output_dir: Path | None = None
    llm: LLMClient | None = None
    scanner: Scanner | None = None
    mode: str = "live"
    bus_health: str = "fresh"


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
    return trace.dedupe()


def _is_dependency(state: SecOpsState) -> bool:
    return is_dependency(state["finding"])


def build_graph(deps: GraphDeps | None = None) -> StateGraph:
    """Return an uncompiled graph; the runner supplies durable SQLite checkpoints."""
    deps = deps or GraphDeps()

    def target_root(state: SecOpsState) -> Path:
        root = state.get("target_root") or deps.target_root
        if root is None:
            return REPO_ROOT
        return Path(root)

    def _code(state: SecOpsState) -> str:
        if state.get("code"):
            return str(state["code"])
        finding = state["finding"]
        path = target_root(state) / finding["file"]
        if path.is_file():
            return path.read_text(encoding="utf-8")
        return ""

    def guard(state: SecOpsState) -> dict[str, Any]:
        finding = dict(state["finding"])
        assert_payload("finding", finding)
        text = "\n".join([json.dumps(finding), state.get("code", "")])
        result = guard_mod.screen(text)
        events = [_ev(state, "FINDING_INGESTED", "guard", rule_id=finding["rule_id"])]
        update: dict[str, Any] = {
            "case_id": finding["case_id"], "guard_flags": result.patterns,
            "bus_health": state.get("bus_health") or deps.bus_health or "fresh",
        }
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
        code = _code(state)
        exposure = exposure_text(state["finding"], code or None)
        items = build_hard_evidence(finding, _trace_from_steps(steps), exposure=exposure)
        ids = [item.evidence_id for item in items]
        return {
            "finding": dict(state["finding"], evidence_ids=ids),
            "evidence": [item.model_dump() for item in items],
            "evidence_block": render_block(
                items, code or None,
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
        status = {"confirmed": "remediating", "uncertain": "human_review",
                  "false_positive": "dropped"}[band]
        return {
            "verdict": verdict, "verdict_metadata": metadata, "band": band,
            "model_calls": [{"role": "adjudicator", **metadata}] if metadata else [],
            "finding": dict(state["finding"], state=band),
            "review_status": status,
            "review_reason": "adjudication requires human review" if band == "uncertain" else "",
            "events": [_ev(state, BAND_ACTIVITY[band], "adjudicator", score=verdict["score"],
                           cited_evidence=verdict.get("cited_evidence", []))],
        }

    def skeptic_node(state: SecOpsState) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        try:
            if deps.skeptic:
                verdict = dict(deps.skeptic(state))
                verdict.setdefault("role", "skeptic")
                verdict.setdefault("band", deps.bands.band_for(verdict["score"]))
                verdict.setdefault("model", "unknown")
                assert_payload("verdict", verdict)
            elif deps.llm:
                verdict = challenge(
                    Finding.model_validate(state["finding"]), state["evidence_block"],
                    state["verdict"], llm=deps.llm, metadata=metadata,
                ).to_payload()
            else:
                verdict = abstained_verdict(
                    "unknown", state["case_id"],
                    "No skeptic model configured; abstain.").to_payload()
        except Exception:
            verdict = abstained_verdict(
                "unknown", state["case_id"], "Unusable skeptic result; abstain.").to_payload()
        return {
            "skeptic": verdict,
            "model_calls": [{"role": "skeptic", **metadata}] if metadata else [],
            "events": [_ev(state, "CHALLENGED", "skeptic", score=verdict.get("score"),
                           band=verdict.get("band"))],
        }

    def verify(state: SecOpsState) -> dict[str, Any]:
        cited = (state.get("verdict") or {}).get("cited_evidence") or []
        report = verify_finding(
            state["finding"], evidence=state.get("evidence") or [], cited=cited,
            target=target_root(state), scanner=deps.scanner,
            patchset=state.get("patchset") or None,
        )
        skeptic = state.get("skeptic")
        outcome = resolution(
            state["band"], None if skeptic is None else skeptic.get("band"), report["ok"])
        events = []
        update: dict[str, Any] = {"verification": report, "verified": report["ok"]}
        if outcome == "abstained":
            reason = "verification failed" if not report["ok"] else (
                "adjudicator and skeptic did not resolve outside 0.3-0.7")
            update.update(
                finding=dict(state["finding"], state="escalated"),
                review_status="human_review", review_reason=reason,
                events=[_ev(state, "ABSTAINED_ESCALATED", "verifier", reason=reason,
                            score=state["verdict"].get("score"))],
            )
            return update
        events.append(_ev(state, "VERIFIED", "verifier", ok=True,
                          score=state["verdict"].get("score")))
        if outcome == "false_positive":
            update.update(
                finding=dict(state["finding"], state="false_positive"),
                review_status="dropped", review_reason="",
                events=events + [_ev(state, "FALSE_POSITIVE_DROPPED", "verifier",
                                     score=state["verdict"].get("score"))],
            )
            return update
        update.update(
            finding=dict(state["finding"], state="confirmed"),
            review_status="remediating", events=events,
        )
        return update

    def blast(state: SecOpsState) -> dict[str, Any]:
        result = score_finding(state["finding"], code=_code(state) or None)
        return {
            "blast_radius": result, "priority": result["priority"],
            "events": [_ev(state, "BLAST_RADIUS_SCORED", "risk",
                           priority=result["priority"], score=result["score"])],
        }

    def remediate(state: SecOpsState) -> dict[str, Any]:
        attempt = state.get("attempt", 0) + 1
        metadata: dict[str, Any] = {}
        finding = Finding.model_validate(state["finding"])
        try:
            if _is_dependency(state):
                text = (target_root(state) / (
                    (finding.extra or {}).get("manifest") or finding.file
                )).read_text(encoding="utf-8")
                patch = deterministic_bump(
                    finding.to_payload(), text, attempt=attempt).to_payload()
                return {"attempt": attempt, "patchset": patch, "patch_error": "",
                        "patch_rejected": False, "patch_metadata": {"deterministic": True},
                        "events": [_ev(state, "PATCH_PROPOSED", "remediator", attempt=attempt,
                                       deterministic=True)]}
            if deps.remediate:
                patch = dict(deps.remediate({**state, "attempt": attempt}))
                patch.update(attempt=attempt, state="proposed", case_id=state["case_id"])
                assert_payload("patchset", patch)
                validate_patch_scope(PatchSet.from_payload(patch), finding)
            else:
                patch = propose_patch(
                    finding, state["evidence_block"], attempt=attempt,
                    sandbox_feedback=state.get("sandbox_feedback"), llm=deps.llm,
                    metadata=metadata,
                ).to_payload()
            return {"attempt": attempt, "patchset": patch, "patch_error": "",
                    "patch_rejected": False, "patch_metadata": metadata,
                    "model_calls": [{"role": "remediator", "attempt": attempt, **metadata}]
                    if metadata else [],
                    "events": [_ev(state, "PATCH_PROPOSED", "remediator", attempt=attempt)]}
        except Exception as exc:
            return {"attempt": attempt, "patch_error": type(exc).__name__,
                    "patch_rejected": False, "patch_metadata": metadata, "patchset": {},
                    "model_calls": [{"role": "remediator", "attempt": attempt, **metadata}]
                    if metadata else [],
                    "events": [_ev(state, "PATCH_PROPOSED", "remediator", attempt=attempt,
                                   rejected=True, reason=type(exc).__name__)]}

    def screen_patch(state: SecOpsState) -> dict[str, Any]:
        patch = state.get("patchset") or {}
        if state.get("patch_error") or not patch:
            return {"patch_rejected": False}
        hit = guard_mod.screen_patchset(patch)
        if not hit.flagged:
            return {"patch_rejected": False}
        reason = "destructive remediation intent: " + ", ".join(hit.patterns)
        return {
            "patch_rejected": True,
            "finding": dict(state["finding"], state="escalated"),
            "review_status": "human_review", "review_reason": reason,
            "patchset": dict(patch, state="proposed"),
            "events": [
                _ev(state, "REJECTED", "guard", reason=reason, patterns=hit.patterns),
                _ev(state, "ABSTAINED_ESCALATED", "guard", reason=reason),
            ],
        }

    def sandbox(state: SecOpsState) -> dict[str, Any]:
        try:
            if state.get("patch_error"):
                report = {"passed": False, "errors": [state["patch_error"]],
                          "feedback": "Patch rejected: invalid JSON, contract or trace scope."}
            elif deps.sandbox:
                report = dict(deps.sandbox(state))
            elif _is_dependency(state):
                extra = state["finding"].get("extra") or {}
                report = SandboxVerifier(
                    target_root(state), state["finding"]["rule_id"], runner=deps.scanner,
                ).verify_dependency(
                    PatchSet.from_payload(state["patchset"]),
                    package=str(extra.get("package") or extra.get("pkg_name") or ""),
                    installed=str(extra.get("installed_version") or ""),
                    fixed=str(extra.get("fixed_version") or ""),
                    manifest=str(extra.get("manifest") or state["finding"]["file"]),
                ).to_dict()
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

    def counterfactual(state: SecOpsState) -> dict[str, Any]:
        original = float(state["verdict"]["score"])
        metadata: dict[str, Any] = {}
        try:
            if deps.counterfactual:
                produced = dict(deps.counterfactual(state))
                patched_score = float(produced["score"])
                verdict = {**produced, "role": "counterfactual",
                           "band": deps.bands.band_for(patched_score),
                           "model": produced.get("model") or "unknown"}
                assert_payload("verdict", verdict)
            else:
                block = _patched_block(state, target_root(state))
                verdict_obj = model_adjudicate(
                    Finding.model_validate(state["finding"]), block,
                    llm=deps.llm, metadata=metadata,
                )
                payload = verdict_obj.to_payload()
                payload["role"] = "counterfactual"
                patched_score = float(payload["score"])
                verdict = payload
        except Exception as exc:
            fail = consistent(original, 1.0)
            detail = f"counterfactual error: {type(exc).__name__}"
            return {
                "counterfactual": {**fail.to_dict(), "detail": detail, "ok": False},
                "finding": dict(state["finding"], state="escalated"),
                "review_status": "human_review",
                "review_reason": detail,
                "events": [_ev(state, "ABSTAINED_ESCALATED", "counterfactual",
                               reason=type(exc).__name__, score=original)],
            }
        result = consistent(original, patched_score)
        update: dict[str, Any] = {
            "counterfactual": result.to_dict(), "counterfactual_verdict": verdict,
            "model_calls": [{"role": "counterfactual", **metadata}] if metadata else [],
        }
        if not result.ok:
            update.update(
                finding=dict(state["finding"], state="escalated"),
                review_status="human_review", review_reason=result.detail,
                events=[_ev(state, "ABSTAINED_ESCALATED", "counterfactual",
                            reason=result.detail, score=patched_score)],
            )
        return update

    def policy(state: SecOpsState) -> dict[str, Any]:
        health = state.get("bus_health") or deps.bus_health or "fresh"
        decision = policy_decide(
            state.get("priority"), verified=state.get("verified") is True, bus_health=health)
        payload = decision.to_dict()
        return {
            "policy": payload, "bus_health": health,
            "review_reason": decision.reason if decision.tier != "auto" else "",
        }

    def poc(state: SecOpsState) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        result = witness(
            target_root(state), PatchSet.from_payload(state["patchset"]), state["evidence_block"],
            case_id=state["case_id"], llm=deps.llm, metadata=metadata,
        )
        item = {"evidence_id": "E5", "kind": "poc", "text": result["detail"], "payload": result}
        items = [it for it in state["evidence"] if it["evidence_id"] != "E5"] + [item]
        finding = dict(state["finding"], evidence_ids=[it["evidence_id"] for it in items])
        events = [_ev(state, "VERIFIED", "poc", check="poc_witness", **result)]
        update: dict[str, Any] = {
            "poc": result, "evidence": items, "finding": finding,
            "evidence_block": state["evidence_block"].replace(
                CODE_HEADER, f"[E5] {result['detail']}\n{CODE_HEADER}", 1),
            "model_calls": [{"role": "poc", **metadata}] if metadata else [],
            "events": events,
        }
        if result["status"] == "failed":
            finding["state"] = "escalated"
            update.update(verified=False, review_status="human_review",
                          review_reason=result["detail"])
            events.append(_ev(state, "ABSTAINED_ESCALATED", "poc", check="poc_witness",
                              reason=result["detail"]))
        return update

    def auto_approve(state: SecOpsState) -> dict[str, Any]:
        approval = Approval(
            case_id=state["case_id"], decision="approve", actor="policy:auto",
            policy_tier="auto", simulated=deps.mode.lower() == "replay",
        )
        patch = dict(state["patchset"], state="approved")
        return {
            "approval": approval.to_dict(), "patchset": patch,
            "review_status": "approved",
            "events": [
                _ev(state, "APPROVAL_REQUESTED", "policy:auto", policy_tier="auto"),
                _ev(state, "APPROVED", "policy:auto", policy_tier="auto",
                    simulated=approval.simulated),
            ],
        }

    def request_approval(state: SecOpsState) -> dict[str, Any]:
        policy_row = state.get("policy") or {}
        tier = policy_row.get("tier", "human")
        reason = policy_row.get("reason", "human approval required")
        make_request(state["case_id"], state["attempt"],
                     sandbox_passed=state["sandbox_report"].get("passed") is True,
                     policy_tier=tier, reason=reason)
        return {"review_status": "awaiting_approval", "review_reason": reason, "events": [
            _ev(state, "APPROVAL_REQUESTED", "governance", policy_tier=tier)]}

    def approve(state: SecOpsState) -> dict[str, Any]:
        policy_row = state.get("policy") or {}
        tier = policy_row.get("tier", "human")
        request = make_request(
            state["case_id"], state["attempt"],
            sandbox_passed=state["sandbox_report"].get("passed") is True,
            policy_tier=tier, reason=policy_row.get("reason", "human approval required"),
        )
        answer = interrupt(request.to_dict())
        approval = record_decision(
            state["case_id"], answer["decision"], answer["actor"],
            mode=deps.mode, comment=answer.get("comment", ""), policy_tier=tier,
        )
        patch = dict(state["patchset"])
        if approval.approved:
            patch["state"] = "approved"
        events = [_ev(state, "APPROVED" if approval.approved else "REJECTED", approval.actor,
                      simulated=approval.simulated, policy_tier=tier)]
        if not approval.approved:
            events.append(_ev(state, "CASE_CLOSED", "governance", outcome="rejected"))
        return {"approval": approval.to_dict(), "patchset": patch, "events": events,
                "review_status": "approved" if approval.approved else "closed"}

    def bundle(state: SecOpsState) -> dict[str, Any]:
        patchset = PatchSet.from_payload(state["patchset"])
        live = deps.mode.lower() == "live"
        snapshots: list[dict[str, str]] = []
        if live:
            output = state.get("output_dir") or deps.output_dir or (
                Path(tempfile.gettempdir()) / "pulseguard-bundles" / state["case_id"])
            snapshots = FixHistoryStore().snapshot_files(
                state["case_id"], target_root(state), patchset.files)
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
        events = []
        if live:
            events = [_ev(state, "PATCH_APPLIED", "bundler", target="remediation bundle"),
                      _ev(state, "CASE_CLOSED", "bundler", outcome="remediated")]
        return {
            "bundle": result, "fix_snapshots": snapshots,
            "patchset": dict(state["patchset"], state="applied" if live else "approved"),
            "finding": dict(state["finding"], state="remediated" if live else "confirmed"),
            "review_status": "closed", "events": events,
        }

    def after_adjudicate(state: SecOpsState) -> str:
        if state["band"] == "false_positive":
            return END
        if state["band"] == "uncertain":
            return "skeptic"
        return "verify"

    def after_verify(state: SecOpsState) -> str:
        if state["finding"]["state"] == "confirmed":
            return "blast"
        return END

    def after_screen(state: SecOpsState) -> str:
        return END if state.get("patch_rejected") else "sandbox"

    def after_sandbox(state: SecOpsState) -> str:
        if state["sandbox_report"].get("passed") is True:
            return "policy" if _is_dependency(state) else "counterfactual"
        return "remediate" if state["attempt"] < MAX_ATTEMPTS else END

    def after_poc(state: SecOpsState) -> str:
        if state["finding"]["state"] == "escalated":
            return END
        return "policy"

    def after_policy(state: SecOpsState) -> str:
        if (state.get("policy") or {}).get("tier") == "auto":
            return "auto_approve"
        return "request_approval"

    graph = StateGraph(SecOpsState)
    for name, fn in [
        ("guard", guard), ("evidence", evidence), ("adjudicate", adjudicate),
        ("skeptic", skeptic_node), ("verify", verify), ("blast", blast),
        ("remediate", remediate), ("screen_patch", screen_patch), ("sandbox", sandbox),
        ("counterfactual", counterfactual), ("poc", poc), ("policy", policy),
        ("auto_approve", auto_approve), ("request_approval", request_approval),
        ("approve", approve), ("bundle", bundle),
    ]:
        graph.add_node(name, fn)
    graph.add_edge(START, "guard")
    graph.add_conditional_edges("guard", lambda s: END if s["finding"]["state"] == "quarantined"
                                else "evidence", ["evidence", END])
    graph.add_edge("evidence", "adjudicate")
    graph.add_conditional_edges(
        "adjudicate", after_adjudicate, ["skeptic", "verify", END])
    graph.add_edge("skeptic", "verify")
    graph.add_conditional_edges("verify", after_verify, ["blast", END])
    graph.add_edge("blast", "remediate")
    graph.add_edge("remediate", "screen_patch")
    graph.add_conditional_edges("screen_patch", after_screen, ["sandbox", END])
    graph.add_conditional_edges(
        "sandbox", after_sandbox, ["remediate", "counterfactual", "policy", END])
    graph.add_edge("counterfactual", "poc")
    graph.add_conditional_edges("poc", after_poc, ["policy", END])
    graph.add_conditional_edges("policy", after_policy, ["auto_approve", "request_approval"])
    graph.add_edge("auto_approve", "bundle")
    graph.add_edge("request_approval", "approve")
    graph.add_conditional_edges("approve", lambda s: (
        "bundle" if s["approval"]["decision"] == "approve" else END), ["bundle", END])
    graph.add_edge("bundle", END)
    return graph


def _patched_block(state: SecOpsState, root: Path) -> str:
    """Build a fresh Hard Evidence Block from a temp copy with the patch applied."""
    finding = Finding.model_validate(state["finding"])
    patchset = PatchSet.from_payload(state["patchset"])
    with tempfile.TemporaryDirectory(prefix="pg-cf-") as tmp:
        work = Path(tmp) / "target"
        shutil.copytree(root, work, ignore=shutil.ignore_patterns(
            "__pycache__", "*.sqlite*", "*.db", ".pytest_cache", ".git"))
        PatchApplier(work).apply(patchset)
        code = (work / finding.file).read_text(encoding="utf-8")
        steps = state.get("trace") or [s.model_dump() for s in finding.trace]
        items = build_hard_evidence(
            finding, _trace_from_steps(steps),
            exposure=exposure_text(state["finding"], code),
        )
        sink = next((s["line"] for s in steps if s["kind"] == "sink"), finding.line)
        return render_block(items, code, sink_line=sink)

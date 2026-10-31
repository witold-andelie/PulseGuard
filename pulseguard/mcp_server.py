"""MCP tool exposure (framework 6, ST-4).

Adapted from revio ``src/revio/mcp_server/server.py`` (FastMCP over stdio). Tools are
``triage_finding``, ``get_case_evidence`` and ``request_approval``. The server never
applies a patch, never opens a shell, and never writes outside the SQLite case store.
stdout is the JSON-RPC channel; logging goes to stderr.

Run: ``python -m pulseguard.mcp_server``
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from mcp.server.fastmcp import FastMCP

from pulseguard import guard as guard_mod
from pulseguard.contracts.models import Finding
from pulseguard.contracts.validate import validate_payload
from pulseguard.evidence import build_hard_evidence, render_block
from pulseguard.governance.approval import ApprovalError, record_decision
from pulseguard.paths import REPO_ROOT, default_db_path, demo_target_dir
from pulseguard.scanners.semgrep import DataflowTrace, TraceLine
from pulseguard.store import Store

CASE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
MODEL_ENV = ("PG_MODEL_BASE_URL", "PG_MODEL_NAME", "PG_MODEL_API_KEY")


def _safe_join(root: Path, rel: str) -> Path | None:
    if not rel or PureWindowsPath(rel).drive or "\\" in rel:
        return None
    posix = PurePosixPath(rel)
    if posix.is_absolute() or ".." in posix.parts:
        return None
    target = (root / rel).resolve()
    root = root.resolve()
    if target != root and root not in target.parents:
        return None
    return target


def _mode() -> str:
    value = (os.environ.get("PG_MODE") or "replay").strip().lower()
    if value not in {"replay", "live"}:
        raise ValueError(f"PG_MODE must be replay or live, got {value!r}")
    return value


def _store() -> Store:
    return Store(default_db_path()).init_db()


def _model_configured() -> bool:
    return all(os.environ.get(key, "").strip() for key in MODEL_ENV)


def _trace_of(finding: Finding) -> DataflowTrace:
    trace = DataflowTrace()
    for step in finding.trace:
        line = TraceLine(step.line, step.content)
        if step.kind == "source":
            trace.source = line
        elif step.kind == "sink":
            trace.sink = line
        else:
            trace.intermediates.append(line)
    return trace


def _read_source(finding: Finding) -> str:
    extra = finding.extra or {}
    code = extra.get("code")
    if isinstance(code, str) and code:
        return code
    rel = finding.file.replace("\\", "/")
    for root in (REPO_ROOT, demo_target_dir(), Path.cwd()):
        path = _safe_join(root, rel)
        if path is not None and path.is_file():
            return path.read_text(encoding="utf-8")
        path = _safe_join(root, Path(rel).name)
        if path is not None and path.is_file() and Path(rel).name == rel:
            return path.read_text(encoding="utf-8")
    return ""


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"error": message, **extra}


def triage_finding(finding_json: str) -> dict[str, Any]:
    """Validate a finding, run guard + deterministic evidence, optionally adjudicate.

    With no model configured this returns the Hard Evidence Block and says so.
    Guard-flagged findings are not sent to a model.
    """
    try:
        payload = json.loads(finding_json)
    except (TypeError, json.JSONDecodeError):
        return _error("finding_json is not valid JSON")
    if not isinstance(payload, dict):
        return _error("finding_json must be a JSON object")
    errors = validate_payload("finding", payload)
    if errors:
        return _error("finding payload invalid", details=errors)
    finding = Finding.model_validate(payload)
    code = _read_source(finding)
    screened = "\n".join([json.dumps(payload), code])
    guard_result = guard_mod.screen(screened)
    if guard_result.flagged:
        code = guard_mod.strip_flagged_lines(code)
    limits: list[dict[str, Any]] = []
    items = build_hard_evidence(finding, _trace_of(finding), code=code or None,
                                analysis_limits=limits)
    sink = next((step.line for step in finding.trace if step.kind == "sink"), finding.line)
    block = render_block(items, code or None, sink_line=sink, analysis_limits=limits)
    result: dict[str, Any] = {
        "guard_flagged": guard_result.flagged,
        "guard_patterns": guard_result.patterns,
        "evidence": [item.model_dump() for item in items],
        "analysis_limits": limits,
        "evidence_block": block,
        "model_configured": False,
        "verdict": None,
        "note": "no model configured; returning evidence only",
    }
    if guard_result.flagged:
        result["note"] = "finding quarantined by guard; returning evidence only"
        return result
    if not _model_configured():
        return result
    from pulseguard.agents.adjudicator import adjudicate
    from pulseguard.agents.llm import make_llm
    try:
        verdict = adjudicate(finding, block, llm=make_llm())
    except Exception as exc:
        result["note"] = f"adjudicator unavailable: {type(exc).__name__}"
        return result
    result.update(
        model_configured=True, verdict=verdict.to_payload(),
        note="adjudicator verdict included",
    )
    return result


def get_case_evidence(case_id: str) -> dict[str, Any]:
    """Return evidence items, verdicts, verification and blast radius from PG_DB_PATH."""
    if not isinstance(case_id, str) or not CASE_ID_RE.fullmatch(case_id):
        return _error("invalid case_id")
    store = _store()
    case = store.get_case(case_id)
    if case is None:
        return _error(f"case {case_id} not found")
    runtime = store.get_runtime(case_id) or {}
    return {
        "case_id": case_id,
        "evidence": store.list_evidence(case_id),
        "analysis_limits": runtime.get("analysis_limits") or [],
        "verdicts": store.list_verdicts(case_id),
        "verification": runtime.get("verification"),
        "blast_radius": runtime.get("blast_radius"),
    }


def request_approval(case_id: str, decision: str, actor: str) -> dict[str, Any]:
    """Record an approval request. Never applies a patch.

    REPLAY: simulated and labelled; nothing is stored. LIVE: writes an
    ``APPROVAL_REQUESTED`` event only; the human decision stays in the existing
    approval flow.
    """
    if not isinstance(case_id, str) or not CASE_ID_RE.fullmatch(case_id):
        return _error("invalid case_id")
    try:
        mode = _mode()
    except ValueError as exc:
        return _error(str(exc))
    store = _store()
    if store.get_case(case_id) is None:
        return _error(f"case {case_id} not found")
    try:
        approval = record_decision(case_id, decision, actor, mode=mode)
    except ApprovalError as exc:
        return _error(str(exc))
    if mode == "replay":
        return {
            "simulated": True,
            "applied": False,
            "label": "REPLAY - simulated approval request; nothing was applied or stored",
            "approval": approval.to_dict(),
        }
    store.add_event({
        "case_id": case_id,
        "activity": "APPROVAL_REQUESTED",
        "ts": datetime.now(UTC).isoformat(),
        "resource": approval.actor,
        "attributes": {
            "run_mode": "LIVE", "decision": approval.decision, "mcp": True,
            "applied": False,
        },
    })
    return {
        "simulated": False,
        "applied": False,
        "label": (
            "LIVE approval request recorded; "
            "human approval stays in the existing approval flow"
        ),
        "approval": None,
    }


def build_server() -> FastMCP:
    """Construct the FastMCP server with the three PulseGuard tools."""
    mcp = FastMCP(
        name="pulseguard",
        instructions=(
            "PulseGuard MCP tools for governed triage. triage_finding builds the Hard "
            "Evidence Block deterministically and only calls a model when PG_MODEL_* is "
            "set. get_case_evidence reads the SQLite case store. request_approval never "
            "applies a patch: REPLAY is simulated, LIVE records a request event only."
        ),
    )
    mcp.add_tool(
        triage_finding, name="triage_finding",
        description=(
            "Validate finding_json against contracts/finding.schema.json, run the guard "
            "and build the Hard Evidence Block. Returns the block; includes an "
            "adjudicator verdict only when PG_MODEL_* is configured."
        ),
    )
    mcp.add_tool(
        get_case_evidence, name="get_case_evidence",
        description=(
            "Return evidence items, verdicts, verification and blast radius for case_id "
            "from the SQLite store at PG_DB_PATH."
        ),
    )
    mcp.add_tool(
        request_approval, name="request_approval",
        description=(
            "Request approval for case_id with decision (approve|reject) and actor. "
            "Never applies a patch. REPLAY is simulated and labelled; LIVE records an "
            "APPROVAL_REQUESTED event only."
        ),
    )
    return mcp


def main() -> None:
    """Synchronous stdio entry point. stdout is JSON-RPC; logs go to stderr."""
    import logging
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    build_server().run("stdio")


if __name__ == "__main__":
    main()

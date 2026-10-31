"""FastAPI app: JSON API + static web UI from one container.

Adapted from tradepulse ``tradepulse/api.py`` + ``serve.py`` (``create_app`` factory, ``/health``,
startup sample check) and the PerpPulse serving-mode switch (``PG_MODE`` = replay | live).

Boot sequence in REPLAY: verify the replay bundle's sha256 manifest, then seed SQLite from it.
If verification fails nothing is seeded and ``/health`` / ``/api/mode`` say so.

Run: ``uvicorn pulseguard.api:create_app --factory --port $PORT``
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from pulseguard import __version__
from pulseguard.agents.graph import GraphDeps
from pulseguard.agents.runner import CaseNotAwaitingApproval, resume_case
from pulseguard.contracts.validate import assert_payload
from pulseguard.governance.approval import ApprovalError, record_decision
from pulseguard.patching.history import FixHistoryStore
from pulseguard.paths import default_db_path, replay_dir, web_dir
from pulseguard.replay.store import RunStore, validate_run_id
from pulseguard.replay.verify import verify_manifest
from pulseguard.store import Store

MODES = ("replay", "live")


class DecisionIn(BaseModel):
    decision: str = Field(description="approve | reject")
    actor: str = Field(default="demo-visitor", max_length=80)
    comment: str = Field(default="", max_length=500)


class RollbackIn(BaseModel):
    actor: str = Field(default="security-engineer", max_length=80)


def resolve_mode(value: str | None = None) -> str:
    mode = (value or os.environ.get("PG_MODE") or "replay").strip().lower()
    if mode not in MODES:
        raise ValueError(f"PG_MODE must be one of {MODES}, got {mode!r}")
    return mode


def seed_from_replay(store: Store, run: dict[str, Any], manifest_sha256: str | None) -> str:
    """Rebuild the case store from one recorded run (ephemeral disk on Render)."""
    # Validate the complete input before touching an existing database.
    if not isinstance(run.get("cases"), list) or not run["cases"]:
        raise ValueError("replay run must contain at least one case")
    validate_run_id(run["run_id"])
    for case in run["cases"]:
        assert_payload("finding", case["finding"])
        for verdict in case.get("verdicts", []):
            assert_payload("verdict", verdict)
        for patch in case.get("patches", []):
            assert_payload("patchset", patch["patchset"])
        for event in case.get("events", []):
            assert_payload("event", event)
    store.reset()
    run_id = run["run_id"]
    store.create_run(run_id, "REPLAY", source_commit=run.get("source_commit"),
                     manifest_sha256=manifest_sha256, started_at=run.get("started_at"))
    for case in run.get("cases", []):
        finding = case["finding"]
        case_id = store.upsert_case(finding, run_id=run_id, priority=case.get("priority"),
                                    created_at=case.get("created_at"))
        for ev in case.get("evidence", []):
            payload = {"text": ev.get("text", ""), **ev.get("payload", {})}
            store.add_evidence(case_id, ev["evidence_id"], ev["kind"], payload)
        for v in case.get("verdicts", []):
            store.add_verdict(case_id, v, created_at=v.get("created_at"))
        for p in case.get("patches", []):
            store.add_patch(case_id, p["patchset"], state=p.get("state", "proposed"),
                            sandbox_report=p.get("sandbox_report"), patch_id=p.get("patch_id"))
        for a in case.get("approvals", []):
            store.add_approval(a["patch_id"], a["decision"], a["actor"],
                               a.get("policy_tier", "manual"), created_at=a.get("created_at"))
        for e in case.get("events", []):
            store.add_event(e)
        store.set_replay_context(case_id, case)
    return run_id


def create_app(
    *,
    mode: str | None = None,
    db_path: str | Path | None = None,
    replay_root: str | Path | None = None,
    web_root: str | Path | None = None,
    live_deps: GraphDeps | None = None,
) -> FastAPI:
    mode = resolve_mode(mode)
    app = FastAPI(title="PulseGuard", version=__version__)
    store = Store(db_path or default_db_path()).init_db()
    replay_root = Path(replay_root or replay_dir())

    info: dict[str, Any] = {
        "mode": mode.upper(), "run_id": None, "manifest_sha256": None,
        "replay_verified": None, "replay_error": None, "label": None, "recorded": None,
    }
    if mode == "replay":
        result = verify_manifest(replay_root)
        info["replay_verified"] = result.ok
        info["manifest_sha256"] = result.manifest_sha256
        if result.ok:
            try:
                run = RunStore(replay_root).latest()
                if run is None:
                    raise ValueError("no recorded run in replay bundle")
                info["run_id"] = seed_from_replay(store, run, result.manifest_sha256)
                info["label"] = run.get("label")
                info["recorded"] = bool(run.get("recorded"))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                info["replay_error"] = f"invalid replay run: {exc}"
        else:
            info["replay_error"] = result.error or (
                f"hash mismatch: mismatched={result.mismatched} missing={result.missing} "
                f"unlisted={result.unlisted}")
    else:
        info["label"] = "LIVE (local). Start scans with python -m pulseguard.run."

    app.state.store = store
    app.state.info = info

    @app.get("/health")
    def health() -> JSONResponse:
        ready = not info["replay_error"]
        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ok" if ready else "unavailable", "version": __version__,
                     "mode": info["mode"], "replay_verified": info["replay_verified"]},
        )

    @app.get("/api/mode")
    def api_mode() -> dict[str, Any]:
        current = dict(info)
        if mode == "live":
            runs = [run for run in store.list_runs() if run["mode"] == "LIVE"]
            current["run_id"] = runs[-1]["run_id"] if runs else None
        return current

    def require_ready() -> None:
        if info["replay_error"]:
            raise HTTPException(status_code=503, detail=info["replay_error"])

    @app.get("/api/cases")
    def list_cases(state: str | None = None) -> dict[str, Any]:
        require_ready()
        cases = store.list_cases(state, mode=info["mode"])
        for c in cases:
            c.pop("finding", None)
        return {"mode": info["mode"], "run_id": api_mode()["run_id"], "cases": cases}

    def _case_or_404(case_id: str) -> dict[str, Any]:
        require_ready()
        case = store.get_case(case_id)
        run = store.get_run(case["run_id"]) if case and case["run_id"] else None
        if case is None or run is None or run["mode"] != info["mode"]:
            raise HTTPException(status_code=404, detail=f"case {case_id} not found")
        return case

    def _rollback_view(case_id: str, runtime: dict[str, Any]) -> dict[str, Any]:
        rolled = bool(runtime.get("rolled_back")) or any(
            p.get("state") == "rolled_back" for p in store.list_patches(case_id))
        available = bool(runtime.get("fix_snapshots")) and not rolled
        return {"available": available, "rolled_back": rolled}

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str) -> dict[str, Any]:
        case = _case_or_404(case_id)
        runtime = store.get_runtime(case_id) or {}
        skeptic = runtime.get("skeptic")
        cf = runtime.get("counterfactual")
        verification = runtime.get("verification")
        blast = runtime.get("blast_radius")
        policy = runtime.get("policy")
        return {
            "mode": info["mode"],
            "case": case,
            "evidence": store.list_evidence(case_id),
            "verdicts": store.list_verdicts(case_id),
            "patches": store.list_patches(case_id),
            "approvals": store.list_approvals(case_id),
            "evidence_block": runtime.get("evidence_block"),
            "review_status": runtime.get("review_status"),
            "review_reason": runtime.get("review_reason"),
            "bundle": runtime.get("bundle"),
            "priority": case.get("priority"),
            "verification": verification,
            "skeptic": skeptic,
            "counterfactual": cf,
            "blast_radius": blast,
            "policy": policy,
            "bus_health": runtime.get("bus_health"),
            "rollback": _rollback_view(case_id, runtime),
        }

    @app.get("/api/cases/{case_id}/trace", response_model=None)
    def get_trace(case_id: str, format: str = "json") -> Any:
        _case_or_404(case_id)
        events = store.list_events(case_id)
        if format == "jsonl":
            body = "".join(json.dumps(e, sort_keys=True) + "\n" for e in events)
            return PlainTextResponse(body, media_type="application/x-ndjson")
        return {"case_id": case_id, "mode": info["mode"], "events": events}

    @app.post("/api/cases/{case_id}/decision")
    async def post_decision(case_id: str, body: DecisionIn) -> dict[str, Any]:
        _case_or_404(case_id)
        try:
            approval = record_decision(case_id, body.decision, body.actor, mode=mode,
                                       comment=body.comment)
        except ApprovalError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if mode == "replay":
            # Simulated: the recorded run is never mutated.
            return {"simulated": True,
                    "label": "REPLAY - simulated decision; nothing was applied or stored",
                    "approval": approval.to_dict()}
        try:
            status = await resume_case(case_id, body.decision, body.actor,
                                       live_deps, store.db_path, comment=body.comment)
        except CaseNotAwaitingApproval as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"simulated": False, "label": "LIVE decision recorded",
                "approval": status["values"]["approval"],
                "awaiting_approval": status["awaiting_approval"],
                "bundle": status["values"].get("bundle")}

    @app.post("/api/cases/{case_id}/rollback")
    def post_rollback(case_id: str, body: RollbackIn) -> dict[str, Any]:
        _case_or_404(case_id)
        if mode == "replay":
            return {
                "simulated": True,
                "label": "REPLAY - simulated rollback; nothing was restored",
                "rollback": {"available": False, "rolled_back": False, "simulated": True},
            }
        runtime = store.get_runtime(case_id) or {}
        if runtime.get("rolled_back"):
            raise HTTPException(status_code=409, detail="case already rolled back")
        snapshots = runtime.get("fix_snapshots") or []
        applied = (runtime.get("bundle") or {}).get("applied_target")
        if not snapshots or not applied:
            raise HTTPException(status_code=409, detail="no fix history for this case")
        FixHistoryStore.restore(Path(applied), snapshots)
        patches = store.list_patches(case_id)
        if patches:
            store.update_patch(patches[-1]["patch_id"], state="rolled_back")
        case = store.get_case(case_id) or {}
        store.add_event({
            "case_id": case_id, "activity": "ROLLED_BACK",
            "ts": datetime.now(UTC).isoformat(),
            "resource": body.actor, "attributes": {
                "run_mode": "LIVE", "priority": case.get("priority"),
            },
        })
        patchset = dict(runtime.get("patchset") or {})
        if patchset:
            patchset["state"] = "rolled_back"
        store.patch_runtime(case_id, rolled_back=True, patchset=patchset)
        return {
            "simulated": False,
            "label": "LIVE rollback restored the bundle target",
            "rollback": {"available": False, "rolled_back": True},
        }

    @app.exception_handler(ValueError)
    async def _value_error(_: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    web = Path(web_root or web_dir())
    if web.is_dir():
        app.mount("/", StaticFiles(directory=web, html=True), name="web")
    return app

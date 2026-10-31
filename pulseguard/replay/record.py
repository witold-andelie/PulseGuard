"""Record actual LIVE artifacts, using tradepulse ``scripts/review_demo.py`` bundle patterns.

Only the recording command offers auto approval. No synthetic response is marked recorded.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pulseguard.agents.llm import LLMConfig
from pulseguard.agents.runner import resume_case
from pulseguard.contracts.validate import assert_payload
from pulseguard.env import load_env_file
from pulseguard.paths import REPO_ROOT, default_db_path, replay_dir
from pulseguard.replay.store import RunStore, validate_run_id
from pulseguard.replay.verify import verify_manifest, write_manifest
from pulseguard.run import live_run
from pulseguard.store import REPLAY_CONTEXT_KEYS, Store


def _portable_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Replace LIVE-run host paths with paths relative to the recorded case directory."""
    out = {k: v for k, v in bundle.items() if k != "applied_target"}
    out["output_dir"] = "bundle"
    return out


def _json(path: Path, value: Any) -> None:
    # LF only: the manifest hashes bytes, and the repo stores replay files with eol=lf.
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
                    newline="\n")


def _classify(status: dict[str, Any], *, allow_approval: bool = False) -> str:
    """Only known terminal graph outcomes or a genuine approval interrupt can export."""
    values = status["values"]
    state = values.get("finding", {}).get("state")
    review = values.get("review_status")
    approval = values.get("approval") or {}
    if approval.get("simulated") or str(values.get("mode", "")).lower() != "live":
        raise ValueError("recording requires LIVE outcomes, never simulated approvals")
    if status["awaiting_approval"]:
        if (allow_approval and review == "awaiting_approval" and state == "confirmed"
                and status.get("next") == ["approve"] and not approval
                and not values.get("bundle")):
            return "awaiting_approval"
    elif not status.get("next"):
        if (state == "remediated" and review == "closed" and values.get("bundle")
                and approval.get("decision") == "approve"):
            if (values.get("policy") or {}).get("tier") == "auto":
                if approval.get("actor") != "policy:auto" or approval.get("policy_tier") != "auto":
                    raise ValueError("policy approval must retain actor policy:auto and tier auto")
            return "remediated"
        if not values.get("bundle") and not approval:
            if state == "false_positive" and review == "dropped":
                return "dropped"
            if state in ("quarantined", "escalated") and review == "human_review":
                return state
    raise ValueError(
        f"unexpected or unfinished LIVE case state: {state!r}, review_status={review!r}")


def write_recording(
    statuses: list[dict[str, Any]], *, root: Path, db_path: Path, run_id: str, model: str,
) -> Path:
    """Export terminal LIVE outcomes; callers must supply genuine model/scanner results."""
    validate_run_id(run_id)
    root = root.resolve()
    if not statuses:
        raise ValueError("recording requires at least one terminal LIVE case")
    if any(status["values"].get("run_id") != run_id for status in statuses):
        raise ValueError("case already belongs to another run; use a fresh PG_DB_PATH")
    for status in statuses:
        _classify(status)
        assert_payload("finding", status["values"]["finding"])
    target = root / "runs" / run_id
    if target.exists():
        raise ValueError(f"recording {run_id} already exists")
    store = Store(db_path).init_db()
    cases = []
    for status in statuses:
        state = status["values"]
        case_id = status["case_id"]
        context = {key: state[key] for key in REPLAY_CONTEXT_KEYS
                   if key in state and key != "topology_extraction"}
        case_row = store.get_case(case_id) or {}
        cases.append({
            **context, "finding": state["finding"], "evidence": state.get("evidence", []),
            "verdicts": [state[key] for key in ("verdict", "skeptic", "counterfactual_verdict")
                         if state.get(key)],
            "patches": store.list_patches(case_id), "approvals": store.list_approvals(case_id),
            "events": store.list_events(case_id),
            "created_at": case_row.get("created_at"),
            # Preserve the view, never the source snapshots or applied host directory.
            "rollback": {"available": bool(state.get("fix_snapshots"))
                         and not state.get("rolled_back", False),
                         "rolled_back": bool(state.get("rolled_back"))},
        })
    run = {
        "run_id": run_id, "mode": "LIVE", "recorded": True, "model": model,
        "label": "RECORDED LIVE run",
        "started_at": (store.get_run(run_id) or {}).get(
            "started_at", datetime.now(UTC).isoformat()),
        "cases": cases,
    }
    topology = statuses[0]["values"].get("topology_extraction")
    if topology is not None:
        run["topology_extraction"] = topology
        run["model_calls"] = topology.get("model_calls", [])
    # Build outside replay, so interrupted recordings cannot invalidate the existing manifest.
    staging = root.parent / f".{run_id}-staging-{uuid.uuid4().hex[:8]}"
    staging.mkdir(parents=True)
    try:
        for case in cases:
            case_dir = staging / case["finding"]["case_id"]
            case_dir.mkdir()
            _json(case_dir / "case.json", case["finding"])
            _json(case_dir / "evidence.json", {
                "items": case["evidence"], "block": case.get("evidence_block"),
            })
            _json(case_dir / "verdicts.json", {
                "verdicts": case["verdicts"], "model_metadata": case.get("verdict_metadata", {}),
            })
            _json(case_dir / "patches.json", case["patches"])
            _json(case_dir / "model_calls.json", case.get("model_calls", []))
            _json(case_dir / "approval.json", case.get("approval"))
            (case_dir / "trace.jsonl").write_text(
                "".join(json.dumps(event) + "\n" for event in case["events"]), encoding="utf-8",
                newline="\n")
            if not case.get("bundle"):
                continue
            bundle_dir = case_dir / "bundle"
            bundle_dir.mkdir()
            source = Path(case["bundle"]["output_dir"])
            for name in ("patch.diff", "pr_description.md"):
                (bundle_dir / name).write_text(
                    (source / name).read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
            # The published bundle must not carry host paths: point into the bundle itself.
            case["bundle"] = _portable_bundle(case["bundle"])
            metadata = json.loads((source / "metadata.json").read_text(encoding="utf-8"))
            _json(bundle_dir / "metadata.json", _portable_bundle(metadata))
        if topology is not None:
            _json(staging / "topology_extraction.json", topology)
            _json(staging / "model_calls.json", run["model_calls"])
        _json(staging / "run.json", run)
        target.parent.mkdir(parents=True, exist_ok=True)
        staging.rename(target)
    finally:
        if staging.exists():
            if staging.resolve().parent != root.parent:
                raise ValueError("recording staging path escaped its parent")
            shutil.rmtree(staging)
    write_manifest(root)
    result = verify_manifest(root)
    if not result.ok:
        raise ValueError(f"recorded replay verification failed: {result}")
    return RunStore(root).path_for(run_id)


async def record(args: argparse.Namespace) -> Path:
    config = LLMConfig.from_env()  # Mandatory even if a previous run exists.
    run_id = args.run_id or f"recorded-{datetime.now(UTC):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:6]}"
    validate_run_id(run_id)
    if (args.root / "runs" / run_id).exists():
        raise ValueError("run id already exists")
    statuses = await live_run(args.target, db_path=args.db_path, run_id=run_id)
    # Validate the entire batch before approving anything; unfinished cases need inspection.
    for status in statuses:
        if status["values"].get("run_id") != run_id:
            raise ValueError("case already belongs to another run; use a fresh PG_DB_PATH")
        _classify(status, allow_approval=True)
    completed = []
    for status in statuses:
        if not status["awaiting_approval"]:
            completed.append(status)
            continue
        actor = args.auto_approve_as
        if not actor:
            answer = input(f"Approve {status['case_id']} after reviewing its sandbox? [yes/no] ")
            if answer.strip().lower() != "yes":
                raise ValueError("recording cancelled; case remains paused")
            actor = input("Approver name: ").strip()
        completed.append(await resume_case(
            status["case_id"], "approve", actor, db_path=args.db_path,
            comment="Recording approval (--auto-approve-as)" if args.auto_approve_as
            else "Recording approval (interactive)"))
    return write_recording(
        completed, root=args.root, db_path=args.db_path, run_id=run_id, model=config.model)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", type=Path, default=REPO_ROOT / "demo_target" / "order_api")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--db-path", type=Path)
    parser.add_argument("--env-file", type=Path, help="Load process-only KEY=VALUE configuration")
    parser.add_argument("--run-id")
    parser.add_argument("--auto-approve-as", metavar="ACTOR",
                        help="Recording only: explicitly attribute automatic approval to ACTOR")
    args = parser.parse_args(argv)
    if args.env_file:
        try:
            load_env_file(args.env_file)
        except ValueError as exc:
            parser.error(str(exc))
    args.root = args.root or replay_dir()
    args.db_path = args.db_path or default_db_path()
    if args.auto_approve_as is not None and not args.auto_approve_as.strip():
        parser.error("--auto-approve-as must name an actor")
    try:
        print(asyncio.run(record(args)))
    except (ValueError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

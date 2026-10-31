"""Local LIVE entry point using revio ``src/revio/agent/runner.py`` and
quant-foundation-gat ``src/quant_alpha/streaming/demo_signals.py`` patterns.

S3 adds a bounded API run coordinator. Approval can be resumed by this CLI or the API.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pulseguard.agents.graph import GraphDeps
from pulseguard.agents.llm import LLMClient, make_llm
from pulseguard.agents.runner import resume_case, start_case
from pulseguard.agents.topology_extract import extract_topology
from pulseguard.bus.memory import FINDINGS_TOPIC, InMemoryBus, Message
from pulseguard.bus.watchdog import BusWatchdog
from pulseguard.env import load_env_file
from pulseguard.ingest import group_dependency_findings, merge_findings
from pulseguard.paths import REPO_ROOT, default_db_path
from pulseguard.scanners.bandit import BanditRunner
from pulseguard.scanners.normalize import normalize, normalize_bandit, normalize_trivy
from pulseguard.scanners.semgrep import SemgrepRunner
from pulseguard.scanners.trivy import TrivyReportLoader

Collector = Callable[[Path], list[dict[str, Any]]]
ALLOWED_SCANNERS = ("semgrep", "bandit", "trivy")
TOPOLOGY_SOURCES = ("fixture", "image")
LIVE_LABEL = "LIVE results are lost on restart."
LiveRunner = Callable[..., Awaitable[list[dict[str, Any]]]]


class RunBusy(ValueError):
    """One API scan already occupies this process."""


class RunRateLimited(ValueError):
    """The per-process run-start budget is exhausted."""


class LiveRuns:
    """In-memory S3 run status and admission policy, owned by one API process.

    All admission operations run without an await on the API event loop. Scanner work is
    delegated by live_run to threads. Retain at most twenty statuses and three starts/minute.
    """

    def __init__(self, runner: LiveRunner, db_path: Path) -> None:
        self.runner = runner
        self.db_path = db_path
        self.runs: dict[str, dict[str, Any]] = {}
        self.starts: deque[float] = deque()
        self.task: asyncio.Task[None] | None = None

    def start(self, scanners: Sequence[str]) -> dict[str, Any]:
        if self.task is not None and not self.task.done():
            raise RunBusy("a LIVE run is already busy")
        now = time.monotonic()
        while self.starts and now - self.starts[0] >= 60:
            self.starts.popleft()
        if len(self.starts) >= 3:
            raise RunRateLimited("at most three LIVE runs per minute per process")
        if not scanners or len(set(scanners)) != len(scanners) or any(
            name not in ALLOWED_SCANNERS for name in scanners
        ):
            raise ValueError("choose unique scanners from semgrep, bandit, trivy")
        self.starts.append(now)
        run_id = f"live-{uuid.uuid4().hex[:12]}"
        row: dict[str, Any] = {
            "run_id": run_id, "status": "running", "scanners": list(scanners),
            "case_ids": [], "started_at": datetime.now(UTC).isoformat(), "finished_at": None,
            "ephemeral": True, "label": LIVE_LABEL,
        }
        self.runs[run_id] = row
        while len(self.runs) > 20:
            del self.runs[next(iter(self.runs))]
        self.task = asyncio.create_task(self._execute(row))
        return dict(row)

    async def _execute(self, row: dict[str, Any]) -> None:
        try:
            results = await self.runner(
                REPO_ROOT / "demo_target" / "order_api", db_path=self.db_path,
                run_id=row["run_id"], scanners=tuple(row["scanners"]),
            )
            row.update(status="completed", case_ids=[result["case_id"] for result in results])
        except asyncio.CancelledError:
            row.update(status="failed", error="run interrupted")
            raise
        except Exception:
            # Provider errors may echo credentials. Return no exception text or request data.
            row.update(status="failed", error="LIVE run failed; inspect local scanner/model setup")
        finally:
            row["finished_at"] = datetime.now(UTC).isoformat()


async def live_run(
    target: Path, *, db_path: Path | None = None, output_dir: Path | None = None,
    llm: LLMClient | None = None, scanner: Any = None, run_id: str | None = None,
    collectors: Sequence[Collector] | None = None,
    scanners: Sequence[str] | None = None,
    topology_source: str | None = None,
) -> list[dict[str, Any]]:
    """Scan -> normalise -> publish/consume -> graph, pausing for human approvals.

    ``collectors`` add findings from the other scanners (default: bandit and the committed
    Trivy report); pass ``()`` to run on the injected Semgrep-style ``scanner`` only.
    ``topology_source`` (default ``PG_TOPOLOGY_SOURCE``, else ``fixture``): ``image`` asks the
    model to extract the topology from the architecture image once per run; a failed
    validation falls back to the hand-written fixture inside ``extract_topology``.
    """
    source = topology_source or os.environ.get("PG_TOPOLOGY_SOURCE", "fixture")
    if source not in TOPOLOGY_SOURCES:
        raise ValueError("PG_TOPOLOGY_SOURCE must be fixture or image")
    target = target.resolve()
    if target != (REPO_ROOT / "demo_target" / "order_api").resolve():
        raise ValueError("LIVE scanning is limited to demo_target/order_api")
    selected = tuple(ALLOWED_SCANNERS if scanners is None else scanners)
    if not selected or len(set(selected)) != len(selected) or any(
        name not in ALLOWED_SCANNERS for name in selected
    ):
        raise ValueError("choose unique scanners from semgrep, bandit, trivy")
    client = llm or make_llm()
    scanner = scanner or SemgrepRunner(timeout=45.0)
    db_path = db_path or default_db_path()
    run_id = run_id or f"live-{uuid.uuid4().hex[:12]}"
    results = await asyncio.to_thread(scanner.run, target) if "semgrep" in selected else []
    payloads = [normalize(result, root=target).to_payload() for result in results]
    defaults = tuple(collect for name, collect in (
        ("bandit", bandit_findings), ("trivy", trivy_findings)) if name in selected)
    if scanners is None:
        defaults = DEFAULT_COLLECTORS
    for collect in (defaults if collectors is None else collectors):
        payloads.extend(await asyncio.to_thread(collect, target))
    payloads = merge_findings(group_dependency_findings(payloads))
    topology = None
    if source == "image" and payloads:
        topology = await asyncio.to_thread(
            extract_topology, llm=client, session=f"pg-{run_id}-topology")
    bus = InMemoryBus()
    watchdog = BusWatchdog()
    inbox: list[Message] = []
    unsubscribe = bus.subscribe(FINDINGS_TOPIC, inbox.append)
    for finding in payloads:
        msg = bus.publish(FINDINGS_TOPIC, finding, key=finding["case_id"])
        watchdog.observe_publish(msg.offset)
    unsubscribe()
    statuses = []
    for message in inbox:
        finding = message.value
        watchdog.observe_processed(message.offset)
        file = (target / finding["file"]).resolve()
        if target not in file.parents or not file.is_file():
            raise ValueError("scanner reported a file outside the demo target")
        output = (output_dir or db_path.parent / "pulseguard-bundles") / run_id / finding["case_id"]
        deps = GraphDeps(
            target_root=target, output_dir=output, llm=client, scanner=scanner,
            bus_health=watchdog.health(), topology=topology,
        )
        state = {
            "finding": finding, "code": file.read_text(encoding="utf-8"),
            "run_id": run_id, "mode": "live", "bus_health": deps.bus_health,
        }
        if topology is not None:
            state["topology_extraction"] = topology
        status = await start_case(state, deps, db_path)
        statuses.append(status)
    return statuses


def bandit_findings(target: Path) -> list[dict[str, Any]]:
    """Bandit pattern findings; an unavailable bandit contributes nothing."""
    if not BanditRunner.available():
        return []
    return [normalize_bandit(result, root=target).to_payload()
            for result in BanditRunner().run(target)]


def trivy_findings(target: Path) -> list[dict[str, Any]]:
    """Findings from the committed Trivy report; provenance decides ``recorded``."""
    report = target / "scan" / "trivy-report.json"
    if not report.is_file():
        return []
    return [normalize_trivy(vuln).to_payload()
            for vuln in TrivyReportLoader(report).vulnerabilities()]


DEFAULT_COLLECTORS: tuple[Collector, ...] = (bandit_findings, trivy_findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", type=Path)
    group.add_argument("--resume", metavar="CASE_ID")
    parser.add_argument("--decision", choices=("approve", "reject"))
    parser.add_argument("--actor")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--env-file", type=Path, help="Load process-only KEY=VALUE configuration")
    args = parser.parse_args(argv)
    if args.env_file:
        try:
            load_env_file(args.env_file)
        except ValueError as exc:
            parser.error(str(exc))
    if args.resume:
        if not args.decision or not args.actor:
            parser.error("--resume requires --decision and --actor")
        statuses = [asyncio.run(resume_case(args.resume, args.decision, args.actor))]
    else:
        if args.decision or args.actor:
            parser.error("decisions require --resume")
        statuses = asyncio.run(live_run(args.target, output_dir=args.output_dir))
    print(json.dumps([{
        "case_id": status["case_id"], "awaiting_approval": status["awaiting_approval"],
        "review_status": status["values"].get("review_status"),
        "review_reason": status["values"].get("review_reason", ""),
        "bundle": status["values"].get("bundle", {}).get("output_dir"),
    } for status in statuses], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

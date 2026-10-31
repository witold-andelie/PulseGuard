"""Local LIVE entry point using revio ``src/revio/agent/runner.py`` and
quant-foundation-gat ``src/quant_alpha/streaming/demo_signals.py`` patterns.

No API run-start endpoint is exposed in S1. Approval can be resumed by this CLI or the local API.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from pulseguard.agents.graph import GraphDeps
from pulseguard.agents.llm import LLMClient, make_llm
from pulseguard.agents.runner import resume_case, start_case
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


async def live_run(
    target: Path, *, db_path: Path | None = None, output_dir: Path | None = None,
    llm: LLMClient | None = None, scanner: Any = None, run_id: str | None = None,
    collectors: Sequence[Collector] | None = None,
) -> list[dict[str, Any]]:
    """Scan -> normalise -> publish/consume -> graph, pausing for every approval.

    ``collectors`` add findings from the other scanners (default: bandit and the committed
    Trivy report); pass ``()`` to run on the injected Semgrep-style ``scanner`` only.
    """
    target = target.resolve()
    if target != (REPO_ROOT / "demo_target" / "order_api").resolve():
        raise ValueError("S1 LIVE scanning is limited to demo_target/order_api")
    client = llm or make_llm()
    scanner = scanner or SemgrepRunner(timeout=45.0)
    db_path = db_path or default_db_path()
    run_id = run_id or f"live-{uuid.uuid4().hex[:12]}"
    results = await asyncio.to_thread(scanner.run, target)
    payloads = [normalize(result, root=target).to_payload() for result in results]
    for collect in (DEFAULT_COLLECTORS if collectors is None else collectors):
        payloads.extend(await asyncio.to_thread(collect, target))
    payloads = merge_findings(group_dependency_findings(payloads))
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
            bus_health=watchdog.health(),
        )
        status = await start_case({
            "finding": finding, "code": file.read_text(encoding="utf-8"),
            "run_id": run_id, "mode": "live", "bus_health": deps.bus_health,
        }, deps, db_path)
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

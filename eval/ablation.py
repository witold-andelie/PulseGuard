"""Sprint 3 ablations using SymbAI-Taint ``src/evaluation/`` discipline.

Uses today's public PulseGuard scanner/evidence/adjudication seams. No model is
constructed implicitly: library callers inject LLMClient; CLI callers opt in with
--env-file. This measures adjudication, not the full governed remediation pipeline.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import platform
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from eval.labels import (
    LINE_WINDOW,
    Site,
    extract_labels,
    finding_class,
    match_site,
    strip_annotations,
)
from eval.metrics import compute_metrics
from eval.report import build_report, render_markdown, write_report
from pulseguard.agents.adjudicator import adjudicate
from pulseguard.agents.bands import DEFAULT_BANDS, Bands
from pulseguard.agents.llm import LLMClient, LLMConfigError, make_llm
from pulseguard.contracts.models import Finding
from pulseguard.env import load_env_file
from pulseguard.evidence import CODE_HEADER, build_hard_evidence, code_excerpt, render_block
from pulseguard.scanners.bandit import BanditError, BanditResult, BanditRunner, BanditUnavailable
from pulseguard.scanners.normalize import normalize, normalize_bandit
from pulseguard.scanners.semgrep import (
    DataflowTrace,
    SemgrepError,
    SemgrepResult,
    SemgrepRunner,
    SemgrepUnavailable,
    TraceLine,
)

MODES = ("semgrep", "bandit", "llm", "neurosymbolic")


class Scanner[Result](Protocol):
    """Injectable public runner.run(target) seam, independent of executables."""

    def run(self, target: Path) -> list[Result]: ...


@dataclass
class Hit:
    """A normalised scanner hit with its optional labelled match."""

    finding: Finding
    trace: DataflowTrace | None
    site: Site | None


def _path(file: str, target: Path) -> Path:
    path = Path(file.replace("\\", "/"))
    if not path.is_absolute():
        # Public runners may return cwd-relative or target-relative paths.
        cwd_path = path.resolve()
        path = cwd_path if cwd_path.is_relative_to(target) else target / path
    path = path.resolve()
    if not path.is_relative_to(target):
        raise ValueError("scanner source is outside the evaluation target")
    return path


def excerpt(code: str, line: int, *, python: bool = True) -> str:
    """Strip both labels before selecting the function, preserving real line numbers.

    Manifests have no function: provide a bounded, annotation-free manifest slice.
    Unlabelled module-level scanner hits use the public helper's bounded fallback.
    """
    clean = strip_annotations(code)
    if python:
        return code_excerpt(clean, line)
    lines = clean.splitlines()
    return "\n".join(f"{i}: {lines[i - 1]}"
                     for i in range(max(1, line - 3), min(len(lines), line + 5) + 1))


def _clean_trace(trace: DataflowTrace | None, code: str) -> DataflowTrace | None:
    if trace is None:
        return None
    lines = strip_annotations(code).splitlines()

    def clean(step: TraceLine | None) -> TraceLine | None:
        if step is None:
            return None
        if not 1 <= step.line <= len(lines):
            raise ValueError("scanner trace line is outside its source file")
        return TraceLine(step.line, lines[step.line - 1].strip())

    intermediates = [clean(step) for step in trace.intermediates]
    return DataflowTrace(clean(trace.source), [step for step in intermediates if step is not None],
                         clean(trace.sink))


def _candidate(site: Site) -> Finding:
    # Class selects the question; the truth label and reason never enter the prompt.
    fingerprint = hashlib.sha256(site.site_id.encode()).hexdigest()
    return Finding(case_id=f"EVAL-{fingerprint[:16]}", fingerprint=fingerprint,
                   rule_id=f"eval-{site.vulnerability_class}", file=site.file,
                   line=max(site.line, site.start_line))


def _completed(
    sites: list[Site], flagged: set[str], *, candidates: int, decisions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {"status": "completed", "reason": None,
            "metrics": compute_metrics(sites, flagged).to_dict(),
            "by_class": {cls: compute_metrics(
                [s for s in sites if s.vulnerability_class == cls],
                flagged & {s.site_id for s in sites if s.vulnerability_class == cls},
            ).to_dict() for cls in sorted({s.vulnerability_class for s in sites})},
            "flagged_sites": sorted(flagged), "candidates": candidates,
            "model_calls": len(decisions),
            "model_failures": sum(d["unusable_reply"] for d in decisions),
            "decisions": decisions}


def _not_run(reason: str) -> dict[str, Any]:
    return {"status": "not run", "reason": reason, "metrics": None}


def _failure(exc: Exception) -> str:
    # Do not record environment dumps or verbose scanner stack traces.
    if "CertOpenSystemStore" in str(exc):
        return f"{type(exc).__name__}: CertOpenSystemStore returned NULL"
    return type(exc).__name__ + ": " + str(exc).splitlines()[0][:200]


def _version(scanner: str) -> str:
    try:
        return importlib.metadata.version(scanner)
    except importlib.metadata.PackageNotFoundError:
        return "unknown (injected runner or external executable)"


def run_ablation(
    target: str | Path, *, modes: Iterable[str] = MODES, llm: LLMClient | None = None,
    semgrep: Scanner[SemgrepResult] | None = None, bandit: Scanner[BanditResult] | None = None,
    bands: Bands = DEFAULT_BANDS, line_window: int = LINE_WINDOW,
) -> dict[str, Any]:
    """Evaluate each label once per mode; never turn unavailable scans into no hits.

    Both neural modes need the complete Semgrep/Bandit union. Without either scan
    they are not run. LLM-only includes every label (even scanner misses) plus
    unmatched hits. Neuro-symbolic adjudicates scanner hits only, OR-ing duplicate
    confirmations at each site. Unmatched hits are retained outside the matrix.
    """
    selected = tuple(dict.fromkeys(modes))
    if not selected or set(selected) - set(MODES):
        raise ValueError(f"modes must be a nonempty subset of {','.join(MODES)}")
    if line_window < 0:
        raise ValueError("line_window must be nonnegative")
    target = Path(target).resolve()
    sites = extract_labels(target)
    if not sites:
        raise ValueError("target contains no labelled sites")
    neural = llm is not None and bool(set(selected) & {"llm", "neurosymbolic"})
    runners = {"semgrep": semgrep, "bandit": bandit}
    scans: dict[str, dict[str, Any]] = {}
    hits: dict[str, list[Hit]] = {}
    for name in ("semgrep", "bandit"):
        if name not in selected and not neural:
            scans[name] = {"status": "not run", "reason": "not needed for requested modes"}
            continue
        runner = runners[name]
        if runner is None:
            runner = SemgrepRunner(timeout=30) if name == "semgrep" else BanditRunner()
        try:
            results = runner.run(target)
            hits[name] = []
            for result in results:
                result = replace(result, path=str(_path(result.path, target)))
                finding = (normalize(result, target) if isinstance(result, SemgrepResult)
                           else normalize_bandit(result, target))
                site = match_site(finding, sites, target, line_window=line_window)
                hits[name].append(Hit(finding, result.trace, site))
            matched = sum(hit.site is not None for hit in hits[name])
            version = (_version(name) if isinstance(runner, (SemgrepRunner, BanditRunner))
                       else "not applicable (injected runner)")
            scans[name] = {"status": "completed", "version": version,
                           "runner": type(runner).__name__,
                           "hits": len(results), "matched_hits": matched,
                           "unmatched_hits": len(results) - matched,
                           "findings": [{"file": hit.finding.file, "line": hit.finding.line,
                                         "rule": hit.finding.rule_id,
                                         "site": hit.site.site_id if hit.site else None,
                                         "trace_available": hit.trace is not None}
                                        for hit in hits[name]]}
        except (SemgrepError, SemgrepUnavailable, BanditError, BanditUnavailable, OSError) as exc:
            hits.pop(name, None)
            scans[name] = {"status": "not run", "reason": _failure(exc)}

    rows: dict[str, dict[str, Any]] = {}
    for mode in selected:
        if mode in {"semgrep", "bandit"}:
            if mode not in hits:
                rows[mode] = _not_run(scans[mode]["reason"])
            else:
                flagged = {hit.site.site_id for hit in hits[mode] if hit.site}
                rows[mode] = _completed(sites, flagged, candidates=len(hits[mode]), decisions=[])
            continue
        if llm is None:
            rows[mode] = _not_run("no injected LLMClient or --env-file; no model calls made")
            continue
        missing = [name for name in ("semgrep", "bandit") if name not in hits]
        if missing:
            rows[mode] = _not_run("candidate union incomplete: " + ", ".join(missing))
            continue
        union = [*hits["semgrep"], *hits["bandit"]]
        candidates = ([(hit.finding, hit.site, hit.trace) for hit in union]
                      if mode == "neurosymbolic" else
                      [*[(_candidate(site), site, None) for site in sites],
                       *[(hit.finding, None, None) for hit in union if hit.site is None]])
        # Deduplicate identical unlabelled scanner candidates in the LLM-only union.
        if mode == "llm":
            candidates = list({(f.file, f.line, finding_class(f)): (f, s, t)
                               for f, s, t in candidates}.values())
        flagged = set()
        decisions = []
        for finding, site, trace in candidates:
            path = _path(finding.file, target)
            code = path.read_text(encoding="utf-8-sig")
            if mode == "llm":
                # Neutralise scanner rule identity for all code-only candidates.
                finding = finding.model_copy(update={"rule_id": f"eval-{finding_class(finding)}"})
                block = CODE_HEADER + "\n" + excerpt(
                    code, finding.line, python=path.suffix == ".py")
            else:
                items = build_hard_evidence(finding, _clean_trace(trace, code))
                block = render_block(items, strip_annotations(code), sink_line=finding.line)
            metadata: dict[str, Any] = {}
            result = adjudicate(finding, block, llm=llm, metadata=metadata)
            confirmed = (result.score >= 0.7 if mode == "llm" else
                         result.band != "abstained" and bands.band_for(result.score) == "confirmed")
            confirmed = confirmed and "error" not in metadata and result.band != "abstained"
            if confirmed and site:
                flagged.add(site.site_id)
            decisions.append({"file": finding.file, "line": finding.line,
                              "class": finding_class(finding),
                              "site": site.site_id if site else None,
                              "score": result.score, "band": result.band,
                              "flagged": confirmed, "model": result.model,
                              "unusable_reply": "error" in metadata,
                              "error_type": metadata.get("error")})
        rows[mode] = _completed(sites, flagged, candidates=len(candidates), decisions=decisions)

    hashes = {p.relative_to(target).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(target.rglob("*"))
              if p.is_file() and (p.suffix == ".py" or p.name == "requirements.txt")}
    return build_report(sites, rows, target=target.name, scanners=scans, corpus_hashes=hashes,
                        configuration={"python": platform.python_version(),
                                       "line_window": line_window, "llm_threshold": 0.7,
                                       "bands": {"confirmed_at": bands.confirmed_at,
                                                 "uncertain_at": bands.uncertain_at},
                                       "model": llm.model if neural else None,
                                       "scanner_union": ["semgrep", "bandit"],
                                       "trivy": "not included in these four modes"})


def main(argv: list[str] | None = None) -> int:
    """Run opted-in modes and write counts plus explicit unavailable-mode reasons."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--modes", default=",".join(MODES))
    parser.add_argument("--name", default="ablation", help="report filename stem")
    args = parser.parse_args(argv)
    modes = tuple(part.strip() for part in args.modes.split(","))
    try:
        llm = None
        if args.env_file and set(modes) & {"llm", "neurosymbolic"}:
            load_env_file(args.env_file)
            llm = make_llm()
        report = run_ablation(args.target, modes=modes, llm=llm)
        write_report(report, args.out, name=args.name)
    except (ValueError, OSError, LLMConfigError) as exc:
        parser.error(str(exc))
    print(render_markdown(report))
    # Partial results are useful artifacts, but requested unavailable scans signal failure.
    return int(any(row["status"] != "completed" for mode, row in report["modes"].items()
                   if mode in {"semgrep", "bandit"} or llm is not None))


if __name__ == "__main__":
    raise SystemExit(main())

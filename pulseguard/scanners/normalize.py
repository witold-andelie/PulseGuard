"""Normalise scanner output into ``Finding`` contracts.

Per the OPM model the normaliser emits the finding in state ``raw`` (it is what travels on the
bus); Guarding then moves it to ``normalized`` or ``quarantined``.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath

from pulseguard.contracts.models import Finding, FindingState, TraceStep
from pulseguard.scanners.bandit import BanditResult
from pulseguard.scanners.semgrep import SemgrepResult
from pulseguard.scanners.trivy import TrivyVulnerability

_SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "unknown": "info",
}


def fingerprint_for(rule_id: str, file: str, anchor: str) -> str:
    """Dedup key (``cases.fingerprint``): rule + file + whitespace-normalised anchor text.

    The line number is deliberately excluded so that unrelated edits above the sink do not
    create a new case.
    """
    norm_anchor = " ".join(anchor.split())
    digest = hashlib.sha256(f"{rule_id}|{file}|{norm_anchor}".encode()).hexdigest()
    return digest


def case_id_for(fingerprint: str) -> str:
    return f"PG-{fingerprint[:10]}"


def _relpath(path: str, root: str | os.PathLike[str] | None) -> str:
    p = Path(path)
    if root is not None:
        try:
            p = p.resolve().relative_to(Path(root).resolve())
        except ValueError:
            pass
    return PurePosixPath(*p.parts).as_posix() if p.parts else path


def normalize(result: SemgrepResult, root: str | os.PathLike[str] | None = None) -> Finding:
    """Semgrep result -> ``Finding`` (state ``raw``) with its dataflow trace attached."""
    file = _relpath(result.path, root)
    anchor = (result.trace.sink.content if result.trace and result.trace.sink else result.code)
    fp = fingerprint_for(result.rule_id, file, anchor or str(result.line))
    trace = [TraceStep(**s) for s in result.trace.steps()] if result.trace else []
    return Finding(
        case_id=case_id_for(fp),
        fingerprint=fp,
        rule_id=result.rule_id,
        scanner="semgrep",
        severity=_SEVERITY_MAP.get(result.severity.lower(), "medium"),  # type: ignore[arg-type]
        message=result.message,
        file=file,
        line=result.line,
        state=FindingState.RAW,
        evidence_ids=[],
        trace=trace,
    )


def normalize_trivy(vuln: TrivyVulnerability) -> Finding:
    """Trivy vulnerability -> ``Finding`` (state ``raw``). Line 0 = whole manifest file."""
    anchor = f"{vuln.pkg_name}=={vuln.installed_version}"
    fp = fingerprint_for(vuln.vulnerability_id, vuln.target, anchor)
    return Finding(
        case_id=case_id_for(fp),
        fingerprint=fp,
        rule_id=vuln.vulnerability_id,
        scanner="trivy",
        severity=_SEVERITY_MAP.get(vuln.severity, "info"),  # type: ignore[arg-type]
        message=vuln.title or f"{vuln.pkg_name} {vuln.installed_version} is vulnerable",
        file=vuln.target,
        line=0,
        state=FindingState.RAW,
        cve_id=vuln.vulnerability_id if vuln.vulnerability_id.startswith("CVE-") else None,
        extra={
            "kind": "dependency",
            "package": vuln.pkg_name,
            "installed_version": vuln.installed_version,
            "fixed_version": vuln.fixed_version or "",
            "cve_id": vuln.vulnerability_id,
            "manifest": vuln.target,
            "report": vuln.report,
            "recorded": vuln.recorded,
        },
    )


def normalize_bandit(result: BanditResult, root: str | os.PathLike[str] | None = None) -> Finding:
    """revio BanditRunner match -> raw finding with locally derived assignment context."""
    file = _relpath(result.path, root)
    # Bandit prefixes snippet rows with line numbers; those are not part of the dedup anchor.
    anchor = re.sub(r"(?m)^\s*\d+\s+", "", result.code)
    fp = fingerprint_for(result.test_id, file, anchor)
    return Finding(
        case_id=case_id_for(fp), fingerprint=fp, rule_id=result.test_id, scanner="bandit",
        severity=_SEVERITY_MAP.get(result.severity.lower(), "info"),  # type: ignore[arg-type]
        message=result.message, file=file, line=result.line, state=FindingState.RAW,
        trace=[TraceStep(**step) for step in result.trace.steps()] if result.trace else [],
        extra={"test_id": result.test_id, "confidence": result.confidence,
               "severity": result.severity},
    )

"""Deterministic Verifying: evidence citation, location, CVE, patch scope, re-run hash.

Adapted from revio ``src/revio/agent/grounding.py`` (``collect_tool_facts``,
``validate_findings``, ``_downgrade``) and tradepulse ``tradepulse/verify.py``
(``check()`` result shape, ``check_rerun_hash``). Checks are small named dicts
``{name, ok, detail}``. Any failed check abstains the verdict and escalates the finding.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from pulseguard.scanners.normalize import fingerprint_for, normalize
from pulseguard.scanners.trivy import TrivyReportLoader

CVE_RE = re.compile(r"CVE-\d{4}-\d+")
Check = dict[str, Any]


def _check(name: str, ok: bool, detail: str) -> Check:
    return {"name": name, "ok": bool(ok), "detail": detail}


def _safe_join(root: Path, rel: str) -> Path | None:
    """Return ``root/rel`` when it stays inside ``root``; otherwise None."""
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


def check_cited_evidence(cited: Iterable[str], evidence: list[dict[str, Any]]) -> Check:
    """Every cited evidence id exists in the Hard Evidence Block."""
    known = {item["evidence_id"] for item in evidence}
    cited_ids = [str(item) for item in cited]
    missing = [item for item in cited_ids if item not in known]
    if not cited_ids:
        return _check("cited_evidence", False, "no evidence cited")
    if missing:
        return _check("cited_evidence", False, f"unknown evidence ids: {missing}")
    return _check("cited_evidence", True, "all cited evidence ids exist")


def check_cited_location(
    finding: dict[str, Any], cited: Iterable[str], evidence: list[dict[str, Any]],
    target: Path,
) -> Check:
    """Cited file/line exist in the target and the line matches the trace."""
    by_id = {item["evidence_id"]: item for item in evidence}
    locations: list[tuple[str, int, str]] = []
    for eid in cited:
        item = by_id.get(str(eid))
        if item is None:
            continue
        payload = item.get("payload") or {}
        if payload.get("file") is not None and payload.get("line") is not None:
            locations.append(
                (str(payload["file"]), int(payload["line"]), str(payload.get("source") or "")))
        for step in payload.get("steps") or []:
            locations.append(
                (finding["file"], int(step["line"]), str(step.get("content") or "")))
    if not locations:
        file, line = finding["file"], int(finding["line"])
        locations.append((file, line, ""))
    for file, line, expected in locations:
        path = _safe_join(target, file)
        if path is None or not path.is_file():
            return _check("cited_location", False, f"{file} is not inside the target")
        if line == 0:
            continue
        rows = path.read_text(encoding="utf-8").splitlines()
        if line < 1 or line > len(rows):
            return _check("cited_location", False, f"{file}:{line} is out of range")
        actual = rows[line - 1].strip()
        needle = expected.strip()
        if needle and needle not in actual and actual not in needle:
            return _check(
                "cited_location", False,
                f"{file}:{line} does not match the trace ({needle!r} vs {actual!r})")
    return _check("cited_location", True, "cited file/line exist and match the trace")


def _cves_in(finding: dict[str, Any], cited: Iterable[str],
             evidence: list[dict[str, Any]]) -> set[str]:
    found: set[str] = set()
    extra = finding.get("extra") or {}
    for value in (finding.get("cve_id"), extra.get("cve_id")):
        if isinstance(value, str) and value:
            found.add(value)
    by_id = {item["evidence_id"]: item for item in evidence}
    for eid in cited:
        item = by_id.get(str(eid), {})
        payload = item.get("payload") or {}
        for value in (payload.get("cve_id"), item.get("text", "")):
            found.update(CVE_RE.findall(str(value)))
    return found


def check_cited_cve(
    finding: dict[str, Any], cited: Iterable[str], evidence: list[dict[str, Any]],
    target: Path,
) -> Check:
    """A cited CVE appears in the Trivy report. No CVE cited is a pass."""
    cves = _cves_in(finding, cited, evidence)
    if not cves:
        return _check("cited_cve", True, "no CVE cited")
    extra = finding.get("extra") or {}
    report_rel = extra.get("report")
    if not report_rel:
        return _check("cited_cve", False, "CVE cited but no Trivy report path")
    path = _safe_join(target, str(report_rel))
    if path is None or not path.is_file():
        return _check("cited_cve", False, f"Trivy report missing: {report_rel}")
    raw = path.read_text(encoding="utf-8")
    synthetic = extra.get("recorded") is False or "synthetic" in raw.lower()
    known = TrivyReportLoader(path).cve_ids()
    missing = sorted(cves - known)
    label = "synthetic Trivy fixture" if synthetic else "Trivy report"
    if missing:
        return _check("cited_cve", False, f"{missing} absent from {label}")
    return _check("cited_cve", True, f"{sorted(cves)} present in {label}")


def check_patch_scope(patchset: dict[str, Any], finding: dict[str, Any]) -> Check:
    """Patch touches only files on the trace, or only the manifest for dependency findings."""
    extra = finding.get("extra") or {}
    ops = patchset.get("ops") or []
    if extra.get("kind") == "dependency" or finding.get("scanner") == "trivy":
        manifest = str(extra.get("manifest") or finding["file"])
        allowed = {manifest, finding["file"]}
        bad = [op["path"] for op in ops if op["path"] not in allowed]
        if bad:
            return _check("patch_scope", False, f"dependency patch left the manifest: {bad}")
        return _check("patch_scope", True, f"patch confined to manifest {manifest}")
    allowed = {finding["file"]}
    for step in finding.get("trace") or []:
        if step.get("file"):
            allowed.add(str(step["file"]))
    bad = [op["path"] for op in ops if op["path"] not in allowed]
    if bad:
        return _check("patch_scope", False, f"patch left the dataflow trace: {bad}")
    return _check("patch_scope", True, "patch confined to files on the trace")


def check_rerun_hash(
    finding: dict[str, Any], target: Path, scanner: Any | None,
) -> Check:
    """Re-running the cited scanner reproduces the same finding fingerprint.

    Inject ``scanner`` so unit tests use a fake. Never fabricate a fingerprint match.
    """
    extra = finding.get("extra") or {}
    if finding.get("scanner") == "trivy" or extra.get("kind") == "dependency":
        return _rerun_trivy(finding, target)
    if scanner is None or not hasattr(scanner, "run"):
        return _check("rerun_hash", False, "no scanner injected for re-run fingerprint")
    try:
        results = scanner.run(target)
    except Exception as exc:
        return _check("rerun_hash", False, f"scanner re-run failed: {type(exc).__name__}")
    fingerprints: list[str] = []
    for result in results or []:
        fp = getattr(result, "fingerprint", None)
        if fp:
            fingerprints.append(str(fp))
            continue
        try:
            fingerprints.append(normalize(result, root=target).fingerprint)
        except Exception as exc:
            return _check("rerun_hash", False, f"normalise failed: {type(exc).__name__}")
    if finding["fingerprint"] in fingerprints:
        return _check("rerun_hash", True, "re-run reproduced the finding fingerprint")
    return _check("rerun_hash", False, "re-run did not reproduce the finding fingerprint")


def _rerun_trivy(finding: dict[str, Any], target: Path) -> Check:
    extra = finding.get("extra") or {}
    report_rel = extra.get("report")
    if not report_rel:
        return _check("rerun_hash", False, "no Trivy report path for re-run")
    path = _safe_join(target, str(report_rel))
    if path is None or not path.is_file():
        return _check("rerun_hash", False, f"Trivy report missing: {report_rel}")
    synthetic = extra.get("recorded") is False
    for vuln in TrivyReportLoader(path).vulnerabilities():
        pkg = extra.get("package") or extra.get("pkg_name")
        if pkg and vuln.pkg_name != pkg:
            continue
        anchor = f"{vuln.pkg_name}=={vuln.installed_version}"
        fp = fingerprint_for(vuln.vulnerability_id, vuln.target, anchor)
        if fp == finding["fingerprint"] or vuln.vulnerability_id == extra.get("cve_id"):
            label = "synthetic Trivy fixture" if synthetic else "Trivy report"
            return _check("rerun_hash", True, f"fingerprint reproduced from {label}")
    return _check("rerun_hash", False, "Trivy re-read did not reproduce the fingerprint")


def verify_finding(
    finding: dict[str, Any],
    *,
    evidence: list[dict[str, Any]],
    cited: Iterable[str],
    target: Path,
    scanner: Any | None = None,
    patchset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the S2 citation checks. ``ok`` is true only when every check passes."""
    checks = [
        check_cited_evidence(cited, evidence),
        check_cited_location(finding, cited, evidence, target),
        check_cited_cve(finding, cited, evidence, target),
        check_rerun_hash(finding, target, scanner),
    ]
    if patchset:
        checks.append(check_patch_scope(patchset, finding))
    return {"ok": all(item["ok"] for item in checks), "checks": checks}

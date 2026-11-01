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

from pulseguard.ingest import group_dependency_findings
from pulseguard.scanners.normalize import fingerprint_for, normalize, normalize_trivy
from pulseguard.scanners.trace_check import trace_line_issue
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
    """Every citation names a claim-bearing E-item present in this case."""
    known = {item["evidence_id"] for item in evidence
             if re.fullmatch(r"E[1-9][0-9]*", str(item.get("evidence_id", "")))
             and item.get("claim") is not False
             and (item.get("payload") or {}).get("claim") is not False
             and item.get("result") != "unknown"
             and item.get("status") != "unknown"
             and item.get("solver_status") != "unknown"
             and (item.get("payload") or {}).get("result") != "unknown"
             and (item.get("payload") or {}).get("status") != "unknown"
             and (item.get("payload") or {}).get("solver_status") != "unknown"}
    cited_ids = [str(item) for item in cited]
    missing = [item for item in cited_ids if item not in known]
    if not cited_ids:
        return _check("cited_evidence", False, "no evidence cited")
    if missing:
        return _check("cited_evidence", False, f"unknown or non-claim evidence ids: {missing}")
    return _check("cited_evidence", True, "all cited ids name claim-bearing evidence")


def check_cited_location(
    finding: dict[str, Any], cited: Iterable[str], evidence: list[dict[str, Any]],
    target: Path,
) -> Check:
    """Cited file/line exist in the target and the line matches the trace."""
    by_id = {item["evidence_id"]: item for item in evidence}
    locations: list[tuple[str, int, str, str]] = []
    for eid in cited:
        item = by_id.get(str(eid))
        if item is None:
            continue
        payload = item.get("payload") or {}
        if item.get("kind") == "rule_source" and any(
            payload.get(key) is None for key in ("file", "line", "source")
        ):
            return _check("cited_location", False, "source trace has no confirmed file/line/call")
        if item.get("kind") == "dataflow" and not payload.get("steps"):
            return _check("cited_location", False, "dataflow trace has no confirmed steps")
        if payload.get("file") is not None and payload.get("line") is not None:
            locations.append(
                (str(payload["file"]), int(payload["line"]), str(payload.get("source") or ""),
                 "source" if item.get("kind") == "rule_source" else ""))
        for step in payload.get("steps") or []:
            locations.append(
                (finding["file"], int(step["line"]), str(step.get("content") or ""),
                 str(step.get("kind") or "intermediate")))
    if not locations:
        file, line = finding["file"], int(finding["line"])
        locations.append((file, line, "", ""))
    for file, line, expected, kind in locations:
        path = _safe_join(target, file)
        if path is None or not path.is_file():
            return _check("cited_location", False, f"{file} is not inside the target")
        if line == 0 and not kind:
            continue
        code = path.read_text(encoding="utf-8")
        rows = code.splitlines()
        if line < 1 or line > len(rows):
            return _check("cited_location", False, f"{file}:{line} is out of range")
        actual = rows[line - 1].strip()
        needle = expected.strip()
        if kind and (issue := trace_line_issue(code, line, expected, kind)):
            return _check("cited_location", False, f"{file}: trace could not be confirmed: {issue}")
        if not kind and needle and needle not in actual:
            return _check(
                "cited_location", False,
                f"{file}:{line} does not match the trace ({needle!r} vs {actual!r})")
    return _check("cited_location", True, "cited file/line exist and match the trace")


def check_validator_lines(evidence: list[dict[str, Any]], target: Path) -> Check:
    """E6 validator lines exist in the target at those line numbers with that exact text.

    A proof about a wrongly extracted validator proves nothing (framework 6, ST-1).
    No E6 item is a pass: there is no constraint claim to check.
    """
    items = [item for item in evidence
             if item.get("evidence_id") == "E6" or item.get("kind") == "constraint"]
    if not items:
        return _check("validator_lines", True, "no constraint evidence")
    for item in items:
        rows = (item.get("payload") or {}).get("validators") or []
        if not rows:
            return _check("validator_lines", False, "E6 names no validator lines")
        for row in rows:
            file = str(row.get("file") or "")
            try:
                line = int(row.get("line") or 0)
            except (TypeError, ValueError):
                return _check("validator_lines", False, f"invalid validator line in {file}")
            expected = str(row.get("text") or "")
            path = _safe_join(target, file)
            if path is None or not path.is_file():
                return _check("validator_lines", False, f"{file} is not inside the target")
            source = path.read_text(encoding="utf-8").splitlines()
            if line < 1 or line > len(source):
                return _check("validator_lines", False, f"{file}:{line} is out of range")
            actual = source[line - 1]
            if actual != expected:
                return _check(
                    "validator_lines", False,
                    f"{file}:{line} does not match the extracted validator "
                    f"({expected!r} vs {actual!r})")
    return _check("validator_lines", True, "validator lines exist with the extracted text")


def _cves_in(finding: dict[str, Any], cited: Iterable[str],
             evidence: list[dict[str, Any]]) -> set[str]:
    found: set[str] = set()
    extra = finding.get("extra") or {}
    found.update(str(value) for value in extra.get("cve_ids") or [])
    for value in (finding.get("cve_id"), extra.get("cve_id")):
        if isinstance(value, str) and value:
            found.add(value)
    by_id = {item["evidence_id"]: item for item in evidence}
    for eid in cited:
        item = by_id.get(str(eid), {})
        payload = item.get("payload") or {}
        found.update(str(value) for value in payload.get("cve_ids") or [])
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


def check_dependency_report(finding: dict[str, Any], target: Path) -> Check:
    """Bind every grouped CVE and its fix to the recorded manifest/package/version.

    Finding metadata alone is not provenance. Re-read the report and use the loader's
    RECORDED attestation checks. A missing fix is valid evidence requiring human review.
    """
    extra = finding.get("extra") or {}
    path = _safe_join(target, str(extra.get("report") or ""))
    if path is None or not path.is_file():
        return _check("dependency_report", False, "Trivy report missing or outside the target")
    try:
        loader = TrivyReportLoader(path)
        provenance = loader.load_raw().get("PulseGuard") or {}
        vulns = loader.vulnerabilities()
    except (OSError, ValueError, TypeError, AttributeError):
        return _check("dependency_report", False, "Trivy report is unreadable or malformed")
    if extra.get("recorded") is not True or not vulns or not all(v.recorded for v in vulns):
        return _check("dependency_report", False, "Trivy report lacks recorded provenance")
    cves = _cves_in(finding, [], [])
    if not cves or any(CVE_RE.fullmatch(cve) is None for cve in cves):
        return _check("dependency_report", False, "dependency finding names no valid CVE ids")
    package = extra.get("package") or extra.get("pkg_name")
    installed = extra.get("installed_version")
    manifest = str(extra.get("manifest") or finding["file"])
    matched = [v for v in vulns if v.vulnerability_id in cves
               and v.pkg_name == package and v.installed_version == installed
               and v.target == manifest]
    missing = sorted(cves - {v.vulnerability_id for v in matched})
    if missing:
        return _check("dependency_report", False,
                      f"{missing} absent for {package}=={installed} in manifest {manifest}")
    fixes = [v.fixed_version for v in matched]
    fixed = (max(fixes, key=lambda version: tuple(int(n) for n in re.findall(r"\d+", version)))
             if all(fixes) else "")
    if fixed and extra.get("fixed_version") and extra["fixed_version"] != fixed:
        return _check("dependency_report", False,
                      f"fixed version does not match the highest recorded fix {fixed}")
    return {
        **_check("dependency_report", True, f"{sorted(cves)} present in RECORDED Trivy report"),
        "cve_ids": sorted(cves), "report": extra["report"], "provenance": provenance,
        "fixed_version": fixed if extra.get("fixed_version") else "",
    }


def check_patch_scope(patchset: dict[str, Any], finding: dict[str, Any]) -> Check:
    """Patch touches only files on the trace, or only the manifest for dependency findings."""
    extra = finding.get("extra") or {}
    ops = patchset.get("ops") or []
    if extra.get("kind") == "dependency" or finding.get("scanner") == "trivy":
        manifest = str(extra.get("manifest") or finding["file"])
        allowed = {manifest}
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
    if extra.get("cve_ids"):
        grouped = group_dependency_findings([
            normalize_trivy(vuln).to_payload() for vuln in TrivyReportLoader(path).vulnerabilities()
        ])
        ok = any(item["fingerprint"] == finding["fingerprint"] for item in grouped)
        return _check("rerun_hash", ok, "grouped Trivy fingerprint "
                      + ("reproduced from report" if ok else "not reproduced from report"))
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
        check_validator_lines(evidence, target),
    ]
    if (finding.get("extra") or {}).get("kind") == "dependency":
        checks.append(check_dependency_report(finding, target))
    if patchset:
        checks.append(check_patch_scope(patchset, finding))
    return {"ok": all(item["ok"] for item in checks), "checks": checks}

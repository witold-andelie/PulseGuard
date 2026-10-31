"""Ingest helpers: location de-dupe across scanners (framework 12).

Bandit and Semgrep can both report the same /order sink. They become one case;
Semgrep (taint trace) wins as the primary finding. Dependency findings never merge
with code findings.
"""

from __future__ import annotations

import re
from typing import Any

from pulseguard.contracts.models import Finding, FindingState
from pulseguard.scanners.normalize import case_id_for, fingerprint_for
from pulseguard.scanners.trivy import TrivyVulnerability

SCANNER_RANK = {"semgrep": 0, "bandit": 1, "trivy": 2}


def location_keys(finding: dict[str, Any]) -> set[tuple[str, int]]:
    """(file, line) pairs that identify this finding's location, including the trace."""
    extra = finding.get("extra") or {}
    if extra.get("kind") == "dependency" or finding.get("scanner") == "trivy":
        return set()
    file = str(finding["file"]).replace("\\", "/")
    keys = {(file, int(finding["line"]))}
    for step in finding.get("trace") or []:
        keys.add((file, int(step["line"])))
    return keys


def _rank(finding: dict[str, Any]) -> int:
    return SCANNER_RANK.get(str(finding.get("scanner") or ""), 9)


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def group_dependency_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One case per (manifest, package): the bump must clear every CVE on that pin.

    Trivy lists each CVE separately (requests 2.31.0 has three, fixed in 2.32.0, 2.32.4 and
    2.33.0). Separate cases would each bump to their own fixed version and leave the others
    open, so the grouped case targets the highest fixed version and keeps every CVE id.
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    out: list[dict[str, Any]] = []
    for finding in findings:
        extra = finding.get("extra") or {}
        if extra.get("kind") != "dependency":
            out.append(finding)
            continue
        key = (str(extra.get("manifest") or finding["file"]), str(extra.get("package")))
        if key not in groups:
            groups[key] = []
            out.append(finding)  # placeholder keeps first-seen order
        groups[key].append(finding)
    for members in groups.values():
        target = max(members, key=lambda f: _version_key(f["extra"].get("fixed_version") or ""))
        cve_ids = sorted({str(m["extra"]["cve_id"]) for m in members
                          if m["extra"].get("cve_id")})
        merged = {**target, "extra": {**target["extra"], "cve_ids": cve_ids}}
        if len(members) > 1:
            anchor = f"{merged['extra']['package']}=={merged['extra']['installed_version']}"
            fp = fingerprint_for(",".join(cve_ids), merged["extra"]["manifest"], anchor)
            merged.update(fingerprint=fp, case_id=case_id_for(fp),
                          message=f"{merged['extra']['package']} "
                                  f"{merged['extra']['installed_version']}: "
                                  f"{len(cve_ids)} CVEs, fixed in "
                                  f"{merged['extra']['fixed_version']}")
        out[out.index(members[0])] = merged
    return out


def merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse overlapping code findings into one case per location.

    The /order SQL injection reported by both Semgrep and bandit B608 becomes one case.
    """
    kept: list[dict[str, Any]] = []
    keys_of: list[set[tuple[str, int]]] = []
    for finding in findings:
        keys = location_keys(finding)
        if not keys:
            kept.append(finding)
            keys_of.append(set())
            continue
        match = next((i for i, existing in enumerate(keys_of) if existing & keys), None)
        if match is None:
            kept.append(finding)
            keys_of.append(keys)
            continue
        primary, other = kept[match], finding
        if _rank(other) < _rank(primary):
            primary, other = other, primary
            kept[match] = primary
        extra = dict(primary.get("extra") or {})
        also = list(extra.get("also_reported_by") or [])
        scanner = other.get("scanner")
        if scanner and scanner not in also and scanner != primary.get("scanner"):
            also.append(scanner)
        extra["also_reported_by"] = also
        primary["extra"] = extra
        keys_of[match] |= keys
    return kept


def finding_from_trivy(
    vuln: TrivyVulnerability, *,
    manifest: str = "requirements.txt",
    report: str = "scan/trivy-report.json",
    recorded: bool = False,
) -> Finding:
    """Finding.extra in the S2 shared contract shape. ``recorded=false`` means synthetic."""
    extra = {
        "kind": "dependency",
        "package": vuln.pkg_name,
        "installed_version": vuln.installed_version,
        "fixed_version": vuln.fixed_version or "",
        "cve_id": vuln.vulnerability_id,
        "manifest": manifest,
        "report": report,
        "recorded": recorded,
    }
    anchor = f"{vuln.pkg_name}=={vuln.installed_version}"
    fp = fingerprint_for(vuln.vulnerability_id, manifest, anchor)
    cve = vuln.vulnerability_id if str(vuln.vulnerability_id).startswith("CVE-") else None
    return Finding(
        case_id=case_id_for(fp),
        fingerprint=fp,
        rule_id=vuln.vulnerability_id,
        scanner="trivy",
        severity="high",
        message=vuln.title or f"{vuln.pkg_name} {vuln.installed_version} is vulnerable",
        file=manifest,
        line=0,
        state=FindingState.RAW,
        cve_id=cve,
        extra=extra,
    )

"""Load a committed Trivy JSON report (``trivy fs --format json``).

Framework 11.2: Trivy and its vulnerability DB are too heavy for the Render free tier, so the
report is generated in CI or locally, committed, and labelled RECORDED. This module only reads it.
Template: revio ``src/revio/layers/static/bandit.py`` runner pattern (a live ``TrivyRunner`` is
not part of S1).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TrivyVulnerability:
    vulnerability_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None
    severity: str
    target: str
    title: str = ""
    raw: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


class TrivyReportLoader:
    """Read vulnerabilities (and count misconfigurations / secrets) from a Trivy JSON report."""

    def __init__(self, report_path: str | os.PathLike[str]) -> None:
        self.report_path = Path(report_path)

    def load_raw(self) -> dict[str, Any]:
        data = json.loads(self.report_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{self.report_path}: Trivy report must be a JSON object")
        return data

    def vulnerabilities(self) -> list[TrivyVulnerability]:
        out: list[TrivyVulnerability] = []
        for result in self.load_raw().get("Results") or []:
            target = str(result.get("Target", ""))
            for v in result.get("Vulnerabilities") or []:
                out.append(
                    TrivyVulnerability(
                        vulnerability_id=str(v.get("VulnerabilityID", "UNKNOWN")),
                        pkg_name=str(v.get("PkgName", "")),
                        installed_version=str(v.get("InstalledVersion", "")),
                        fixed_version=v.get("FixedVersion") or None,
                        severity=str(v.get("Severity", "UNKNOWN")).lower(),
                        target=target,
                        title=str(v.get("Title", "")),
                        raw=v,
                    )
                )
        return out

    def cve_ids(self) -> set[str]:
        """All vulnerability ids in the report (used by the S2 citation check)."""
        return {v.vulnerability_id for v in self.vulnerabilities()}

    def summary(self) -> dict[str, int]:
        counts = {"vulnerabilities": 0, "misconfigurations": 0, "secrets": 0}
        for result in self.load_raw().get("Results") or []:
            counts["vulnerabilities"] += len(result.get("Vulnerabilities") or [])
            counts["misconfigurations"] += len(result.get("Misconfigurations") or [])
            counts["secrets"] += len(result.get("Secrets") or [])
        return counts

"""Load a committed Trivy JSON report (``trivy fs --format json``).

Framework 11.2: Render reads a bundled report; local recording uses the subprocess runner
adapted from revio ``src/revio/layers/static/bandit.py``. Provenance is explicit: unlabelled
or synthetic input always normalises with ``recorded=false``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
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
    report: str = "scan/trivy-report.json"
    recorded: bool = False


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
        data = self.load_raw()
        provenance = data.get("PulseGuard", {})
        recorded = (provenance.get("recorded") is True and provenance.get("label") == "RECORDED"
                    and bool(provenance.get("tool_version")) and bool(provenance.get("scanned_at")))
        for result in data.get("Results") or []:
            target = str(result.get("Target", "")).replace("\\", "/")
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
                        recorded=recorded,
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


class TrivyUnavailable(RuntimeError):
    """Trivy executable not found or could not be started."""


class TrivyError(RuntimeError):
    """Trivy scan failed; no synthetic fallback is substituted."""


class TrivyRunner:
    """Run a real filesystem vulnerability scan locally (revio subprocess pattern)."""

    def __init__(self, executable: str | None = None, timeout: float = 180.0,
                 cache_dir: str | os.PathLike[str] | None = None) -> None:
        self.executable = executable or os.environ.get("PG_TRIVY_BIN") or shutil.which("trivy")
        self.timeout = timeout
        self.cache_dir = cache_dir

    @staticmethod
    def available() -> bool:
        return bool(os.environ.get("PG_TRIVY_BIN") or shutil.which("trivy"))

    def run_json(self, target: str | os.PathLike[str]) -> dict[str, Any]:
        if not self.executable:
            raise TrivyUnavailable("trivy executable not found; set PG_TRIVY_BIN")
        command = [self.executable, "fs", "--format", "json", "--scanners", "vuln"]
        if self.cache_dir:
            command += ["--cache-dir", str(self.cache_dir)]
        try:
            proc = subprocess.run([*command, str(target)], capture_output=True,
                                  timeout=self.timeout, check=False)
        except OSError as exc:
            raise TrivyUnavailable(str(exc)) from exc
        except subprocess.TimeoutExpired as exc:
            raise TrivyError(f"trivy timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            raise TrivyError(f"trivy exited {proc.returncode}: "
                             f"{proc.stderr.decode('utf-8', 'replace')[:1500]}")
        try:
            data = json.loads(proc.stdout)
        except (ValueError, UnicodeError) as exc:
            raise TrivyError("trivy did not return valid JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
            raise TrivyError("trivy report has no Results list")
        return data

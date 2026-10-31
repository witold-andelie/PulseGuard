"""Sandbox Verifying (SD1.1): temp copy of the demo repo, apply patch, re-scan, pytest.

S1 gates: Semgrep finding count for the rule goes 1 -> 0, and the demo service's pytest suite
passes. Counterfactual [S2], PoC witness [S3] and z3 [ST-1] are not part of S1.

Status: structurally complete but only lightly exercised in the S1 skeleton - treat as a stub
until it runs in CI against a real patch. The workspace lives under the system temp dir (which
honours TMP/TEMP).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pulseguard.patching.patch import PatchApplier, PatchError, PatchSet, unified_diff
from pulseguard.scanners.semgrep import SemgrepError, SemgrepRunner, SemgrepUnavailable


@dataclass
class SandboxReport:
    passed: bool
    rescan_before: int | None = None
    rescan_after: int | None = None
    pytest_ok: bool | None = None
    pytest_tail: str = ""
    diff: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def feedback(self) -> str:
        """Short text handed back to the Remediator on failure."""
        parts = []
        if self.rescan_after:
            parts.append(f"re-scan still reports {self.rescan_after} finding(s)")
        if self.pytest_ok is False:
            parts.append("pytest failed:\n" + self.pytest_tail[-800:])
        parts += self.errors
        return "; ".join(parts) or "unknown failure"


class SandboxVerifier:
    def __init__(
        self,
        target_dir: str | os.PathLike[str],
        rule_id: str,
        tests_subdir: str = "tests",
        runner: SemgrepRunner | None = None,
        pytest_timeout: float = 120.0,
    ) -> None:
        self.target_dir = Path(target_dir)
        self.rule_id = rule_id
        self.tests_subdir = tests_subdir
        self.runner = runner or SemgrepRunner()
        self.pytest_timeout = pytest_timeout

    def _pytest(self, workdir: Path) -> tuple[bool, str]:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", self.tests_subdir],
            cwd=workdir, capture_output=True, text=True, timeout=self.pytest_timeout, check=False,
        )
        return proc.returncode == 0, (proc.stdout + proc.stderr)[-4000:]

    def verify(self, patchset: PatchSet) -> SandboxReport:
        report = SandboxReport(passed=False)
        with tempfile.TemporaryDirectory(prefix="pg-sandbox-") as tmp:
            work = Path(tmp) / self.target_dir.name
            shutil.copytree(self.target_dir, work,
                            ignore=shutil.ignore_patterns(
                                "__pycache__", "*.sqlite", ".pytest_cache"))
            try:
                report.rescan_before = self.runner.count(work, self.rule_id)
            except (SemgrepUnavailable, SemgrepError) as exc:
                report.errors.append(f"re-scan unavailable: {exc}")
            try:
                report.diff = unified_diff(PatchApplier(work).apply(patchset))
            except PatchError as exc:
                report.errors.append(f"patch did not apply: {exc}")
                return report
            if report.rescan_before is not None:
                try:
                    report.rescan_after = self.runner.count(work, self.rule_id)
                except (SemgrepUnavailable, SemgrepError) as exc:
                    report.errors.append(f"re-scan unavailable: {exc}")
            try:
                report.pytest_ok, report.pytest_tail = self._pytest(work)
            except (OSError, subprocess.TimeoutExpired) as exc:
                report.errors.append(f"pytest unavailable or timed out: {exc}")
        report.passed = (
            not report.errors
            and report.rescan_before == 1
            and report.rescan_after == 0
            and bool(report.pytest_ok)
        )
        return report

"""Sandbox Verifying (SD1.1): temp copy of the demo repo, apply patch, re-scan, pytest.

S1 gates: Semgrep finding count for the rule goes 1 -> 0, and the demo service's pytest suite
passes. S2 adds a manifest-check path for dependency bumps (not presented as a live Trivy scan).
PoC witness [S3] and z3 [ST-1] stay out of this module.

Subprocess pattern adapted from revio ``src/revio/layers/static/bandit.py``.
The workspace lives under the system temp dir (which honours TMP/TEMP).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from pulseguard.patching.patch import PatchApplier, PatchError, PatchSet, unified_diff
from pulseguard.scanners.semgrep import SemgrepError, SemgrepRunner, SemgrepUnavailable


class Scanner(Protocol):
    """Injectable deterministic scanner; unit tests never need Semgrep."""

    def count(self, target: str | os.PathLike[str], rule_id: str | None = None) -> int: ...


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
        return {**asdict(self), "feedback": "" if self.passed else self.feedback()}

    def feedback(self) -> str:
        """Short text handed back to the Remediator on failure."""
        parts = []
        if self.rescan_before != 1:
            parts.append(f"baseline count must be 1; got {self.rescan_before}")
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
        runner: Scanner | None = None,
        pytest_timeout: float = 120.0,
    ) -> None:
        self.target_dir = Path(target_dir)
        self.rule_id = rule_id
        self.tests_subdir = tests_subdir
        self.runner = runner or SemgrepRunner(timeout=45.0)
        self.pytest_timeout = pytest_timeout

    def _pytest(self, workdir: Path) -> tuple[bool, str]:
        env = dict(os.environ)
        # Parent test-selection options (e.g. --collect-only) must not weaken this gate.
        for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
            env.pop(key, None)
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "--basetemp", str(workdir / ".pytest-tmp"), self.tests_subdir],
            cwd=workdir, capture_output=True, text=True, timeout=self.pytest_timeout, check=False,
            env=env,
        )
        return proc.returncode == 0, (proc.stdout + proc.stderr)[-4000:]

    def verify(self, patchset: PatchSet) -> SandboxReport:
        report = SandboxReport(passed=False)
        with tempfile.TemporaryDirectory(prefix="pg-sandbox-") as tmp:
            work = Path(tmp) / "target"
            shutil.copytree(self.target_dir, work,
                            ignore=shutil.ignore_patterns(
                                "__pycache__", "*.sqlite*", "*.db", ".pytest_cache", ".git"))
            try:
                report.rescan_before = self.runner.count(work, self.rule_id)
            except (SemgrepUnavailable, SemgrepError) as exc:
                report.errors.append(f"re-scan unavailable: {exc}")
            try:
                report.diff = unified_diff(PatchApplier(work).apply(patchset))
                if not report.diff:
                    report.errors.append("patch made no source changes")
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

    def verify_dependency(
        self, patchset: PatchSet, *, package: str, installed: str, fixed: str,
        manifest: str = "requirements.txt",
    ) -> SandboxReport:
        """Manifest check + pytest. Not a live Trivy rescan (the committed report is evidence)."""
        report = SandboxReport(passed=False)
        pin_old, pin_new = f"{package}=={installed}", f"{package}=={fixed}"
        with tempfile.TemporaryDirectory(prefix="pg-sandbox-") as tmp:
            work = Path(tmp) / "target"
            shutil.copytree(self.target_dir, work,
                            ignore=shutil.ignore_patterns(
                                "__pycache__", "*.sqlite*", "*.db", ".pytest_cache", ".git"))
            man = work / manifest
            if not man.is_file():
                report.errors.append(f"manifest missing: {manifest}")
                return report
            before = man.read_text(encoding="utf-8")
            report.rescan_before = 1 if pin_old in before else 0
            try:
                report.diff = unified_diff(PatchApplier(work).apply(patchset))
                if not report.diff:
                    report.errors.append("patch made no source changes")
            except PatchError as exc:
                report.errors.append(f"patch did not apply: {exc}")
                return report
            after = man.read_text(encoding="utf-8")
            report.rescan_after = 0 if pin_old not in after and pin_new in after else 1
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

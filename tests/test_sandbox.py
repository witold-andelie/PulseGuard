"""S1 sandbox gates from revio patch/subprocess patterns, plus marked Semgrep integration."""

import subprocess
from types import SimpleNamespace

import pytest

from pulseguard.patching.patch import PatchOp, PatchSet
from pulseguard.patching.sandbox import SandboxVerifier
from pulseguard.paths import REPO_ROOT
from pulseguard.scanners.semgrep import SemgrepError, SemgrepRunner, SemgrepUnavailable
from tests.fakes import PATCH, FakeScanner

TARGET = REPO_ROOT / "demo_target" / "order_api"


@pytest.fixture(scope="module")
def real_semgrep():
    runner = SemgrepRunner(timeout=30.0)
    try:
        count = runner.count(TARGET, "flask-sqli-taint")
    except (SemgrepError, SemgrepUnavailable, OSError) as exc:
        reason = ("CertOpenSystemStore returned NULL" if "CertOpenSystemStore" in str(exc)
                  else str(exc).splitlines()[0])
        pytest.skip(f"Semgrep cannot run on this host: {reason}")
    assert count == 1, "real demo baseline must have exactly one finding"
    return runner


@pytest.mark.semgrep
@pytest.mark.parametrize("correct", [True, False])
def test_real_sandbox_parameterised_patch_and_noop(real_semgrep, correct):
    original = (TARGET / "routes.py").read_bytes()
    patchset = PatchSet.from_payload(PATCH) if correct else PatchSet(
        [PatchOp("routes.py", "conn.execute(q)", "conn.execute(q)")], "No-op negative control")
    report = SandboxVerifier(
        TARGET, "flask-sqli-taint", runner=real_semgrep,
    ).verify(patchset)
    assert report.rescan_before == 1
    assert report.rescan_after == (0 if correct else 1)
    assert report.pytest_ok is True, report.to_dict()
    assert report.passed is correct, report.to_dict()
    assert (TARGET / "routes.py").read_bytes() == original


def test_pytest_failure_cannot_pass(monkeypatch):
    monkeypatch.setattr(SandboxVerifier, "_pytest", lambda self, work: (False, "regression failed"))
    report = SandboxVerifier(TARGET, "flask-sqli-taint", runner=FakeScanner()).verify(
        PatchSet.from_payload(PATCH))
    assert not report.passed
    assert report.rescan_before == 1 and report.rescan_after == 0
    assert "regression failed" in report.to_dict()["feedback"]


def test_pytest_timeout_is_reported(monkeypatch):
    def timeout(self, work):
        raise subprocess.TimeoutExpired("pytest", 0.1)

    monkeypatch.setattr(SandboxVerifier, "_pytest", timeout)
    report = SandboxVerifier(TARGET, "flask-sqli-taint", runner=FakeScanner()).verify(
        PatchSet.from_payload(PATCH))
    assert not report.passed
    assert "timed out" in report.to_dict()["feedback"]


def test_baseline_must_be_one(monkeypatch):
    monkeypatch.setattr(SandboxVerifier, "_pytest", lambda self, work: (True, "3 passed"))
    report = SandboxVerifier(TARGET, "flask-sqli-taint", runner=FakeScanner([0, 0])).verify(
        PatchSet.from_payload(PATCH))
    assert not report.passed
    assert "baseline count must be 1" in report.to_dict()["feedback"]


def test_demo_pytest_does_not_inherit_test_selection(monkeypatch, tmp_path):
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "untrusted_plugin")

    def run(args, **kwargs):
        assert "PYTEST_ADDOPTS" not in kwargs["env"]
        assert "PYTEST_PLUGINS" not in kwargs["env"]
        assert str(tmp_path / ".pytest-tmp") in args
        assert kwargs["timeout"] == 120.0
        return SimpleNamespace(returncode=0, stdout="3 passed", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    assert SandboxVerifier(TARGET, "flask-sqli-taint", runner=FakeScanner())._pytest(tmp_path) == (
        True, "3 passed")

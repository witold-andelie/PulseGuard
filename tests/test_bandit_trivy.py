"""Real bandit on the demo target; real Trivy only when the binary is present."""

import json
import os
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from pulseguard.paths import REPO_ROOT

DEMO = REPO_ROOT / "demo_target" / "order_api" / "routes.py"


def test_bandit_flags_b608_on_demo_target():
    proc = subprocess.run(
        [sys.executable, "-m", "bandit", "-f", "json", "-q", str(DEMO)],
        capture_output=True, text=True, check=False,
    )
    data = json.loads(proc.stdout or proc.stderr)
    ids = {item.get("test_id") for item in data.get("results") or []}
    assert "B608" in ids


@pytest.mark.trivy
def test_real_trivy_if_installed(tmp_path):
    exe = os.environ.get("PG_TRIVY_BIN") or shutil.which("trivy")
    if exe is None:
        pytest.skip("trivy executable not installed (set PG_TRIVY_BIN)")
    target = tmp_path / "req"
    target.mkdir()
    # A pinned requirement: Trivy omits "Results" entirely when nothing resolves to a package.
    (target / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    cmd = [exe, "fs", "--quiet", "--format", "json", "--scanners", "vuln", "--exit-code", "0"]
    if os.environ.get("PG_TRIVY_CACHE_DIR"):
        cmd += ["--cache-dir", os.environ["PG_TRIVY_CACHE_DIR"]]
    proc = subprocess.run(cmd + [str(target)], capture_output=True, text=True, timeout=180,
                          check=False)
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        pytest.skip(
            "trivy could not scan: "
            + ((proc.stderr or proc.stdout or str(proc.returncode)).splitlines() or ["?"])[-1]
        )
    data = json.loads(proc.stdout)
    assert data["SchemaVersion"] == 2
    vulns = [v for r in data.get("Results") or [] for v in r.get("Vulnerabilities") or []]
    assert any(v["PkgName"] == "requests" for v in vulns)


def test_trivy_smoke_honours_configured_binary(tmp_path, monkeypatch):
    """The smoke test must use PG_TRIVY_BIN even when Trivy is absent from PATH."""
    monkeypatch.setenv("PG_TRIVY_BIN", "configured-trivy")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({
            "SchemaVersion": 2, "Results": [{"Vulnerabilities": [{"PkgName": "requests"}]}],
        }))

    monkeypatch.setattr(subprocess, "run", run)
    test_real_trivy_if_installed(tmp_path)
    assert calls[0][0] == "configured-trivy"

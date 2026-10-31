"""Real bandit on the demo target; real Trivy only when the binary is present."""

import json
import shutil
import subprocess
import sys

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
    exe = shutil.which("trivy")
    if exe is None:
        pytest.skip("trivy executable not installed")
    target = tmp_path / "req"
    target.mkdir()
    (target / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")
    proc = subprocess.run(
        [exe, "fs", "--quiet", "--format", "json", "--exit-code", "0", str(target)],
        capture_output=True, text=True, timeout=90, check=False,
    )
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        pytest.skip(
            "trivy could not scan: "
            + ((proc.stderr or proc.stdout or str(proc.returncode)).splitlines() or ["?"])[-1]
        )
    data = json.loads(proc.stdout)
    assert "Results" in data

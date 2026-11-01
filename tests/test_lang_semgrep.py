"""Original local rules: every vulnerable/safe fixture pair, using real Semgrep."""

from pathlib import Path

import pytest

from pulseguard.lang import _RULES
from pulseguard.paths import rules_dir
from pulseguard.scanners.semgrep import SemgrepError, SemgrepRunner, SemgrepUnavailable

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "lang"
RULES = {**_RULES, "python": "flask-sqli-taint.yaml"}
CASES = sorted(p for p in FIXTURES.glob("*/*")
               if p.parent.name in RULES and p.name.startswith(("vulnerable_", "safe_")))


@pytest.fixture(scope="module")
def semgrep_available():
    # Probe the existing Python rule first. Once the engine works, failures in
    # the new rules must fail these tests, not masquerade as availability skips.
    try:
        SemgrepRunner(timeout=30).run(ROOT / "demo_target/order_api", with_traces=False)
    except (SemgrepUnavailable, SemgrepError) as exc:
        reason = ("CertOpenSystemStore returned NULL" if "CertOpenSystemStore" in str(exc)
                  else str(exc)[:300])
        pytest.skip(f"Semgrep cannot run on this host: {reason}")


@pytest.mark.semgrep
@pytest.mark.parametrize("path", CASES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_vulnerable_and_safe_pairs(semgrep_available, path):
    runner = SemgrepRunner(rules=rules_dir() / RULES[path.parent.name], timeout=30)
    hits = runner.run(path, with_traces=False)
    if path.name.startswith("vulnerable_"):
        assert hits, f"missed vulnerable SQL text in {path.name}"
    else:
        assert not hits, f"flagged bound parameters in {path.name}"

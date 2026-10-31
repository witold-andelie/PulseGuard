"""Merge-time regressions: scanner collectors and per-package dependency grouping."""

import pytest

from pulseguard.ingest import group_dependency_findings, merge_findings
from pulseguard.paths import REPO_ROOT
from pulseguard.run import bandit_findings, trivy_findings
from pulseguard.scanners.bandit import BanditRunner

TARGET = REPO_ROOT / "demo_target" / "order_api"


def dep(cve: str, fixed: str) -> dict:
    return {
        "case_id": f"PG-{cve}", "fingerprint": cve, "rule_id": cve, "scanner": "trivy",
        "file": "requirements.txt", "line": 0, "message": cve,
        "extra": {"kind": "dependency", "package": "requests", "installed_version": "2.31.0",
                  "fixed_version": fixed, "cve_id": cve, "manifest": "requirements.txt",
                  "report": "scan/trivy-report.json", "recorded": True},
    }


def test_cves_on_one_pin_become_one_case_at_the_highest_fixed_version():
    code = {"case_id": "PG-code", "scanner": "semgrep", "file": "routes.py", "line": 38,
            "extra": {}}
    out = group_dependency_findings([
        dep("CVE-A", "2.32.0"), code, dep("CVE-B", "2.33.0"), dep("CVE-C", "2.32.4")])
    assert [f["scanner"] for f in out] == ["trivy", "semgrep"]
    grouped = out[0]
    assert grouped["extra"]["fixed_version"] == "2.33.0"
    assert grouped["extra"]["cve_ids"] == ["CVE-A", "CVE-B", "CVE-C"]
    assert grouped["case_id"] not in {"PG-CVE-A", "PG-CVE-B", "PG-CVE-C"}


def test_single_cve_keeps_its_identity():
    only = group_dependency_findings([dep("CVE-A", "2.32.0")])
    assert only[0]["case_id"] == "PG-CVE-A"
    assert only[0]["extra"]["cve_ids"] == ["CVE-A"]


def test_committed_trivy_report_yields_one_recorded_requests_case():
    grouped = group_dependency_findings(trivy_findings(TARGET))
    assert len(grouped) == 1
    extra = grouped[0]["extra"]
    assert (extra["package"], extra["fixed_version"], extra["recorded"]) == (
        "requests", "2.33.0", True)
    assert len(extra["cve_ids"]) == 3


@pytest.mark.skipif(not BanditRunner.available(), reason="bandit not installed")
def test_default_bandit_collector_returns_payloads_for_the_demo_target():
    found = bandit_findings(TARGET)
    assert found, "bandit findings must reach the pipeline, not be filtered out"
    assert all(f["scanner"] == "bandit" and "fingerprint" in f for f in found)
    files = {f["file"] for f in found}
    assert "routes.py" in files
    merged = merge_findings(found)
    # /order and /order_by_number stay separate cases; scenario 4 lives in order_note.py.
    assert {(f["file"], f["rule_id"]) for f in merged} >= {("routes.py", "B608")}

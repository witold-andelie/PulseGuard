"""Named verify checks (revio grounding.py + tradepulse verify.py check() shape)."""

from pathlib import Path

import pytest

from pulseguard.ingest import finding_from_trivy, group_dependency_findings
from pulseguard.paths import REPO_ROOT
from pulseguard.run import trivy_findings
from pulseguard.scanners.trivy import TrivyReportLoader
from pulseguard.verify import (
    check_cited_cve,
    check_cited_evidence,
    check_cited_location,
    check_dependency_report,
    check_patch_scope,
    check_rerun_hash,
    check_validator_lines,
    verify_finding,
)
from tests.fakes import EchoScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_cited_evidence_pass_and_fail():
    evidence = [{"evidence_id": "E1", "kind": "rule_source", "text": "x", "payload": {}}]
    assert check_cited_evidence(["E1"], evidence)["ok"]
    assert not check_cited_evidence(["E9"], evidence)["ok"]
    assert not check_cited_evidence([], evidence)["ok"]


@pytest.mark.parametrize(("eid", "payload"), [
    ("L1", {}), ("E6", {"claim": False}), ("E6", {"result": "unknown"}),
    ("E6", {"solver_status": "unknown"}),
])
def test_present_but_non_claim_evidence_cannot_be_cited(eid, payload):
    evidence = [{"evidence_id": eid, "kind": "constraint", "payload": payload}]
    assert not check_cited_evidence([eid], evidence)["ok"]


def test_cited_location_pass_and_fail(tmp_path):
    (tmp_path / "routes.py").write_text('a = request.args.get("id")\nb = 2\n', encoding="utf-8")
    finding = {"file": "routes.py", "line": 1, "fingerprint": "a" * 16, "extra": {}}
    evidence = [{"evidence_id": "E1", "kind": "rule_source", "text": "x",
                 "payload": {"file": "routes.py", "line": 1,
                             "source": 'request.args.get("id")'}}]
    assert check_cited_location(finding, ["E1"], evidence, tmp_path)["ok"]
    evidence[0]["payload"]["source"] = "missing"
    assert not check_cited_location(finding, ["E1"], evidence, tmp_path)["ok"]
    escaped = [{"evidence_id": "E1", "kind": "rule_source", "text": "x",
                "payload": {"file": "../secret.py", "line": 1, "source": "x"}}]
    assert not check_cited_location(finding, ["E1"], escaped, tmp_path)["ok"]


def test_cited_cve_pass_fail_and_none(tmp_path):
    dest = tmp_path / "scan"
    dest.mkdir()
    src = FIXTURES / "dependency" / "scan" / "trivy-report.json"
    (dest / "trivy-report.json").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    finding = {
        "file": "requirements.txt", "line": 0, "fingerprint": "a" * 16,
        "cve_id": "CVE-2024-0001",
        "extra": {"cve_id": "CVE-2024-0001", "report": "scan/trivy-report.json",
                  "recorded": False},
    }
    evidence = [{"evidence_id": "E1", "kind": "rule_source", "text": "CVE-2024-0001",
                 "payload": {"cve_id": "CVE-2024-0001"}}]
    ok = check_cited_cve(finding, ["E1"], evidence, tmp_path)
    assert ok["ok"]
    assert "synthetic" in ok["detail"]
    finding["cve_id"] = "CVE-1999-9999"
    finding["extra"]["cve_id"] = "CVE-1999-9999"
    evidence[0]["text"] = "CVE-1999-9999"
    evidence[0]["payload"]["cve_id"] = "CVE-1999-9999"
    assert not check_cited_cve(finding, ["E1"], evidence, tmp_path)["ok"]
    clean = {"file": "routes.py", "line": 1, "fingerprint": "a" * 16, "extra": {}}
    assert check_cited_cve(clean, ["E1"], [{"evidence_id": "E1", "kind": "rule_source",
                                           "text": "x", "payload": {}}], tmp_path)["ok"]


def test_patch_scope_code_and_dependency():
    code = {"file": "routes.py", "scanner": "semgrep", "extra": {}, "trace": []}
    assert check_patch_scope(
        {"ops": [{"path": "routes.py", "old": "a", "new": "b"}]}, code)["ok"]
    assert not check_patch_scope(
        {"ops": [{"path": "other.py", "old": "a", "new": "b"}]}, code)["ok"]
    dep = {"file": "requirements.txt", "scanner": "trivy",
           "extra": {"kind": "dependency", "manifest": "requirements.txt"}}
    assert check_patch_scope(
        {"ops": [{"path": "requirements.txt", "old": "a==1", "new": "a==2"}]}, dep)["ok"]
    assert not check_patch_scope(
        {"ops": [{"path": "routes.py", "old": "a", "new": "b"}]}, dep)["ok"]
    assert not check_patch_scope(
        {"ops": [{"path": "routes.py", "old": "a", "new": "b"}]},
        {**dep, "file": "routes.py"})["ok"]


def test_grouped_dependency_verification_checks_all_cves_and_reproduces_group_hash():
    target = REPO_ROOT / "demo_target" / "order_api"
    finding, = group_dependency_findings(trivy_findings(target))
    assert check_cited_cve(finding, [], [], target)["ok"]
    assert check_dependency_report(finding, target)["ok"]
    assert check_rerun_hash(finding, target, None)["ok"]
    # A primary CVE match cannot rescue an unreproducible grouped fingerprint.
    assert not check_rerun_hash({**finding, "fingerprint": "ab" * 32}, target, None)["ok"]
    finding["extra"]["cve_ids"].append("CVE-1999-9999")
    assert not check_cited_cve(finding, [], [], target)["ok"]
    assert not check_dependency_report(finding, target)["ok"]


def test_rerun_hash_injected_scanner_and_trivy(tmp_path):
    finding = {"fingerprint": "ab" * 16, "file": "routes.py", "scanner": "semgrep", "extra": {}}
    assert check_rerun_hash(finding, tmp_path, EchoScanner(finding))["ok"]
    other = EchoScanner({**finding, "fingerprint": "cd" * 16})
    assert not check_rerun_hash(finding, tmp_path, other)["ok"]
    assert not check_rerun_hash(finding, tmp_path, None)["ok"]
    report = FIXTURES / "dependency" / "scan" / "trivy-report.json"
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "trivy-report.json").write_text(report.read_text(encoding="utf-8"),
                                                        encoding="utf-8")
    vuln = TrivyReportLoader(tmp_path / "scan" / "trivy-report.json").vulnerabilities()[0]
    dep = finding_from_trivy(vuln, recorded=False).to_payload()
    assert check_rerun_hash(dep, tmp_path, None)["ok"]


def test_verify_finding_ok_requires_every_check(tmp_path):
    (tmp_path / "routes.py").write_text('sink(request.args.get("id"))\n', encoding="utf-8")
    finding = {
        "file": "routes.py", "line": 1, "fingerprint": "ab" * 16, "scanner": "semgrep",
        "extra": {}, "trace": [{"kind": "sink", "line": 1,
                                 "content": 'sink(request.args.get("id"))'}],
    }
    evidence = [{"evidence_id": "E1", "kind": "rule_source", "text": "x",
                 "payload": {"file": "routes.py", "line": 1,
                             "source": 'request.args.get("id")'}}]
    report = verify_finding(
        finding, evidence=evidence, cited=["E1"], target=tmp_path,
        scanner=EchoScanner(finding),
    )
    assert report["ok"]
    assert {c["name"] for c in report["checks"]} >= {
        "cited_evidence", "cited_location", "cited_cve", "rerun_hash", "validator_lines"}
    assert check_validator_lines(evidence, tmp_path)["ok"]

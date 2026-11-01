"""End-to-end demo scenarios 1–4 with fake scanners/fixtures (framework 13)."""

import asyncio
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pulseguard.agents.graph import GraphDeps
from pulseguard.agents.runner import resume_case, start_case
from pulseguard.api import create_app
from pulseguard.ingest import group_dependency_findings
from pulseguard.patching.sandbox import SandboxVerifier
from pulseguard.paths import REPO_ROOT
from pulseguard.run import live_run, trivy_findings
from pulseguard.scanners.normalize import normalize
from pulseguard.store import Store
from tests.fakes import PATCH, FakeLLM, FakeScanner, low_verdict, verdict

FIXTURES = Path(__file__).parent / "fixtures"
DETAIL_KEYS = (
    "priority", "verification", "skeptic", "counterfactual", "blast_radius", "policy",
    "bus_health", "rollback",
)


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _start(target, finding, llm, scanner, db, output, **deps_kw):
    code = (target / finding["file"]).read_text(encoding="utf-8") if (
        target / finding["file"]).is_file() else ""
    deps = GraphDeps(llm=llm, scanner=scanner, target_root=target, output_dir=output, **deps_kw)
    state = {"finding": finding, "code": code, "run_id": "s2-e2e", "mode": "live",
             "bus_health": deps_kw.get("bus_health", "fresh")}
    return asyncio.run(start_case(state, deps, db)), deps


def test_scenario_1_sqli_p0_human_bundle_and_rollback(tmp_path, monkeypatch):
    monkeypatch.setattr(SandboxVerifier, "_pytest", lambda self, work: (True, "3 passed"))
    target = tmp_path / "app"
    shutil.copytree(FIXTURES / "order_sqli", target)
    finding = normalize(FakeScanner().run(target)[0], root=target).to_payload()
    db, output = tmp_path / "s1.sqlite", tmp_path / "bundle"
    status, deps = _start(
        target, finding, FakeLLM([verdict(), PATCH, low_verdict()]), FakeScanner(), db, output)
    assert status["awaiting_approval"]
    assert status["values"]["priority"] == "P0"
    assert status["values"]["blast_radius"]["priority"] == "P0"
    assert status["values"]["verification"]["ok"]
    assert status["values"]["counterfactual"]["ok"]
    assert status["values"]["policy"]["tier"] == "human"
    activities = [e["activity"] for e in status["values"]["events"]]
    assert activities == [
        "FINDING_INGESTED", "EVIDENCE_BUILT", "VERDICT_CONFIRMED", "VERIFIED",
        "BLAST_RADIUS_SCORED", "PATCH_PROPOSED", "SANDBOX_PASSED", "VERIFIED", "APPROVAL_REQUESTED",
    ]
    assert "E4" in status["values"]["evidence_block"]
    assert "exposure: /order reachable from api-gateway (internet-facing)" in (
        status["values"]["evidence_block"])
    status = asyncio.run(resume_case(finding["case_id"], "approve", "security-engineer",
                                     deps, db))
    assert status["values"]["finding"]["state"] == "remediated"
    assert status["values"]["patchset"]["state"] == "applied"
    applied = Path(status["values"]["bundle"]["applied_target"]) / "routes.py"
    assert "conn.execute(q, (order_id,))" in applied.read_text(encoding="utf-8")
    with TestClient(create_app(mode="live", db_path=db, live_deps=deps)) as client:
        detail = client.get("/api/cases/" + finding["case_id"]).json()
        for key in DETAIL_KEYS:
            assert key in detail
        assert detail["priority"] == "P0"
        assert detail["rollback"]["available"] is True
        resp = client.post("/api/cases/" + finding["case_id"] + "/rollback",
                           json={"actor": "security-engineer"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["rollback"]["rolled_back"] is True
        assert "order_id + " in applied.read_text(encoding="utf-8")
        assert client.get("/api/cases/" + finding["case_id"]).json()["rollback"]["rolled_back"]
        assert Store(db).list_patches(finding["case_id"])[-1]["state"] == "rolled_back"
        events = [e["activity"] for e in Store(db).list_events(finding["case_id"])]
        assert "ROLLED_BACK" in events


def test_scenario_2_dependency_bump_p2_auto_approval(tmp_path):
    target = REPO_ROOT / "demo_target" / "order_api"
    finding, = group_dependency_findings(trivy_findings(target))
    db, output = tmp_path / "s2.sqlite", tmp_path / "bundle"
    llm = FakeLLM([])
    status, _ = _start(target, finding, llm, None, db, output)
    assert not status["awaiting_approval"]
    assert status["values"]["priority"] in ("P2", "P3")
    assert status["values"]["policy"]["tier"] == "auto"
    assert status["values"]["approval"]["actor"] == "policy:auto"
    assert status["values"]["finding"]["state"] == "remediated"
    assert not status["values"].get("counterfactual")
    assert "requests==2.33.0" in (
        Path(status["values"]["bundle"]["applied_target"]) / "requirements.txt"
    ).read_text(encoding="utf-8")
    assert "requests==2.33.0" in status["values"]["bundle"]["patch"]
    assert llm.calls == []
    assert not status["values"].get("model_calls")
    assert not status["values"].get("skeptic")
    result = status["values"]["verdict"]
    assert result["role"] == "verifier" and result["model"] == "none"
    assert result["band"] == "confirmed" and result["score"] == 1.0
    assert set(result["cited_evidence"]) == {e["evidence_id"]
                                            for e in status["values"]["evidence"]}
    assert set(finding["extra"]["cve_ids"]) == {
        "CVE-2024-35195", "CVE-2024-47081", "CVE-2026-25645"}
    assert status["values"]["sandbox_report"]["pytest_ok"] is True
    assert {c["name"] for c in status["values"]["verification"]["checks"]} >= {
        "cited_cve", "dependency_report", "patch_scope"}
    activities = [e["activity"] for e in status["values"]["events"]]
    confirmed = next(e for e in status["values"]["events"]
                     if e["activity"] == "VERDICT_CONFIRMED")
    assert confirmed["resource"] == "deterministic"
    assert "CHALLENGED" not in activities
    assert "PATCH_PROPOSED" in activities and "APPROVED" in activities
    assert activities.count("APPROVED") == 1
    assert Store(db).list_approvals(finding["case_id"])[0]["policy_tier"] == "auto"
    assert Store(db).get_case(finding["case_id"])["priority"] in ("P2", "P3")


def test_scenario_2_stale_bus_is_advise_only(tmp_path):
    target = REPO_ROOT / "demo_target" / "order_api"
    finding, = group_dependency_findings(trivy_findings(target))
    db, output = tmp_path / "stale.sqlite", tmp_path / "bundle"
    llm = FakeLLM([])
    status, _ = _start(target, finding, llm, None, db, output,
                       bus_health="stale")
    assert llm.calls == []
    assert status["awaiting_approval"]
    assert status["values"]["policy"]["tier"] == "advise-only"
    assert "human" in status["values"]["review_reason"]
    assert status["values"]["events"][-1]["activity"] == "APPROVAL_REQUESTED"
    assert status["values"]["events"][-1]["attributes"]["policy_tier"] == "advise-only"


def test_dependency_only_run_never_requires_model_or_topology(tmp_path, monkeypatch):
    def unexpected_model():
        pytest.fail("dependency-only runs must not configure a model")

    monkeypatch.setattr("pulseguard.run.make_llm", unexpected_model)
    statuses = asyncio.run(live_run(
        REPO_ROOT / "demo_target" / "order_api", scanners=("trivy",), topology_source="image",
        db_path=tmp_path / "live.sqlite", output_dir=tmp_path / "bundles"))
    assert len(statuses) == 1
    state = statuses[0]["values"]
    assert state["finding"]["state"] == "remediated"
    assert state["approval"]["actor"] == "policy:auto"
    assert not state.get("model_calls") and not state.get("topology_extraction")


@pytest.mark.parametrize("problem,band", [
    ("no_fix", "uncertain"), ("one_cve_unfixed", "uncertain"),
    ("unrecorded", "abstained"), ("forged_recorded_flag", "abstained"),
    ("missing_cve", "abstained"), ("wrong_package", "abstained"),
    ("wrong_version", "abstained"), ("wrong_fix", "abstained"),
    ("missing_report", "abstained"), ("invalid_report", "abstained"),
])
def test_dependency_without_verified_fix_requires_human_without_model(tmp_path, problem, band):
    target = tmp_path / "dep"
    shutil.copytree(REPO_ROOT / "demo_target" / "order_api", target)
    finding, = group_dependency_findings(trivy_findings(target))
    report = target / "scan" / "trivy-report.json"
    data = json.loads(report.read_text(encoding="utf-8"))
    if problem == "no_fix":
        finding["extra"]["fixed_version"] = ""
        for item in data["Results"][0]["Vulnerabilities"]:
            item.pop("FixedVersion")
    elif problem == "one_cve_unfixed":
        data["Results"][0]["Vulnerabilities"][0].pop("FixedVersion")
    elif problem == "unrecorded":
        finding["extra"]["recorded"] = False
    elif problem == "forged_recorded_flag":
        data["PulseGuard"]["recorded"] = False
    elif problem == "missing_cve":
        # Remove a non-primary CVE: checking only extra.cve_id would miss this.
        data["Results"][0]["Vulnerabilities"].pop(0)
    elif problem == "wrong_package":
        finding["extra"]["package"] = "other-package"
    elif problem == "wrong_version":
        finding["extra"]["installed_version"] = "0.0.1"
    elif problem == "wrong_fix":
        finding["extra"]["fixed_version"] = "2.32.0"
    report.write_text(json.dumps(data), encoding="utf-8")
    if problem == "missing_report":
        report.unlink()
    elif problem == "invalid_report":
        report.write_text("{", encoding="utf-8")
    llm = FakeLLM([])
    status, _ = _start(target, finding, llm, None, tmp_path / "dep.sqlite", tmp_path / "out")
    state = status["values"]
    assert llm.calls == []
    assert state["band"] == band
    assert state["finding"]["state"] == ("uncertain" if band == "uncertain" else "escalated")
    assert state["review_status"] == "human_review"
    assert not state.get("patchset") and not state.get("bundle")
    assert not state.get("skeptic") and not state.get("counterfactual")
    assert "CHALLENGED" not in [e["activity"] for e in state["events"]]


def test_scenario_3_int_cast_false_positive_dropped(tmp_path):
    target = tmp_path / "fp"
    target.mkdir()
    src = (FIXTURES / "bandit_fp" / "routes.py").read_text(encoding="utf-8")
    (target / "routes.py").write_text(src, encoding="utf-8")
    lines = src.splitlines()
    # The docstring also mentions "int()", so locate the request read itself.
    source = next(i for i, line in enumerate(lines, 1) if "request.args" in line)
    sink = next(i for i, line in enumerate(lines, 1) if "execute" in line)
    finding = {
        "case_id": "PG-banditfp0001", "fingerprint": _fp("B608", "routes.py", "int"),
        "rule_id": "B608", "scanner": "bandit", "severity": "medium",
        "message": "SYNTHETIC bandit B608 fixture; not a live bandit report",
        "file": "routes.py", "line": sink, "state": "raw", "evidence_ids": [],
        "trace": [
            {"kind": "source", "line": source, "content": lines[source - 1].strip()},
            {"kind": "sink", "line": sink, "content": lines[sink - 1].strip()},
        ],
        "extra": {"test_id": "B608", "confidence": "HIGH", "severity": "MEDIUM"},
    }
    llm = FakeLLM([verdict(0.2)])
    status, _ = _start(target, finding, llm, None, tmp_path / "s3.sqlite", tmp_path / "out")
    assert status["values"]["finding"]["state"] == "false_positive"
    assert status["values"]["review_status"] == "dropped"
    assert "int-cast" in status["values"]["evidence_block"]
    assert status["values"]["events"][-1]["activity"] == "FALSE_POSITIVE_DROPPED"
    assert len(llm.calls) == 1
    assert "patchset" not in status["values"]


def test_scenario_4_quarantine_before_any_model_call(tmp_path):
    target = tmp_path / "inj"
    target.mkdir()
    code = (FIXTURES / "scenario4.py").read_text(encoding="utf-8")
    (target / "routes.py").write_text("x = 1\n", encoding="utf-8")
    finding = {
        "case_id": "PG-inject00001", "fingerprint": _fp("guard", "routes.py", "comment"),
        "rule_id": "B608", "scanner": "bandit", "file": "routes.py", "line": 1, "state": "raw",
        "evidence_ids": [], "extra": {"test_id": "B608"},
        "message": "SYNTHETIC", "trace": [],
    }
    llm = FakeLLM([])
    deps = GraphDeps(llm=llm, target_root=target, output_dir=tmp_path / "out")
    status = asyncio.run(start_case({
        "finding": finding, "code": code, "run_id": "s4", "mode": "live",
    }, deps, tmp_path / "s4.sqlite"))
    assert not llm.calls
    assert status["values"]["finding"]["state"] == "quarantined"
    assert status["values"]["review_reason"] == "suspected manipulation"
    assert status["values"]["events"][-1]["activity"] == "FINDING_QUARANTINED"
    assert "evidence_block" not in status["values"]


def test_destructive_patch_is_rejected_and_escalated(tmp_path, monkeypatch):
    monkeypatch.setattr(SandboxVerifier, "_pytest", lambda self, work: (True, "3 passed"))
    target = tmp_path / "app"
    shutil.copytree(FIXTURES / "order_sqli", target)
    finding = normalize(FakeScanner().run(target)[0], root=target).to_payload()
    bad = {
        "ops": [{"path": "routes.py", "old": "conn.execute(q).fetchall()",
                 "new": "conn.execute('DROP TABLE orders')"}],
        "rationale": "wipe the table", "attempt": 1,
    }
    llm = FakeLLM([verdict(), bad])
    status, _ = _start(
        target, finding, llm, FakeScanner(), tmp_path / "d.sqlite", tmp_path / "out")
    assert status["values"]["finding"]["state"] == "escalated"
    assert status["values"]["patch_rejected"] is True
    assert "sandbox_report" not in status["values"]
    acts = [e["activity"] for e in status["values"]["events"]]
    assert "REJECTED" in acts and "ABSTAINED_ESCALATED" in acts

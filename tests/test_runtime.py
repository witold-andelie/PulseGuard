import json
from dataclasses import replace

import pytest

from pulseguard.bus.memory import FINDINGS_TOPIC, InMemoryBus
from pulseguard.patching.patch import PatchApplier, PatchError, PatchOp, PatchSet
from pulseguard.scanners.normalize import normalize, normalize_trivy
from pulseguard.scanners.semgrep import SemgrepResult
from pulseguard.scanners.trivy import TrivyReportLoader
from pulseguard.store import Store
from pulseguard.trace import Tracer


def test_bus_publish_replay_and_unsubscribe(sample_finding):
    bus = InMemoryBus()
    messages = []
    unsubscribe = bus.subscribe(FINDINGS_TOPIC, messages.append)
    bus.publish(FINDINGS_TOPIC, sample_finding, key=sample_finding["case_id"])
    unsubscribe()
    bus.publish(FINDINGS_TOPIC, sample_finding)
    assert [message.offset for message in messages] == [0]
    assert [message.offset for message in bus.replay(FINDINGS_TOPIC, 1)] == [1]
    assert bus.size(FINDINGS_TOPIC) == 2


def test_patch_dry_run_apply_revert_and_path_aliases(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("unsafe()\n", encoding="utf-8")
    patch = PatchSet(ops=[
        PatchOp("target.py", "unsafe", "first"),
        PatchOp("./target.py", "first", "safe"),
    ], rationale="Test sequential edits through equivalent paths")
    applier = PatchApplier(tmp_path)
    assert len(applier.apply(patch, dry_run=True)) == 1
    target.write_text("external_change()\n", encoding="utf-8")
    applier.revert()
    assert target.read_text() == "external_change()\n"
    target.write_text("unsafe()\n", encoding="utf-8")
    applier.apply(patch)
    assert target.read_text() == "safe()\n"
    applier.revert()
    assert target.read_text() == "unsafe()\n"
    for bad in (
        PatchOp("../outside.py", "x", "y"),
        PatchOp("target.py", "", "y"),
        PatchOp("target.py", "missing", "y"),
    ):
        with pytest.raises(PatchError):
            applier.apply(PatchSet([bad], "invalid patch"))
    assert target.read_text() == "unsafe()\n"


def test_store_wal_crud_and_dedup_identity(tmp_path, sample_finding, sample_run):
    store = Store(tmp_path / "store.sqlite").init_db()
    assert store.journal_mode() == "wal"
    store.create_run("test", "LIVE")
    case_id = store.upsert_case(sample_finding, run_id="test")
    store.create_run("test", "LIVE")  # Updating a run must preserve its dependent cases.
    assert store.upsert_case({**sample_finding, "case_id": "another-id"}) == case_id
    assert store.get_case(case_id)["finding"]["case_id"] == case_id
    store.update_case_state(case_id, "remediated", closed=True)
    case = store.get_case(case_id)
    assert case["state"] == case["finding"]["state"] == "remediated"
    assert case["closed_at"]
    store.add_evidence(case_id, "E1", "rule_source", {"text": "test"})
    store.add_verdict(case_id, sample_run["cases"][0]["verdicts"][0])
    patch_id = store.add_patch(case_id, sample_run["cases"][0]["patches"][0]["patchset"])
    store.update_patch(patch_id, state="sandbox_passed", sandbox_report={"passed": True})
    store.add_approval(patch_id, "approve", "tester")
    assert len(store.list_evidence(case_id)) == len(store.list_verdicts(case_id)) == 1
    assert store.list_patches(case_id)[0]["sandbox_report"]["passed"] is True
    assert store.list_approvals(case_id)[0]["actor"] == "tester"
    store.reset()
    assert not store.list_cases()
    assert not store.list_runs()


def test_trace_redacts_and_resumes(tmp_path):
    path = tmp_path / "trace.jsonl"
    trace = Tracer(path)
    trace.event("PG-TEST", "FINDING_INGESTED", api_key="secret-value")
    with trace.span("PG-TEST", "inspection"):
        pass
    with pytest.raises(RuntimeError), trace.span("PG-TEST", "failure"):
        raise RuntimeError("password=supersecret")
    Tracer(path).event("PG-OTHER", "CASE_CLOSED")
    events = Tracer(path).read()
    assert [event["seq"] for event in events] == list(range(6))
    assert len(trace.read("PG-TEST")) == 5
    assert "supersecret" not in path.read_text()
    assert "secret-value" not in path.read_text()


def test_normalization_stable_across_line_changes():
    result = SemgrepResult(
        rule_id="flask-sqli-taint", path="routes.py", line=10, end_line=10,
        message="SQL injection", severity="ERROR", code="conn.execute(q)",
    )
    finding = normalize(result)
    assert finding.fingerprint == normalize(replace(result, line=20)).fingerprint
    assert finding.state == "raw"


def test_trivy_loader_with_synthetic_input(tmp_path):
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps({"Results": [{
        "Target": "requirements.txt",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-TEST-0001", "PkgName": "test-only",
            "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH",
        }],
        "Secrets": [],
    }]}))
    loader = TrivyReportLoader(path)
    assert loader.summary() == {"vulnerabilities": 1, "misconfigurations": 0, "secrets": 0}
    finding = normalize_trivy(loader.vulnerabilities()[0])
    assert finding.extra["fixed_version"] == "2"
    assert finding.severity == "high"

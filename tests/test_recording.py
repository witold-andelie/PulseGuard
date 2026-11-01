"""Multi-scenario LIVE export and REPLAY serving; every model/scanner call is scripted."""

import asyncio
import csv
import io
import json
import re
import shutil
from argparse import Namespace
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from pulseguard.agents.llm import VisionUnsupportedError
from pulseguard.api import create_app
from pulseguard.paths import REPO_ROOT, replay_dir
from pulseguard.replay.record import main, record, write_recording
from pulseguard.replay.store import RunStore
from pulseguard.replay.verify import verify_manifest, write_manifest
from pulseguard.risk.blast_radius import load_topology
from pulseguard.run import trivy_findings
from pulseguard.scanners.bandit import BanditRunner
from pulseguard.scanners.normalize import normalize_bandit
from pulseguard.store import Store
from tests.fakes import PATCH, FakeLLM, FakeScanner, low_verdict, verdict
from tests.test_live import POC

HOST_PATH = re.compile(rb"(?<![A-Za-z])[A-Za-z]:(?:\\\\|/)[A-Za-z_]|/home/|/Users/|/tmp/")


class FakeBandit(BanditRunner):
    """Fake scan rows; retain real B608 assignment slicing and normalization."""

    def run_json(self, target):
        rows = []
        for name, needle in (("routes.py", 'q = "SELECT'),
                             ("routes.py", 'number_query = "SELECT'),
                             ("order_note.py", 'note_query = "SELECT')):
            path = target / name
            lines = path.read_text(encoding="utf-8").splitlines()
            line = next(i for i, text in enumerate(lines, 1) if needle in text)
            rows.append({
                "test_id": "B608", "filename": str(path), "line_number": line,
                "issue_text": "Scripted B608 SQL pattern", "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH", "code": lines[line - 1],
            })
        return {"results": rows}


def fake_bandit_findings(target):
    return [normalize_bandit(row, root=target).to_payload() for row in FakeBandit().run(target)]


def activities(case):
    return [event["activity"] for event in case["events"]]


@pytest.mark.parametrize("topology_reply", ["valid", "invalid", "unsupported"])
def test_record_all_scenarios_and_serve_replay(tmp_path, monkeypatch, topology_reply):
    topology = load_topology().to_payload()
    reply = {"valid": topology, "invalid": {}, "unsupported": VisionUnsupportedError(422)}[
        topology_reply]
    llm = FakeLLM([reply, verdict(), PATCH, low_verdict(), POC, low_verdict()])
    monkeypatch.setattr("pulseguard.run.make_llm", lambda: llm)
    monkeypatch.setattr("pulseguard.run.SemgrepRunner", lambda **kwargs: FakeScanner())
    monkeypatch.setattr("pulseguard.run.DEFAULT_COLLECTORS",
                        (fake_bandit_findings, trivy_findings))
    config = {
        "PG_MODEL_BASE_URL": "https://provider.test/v1", "PG_MODEL_NAME": llm.model,
        "PG_MODEL_API_KEY": "test-only-credential-never-export",
        "PG_DB_PATH": str(tmp_path / "live.sqlite"), "PG_TOPOLOGY_SOURCE": "image",
    }
    # Exercise both --env-file and inherited PG_TOPOLOGY_SOURCE through the recording CLI.
    env_file = tmp_path / "record.env"
    env_file.write_text("\n".join(f"{key}={value}" for key, value in config.items()
                                  if key != "PG_TOPOLOGY_SOURCE" or topology_reply == "valid"),
                        encoding="utf-8")
    for key, value in config.items():
        monkeypatch.setenv(key, "fixture" if key == "PG_TOPOLOGY_SOURCE"
                           and topology_reply == "valid" else value)
    root = tmp_path / "replay"
    shutil.copytree(replay_dir(), root)
    originals = {path.relative_to(root): path.read_bytes() for path in (root / "runs").rglob("*")
                 if path.is_file()}
    target = REPO_ROOT / "demo_target" / "order_api"
    before = {path.relative_to(target): path.read_bytes() for path in target.rglob("*")
              if path.is_file() and "__pycache__" not in path.parts}
    assert main([
        "--env-file", str(env_file), "--root", str(root), "--run-id", "recorded-s2-test",
        "--auto-approve-as", "test-recorder",
    ]) == 0
    assert not llm.responses  # Includes a real sandbox and bounded PoC on the real demo.
    run = RunStore(root).load("recorded-s2-test")
    assert run["recorded"] is True and run["mode"] == "LIVE"
    assert len(run["cases"]) == 4
    cases = {case["finding"]["scanner"]: case for case in run["cases"]
             if case["finding"]["scanner"] != "bandit"}
    sql, dep = cases["semgrep"], cases["trivy"]
    fp = next(case for case in run["cases"] if case["finding"]["state"] == "false_positive")
    guard = next(case for case in run["cases"] if case["finding"]["state"] == "quarantined")
    assert sql["finding"]["state"] == dep["finding"]["state"] == "remediated"
    assert sql["finding"]["extra"]["also_reported_by"] == ["bandit"]
    assert sql["priority"] == "P0" and sql["policy"]["tier"] == "human"
    assert sql["approval"]["actor"] == "test-recorder"
    assert sql["approval"]["comment"] == "Recording approval (--auto-approve-as)"
    assert sql["approval"]["simulated"] is False
    assert sql["review_status"] == "closed"
    assert sql["verification"]["ok"] and sql["counterfactual"]["ok"]
    assert sql["poc"]["status"] == "witnessed"
    assert any(item["evidence_id"] == "E5" for item in sql["evidence"])
    assert sql["z3_veto"] == "not_applicable"
    assert sql["analysis_limits"][0]["status"] == "not_covered"
    assert [v["role"] for v in sql["verdicts"]] == ["adjudicator", "counterfactual"]
    assert activities(sql) == [
        "FINDING_INGESTED", "EVIDENCE_BUILT", "VERDICT_CONFIRMED", "VERIFIED",
        "BLAST_RADIUS_SCORED", "PATCH_PROPOSED", "SANDBOX_PASSED", "VERIFIED",
        "APPROVAL_REQUESTED", "APPROVED", "PATCH_APPLIED", "CASE_CLOSED",
    ]
    assert dep["priority"] in ("P2", "P3") and dep["policy"]["tier"] == "auto"
    assert dep["approval"]["actor"] == dep["approvals"][0]["actor"] == "policy:auto"
    assert dep["approval"]["policy_tier"] == "auto"
    assert dep["finding"]["extra"]["recorded"] is True
    assert len(dep["finding"]["extra"]["cve_ids"]) == 3
    assert dep["finding"]["extra"]["fixed_version"] == "2.33.0"
    assert dep["patches"][0]["patchset"]["ops"][0]["new"] == "requests==2.33.0"
    assert "requests==2.33.0" in dep["bundle"]["patch"]
    assert dep["model_calls"] == []
    assert dep.get("skeptic") is None and dep.get("counterfactual") is None
    assert [v["role"] for v in dep["verdicts"]] == ["verifier"]
    assert dep["verdicts"][0]["model"] == "none" and dep["verdicts"][0]["score"] == 1.0
    assert next(e for e in dep["events"] if e["activity"] == "VERDICT_CONFIRMED")[
        "resource"] == "deterministic"
    assert not any(dep["finding"]["case_id"] in call["session"] for call in llm.calls)
    assert "CHALLENGED" not in activities(dep)
    assert activities(dep) == [
        "FINDING_INGESTED", "EVIDENCE_BUILT", "VERDICT_CONFIRMED", "VERIFIED",
        "BLAST_RADIUS_SCORED", "PATCH_PROPOSED", "SANDBOX_PASSED", "APPROVAL_REQUESTED",
        "APPROVED", "PATCH_APPLIED", "CASE_CLOSED",
    ]
    assert fp["review_status"] == "dropped" and fp["verdicts"][0]["score"] < 0.3
    assert "int-cast" in fp["evidence_block"]
    assert activities(fp) == ["FINDING_INGESTED", "EVIDENCE_BUILT", "FALSE_POSITIVE_DROPPED"]
    assert guard["finding"]["file"] == "order_note.py"
    assert guard["review_status"] == "human_review"
    assert guard["review_reason"] == "suspected manipulation"
    assert activities(guard) == ["FINDING_INGESTED", "FINDING_QUARANTINED"]
    for case in (fp, guard):
        assert not case.get("bundle") and case["patches"] == case["approvals"] == []
    for case in (sql, dep):
        assert case["patches"][0]["sandbox_report"]["passed"] is True
        assert case["bundle"]["output_dir"] == "bundle"
        assert "applied_target" not in case["bundle"]
        assert case["rollback"] == {"available": True, "rolled_back": False}
    extraction = run["topology_extraction"]
    assert extraction["topology"] == topology
    assert extraction["source"] == ("extracted" if topology_reply == "valid" else "fixture")
    assert extraction["validation"]["ok"] is (topology_reply == "valid")
    assert [call["role"] for call in run["model_calls"]] == ["topology"]
    if topology_reply == "unsupported":
        assert extraction["validation"]["errors"] == ["vision_unsupported"]
        assert run["model_calls"][0]["status_code"] == 422
    else:
        assert run["model_calls"][0]["usage"]["total_tokens"] == 150
    assert sum(call["session"].endswith("-topology") for call in llm.calls) == 1
    for case in (sql, dep):
        assert case["blast_radius"]["validation"] == extraction["validation"]
        if topology_reply == "valid":
            assert case["blast_radius"]["source"] == "extracted"
        else:
            assert case["blast_radius"]["fixture"] == "hand-written"
    assert verify_manifest(root).ok
    for path in root.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert b"\r\n" not in data and not HOST_PATH.search(data), path
            assert config["PG_MODEL_API_KEY"].encode() not in data
            assert b"data:image" not in data and b"base64" not in data
    assert all((root / path).read_bytes() == data for path, data in originals.items())
    assert all((target / path).read_bytes() == data for path, data in before.items())
    # Newest recorded=true wins even over a later unrecorded placeholder.
    RunStore(root).save("future-placeholder", {
        "run_id": "future-placeholder", "recorded": False, "started_at": "2099-01-01"})
    write_manifest(root)
    assert RunStore(root).latest()["run_id"] == run["run_id"]
    with TestClient(create_app(mode="replay", db_path=tmp_path / "replay.sqlite",
                               replay_root=root)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/mode").json()["topology_extraction"] == extraction
        board = client.get("/api/cases").json()["cases"]
        assert len(board) == 4
        assert {c["case_id"]: c["state"] for c in board} == {
            c["finding"]["case_id"]: c["finding"]["state"] for c in run["cases"]}
        for case in run["cases"]:
            case_id = case["finding"]["case_id"]
            path = "/api/cases/" + case_id
            detail = client.get(path).json()
            for key in ("priority", "verification", "skeptic", "counterfactual", "poc",
                        "z3_veto", "blast_radius", "policy", "bus_health", "rollback",
                        "bundle", "review_status", "review_reason", "evidence_block"):
                assert detail[key] == case.get(key), key
            assert detail["analysis_limits"] == case.get("analysis_limits", [])
            assert detail["case"]["state"] == case["finding"]["state"]
            assert detail["case"]["priority"] == case.get("priority")
            assert next(c for c in board if c["case_id"] == case_id)["priority"] == case.get(
                "priority")
            assert {v["role"] for v in detail["verdicts"]} == {
                v["role"] for v in case["verdicts"]}
            assert len(detail["evidence"]) == len(case["evidence"])
            assert len(client.get("/api/cases?state=" + case["finding"]["state"]).json()[
                "cases"]) >= 1
            events = client.get(path + "/trace").json()["events"]
            for suffix, body in (("/decision", {"decision": "approve", "actor": "visitor"}),
                                 ("/rollback", {"actor": "visitor"})):
                response = client.post(path + suffix, json=body)
                assert response.status_code == 200 and response.json()["simulated"] is True
                assert client.get(path).json() == detail
                assert client.get(path + "/trace").json()["events"] == events
        rows = list(csv.DictReader(io.StringIO(client.get("/api/eventlog.csv").text)))
        assert len(rows) == sum(len(c["events"]) for c in run["cases"])
        assert {row["run_mode"] for row in rows} == {"REPLAY"}
        assert {row["case_id"] for row in rows} == {c["case_id"] for c in board}
        kpis = client.get("/api/kpis").json()
        assert kpis["cases_total"] == 4
        assert kpis["false_positives_dropped"] == kpis["approvals_automatic"] == kpis[
            "approvals_human"] == 1
        assert kpis["mean_time_to_remediate_s"] >= 0
        assert kpis["cases_by_final_state"] == {
            "remediated": 2, "false_positive": 1, "quarantined": 1}


@pytest.mark.parametrize(("state", "review", "next_nodes", "awaiting"), [
    ("raw", None, [], False), ("normalized", None, ["evidence"], False),
    ("confirmed", "human_review", [], False), ("uncertain", "human_review", [], False),
    ("remediated", "closed", [], False), ("false_positive", "human_review", [], False),
    ("quarantined", "remediating", [], False), ("escalated", "human_review", ["verify"], False),
    ("confirmed", "awaiting_approval", ["sandbox"], True),
])
def test_refuse_unexpected_or_unfinished_states(tmp_path, monkeypatch, sample_finding,
                                             state, review, next_nodes, awaiting):
    for key in ("PG_MODEL_BASE_URL", "PG_MODEL_NAME", "PG_MODEL_API_KEY"):
        monkeypatch.setenv(key, "test-only-configuration")
    status = {"case_id": sample_finding["case_id"], "awaiting_approval": awaiting,
              "next": next_nodes, "values": {
                  "finding": dict(sample_finding, state=state), "run_id": "refused",
                  "mode": "live", "review_status": review,
              }}

    async def fake_run(*args, **kwargs):
        return [status]

    async def unexpected_approval(*args, **kwargs):
        pytest.fail("unexpected state must be refused before approval")

    monkeypatch.setattr("pulseguard.replay.record.live_run", fake_run)
    monkeypatch.setattr("pulseguard.replay.record.resume_case", unexpected_approval)
    args = Namespace(target=tmp_path, root=tmp_path / "replay", run_id="refused",
                     db_path=tmp_path / "live.sqlite", auto_approve_as="recorder")
    with pytest.raises(ValueError, match="unexpected or unfinished"):
        asyncio.run(record(args))
    with pytest.raises(ValueError, match="unexpected or unfinished"):
        write_recording([status], root=args.root, db_path=args.db_path,
                        run_id=args.run_id, model="test")
    assert not args.root.exists()


@pytest.mark.parametrize("invalid", ["simulated", "replay", "policy_actor"])
def test_refuse_non_live_or_misattributed_approvals(tmp_path, sample_finding, invalid):
    status = {"case_id": sample_finding["case_id"], "next": [], "awaiting_approval": False,
              "values": {
                  "run_id": "refused", "mode": "replay" if invalid == "replay" else "live",
                  "finding": dict(sample_finding, state="remediated"), "review_status": "closed",
                  "bundle": {"output_dir": "unused"}, "policy": {"tier": "auto"},
                  "approval": {"decision": "approve", "policy_tier": "auto",
                               "actor": "human" if invalid == "policy_actor" else "policy:auto",
                               "simulated": invalid == "simulated"},
              }}
    root = tmp_path / "replay"
    with pytest.raises(ValueError, match="LIVE outcomes|policy approval"):
        write_recording([status], root=root, db_path=tmp_path / "live.sqlite",
                        run_id="refused", model="test")
    assert not root.exists()


def test_validate_whole_batch_before_any_recording_approval(tmp_path, monkeypatch, sample_finding):
    for key in ("PG_MODEL_BASE_URL", "PG_MODEL_NAME", "PG_MODEL_API_KEY"):
        monkeypatch.setenv(key, "test-only-configuration")
    pending = {"case_id": sample_finding["case_id"], "next": ["approve"],
               "awaiting_approval": True, "values": {
                   "run_id": "batch", "mode": "live", "review_status": "awaiting_approval",
                   "finding": dict(sample_finding, state="confirmed"),
               }}
    unfinished = deepcopy(pending)
    unfinished["awaiting_approval"] = False
    unfinished["next"] = ["sandbox"]

    async def fake_run(*args, **kwargs):
        return [pending, unfinished]

    async def unexpected_approval(*args, **kwargs):
        pytest.fail("the full batch must be validated before approving its first case")

    monkeypatch.setattr("pulseguard.replay.record.live_run", fake_run)
    monkeypatch.setattr("pulseguard.replay.record.resume_case", unexpected_approval)
    with pytest.raises(ValueError, match="unexpected or unfinished"):
        asyncio.run(record(Namespace(
            target=tmp_path, root=tmp_path / "replay", run_id="batch",
            db_path=tmp_path / "live.sqlite", auto_approve_as="recorder")))


def test_export_escalation_with_skeptic_limits_and_veto(tmp_path, sample_finding):
    finding = dict(deepcopy(sample_finding), state="escalated")
    db = tmp_path / "live.sqlite"
    store = Store(db).init_db()
    store.create_run("escalated-test", "LIVE")
    store.upsert_case(finding, run_id="escalated-test")
    adjudicator = {**verdict(0.5), "case_id": finding["case_id"], "band": "abstained",
                   "role": "adjudicator", "model": "test-model"}
    skeptic = {**adjudicator, "role": "skeptic"}
    limits = [{"id": "L1", "check": "z3 validator check", "status": "unknown",
               "reason": "unsupported regex"}]
    status = {"case_id": finding["case_id"], "next": [], "awaiting_approval": False,
              "values": {"finding": finding, "run_id": "escalated-test", "mode": "live",
                         "review_status": "human_review", "review_reason": "verification failed",
                         "verdict": adjudicator, "skeptic": skeptic, "analysis_limits": limits,
                         "verification": {"ok": False, "checks": []}, "z3_veto": "applied"}}
    root = tmp_path / "replay"
    write_recording([status], root=root, db_path=db, run_id="escalated-test", model="test-model")
    with TestClient(create_app(mode="replay", db_path=tmp_path / "replay.sqlite",
                               replay_root=root)) as client:
        detail = client.get("/api/cases/" + finding["case_id"]).json()
        assert detail["case"]["state"] == "escalated"
        assert detail["analysis_limits"] == limits and detail["skeptic"] == skeptic
        assert detail["z3_veto"] == "applied"
        assert {v["role"] for v in detail["verdicts"]} == {"adjudicator", "skeptic"}
        assert detail["review_reason"] == "verification failed"
        assert detail["bundle"] is None


LEGACY_RUNS = ("recorded-20261031T012001-4192c0", "s1-placeholder")


def test_existing_s1_and_placeholder_still_load(tmp_path):
    for run_id in [run for run in RunStore(replay_dir()).list_runs() if run in LEGACY_RUNS]:
        root = tmp_path / run_id / "replay"
        shutil.copytree(replay_dir() / "runs" / run_id, root / "runs" / run_id)
        write_manifest(root)
        with TestClient(create_app(mode="replay", db_path=root.parent / "db.sqlite",
                                   replay_root=root)) as client:
            assert client.get("/health").status_code == 200
            cases = client.get("/api/cases").json()["cases"]
            assert len(cases) == 1
            detail = client.get("/api/cases/" + cases[0]["case_id"]).json()
            assert detail["evidence"] and detail["verdicts"]
            for key in ("poc", "verification", "blast_radius", "z3_veto"):
                assert detail[key] is None
            assert detail["rollback"] is None


MUSE_RUN = "recorded-20261101T000444-c1f323"


def test_committed_muse_recording_shows_the_four_scenarios(tmp_path):
    """Pins the real Meta Muse Spark recording served on Render (framework section 13)."""
    with TestClient(create_app(mode="replay", db_path=tmp_path / "muse.sqlite")) as client:
        mode = client.get("/api/mode").json()
        assert (mode["run_id"], mode["recorded"]) == (MUSE_RUN, True)
        assert mode["model"] == "muse-spark-1.3-contributor"
        cases = {case["case_id"]: case for case in client.get("/api/cases").json()["cases"]}
        details = {cid: client.get("/api/cases/" + cid).json() for cid in cases}

    by_rule = {detail["case"]["rule_id"]: detail for detail in details.values()}
    assert len(cases) == 4

    sqli = by_rule["flask-sqli-taint"]  # scenarios 1 and 5
    assert sqli["case"]["state"] == "remediated" and sqli["priority"] == "P0"
    assert sqli["verification"]["ok"] is True
    assert sqli["poc"]["status"] == "witnessed"
    assert sqli["blast_radius"]["source"] == "extracted"
    assert sqli["approvals"][-1]["actor"] == "security-engineer (recording)"

    # scenario 2
    dependency = next(d for d in details.values() if d["case"]["finding"]["scanner"] == "trivy")
    verdict = dependency["verdicts"][0]
    assert (verdict["role"], verdict["model"], verdict["band"]) == ("verifier", "none", "confirmed")
    assert dependency["case"]["state"] == "remediated"
    assert dependency["approvals"][-1]["actor"] == "policy:auto"
    assert "requests==2.33.0" in json.dumps(dependency["bundle"])

    states = sorted(d["case"]["state"] for d in details.values())
    assert states == ["false_positive", "quarantined", "remediated", "remediated"]  # scenarios 3, 4
    quarantined = next(d for d in details.values() if d["case"]["state"] == "quarantined")
    assert not quarantined["verdicts"]  # the guard stopped it before any model call

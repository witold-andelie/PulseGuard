"""S3 demo PoC policy and graph integration (framework 4.5 / 13 scenario 5)."""

import asyncio
import shutil
import time
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from pulseguard.agents.graph import GraphDeps
from pulseguard.agents.llm import output_schema
from pulseguard.agents.runner import start_case
from pulseguard.api import create_app
from pulseguard.falsify.poc import DEMO_ROOT, _execute, propose_poc, witness
from pulseguard.patching.patch import PatchApplier, PatchSet
from pulseguard.patching.sandbox import SandboxVerifier
from pulseguard.scanners.normalize import normalize
from pulseguard.store import Store
from tests.fakes import PATCH, FakeLLM, FakeScanner, low_verdict, verdict

PROPOSAL = {
    "route": "/order", "params": {"id": "1' OR '1'='1"}, "expected_max_rows": 1,
    "rationale": "A tautology should return more than one order only before parameter binding.",
}
NO_FIX = {
    "ops": [{"path": "routes.py", "old": "def order():", "new": "def order():  # same query"}],
    "rationale": "Negative control leaves injection in place", "attempt": 1,
}


@pytest.fixture
def demo_copy(tmp_path):
    target = tmp_path / "target"
    shutil.copytree(DEMO_ROOT, target)
    return target


@pytest.mark.parametrize(("proposal", "patch", "status", "before_rows", "after_rows"), [
    (PROPOSAL, PATCH, "witnessed", 12, 0),
    ({**PROPOSAL, "params": {"id": "1"}}, PATCH, "not_witnessed", 1, 1),
    (PROPOSAL, NO_FIX, "failed", 12, 12),
])
def test_before_after_real_demo_copies(demo_copy, proposal, patch, status, before_rows, after_rows):
    before = (demo_copy / "routes.py").read_bytes()
    llm = FakeLLM([proposal])
    result = witness(demo_copy, PatchSet.from_payload(patch), "evidence", case_id="PG-poc", llm=llm)
    assert result["status"] == status, result
    assert result["before"]["rows"] == before_rows
    assert result["after"]["rows"] == after_rows
    assert (demo_copy / "routes.py").read_bytes() == before
    assert not (demo_copy / "fixture.sqlite").exists()
    assert llm.calls[0]["session"] == "pg-PG-poc-poc"
    assert llm.calls[0]["schema"]["title"] == "PoCProposal"
    if status == "witnessed":
        assert 'PoC witness: input "1\' OR \'1\'=\'1" returned 12 rows, expected <= 1' in (
            result["detail"])


@pytest.mark.parametrize("route", ["/not_registered", "/order/"])
def test_unregistered_routes_are_rejected(demo_copy, route):
    result = witness(demo_copy, PatchSet.from_payload(PATCH), "", case_id="poc",
                     llm=FakeLLM([{**PROPOSAL, "route": route}]))
    assert result["status"] == "not_witnessed"
    assert result["before"]["rejected"]
    assert "inconclusive" in result["detail"]


@pytest.mark.parametrize("change", [
    {"route": "https://example.invalid/order"}, {"route": "//example.invalid"},
    {"route": "/order?other=1"}, {"method": "POST"}, {"expected_max_rows": True},
    {"params": {"id": 1}}, {"params": {"id": "x" * 513}},
    {"params": {"x" * 65: "1"}}, {"params": {str(i): "1" for i in range(9)}},
])
def test_invalid_proposals_never_execute(demo_copy, monkeypatch, change):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid proposals must not enter the child")
    monkeypatch.setattr("pulseguard.falsify.poc._execute", forbidden)
    result = witness(demo_copy, PatchSet.from_payload(PATCH), "", case_id="poc",
                     llm=FakeLLM([{**PROPOSAL, **change}]))
    assert result["status"] == "not_witnessed"
    assert "rejected" in result["detail"]


def test_schema_and_foreign_target_policy(tmp_path):
    Draft202012Validator.check_schema(output_schema("poc"))
    llm = FakeLLM([PROPOSAL])
    result = witness(tmp_path, PatchSet.from_payload(PATCH), "", case_id="poc", llm=llm)
    assert result["status"] == "not_witnessed"
    assert not llm.calls
    proposal = propose_poc("untrusted code", case_id="poc", llm=llm)
    assert proposal == PROPOSAL
    assert "untrusted code" in llm.calls[0]["user"]
    assert "$schema" not in llm.calls[0]["schema"]


@pytest.mark.parametrize("operation", [
    'socket.socket().connect(("127.0.0.1", 9))',
    'socket.socket().connect_ex(("127.0.0.1", 9))',
    'socket.create_connection(("127.0.0.1", 9))',
    'socket.socket(type=socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))',
    'socket.getaddrinfo("example.invalid", 80)',
])
def test_network_attempt_inside_child_is_blocked(demo_copy, operation):
    probe = (
        "import socket\n    try:\n        " + operation + "\n"
        "    except PermissionError:\n        return jsonify([{'blocked': True}])\n"
        "    return jsonify([])"
    )
    patch = {"ops": [{"path": "routes.py", "old": 'order_id = request.args.get("id")',
                      "new": probe}], "rationale": "Test child network policy", "attempt": 1}
    PatchApplier(demo_copy).apply(PatchSet.from_payload(patch))
    result = _execute(demo_copy, PROPOSAL, 5)
    assert result["rows"] == 1, result


def test_timeout_enforced_and_repair_fails_closed(demo_copy):
    patch = {"ops": [{"path": "routes.py", "old": "def order():",
                      "new": "def order():\n    while True:\n        pass"}],
             "rationale": "Test timeout", "attempt": 1}
    started = time.monotonic()
    result = witness(demo_copy, PatchSet.from_payload(patch), "", case_id="poc",
                     llm=FakeLLM([PROPOSAL]), timeout_s=2)
    assert time.monotonic() - started < 4
    assert result["before"]["deviation"], result
    assert result["after"]["timed_out"], result
    assert result["status"] == "failed"


def test_child_launch_error_after_baseline_fails_closed(demo_copy, monkeypatch):
    def execute(root, proposal, timeout):
        if root.name == "before":
            return {"rows": 12, "deviation": True}
        raise OSError("child unavailable")
    monkeypatch.setattr("pulseguard.falsify.poc._execute", execute)
    result = witness(demo_copy, PatchSet.from_payload(PATCH), "", case_id="poc",
                     llm=FakeLLM([PROPOSAL]))
    assert result["status"] == "failed"
    assert "repair could not be verified" in result["detail"]


def test_child_ignores_sitecustomize_secrets_and_proxies(demo_copy, monkeypatch):
    marker = demo_copy / "sitecustomize-ran"
    (demo_copy / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).touch()", encoding="utf-8")
    monkeypatch.setenv("PG_LIVE_TOKEN", "must-not-be-inherited")
    monkeypatch.setenv("HTTPS_PROXY", "http://must-not-be-inherited")
    probe = ("import os\n    ok = ('PG_LIVE_TOKEN' not in os.environ and "
             "os.environ['HTTPS_PROXY'] == '' and os.environ['NO_PROXY'] == '*')\n"
             "    return jsonify([{'clean': True}] if ok else [])")
    PatchApplier(demo_copy).apply(PatchSet.from_payload({
        "ops": [{"path": "routes.py", "old": 'order_id = request.args.get("id")', "new": probe}],
        "rationale": "Test clean bootstrap", "attempt": 1,
    }))
    assert _execute(demo_copy, PROPOSAL, 5)["rows"] == 1
    assert not marker.exists()


def test_post_only_route_is_rejected(demo_copy):
    PatchApplier(demo_copy).apply(PatchSet.from_payload({
        "ops": [{"path": "routes.py", "old": '@app.route("/order")',
                 "new": '@app.route("/order", methods=["POST"])'}],
        "rationale": "Test GET policy", "attempt": 1,
    }))
    assert _execute(demo_copy, PROPOSAL, 5) == {"error": "MethodNotAllowed", "rejected": True}


def test_sql_error_leak_observed_in_child(demo_copy):
    with (demo_copy / "routes.py").open("a", encoding="utf-8") as handle:
        handle.write('\n@app.errorhandler(sqlite3.Error)\ndef sql_leak(exc):\n'
                     '    return jsonify({"error": "sqlite3.OperationalError: "'
                     ' + str(exc)}), 500\n')
    result = _execute(demo_copy, {**PROPOSAL, "params": {"id": "'"}}, 5)
    assert result["sql_error"] and result["deviation"]
    assert "OperationalError" not in str(result)  # Raw errors are never returned.


@pytest.mark.parametrize(("patch", "proposal", "expected"), [
    (PATCH, PROPOSAL, "witnessed"),
    (PATCH, {**PROPOSAL, "params": {"id": "1"}}, "not_witnessed"),
    (NO_FIX, PROPOSAL, "failed"),
])
def test_graph_persists_e5_and_gates_approval(demo_copy, tmp_path, monkeypatch,
                                           patch, proposal, expected):
    # Exercise real sandbox copies + demo pytest for a repaired patch. For the negative
    # control, simulate a scanner that missed it so PoC must catch the remaining deviation.
    scanner = FakeScanner()
    if expected == "failed":
        monkeypatch.setattr(SandboxVerifier, "verify", lambda self, patch: type("Report", (), {
            "to_dict": lambda self: {"passed": True}})())
    finding = normalize(scanner.run(demo_copy)[0], root=demo_copy).to_payload()
    llm = FakeLLM([verdict(), deepcopy(patch), low_verdict(), proposal])
    db = tmp_path / "poc.sqlite"
    status = asyncio.run(start_case({"finding": finding, "run_id": "poc-test"}, GraphDeps(
        target_root=demo_copy, output_dir=tmp_path / "bundle", llm=llm, scanner=scanner,
    ), db))
    state = status["values"]
    assert state["poc"]["status"] == expected, state["poc"]
    assert status["awaiting_approval"] is (expected != "failed")
    assert "[E5] PoC witness:" in state["evidence_block"]
    events = Store(db).list_events(finding["case_id"])
    checks = [event for event in events if event["attributes"].get("check") == "poc_witness"]
    assert checks[0]["activity"] == "VERIFIED"
    assert checks[0]["attributes"]["status"] == expected
    assert any(item["evidence_id"] == "E5" for item in Store(db).list_evidence(finding["case_id"]))
    if expected == "failed":
        assert checks[-1]["activity"] == "ABSTAINED_ESCALATED"
        assert state["finding"]["state"] == "escalated"
        assert "approval" not in state and "policy" not in state
    with TestClient(create_app(mode="live", db_path=db)) as client:
        detail = client.get("/api/cases/" + finding["case_id"]).json()
        assert detail["poc"]["status"] == expected

"""ST-4 MCP tools: direct function calls, FastMCP listing, store reads, no network."""

import asyncio
import json
import os

from pulseguard.mcp_server import (
    build_server,
    get_case_evidence,
    request_approval,
    triage_finding,
)
from pulseguard.paths import REPO_ROOT
from pulseguard.store import Store

MODEL_ENV = ("PG_MODEL_BASE_URL", "PG_MODEL_NAME", "PG_MODEL_API_KEY")


def _clear_model_env(monkeypatch):
    for key in MODEL_ENV:
        monkeypatch.delenv(key, raising=False)


def _seed_case(tmp_path, monkeypatch, sample_finding, sample_run):
    db = tmp_path / "pg.sqlite"
    monkeypatch.setenv("PG_DB_PATH", str(db))
    store = Store(db).init_db()
    store.create_run("mcp-test", "LIVE")
    case_id = store.upsert_case(sample_finding, run_id="mcp-test")
    store.add_evidence(case_id, "E1", "rule_source", {"text": "rule"})
    store.add_verdict(case_id, sample_run["cases"][0]["verdicts"][0])
    store.patch_runtime(
        case_id,
        verification={"ok": True, "checks": []},
        blast_radius={"priority": "P0", "score": 1.0},
    )
    return store, case_id


def test_fastmcp_lists_the_three_tools():
    server = build_server()
    names = {info.name for info in server._tool_manager.list_tools()}
    listed = {tool.name for tool in asyncio.run(server.list_tools())}
    assert names == listed == {"triage_finding", "get_case_evidence", "request_approval"}


def test_triage_finding_evidence_only_without_model(monkeypatch, sample_finding):
    _clear_model_env(monkeypatch)
    result = triage_finding(json.dumps(sample_finding))
    assert "error" not in result
    assert result["model_configured"] is False
    assert result["verdict"] is None
    assert "no model configured" in result["note"]
    assert result["evidence_block"].startswith("=== HARD EVIDENCE")
    assert any(item["evidence_id"] == "E1" for item in result["evidence"])
    assert result["guard_flagged"] is False


def test_triage_finding_builds_e6_for_labelled_unsat(monkeypatch):
    _clear_model_env(monkeypatch)
    code = (REPO_ROOT / "demo_target" / "z3_cases" / "alnum_unsat.py").read_text(
        encoding="utf-8")
    lines = code.splitlines()
    source = next(i for i, line in enumerate(lines, 1) if "request.args.get" in line)
    sink = next(i for i, line in enumerate(lines, 1) if line.strip() == "return order_id")
    finding = {
        "case_id": "PG-mcp-z3", "fingerprint": "ab" * 16, "rule_id": "flask-sqli-taint",
        "scanner": "semgrep", "file": "demo_target/z3_cases/alnum_unsat.py",
        "line": sink, "state": "raw", "evidence_ids": [],
        "trace": [
            {"kind": "source", "line": source, "content": lines[source - 1].strip()},
            {"kind": "sink", "line": sink, "content": lines[sink - 1].strip()},
        ],
        "extra": {},
    }
    result = triage_finding(json.dumps(finding))
    assert "error" not in result
    e6 = next(item for item in result["evidence"] if item["evidence_id"] == "E6")
    assert e6["text"].endswith("unsat")
    assert "[E6]" in result["evidence_block"]


def test_triage_rejects_invalid_payload(monkeypatch):
    _clear_model_env(monkeypatch)
    assert triage_finding("not json")["error"]
    assert triage_finding("{}")["error"]
    assert triage_finding("[]")["error"]


def test_get_case_evidence_reads_store(tmp_path, monkeypatch, sample_finding, sample_run):
    _clear_model_env(monkeypatch)
    _store, case_id = _seed_case(tmp_path, monkeypatch, sample_finding, sample_run)
    result = get_case_evidence(case_id)
    assert "error" not in result
    assert result["case_id"] == case_id
    assert result["evidence"]
    assert result["verdicts"]
    assert result["verification"]["ok"] is True
    assert result["blast_radius"]["priority"] == "P0"
    assert get_case_evidence("missing-id")["error"]
    assert get_case_evidence("../etc/passwd")["error"]


def test_request_approval_replay_is_simulated(
    tmp_path, monkeypatch, sample_finding, sample_run,
):
    _clear_model_env(monkeypatch)
    store, case_id = _seed_case(tmp_path, monkeypatch, sample_finding, sample_run)
    monkeypatch.setenv("PG_MODE", "replay")
    result = request_approval(case_id, "approve", "demo-visitor")
    assert result["simulated"] is True
    assert result["applied"] is False
    assert "simulated" in result["label"].lower()
    assert result["approval"]["simulated"] is True
    assert store.list_approvals(case_id) == []
    assert store.list_events(case_id) == []


def test_request_approval_live_records_request_only(
    tmp_path, monkeypatch, sample_finding, sample_run,
):
    _clear_model_env(monkeypatch)
    store, case_id = _seed_case(tmp_path, monkeypatch, sample_finding, sample_run)
    monkeypatch.setenv("PG_MODE", "live")
    result = request_approval(case_id, "reject", "security-engineer")
    assert result["simulated"] is False
    assert result["applied"] is False
    assert "request" in result["label"].lower()
    assert store.list_approvals(case_id) == []
    events = store.list_events(case_id)
    assert len(events) == 1
    assert events[0]["activity"] == "APPROVAL_REQUESTED"
    assert events[0]["attributes"]["run_mode"] == "LIVE"
    assert events[0]["attributes"]["applied"] is False
    assert events[0]["resource"] == "security-engineer"


def test_request_approval_rejects_invalid_inputs(
    tmp_path, monkeypatch, sample_finding, sample_run,
):
    _clear_model_env(monkeypatch)
    _store, case_id = _seed_case(tmp_path, monkeypatch, sample_finding, sample_run)
    monkeypatch.setenv("PG_MODE", "replay")
    assert request_approval(case_id, "merge", "actor")["error"]
    assert request_approval(case_id, "approve", "  ")["error"]
    assert request_approval("nope", "approve", "actor")["error"]


def test_mcp_tools_do_not_require_network(monkeypatch, sample_finding):
    _clear_model_env(monkeypatch)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(key, raising=False)
    result = triage_finding(json.dumps(sample_finding))
    assert result["verdict"] is None
    assert os.environ.get("PG_MODEL_BASE_URL") in (None, "")

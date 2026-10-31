"""Framework 10.1 exports, using direct SQLite event rows and no model/scanner calls."""

import csv
import io
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from pulseguard.api import create_app
from pulseguard.eventlog import CSV_COLUMNS, compute_kpis, export_csv, read_events
from pulseguard.store import Store


def add(store, case, activity, seconds=0, resource="verifier", **attributes):
    """Insert contract-shaped rows directly; also works before CORE adds S2 activities."""
    stamp = (datetime(2026, 10, 31, tzinfo=UTC) + timedelta(seconds=seconds)).isoformat()
    with store.connect() as conn:
        conn.execute("INSERT INTO events (case_id, activity, ts, resource, attributes_json) "
                     "VALUES (?, ?, ?, ?, ?)",
                     (case, activity, stamp, resource, json.dumps(attributes)))


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "events.sqlite").init_db()


def test_empty_log(store):
    assert export_csv(read_events(store)) == ",".join(CSV_COLUMNS) + "\n"
    assert compute_kpis(read_events(store)) == {
        "mean_time_to_remediate_s": None, "false_positives_dropped": 0,
        "approvals_automatic": 0, "approvals_human": 0,
        "rework_loops": {"mean": 0.0, "max": 0}, "cases_total": 0, "cases_by_final_state": {},
    }


def test_csv_exact_columns_quoting_and_utc(store):
    add(store, "case,one", "FINDING_INGESTED", resource='reviewer "one"',
        priority="P2", score=0.0, run_mode="REPLAY")
    with store.connect() as conn:
        conn.execute("UPDATE events SET ts = '2026-10-31T02:00:00+02:00'")
    body = export_csv(read_events(store))
    assert "\r\n" not in body
    rows = list(csv.DictReader(io.StringIO(body)))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert rows[0] == {
        "case_id": "case,one", "activity": "FINDING_INGESTED", "timestamp": "2026-10-31T00:00:00Z",
        "resource": 'reviewer "one"', "priority": "P2", "score": "0.0", "run_mode": "REPLAY",
    }


def test_kpis_are_derived_from_events_and_include_zero_rework_cases(store):
    for case in ("auto", "human", "fp", "rejected", "open"):
        add(store, case, "FINDING_INGESTED")
    add(store, "auto", "PATCH_PROPOSED", 1)
    add(store, "auto", "SANDBOX_FAILED", 2)
    add(store, "auto", "VERIFIED", 3)
    add(store, "auto", "PATCH_PROPOSED", 4)
    add(store, "auto", "PATCH_PROPOSED", 5)  # No additional failure, no additional cycle.
    add(store, "auto", "SANDBOX_FAILED", 6)
    add(store, "auto", "PATCH_PROPOSED", 7)
    add(store, "auto", "APPROVED", 8, resource="policy:auto", policy_tier="auto")
    add(store, "auto", "PATCH_APPLIED", 9)
    add(store, "auto", "CASE_CLOSED", 20, outcome="remediated")
    add(store, "human", "APPROVED", 9, resource="security-engineer", policy_tier="human")
    add(store, "human", "PATCH_APPLIED", 10)
    add(store, "human", "CASE_CLOSED", 40)  # S1-compatible inference from applied event.
    add(store, "fp", "FALSE_POSITIVE_DROPPED", 1)
    add(store, "fp", "CASE_CLOSED", 2, outcome="false_positive")
    add(store, "rejected", "REJECTED", 2)
    add(store, "rejected", "CASE_CLOSED", 1000, outcome="rejected")
    add(store, "open", "SANDBOX_FAILED", 3)  # No retry yet.
    assert compute_kpis(read_events(store)) == {
        "mean_time_to_remediate_s": 30.0, "false_positives_dropped": 1,
        "approvals_automatic": 1, "approvals_human": 1,
        "rework_loops": {"mean": 0.4, "max": 2}, "cases_total": 5,
        "cases_by_final_state": {"false_positive": 1, "raw": 1, "rejected": 1, "remediated": 2},
    }


def test_missing_ingestion_negative_duration_and_rollback_excluded_from_mttr(store):
    add(store, "missing", "CASE_CLOSED", 10, outcome="remediated")
    add(store, "negative", "FINDING_INGESTED", 50)
    add(store, "negative", "CASE_CLOSED", 10, outcome="remediated")
    add(store, "rollback", "FINDING_INGESTED")
    add(store, "rollback", "PATCH_APPLIED", 1)
    add(store, "rollback", "CASE_CLOSED", 10, outcome="remediated")
    add(store, "rollback", "ROLLED_BACK", 20)
    add(store, "quarantined", "FINDING_QUARANTINED", 1)
    add(store, "escalated", "ABSTAINED_ESCALATED", 1)
    result = compute_kpis(read_events(store))
    assert result["mean_time_to_remediate_s"] is None
    assert result["cases_by_final_state"] == {
        "remediated": 2, "rolled_back": 1, "quarantined": 1, "escalated": 1,
    }


def test_api_event_only_rows_live_and_no_data_mutation(tmp_path):
    app = create_app(mode="live", db_path=tmp_path / "api.sqlite")
    add(app.state.store, "live", "FINDING_INGESTED", run_mode="LIVE")
    add(app.state.store, "replay", "FINDING_INGESTED", run_mode="REPLAY")
    before = app.state.store.list_events()
    with TestClient(app) as client:
        response = client.get("/api/eventlog.csv")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert 'filename="pulseguard-eventlog.csv"' in response.headers["content-disposition"]
        assert [row["case_id"] for row in csv.DictReader(io.StringIO(response.text))] == ["live"]
        assert client.get("/api/kpis").json()["cases_total"] == 1
    assert app.state.store.list_events() == before


def test_replay_mode_fallback_and_live_cannot_leak_replay_rows(tmp_path):
    db = tmp_path / "shared.sqlite"
    app = create_app(mode="replay", db_path=db)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        rows = list(csv.DictReader(io.StringIO(client.get("/api/eventlog.csv").text)))
        assert rows and all(row["run_mode"] == "REPLAY" for row in rows)
        assert client.get("/api/kpis").json() == compute_kpis(read_events(app.state.store))
    with TestClient(create_app(mode="live", db_path=db)) as client:
        assert client.get("/api/kpis").json()["cases_total"] == 0
        assert len(client.get("/api/eventlog.csv").text.splitlines()) == 1


def test_invalid_replay_blocks_telemetry(tmp_path):
    root = tmp_path / "invalid"
    root.mkdir()
    with TestClient(create_app(mode="replay", db_path=tmp_path / "bad.sqlite",
                               replay_root=root)) as client:
        for path in ("/api/kpis", "/api/eventlog.csv"):
            assert client.get(path).status_code == 503


def test_surface_static_files_reference_new_contract_without_javascript(tmp_path):
    with TestClient(create_app(mode="replay", db_path=tmp_path / "web.sqlite")) as client:
        html = client.get("/")
        assert html.status_code == 200
        assert 'id="mode"' in html.text and "MODE UNAVAILABLE" in html.text
        assert '/api/eventlog.csv' in html.text and '/api/kpis' in html.text
        js = client.get("/app.js")
        assert js.status_code == 200
        for reference in ("/api/kpis", '"/rollback"', "verification", "skeptic", "counterfactual",
                          "blast_radius", "bus_health", "policy_tier", "SYNTHETIC"):
            assert reference in js.text
        assert client.get("/style.css").status_code == 200

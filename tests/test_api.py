import json
import shutil

import pytest
from fastapi.testclient import TestClient

from pulseguard.api import create_app
from pulseguard.paths import replay_dir


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(mode="replay", db_path=tmp_path / "api.sqlite")) as client:
        yield client


def test_health_and_default_mode(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["replay_verified"] is True
    mode = client.get("/api/mode").json()
    assert mode["mode"] == "REPLAY"
    assert mode["recorded"] is False
    assert "PLACEHOLDER" in mode["label"]
    assert len(mode["manifest_sha256"]) == 64


def test_mode_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("PG_MODE", "LiVe")
    with TestClient(create_app(db_path=tmp_path / "live.sqlite")) as client:
        assert client.get("/api/mode").json()["mode"] == "LIVE"
        assert client.get("/api/cases").json()["cases"] == []
        assert client.post("/api/runs").status_code in (404, 405)


def test_board_detail_trace_and_simulated_decisions(client):
    cases = client.get("/api/cases").json()["cases"]
    assert len(cases) == 1
    path = "/api/cases/" + cases[0]["case_id"]
    before = client.get(path).json()
    assert len(before["evidence"]) == 3
    assert len(before["verdicts"]) == 1
    assert client.get("/api/cases?state=quarantined").json()["cases"] == []
    events = client.get(path + "/trace").json()["events"]
    jsonl = client.get(path + "/trace?format=jsonl")
    assert jsonl.headers["content-type"].startswith("application/x-ndjson")
    assert [json.loads(line) for line in jsonl.text.splitlines()] == events
    for decision in ("approve", "reject"):
        response = client.post(path + "/decision", json={"decision": decision})
        assert response.status_code == 200
        assert response.json()["simulated"] is True
        assert response.json()["approval"]["simulated"] is True
        assert "simulated" in response.json()["label"]
    assert client.get(path).json() == before
    assert client.get(path + "/trace").json()["events"] == events
    assert client.post(path + "/decision", json={"decision": "merge"}).status_code == 422
    assert client.post(path + "/decision", json={
        "decision": "approve", "actor": " ",
    }).status_code == 422
    assert client.get("/api/cases/missing").status_code == 404


def test_static_ui_is_served(client):
    assert "MODE UNAVAILABLE" in client.get("/").text
    for path in ("/app.js", "/style.css"):
        assert client.get(path).status_code == 200


def test_tampered_bundle_blocks_stale_cases(tmp_path):
    root = tmp_path / "replay"
    shutil.copytree(replay_dir(), root)
    db = tmp_path / "state.sqlite"
    app = create_app(mode="replay", db_path=db, replay_root=root)
    assert app.state.store.list_cases()
    next((root / "runs").rglob("run.json")).write_text("{}")
    with TestClient(create_app(mode="replay", db_path=db, replay_root=root)) as client:
        assert client.get("/health").status_code == 503
        assert client.get("/api/mode").json()["replay_verified"] is False
        assert client.get("/api/cases").status_code == 503
        assert client.get("/api/cases/PG-S1-PLACEHOLDER").status_code == 503


def test_invalid_mode(tmp_path):
    with pytest.raises(ValueError):
        create_app(mode="pretend", db_path=tmp_path / "api.sqlite")


def test_live_mode_never_relabels_replay_cases(tmp_path):
    db = tmp_path / "shared.sqlite"
    create_app(mode="replay", db_path=db)
    with TestClient(create_app(mode="live", db_path=db)) as client:
        assert client.get("/api/cases").json()["cases"] == []
        assert client.get("/api/cases/PG-S1-PLACEHOLDER").status_code == 404

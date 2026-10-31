"""Token-gated S3 run admission, adapted from tradepulse API contract tests."""

import asyncio
import threading

import pytest
from fastapi.testclient import TestClient

from pulseguard.api import create_app
from pulseguard.paths import REPO_ROOT
from pulseguard.run import live_run
from tests.fakes import FakeLLM

TOKEN = "test-token-never-log"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


class FakeRunner:
    def __init__(self, *, paused=False, error=None):
        self.release = threading.Event()
        self.finished = threading.Event()
        self.calls = []
        self.error = error
        if not paused:
            self.release.set()

    async def __call__(self, target, **kwargs):
        self.calls.append((target, kwargs))
        while not self.release.is_set():
            await asyncio.sleep(0.01)
        self.finished.set()
        if self.error:
            raise self.error
        return [{"case_id": "PG-test-run"}]


@pytest.mark.parametrize(("mode", "token", "headers", "code"), [
    ("replay", TOKEN, HEADERS, 404),
    ("live", None, HEADERS, 503),
    ("live", "", HEADERS, 503),
    ("live", TOKEN, {}, 401),
    ("live", TOKEN, {"Authorization": "Bearer wrong"}, 401),
    ("live", TOKEN, {"Authorization": f"Basic {TOKEN}"}, 401),
])
def test_run_endpoint_mode_and_auth(tmp_path, monkeypatch, mode, token, headers, code):
    if token is None:
        monkeypatch.delenv("PG_LIVE_TOKEN", raising=False)
    else:
        monkeypatch.setenv("PG_LIVE_TOKEN", token)
    runner = FakeRunner()
    with TestClient(create_app(mode=mode, db_path=tmp_path / "api.sqlite",
                               live_runner=runner)) as client:
        assert client.post("/api/runs", headers=headers, json={}).status_code == code
        assert client.post("/api/runs", headers=headers, content="{broken").status_code == code
        assert client.get("/api/runs/missing", headers=headers).status_code == code
        assert not runner.calls
        assert client.get("/health").status_code == 200


def wait_completed(client, run_id):
    for _ in range(100):
        response = client.get(f"/api/runs/{run_id}", headers=HEADERS)
        assert response.status_code == 200
        if response.json()["status"] in ("completed", "failed"):
            return response.json()
    pytest.fail("injected runner did not complete")


def test_good_token_202_status_200_and_busy_409(tmp_path, monkeypatch):
    monkeypatch.setenv("PG_MODE", "live")
    monkeypatch.setenv("PG_LIVE_TOKEN", TOKEN)
    runner = FakeRunner(paused=True)
    compared = []
    import hmac
    compare = hmac.compare_digest

    def checked(left, right):
        compared.append((left, right))
        return compare(left, right)

    monkeypatch.setattr("pulseguard.api.hmac.compare_digest", checked)
    with TestClient(create_app(db_path=tmp_path / "api.sqlite", live_runner=runner)) as client:
        response = client.post("/api/runs", headers=HEADERS, json={"scanners": ["bandit"]})
        assert response.status_code == 202, response.text
        run_id = response.json()["run_id"]
        assert response.json()["ephemeral"] is True
        assert "lost on restart" in response.json()["label"]
        assert client.get(f"/api/runs/{run_id}", headers=HEADERS).json()["status"] == "running"
        assert client.post("/api/runs", headers=HEADERS, json={}).status_code == 409
        assert client.get("/api/mode").json()["label"].endswith("lost on restart.")
        assert client.get("/api/mode").json()["run_id"] == run_id
        runner.release.set()
        assert runner.finished.wait(2)
        completed = wait_completed(client, run_id)
        assert completed["status"] == "completed"
        assert completed["case_ids"] == ["PG-test-run"]
        assert runner.calls == [(REPO_ROOT / "demo_target" / "order_api", {
            "db_path": tmp_path / "api.sqlite", "run_id": run_id, "scanners": ("bandit",),
        })]
        assert any(pair == (TOKEN.encode(), TOKEN.encode()) for pair in compared)


@pytest.mark.parametrize("body", [
    {"target": "elsewhere"}, {"scanners": ["trivy"], "url": "https://example.invalid"},
    {"scanners": ["arbitrary-command"]}, {"scanners": []},
    {"scanners": ["bandit", "bandit"]}, {"scanners": [1]},
])
def test_only_allowlisted_scanner_selection_accepted(tmp_path, monkeypatch, body):
    monkeypatch.setenv("PG_LIVE_TOKEN", TOKEN)
    runner = FakeRunner()
    with TestClient(create_app(mode="live", db_path=tmp_path / "api.sqlite",
                               live_runner=runner)) as client:
        assert client.post("/api/runs", headers=HEADERS, json=body).status_code == 422
        assert not runner.calls


def test_rate_limit_failed_run_release_and_no_token_leaks(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("PG_LIVE_TOKEN", TOKEN)
    runner = FakeRunner(error=RuntimeError(f"provider echoed {TOKEN}"))
    with TestClient(create_app(mode="live", db_path=tmp_path / "api.sqlite",
                               live_runner=runner)) as client:
        for _ in range(3):
            response = client.post("/api/runs", headers=HEADERS)
            assert response.status_code == 202
            row = wait_completed(client, response.json()["run_id"])
            assert row["status"] == "failed"
            assert TOKEN not in str(row)
            assert runner.calls[-1][1]["scanners"] == ("semgrep", "bandit", "trivy")
        response = client.post("/api/runs", headers=HEADERS)
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "60"
        assert TOKEN not in response.text and TOKEN not in caplog.text


def test_status_lost_on_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("PG_LIVE_TOKEN", TOKEN)
    db = tmp_path / "api.sqlite"
    with TestClient(create_app(mode="live", db_path=db, live_runner=FakeRunner())) as client:
        run_id = client.post("/api/runs", headers=HEADERS).json()["run_id"]
        wait_completed(client, run_id)
    with TestClient(create_app(mode="live", db_path=db, live_runner=FakeRunner())) as client:
        assert client.get(f"/api/runs/{run_id}", headers=HEADERS).status_code == 404


def test_live_run_scanner_selection_and_bundled_target(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("pulseguard.run.bandit_findings", lambda target: calls.append(target) or [])

    class NoSemgrep:
        def run(self, target):
            pytest.fail("unselected Semgrep must not run")

    statuses = asyncio.run(live_run(
        REPO_ROOT / "demo_target" / "order_api", db_path=tmp_path / "live.sqlite",
        llm=FakeLLM([]), scanner=NoSemgrep(), scanners=("bandit",),
    ))
    assert statuses == []
    assert calls == [REPO_ROOT / "demo_target" / "order_api"]
    with pytest.raises(ValueError, match="limited to demo_target"):
        asyncio.run(live_run(tmp_path, llm=FakeLLM([]), scanners=("bandit",)))
    with pytest.raises(ValueError, match="unique scanners"):
        asyncio.run(live_run(REPO_ROOT / "demo_target" / "order_api", llm=FakeLLM([]),
                             scanners=("untrusted",)))

"""Playground API: caps, Guard, scanners, evidence, limits, veto, rate limits.

No test in this module makes a real model call. Clients are injected fakes.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pulseguard.api import create_app
from pulseguard.paths import REPO_ROOT
from pulseguard.playground import (
    EXAMPLES,
    MAX_BYTES,
    MAX_LINES,
    SNIPPET_NAME,
    PlaygroundHooks,
    PlaygroundLimiter,
    config_from_prefix,
    strip_ground_truth,
    validate_snippet,
)
from pulseguard.scanners.semgrep import SemgrepError, SemgrepRunner, SemgrepUnavailable
from tests.fakes import FakeLLM, verdict

SQLI = next(item["code"] for item in EXAMPLES if item["id"] == "sqli-concat")
REVIEWER = next(item["code"] for item in EXAMPLES if item["id"] == "ai-reviewer")
NUMERIC = next(item["code"] for item in EXAMPLES if item["id"] == "z3-numeric-unsat")
SECRET = "pg-playground-secret-never-echo"
HOSTISH = tempfile.gettempdir()


class EmptyScanner:
    def __init__(self) -> None:
        self.targets: list[Path] = []

    def run(self, target):
        path = Path(target)
        self.targets.append(path)
        assert (path / SNIPPET_NAME).is_file()
        return []


class BoomLLM:
    model = "boom-model"

    def chat(self, *args, **kwargs):
        raise AssertionError("model must not be called")


class Clock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _client(tmp_path, *, clients=None, limiter=None, semgrep=None, bandit=None, mode="replay"):
    hooks = PlaygroundHooks(
        clients={} if clients is None else clients,
        limiter=limiter,
        semgrep=EmptyScanner() if semgrep is None else semgrep,
        bandit=EmptyScanner() if bandit is None else bandit,
    )
    return TestClient(create_app(
        mode=mode, db_path=tmp_path / "playground.sqlite", playground=hooks))


def _analyze(client, code=SQLI, model="muse", headers=None):
    return client.post(
        "/api/playground/analyze",
        json={"code": code, "model": model},
        headers=headers or {},
    )


def test_caps_size_lines_and_non_parsable(tmp_path):
    client = _client(tmp_path)
    huge = "x = 1\n" + ("a" * (MAX_BYTES + 10))
    size = _analyze(client, huge)
    assert size.status_code == 400
    assert "bytes" in size.json()["detail"]
    lines = _analyze(client, "x = 1\n" * (MAX_LINES + 1))
    assert lines.status_code == 400
    assert "lines" in lines.json()["detail"]
    parse = _analyze(client, "def (\n")
    assert parse.status_code == 400
    assert "parse" in parse.json()["detail"].lower()
    empty = _analyze(client, "   \n")
    assert empty.status_code == 400


def test_validate_snippet_and_strip_helpers():
    with pytest.raises(ValueError, match="UTF-8"):
        validate_snippet("ok\0no")
    stripped = strip_ground_truth(
        "q = 1  # @vuln sqli: concat\n"
        "r = 2  # @safe sqli: bound\n"
    )
    assert "@vuln" not in stripped
    assert "@safe" not in stripped
    assert "q = 1" in stripped


def test_annotation_stripping_never_reaches_model(tmp_path):
    llm = FakeLLM([verdict()])
    client = _client(tmp_path, clients={"muse": llm})
    code = (
        "import sqlite3\nfrom flask import request\n"
        "def order():\n"
        "    order_id = request.args.get(\"id\")\n"
        "    q = \"SELECT id FROM orders WHERE id = '\" + order_id + \"'\"  # @vuln sqli\n"
        "    return sqlite3.connect(\":memory:\").execute(q).fetchall()\n"
    )
    response = _analyze(client, code)
    assert response.status_code == 200
    assert llm.calls
    assert "@vuln" not in llm.calls[0]["user"]
    assert response.json()["stripped_annotations"] is True


def test_guard_quarantine_skips_model(tmp_path):
    llm = BoomLLM()
    client = _client(tmp_path, clients={"muse": llm})
    response = _analyze(client, REVIEWER)
    assert response.status_code == 200
    body = response.json()
    assert body["guard"]["flagged"] is True
    assert "ai_reviewer" in ",".join(body["guard"]["patterns"]) or body["guard"]["patterns"]
    row = body["results"][0]
    assert row["model_called"] is False
    assert "quarantined" in row["model_skipped_reason"]
    assert "Guard" in row["decision"]


def test_examples_and_config_endpoints(tmp_path, monkeypatch):
    monkeypatch.setenv("PG_PLAYGROUND_MUSE_API_KEY", SECRET)
    monkeypatch.setenv("PG_PLAYGROUND_MUSE_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("PG_PLAYGROUND_MUSE_NAME", "muse-spark-test")
    client = _client(tmp_path, clients={})
    examples = client.get("/api/playground/examples").json()["examples"]
    ids = [item["id"] for item in examples]
    assert ids == [
        "sqli-concat", "sqli-fstring", "parameterized-safe", "allowlist-safe",
        "z3-numeric-unsat", "unanchored-regex", "comment-inject", "ai-reviewer",
    ]
    config = client.get("/api/playground/config")
    assert config.status_code == 200
    body = config.json()
    assert body["enabled"] is True
    assert body["caps"]["max_bytes"] == MAX_BYTES
    assert body["limits"]["counters_reset_on_restart"] is True
    assert SECRET not in config.text
    assert "example.test" not in config.text
    names = {item["id"]: item for item in body["models"]}
    assert names["muse"]["name"] == "Meta Muse Spark"
    assert names["nemotron"]["name"] == "NVIDIA Nemotron"
    assert names["muse"]["available"] is False


def test_degraded_without_keys(tmp_path):
    client = _client(tmp_path, clients={})
    response = _analyze(client, SQLI)
    assert response.status_code == 200
    row = response.json()["results"][0]
    assert row["model_called"] is False
    assert "not configured" in row["model_skipped_reason"]
    assert "Static analysis only" in row["decision"]
    assert row["evidence"]


def test_compare_mode_two_fakes_disagree(tmp_path):
    muse = FakeLLM([verdict(0.95)])
    nemo = FakeLLM([verdict(0.1)])
    client = _client(tmp_path, clients={"muse": muse, "nemotron": nemo})
    response = _analyze(client, SQLI, model="both")
    assert response.status_code == 200
    body = response.json()
    assert body["compare"]["agree"] is False
    bands = [(row["model_id"], row["verdict"]["band"]) for row in body["results"]]
    assert ("muse", "confirmed") in bands
    assert ("nemotron", "false_positive") in bands
    assert muse.calls and nemo.calls


def test_evidence_limits_and_z3_unsat_veto(tmp_path):
    pytest.importorskip("z3")
    llm = FakeLLM([verdict(0.95)])
    client = _client(tmp_path, clients={"muse": llm})
    response = _analyze(client, NUMERIC)
    assert response.status_code == 200
    row = response.json()["results"][0]
    ids = [item["evidence_id"] for item in row["evidence"]]
    assert "E1" in ids and "E2" in ids and "E3" in ids
    assert row["z3"]["result"] == "unsat"
    assert row["z3"]["claim"] is True
    assert row["dominance"]["dominates"] is True
    assert row["z3_veto"] == "applied"
    assert row["verdict"]["band"] == "abstained"
    assert "E6" in row["decision"] or "veto" in row["decision"].lower()


def test_no_scanner_finding_still_adjudicates(tmp_path):
    llm = FakeLLM([verdict(0.4)])
    client = _client(tmp_path, clients={"muse": llm})
    response = _analyze(client, SQLI)
    assert response.status_code == 200
    row = response.json()["results"][0]
    assert row["scanner_finding"] is False
    assert row["scanner_note"] == "no scanner finding"
    assert row["model_called"] is True
    assert llm.calls
    assert "no scanner finding" in row["decision"].lower()


def test_provider_error_type_only_no_secrets_or_host_paths(tmp_path):
    class SecretError(RuntimeError):
        def __init__(self) -> None:
            super().__init__("api_key=" + SECRET)
            self.status_code = 401

    llm = FakeLLM([SecretError()])
    client = _client(tmp_path, clients={"muse": llm})
    response = _analyze(client, SQLI)
    assert response.status_code == 200
    text = json.dumps(response.json())
    assert SECRET not in text
    assert HOSTISH.replace("\\", "/") not in text.replace("\\", "/")
    assert "C:/" not in text and "D:/" not in text
    meta = response.json()["results"][0]["model_metadata"]
    assert meta["error"] == "SecretError"
    assert meta["status_code"] == 401
    assert SQLI.splitlines()[0] not in text


def test_non_execution_marker_file_absent(tmp_path):
    marker = tmp_path / "executed.marker"
    code = (
        "from pathlib import Path\n"
        f"Path(r'{marker}').write_text('executed')\n"
        "import sqlite3\n"
        "from flask import request\n"
        "def order():\n"
        "    order_id = request.args.get('id')\n"
        "    q = \"SELECT id FROM orders WHERE id = '\" + order_id + \"'\"\n"
        "    return sqlite3.connect(':memory:').execute(q).fetchall()\n"
    )
    llm = FakeLLM([verdict()])
    client = _client(tmp_path, clients={"muse": llm})
    response = _analyze(client, code)
    assert response.status_code == 200
    assert not marker.exists()


def test_rate_limits_minute_day_concurrent_and_forwarded_for(tmp_path):
    clock = Clock(10.0)
    limiter = PlaygroundLimiter(per_minute=2, per_day=3, daily_model_calls=50, clock=clock)
    client = _client(tmp_path, clients={}, limiter=limiter)
    headers_a = {"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}
    headers_b = {"X-Forwarded-For": "198.51.100.2"}
    assert _analyze(client, SQLI, headers=headers_a).status_code == 200
    assert _analyze(client, SQLI, headers=headers_a).status_code == 200
    limited = _analyze(client, SQLI, headers=headers_a)
    assert limited.status_code == 429
    assert limited.headers["Retry-After"]
    assert _analyze(client, SQLI, headers=headers_b).status_code == 200
    clock.t = 10.0 + 61
    assert _analyze(client, SQLI, headers=headers_a).status_code == 200
    day = _analyze(client, SQLI, headers=headers_a)
    assert day.status_code == 429
    assert "day" in day.json()["detail"]
    clock.t = 10.0 + 86401
    assert _analyze(client, SQLI, headers=headers_a).status_code == 200

    busy = PlaygroundLimiter(clock=Clock(0))
    busy.in_flight.add("203.0.113.9")
    other = _client(tmp_path / "busy", clients={}, limiter=busy)
    concurrent = _analyze(other, SQLI, headers=headers_a)
    assert concurrent.status_code == 429
    assert "one analysis" in concurrent.json()["detail"]


def test_global_model_budget_degrades(tmp_path):
    limiter = PlaygroundLimiter(daily_model_calls=1, clock=Clock(0))
    muse = FakeLLM([verdict(), verdict()])
    client = _client(tmp_path, clients={"muse": muse}, limiter=limiter)
    first = _analyze(client, SQLI)
    second = _analyze(client, SQLI)
    assert first.status_code == 200
    assert first.json()["results"][0]["model_called"] is True
    assert second.status_code == 200
    row = second.json()["results"][0]
    assert row["model_called"] is False
    assert "budget" in row["model_skipped_reason"]
    assert len(muse.calls) == 1
    assert second.json()["budget"]["remaining_model_calls"] == 0


def test_config_from_prefix_defaults():
    muse = config_from_prefix("PG_PLAYGROUND_MUSE", {
        "PG_PLAYGROUND_MUSE_BASE_URL": "http://local.test/v1",
        "PG_PLAYGROUND_MUSE_NAME": "muse-spark-test",
        "PG_PLAYGROUND_MUSE_API_KEY": "k",
    }, defaults={"SESSION_HEADER": "x-opencode-session"})
    assert muse is not None
    assert muse.session_header == "x-opencode-session"
    nemo = config_from_prefix("PG_PLAYGROUND_NEMOTRON", {
        "PG_PLAYGROUND_NEMOTRON_BASE_URL": "http://local.test/v1",
        "PG_PLAYGROUND_NEMOTRON_NAME": "nemotron-test",
        "PG_PLAYGROUND_NEMOTRON_API_KEY": "k",
    }, defaults={"STRUCTURED": "off"})
    assert nemo is not None
    assert nemo.structured == "off"
    assert config_from_prefix("PG_PLAYGROUND_MUSE", {}) is None


def test_playground_works_in_live_mode(tmp_path):
    client = _client(tmp_path, clients={}, mode="live")
    assert client.get("/api/playground/config").status_code == 200
    assert _analyze(client, SQLI).status_code == 200


def test_replay_cases_unchanged_by_playground(tmp_path):
    llm = FakeLLM([verdict()])
    client = _client(tmp_path, clients={"muse": llm})
    before = client.get("/api/cases").json()
    assert _analyze(client, SQLI).status_code == 200
    after = client.get("/api/cases").json()
    assert before == after
    assert client.get("/health").json()["status"] == "ok"


def test_tempfile_cleaned_after_analysis(tmp_path, monkeypatch):
    created: list[str] = []
    real = tempfile.mkdtemp

    def wrapped(*args, **kwargs):
        path = real(*args, **kwargs)
        created.append(path)
        return path

    monkeypatch.setattr("pulseguard.playground.tempfile.mkdtemp", wrapped)
    client = _client(tmp_path, clients={})
    assert _analyze(client, SQLI).status_code == 200
    assert created
    assert not Path(created[0]).exists()


@pytest.mark.semgrep
def test_semgrep_and_bandit_on_temp_snippet(tmp_path, monkeypatch):
    from pulseguard.scanners.bandit import BanditRunner

    created: list[str] = []
    real = tempfile.mkdtemp

    def wrapped(*args, **kwargs):
        path = real(*args, **kwargs)
        created.append(path)
        return path

    monkeypatch.setattr("pulseguard.playground.tempfile.mkdtemp", wrapped)
    try:
        semgrep = SemgrepRunner(timeout=30.0)
        semgrep.count(REPO_ROOT / "demo_target" / "order_api", "flask-sqli-taint")
    except (SemgrepError, SemgrepUnavailable, OSError) as exc:
        reason = ("CertOpenSystemStore returned NULL" if "CertOpenSystemStore" in str(exc)
                  else str(exc).splitlines()[0])
        pytest.skip(f"Semgrep cannot run on this host: {reason}")
    llm = FakeLLM([verdict()])
    client = _client(
        tmp_path, clients={"muse": llm},
        semgrep=semgrep, bandit=BanditRunner(timeout=30.0),
    )
    response = _analyze(client, SQLI)
    assert response.status_code == 200
    row = response.json()["results"][0]
    assert any(hit["rule_id"] == "flask-sqli-taint" for hit in row["semgrep"])
    assert row["scanner_finding"] is True
    assert created
    assert not Path(created[0]).exists()
    text = json.dumps(response.json())
    assert HOSTISH.replace("\\", "/") not in text.replace("\\", "/")
    assert os.path.abspath(created[0]).replace("\\", "/") not in text.replace("\\", "/")

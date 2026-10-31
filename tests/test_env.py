"""CLI env-file and recording privacy tests for tradepulse's bundle export pattern."""

import json
import os
from types import SimpleNamespace

import pytest

from pulseguard.agents.llm import LLMConfig, OpenAIChatClient
from pulseguard.env import load_env_file
from pulseguard.patching.sandbox import SandboxVerifier
from pulseguard.paths import default_db_path
from pulseguard.replay.record import main as record_main
from pulseguard.replay.verify import verify_manifest
from pulseguard.run import main as run_main
from tests.fakes import PATCH, FakeScanner, verdict


def test_env_file_literal_values_and_override(tmp_path, monkeypatch):
    path = tmp_path / "model.env"
    path.write_text('# comment\n\nPG_TEST_ENV = "literal=a#b"\nPG_TEST_OTHER=\'no expansion $x\'\n',
                    encoding="utf-8-sig")
    monkeypatch.setenv("PG_TEST_ENV", "previous")
    monkeypatch.setenv("PG_TEST_OTHER", "previous")
    load_env_file(path)
    assert os.environ["PG_TEST_ENV"] == "literal=a#b"
    assert os.environ["PG_TEST_OTHER"] == "no expansion $x"


@pytest.mark.parametrize("line", ["secret-bad-line", 'KEY="secret-unclosed', "KEY=secret\0"])
def test_invalid_env_file_never_echoes_values_or_partially_loads(tmp_path, monkeypatch, line):
    path = tmp_path / "model.env"
    path.write_text("PG_TEST_ENV=new-value\n" + line, encoding="utf-8")
    monkeypatch.setenv("PG_TEST_ENV", "previous")
    with pytest.raises(ValueError) as error:
        load_env_file(path)
    assert "secret" not in str(error.value)
    assert os.environ["PG_TEST_ENV"] == "previous"


def test_live_cli_env_file_loaded_before_run(tmp_path, monkeypatch, capsys):
    path = tmp_path / "live.env"
    db = tmp_path / "from-env.sqlite"
    path.write_text(f"PG_MODEL_API_KEY=live-test-secret\nPG_DB_PATH={db}\n", encoding="utf-8")
    monkeypatch.setenv("PG_MODEL_API_KEY", "previous")
    monkeypatch.setenv("PG_DB_PATH", "previous")

    async def fake_run(target, **kwargs):
        assert os.environ["PG_MODEL_API_KEY"] == "live-test-secret"
        assert default_db_path() == db
        return []

    monkeypatch.setattr("pulseguard.run.live_run", fake_run)
    assert run_main(["--env-file", str(path), "--target", "demo_target/order_api"]) == 0
    assert "live-test-secret" not in capsys.readouterr().out


def test_recording_env_file_keeps_key_out_of_bundle_trace_and_metadata(tmp_path, monkeypatch,
                                                                    capsys):
    secret = "test-only-credential-never-export"
    values = {
        "PG_MODEL_BASE_URL": f"https://user:{secret}@provider.test/v1?key={secret}",
        "PG_MODEL_NAME": "configured-test-model", "PG_MODEL_API_KEY": secret,
        "PG_MODEL_STRUCTURED": "off", "PG_MODEL_SESSION_HEADER": "x-opencode-session",
        "PG_DB_PATH": str(tmp_path / "recording.sqlite"),
    }
    path = tmp_path / "record.env"
    path.write_text("\n".join(f"{key}={value}" for key, value in values.items()), encoding="utf-8")
    for key in values:
        monkeypatch.setenv(key, "previous")
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        assert "response_format" not in kwargs
        payload = verdict() if len(calls) == 1 else PATCH
        return SimpleNamespace(
            model="actual-test-model",
            choices=[SimpleNamespace(message=SimpleNamespace(
                content=json.dumps(payload), reasoning_content=secret))],
            usage=SimpleNamespace(model_dump=lambda: {
                "total_tokens": 150, "opencode": {"cost": 0.001}}),
        )

    def factory():
        config = LLMConfig.from_env()
        assert config.api_key == secret
        return OpenAIChatClient(config, SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))))

    monkeypatch.setattr("pulseguard.run.make_llm", factory)
    monkeypatch.setattr("pulseguard.run.SemgrepRunner", lambda **kwargs: FakeScanner())
    monkeypatch.setattr(SandboxVerifier, "_pytest", lambda self, work: (True, "3 passed"))
    root = tmp_path / "replay"
    assert record_main([
        "--env-file", str(path), "--root", str(root), "--run-id", "env-recording",
        "--auto-approve-as", "test-recorder",
    ]) == 0
    assert secret not in capsys.readouterr().out
    assert verify_manifest(root).ok
    run = json.loads((root / "runs" / "env-recording" / "run.json").read_text())
    case = run["cases"][0]
    metadata = case["verdict_metadata"]
    assert metadata["model"] == "actual-test-model"
    assert metadata["base_url_host"] == "provider.test"
    assert metadata["structured_mode"] == "off" and metadata["structured_output"] is False
    assert metadata["latency_ms"] >= 0
    assert metadata["usage"]["opencode"] == {"cost": 0.001}
    assert len(case["model_calls"]) == 2
    assert all(call["usage"]["total_tokens"] == 150 for call in case["model_calls"])
    artifact_roots = [root, tmp_path / "pulseguard-bundles"]
    for artifact_root in artifact_roots:
        for artifact in artifact_root.rglob("*"):
            if artifact.is_file():
                assert secret.encode() not in artifact.read_bytes(), artifact.name
    assert secret not in (tmp_path / "recording.trace.jsonl").read_text()

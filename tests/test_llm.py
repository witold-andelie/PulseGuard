"""Provider adapter tests for the revio OpenAI factory, using httpx transport only."""

import json
from dataclasses import replace

import httpx
import pytest
from openai import APITimeoutError, OpenAI, RateLimitError

from pulseguard import __version__
from pulseguard.agents.adjudicator import adjudicate
from pulseguard.agents.llm import (
    LLMConfig,
    LLMConfigError,
    OpenAIChatClient,
    make_llm,
    model_facing_schema,
    output_schema,
)
from pulseguard.agents.remediator import propose_patch
from pulseguard.contracts.models import Finding
from tests.fakes import PATCH, verdict


def completion():
    return {
        "id": "test", "object": "chat.completion", "created": 1, "model": "provider-test-model",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": '{"score":0.9}'},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def client(handler, retries=2, **config_options):
    config = LLMConfig("http://local.test/v1", "configured-test-model", "test-only-key",
                       **config_options)
    sdk = OpenAI(
        base_url=config.base_url, api_key=config.api_key, timeout=0.1, max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    return OpenAIChatClient(config, sdk, max_retries=retries)


def test_schema_fallback_and_metadata():
    calls = []

    def handler(request):
        data = json.loads(request.content)
        calls.append(data)
        if len(calls) == 1:
            return httpx.Response(400, json={"error": {"message": "response_format unsupported"}})
        return httpx.Response(200, json=completion())

    adapter = client(handler)
    response = adapter.chat("system", "user", schema=output_schema("verdict"))
    assert calls[0]["response_format"]["type"] == "json_schema"
    assert calls[0]["response_format"]["json_schema"]["schema"] == model_facing_schema(
        output_schema("verdict"))
    assert json.loads(calls[0]["messages"][1]["content"].split("Return JSON matching:\n")[1]) == (
        calls[0]["response_format"]["json_schema"]["schema"])
    assert "response_format" not in calls[1]
    assert "Return JSON matching:" in calls[1]["messages"][1]["content"]
    assert response.text == '{"score":0.9}'
    assert response.model == "provider-test-model"
    assert response.latency_ms >= 0
    assert response.usage["total_tokens"] == 15
    adapter.chat("system", "user", schema=output_schema("patchset"))
    assert "response_format" not in calls[2]


@pytest.mark.parametrize("timeout", [True, False])
def test_retries_are_bounded(monkeypatch, timeout):
    monkeypatch.setattr("pulseguard.agents.llm.time.sleep", lambda seconds: None)
    calls = []

    def handler(request):
        calls.append(request)
        if timeout:
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(429, json={"error": {"message": "too many requests"}})

    with pytest.raises(APITimeoutError if timeout else RateLimitError):
        client(handler).chat("system", "user", schema=output_schema("verdict"))
    assert len(calls) == 3


def test_factory_uses_environment_and_timeout(monkeypatch):
    monkeypatch.setenv("PG_MODEL_BASE_URL", "http://configured.test/v1")
    monkeypatch.setenv("PG_MODEL_NAME", "configured-test-model")
    monkeypatch.setenv("PG_MODEL_API_KEY", "test-only-key")
    adapter = make_llm()
    assert adapter.model == "configured-test-model"
    assert str(adapter.client.base_url) == "http://configured.test/v1/"
    assert adapter.client.max_retries == 0
    assert adapter.client.timeout == 120.0
    assert adapter.config.max_tokens == 8192
    assert adapter.config.structured == "auto"
    assert "test-only-key" not in repr(adapter.config)


@pytest.mark.parametrize("name", ["verdict", "patchset"])
def test_model_schema_removes_provider_keywords_and_system_fields(name):
    schema = output_schema(name)
    original = json.dumps(schema)
    facing = model_facing_schema(schema)
    assert json.dumps(schema) == original
    assert all(key not in json.dumps(facing) for key in ("$schema", "$id", "uniqueItems"))
    assert set(facing["properties"]).isdisjoint({
        "band", "role", "model", "case_id", "verdict_id", "created_at", "state"})
    assert set(facing["required"]) <= set(facing["properties"])
    if name == "verdict":
        assert facing["properties"]["score"] == {
            "type": "number", "minimum": 0.0, "maximum": 1.0}
        assert schema["properties"]["cited_evidence"]["uniqueItems"] is True


@pytest.mark.parametrize("status", [400, 404, 422])
@pytest.mark.parametrize("message", [
    'Grammar error: Unimplemented keys: ["uniqueItems"]',
    "unsupported keys", "json_schema unavailable", "structured output unavailable",
])
def test_auto_retries_grammar_without_response_format(status, message):
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        if len(calls) == 1:
            return httpx.Response(status, json={"error": {"message": message}})
        return httpx.Response(200, json=completion())

    adapter = client(handler)
    result = adapter.chat("system", "user", schema=output_schema("verdict"))
    assert "response_format" in calls[0]
    assert "response_format" not in calls[1]
    assert result.metadata()["structured_mode"] == "auto"
    assert result.metadata()["structured_output"] is False
    adapter.chat("system", "user", schema=output_schema("verdict"))
    assert "response_format" not in calls[2]


def test_off_extra_body_and_reasoning_usage():
    calls = []
    extra = {"chat_template_kwargs": {"enable_thinking": True}}

    def handler(request):
        calls.append(json.loads(request.content))
        result = completion()
        result["choices"][0]["message"]["reasoning_content"] = "private reasoning, not the answer"
        result["usage"]["opencode"] = {"cost": 0.001}
        return httpx.Response(200, json=result)

    response = client(handler, structured="off", extra_body=extra, max_tokens=9000).chat(
        "system", "user", schema=output_schema("patchset"))
    assert "response_format" not in calls[0]
    assert calls[0]["chat_template_kwargs"] == extra["chat_template_kwargs"]
    assert calls[0]["max_tokens"] == 9000
    assert response.text == '{"score":0.9}'
    assert "private reasoning" not in json.dumps(response.metadata())
    assert response.usage["opencode"] == {"cost": 0.001}
    assert all(response.usage[key] == value for key, value in completion()["usage"].items())
    assert response.metadata()["base_url_host"] == "local.test"
    assert response.metadata()["structured_mode"] == "off"
    assert response.metadata()["session_header_sent"] is False
    assert "session_header" not in response.metadata()


@pytest.mark.parametrize("extra", [
    "not JSON", "[]", "null", '{"x":', '{"x":NaN}', '{"x":Infinity}',
])
def test_extra_body_must_be_json_object(extra):
    with pytest.raises(LLMConfigError, match="PG_MODEL_EXTRA_BODY"):
        LLMConfig.from_env({"PG_MODEL_BASE_URL": "http://local.test", "PG_MODEL_NAME": "test",
                            "PG_MODEL_API_KEY": "test-key", "PG_MODEL_EXTRA_BODY": extra})


def test_optional_configuration_from_env():
    config = LLMConfig.from_env({
        "PG_MODEL_BASE_URL": "http://local.test", "PG_MODEL_NAME": "test",
        "PG_MODEL_API_KEY": "test-key", "PG_MODEL_TIMEOUT_S": "150",
        "PG_MODEL_MAX_TOKENS": "10000", "PG_MODEL_STRUCTURED": "off",
        "PG_MODEL_EXTRA_BODY": '{"chat_template_kwargs":{"enable_thinking":true}}',
        "PG_MODEL_SESSION_HEADER": "x-opencode-session", "PG_MODEL_USER_AGENT": "test-agent",
    })
    assert config.timeout_s == 150.0 and config.max_tokens == 10000
    assert config.structured == "off"
    assert config.extra_body == {"chat_template_kwargs": {"enable_thinking": True}}
    assert config.session_header == "x-opencode-session"
    assert config.user_agent == "test-agent"
    assert "test-key" not in repr(config)


@pytest.mark.parametrize(("key", "value"), [
    ("PG_MODEL_TIMEOUT_S", "0"), ("PG_MODEL_TIMEOUT_S", "nan"),
    ("PG_MODEL_TIMEOUT_S", "secret-not-number"), ("PG_MODEL_MAX_TOKENS", "-1"),
    ("PG_MODEL_MAX_TOKENS", "1.2"), ("PG_MODEL_STRUCTURED", "maybe"),
])
def test_invalid_optional_configuration_is_safe(key, value):
    with pytest.raises(LLMConfigError) as error:
        LLMConfig.from_env({"PG_MODEL_BASE_URL": "http://local.test", "PG_MODEL_NAME": "test",
                            "PG_MODEL_API_KEY": "test-key", key: value})
    assert key in str(error.value)
    assert "secret-not-number" not in str(error.value)


@pytest.mark.parametrize("header", [None, "x-opencode-session"])
@pytest.mark.parametrize("retry_status", [400, 429])
def test_case_role_session_stable_across_retries_and_patch_attempts(sample_finding, header,
                                                                  retry_status, monkeypatch):
    monkeypatch.setattr("pulseguard.agents.llm.time.sleep", lambda seconds: None)
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append((dict(request.headers), body))
        if len(calls) == 1:
            return httpx.Response(retry_status, json={"error": {
                "message": "Grammar error: Unimplemented keys" if retry_status == 400 else "retry",
            }})
        result = completion()
        result["choices"][0]["message"]["content"] = json.dumps(
            verdict() if "Adjudicator" in body["messages"][0]["content"] else PATCH)
        return httpx.Response(200, json=result)

    adapter = client(handler, session_header=header)
    finding = Finding.model_validate({**sample_finding, "file": "routes.py"})
    assert adjudicate(finding, "evidence", llm=adapter).band == "confirmed"
    propose_patch(finding, "evidence", llm=adapter)
    propose_patch(finding, "evidence", llm=adapter, attempt=2)
    assert len(calls) == 4
    assert all(headers["user-agent"] == f"PulseGuard/{__version__}" for headers, _ in calls)
    if header:
        assert [headers[header] for headers, _ in calls] == [
            f"pg-{finding.case_id}-adjudicator", f"pg-{finding.case_id}-adjudicator",
            f"pg-{finding.case_id}-remediator", f"pg-{finding.case_id}-remediator"]
    else:
        assert all("x-opencode-session" not in headers for headers, _ in calls)


def test_session_header_flag_is_boolean_only():
    captured = []

    def handler(request):
        captured.append(dict(request.headers))
        return httpx.Response(200, json=completion())

    adapter = client(handler, session_header="x-opencode-session")
    meta = adapter.chat("s", "u", schema=output_schema("verdict"), session="pg-case-adjudicator"
                        ).metadata()
    assert meta["session_header_sent"] is True
    dumped = json.dumps(meta)
    assert "x-opencode-session" not in dumped
    assert "pg-case-adjudicator" not in dumped
    assert captured[0]["x-opencode-session"] == "pg-case-adjudicator"
    silent = client(handler).chat("s", "u", schema=output_schema("verdict"),
                                  session="pg-case-adjudicator").metadata()
    assert silent["session_header_sent"] is False


@pytest.mark.parametrize("mode", ["on", "off", "auto"])
def test_provider_error_metadata_never_keeps_message(sample_finding, mode):
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(400, json={"error": {
            "message": "Grammar error: echoed-test-credential"}})

    adapter = client(handler, structured=mode)
    # Even URL credentials, paths and query strings must not enter model metadata.
    adapter.config = replace(adapter.config, base_url="http://user:password@local.test/v1?key=x")
    metadata = {}
    result = adjudicate(Finding.model_validate(sample_finding), "evidence", llm=adapter,
                        metadata=metadata)
    assert result.band == "uncertain"
    assert metadata == {"error": "BadRequestError", "status_code": 400}
    assert "echoed-test-credential" not in json.dumps(result.to_payload())
    assert len(calls) == (2 if mode == "auto" else 1)


def test_non_schema_bad_request_does_not_fallback():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(400, json={"error": {"message": "missing x-opencode-session"}})

    from openai import BadRequestError

    with pytest.raises(BadRequestError):
        client(handler).chat("system", "user", schema=output_schema("verdict"))
    assert len(calls) == 1

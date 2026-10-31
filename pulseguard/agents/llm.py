"""OpenAI-compatible chat, adapted from revio ``src/revio/agent/llm.py``.

Configuration comes exclusively from PG_MODEL_*; REPLAY never constructs this client.
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from pulseguard import __version__
from pulseguard.paths import contracts_dir

UNSUPPORTED_SCHEMA_KEYWORDS = frozenset({
    "$schema", "$id", "$comment", "description", "uniqueItems", "examples", "default",
})
SYSTEM_FIELDS = frozenset({
    "band", "role", "model", "case_id", "verdict_id", "created_at", "state",
})


def model_facing_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Derive revio-style output guidance without changing the authoritative contract."""
    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items()
                    if key not in UNSUPPORTED_SCHEMA_KEYWORDS}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value

    result = clean(schema)
    if "properties" in result:
        result["properties"] = {key: value for key, value in result["properties"].items()
                                if key not in SYSTEM_FIELDS}
    if "required" in result:
        result["required"] = [key for key in result["required"] if key not in SYSTEM_FIELDS]
    return result


def error_metadata(exc: Exception) -> dict[str, Any]:
    """Keep provider exception types/statuses only; messages may echo credentials."""
    result: dict[str, Any] = {"error": type(exc).__name__}
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        result["status_code"] = status
    return result


class LLMConfigError(RuntimeError):
    """Model environment variables are missing or invalid."""


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    model: str
    api_key: str = field(repr=False)
    timeout_s: float = 120.0
    max_tokens: int = 8192
    structured: str = "auto"
    extra_body: dict[str, Any] = field(default_factory=dict, repr=False)
    session_header: str | None = None
    user_agent: str = f"PulseGuard/{__version__}"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LLMConfig:
        env = dict(os.environ) if env is None else env
        keys = ("PG_MODEL_BASE_URL", "PG_MODEL_NAME", "PG_MODEL_API_KEY")
        missing = [key for key in keys if not env.get(key, "").strip()]
        if missing:
            raise LLMConfigError(f"LIVE mode needs {', '.join(missing)}")
        try:
            timeout = float(env.get("PG_MODEL_TIMEOUT_S", "120"))
            if not math.isfinite(timeout) or timeout <= 0:
                raise ValueError
        except ValueError:
            raise LLMConfigError("PG_MODEL_TIMEOUT_S must be a positive finite number") from None
        try:
            max_tokens = int(env.get("PG_MODEL_MAX_TOKENS", "8192"))
            if max_tokens <= 0:
                raise ValueError
        except ValueError:
            raise LLMConfigError("PG_MODEL_MAX_TOKENS must be a positive integer") from None
        structured = env.get("PG_MODEL_STRUCTURED", "auto").strip().lower()
        if structured not in {"auto", "on", "off"}:
            raise LLMConfigError("PG_MODEL_STRUCTURED must be auto, on or off")
        try:
            extra_body = json.loads(env.get("PG_MODEL_EXTRA_BODY", "{}"))
            if not isinstance(extra_body, dict):
                raise ValueError
            json.dumps(extra_body, allow_nan=False)
        except ValueError:
            raise LLMConfigError("PG_MODEL_EXTRA_BODY must be a JSON object") from None
        return cls(
            *(env[key] for key in keys), timeout_s=timeout, max_tokens=max_tokens,
            structured=structured, extra_body=extra_body,
            session_header=env.get("PG_MODEL_SESSION_HEADER", "").strip() or None,
            user_agent=env.get("PG_MODEL_USER_AGENT", f"PulseGuard/{__version__}"),
        )


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    latency_ms: float
    usage: dict[str, Any] | None = None
    base_url_host: str | None = None
    structured_mode: str | None = None
    structured_output: bool | None = None
    session_header_sent: bool = False

    def metadata(self) -> dict[str, Any]:
        # session_header_sent is a boolean only: never the header name or its value.
        return {
            "model": self.model, "base_url_host": self.base_url_host,
            "structured_mode": self.structured_mode, "structured_output": self.structured_output,
            "session_header_sent": self.session_header_sent,
            "latency_ms": self.latency_ms, "usage": self.usage,
        }


class LLMClient(Protocol):
    """Small seam for a scripted FakeLLM, independent of the provider SDK."""

    @property
    def model(self) -> str: ...

    def chat(
        self, system: str, user: str, *, schema: dict[str, Any], session: str | None = None,
    ) -> LLMResponse: ...


def output_schema(name: str) -> dict[str, Any]:
    return json.loads((contracts_dir() / f"{name}.schema.json").read_text(encoding="utf-8"))


class OpenAIChatClient:
    """Bounded retries and per-request timeout, including schema capability fallback."""

    def __init__(self, config: LLMConfig, client: Any, *, max_retries: int = 2) -> None:
        self.config = config
        self.client = client
        self.max_retries = max_retries
        self._schema_supported = config.structured != "off"

    @property
    def model(self) -> str:
        return self.config.model

    def chat(
        self, system: str, user: str, *, schema: dict[str, Any], session: str | None = None,
    ) -> LLMResponse:
        from openai import APIConnectionError, APIStatusError, APITimeoutError

        started = time.perf_counter()
        schema = model_facing_schema(schema)
        headers = {"User-Agent": self.config.user_agent}
        session_header_sent = bool(self.config.session_header and session)
        if session_header_sent:
            headers[self.config.session_header] = session
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {
                "role": "user", "content": user + "\nReturn JSON matching:\n" + json.dumps(schema),
            }],
            "temperature": 0.0,
            "max_tokens": self.config.max_tokens,
            "timeout": self.config.timeout_s,
            "extra_body": self.config.extra_body,
            "extra_headers": headers,
        }
        retries = 0
        while True:
            if self._schema_supported:
                kwargs["response_format"] = {
                    "type": "json_schema", "json_schema": {
                        "name": schema.get("title", "response"), "schema": schema,
                    },
                }
            else:
                kwargs.pop("response_format", None)
            try:
                response = self.client.chat.completions.create(**kwargs)
                usage = getattr(response, "usage", None)
                return LLMResponse(
                    response.choices[0].message.content or "",
                    getattr(response, "model", None) or self.model,
                    round((time.perf_counter() - started) * 1000, 3),
                    usage.model_dump() if usage is not None else None,
                    base_url_host=urlsplit(self.config.base_url).hostname,
                    structured_mode=self.config.structured,
                    structured_output=self._schema_supported,
                    session_header_sent=session_header_sent,
                )
            except APIStatusError as exc:
                unsupported = exc.status_code in (400, 404, 422) and any(
                    word in str(exc).lower()
                    for word in ("response_format", "json_schema", "structured output", "grammar",
                                 "unimplemented", "unsupported keys")
                )
                if self.config.structured == "auto" and self._schema_supported and unsupported:
                    self._schema_supported = False
                    continue
                if exc.status_code not in (408, 409, 429) and exc.status_code < 500:
                    raise
                if retries >= self.max_retries:
                    raise
            except (APIConnectionError, APITimeoutError):
                if retries >= self.max_retries:
                    raise
            time.sleep(min(0.25 * 2**retries, 1.0))
            retries += 1


def make_llm(config: LLMConfig | None = None) -> LLMClient:
    from openai import OpenAI

    cfg = config or LLMConfig.from_env()
    return OpenAIChatClient(cfg, OpenAI(
        base_url=cfg.base_url, api_key=cfg.api_key, timeout=cfg.timeout_s, max_retries=0,
        default_headers={"User-Agent": cfg.user_agent},
    ))

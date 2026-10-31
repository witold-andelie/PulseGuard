"""OpenAI-compatible model client factory.

Adapted from revio ``src/revio/agent/llm.py`` (``make_llm`` provider factory). Endpoint and
model come from the environment; the final model choice is deferred (framework 12):

- ``PG_MODEL_BASE_URL`` - OpenAI-compatible base URL
- ``PG_MODEL_NAME``     - model name
- ``PG_MODEL_API_KEY``  - API key (never logged; the tracer redacts it)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


class LLMConfigError(RuntimeError):
    """Required model environment variables are missing."""


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    model: str
    api_key: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LLMConfig:
        env = dict(os.environ) if env is None else env
        missing = [k for k in ("PG_MODEL_BASE_URL", "PG_MODEL_NAME", "PG_MODEL_API_KEY")
                   if not env.get(k)]
        if missing:
            raise LLMConfigError(f"LIVE mode needs {', '.join(missing)}")
        return cls(env["PG_MODEL_BASE_URL"], env["PG_MODEL_NAME"], env["PG_MODEL_API_KEY"])

    def __repr__(self) -> str:  # keep the key out of logs and tracebacks
        return f"LLMConfig(base_url={self.base_url!r}, model={self.model!r}, api_key='***')"


@dataclass
class LLMClient:
    """Thin wrapper holding an ``openai.OpenAI`` client and the configured model name."""

    config: LLMConfig
    client: Any

    @property
    def model(self) -> str:
        return self.config.model

    def chat(self, system: str, user: str, *, response_format: dict[str, Any] | None = None,
             temperature: float = 0.0, max_tokens: int = 1200) -> str:
        """Single chat completion; returns the raw text content."""
        kwargs: dict[str, Any] = {
            "model": self.config.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format is not None:
            kwargs["response_format"] = response_format
        resp = self.client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""


def make_llm(config: LLMConfig | None = None) -> LLMClient:
    """Build the OpenAI-compatible client (raises :class:`LLMConfigError` if unconfigured)."""
    from openai import OpenAI  # imported lazily: REPLAY mode never needs it

    cfg = config or LLMConfig.from_env()
    return LLMClient(cfg, OpenAI(base_url=cfg.base_url, api_key=cfg.api_key))

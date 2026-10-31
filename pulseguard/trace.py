"""Tracing: append-only JSONL audit trail with secret redaction.

Adapted from tradepulse ``tradepulse/trace.py`` (``Tracer`` with ``span`` / ``event``,
``redact``). Added: ``case_id`` and ``activity`` on every event, monotonic ``seq``, and
contract validation against ``contracts/event.schema.json``.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pulseguard.contracts.validate import assert_payload

REDACTED = "[REDACTED]"

_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|apikey|secret|token|password|passwd|authorization|private[_-]?key|"
    r"access[_-]?key|client[_-]?secret|cookie|session)", re.I)

_SECRET_VALUE_RES: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),                       # OpenAI-style keys
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-~+/]{8,}=*"),        # bearer tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),                             # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                   # GitHub tokens
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),                 # Slack tokens
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd)\b(\s*[:=]\s*)"
               r"(['\"]?)[^\s'\",;]{4,}\3"),
]


def _redact_str(value: str) -> str:
    out = value
    for rx in _SECRET_VALUE_RES:
        if rx.groups >= 3:
            out = rx.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
        else:
            out = rx.sub(REDACTED, out)
    return out


def redact(obj: Any, _key: str | None = None) -> Any:
    """Recursively replace secret-looking values. Dict keys that name secrets are blanked."""
    if _key is not None and _SECRET_KEY_RE.search(_key) and isinstance(obj, (str, int, float)):
        return REDACTED
    if isinstance(obj, dict):
        return {k: redact(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return _redact_str(obj)
    return obj


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Tracer:
    """Append-only JSONL writer. One line per event; ``seq`` resumes from an existing file."""

    def __init__(self, path: str | Path, *, validate: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.validate = validate
        self._lock = threading.Lock()
        self._seq = self._count_existing()

    def _count_existing(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("rb") as fh:
            return sum(1 for line in fh if line.strip())

    def event(self, case_id: str, activity: str, resource: str = "pulseguard",
              **attributes: Any) -> dict[str, Any]:
        """Append one event. ``case_id`` and ``activity`` are mandatory."""
        if not case_id:
            raise ValueError("case_id is required on every trace event")
        if not activity:
            raise ValueError("activity is required on every trace event")
        with self._lock:
            record = {
                "seq": self._seq,
                "case_id": case_id,
                "activity": activity,
                "ts": utc_now(),
                "resource": resource,
                "attributes": redact(attributes),
            }
            if self.validate:
                assert_payload("event", record)
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            self._seq += 1
        return record

    @contextmanager
    def span(self, case_id: str, name: str, resource: str = "pulseguard",
             **attributes: Any) -> Iterator[dict[str, Any]]:
        """Emit SPAN_START / SPAN_END around a block (SPAN_END carries duration and error)."""
        start = time.perf_counter()
        self.event(case_id, "SPAN_START", resource, span=name, **attributes)
        extra: dict[str, Any] = {}
        try:
            yield extra
        except BaseException as exc:
            self.event(case_id, "SPAN_END", resource, span=name, ok=False,
                       error=f"{type(exc).__name__}: {exc}",
                       duration_ms=round((time.perf_counter() - start) * 1000, 3), **extra)
            raise
        self.event(case_id, "SPAN_END", resource, span=name, ok=True,
                   duration_ms=round((time.perf_counter() - start) * 1000, 3), **extra)

    def read(self, case_id: str | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    if case_id is None or rec.get("case_id") == case_id:
                        out.append(rec)
        return out

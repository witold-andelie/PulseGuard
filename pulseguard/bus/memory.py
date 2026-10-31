"""In-process publish/subscribe bus used on Render and in tests.

Same idea as quant-foundation-gat ``src/quant_alpha/streaming/demo_signals.py`` (bypassing the
broker when Docker is unavailable). The Redpanda bus [S3] will keep the same topic and event
contract.
"""

from __future__ import annotations

import itertools
import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

FINDINGS_TOPIC = "security.findings"

Handler = Callable[["Message"], None]


@dataclass(frozen=True)
class Message:
    topic: str
    offset: int
    key: str | None
    value: dict[str, Any]
    ts: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class InMemoryBus:
    """Thread-safe, synchronous pub/sub with a per-topic retained log.

    ``publish`` delivers to every current subscriber of the topic in subscription order and
    appends to the topic log, so late consumers can ``replay`` from an offset.
    """

    def __init__(self) -> None:
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._log: dict[str, list[Message]] = defaultdict(list)
        self._offsets: dict[str, itertools.count] = defaultdict(itertools.count)
        self._lock = threading.RLock()

    def subscribe(self, topic: str, handler: Handler) -> Callable[[], None]:
        """Register ``handler`` for ``topic``. Returns an unsubscribe callable."""
        with self._lock:
            self._subs[topic].append(handler)

        def _unsubscribe() -> None:
            with self._lock:
                if handler in self._subs[topic]:
                    self._subs[topic].remove(handler)

        return _unsubscribe

    def publish(self, topic: str, value: dict[str, Any], key: str | None = None) -> Message:
        with self._lock:
            msg = Message(topic=topic, offset=next(self._offsets[topic]), key=key, value=value)
            self._log[topic].append(msg)
            handlers = list(self._subs[topic])
        for handler in handlers:
            handler(msg)
        return msg

    def replay(self, topic: str, from_offset: int = 0) -> list[Message]:
        with self._lock:
            return [m for m in self._log[topic] if m.offset >= from_offset]

    def size(self, topic: str) -> int:
        with self._lock:
            return len(self._log[topic])

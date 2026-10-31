"""Optional Kafka-API transport, reimplemented from quant-foundation-gat's streaming ideas.

Install ``pulseguard[stream]``. No Kafka or Avro imports occur when importing this module.
Publish waits for broker acknowledgement; subscribers run on a polling thread by default.
Use ``background=False`` and ``poll()`` for an externally driven loop or deterministic tests.
The demo uses partition zero so Message offsets retain the memory bus's per-topic meaning.
Replay/size cover this instance's observed messages, not the broker's complete retained log.
"""

from __future__ import annotations

import io
import json
import math
import threading
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pulseguard.bus.memory import FINDINGS_TOPIC, Handler, Message
from pulseguard.contracts.validate import assert_payload
from pulseguard.paths import contracts_dir


class RedpandaError(RuntimeError):
    """A dependency, contract, broker, decoding or handler failure; never a silent fallback."""


class RedpandaBus:
    """Finding pub/sub with explicit shutdown and injectable confluent-kafka-compatible clients.

    Call ``close()`` (or use a context manager) to release the polling thread and clients.
    Background failures stop consumption and surface on the next public operation.
    Consumer offsets are committed only after all handlers succeed; delivery is at least once.
    """

    def __init__(
        self, bootstrap_servers: str = "localhost:19092", *,
        group_id: str = "pulseguard-findings", schema_path: str | Path | None = None,
        producer: Any = None, consumer: Any = None, background: bool = True,
        timeout: float = 10.0,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        self._servers, self._group = bootstrap_servers, group_id
        self._producer, self._consumer = producer, consumer
        self._background, self._timeout = background, timeout
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._log: dict[str, dict[int, Message]] = defaultdict(dict)
        self._lock = threading.RLock()
        self._client_lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._error: Exception | None = None
        self._closed = False
        try:
            from fastavro import parse_schema

            path = Path(schema_path) if schema_path else contracts_dir() / "finding.avsc"
            self._schema = parse_schema(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:
            raise RedpandaError(
                "Cannot load finding Avro schema; install pulseguard[stream]"
            ) from exc

    def _check(self) -> None:
        if self._closed:
            raise RedpandaError("Bus is closed")
        if self._error is not None:
            raise RedpandaError("Subscriber stopped after a consumption failure") from self._error

    def _client(self, kind: str) -> Any:
        attr = f"_{kind}"
        if getattr(self, attr) is None:
            try:
                from confluent_kafka import Consumer, Producer

                config: dict[str, Any] = {"bootstrap.servers": self._servers}
                if kind == "consumer":
                    config.update({"group.id": self._group, "auto.offset.reset": "earliest",
                                   "enable.auto.commit": False, "enable.auto.offset.store": False})
                    client = Consumer(config)
                else:
                    config.update({"enable.idempotence": True,
                                   "message.timeout.ms": int(self._timeout * 1000)})
                    client = Producer(config)
                setattr(self, attr, client)
            except Exception as exc:
                raise RedpandaError(
                    "Cannot create Kafka client; install pulseguard[stream]"
                ) from exc
        return getattr(self, attr)

    def subscribe(self, topic: str, handler: Handler) -> Callable[[], None]:
        self._check()
        try:
            with self._client_lock, self._lock:
                client = self._client("consumer")
                client.subscribe(sorted(set(self._subs) | {topic}))
                self._subs[topic].append(handler)
                if self._background and self._thread is None:
                    self._thread = threading.Thread(target=self._run, daemon=True,
                                                    name="pulseguard-redpanda")
                    self._thread.start()
        except Exception as exc:
            raise RedpandaError(f"Cannot subscribe to {topic!r}") from exc

        def unsubscribe() -> None:
            self._check()
            with self._lock:
                if handler in self._subs.get(topic, []):
                    self._subs[topic].remove(handler)

        return unsubscribe

    def publish(
        self, topic: str, value: dict[str, Any], key: str | None = None,
    ) -> Message:
        self._check()
        try:
            from fastavro import schemaless_writer

            assert_payload("finding", value)
            wire = dict(value)
            if "extra" in wire:
                wire["extra"] = json.dumps(wire["extra"], allow_nan=False)
            buffer = io.BytesIO()
            schemaless_writer(buffer, self._schema, wire)
            delivered: list[tuple[Any, Any]] = []
            with self._client_lock:
                client = self._client("producer")
                client.produce(
                    topic, value=buffer.getvalue(), key=key, partition=0,
                    headers=[("pulseguard.fields", json.dumps(list(value)).encode("utf-8"))],
                    on_delivery=lambda error, message: delivered.append((error, message)),
                )
                remaining = client.flush(self._timeout)
            if remaining or not delivered:
                raise TimeoutError("Broker acknowledgement timed out")
            error, raw = delivered[0]
            if error is not None:
                raise RedpandaError(f"Broker rejected message: {error}")
            message = Message(topic=topic, offset=raw.offset(), key=key,
                              value=json.loads(json.dumps(value)))
            with self._lock:
                self._log[topic][message.offset] = message
            return message
        except Exception as exc:
            raise RedpandaError(f"Cannot publish finding to {topic!r}") from exc

    def poll(self, timeout: float = 0.1) -> Message | None:
        """Consume one record and dispatch it; background subscribers call this automatically."""
        self._check()
        try:
            from fastavro import schemaless_reader

            with self._client_lock:
                client = self._client("consumer")
                raw = client.poll(timeout)
            if raw is None:
                return None
            if raw.error() is not None:
                raise RedpandaError(f"Broker consumption error: {raw.error()}")
            if raw.partition() != 0:
                raise RedpandaError("The demo bus supports partition zero only")
            buffer = io.BytesIO(raw.value())
            value = schemaless_reader(buffer, self._schema)
            if buffer.read():
                raise ValueError("Trailing bytes after Avro finding")
            headers = dict(raw.headers() or [])
            present = headers.get("pulseguard.fields")
            if present is not None:
                fields = json.loads(present)
                if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
                    raise ValueError("Invalid field-presence header")
                value = {name: value[name] for name in fields}
            else:
                value = {name: item for name, item in value.items() if item is not None}
            if "extra" in value:
                value["extra"] = json.loads(value["extra"])
            assert_payload("finding", value)
            key = raw.key()
            stamp = raw.timestamp()[1]
            ts = datetime.fromtimestamp(stamp / 1000, UTC).isoformat() if stamp >= 0 else None
            message = Message(topic=raw.topic(), offset=raw.offset(),
                              key=key.decode("utf-8") if key is not None else None, value=value,
                              **({"ts": ts} if ts else {}))
            with self._lock:
                handlers = list(self._subs.get(message.topic, []))
            for handler in handlers:
                handler(message)
            with self._client_lock:
                client.commit(message=raw, asynchronous=False)
            with self._lock:
                self._log[message.topic][message.offset] = message
            return message
        except Exception as exc:
            raise RedpandaError("Cannot consume finding") from exc

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll()
            except Exception as exc:
                self._error = exc
                self._stop.set()

    def replay(self, topic: str, from_offset: int = 0) -> list[Message]:
        self._check()
        with self._lock:
            return [msg for offset, msg in sorted(self._log[topic].items())
                    if offset >= from_offset]

    def size(self, topic: str) -> int:
        return len(self.replay(topic))

    def close(self) -> None:
        if self._closed:
            return
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(self._timeout)
            if self._thread.is_alive():
                raise RedpandaError("Subscriber did not stop before shutdown timeout")
        try:
            with self._client_lock:
                if self._consumer is not None:
                    self._consumer.close()
                if self._producer is not None and self._producer.flush(self._timeout):
                    raise TimeoutError("Producer shutdown timed out")
        except Exception as exc:
            raise RedpandaError("Cannot close Kafka clients") from exc
        finally:
            self._closed = True
        if self._error is not None:
            raise RedpandaError("Subscriber failed before shutdown") from self._error

    def __enter__(self) -> RedpandaBus:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


__all__ = ["FINDINGS_TOPIC", "RedpandaBus", "RedpandaError"]

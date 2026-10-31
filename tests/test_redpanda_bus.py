"""Avro contract and injected broker tests; no running Docker or Kafka is required."""

import builtins
import io
import json
import queue
import threading
from pathlib import Path

import pytest

fastavro = pytest.importorskip(
    "fastavro", reason="optional stream extra: fastavro is not installed",
)

from pulseguard.bus.memory import FINDINGS_TOPIC  # noqa: E402
from pulseguard.bus.redpanda import RedpandaBus, RedpandaError  # noqa: E402
from pulseguard.contracts.validate import assert_payload  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class FakeRecord:
    def __init__(self, topic, value, key, headers, offset=0, error=None):
        self._topic, self._value, self._key = topic, value, key
        self._headers, self._offset, self._error = headers, offset, error

    def topic(self):
        return self._topic

    def value(self):
        return self._value

    def key(self):
        return self._key.encode() if self._key is not None else None

    def headers(self):
        return self._headers

    def offset(self):
        return self._offset

    def partition(self):
        return 0

    def error(self):
        return self._error

    def timestamp(self):
        return (1, 1793408400000)


class FakeConsumer:
    def __init__(self):
        self.records = queue.Queue()
        self.topics = []
        self.committed = []
        self.closed = False

    def subscribe(self, topics):
        self.topics = topics

    def poll(self, timeout):
        try:
            return self.records.get(timeout=timeout)
        except queue.Empty:
            return None

    def commit(self, *, message, asynchronous):
        assert asynchronous is False
        self.committed.append(message)

    def close(self):
        self.closed = True


class FakeProducer:
    def __init__(self, consumer):
        self.consumer, self.produced = consumer, []
        self.error = None
        self.remaining = 0

    def produce(self, topic, *, value, key, partition, headers, on_delivery):
        assert partition == 0
        record = FakeRecord(topic, value, key, headers, len(self.produced))
        self.produced.append(record)
        if self.error is None:
            self.consumer.records.put(record)
        on_delivery(self.error, record)

    def flush(self, timeout):
        return self.remaining


@pytest.fixture
def finding():
    return {
        "case_id": "PG-stream", "fingerprint": "a" * 64, "rule_id": "flask-sqli-taint",
        "file": "routes.py", "line": 37, "state": "raw", "evidence_ids": [],
    }


@pytest.fixture
def clients():
    consumer = FakeConsumer()
    return FakeProducer(consumer), consumer


def test_avro_schema_matches_json_fields_and_round_trips(finding):
    schema = json.loads((ROOT / "contracts/finding.avsc").read_text(encoding="utf-8"))
    contract = json.loads((ROOT / "contracts/finding.schema.json").read_text(encoding="utf-8"))
    assert {field["name"] for field in schema["fields"]} == set(contract["properties"])
    assert {field["name"] for field in schema["fields"] if "default" not in field} == set(
        contract["required"])
    finding.update(scanner="trivy", severity="high", message="dependency – recorded",
                   cve_id=None, trace=[{"kind": "sink", "line": 37, "content": "execute(q)"}],
                   extra={"nested": {"fixed": ["2.32.0", None, True, 3.5]}})
    assert_payload("finding", finding)
    wire = {**finding, "extra": json.dumps(finding["extra"])}
    parsed = fastavro.parse_schema(schema)
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, parsed, wire)
    buf.seek(0)
    decoded = fastavro.schemaless_reader(buf, parsed)
    decoded["extra"] = json.loads(decoded["extra"])
    assert decoded == finding


@pytest.mark.parametrize("full", [False, True])
def test_publish_subscribe_unsubscribe_and_retained_offsets(finding, clients, full):
    producer, consumer = clients
    if full:
        finding.update(scanner="semgrep", severity="high", message="SQL injection",
                       cve_id=None, trace=[], extra={"nested": [None, True, {"value": "ż"}]})
    with RedpandaBus(producer=producer, consumer=consumer, background=False) as bus:
        first, second = [], []
        unsubscribe = bus.subscribe(FINDINGS_TOPIC, first.append)
        bus.subscribe(FINDINGS_TOPIC, second.append)
        sent = bus.publish(FINDINGS_TOPIC, finding, key=finding["case_id"])
        assert sent.offset == 0 and sent.value == finding
        received = bus.poll(0)
        assert received.key == finding["case_id"] and received.value == finding
        assert first == second == [received]
        unsubscribe()
        unsubscribe()
        bus.publish(FINDINGS_TOPIC, finding)
        assert bus.poll(0).key is None
        assert len(first) == 1 and len(second) == 2
        assert bus.size(FINDINGS_TOPIC) == 2
        assert [m.offset for m in bus.replay(FINDINGS_TOPIC, 1)] == [1]
        assert len(consumer.committed) == 2
    assert consumer.closed
    with pytest.raises(RedpandaError, match="closed"):
        bus.publish(FINDINGS_TOPIC, finding)


def test_background_subscription_dispatches_and_closes(finding, clients):
    producer, consumer = clients
    received = threading.Event()
    with RedpandaBus(producer=producer, consumer=consumer) as bus:
        bus.subscribe(FINDINGS_TOPIC, lambda message: received.set())
        bus.publish(FINDINGS_TOPIC, finding)
        assert received.wait(3), "polling thread did not deliver the finding"
    assert consumer.closed and len(consumer.committed) == 1


def test_background_failure_is_observable_and_shutdown_releases_client(finding, clients):
    producer, consumer = clients
    bus = RedpandaBus(producer=producer, consumer=consumer)

    def fail(message):
        raise ValueError("subscriber failed")

    bus.subscribe(FINDINGS_TOPIC, fail)
    bus.publish(FINDINGS_TOPIC, finding)
    bus._thread.join(3)
    assert not bus._thread.is_alive()
    with pytest.raises(RedpandaError, match="consumption failure"):
        bus.size(FINDINGS_TOPIC)
    with pytest.raises(RedpandaError, match="before shutdown"):
        bus.close()
    assert consumer.closed and consumer.committed == []
    bus.close()


def test_injected_clients_do_not_import_kafka(finding, clients, monkeypatch):
    original = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "confluent_kafka":
            raise AssertionError("Injected clients must not import confluent_kafka")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    producer, consumer = clients
    with RedpandaBus(producer=producer, consumer=consumer, background=False) as bus:
        bus.subscribe(FINDINGS_TOPIC, lambda message: None)
        bus.publish(FINDINGS_TOPIC, finding)
        assert bus.poll(0).value == finding


def test_missing_kafka_dependency_is_wrapped(finding, monkeypatch):
    original = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "confluent_kafka":
            raise ImportError("optional client absent")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with RedpandaBus(background=False) as bus:
        with pytest.raises(RedpandaError, match="publish") as caught:
            bus.publish(FINDINGS_TOPIC, finding)
        assert isinstance(caught.value.__cause__, RedpandaError)


@pytest.mark.parametrize("failure", ["invalid-contract", "produce", "ack", "timeout"])
def test_publish_errors_are_wrapped(finding, clients, monkeypatch, failure):
    producer, consumer = clients
    with RedpandaBus(producer=producer, consumer=consumer, background=False) as bus:
        if failure == "invalid-contract":
            finding["state"] = "invented"
        elif failure == "ack":
            producer.error = "broker rejected record"
        elif failure == "timeout":
            producer.remaining = 1
        else:
            def fail(*args, **kwargs):
                raise BufferError("queue full")
            monkeypatch.setattr(producer, "produce", fail)
        with pytest.raises(RedpandaError, match="publish"):
            bus.publish(FINDINGS_TOPIC, finding)
        assert bus.size(FINDINGS_TOPIC) == 0
        producer.remaining = 0


@pytest.mark.parametrize("failure", ["avro", "broker", "handler", "commit"])
def test_consume_failures_never_commit(finding, clients, monkeypatch, failure):
    producer, consumer = clients
    with RedpandaBus(producer=producer, consumer=consumer, background=False) as bus:
        def handler(message):
            if failure == "handler":
                raise ValueError("handler failed")

        bus.subscribe(FINDINGS_TOPIC, handler)
        bus.publish(FINDINGS_TOPIC, finding)
        record = producer.produced[0]
        if failure == "avro":
            record._value = b"broken avro"
        elif failure == "broker":
            record._error = "broker unavailable"
        elif failure == "commit":
            def fail(**kwargs):
                raise OSError("commit failed")
            monkeypatch.setattr(consumer, "commit", fail)
        with pytest.raises(RedpandaError, match="consume"):
            bus.poll(0)
        assert consumer.committed == []

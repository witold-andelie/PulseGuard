"""Event bus abstraction. S1 ships only the in-memory bus; Redpanda arrives in S3."""

from pulseguard.bus.memory import FINDINGS_TOPIC, InMemoryBus, Message

__all__ = ["FINDINGS_TOPIC", "InMemoryBus", "Message"]

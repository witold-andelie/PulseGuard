"""Event bus abstraction. S1 ships only the in-memory bus; Redpanda arrives in S3."""

from pulseguard.bus.memory import FINDINGS_TOPIC, InMemoryBus, Message
from pulseguard.bus.watchdog import BusWatchdog

__all__ = ["FINDINGS_TOPIC", "InMemoryBus", "Message", "BusWatchdog"]

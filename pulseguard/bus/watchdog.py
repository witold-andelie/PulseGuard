"""Bus freshness watching, adapted from PerpPulse ``crates/perppulse/src/live.rs``.

``max_lag`` is a time budget. "processed coverage has stalled" is a separate degrade
when the consumer offset has not advanced while the log is still ahead. Health never
raises: degrade instead of fail. Stale or stalled feeds the policy (advise-only).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from pulseguard.contracts.models import BusHealth


@dataclass
class BusWatchdog:
    max_lag_s: float = 30.0
    stall_after_s: float = 30.0
    _published_offset: int = field(default=-1, repr=False)
    _published_at: float | None = field(default=None, repr=False)
    _processed_offset: int = field(default=-1, repr=False)
    _processed_advanced_at: float | None = field(default=None, repr=False)

    def observe_publish(self, offset: int, ts: float | None = None) -> None:
        now = time.time() if ts is None else ts
        if offset >= self._published_offset:
            self._published_offset = offset
            self._published_at = now

    def observe_processed(self, offset: int, ts: float | None = None) -> None:
        now = time.time() if ts is None else ts
        if offset > self._processed_offset:
            self._processed_offset = offset
            self._processed_advanced_at = now

    def health(self, now: float | None = None) -> str:
        """Return ``fresh``, ``stale`` or ``stalled``. Never raises."""
        clock = time.time() if now is None else now
        if self._published_offset < 0:
            return BusHealth.FRESH
        behind = self._processed_offset < self._published_offset
        stall_ref = self._processed_advanced_at
        if behind:
            if stall_ref is None:
                stall_ref = self._published_at
            if stall_ref is not None and (clock - stall_ref) > self.stall_after_s:
                return BusHealth.STALLED
            published_at = self._published_at
            if published_at is not None and (clock - published_at) > self.max_lag_s:
                return BusHealth.STALE
        return BusHealth.FRESH

"""Score bands (framework 4.4) - replaces SymbAI-Taint's single soft threshold.

Adapted from SymbAI-Taint ``src/pipeline.py`` (confidence gating at 0.7), split into three bands:

| score            | band / finding state |
| ---------------- | -------------------- |
| score >= 0.7     | confirmed            |
| 0.3 <= s < 0.7   | uncertain            |
| score < 0.3      | false_positive       |

Thresholds are tuned in S3 on the labelled set; they are parameters, not constants baked into
callers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal

from pulseguard.contracts.models import FindingState

BandName = Literal["confirmed", "uncertain", "false_positive"]

CONFIRMED_AT = 0.7
UNCERTAIN_AT = 0.3


@dataclass(frozen=True)
class Bands:
    confirmed_at: float = CONFIRMED_AT
    uncertain_at: float = UNCERTAIN_AT

    def __post_init__(self) -> None:
        if not 0.0 <= self.uncertain_at <= self.confirmed_at <= 1.0:
            raise ValueError("require 0 <= uncertain_at <= confirmed_at <= 1")

    def band_for(self, score: float) -> BandName:
        if score is None or isinstance(score, bool) or math.isnan(float(score)):
            raise ValueError(f"score must be a number in [0, 1], got {score!r}")
        s = float(score)
        if not 0.0 <= s <= 1.0:
            raise ValueError(f"score must be in [0, 1], got {s}")
        if s >= self.confirmed_at:
            return "confirmed"
        if s >= self.uncertain_at:
            return "uncertain"
        return "false_positive"


DEFAULT_BANDS = Bands()

# Activity names emitted when a verdict lands in each band (framework 10.1).
BAND_ACTIVITY: dict[BandName, str] = {
    "confirmed": "VERDICT_CONFIRMED",
    "uncertain": "VERDICT_UNCERTAIN",
    "false_positive": "FALSE_POSITIVE_DROPPED",
}


def band_for(score: float, bands: Bands = DEFAULT_BANDS) -> BandName:
    """Map a score in [0, 1] to its band (raises ``ValueError`` outside [0, 1] or NaN)."""
    return bands.band_for(score)


def finding_state_for(score: float, bands: Bands = DEFAULT_BANDS) -> FindingState:
    return FindingState(band_for(score, bands))

"""Site metrics adapted from SymbAI-Taint ``src/evaluation/metrics.py``.

The explicit safe sites define a finite negative universe, so TN is measured.
Zero denominators produce 0.0, matching upstream's metric convention.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass

from eval.labels import Site


@dataclass(frozen=True)
class Metrics:
    """Confusion counts precede ratios in both serialised and printed reports."""

    tp: int
    fp: int
    fn: int
    tn: int

    def __post_init__(self) -> None:
        if any(isinstance(n, bool) or not isinstance(n, int) or n < 0
               for n in (self.tp, self.fp, self.fn, self.tn)):
            raise ValueError("confusion counts must be nonnegative integers")

    def to_dict(self) -> dict[str, int | float]:
        def ratio(numerator: int, denominator: int) -> float:
            return numerator / denominator if denominator else 0.0

        return {**asdict(self), "precision": ratio(self.tp, self.tp + self.fp),
                "recall": ratio(self.tp, self.tp + self.fn),
                "f1": ratio(2 * self.tp, 2 * self.tp + self.fp + self.fn),
                "fp_rate": ratio(self.fp, self.fp + self.tn),
                "fn_rate": ratio(self.fn, self.fn + self.tp)}


def compute_metrics(sites: Iterable[Site], flagged: Iterable[str]) -> Metrics:
    """Deduplicate flags; reject ids outside the labelled evaluation universe."""
    sites = list(sites)
    ids = {s.site_id for s in sites}
    if len(ids) != len(sites):
        raise ValueError("duplicate site ids")
    predicted = set(flagged)
    if predicted - ids:
        raise ValueError("predictions contain unknown site ids")
    positive = {s.site_id for s in sites if s.label == "vuln"}
    negative = ids - positive
    return Metrics(len(predicted & positive), len(predicted & negative),
                   len(positive - predicted), len(negative - predicted))

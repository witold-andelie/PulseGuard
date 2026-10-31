"""Counterfactual consistency after a sandbox pass (framework 4.5).

Adapted from SymbAI-Taint ``src/taint_analysis/counterfactual.py`` (VISION-style
counterfactual validation). The pair is original vs patched code: a fresh adjudication
of the patched copy must score < 0.3 while the original scored ≥ 0.7; otherwise escalate
before approval. Code findings only; dependency bumps skip this check.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class CounterfactualResult:
    ok: bool
    original_score: float
    patched_score: float
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def consistent(original_score: float, patched_score: float) -> CounterfactualResult:
    """Pass when the original was confirmed and the patched copy is a false positive."""
    ok = original_score >= 0.7 and patched_score < 0.3
    if ok:
        detail = (
            f"patched score {patched_score:.3f} < 0.3 while original "
            f"{original_score:.3f} >= 0.7")
    else:
        detail = (
            f"counterfactual failed: original {original_score:.3f}, "
            f"patched {patched_score:.3f} (need original >= 0.7 and patched < 0.3)")
    return CounterfactualResult(
        ok=ok, original_score=float(original_score), patched_score=float(patched_score),
        detail=detail,
    )

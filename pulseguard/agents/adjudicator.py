"""Adjudicating (neural): exploitability verdict from the Hard Evidence Block.

Will be adapted from SymbAI-Taint ``src/orchestrator/llm_client.py::analyze_taint_path_cot``
(framework 4.3 / 7.4). In S1 the deterministic half (parsing + banding + contract validation) is
real; the model call itself is a stub until the endpoint is chosen.
"""

from __future__ import annotations

import math
from typing import Any

from pulseguard.agents.bands import DEFAULT_BANDS, Bands
from pulseguard.agents.json_parse import parse_json_response
from pulseguard.agents.llm import LLMClient
from pulseguard.agents.prompts import ADJUDICATOR_SYSTEM, build_adjudicator_user
from pulseguard.contracts.models import Finding, Verdict


class VerdictParseError(ValueError):
    """The model reply had no usable decision fields."""


def parse_verdict(
    raw_text: str, *, model: str, case_id: str | None = None, bands: Bands = DEFAULT_BANDS
) -> Verdict:
    """Turn a raw model reply into a contract-valid :class:`Verdict` (working in S1).

    Uses the tolerant parser; requires at least ``score``. ``is_exploitable`` defaults to
    ``score >= confirmed_at`` if the model omitted it. Scores are clamped to [0, 1].
    """
    data: dict[str, Any] | None = parse_json_response(raw_text)
    if not data or "score" not in data:
        raise VerdictParseError("no score in model reply")
    try:
        raw_score = data["score"]
        if isinstance(raw_score, bool) or not math.isfinite(float(raw_score)):
            raise ValueError("non-finite or boolean score")
        score = min(1.0, max(0.0, float(raw_score)))
    except (TypeError, ValueError) as exc:
        raise VerdictParseError(f"score is not a number: {data['score']!r}") from exc
    cited = data.get("cited_evidence") or []
    if not isinstance(cited, list) or any(
        not isinstance(e, str) or not e.startswith("E") or not e[1:].isdigit() for e in cited
    ):
        raise VerdictParseError("cited_evidence must be a list of evidence ids")
    exploitable = data.get("is_exploitable", score >= bands.confirmed_at)
    if not isinstance(exploitable, bool):
        raise VerdictParseError("is_exploitable must be a boolean")
    return Verdict(
        is_exploitable=exploitable,
        score=score,
        band=bands.band_for(score),
        cited_evidence=list(dict.fromkeys(cited)),
        step1_dataflow=str(data.get("step1_dataflow", "")),
        step2_constraint=str(data.get("step2_constraint", "")),
        step3_context=str(data.get("step3_context", "")),
        step4_verdict=str(data.get("step4_verdict", "")),
        role="adjudicator",
        model=model,
        case_id=case_id,
    )


def adjudicate(finding: Finding, evidence_block: str, *, llm: LLMClient | None = None) -> Verdict:
    """LIVE adjudication: one structured model call, then :func:`parse_verdict`.

    Source to adapt: SymbAI-Taint ``src/orchestrator/llm_client.py::analyze_taint_path_cot``.
    Prompt: :data:`pulseguard.agents.prompts.ADJUDICATOR_SYSTEM` +
    :func:`build_adjudicator_user`. Not implemented in the S1 skeleton.
    """
    _ = (ADJUDICATOR_SYSTEM, build_adjudicator_user(evidence_block, finding.rule_id,
                                                    finding.file, finding.line), llm)
    raise NotImplementedError(
        "LIVE adjudication is a Sprint 1 stub; adapt SymbAI-Taint "
        "src/orchestrator/llm_client.py::analyze_taint_path_cot"
    )

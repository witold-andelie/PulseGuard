"""Challenging (Skeptic) for the uncertain band (framework 4.4).

Adapted from the tradepulse Analyst → Skeptic → Verifier split (README "How it works",
framework 7.2). The Skeptic receives the same Hard Evidence Block plus the Adjudicator's
four steps and must argue the opposite. Output is a Verdict with ``role=skeptic``.

Resolved only if adjudicator and skeptic land in the same band outside 0.3–0.7
AND Verifying passes; otherwise abstain → escalate.
"""

from __future__ import annotations

from typing import Any

from pulseguard.agents.adjudicator import VerdictParseError, parse_verdict
from pulseguard.agents.bands import DEFAULT_BANDS, Bands
from pulseguard.agents.llm import LLMClient, error_metadata, make_llm, output_schema
from pulseguard.agents.prompts import SKEPTIC_SYSTEM, build_skeptic_user
from pulseguard.contracts.models import Finding, Verdict
from pulseguard.contracts.validate import assert_payload

OUTER_BANDS = frozenset({"confirmed", "false_positive"})


def abstained_verdict(model: str, case_id: str | None, reason: str, *, role: str = "skeptic"
                      ) -> Verdict:
    return Verdict(
        is_exploitable=False, score=0.5, band="abstained", role=role,  # type: ignore[arg-type]
        model=model, case_id=case_id, step4_verdict=reason,
    )


def resolution(
    adjudicator_band: str, skeptic_band: str | None, verify_ok: bool,
) -> str:
    """Return confirmed / false_positive / abstained per the S2 decision rule."""
    if skeptic_band is None:
        if adjudicator_band == "confirmed" and verify_ok:
            return "confirmed"
        if adjudicator_band == "false_positive":
            return "false_positive"
        return "abstained"
    if (adjudicator_band == skeptic_band and adjudicator_band in OUTER_BANDS and verify_ok):
        return adjudicator_band
    return "abstained"


def parse_skeptic(
    raw_text: str, *, model: str, case_id: str | None = None, bands: Bands = DEFAULT_BANDS,
) -> Verdict:
    verdict = parse_verdict(raw_text, model=model, case_id=case_id, bands=bands)
    payload = verdict.to_payload()
    payload["role"] = "skeptic"
    assert_payload("verdict", payload)
    return Verdict.model_validate(payload)


def challenge(
    finding: Finding, evidence_block: str, adjudicator: dict[str, Any], *,
    llm: LLMClient | None = None, metadata: dict[str, Any] | None = None,
) -> Verdict:
    """One structured call that argues the opposite of ``adjudicator``."""
    client = llm or make_llm()
    try:
        response = client.chat(
            SKEPTIC_SYSTEM,
            build_skeptic_user(evidence_block, adjudicator),
            schema=output_schema("verdict"),
            session=f"pg-{finding.case_id}-skeptic",
        )
        if metadata is not None:
            metadata.update(response.metadata())
        return parse_skeptic(response.text, model=response.model, case_id=finding.case_id)
    except Exception as exc:
        if metadata is not None:
            if isinstance(exc, VerdictParseError):
                metadata.update({"error": type(exc).__name__})
            else:
                metadata.update(error_metadata(exc))
        return abstained_verdict(
            client.model, finding.case_id, "Unusable skeptic result; abstain.")

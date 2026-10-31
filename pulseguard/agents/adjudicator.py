"""Evidence-first adjudication from SymbAI-Taint
``src/orchestrator/llm_client.py::analyze_taint_path_cot`` (framework 4.3).
"""

from __future__ import annotations

import json
import re
from typing import Any

from pulseguard.agents.bands import DEFAULT_BANDS, Bands
from pulseguard.agents.json_parse import parse_json_response, strip_wrappers
from pulseguard.agents.llm import LLMClient, error_metadata, make_llm, output_schema
from pulseguard.agents.prompts import ADJUDICATOR_SYSTEM, build_adjudicator_user
from pulseguard.contracts.models import Finding, Verdict
from pulseguard.contracts.validate import assert_payload


class VerdictParseError(ValueError):
    """The model reply was incomplete, malformed or violated the verdict contract."""


def parse_verdict(
    raw_text: str, *, model: str, case_id: str | None = None, bands: Bands = DEFAULT_BANDS
) -> Verdict:
    """Use the tolerant parser, but never promote repaired/truncated JSON to confirmed."""
    data = parse_json_response(raw_text)
    body = strip_wrappers(raw_text)
    try:
        complete, _ = json.JSONDecoder().raw_decode(body[body.index("{"):])
        if not isinstance(complete, dict) or data != complete:
            raise ValueError("not a complete JSON object")
        if not data:
            raise ValueError("no verdict")
        data = dict(data)
        citations = data.get("cited_evidence")
        if isinstance(citations, list):
            data["cited_evidence"] = [
                re.sub(r"^\[(E[0-9]+)\](?:\s+.*)?$", r"\1", item)
                if isinstance(item, str) else item for item in citations
            ]
        score = data["score"]
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ValueError("score must be a JSON number")
        data.update(band=bands.band_for(score), model=model, role="adjudicator")
        if case_id is not None:
            data["case_id"] = case_id
        assert_payload("verdict", data)
        return Verdict.model_validate(data)
    except (ValueError, KeyError, TypeError) as exc:
        raise VerdictParseError("malformed or incomplete verdict") from exc


def uncertain_verdict(model: str, case_id: str, reason: str) -> Verdict:
    return Verdict(
        is_exploitable=False, score=0.5, band="uncertain", model=model, case_id=case_id,
        step4_verdict=reason,
    )


def adjudicate(
    finding: Finding, evidence_block: str, *, llm: LLMClient | None = None,
    metadata: dict[str, Any] | None = None,
) -> Verdict:
    """One structured call; unusable replies and provider failures require human review."""
    client = llm or make_llm()
    try:
        response = client.chat(
            ADJUDICATOR_SYSTEM,
            build_adjudicator_user(evidence_block, finding.rule_id, finding.file, finding.line),
            schema=output_schema("verdict"),
            session=f"pg-{finding.case_id}-adjudicator",
        )
        if metadata is not None:
            metadata.update(response.metadata())
        return parse_verdict(response.text, model=response.model, case_id=finding.case_id)
    except Exception as exc:
        # Provider exceptions can contain credentials: retain the type only.
        if metadata is not None:
            metadata.update(error_metadata(exc))
        return uncertain_verdict(
            client.model, finding.case_id, "Unusable model result; human review.")

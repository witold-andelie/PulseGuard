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
                re.sub(r"^\[([A-Z][0-9]+)\](?:\s+.*)?$", r"\1", item)
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
    """System substitute when the model reply is unusable. Makes no evidence claim."""
    verdict = Verdict(
        is_exploitable=False, score=0.5, band="uncertain", model=model, case_id=case_id,
        step4_verdict=reason,
    )
    verdict._system_fallback = True
    return verdict


def is_system_fallback(verdict: Verdict) -> bool:
    """True only for :func:`uncertain_verdict` substitutes, never inferred from fields."""
    return bool(getattr(verdict, "_system_fallback", False))


def dependency_verdict(finding: Finding, report: dict[str, Any]) -> Verdict:
    """Decide recorded dependency facts without consulting an exploitability model."""
    confirmed = report["ok"] and bool(report.get("fixed_version"))
    band = "confirmed" if confirmed else ("uncertain" if report["ok"] else "abstained")
    provenance = report.get("provenance") or {}
    verdict = Verdict(
        is_exploitable=confirmed, score=1.0 if confirmed else 0.5, band=band,
        role="verifier", model="none", case_id=finding.case_id,
        cited_evidence=["E1", "E2", "E3"] if report["ok"] else [],
        step1_dataflow=f"Dependency {finding.extra.get('package')}=="
                       f"{finding.extra.get('installed_version')}; {report['detail']}.",
        step2_constraint="Highest recorded fixed version: "
                         f"{report.get('fixed_version') or 'none'}.",
        step3_context=f"Report {finding.extra.get('report')}; "
                      f"label {provenance.get('label', 'unverified')}, "
                      f"Trivy {provenance.get('tool_version', 'unknown')}, "
                      f"scanned at {provenance.get('scanned_at', 'unknown')}.",
        step4_verdict=("Recorded CVEs and fixed version confirmed; deterministic manifest bump."
                       if confirmed else "Human review: " + (
                           "no fixed version available" if report["ok"] else report["detail"])),
    )
    assert_payload("verdict", verdict.to_payload())
    return verdict


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

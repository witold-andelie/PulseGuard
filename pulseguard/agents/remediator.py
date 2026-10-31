"""Remediating (neural): propose a PatchSet for a confirmed finding.

The PatchSet JSON schema doubles as the model's structured-output schema (framework 7.1,
revio ``src/revio/agent/patch.py``). Retry semantics (max 3 attempts, sandbox feedback) follow
revio ``src/revio/cli/fix.py::run_fix_flow``. The model call is a stub in S1; parsing is real.
"""

from __future__ import annotations

from pulseguard.agents.json_parse import parse_json_response
from pulseguard.agents.llm import LLMClient
from pulseguard.agents.prompts import REMEDIATOR_SYSTEM, build_remediator_user
from pulseguard.contracts.models import Finding
from pulseguard.contracts.validate import assert_payload
from pulseguard.patching.patch import PatchSet

MAX_ATTEMPTS = 3


class PatchParseError(ValueError):
    """The model reply is not a valid PatchSet."""


def parse_patchset(raw_text: str, *, attempt: int, case_id: str | None = None) -> PatchSet:
    """Parse and contract-validate a model reply into a :class:`PatchSet` (working in S1)."""
    data = parse_json_response(raw_text)
    if not data or "ops" not in data:
        raise PatchParseError("no ops in model reply")
    data["attempt"] = attempt
    data.setdefault("rationale", "(none given)")
    data.pop("case_id", None)
    data.pop("state", None)
    try:
        assert_payload("patchset", data)
    except ValueError as exc:
        raise PatchParseError(str(exc)) from exc
    ps = PatchSet.from_payload(data)
    ps.case_id = case_id
    return ps


def propose_patch(
    finding: Finding,
    evidence_block: str,
    *,
    attempt: int = 1,
    sandbox_feedback: str | None = None,
    llm: LLMClient | None = None,
) -> PatchSet:
    """LIVE remediation call. Not implemented in the S1 skeleton.

    Source to adapt: revio ``src/revio/agent/patch.py`` (PatchSet structured output) and
    ``src/revio/cli/fix.py::run_fix_flow`` (retry loop).
    """
    if attempt > MAX_ATTEMPTS:
        raise ValueError(f"attempt {attempt} exceeds max {MAX_ATTEMPTS}")
    _ = (REMEDIATOR_SYSTEM,
         build_remediator_user(evidence_block, finding.file, attempt, sandbox_feedback), llm)
    raise NotImplementedError(
        "LIVE remediation is a Sprint 1 stub; adapt revio src/revio/agent/patch.py"
    )

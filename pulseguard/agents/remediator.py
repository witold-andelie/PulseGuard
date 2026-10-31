"""Remediating (neural): propose a PatchSet for a confirmed finding.

The PatchSet contract supplies the model's output guidance (framework 7.1,
revio ``src/revio/agent/patch.py``). Retry semantics (max 3 attempts, sandbox feedback) follow
revio ``src/revio/cli/fix.py::run_fix_flow``.
"""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from pulseguard.agents.json_parse import parse_json_response
from pulseguard.agents.llm import LLMClient, error_metadata, make_llm, output_schema
from pulseguard.agents.prompts import REMEDIATOR_SYSTEM, build_remediator_user
from pulseguard.contracts.models import Finding
from pulseguard.contracts.validate import assert_payload
from pulseguard.patching.patch import PatchSet

MAX_ATTEMPTS = 3


def validate_patch_scope(patchset: PatchSet, finding: Finding) -> None:
    """S1 traces are intraprocedural: every step belongs to finding.file."""
    for op in patchset.ops:
        path = PurePosixPath(op.path)
        if (path.is_absolute() or PureWindowsPath(op.path).drive or "\\" in op.path
                or ".." in path.parts or path.as_posix() != finding.file):
            raise PatchParseError(f"patch outside finding trace: {op.path}")


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
    metadata: dict[str, Any] | None = None,
) -> PatchSet:
    """Request a contract-valid patch confined to the finding's trace.

    Source to adapt: revio ``src/revio/agent/patch.py`` (PatchSet structured output) and
    ``src/revio/cli/fix.py::run_fix_flow`` (retry loop).
    """
    if not 1 <= attempt <= MAX_ATTEMPTS:
        raise ValueError(f"attempt {attempt} exceeds max {MAX_ATTEMPTS}")
    try:
        response = (llm or make_llm()).chat(
            REMEDIATOR_SYSTEM,
            build_remediator_user(evidence_block, finding.file, attempt, sandbox_feedback),
            schema=output_schema("patchset"),
            session=f"pg-{finding.case_id}-remediator",
        )
    except Exception as exc:
        if metadata is not None:
            metadata.update(error_metadata(exc))
        raise
    if metadata is not None:
        metadata.update(response.metadata())
    patchset = parse_patchset(response.text, attempt=attempt, case_id=finding.case_id)
    validate_patch_scope(patchset, finding)
    return patchset

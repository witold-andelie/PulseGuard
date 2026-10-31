"""``PatchOp`` / ``PatchSet`` / ``PatchApplier`` and remediation bundling.

Adapted from revio ``src/revio/agent/patch.py``. A PatchSet is a list of exact search/replace
operations; ``old`` must occur exactly once in its file. Application is all-or-nothing: every op
is checked before any file is written. Paths are confined to the applier root.
"""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pulseguard.contracts.models import PatchOpModel, PatchSetModel


class PatchError(ValueError):
    """A patch op cannot be applied (missing file, ambiguous or absent ``old`` text, escape)."""


@dataclass(frozen=True)
class PatchOp:
    path: str
    old: str
    new: str


@dataclass
class PatchSet:
    ops: list[PatchOp]
    rationale: str
    attempt: int = 1
    case_id: str | None = None
    state: str = "proposed"

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> PatchSet:
        model = PatchSetModel.model_validate(data)
        return cls(
            ops=[PatchOp(o.path, o.old, o.new) for o in model.ops],
            rationale=model.rationale,
            attempt=model.attempt,
            case_id=model.case_id,
            state=model.state or "proposed",
        )

    def to_payload(self) -> dict[str, Any]:
        return PatchSetModel(
            case_id=self.case_id,
            ops=[PatchOpModel(path=o.path, old=o.old, new=o.new) for o in self.ops],
            rationale=self.rationale,
            attempt=self.attempt,
            state=self.state,  # type: ignore[arg-type]
        ).to_payload()

    @property
    def files(self) -> list[str]:
        return list(dict.fromkeys(o.path for o in self.ops))


@dataclass
class ApplyResult:
    path: str
    before: str
    after: str

    def diff(self) -> str:
        return "".join(difflib.unified_diff(
            self.before.splitlines(keepends=True), self.after.splitlines(keepends=True),
            fromfile=f"a/{self.path}", tofile=f"b/{self.path}",
        ))


@dataclass
class PatchApplier:
    root: Path
    results: list[ApplyResult] = field(default_factory=list)

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        self.results = []

    def _resolve(self, rel: str) -> Path:
        target = (self.root / rel).resolve()
        if target != self.root and self.root not in target.parents:
            raise PatchError(f"{rel}: path escapes patch root")
        return target

    def plan(self, patchset: PatchSet) -> list[ApplyResult]:
        """Compute the new contents for every touched file without writing anything."""
        contents: dict[str, str] = {}
        originals: dict[str, str] = {}
        for op in patchset.ops:
            path = self._resolve(op.path)
            rel = path.relative_to(self.root).as_posix()
            if not op.old:
                raise PatchError(f"{op.path}: 'old' text must not be empty")
            if rel not in contents:
                if not path.is_file():
                    raise PatchError(f"{op.path}: file not found")
                text = path.read_text(encoding="utf-8")
                contents[rel] = originals[rel] = text
            count = contents[rel].count(op.old)
            if count != 1:
                raise PatchError(f"{op.path}: 'old' text found {count} times (need exactly 1)")
            contents[rel] = contents[rel].replace(op.old, op.new, 1)
        return [ApplyResult(p, originals[p], contents[p]) for p in contents]

    def apply(self, patchset: PatchSet, dry_run: bool = False) -> list[ApplyResult]:
        planned = self.plan(patchset)
        if not dry_run:
            for res in planned:
                target = self._resolve(res.path)
                tmp = target.with_suffix(target.suffix + ".pgtmp")
                tmp.write_text(res.after, encoding="utf-8", newline="")
                os.replace(tmp, target)
            self.results = planned
        return planned

    def revert(self) -> None:
        """Undo the last :meth:`apply` (S1 convenience; Fix History rollback is S2)."""
        for res in self.results:
            self._resolve(res.path).write_text(res.before, encoding="utf-8", newline="")
        self.results = []


def unified_diff(results: list[ApplyResult]) -> str:
    return "".join(r.diff() for r in results)


def build_bundle(
    *,
    case_id: str,
    finding: dict[str, Any],
    patchset: PatchSet,
    diff: str,
    verdict: dict[str, Any] | None,
    sandbox_report: dict[str, Any] | None,
    approval: dict[str, Any] | None,
    mode: str,
) -> dict[str, Any]:
    """Remediation Bundle = patch + PR description. Never pushed anywhere (framework 2.2)."""
    score = verdict.get("score") if verdict else None
    lines = [
        f"## [PulseGuard] Fix {finding.get('rule_id')} in {finding.get('file')}",
        "",
        f"Case `{case_id}` · run mode **{mode.upper()}**",
        "",
        f"**Rationale:** {patchset.rationale}",
        "",
        f"- Adjudicator score: {score}" if score is not None else "- Adjudicator score: n/a",
        f"- Cited evidence: {', '.join(verdict.get('cited_evidence', [])) if verdict else 'n/a'}",
        f"- Sandbox: {'passed' if sandbox_report and sandbox_report.get('passed') else 'n/a'}",
        f"- Approval: {approval.get('decision') if approval else 'pending'}"
        f" by {approval.get('actor') if approval else '-'}",
    ]
    return {
        "case_id": case_id,
        "files": patchset.files,
        "patch": diff,
        "pr_title": f"[PulseGuard] Fix {finding.get('rule_id')} in {finding.get('file')}",
        "pr_description": "\n".join(lines),
    }

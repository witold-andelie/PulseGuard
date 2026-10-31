"""Deterministic dependency bump from Finding.extra (framework 12 / scenario 2).

Consumes the SURFACE contract extra: ``package``, ``installed_version``, ``fixed_version``,
``manifest``. No model call.
"""

from __future__ import annotations

import re
from typing import Any

from pulseguard.patching.patch import PatchOp, PatchSet


class BumpError(ValueError):
    """The manifest does not contain a pin the bump can replace."""


def deterministic_bump(
    finding: dict[str, Any], manifest_text: str, *, attempt: int = 1,
) -> PatchSet:
    extra = finding.get("extra") or {}
    package = str(extra.get("package") or extra.get("pkg_name") or "")
    installed = str(extra.get("installed_version") or "")
    fixed = str(extra.get("fixed_version") or "")
    manifest = str(extra.get("manifest") or finding.get("file") or "requirements.txt")
    if not package or not installed or not fixed:
        raise BumpError("dependency finding extra lacks package/installed_version/fixed_version")
    pattern = re.compile(
        rf"^{re.escape(package)}\s*==\s*{re.escape(installed)}\s*(?:[;#].*)?$", re.M)
    match = pattern.search(manifest_text)
    if match is None:
        raise BumpError(f"{package}=={installed} not found in {manifest}")
    old = match.group(0)
    comment = ""
    if " #" in old:
        comment = old[old.index(" #"):]
    elif ";" in old:
        comment = old[old.index(";"):]
    new = f"{package}=={fixed}{comment}"
    return PatchSet(
        ops=[PatchOp(manifest, old, new)],
        rationale=f"Bump {package} {installed} → {fixed} (deterministic; no model call).",
        attempt=attempt,
        case_id=finding.get("case_id"),
        state="proposed",
    )

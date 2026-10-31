"""On-disk store for recorded runs (``replay/runs/<run_id>/run.json``).

Adapted from tradepulse ``tradepulse/store.py`` (``RunStore``: validated run ids, atomic save).
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
RUN_FILE = "run.json"


class InvalidRunId(ValueError):
    pass


def validate_run_id(run_id: str) -> str:
    if not RUN_ID_RE.fullmatch(run_id or "") or ".." in run_id:
        raise InvalidRunId(f"invalid run id: {run_id!r}")
    return run_id


class RunStore:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.runs_dir = self.root / "runs"

    def path_for(self, run_id: str) -> Path:
        return self.runs_dir / validate_run_id(run_id) / RUN_FILE

    def list_runs(self) -> list[str]:
        if not self.runs_dir.is_dir():
            return []
        return sorted(p.parent.name for p in self.runs_dir.glob(f"*/{RUN_FILE}")
                      if RUN_ID_RE.fullmatch(p.parent.name) and ".." not in p.parent.name)

    def load(self, run_id: str) -> dict[str, Any]:
        return json.loads(self.path_for(run_id).read_text(encoding="utf-8"))

    def latest(self) -> dict[str, Any] | None:
        runs = self.list_runs()
        loaded = [self.load(run_id) for run_id in runs]
        return max(loaded, key=lambda run: (run.get("recorded") is True,
                                            run.get("started_at", ""), run["run_id"])) \
            if loaded else None

    def save(self, run_id: str, data: dict[str, Any]) -> Path:
        """Atomic write (temp file + ``os.replace``). Caller must re-write the manifest."""
        target = self.path_for(run_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return target

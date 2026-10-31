"""Fix History and Rolling Back, adapted from revio ``src/revio/agent/fix_history.py``.

``FixHistoryStore``, ``FixSession`` and ``FileSnapshot`` capture the pre-patch bytes of
an applied bundle target so ``POST /api/cases/{id}/rollback`` can restore them.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    content: str


@dataclass
class FixSession:
    session_id: str
    case_id: str
    snapshots: list[FileSnapshot] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "case_id": self.case_id,
            "snapshots": [asdict(item) for item in self.snapshots],
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> FixSession:
        snaps = [FileSnapshot(s["path"], s["content"]) for s in data.get("snapshots") or []]
        return cls(str(data["session_id"]), str(data["case_id"]), snaps)


class FixHistoryStore:
    """In-memory / state-backed snapshots. The case runtime JSON is the durable copy."""

    def __init__(self) -> None:
        self._sessions: dict[str, FixSession] = {}

    def begin(self, case_id: str, root: Path, files: list[str]) -> FixSession:
        snapshots: list[FileSnapshot] = []
        for rel in files:
            path = _safe_file(root, rel)
            snapshots.append(FileSnapshot(rel.replace("\\", "/"), path.read_text(encoding="utf-8")))
        session = FixSession(f"FH-{uuid4().hex[:12]}", case_id, snapshots)
        self._sessions[session.session_id] = session
        return session

    def snapshot_files(self, case_id: str, root: Path, files: list[str]) -> list[dict[str, str]]:
        return [asdict(item) for item in self.begin(case_id, root, files).snapshots]

    @staticmethod
    def restore(root: Path, snapshots: list[dict[str, str] | FileSnapshot]) -> None:
        """Write each snapshot back under ``root``. Rejects escaping paths."""
        for item in snapshots:
            if isinstance(item, FileSnapshot):
                rel, content = item.path, item.content
            else:
                rel, content = item["path"], item["content"]
            path = _safe_file(root, rel, must_exist=False)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="")


def _safe_file(root: Path, rel: str, *, must_exist: bool = True) -> Path:
    posix = PurePosixPath(rel.replace("\\", "/"))
    if posix.is_absolute() or ".." in posix.parts or not rel:
        raise ValueError(f"snapshot path escapes root: {rel}")
    path = (root / rel).resolve()
    root = root.resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"snapshot path escapes root: {rel}")
    if must_exist and not path.is_file():
        raise FileNotFoundError(rel)
    return path

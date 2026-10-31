"""sha256 manifest verification of the ``replay/`` bundle.

Adapted from tradepulse ``scripts/review_demo.py`` (hash-verified review bundle,
``--verify-only``). The API verifies the bundle at boot before seeding SQLite; a failed
verification is reported on ``/health`` and ``/api/mode`` instead of serving silently.

CLI::

    python -m pulseguard.replay.verify            # verify (exit 1 on mismatch)
    python -m pulseguard.replay.verify --write    # regenerate the manifest
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from pulseguard.paths import replay_dir

MANIFEST_NAME = "manifest.sha256.json"


@dataclass
class VerifyResult:
    ok: bool
    manifest_sha256: str | None = None
    checked: int = 0
    mismatched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unlisted: list[str] = field(default_factory=list)
    error: str | None = None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _bundle_files(root: Path) -> list[str]:
    return sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.relative_to(root).as_posix() != MANIFEST_NAME
    )


def build_manifest(root: Path) -> dict[str, object]:
    return {
        "algorithm": "sha256",
        "files": {rel: sha256_file(root / rel) for rel in _bundle_files(root)},
    }


def write_manifest(root: Path | None = None) -> Path:
    root = Path(root or replay_dir())
    path = root / MANIFEST_NAME
    path.write_text(json.dumps(build_manifest(root), indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    return path


def verify_manifest(root: Path | None = None) -> VerifyResult:
    root = Path(root or replay_dir())
    mpath = root / MANIFEST_NAME
    if not mpath.is_file():
        return VerifyResult(ok=False, error=f"manifest not found: {mpath}")
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
        files = manifest["files"]
        if manifest.get("algorithm") != "sha256":
            raise ValueError("algorithm must be sha256")
        if not isinstance(files, dict) or not files:
            raise ValueError("files must be a nonempty object")
        for rel, digest in files.items():
            if not isinstance(rel, str) or not rel or rel == MANIFEST_NAME:
                raise ValueError("invalid bundle filename")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"invalid sha256 for {rel}")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return VerifyResult(ok=False, error=f"bad manifest: {exc}")

    res = VerifyResult(ok=True, manifest_sha256=sha256_file(mpath))
    for rel, expected in sorted(files.items()):
        target = (root / rel).resolve()
        if (
            root.resolve() not in target.parents
            or Path(rel).is_absolute()
            or "\\" in rel
            or ".." in Path(rel).parts
        ):
            res.mismatched.append(rel)
            continue
        if not target.is_file():
            res.missing.append(rel)
            continue
        res.checked += 1
        if sha256_file(target) != expected:
            res.mismatched.append(rel)
    res.unlisted = [f for f in _bundle_files(root) if f not in files]
    res.ok = not (res.mismatched or res.missing or res.unlisted)
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=None)
    ap.add_argument("--write", action="store_true", help="regenerate the manifest")
    args = ap.parse_args(argv)
    if args.write:
        print(f"wrote {write_manifest(args.root)}")
        return 0
    res = verify_manifest(args.root)
    print(json.dumps(res.__dict__, indent=2))
    return 0 if res.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

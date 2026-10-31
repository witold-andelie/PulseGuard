"""Repository paths, overridable through environment variables for container layouts."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = Path(__file__).resolve().parent


def _env_path(var: str, default: Path) -> Path:
    value = os.environ.get(var)
    return Path(value) if value else default


def contracts_dir() -> Path:
    return _env_path("PG_CONTRACTS_DIR", REPO_ROOT / "contracts")


def web_dir() -> Path:
    return _env_path("PG_WEB_DIR", REPO_ROOT / "web")


def replay_dir() -> Path:
    return _env_path("PG_REPLAY_DIR", REPO_ROOT / "replay")


def demo_target_dir() -> Path:
    return _env_path("PG_DEMO_TARGET", REPO_ROOT / "demo_target")


def rules_dir() -> Path:
    return PACKAGE_DIR / "rules" / "semgrep"


def default_db_path() -> Path:
    """``PG_DB_PATH`` or ``<system temp>/pulseguard.sqlite`` (temp honours TMP/TEMP)."""
    return _env_path("PG_DB_PATH", Path(tempfile.gettempdir()) / "pulseguard.sqlite")

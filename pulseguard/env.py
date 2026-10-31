"""Process-only CLI configuration for the revio ``src/revio/agent/runner.py`` pattern.

Values are literal KEY=VALUE data, never shell commands or recording metadata.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


def load_env_file(path: Path) -> None:
    """Load literal assignments atomically, overriding this process's environment."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        raise ValueError("Cannot read --env-file") from None
    values: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError(f"Invalid --env-file assignment at line {number}")
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError(f"Invalid --env-file quoting at line {number}")
            value = value[1:-1]
        if "\0" in value:
            raise ValueError(f"Invalid --env-file value at line {number}")
        values[key] = value
    os.environ.update(values)

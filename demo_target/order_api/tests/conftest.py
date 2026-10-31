"""Make ``routes`` importable when pytest runs from the repo root or a sandbox copy."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

"""JSON Schema 2020-12 validation of payloads against ``contracts/*.schema.json``.

Adapted from tradepulse ``tradepulse/contracts.py`` (``validate_payload`` / ``assert_payload``).
"""

from __future__ import annotations

import json
from functools import cache
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from pulseguard.paths import contracts_dir

CONTRACT_NAMES = ("finding", "verdict", "patchset", "event")


class ContractError(ValueError):
    """Raised by :func:`assert_payload` when a payload violates its contract."""

    def __init__(self, name: str, errors: list[str]):
        self.name = name
        self.errors = errors
        super().__init__(f"{name} payload invalid: " + "; ".join(errors))


@cache
def _validator(name: str) -> Draft202012Validator:
    if name not in CONTRACT_NAMES:
        raise KeyError(f"unknown contract {name!r}; expected one of {CONTRACT_NAMES}")
    schema = json.loads((contracts_dir() / f"{name}.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_payload(name: str, obj: Any) -> list[str]:
    """Return a list of human-readable violations (empty list = valid)."""
    validator = _validator(name)
    errors = sorted(validator.iter_errors(obj), key=lambda e: tuple(map(str, e.absolute_path)))
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errors]


def assert_payload(name: str, obj: Any) -> Any:
    """Raise :class:`ContractError` if ``obj`` is invalid; otherwise return it unchanged."""
    errors = validate_payload(name, obj)
    if errors:
        raise ContractError(name, errors)
    return obj


def check_all_schemas() -> list[str]:
    """Meta-validate every schema file (used by CI). Returns the names checked."""
    for name in CONTRACT_NAMES:
        _validator(name)
    return list(CONTRACT_NAMES)


if __name__ == "__main__":  # pragma: no cover - CI helper
    print("schemas ok:", ", ".join(check_all_schemas()))

"""Bandit subprocess adapter, from revio ``src/revio/layers/static/bandit.py``.

Bandit supplies pattern matches, never a taint proof. For B608 we also attach a syntactic
assignment slice from the enclosing function so the evidence builder can inspect int casts.
This locally derived context is separate from the unchanged scanner JSON in ``raw``.
Test files are excluded and B101 is skipped by default: pytest asserts express test
expectations, not production vulnerabilities. Both defaults can be overridden by callers.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pulseguard.scanners.semgrep import DataflowTrace, TraceLine


class BanditUnavailable(RuntimeError):
    """Bandit could not be started."""


class BanditError(RuntimeError):
    """Bandit failed or returned an incomplete report."""


@dataclass
class BanditResult:
    test_id: str
    path: str
    line: int
    message: str
    severity: str
    confidence: str
    code: str
    trace: DataflowTrace | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def _sql_context(code: str, line: int) -> DataflowTrace | None:
    """Extract B608 assignment context, including casts in try blocks, not scanner taint."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                 and node.lineno <= line <= (node.end_lineno or node.lineno)]
    if not functions:
        return None
    function = min(functions, key=lambda node: (node.end_lineno or node.lineno) - node.lineno)
    if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
           for node in ast.walk(function) if node is not function):
        return None
    assignments = sorted((node for node in ast.walk(function) if isinstance(node, ast.Assign)),
                         key=lambda node: node.lineno)
    query = next((node for node in assignments
                  if node.lineno <= line <= (node.end_lineno or node.lineno)), None)
    if query is None or len(query.targets) != 1 or not isinstance(query.targets[0], ast.Name):
        return None
    query_name = query.targets[0].id
    sinks = [node for node in ast.walk(function) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
             and node.args and isinstance(node.args[0], ast.Name)
             and node.args[0].id == query_name and node.lineno > query.lineno]
    if not sinks:
        return None
    dependencies = {node.id for node in ast.walk(query.value) if isinstance(node, ast.Name)}
    selected = [query]
    for node in reversed(assignments):
        if node.lineno >= query.lineno:
            continue
        names = {target.id for target in node.targets if isinstance(target, ast.Name)}
        if names & dependencies:
            selected.append(node)
            dependencies.difference_update(names)
            dependencies.update(n.id for n in ast.walk(node.value) if isinstance(n, ast.Name))
    selected.reverse()
    lines = code.splitlines()

    def location(node: ast.AST) -> TraceLine:
        return TraceLine(node.lineno, lines[node.lineno - 1].strip())

    # No source claim unless the slice actually contains a request expression.
    source = next((node for node in selected if any(
        isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
        and n.value.id == "request" and n.attr in ("args", "form", "values", "json")
        for n in ast.walk(node.value))), None)
    return DataflowTrace(
        source=location(source) if source else None,
        intermediates=[location(node) for node in selected if node is not source],
        sink=location(min(sinks, key=lambda node: node.lineno)),
    )


class BanditRunner:
    """Run Bandit JSON on Python source; exit 1 means findings, not failure."""

    def __init__(self, executable: str | None = None, timeout: float = 60.0, *,
                 excludes: Sequence[str] = ("*/tests/*", "*/test_*.py", "*/*_test.py",
                                            "*/conftest.py"),
                 skips: Sequence[str] = ("B101",)) -> None:
        self.executable = executable or os.environ.get("PG_BANDIT_BIN")
        self.timeout = timeout
        self.excludes = tuple(excludes)
        self.skips = tuple(skips)

    @staticmethod
    def available() -> bool:
        return bool(os.environ.get("PG_BANDIT_BIN") or importlib.util.find_spec("bandit"))

    def run_json(self, target: str | os.PathLike[str]) -> dict[str, Any]:
        # A full path makes the test-directory globs work for relative targets too.
        target = Path(target).resolve()
        command = [self.executable] if self.executable else [sys.executable, "-m", "bandit"]
        command += ["-r", str(target), "-f", "json", "-q"]
        if self.excludes:
            command += ["--exclude", ",".join(self.excludes)]
        if self.skips:
            command += ["--skip", ",".join(self.skips)]
        try:
            proc = subprocess.run(
                command,
                capture_output=True, timeout=self.timeout, check=False,
                env=dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1"),
            )
        except OSError as exc:
            raise BanditUnavailable(str(exc)) from exc
        except subprocess.TimeoutExpired as exc:
            raise BanditError(f"bandit timed out after {self.timeout}s") from exc
        if proc.returncode not in (0, 1):
            raise BanditError(f"bandit exited {proc.returncode}: "
                              f"{proc.stderr.decode('utf-8', 'replace')[:1500]}")
        try:
            data = json.loads(proc.stdout)
        except (ValueError, UnicodeError) as exc:
            raise BanditError("bandit did not return valid JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise BanditError("bandit report has no results list")
        if data.get("errors"):
            raise BanditError(f"bandit reported scan errors: {data['errors']}")
        return data

    def run(self, target: str | os.PathLike[str]) -> list[BanditResult]:
        results = []
        for row in self.run_json(target)["results"]:
            try:
                result = BanditResult(
                    test_id=row["test_id"], path=row["filename"], line=int(row["line_number"]),
                    message=row["issue_text"], severity=row["issue_severity"],
                    confidence=row["issue_confidence"], code=row["code"], raw=row,
                )
                if result.test_id == "B608":
                    result.trace = _sql_context(
                        Path(result.path).read_text(encoding="utf-8"), result.line)
                results.append(result)
            except (KeyError, TypeError, ValueError, OSError) as exc:
                raise BanditError("bandit result or its source file is unavailable") from exc
        return results

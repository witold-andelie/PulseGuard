"""Semgrep CLI runner (subprocess; Semgrep is never imported).

Subprocess pattern adapted from revio ``src/revio/layers/static/bandit.py`` (``BanditRunner``).

Framework 4.1: with Semgrep 1.183.0 the source -> intermediate -> sink trace appears only in the
**text** output with ``--dataflow-traces``. The runner therefore runs twice: JSON for the sink
location and metadata, text for the trace. If a future Semgrep version puts
``extra.dataflow_trace`` into the JSON, that is used directly.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pulseguard.paths import rules_dir

DEFAULT_RULE = "flask-sqli-taint.yaml"


class SemgrepUnavailable(RuntimeError):
    """The ``semgrep`` executable could not be found."""


class SemgrepError(RuntimeError):
    """Semgrep exited with an error status."""


@dataclass(frozen=True)
class TraceLine:
    line: int
    content: str


@dataclass
class DataflowTrace:
    """Deterministic taint trace: one source, zero or more intermediates, one sink."""

    source: TraceLine | None = None
    intermediates: list[TraceLine] = field(default_factory=list)
    sink: TraceLine | None = None

    def dedupe(self) -> DataflowTrace:
        """Drop the source (and sink) line when Semgrep also lists it as an intermediate."""
        skip = {tl.line for tl in (self.source, self.sink) if tl is not None}
        seen: set[tuple[int, str]] = set()
        unique: list[TraceLine] = []
        for tl in self.intermediates:
            key = (tl.line, tl.content)
            if tl.line in skip or key in seen:
                continue
            seen.add(key)
            unique.append(tl)
        self.intermediates = unique
        return self

    def steps(self) -> list[dict[str, Any]]:
        """Trace in the ``finding.schema.json`` ``trace`` shape (source first, sink last)."""
        self.dedupe()
        out: list[dict[str, Any]] = []
        if self.source:
            out.append({"kind": "source", "line": self.source.line, "content": self.source.content})
        for t in self.intermediates:
            out.append({"kind": "intermediate", "line": t.line, "content": t.content})
        if self.sink:
            out.append({"kind": "sink", "line": self.sink.line, "content": self.sink.content})
        return out


@dataclass
class SemgrepResult:
    rule_id: str
    path: str
    line: int
    end_line: int
    message: str
    severity: str
    code: str
    trace: DataflowTrace | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def short_rule_id(check_id: str) -> str:
    """Semgrep prefixes local rule ids with the config path; keep the last dotted segment."""
    return check_id.rsplit(".", 1)[-1]


# --------------------------------------------------------------------------- text trace parsing

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_PATH_RE = re.compile(r"^\s+([^\s┆|]+\.[A-Za-z0-9]+)\s*$")
_RULE_RE = re.compile(r"^\s*[❯❱>]+\s+(\S+)\s*$")
_CODE_RE = re.compile(r"^\s*(\d+)\s*[┆|]\s?(.*)$")


def parse_dataflow_text(text: str) -> list[tuple[str, str, DataflowTrace]]:
    """Parse ``semgrep --text --dataflow-traces`` output.

    Returns ``(path, short_rule_id, trace)`` tuples in output order. The parser is deliberately
    tolerant: a rule header is a ``❯❱ rule-id`` line, the file header is the bare path line right
    before it (Semgrep omits it for consecutive findings in the same file), and the trace comes
    from the section headers ("Taint comes from", "intermediate variables", "reaches the sink")
    followed by ``<line>┆ <code>`` rows. Code rows before any section header are the matched
    code and become the sink if no explicit sink section follows.
    """
    results: list[tuple[str, str, DataflowTrace]] = []
    path = ""
    current: DataflowTrace | None = None
    rule = ""
    section = "match"
    match_lines: list[TraceLine] = []
    prev_nonblank = ""

    def flush() -> None:
        nonlocal current, match_lines
        if current is not None:
            if current.sink is None and match_lines:
                current.sink = match_lines[-1]
            results.append((path, rule, current.dedupe()))
        current, match_lines = None, []

    for raw in text.splitlines():
        line = _ANSI_RE.sub("", raw).rstrip()
        lower = line.lower()
        rule_m = _RULE_RE.match(line)
        if rule_m:
            flush()
            path_m = _PATH_RE.match(prev_nonblank)
            if path_m:
                path = path_m.group(1)
            rule = short_rule_id(rule_m.group(1))
            current = DataflowTrace()
            section = "match"
            prev_nonblank = line
            continue
        if line.strip():
            prev_nonblank = line
        if current is None:
            continue
        if "taint comes from" in lower:
            section = "source"
            continue
        if "intermediate variable" in lower:
            section = "intermediate"
            continue
        if "reaches the sink" in lower:
            section = "sink"
            continue
        code_m = _CODE_RE.match(line)
        if not code_m:
            continue
        tl = TraceLine(int(code_m.group(1)), code_m.group(2).strip())
        if section == "match":
            match_lines.append(tl)
        elif section == "source" and current.source is None:
            current.source = tl
        elif section == "intermediate":
            if tl not in current.intermediates:
                current.intermediates.append(tl)
        elif section == "sink" and current.sink is None:
            current.sink = tl
    flush()
    return results


def trace_from_json(extra: dict[str, Any]) -> DataflowTrace | None:
    """Use ``extra.dataflow_trace`` from Semgrep JSON when a Semgrep version provides it."""
    dft = extra.get("dataflow_trace")
    if not isinstance(dft, dict):
        return None

    def _loc(obj: Any) -> TraceLine | None:
        # Shapes seen in Semgrep JSON: ["CliLoc", [{start:{line}}, "content"]]
        try:
            if isinstance(obj, list) and len(obj) == 2 and isinstance(obj[1], list):
                loc, content = obj[1]
                return TraceLine(int(loc["start"]["line"]), str(content).strip())
        except (KeyError, TypeError, ValueError):
            return None
        return None

    trace = DataflowTrace(source=_loc(dft.get("taint_source")), sink=_loc(dft.get("taint_sink")))
    for var in dft.get("intermediate_vars") or []:
        try:
            trace.intermediates.append(
                TraceLine(int(var["location"]["start"]["line"]), str(var["content"]).strip())
            )
        except (KeyError, TypeError, ValueError):
            continue
    if not (trace.source or trace.sink):
        return None
    return trace.dedupe()


# --------------------------------------------------------------------------------- the runner


class SemgrepRunner:
    """Run local Semgrep rules against a target directory.

    ``SemgrepRunner().run("demo_target/order_api")`` returns a list of :class:`SemgrepResult`
    with the dataflow trace attached when Semgrep reports one.
    """

    def __init__(
        self,
        rules: str | os.PathLike[str] | None = None,
        executable: str | None = None,
        timeout: float = 180.0,
    ) -> None:
        self.rules = Path(rules) if rules else rules_dir() / DEFAULT_RULE
        self.executable = executable or os.environ.get("PG_SEMGREP_BIN") or _find_semgrep()
        self.timeout = timeout

    @staticmethod
    def available() -> bool:
        return _find_semgrep() is not None

    def _base_cmd(self) -> list[str]:
        if not self.executable:
            raise SemgrepUnavailable("semgrep executable not found on PATH (pip install semgrep)")
        return [
            self.executable,
            "scan",
            "--config",
            str(self.rules),
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--quiet",
        ]

    def _exec(self, args: list[str]) -> str:
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", NO_COLOR="1")
        try:
            proc = subprocess.run(
                args, capture_output=True, timeout=self.timeout, env=env, check=False
            )
        except OSError as exc:
            raise SemgrepUnavailable(str(exc)) from exc
        except subprocess.TimeoutExpired as exc:
            raise SemgrepError(f"semgrep timed out after {self.timeout}s") from exc
        # 0 = no findings, 1 = findings (with --error); anything else is a failure.
        if proc.returncode not in (0, 1):
            detail = proc.stderr.decode('utf-8', 'replace')
            if len(detail) > 2000:
                detail = detail[:1000] + "\n...\n" + detail[-1000:]
            raise SemgrepError(
                f"semgrep exited {proc.returncode}: {detail}"
            )
        return proc.stdout.decode("utf-8", "replace")

    def run_json(self, target: str | os.PathLike[str]) -> dict[str, Any]:
        try:
            data = json.loads(self._exec([*self._base_cmd(), "--json", str(target)]))
        except json.JSONDecodeError as exc:
            raise SemgrepError("semgrep did not return valid JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise SemgrepError("semgrep report has no results list")
        if data.get("errors"):
            raise SemgrepError(f"semgrep reported scan errors: {data['errors']}")
        return data

    def run_text_traces(self, target: str | os.PathLike[str]) -> str:
        return self._exec(
            [*self._base_cmd(), "--text", "--dataflow-traces", str(target)]
        )

    def run(self, target: str | os.PathLike[str], with_traces: bool = True) -> list[SemgrepResult]:
        data = self.run_json(target)
        results = [_result_from_json(r) for r in data.get("results", [])]
        if with_traces and results and any(r.trace is None for r in results):
            parsed = parse_dataflow_text(self.run_text_traces(target))
            _attach_traces(results, parsed)
        return results

    def count(self, target: str | os.PathLike[str], rule_id: str | None = None) -> int:
        """Number of findings (optionally for one rule) - the sandbox re-scan gate."""
        results = self.run(target, with_traces=False)
        return sum(1 for r in results if rule_id is None or r.rule_id == rule_id)


def _find_semgrep() -> str | None:
    found = shutil.which("semgrep")
    if found:
        return found
    # Same venv as this interpreter, even when the venv is not activated.
    scripts = Path(sys.executable).parent
    for name in ("semgrep.exe", "semgrep"):
        if (scripts / name).exists():
            return str(scripts / name)
    return None


def _result_from_json(r: dict[str, Any]) -> SemgrepResult:
    extra = r.get("extra", {}) or {}
    return SemgrepResult(
        rule_id=short_rule_id(r.get("check_id", "unknown")),
        path=str(r.get("path", "")).replace("\\", "/"),
        line=int(r.get("start", {}).get("line", 0)),
        end_line=int(r.get("end", {}).get("line", 0)),
        message=str(extra.get("message", "")),
        severity=str(extra.get("severity", "")),
        code=str(extra.get("lines", "")).strip(),
        trace=trace_from_json(extra),
        raw=r,
    )


def _attach_traces(
    results: list[SemgrepResult], parsed: list[tuple[str, str, DataflowTrace]]
) -> None:
    def _norm(p: str) -> str:
        return p.replace("\\", "/").lstrip("./")

    pool = list(parsed)
    for res in results:
        if res.trace is not None:
            continue
        for i, (path, rule, trace) in enumerate(pool):
            same_file = _norm(path).endswith(_norm(res.path)) or _norm(res.path).endswith(
                _norm(path)
            )
            same_rule = rule == res.rule_id
            same_line = trace.sink is None or trace.sink.line == res.line
            if same_file and same_rule and same_line:
                res.trace = trace
                pool.pop(i)
                break


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - CLI helper used by CI
    import argparse

    ap = argparse.ArgumentParser(description="Run PulseGuard Semgrep rules on a target")
    ap.add_argument("target")
    ap.add_argument("--rules", default=None)
    ap.add_argument("--expect", type=int, default=None, help="fail unless exactly N findings")
    args = ap.parse_args(argv)
    results = SemgrepRunner(rules=args.rules).run(args.target)
    for r in results:
        print(f"{r.rule_id} {r.path}:{r.line} {r.code}")
        if r.trace:
            for step in r.trace.steps():
                print(f"    {step['kind']:<12} L{step['line']}: {step['content']}")
    print(f"findings: {len(results)}")
    if args.expect is not None and len(results) != args.expect:
        print(f"expected {args.expect} findings", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

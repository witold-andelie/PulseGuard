"""Python labels adapted from SymbAI-Taint ``src/ground_truth/extractor.py``.

Unlike the upstream C extractor, only explicit comment tokens define ground truth.
Matching uses exact target-relative file, innermost qualified function, class and
nearest annotation within 12 lines. It never matches across a function boundary.
This accommodates Bandit's query-construction line versus Semgrep's execute line.
Equidistant same-class labels are ambiguous and remain unmatched. Manifest-wide
line-zero findings match dependency labels only, disambiguated by CVE if available.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pulseguard.contracts.models import Finding

LINE_WINDOW = 12
ANNOTATION = re.compile(r"@(?P<label>vuln|safe)\b\s*:?[ \t]*(?P<body>.*)", re.IGNORECASE)
KNOWN_CLASSES = {"sqli", "dependency", "prompt-injection", "cmdi", "ssrf"}
CORPORA = ("original", "hard", "all")


def site_corpus(file: str) -> str:
    """Corpus identity is a path convention, never inferred from truth labels."""
    return "hard" if file.replace("\\", "/").startswith("eval_cases/hard/") else "original"


def in_corpus(file: str, corpus: str) -> bool:
    return corpus == "all" or site_corpus(file) == corpus


@dataclass(frozen=True)
class FunctionSpan:
    """AST function identity, including nested functions and class methods."""

    name: str
    start: int
    end: int


def function_spans(code: str) -> list[FunctionSpan]:
    """Return qualified Python function spans without executing the target."""
    spans: list[FunctionSpan] = []
    lines = code.splitlines()

    def visit(node: ast.AST, parents: tuple[str, ...] = ()) -> None:
        for child in ast.iter_child_nodes(node):
            scope = parents
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope = (*parents, child.name)
                if not isinstance(child, ast.ClassDef):
                    start = min([child.lineno, *(d.lineno for d in child.decorator_list)])
                    end = child.end_lineno or child.lineno
                    # AST end_lineno excludes trailing comments in a function body.
                    # Preserve their lexical ownership instead of attaching them to
                    # the following definition as preceding annotations.
                    for number in range(end + 1, len(lines) + 1):
                        text = lines[number - 1]
                        if not text.strip():
                            continue
                        indent = len(text) - len(text.lstrip())
                        if text.lstrip().startswith("#") and indent > child.col_offset:
                            end = number
                        else:
                            break
                    spans.append(FunctionSpan(".".join(scope), start, end))
            visit(child, scope)

    visit(ast.parse(code))
    return spans


def enclosing_function(spans: list[FunctionSpan], line: int) -> FunctionSpan | None:
    """Use the narrowest span so nested functions do not inherit outer labels."""
    return min((span for span in spans if span.start <= line <= span.end),
               key=lambda span: span.end - span.start, default=None)


def strip_annotations(code: str) -> str:
    """Remove both annotation comment forms, preserving source lines and strings."""
    lines = code.splitlines(keepends=True)
    for token in tokenize.generate_tokens(io.StringIO(code).readline):
        if token.type == tokenize.COMMENT and ANNOTATION.search(token.string):
            row, column = token.start
            ending = "\n" if lines[row - 1].endswith("\n") else ""
            lines[row - 1] = lines[row - 1][:column].rstrip() + ending
    return "".join(lines)


@dataclass(frozen=True)
class Site:
    """One labelled annotation; a function may have labels for different classes."""

    file: str
    line: int
    function: str | None
    label: Literal["vuln", "safe"]
    vulnerability_class: str
    reason: str = ""
    start_line: int = 1
    end_line: int = 1

    @property
    def site_id(self) -> str:
        return f"{self.file}:{self.line}:{self.vulnerability_class}"

    def to_dict(self) -> dict[str, str | int | None]:
        return {"id": self.site_id, "file": self.file, "line": self.line,
                "function": self.function, "label": self.label,
                "class": self.vulnerability_class, "reason": self.reason,
                "start_line": self.start_line, "end_line": self.end_line}


def extract_file(path: Path, root: Path) -> list[Site]:
    """Parse inline/standalone Python or requirements.txt comment annotations.

    A standalone comment immediately before a decorator/definition belongs to that
    function. A bare safe reason defaults to SQLi for this SQL-focused benchmark;
    an explicit class (e.g. ``sqli: int-cast``) takes precedence. Manifest labels
    retain the annotation line and cover the next requirement through intervening
    comments, allowing both inline and preceding ``dependency:`` annotations.
    """
    code = path.read_text(encoding="utf-8-sig")
    file = path.resolve().relative_to(root.resolve()).as_posix()
    lines = code.splitlines()
    python = path.suffix == ".py"
    spans = function_spans(code) if python else []
    comments = [(token.start[0], token.string)
                for token in tokenize.generate_tokens(io.StringIO(code).readline)
                if token.type == tokenize.COMMENT] if python else [
                    (number, line[line.index("#"):])
                    for number, line in enumerate(lines, 1) if "#" in line]
    sites = []
    for number, comment in comments:
        match = ANNOTATION.search(comment)
        if match is None:
            continue
        label = match["label"].lower()
        body = match["body"].strip()
        if not body:
            raise ValueError(f"{file}:{number}: annotation needs a class or reason")
        first = re.split(r"[:\s]", body, maxsplit=1)[0].lower()
        cls = first if label == "vuln" or first in KNOWN_CLASSES else "sqli"
        span = enclosing_function(spans, number)
        if span is None and python:
            # Only comments/blank lines may separate a preceding label and definition.
            span = next((s for s in sorted(spans, key=lambda s: s.start)
                         if s.start > number and all(not line.strip() or
                                                    line.lstrip().startswith("#")
                                                    for line in lines[number:s.start - 1])), None)
        end = number
        if not python and not lines[number - 1].split("#", 1)[0].strip():
            end = next((i for i in range(number + 1, len(lines) + 1)
                        if lines[i - 1].split("#", 1)[0].strip()), number)
        sites.append(Site(file, number, span.name if span else None,
                          "vuln" if label == "vuln" else "safe", cls, body,
                          span.start if span else number, span.end if span else end))
    return sites


def extract_labels(target: str | Path, *, corpus: str = "original") -> list[Site]:
    """Extract annotations from Python and requirements manifests in sorted order."""
    root = Path(target).resolve()
    if corpus not in CORPORA:
        raise ValueError(f"corpus must be one of {','.join(CORPORA)}")
    if not root.is_dir():
        raise ValueError("target must be a directory")
    return [site for path in sorted(root.rglob("*"))
            if path.is_file() and (path.suffix == ".py" or path.name == "requirements.txt")
            and in_corpus(path.relative_to(root).as_posix(), corpus)
            for site in extract_file(path, root)]


def finding_class(finding: Finding) -> str:
    """Map public scanner rule ids to benchmark classes, without consulting labels."""
    rule = finding.rule_id.rsplit(".", 1)[-1]
    if rule in {"flask-sqli-taint", "B608"}:
        return "sqli"
    if finding.scanner == "trivy":
        return "dependency"
    return rule.removeprefix("eval-")


def match_site(
    finding: Finding, sites: list[Site], target: Path, *, line_window: int = LINE_WINDOW,
) -> Site | None:
    """Resolve one hit to at most one label; unknown/unlabelled hits stay auditable."""
    if line_window < 0:
        raise ValueError("line_window must be nonnegative")
    path = Path(finding.file.replace("\\", "/"))
    if not path.is_absolute():
        path = target / path
    try:
        file = path.resolve().relative_to(target.resolve()).as_posix()
    except ValueError:
        return None
    candidates = [s for s in sites if s.file == file
                  and s.vulnerability_class == finding_class(finding)]
    if not candidates:
        return None
    if finding.line == 0:
        candidates = [s for s in candidates if s.vulnerability_class == "dependency"
                      and (not finding.cve_id or finding.cve_id in s.reason)]
        return candidates[0] if len(candidates) == 1 else None
    if path.suffix == ".py":
        span = enclosing_function(function_spans(path.read_text(encoding="utf-8-sig")),
                                  finding.line)
        candidates = [s for s in candidates if s.function == (span.name if span else None)]
    distances = [(min(abs(finding.line - s.line), abs(finding.line - s.end_line))
                  if s.function is None else abs(finding.line - s.line), s) for s in candidates]
    distances = sorted(((d, s) for d, s in distances if d <= line_window), key=lambda ds: ds[0])
    if not distances or (len(distances) > 1 and distances[0][0] == distances[1][0]):
        return None
    return distances[0][1]

"""Non-executing static analysis with explicit language coverage tiers."""

from __future__ import annotations

import ast
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pulseguard.contracts.models import EvidenceItem
from pulseguard.evidence import build_hard_evidence, code_excerpt, render_block
from pulseguard.paths import rules_dir
from pulseguard.scanners.semgrep import DataflowTrace, SemgrepRunner, TraceLine

from .detect import GRAMMAR_LANGUAGES, detect_language, tier_for
from .trace_check import source_text, sources, trace_line_issue
from .treesitter_generic import advisory_excerpt, parse

__all__ = ["StaticResult", "analyze_static", "detect_language", "tier_for"]

_EXTENSIONS = {"java": "java", "javascript": "js", "typescript": "ts", "go": "go",
               "csharp": "cs", "c": "c", "cpp": "cpp"}
_RULES = {"java": "java-sqli-taint.yaml", "javascript": "javascript-sqli-taint.yaml",
          "typescript": "javascript-sqli-taint.yaml", "go": "go-sqli-taint.yaml",
          "csharp": "csharp-sqli-taint.yaml", "c": "c-sqli-taint.yaml",
          "cpp": "cpp-sqli-taint.yaml"}


@dataclass
class StaticResult:
    language: str
    tier: str
    parse_ok: bool
    parse_error: str | None
    findings: list[dict]
    trace: list[dict]
    evidence: list[EvidenceItem]
    analysis_limits: list[dict]
    excerpt: str
    evidence_block: str
    sink_line: int | None
    z3: dict | None
    dominance: dict | None


def _limit(limits: list[dict], check: str, reason: str) -> None:
    limits.append({"id": f"L{len(limits) + 1}", "check": check,
                   "status": "not_covered", "reason": reason})


def _block(items: list[EvidenceItem], limits: list[dict], excerpt: str) -> str:
    # Reuse the canonical renderer; replace its unavailable-code placeholder
    # with the already selected grammar excerpt, without running Python slicing.
    block = render_block(items, analysis_limits=limits)
    return block.rsplit("\n", 1)[0] + "\n" + excerpt


def _advisory(code: str, language: str, reason: str) -> StaticResult:
    limits: list[dict] = []
    _limit(limits, "language coverage", reason + "; no hard evidence; verdict is advisory only")
    excerpt = advisory_excerpt(code)
    return StaticResult(language, "llm_only", False, reason, [], [], [], limits,
                        excerpt, _block([], limits, excerpt), None, None, None)


def _python(code: str) -> StaticResult:
    # Delegate to the pre-existing playground's static helpers. Do not call
    # analyze_snippet: guard, model adjudication, verification and veto stay there.
    from pulseguard.falsify.z3_check import check_validator_dominance, check_validators
    from pulseguard.playground import (
        SNIPPET_NAME,
        PlaygroundHooks,
        _bandit_runner,
        _pick_finding,
        _run_scanners,
        _semgrep_runner,
        strip_ground_truth,
    )

    try:
        ast.parse(code)
    except (SyntaxError, ValueError) as exc:
        return _advisory(code, "python", f"Python parse error: {exc}")
    stripped = strip_ground_truth(code)
    hooks = PlaygroundHooks()
    with tempfile.TemporaryDirectory(prefix="pg-lang-") as directory:
        root = Path(directory)
        (root / SNIPPET_NAME).write_text(stripped, encoding="utf-8")
        semgrep, bandit, _ = _run_scanners(
            root, semgrep=_semgrep_runner(hooks), bandit=_bandit_runner(hooks))
        finding, trace, _ = _pick_finding(stripped, "PG-static", semgrep, bandit, root)
        limits: list[dict] = []
        items = build_hard_evidence(finding, trace, code=stripped, analysis_limits=limits)
        sink = trace.sink.line if trace and trace.sink else finding.line
        source = trace.source.line if trace and trace.source else finding.line
        z3 = check_validators(stripped, source_line=source, sink_line=sink, file=SNIPPET_NAME)
        dominance = check_validator_dominance(stripped, source_line=source, sink_line=sink)
        findings = [
            {"scanner": "semgrep", "rule_id": item.rule_id, "line": item.line,
             "message": item.message, "severity": item.severity}
            for item in semgrep
        ] + [
            {"scanner": "bandit", "rule_id": item.test_id, "line": item.line,
             "message": item.message, "severity": item.severity}
            for item in bandit
        ]
        return StaticResult(
            "python", "full", True, None, findings, trace.steps() if trace else [], items, limits,
            code_excerpt(stripped, sink),
            render_block(items, stripped, sink_line=sink, analysis_limits=limits), sink,
            {"result": z3.result, "claim": z3.claim, "detail": z3.detail,
             "context": z3.context, "question": z3.question, "witness": z3.witness},
            {"dominates": bool(dominance.get("dominates")), "reason": dominance.get("reason"),
             "guard_line": dominance.get("guard_line"), "sink_line": dominance.get("sink_line")},
        )


def _scan(code: str, language: str, limits: list[dict]) -> list:
    if language not in _RULES:
        _limit(limits, "SQL injection scan", f"no Semgrep SQL injection rule for {language}")
        return []
    try:
        with tempfile.TemporaryDirectory(prefix="pg-lang-") as directory:
            root = Path(directory)
            (root / f"snippet.{_EXTENSIONS[language]}").write_text(code, encoding="utf-8")
            return SemgrepRunner(rules=rules_dir() / _RULES[language], timeout=25).run(root)
    except (OSError, RuntimeError) as exc:
        # Do not expose exception text (scanner diagnostics can contain host paths).
        _limit(limits, "SQL injection scan", f"Semgrep unavailable for {language}: "
               f"{type(exc).__name__}; no absence or safety claim")
        return []


def analyze_static(code: str, language: str) -> StaticResult:
    """Parse and scan source text; never import or execute submitted code."""
    if language == "python":
        return _python(code)
    if language not in GRAMMAR_LANGUAGES:
        return _advisory(code, language, f"no static analysis support for {language}")
    snippet, error = parse(code, language)
    if snippet is None:
        return _advisory(code, language, error)
    limits: list[dict] = []
    stripped = snippet.stripped()
    hits = _scan(stripped, language, limits)
    findings = [{"scanner": "semgrep", "rule_id": h.rule_id, "line": h.line,
                 "message": h.message, "severity": h.severity} for h in hits]
    trace = (hits[0].trace or DataflowTrace()) if hits else DataflowTrace()
    sink = hits[0].line if hits else None
    if not hits:
        first_source = next(iter(sources(snippet)), None)
        if first_source is not None:
            line = first_source.start_point.row + 1
            trace.source = TraceLine(line, stripped.splitlines()[line - 1].strip())
    anchor = sink or (trace.source.line if trace.source else 1)
    items = []
    source_issue = (trace_line_issue(snippet, trace.source.line, trace.source.content, "source")
                    if trace.source else "source not reported")
    if source_issue is None:
        src = source_text(snippet, trace.source.line, trace.source.content)
        rule = hits[0].rule_id if hits else "source-syntax"
        filename = f"snippet.{_EXTENSIONS.get(language, 'sql')}"
        items.append(EvidenceItem(
            evidence_id="E1", kind="rule_source",
            text=f"rule {rule} · source {src} @ {filename}:{trace.source.line}",
            payload={"rule_id": rule, "source": src, "file": filename,
                     "line": trace.source.line},
        ))
    issue = source_issue or ("sink not reported" if trace.sink is None else None)
    # Check every reported hop before dedupe: a bogus same-line intermediate
    # must not disappear merely because its row also contains the source/sink.
    reported = ([("source", trace.source)] if trace.source else [])
    reported += [("intermediate", hop) for hop in trace.intermediates]
    reported += [("sink", trace.sink)] if trace.sink else []
    for kind, hop in reported:
        issue = issue or trace_line_issue(snippet, hop.line, hop.content, kind)
    if not issue and trace.sink.line != sink:
        issue = "trace sink does not match the scanner finding line"
    if not issue and [s["line"] for s in trace.steps()] != sorted(
            s["line"] for s in trace.steps()):
        issue = "trace hops are not in source order"
    if not issue and any(snippet.enclosing(step["line"]) != snippet.enclosing(anchor)
                         for step in trace.steps()):
        issue = "trace hops do not belong to the same enclosing function"
    if issue:
        _limit(limits, "trace confirmation", "trace could not be confirmed: " + issue)
    else:
        chain = " -> ".join(f"{s['content']} (L{s['line']})" for s in trace.steps())
        items.append(EvidenceItem(evidence_id="E2", kind="dataflow", text=f"dataflow {chain}",
                                  payload={"steps": trace.steps()}))
    _limit(limits, "sanitizer recognition", f"sanitizer recognition not available for {language}")
    _limit(limits, "constraint solving", f"constraint solving not available for {language}")
    if language in {"c", "cpp"}:
        _limit(limits, "memory-safety classes",
               f"memory-safety classes (buffer overflow, format string, integer overflow) "
               f"are not analysed for {language}")
    excerpt = snippet.excerpt(anchor)
    return StaticResult(language, "grammar", True, None, findings, trace.steps(), items,
                        limits, excerpt, _block(items, limits, excerpt), sink, None, None)

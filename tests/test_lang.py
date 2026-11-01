"""Language contract, grammar grounding and Python parity; no analysed code runs."""

import json
from contextlib import nullcontext
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

import pytest

import pulseguard.lang as lang
from pulseguard.contracts.models import EvidenceItem
from pulseguard.evidence import REFERENCE_MAX_BYTES, REFERENCE_MAX_LINES, REFERENCES_HEADER
from pulseguard.lang import StaticResult, analyze_static, detect_language, tier_for
from pulseguard.lang.detect import GRAMMAR_LANGUAGES, LANGUAGES
from pulseguard.lang.language_support import get_parser
from pulseguard.lang.trace_check import source_text, sources, trace_line_issue
from pulseguard.lang.treesitter_generic import parse
from pulseguard.scanners.semgrep import DataflowTrace, SemgrepResult, TraceLine

FIXTURES = Path(__file__).parent / "fixtures" / "lang"
GRAMMAR_FIXTURES = sorted(p for p in FIXTURES.glob("*/*")
                          if p.parent.name in GRAMMAR_LANGUAGES)


@pytest.fixture(autouse=True)
def no_scanner_processes(monkeypatch):
    monkeypatch.setattr(lang, "_scan", lambda code, language, limits: [])


def parsed(code, language):
    if get_parser(language) is None:
        pytest.skip(f"optional {language} grammar missing (install .[languages])")
    snippet, error = parse(code, language)
    assert error is None
    return snippet


@pytest.mark.parametrize("hint", sorted(LANGUAGES))
def test_supported_hint_wins(hint):
    assert detect_language("def foo(): pass", hint) == hint


@pytest.mark.parametrize(("code", "expected"), [
    ("def order():\n    pass", "python"),
    ("class Orders { public void order() {} }", "java"),
    ("function order(req, db) { return req.query.id; }", "javascript"),
    ("function order(id: string) { return id; }", "typescript"),
    ("package main\nfunc main() {}", "go"),
    ("using System; class Orders {}", "csharp"),
    ("SELECT * FROM orders;", "sql"),
    ("IDENTIFICATION DIVISION. PROGRAM-ID. ORDERS.", "cobol"),
    ("proc sql; select * from orders; quit;", "sas"),
    ("DECLARE id NUMBER; BEGIN id := 1; END;", "plsql"),
    ("CREATE OR REPLACE PROCEDURE order_data AS BEGIN NULL; END;", "plsql"),
    ("", "unknown"),
    ("nondescript text", "unknown"),
])
def test_detection_markers(code, expected):
    assert detect_language(code) == expected
    assert detect_language(code, "unsupported-hint") == expected


@pytest.mark.parametrize("language", sorted(LANGUAGES))
@pytest.mark.parametrize("ok", [True, False])
def test_tiers(language, ok):
    expected = ("full" if language == "python" else
                "grammar" if language in GRAMMAR_LANGUAGES else "llm_only") if ok else "llm_only"
    assert tier_for(language, ok) == expected


def test_exact_dataclass_contract():
    assert [f.name for f in fields(StaticResult)] == [
        "language", "tier", "parse_ok", "parse_error", "findings", "trace", "evidence",
        "analysis_limits", "excerpt", "evidence_block", "sink_line", "z3", "dominance",
    ]


@pytest.mark.parametrize("path", GRAMMAR_FIXTURES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_fixture_detection_parsing_limits_and_annotations(path):
    language = path.parent.name
    code = path.read_text(encoding="utf-8")
    parsed(code, language)
    assert detect_language(code) == language
    result = analyze_static(code, language)
    assert result.tier == "grammar"
    assert result.parse_ok and result.parse_error is None
    assert result.z3 is result.dominance is None
    assert "@vuln" not in result.excerpt and "@safe" not in result.excerpt
    assert result.excerpt in result.evidence_block
    assert all(isinstance(item, EvidenceItem) for item in result.evidence)
    assert {e.evidence_id for e in result.evidence} <= {"E1"}
    assert not result.findings and result.sink_line is None
    assert any(limit["reason"] == f"sanitizer recognition not available for {language}"
               for limit in result.analysis_limits)
    assert any(limit["reason"] == f"constraint solving not available for {language}"
               for limit in result.analysis_limits)
    assert all(limit["status"] == "not_covered" for limit in result.analysis_limits)
    assert [limit["id"] for limit in result.analysis_limits] == [
        f"L{i + 1}" for i in range(len(result.analysis_limits))]


@pytest.mark.parametrize(("language", "code"), [
    ("java", "class {"), ("javascript", "function ("), ("typescript", "interface {"),
    ("go", "package\nfunc {"), ("csharp", "class {"), ("sql", "SELECT ( ;"),
    ("python", "def ("),
])
def test_parse_errors_are_advisory(monkeypatch, language, code):
    if language != "python" and get_parser(language) is None:
        pytest.skip(f"optional {language} grammar missing (install .[languages])")
    monkeypatch.setattr(lang, "_scan", lambda *a: pytest.fail("scanner ran on invalid input"))
    result = analyze_static(code, language)
    assert result.tier == "llm_only" and not result.parse_ok
    assert "parse error" in result.parse_error
    assert result.evidence == result.findings == result.trace == []
    assert len(result.analysis_limits) == 1
    assert "advisory only" in result.analysis_limits[0]["reason"]


@pytest.mark.parametrize("language", ["cobol", "sas", "plsql", "unknown"])
def test_unsupported_has_no_hard_evidence(language):
    path = next(iter((FIXTURES / language).glob("*")), None)
    code = path.read_text() if path else "BEGIN NULL; END; -- @safe label"
    result = analyze_static(code, language)
    assert result.tier == "llm_only"
    assert result.evidence == result.findings == result.trace == []
    assert result.sink_line is result.z3 is result.dominance is None
    assert len(result.analysis_limits) == 1
    assert "@safe" not in result.excerpt


def test_missing_grammar_degrades(monkeypatch):
    import pulseguard.lang.treesitter_generic as generic

    monkeypatch.setattr(generic, "get_parser", lambda language: None)
    result = analyze_static("function order() {}", "javascript")
    assert result.tier == "llm_only"
    assert result.parse_error == "Tree-sitter grammar not available for javascript"
    assert not result.evidence and len(result.analysis_limits) == 1


SOURCE_CASES = [
    ("java", 'class C { void f(HttpServletRequest req) {\nString x = req.%s;\n}}', source)
    for source in ['getParameter("x")', 'getHeader("x")', 'getCookies()']
] + [
    (language, 'function f(req) {\nconst x = %s;\n}', f"req.{name}.x")
    for language in ("javascript", "typescript")
    for name in ("query", "params", "body", "headers")
] + [
    ("go", 'package p\nfunc f(r *http.Request) {\nx := %s\n}', source)
    for source in ['r.URL.Query().Get("x")', 'r.FormValue("x")', 'mux.Vars(r)["x"]']
] + [
    ("csharp", 'class C { void F() {\nvar x = %s;\n}}', f'Request.{name}["x"]')
    for name in ("Query", "Form")
]


@pytest.mark.parametrize(("language", "template", "expression"), SOURCE_CASES)
def test_source_tables(language, template, expression):
    code = template % expression
    snippet = parsed(code, language)
    node = sources(snippet)[0]
    line = node.start_point.row + 1
    content = code.splitlines()[line - 1].strip()
    assert source_text(snippet, line, content)
    assert trace_line_issue(snippet, line, content, "source") is None
    assert source_text(snippet, line + 1, content) is None
    assert source_text(snippet, line, "other_variable") is None


@pytest.mark.parametrize(("language", "code"), [
    ("java", 'class C { void f(@RequestParam("id") String id) {} }'),
    ("java", 'class C { void f(@RequestParam String id) {} }'),
    ("csharp", 'class C { void F([FromQuery] string id) {} }'),
])
def test_annotated_source_parameters(language, code):
    snippet = parsed(code, language)
    assert len(sources(snippet)) == 1
    assert source_text(snippet, 1, code)
    # The local rules focus on the parameter identifier, as real Semgrep does.
    assert source_text(snippet, 1, "id")
    assert trace_line_issue(snippet, 1, "id", "source") is None
    assert source_text(snippet, 1, "invented_variable") is None


@pytest.mark.parametrize(("language", "code"), [
    ("java", 'class C { void f(Other req) { String x = req.getParameter("id"); } }'),
    ("javascript", 'function f(req) { const x = "req.query.id"; /* req.body.x */ }'),
    ("typescript", 'function f(req) { const x = "req.params.id"; // req.headers.x\n}'),
    ("go", 'package p\nfunc f() { x := "r.FormValue(1)" /* mux.Vars(r) */ }'),
    ("csharp", 'class C { void F() { var x = "Request.Query"; /* Request.Form */ } }'),
    ("javascript", 'function f(req) { req.query.id = "fixed"; }'),
    ("typescript", 'function f(req) { type X = typeof req.query; }'),
    ("csharp", 'class C { void F() { Request.Form["id"] = "fixed"; } }'),
])
def test_comments_strings_and_wrong_receiver_are_not_sources(language, code):
    assert sources(parsed(code, language)) == []


def scanner_hit(code, language):
    snippet = parsed(code, language)
    source = sources(snippet)[0].start_point.row + 1
    lines = code.splitlines()
    sink = next(i for i, line in enumerate(lines, 1)
                if any(x in line for x in ("executeQuery(query)", "db.query(query)",
                                           "db.Query(query)", "new SqlCommand(query")))
    intermediate = next(i for i, line in enumerate(lines, 1)
                        if 'query = ' in line or 'query := ' in line)
    def at(n):
        return TraceLine(n, lines[n - 1].strip())

    trace = DataflowTrace(at(source), [at(intermediate)], at(sink))
    return SemgrepResult("test-sqli", "snippet", sink, sink, "SQL injection", "ERROR",
                         lines[sink - 1].strip(), trace)


@pytest.mark.parametrize("language", ["java", "javascript", "typescript", "go", "csharp"])
@pytest.mark.parametrize("defect", [None, "source_line", "hop_variable", "hop_line", "string",
                                  "sink_line", "no_trace", "out_of_range", "order", "same_line"])
def test_scanner_trace_confirmation(monkeypatch, language, defect):
    path = next((FIXTURES / language).glob("vulnerable_concat.*"))
    code = path.read_text()
    hit = scanner_hit(code, language)
    if defect == "source_line":
        hit.trace.source = TraceLine(1, hit.trace.source.content)
    elif defect == "hop_variable":
        hit.trace.intermediates = [TraceLine(hit.trace.intermediates[0].line, "invented_variable")]
    elif defect == "hop_line":
        hit.trace.intermediates = [TraceLine(1, hit.trace.intermediates[0].content)]
    elif defect == "string":
        # A quoted variable name is not an identifier reference.
        hit.trace.intermediates = [TraceLine(hit.trace.intermediates[0].line, '"query"')]
    elif defect == "sink_line":
        hit.line += 1
    elif defect == "no_trace":
        hit.trace = None
    elif defect == "out_of_range":
        hit.trace.sink = TraceLine(999, "query")
    elif defect == "order":
        hit.trace.intermediates = [TraceLine(hit.trace.sink.line + 1, "query")]
    elif defect == "same_line":
        hit.trace.intermediates = [TraceLine(hit.trace.source.line, "invented_variable")]
    monkeypatch.setattr(lang, "_scan", lambda *a: [hit])
    result = analyze_static(code, language)
    evidence = {e.evidence_id for e in result.evidence}
    if defect is None:
        assert evidence == {"E1", "E2"}
        assert not any(limit["check"] == "trace confirmation" for limit in result.analysis_limits)
    else:
        assert "E2" not in evidence
        assert any(limit["check"] == "trace confirmation" for limit in result.analysis_limits)
    assert "E3" not in evidence and "E6" not in evidence
    assert result.sink_line == hit.line
    assert result.findings[0]["scanner"] == "semgrep"


def test_no_finding_anchors_first_source_function():
    code = ('function unrelated() { return 1; }\n'
            'function first(req) {\nconst x = req.query.id;\nreturn x;\n}\n'
            'function second(req) { return req.body.x; }\n')
    parsed(code, "javascript")
    result = analyze_static(code, "javascript")
    assert result.excerpt.startswith("2: function first")
    assert "unrelated" not in result.excerpt and "function second" not in result.excerpt
    assert {e.evidence_id for e in result.evidence} == {"E1"}


@pytest.mark.parametrize(("language", "code", "line", "references"), [
    ("javascript", 'const PREFIX = "SELECT ";\nfunction helper(x) { return tail(x); }\n'
     'function tail(x) { return x; }\nfunction f(req) {\n'
     'return helper(PREFIX + req.query.id);\n}', 5, ["PREFIX", "helper"]),
    ("java", 'class C {\nstatic final String PREFIX = "SELECT ";\n'
     'enum Kind { A, B }\nString helper(String x) { return x; }\n'
     'void f(HttpServletRequest req) {\nString q = helper(PREFIX + req.getParameter("id"));\n'
     'Kind k = Kind.A;\n}\n}', 6, ["PREFIX", "helper", "Kind"]),
    ("go", 'package p\nconst PREFIX = "SELECT "\nfunc helper(x string) string { return x }\n'
     'func f(r *http.Request) {\nx := helper(PREFIX + r.FormValue("id"))\n}',
     5, ["PREFIX", "helper"]),
    ("csharp", 'class C {\nconst string PREFIX = "SELECT ";\nenum Kind { A, B }\n'
     'string Helper(string x) { return x; }\nvoid F() {\n'
     'var x = Helper(PREFIX + Request.Query["id"]);\nKind k = Kind.A;\n}\n}',
     6, ["PREFIX", "Helper", "Kind"]),
])
def test_numbered_one_hop_references(language, code, line, references):
    snippet = parsed(code, language)
    excerpt = snippet.excerpt(line)
    primary, section = excerpt.split(REFERENCES_HEADER)
    assert f"{line}: " in primary
    for reference in references:
        assert reference in section
    assert "function tail" not in section
    for row in excerpt.splitlines():
        if row and row[0].isdigit():
            n, content = row.split(": ", 1)
            assert content == code.splitlines()[int(n) - 1]


@pytest.mark.parametrize("large", [False, True])
def test_reference_caps_and_unicode(large):
    names = [f"KEY_{i}" for i in range(100)]
    value = "α" * 1000 if large else "value"
    code = "\n".join(f'const {name} = "{value}";' for name in names)
    code += '\nfunction f(req) {\nreturn req.query.x + ' + " + ".join(names) + ';\n}'
    section = parsed(code, "javascript").excerpt(102).split(REFERENCES_HEADER)[1]
    section = REFERENCES_HEADER + section
    assert len(section.splitlines()) <= REFERENCE_MAX_LINES
    assert len(section.encode()) <= REFERENCE_MAX_BYTES
    assert "truncated" in section


def test_annotation_stripping_preserves_rows_and_strings():
    code = ('function f(req) {\n// @vuln label\n'
            'const x = req.query.id; /* @safe label */\nreturn "@safe literal" + x;\n}')
    snippet = parsed(code, "javascript")
    assert len(snippet.stripped().splitlines()) == len(code.splitlines())
    assert "@vuln" not in snippet.stripped()
    assert "@safe label" not in snippet.stripped()
    assert '"@safe literal"' in snippet.stripped()
    assert snippet.excerpt(3).startswith("1: function f")


def test_template_interpolation_is_code_but_literal_mentions_are_not():
    code = ('function f(req, db) {\nconst id = req.query.id;\n'
            'return db.query(`SELECT ${id} ${req.body.value}`);\n}')
    snippet = parsed(code, "javascript")
    assert source_text(snippet, 3, code.splitlines()[2]) == "req.body"
    assert trace_line_issue(snippet, 3, "id", "intermediate") is None
    assert trace_line_issue(snippet, 3, "SELECT", "intermediate") is not None


def test_nested_function_and_shadowed_reference_context():
    code = ('const KEY = "global";\nfunction outer(req) {\n'
            'const KEY = "local";\nreturn req.query.id + KEY;\n'
            'function inner(req) {\nreturn req.body.x;\n}\n}')
    snippet = parsed(code, "javascript")
    assert REFERENCES_HEADER not in snippet.excerpt(4)
    assert snippet.excerpt(6).startswith("5: function inner")


def test_missing_wheel_is_cached_and_parsers_are_not_shared(monkeypatch):
    import pulseguard.lang.language_support as support

    if support.get_parser("java") is None:
        pytest.skip("optional java grammar missing (install .[languages])")
    support.get_language.cache_clear()
    original = support.import_module
    calls = []

    def load(name):
        calls.append(name)
        if name == "tree_sitter_java":
            raise ImportError("missing optional wheel")
        return original(name)

    monkeypatch.setattr(support, "import_module", load)
    assert support.get_parser("java") is None
    assert support.get_parser("java") is None
    assert calls == ["tree_sitter_java"]
    support.get_language.cache_clear()
    monkeypatch.setattr(support, "import_module", original)
    assert support.get_parser("java") is not support.get_parser("java")


def test_sql_explicitly_has_no_scan_rule(monkeypatch):
    parsed("SELECT * FROM orders;", "sql")
    # Undo only the default no-process fixture for this ruleless language.
    monkeypatch.undo()
    from pulseguard.lang import _scan

    limits = []
    assert _scan("SELECT * FROM orders;", "sql", limits) == []
    assert limits[0]["reason"] == "no Semgrep SQL injection rule for sql"
    result = analyze_static("SELECT * FROM orders;", "sql")
    assert not result.evidence
    assert any(limit["check"] == "SQL injection scan" for limit in result.analysis_limits)


def test_python_matches_frozen_demo_evidence(monkeypatch):
    import pulseguard.playground as playground

    code = (Path(__file__).parents[1] / "demo_target/order_api/routes.py").read_text()
    expected = json.loads((FIXTURES / "python/order_golden.json").read_text(encoding="utf-8"))

    def scan(root):
        trace = DataflowTrace()
        for step in expected["trace"]:
            value = TraceLine(step["line"], step["content"])
            if step["kind"] == "source":
                trace.source = value
            elif step["kind"] == "sink":
                trace.sink = value
            else:
                trace.intermediates.append(value)
        return [SemgrepResult("flask-sqli-taint", str(root / "snippet.py"),
                              trace.sink.line, trace.sink.line, "SQL injection", "ERROR",
                              trace.sink.content, trace)]

    monkeypatch.setattr(playground, "_semgrep_runner", lambda hooks: SimpleNamespace(run=scan))
    monkeypatch.setattr(playground, "_bandit_runner",
                        lambda hooks: SimpleNamespace(run=lambda r: []))
    # Isolate filesystem I/O in this golden unit comparison; neither scanner
    # reads a file. Real filesystem/scanner coverage is in the marked suite.
    monkeypatch.setattr(lang, "tempfile", SimpleNamespace(
        TemporaryDirectory=lambda **kw: nullcontext("static-unit-test")))
    writes = []
    monkeypatch.setattr(Path, "write_text", lambda self, value, **kw: writes.append(value))
    result = analyze_static(code, "python")
    assert writes == [playground.strip_ground_truth(code)]
    assert result.tier == "full" and result.parse_ok
    assert set(result.findings[0]) == {"scanner", "rule_id", "line", "message", "severity"}
    for key, value in expected.items():
        actual = getattr(result, key)
        if key == "evidence":
            actual = [e.model_dump(mode="json") for e in actual]
        assert actual == value, key

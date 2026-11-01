"""C/C++ grammar grounding and bounded source context; snippets never execute."""

from pathlib import Path

import pytest

import pulseguard.lang as lang
from pulseguard.evidence import REFERENCE_MAX_BYTES, REFERENCE_MAX_LINES, REFERENCES_HEADER
from pulseguard.lang import analyze_static, detect_language, tier_for
from pulseguard.lang.language_support import get_parser
from pulseguard.lang.trace_check import source_text, sources, trace_line_issue
from pulseguard.lang.treesitter_generic import parse
from pulseguard.scanners.semgrep import DataflowTrace, SemgrepResult, TraceLine

FIXTURES = Path(__file__).parent / "fixtures/lang"


def parsed(code, language):
    if get_parser(language) is None:
        pytest.skip(f"optional {language} grammar missing (install .[languages])")
    snippet, error = parse(code, language)
    assert error is None
    return snippet


@pytest.mark.parametrize(("code", "hint", "expected"), [
    ("int main(void) { return 0; }", None, "c"),
    ('#include <stdio.h>\nvoid f(void) {}', None, "c"),
    ('typedef struct Order { int id; } Order;', None, "c"),
    ('#include "orders.h"', None, "c"),
    ('int f() { puts("std::string"); /* template<class T> */ }', None, "c"),
    ('std::string order;', None, "cpp"),
    ('class Order {};', None, "cpp"),
    ('template <typename T> T order(T x) { return x; }', None, "cpp"),
    ('namespace orders { int id; }', None, "cpp"),
    ('#include <string>\nint order();', None, "cpp"),
    ('void f() {}', "order.c", "c"),
    ('void f() {}', "order.h", "c"),
    ('std::string id;', "order.h", "cpp"),
    ('class Order {};', "order.h", "cpp"),
    ('void f() {}', "order.cpp", "cpp"),
    ('void f() {}', "order.hpp", "cpp"),
    ('void f() {}', ".c", "c"),
    ('void f() {}', ".h", "c"),
    ('void f() {}', ".cpp", "cpp"),
    ('std::string id;', "c", "c"),
    ('int main(void) { return 0; }', "cpp", "cpp"),
])
def test_detection(code, hint, expected):
    assert detect_language(code, hint) == expected


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_tier_parse_error_and_missing_grammar(monkeypatch, language):
    import pulseguard.lang.treesitter_generic as generic

    assert tier_for(language, True) == "grammar"
    assert tier_for(language, False) == "llm_only"
    parsed("int main(void) { return 0; }", language)
    invalid = analyze_static("int main( {", language)
    assert invalid.tier == "llm_only" and not invalid.parse_ok
    assert not invalid.evidence and len(invalid.analysis_limits) == 1
    monkeypatch.setattr(generic, "get_parser", lambda _: None)
    missing = analyze_static("int main(void) {}", language)
    assert missing.tier == "llm_only"
    assert missing.parse_error == f"Tree-sitter grammar not available for {language}"
    assert not missing.evidence and len(missing.analysis_limits) == 1


C_SOURCES = [
    ('const char *input = argv[1];', "argv"),
    ('const char *input = getenv("QUERY_STRING");', 'getenv("QUERY_STRING")'),
    ('const char *input = getenv("OWNER");', 'getenv("OWNER")'),
    ('recv(fd, input, 127, 0);', "input"),
    ('recvfrom(fd, input, 127, 0, 0, 0);', "input"),
    ('read(fd, input, 127);', "input"),
    ('fgets(input, 128, stdin);', "input"),
]
CPP_SOURCES = [
    ('std::cin >> input;', "input"),
    ('std::cin >> first >> input;', "input"),
    ('std::getline(std::cin, input);', "input"),
    ("std::getline(std::cin, input, ',');", "input"),
    ('std::getenv("QUERY_STRING");', 'std::getenv("QUERY_STRING")'),
    ('std::fgets(input, 128, stdin);', "input"),
]


@pytest.mark.parametrize(("language", "statement", "focus"), [
    (language, statement, focus) for language in ("c", "cpp") for statement, focus in C_SOURCES
] + [("cpp", statement, focus) for statement, focus in CPP_SOURCES])
def test_exact_line_sources_and_focused_buffers(language, statement, focus):
    code = 'int main(int argc, char **argv) {\n' + statement + '\nreturn 0;\n}'
    snippet = parsed(code, language)
    assert sources(snippet)
    assert source_text(snippet, 2, statement)
    assert source_text(snippet, 2, focus)
    assert trace_line_issue(snippet, 2, focus, "source") is None
    assert source_text(snippet, 3, focus) is None
    assert source_text(snippet, 2, "invented_buffer") is None


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("statement", [
    'puts("getenv(QUERY_STRING)");',
    '/* recv(fd, input, 127, 0); */',
    'fgets(input, 128, file);',
    'argv[1] = "fixed";',
    'char *argv = "fixed";',
    '#define INPUT getenv("QUERY_STRING")',
    'recv(fd, 0, 127, 0);',
])
def test_non_sources(language, statement):
    code = 'int main(int argc, char **argv) {\n' + statement + '\nreturn 0;\n}'
    assert not sources(parsed(code, language))


def test_cpp_streams_must_be_standard_input():
    code = ('void order() {\nstd::getline(file, input);\n'
            'stream >> input;\nstd::cout << input;\nstd::cin >> 1;\n}')
    assert not sources(parsed(code, "cpp"))


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_io_return_value_is_not_the_source_buffer(language):
    code = 'int order() {\nint count = recv(fd, input, 127, 0);\nreturn count;\n}'
    snippet = parsed(code, language)
    assert source_text(snippet, 2, "input")
    assert source_text(snippet, 2, "count") is None
    assert trace_line_issue(snippet, 2, "count", "source") is not None


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("defect", [None, "source_line", "source_variable", "intermediate",
                                  "sink_line", "no_trace", "duplicate_bad_hop"])
def test_trace_confirmation_and_explicit_limits(monkeypatch, language, defect):
    path = FIXTURES / language / ("vulnerable_mysql.c" if language == "c"
                                else "vulnerable_mysql.cpp")
    code = path.read_text()
    snippet = parsed(code, language)
    lines = code.splitlines()
    source = sources(snippet)[0].start_point.row + 1
    sink = next(i for i, row in enumerate(lines, 1) if "return mysql_query" in row)
    middle = next(i for i, row in enumerate(lines, 1)
                  if "sprintf(query" in row or "std::string query =" in row)
    trace = DataflowTrace(TraceLine(source, lines[source - 1]),
                          [TraceLine(middle, lines[middle - 1])], TraceLine(sink, lines[sink - 1]))
    hit = SemgrepResult("c-family-sqli", "snippet", sink, sink, "SQL injection", "ERROR",
                        lines[sink - 1], trace)
    if defect == "source_line":
        trace.source = TraceLine(source + 1, trace.source.content)
    elif defect == "source_variable":
        trace.source = TraceLine(source, "invented_source")
    elif defect == "intermediate":
        trace.intermediates = [TraceLine(middle, "invented_variable")]
    elif defect == "sink_line":
        hit.line += 1
    elif defect == "no_trace":
        hit.trace = None
    elif defect == "duplicate_bad_hop":
        trace.intermediates.append(TraceLine(source, "invented_variable"))
    monkeypatch.setattr(lang, "_scan", lambda *args: [hit])
    result = analyze_static(code, language)
    assert result.tier == "grammar"
    assert {item.evidence_id for item in result.evidence} == (
        {"E1", "E2"} if defect is None else
        set() if defect in {"source_line", "source_variable", "no_trace"} else {"E1"})
    assert result.z3 is result.dominance is None
    reasons = [limit["reason"] for limit in result.analysis_limits]
    assert f"sanitizer recognition not available for {language}" in reasons
    assert f"constraint solving not available for {language}" in reasons
    assert all(limit["status"] == "not_covered" for limit in result.analysis_limits)


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_one_hop_macro_array_and_static_function_context(language):
    code = ('#define PREFIX "SELECT " // @safe label\n'
            'static const char *IDS[] = {"1", "2"};\n'
            'static const char *tail(const char *x) { return x; }\n'
            'static const char *helper(const char *x) { return tail(x); }\n'
            'static void unused(void) {}\n'
            'int main(int argc, char **argv) {\n'
            'const char *input = argv[1]; // @vuln label\n'
            'mysql_query(db, helper(PREFIX));\nmysql_query(db, IDS[0]);\n}\n')
    snippet = parsed(code, language)
    excerpt = snippet.excerpt(8)
    primary, context = excerpt.split(REFERENCES_HEADER)
    assert primary.startswith("6: int main")
    assert '1: #define PREFIX "SELECT "' in context
    assert '2: static const char *IDS[]' in context
    assert '4: static const char *helper' in context
    assert "static const char *tail" not in context
    assert "static void unused" not in context
    assert "@vuln" not in excerpt and "@safe" not in excerpt


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("large", [False, True])
def test_reference_caps_line_numbers_and_unicode(language, large):
    value = "α" * 1000 if large else "value"
    code = "\n".join(f'#define KEY_{i} "{value}"' for i in range(100))
    code += '\nint order(void) {\nconsume(' + ", ".join(f"KEY_{i}" for i in range(100)) + ');\n}'
    snippet = parsed(code, language)
    excerpt = snippet.excerpt(102)
    context = REFERENCES_HEADER + excerpt.split(REFERENCES_HEADER)[1]
    assert len(context.splitlines()) <= REFERENCE_MAX_LINES
    assert len(context.encode()) <= REFERENCE_MAX_BYTES
    assert "truncated" in context
    for row in context.splitlines():
        if row and row[0].isdigit():
            number, content = row.split(": ", 1)
            assert content == code.splitlines()[int(number) - 1]


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_local_constant_shadows_module_context(language):
    code = ('static const char *PREFIX = "global";\nint order(void) {\n'
            'const char *PREFIX = "local";\nconsume(PREFIX);\n}')
    assert REFERENCES_HEADER not in parsed(code, language).excerpt(4)


def test_cpp_method_context_and_macro_literal_annotations():
    code = ('#define LITERAL "@safe is data" // @vuln annotation\n'
            'class Orders {\nstatic const char *IDS[2] = {"1", "2"};\n'
            'static const char *helper(const char *id) { return id; }\n'
            'public: int order() {\nstd::string input;\nstd::cin >> input;\n'
            'consume(Orders::helper(IDS[0]), LITERAL);\nreturn 0;\n}\n};\n')
    snippet = parsed(code, "cpp")
    excerpt = snippet.excerpt(8)
    primary, context = excerpt.split(REFERENCES_HEADER)
    assert primary.startswith("5: public: int order")
    assert "static const char *IDS" in context
    assert "static const char *helper" in context
    assert '"@safe is data"' in context
    assert "@vuln annotation" not in context

"""Hard evidence must describe the actual source line and sink-reaching value."""

import ast

import pytest

from eval.ablation import _clean_trace
from pulseguard.contracts.models import Finding
from pulseguard.evidence import build_hard_evidence
from pulseguard.falsify.z3_check import check_validators
from pulseguard.paths import REPO_ROOT
from pulseguard.scanners.bandit import BanditResult, _sql_context
from pulseguard.scanners.normalize import normalize, normalize_bandit
from pulseguard.scanners.semgrep import DataflowTrace, SemgrepResult, TraceLine
from pulseguard.verify import check_cited_location


def evidence(code, *, trace=None, scanner="bandit"):
    lines = code.splitlines()
    sink = next(i for i, line in reversed(list(enumerate(lines, 1))) if "conn.execute" in line)
    source = next(i for i, line in enumerate(lines, 1) if "request.args.get" in line)
    trace = trace or DataflowTrace(TraceLine(source, lines[source - 1]), [],
                                   TraceLine(sink, lines[sink - 1]))
    finding = Finding(case_id="defects", fingerprint="ab" * 16, file="case.py",
                      line=sink, rule_id="B608", scanner=scanner)
    limits = []
    items = build_hard_evidence(finding, trace, code=code, analysis_limits=limits)
    return {item.evidence_id: item for item in items}, limits


@pytest.mark.parametrize("cast", ["int", "float", "Decimal"])
@pytest.mark.parametrize("direct", [True, False])
@pytest.mark.parametrize("hole", ["value", "str(value)"])
def test_numeric_cast_result_reaches_sink(cast, direct, hole):
    source = 'request.args.get("qty", "0")'
    assignment = (f'    value = {cast}({source})\n' if direct else
                  f'    raw = {source}\n    value = {cast}(raw)\n')
    module = 'from decimal import Decimal\n' if cast == 'Decimal' else ''
    code = (module + 'def route():\n' + assignment
            + f'    query = f"SELECT id FROM orders WHERE qty = {{{hole}}}"\n'
              '    return conn.execute(query)\n')
    items, _ = evidence(code)
    hit = next(h for h in items["E3"].payload["matched"] if h["rule"] == f"{cast}-cast")
    assert hit["variable"] == "value"
    assert f"{cast}() cast @ L{hit['line']}" in items["E3"].text
    assert "result value reaches SQL sink" in items["E3"].text
    assert "syntax match" not in items["E3"].text


@pytest.mark.parametrize("exit_body", [
    "return None", "raise ValueError()",
    "if enabled:\n            return None\n        else:\n            raise ValueError()",
])
@pytest.mark.parametrize("cast", ["int", "float", "Decimal"])
def test_cast_in_try_with_every_exception_path_exiting(cast, exit_body):
    module = 'from decimal import Decimal\n' if cast == 'Decimal' else ''
    code = (module + 'def route():\n    raw = request.args.get("id")\n'
            f'    try:\n        value = {cast}(raw)\n'
            f'    except (TypeError, ValueError):\n        {exit_body}\n'
            '    query = "SELECT id FROM orders WHERE id = " + str(value)\n'
            '    return conn.execute(query)\n')
    assert f"{cast}-cast" in evidence(code)[0]["E3"].text


@pytest.mark.parametrize("body,hole", [
    ('    int(raw)\n', 'raw'),
    ('    discarded = int(raw)\n', 'raw'),
    ('    value = raw\n    if enabled:\n        value = int(raw)\n', 'value'),
    ('    value = raw\n    try:\n        value = int(raw)\n'
     '    except ValueError:\n        pass\n', 'value'),
    ('    try:\n        value = int(raw)\n'
     '    except ValueError:\n        value = raw\n', 'value'),
    ('    value = int(raw)\n', 'raw'),
    ('    value = int(raw)\n    value = raw\n', 'value'),
    ('    value = int(raw); value = raw\n', 'value'),
    ('    query = f"SELECT id FROM orders WHERE id = {raw}"\n'
     '    raw = int(raw)\n', None),
    ('    try:\n        value = int(raw)\n    except ValueError:\n'
     '        if enabled:\n            return None\n', 'value'),
    ('    try:\n        value = int(raw)\n    except ValueError:\n        return None\n'
     '    finally:\n        value = raw\n', 'value'),
    ('    int = parse\n    value = int(raw)\n', 'value'),
    ('    value = float(raw)\n    mutate(value)\n', 'value'),
    ('    value = int(raw)\n    str = render\n', 'str(value)'),
])
def test_unproven_or_unused_cast_is_not_a_sanitizer(body, hole):
    query = (f'    query = f"SELECT id FROM orders WHERE id = {{{hole}}}"\n'
             if hole else '')
    code = ('def route():\n    raw = request.args.get("id")\n' + body + query
            + '    return conn.execute(query)\n')
    # Include all lines: an unrelated cast must not become a regex-only E3 hit either.
    lines = code.splitlines()
    trace = DataflowTrace(TraceLine(2, lines[1]),
                         [TraceLine(i, line) for i, line in enumerate(lines, 1)
                          if 2 < i < len(lines)], TraceLine(len(lines), lines[-1]))
    items, _ = evidence(code, trace=trace)
    assert not items["E3"].payload["matched"]


@pytest.mark.parametrize("pattern,answer", [(r"^[0-9]{1,8}$", "unsat"),
                                             (r"^[0-9\s]{1,8}$", "unsat"),
                                             (r"^[0-9A-Z= ]{1,8}$", "sat")])
def test_numeric_question_excludes_digits_and_whitespace(pattern, answer):
    code = ('import re\ndef route():\n    value = request.args.get("id")\n'
            f'    if not re.match(r"{pattern}", value):\n        return None\n'
            '    return conn.execute(f"SELECT id FROM orders WHERE id = {value}")\n')
    result = check_validators(code, source_line=3, sink_line=6)
    assert result.result == answer
    assert result.question == "admits a character other than digits and whitespace (numeric sink)?"
    if answer == "sat":
        assert result.witness == "1 OR 1=1"
    else:
        assert result.witness is None


@pytest.mark.parametrize("scanner", ["bandit", "semgrep"])
@pytest.mark.parametrize("bad_part", ["source-header", "source-mismatch", "intermediate-mismatch",
                                       "intermediate-header", "sink-mismatch"])
def test_unconfirmed_trace_claims_are_omitted(scanner, bad_part):
    code = ('def route():\n    raw = request.args.get("id")\n    try:\n'
            '        value = int(raw)\n    except ValueError:\n        return None\n'
            '    query = f"SELECT id FROM orders WHERE id = {value}"\n'
            '    return conn.execute(query)\n')
    lines = code.splitlines()
    source, middle, sink = TraceLine(2, lines[1]), TraceLine(7, lines[6]), TraceLine(8, lines[7])
    if bad_part == "source-header":
        source = TraceLine(3, "try:")
    elif bad_part == "source-mismatch":
        source = TraceLine(3, lines[1])
    elif bad_part == "intermediate-mismatch":
        middle = TraceLine(4, "query")
    elif bad_part == "intermediate-header":
        middle = TraceLine(3, "try:")
    else:
        sink = TraceLine(7, "conn.execute(query)")
    items, limits = evidence(code, trace=DataflowTrace(source, [middle], sink), scanner=scanner)
    assert "E2" not in items
    assert ("E1" not in items) == bad_part.startswith("source")
    assert any("trace could not be confirmed" in limit["reason"] for limit in limits)


@pytest.mark.parametrize("source", [
    'request.args.get("id")', 'request.form["id"]', 'request.json.get("id")',
    'request.get_json().get("id")', 'request.headers.get("X-Id")',
    'request.cookies.get("id")', 'request.view_args.get("id")',
])
def test_bandit_finds_source_assignment_inside_try(source):
    code = ('def route():\n    unused = request.args.get("ignored")\n    try:\n'
            f'        raw = {source}\n        value = int(raw)\n'
            '    except ValueError:\n        return None\n'
            '    query = f"SELECT id FROM orders WHERE id = {value}"\n'
            '    return conn.execute(query)\n')
    trace = _sql_context(code, 8)
    assert trace.source == TraceLine(4, f"raw = {source}")
    assert all(step["content"] != "try:" for step in trace.steps())


def test_bandit_multiline_assignment_locates_the_actual_source_call():
    code = ('def route():\n    try:\n        raw = (\n'
            '            request.args.get("id")\n        )\n'
            '    except ValueError:\n        return None\n'
            '    query = f"SELECT id FROM orders WHERE id = {raw}"\n'
            '    return conn.execute(query)\n')
    trace = _sql_context(code, 8)
    assert trace.source == TraceLine(4, 'request.args.get("id")')
    items, _ = evidence(code, trace=trace)
    assert items["E1"].payload["line"] == 4
    assert 'source request.args.get("id") @ case.py:4' in items["E1"].text


@pytest.mark.parametrize("eid,kind,content,line", [
    ("E1", "rule_source", 'request.args.get("number")', "try:"),
    ("E1", "rule_source", 'try:', "try:"),
    ("E2", "dataflow", 'number_query', "raw_number ="),
    ("E2", "dataflow", 'try:', "try:"),
    ("E2", "dataflow", 'request.args.get("number") trailing invented text', "raw_number ="),
])
def test_verifier_rejects_unconfirmed_trace_at_exact_line(eid, kind, content, line):
    file = "demo_target/order_api/routes.py"
    lines = (REPO_ROOT / file).read_text(encoding="utf-8").splitlines()
    line = next(i for i, text in enumerate(lines, 1) if line in text)
    payload = ({"source": content, "file": file, "line": line} if eid == "E1" else
               {"steps": [{"kind": "intermediate", "content": content, "line": line}]})
    check = check_cited_location(
        {"file": file, "line": line}, [eid],
        [{"evidence_id": eid, "kind": kind, "payload": payload}], REPO_ROOT)
    assert not check["ok"]


@pytest.mark.parametrize("name", ["float_used", "dollar_final_newline", "order_by_number"])
@pytest.mark.parametrize("scanner", ["bandit", "semgrep"])
def test_real_evidence_defect_cases(name, scanner):
    rel = ("demo_target/order_api/routes.py" if name == "order_by_number" else
           "demo_target/eval_cases/hard/safes.py")
    code = (REPO_ROOT / rel).read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(code)) if isinstance(n, ast.FunctionDef)
              and n.name == name)
    query = next(n for n in ast.walk(fn) if isinstance(n, ast.Assign)
                 and any(isinstance(c, ast.Constant) and isinstance(c.value, str)
                         and "SELECT" in c.value for c in ast.walk(n.value)))
    trace = _sql_context(code, query.lineno)
    if scanner == "bandit":
        finding = normalize_bandit(BanditResult("B608", rel, query.lineno, "SQL", "MEDIUM",
                                                "LOW", "", trace))
    else:
        finding = normalize(SemgrepResult("flask-sqli-taint", rel, trace.sink.line,
                                          trace.sink.line, "SQL", "ERROR", "", trace))
    items = {i.evidence_id: i for i in build_hard_evidence(finding, trace, code=code)}
    source = next(n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
                  and ast.unparse(n.func.value) == "request.args")
    assert items["E1"].payload["line"] == source
    expr = next(n for n in ast.walk(fn) if isinstance(n, ast.Call) and n.lineno == source
                and isinstance(n.func, ast.Attribute) and n.func.attr == "get")
    assert items["E1"].text == (f"rule {finding.rule_id} · source "
                                f"{ast.get_source_segment(code, expr)} @ {rel}:{source}")
    assert "try:" not in items["E1"].text + items["E2"].text
    source_name = "raw_number" if name == "order_by_number" else "value"
    query_name = "number_query" if name == "order_by_number" else "query"
    middle = " -> order_number (L45)" if name == "order_by_number" else ""
    assert items["E2"].text == (f"dataflow {source_name} (L{source}){middle} -> "
                                f"{query_name} (L{query.lineno}) -> "
                                f"conn.execute({query_name}) (L{trace.sink.line})")
    if name == "dollar_final_newline":
        assert items["E6"].text == (
            "validator model: ^[0-9]{1,8}$ admits a character other than digits and whitespace "
            "(numeric sink)? unsat")
    else:
        cast = "int" if name == "order_by_number" else "float"
        assert f"{cast}-cast" in items["E3"].text
        assert "reaches SQL sink" in items["E3"].text
    assert check_cited_location(finding.to_payload(), ["E1", "E2"],
                                 [i.model_dump() for i in items.values()], REPO_ROOT)["ok"]


def test_missing_code_omits_trace_claims_and_records_limit():
    trace = DataflowTrace(TraceLine(2, 'raw = request.args.get("id")'), [],
                          TraceLine(3, 'conn.execute(raw)'))
    finding = Finding(case_id="missing", fingerprint="ab" * 16, file="missing.py",
                      line=3, rule_id="B608")
    limits = []
    items = build_hard_evidence(finding, trace, analysis_limits=limits)
    assert not {"E1", "E2"} & {i.evidence_id for i in items}
    assert "source code unavailable" in limits[0]["reason"]


def test_semgrep_variable_snippets_match_real_line_tokens():
    code = ('def route():\n    raw = request.args.get("id")\n'
            '    query = f"SELECT id FROM orders WHERE id = {raw}"\n'
            '    return conn.execute(query)\n')
    trace = DataflowTrace(TraceLine(2, 'request.args.get("id")'), [TraceLine(3, 'query')],
                          TraceLine(4, 'query'))
    items, _ = evidence(code, trace=trace, scanner="semgrep")
    assert {"E1", "E2"} <= items.keys()


@pytest.mark.parametrize("line", ['    text = \'request.args.get("id")\'',
                                  '    # request.args.get("id")'])
def test_source_mentions_in_string_or_comment_are_not_source_calls(line):
    code = 'def route():\n' + line + '\n    return conn.execute(query)\n'
    items, limits = evidence(code)
    assert not {"E1", "E2"} & items.keys()
    assert "trace could not be confirmed" in limits[0]["reason"]


@pytest.mark.parametrize("module", ['', 'from unknown import Decimal\n',
                                   'from decimal import Decimal\nDecimal = unknown\n'])
def test_decimal_requires_unshadowed_standard_library_import(module):
    code = (module + 'def route():\n    raw = request.args.get("id")\n'
            '    value = Decimal(raw)\n'
            '    return conn.execute(f"SELECT id FROM orders WHERE id = {value}")\n')
    assert not evidence(code)[0]["E3"].payload["matched"]


@pytest.mark.parametrize("line,content", [(3, 'raw = request.args.get("id")'),
                                         (99, 'raw = request.args.get("id")'),
                                         (2, 'other = request.args.get("other")')])
def test_ablation_preserves_bad_claims_for_evidence_guard(line, content):
    code = ('def route():\n    raw = request.args.get("id")\n'
            '    return conn.execute(raw)\n')
    trace = DataflowTrace(TraceLine(line, content + '  # @safe label'), [],
                          TraceLine(3, 'conn.execute(raw)'))
    clean = _clean_trace(trace)
    assert clean.source == TraceLine(line, content)
    items, limits = evidence(code, trace=clean, scanner="semgrep")
    assert not {"E1", "E2"} & items.keys()
    assert "trace could not be confirmed" in limits[0]["reason"]

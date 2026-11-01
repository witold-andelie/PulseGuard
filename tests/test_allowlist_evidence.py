"""Finite allow-list facts must constrain the value actually interpolated at the sink."""

import ast

import pytest

from pulseguard.contracts.models import Finding
from pulseguard.evidence import build_hard_evidence, render_block
from pulseguard.paths import REPO_ROOT
from pulseguard.scanners.semgrep import DataflowTrace, TraceLine
from pulseguard.verify import check_cited_evidence


def evidence(code):
    lines = code.splitlines()
    sink = next(i for i, line in reversed(list(enumerate(lines, 1))) if 'conn.execute' in line)
    fn = min((n for n in ast.walk(ast.parse(code)) if isinstance(n, ast.FunctionDef)
              and n.lineno <= sink <= n.end_lineno), key=lambda n: n.end_lineno - n.lineno)
    source = next(i for i, line in enumerate(lines, 1)
                  if fn.lineno <= i <= fn.end_lineno and 'request.args' in line)
    trace = DataflowTrace(TraceLine(source, lines[source - 1]), [],
                         TraceLine(sink, lines[sink - 1]))
    finding = Finding(case_id="allowlist", fingerprint="ab" * 16, file="cases.py",
                      line=sink, rule_id="flask-sqli-taint")
    limits = []
    items = build_hard_evidence(finding, trace, code=code, analysis_limits=limits)
    return next(item for item in items if item.evidence_id == "E3"), items, limits


def program(body, *, module="", sink='    return conn.execute(query)\n'):
    return (module + 'def route():\n    x = request.args.get("column")\n' + body
            + '    query = "SELECT id FROM orders ORDER BY " + x\n' + sink)


@pytest.mark.parametrize("container", ['{"id", "item", "qty"}',
                                       '("id", "item", "qty")',
                                       '["id", "item", "qty"]', 'ALLOWED'])
@pytest.mark.parametrize("exit_statement", ['return None', 'raise ValueError()', 'abort(400)'])
def test_exit_membership_guards(container, exit_statement):
    code = program(f'    if x not in {container}:\n        {exit_statement}\n',
                   module='from flask import abort\nALLOWED = {"id", "item", "qty"}\n')
    e3, _, _ = evidence(code)
    assert "allow-list membership guard @ L" in e3.text
    hit = next(hit for hit in e3.payload["matched"] if "members" in hit)
    assert hit["members"] == ["id", "item", "qty"]
    assert ast.parse(code).body[-1].body[1].lineno == hit["line"]


@pytest.mark.parametrize("body", [
    '    allowed_columns = {"id", "item", "qty"}\n'
    '    if x not in allowed_columns:\n        return None\n',
    '    x = x if x in {"id", "item", "qty"} else "id"\n',
    '    columns = {"a": "id", "b": "item", "c": "qty"}\n    x = columns[x]\n',
    '    x = {"a": "id", "b": "item", "c": "qty"}.get(x)\n',
    '    x = {"a": "id", "b": "item", "c": "qty"}.get(x, "id")\n',
])
def test_local_constant_mapping_and_conditional(body):
    e3, _, _ = evidence(program(body))
    members = [None, "id", "item", "qty"] if '.get(x)\n' in body else ["id", "item", "qty"]
    assert any(hit.get("members") == members for hit in e3.payload["matched"])


def test_positive_membership_wraps_sink():
    code = ('ALLOWED = {"id", "item", "qty"}\ndef route():\n'
            '    x = request.args.get("column")\n    if x in ALLOWED:\n'
            '        query = f"SELECT {x} FROM orders"\n'
            '        return conn.execute(query)\n    return None\n')
    assert "allow-list membership guard" in evidence(code)[0].text


@pytest.mark.parametrize("body", [
    '    columns = {"a": "id", "b": "item"}\n    col = columns[x]\n',
    '    col = COLUMNS.get(x, "id")\n',
])
def test_mapping_to_distinct_sink_variable(body):
    code = program(body, module='COLUMNS = {"a": "id", "b": "item"}\n')
    code = code.replace('ORDER BY " + x', 'ORDER BY " + col')
    e3, _, _ = evidence(code)
    assert e3.payload["matched"][0]["variable"] == "col"


def test_imported_flask_abort_and_function_constant():
    code = program('    allowed = ["id", "qty"]\n'
                   '    if x not in allowed:\n        flask.abort(400)\n',
                   module='import flask\n')
    assert 'allow-list membership guard' in evidence(code)[0].text


@pytest.mark.parametrize("body", [
    '    other = request.args.get("other")\n'
    '    if other not in {"id"}:\n        return None\n',
    '    if enabled:\n        if x not in {"id"}:\n            return None\n',
    '    allowed = get_allowed()\n    if x not in allowed:\n        return None\n',
    '    if x not in {"id"}:\n        return None\n    x = request.args.get("new")\n',
    '    if x not in {"id"}:\n        return None\n    x += request.args.get("suffix")\n',
    '    if x not in {"id", "1\' OR \'1\'=\'1"}:\n        return None\n',
    '    allowed = {"id"}\n    allowed.add(request.args.get("new"))\n'
    '    if x not in allowed:\n        return None\n',
    '    allowed = {"id"}\n    alias = allowed\n    alias.add(x)\n'
    '    if x not in allowed:\n        return None\n',
    '    if x not in {"id"}:\n        log_error()\n',
    '    if x not in {"id"} and enabled:\n        return None\n',
    '    if x in {"id"}:\n        pass\n',
    '    if x not in {"id"}:\n        abort(400)\n',  # unbound abort
    '    allowed = {"id", dynamic}\n    if x not in allowed:\n        return None\n',
    '    x = x if x in {"id"} else request.args.get("fallback")\n',
    '    x = {"a": "id"}.get(x, x)\n',
    '    x = {"a": "1 OR 1=1"}.get(x)\n',
    '    try:\n        x = {"a": "id"}[x]\n    except KeyError:\n        pass\n',
    '    query = "SELECT " + x\n    if x not in {"id"}:\n        return None\n',
    '    if x not in {"id"}:\n        return None\n    mutate(x)\n',
    '    allowed = {"id"}\n    allowed = {"id", x}\n'
    '    if x not in allowed:\n        return None\n',
    '    if x not in ALLOWED:\n        return None\n',  # imported/unbound constant
    '    columns = {"a": "id"}\n    columns[x] = x\n    x = columns[x]\n',
    '    columns = {"a": dynamic}\n    x = columns.get(x)\n',
    '    x = {**dynamic}.get(x)\n',
    '    x = x if x in {"id", "1\' OR \'1\'=\'1"} else "id"\n',
    '    if x in {"id"}:\n        x = request.args.get("new")\n',
    '    x = {"a": "id"}.get(x); x = request.args.get("new")\n',
    '    x = x if x in {"id"} else "id"; x = request.args.get("new")\n',
])
def test_unproven_guards_are_not_sanitizers(body):
    e3, _, limits = evidence(program(body))
    assert not any("members" in hit for hit in e3.payload["matched"])
    assert e3.text == "sanitizer rules on path: none recognised"
    assert limits[0]["status"] == "not_covered"


def test_guard_after_sink_and_value_captured_before_guard_rejected():
    for code in [program('', sink='    conn.execute(query)\n'
                                 '    if x not in {"id"}:\n        return None\n'),
                 'def route():\n    x = request.args.get("column")\n'
                 '    query = "SELECT " + x\n    if x not in {"id"}:\n'
                 '        return None\n    return conn.execute(query)\n']:
        assert not any("members" in hit for hit in evidence(code)[0].payload["matched"])


def test_original_column_choice_regression():
    code = (REPO_ROOT / 'demo_target/eval_cases/constraints.py').read_text(encoding='utf-8')
    # Use the real function while keeping its module imports and declarations.
    tree = ast.parse(code)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'column_choice')
    code = '\n'.join(code.splitlines()[:fn.end_lineno])
    e3, _, _ = evidence(code)
    assert "allow-list membership guard @ L" in e3.text
    assert "{id,item,qty}" in e3.text


def test_tuple_guard_with_literal_format_query():
    code = program('    if x not in ("ASC", "DESC"):\n        return None\n')
    code = code.replace('"SELECT id FROM orders ORDER BY " + x',
                        '"SELECT id FROM orders ORDER BY id {}".format(x)')
    assert '{ASC,DESC}' in evidence(code)[0].text


def test_no_match_is_coverage_limit_and_limits_remain_uncitable():
    e3, items, limits = evidence(program(''))
    assert e3.text == 'sanitizer rules on path: none recognised'
    assert limits[0]['checked'] == e3.payload['checked']
    assert 'unrecognised guards may exist' in limits[0]['reason']
    block = render_block(items, analysis_limits=limits)
    assert '[L1]' in block and 'not_covered' in block
    assert not check_cited_evidence(['L1'], [item.model_dump() for item in items])['ok']
    assert '[L1] sanitizer recognition' in render_block(items)

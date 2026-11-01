"""One-hop sanitizer facts must describe the value actually captured by SQL."""

import ast

import pytest

from pulseguard.contracts.models import Finding
from pulseguard.evidence import build_hard_evidence
from pulseguard.falsify.allowlist import allowlist_facts
from pulseguard.paths import REPO_ROOT
from pulseguard.scanners.semgrep import DataflowTrace, TraceLine
from tests.test_allowlist_evidence import evidence, program

ENUM = ('from enum import Enum\nclass Column(Enum):\n'
        '    ID = "id"\n    ITEM = "item"\n    QTY = "qty"\n')


@pytest.mark.parametrize("expression", ['Column(x)', 'Column(x).value', 'Column[x]',
                                         'Column[x].value'])
def test_enum_construction_and_name_lookup(expression):
    e3, _, _ = evidence(program(f'    x = {expression}\n', module=ENUM))
    hit = e3.payload['matched'][0]
    assert hit['members'] == ['id', 'item', 'qty']
    assert hit['variable'] == 'x' and hit['line'] == 8
    assert 'Enum Column members {id,item,qty}' in e3.text
    assert 'called @ L8' in e3.text


@pytest.mark.parametrize("module", [
    ENUM.replace('from enum import Enum', 'from enum import Enum as Base')
        .replace('Column(Enum)', 'Column(Base)'),
    ENUM.replace('from enum import Enum', 'import enum')
        .replace('Column(Enum)', 'Column(enum.Enum)'),
    ENUM.replace('Column(Enum)', 'Column(str, Enum)'),
])
def test_enum_import_aliases_and_plain_str_mixin(module):
    assert evidence(program('    x = Column(x).value\n', module=module))[0].payload['matched']


@pytest.mark.parametrize("module", [
    ENUM + '    @classmethod\n    def _missing_(cls, value):\n        return value\n',
    ENUM.replace('Column(Enum)', 'Column(str, Enum)')
        + '    @classmethod\n    def _missing_(cls, value):\n'
          '        return str.__new__(cls, value)\n',
    ENUM + '    def __str__(self):\n        return request.args.get("raw")\n',
    ENUM.replace('"qty"', 'dynamic'),
    ENUM.replace('"qty"', '"id LIMIT 1"'),
    ENUM + 'Column = imported\n',
    ENUM + 'alias = Column\n',
    ENUM + 'Column.ID._value_ = "id LIMIT 1"\n',
    ENUM.replace('from enum import Enum', 'from elsewhere import Enum'),
    ENUM + 'Enum = imported\n',
    ENUM + 'Enum.__new__ = imported\n',
    ENUM + 'alias = Enum\n',
    ENUM.replace('from enum import Enum', 'import enum')
        .replace('Column(Enum)', 'Column(enum.Enum)') + 'enum.Enum = imported\n',
    ENUM + 'from elsewhere import *\n',
    ENUM.replace('class Column', '@decorate\nclass Column'),
    ENUM.replace('Column(Enum)', 'Column(Custom, Enum)'),
    ENUM.replace('Column(Enum)', 'Column(Enum, metaclass=Custom)'),
])
def test_enum_unknown_overrides_mutation_and_shadowing_rejected(module):
    assert not evidence(program('    x = Column(x).value\n', module=module))[0].payload['matched']


@pytest.mark.parametrize("kind", ['enum', 'helper'])
@pytest.mark.parametrize("body", [
    '    checked = TRANSFORM(x)\n',
    '    x = TRANSFORM(x)\n    x = request.args.get("raw")\n',
    '    x = TRANSFORM(x); x = request.args.get("raw")\n',
    '    if enabled:\n        x = TRANSFORM(x)\n',
    '    try:\n        x = TRANSFORM(x)\n    except ValueError:\n        pass\n',
    '    query = "SELECT " + x\n    x = TRANSFORM(x)\n',
    '    x = TRANSFORM(x)\n    mutate(x)\n',
])
def test_result_must_dominate_same_sink_value(kind, body):
    module = ENUM if kind == 'enum' else 'def parse_number(value):\n    return int(value)\n'
    transform = 'Column' if kind == 'enum' else 'parse_number'
    code = program(body.replace('TRANSFORM', transform), module=module)
    if '    query = "SELECT " + x\n' in body:
        code = code.replace('    query = "SELECT id FROM orders ORDER BY " + x\n', '')
    assert not evidence(code)[0].payload['matched']


@pytest.mark.parametrize("cast", ['int', 'float'])
def test_helper_cast_records_return_and_call_lines(cast):
    code = program('    x = parse_number(x)\n',
                   module=f'def parse_number(value):\n    return {cast}(value)\n')
    e3, _, _ = evidence(code)
    hit = e3.payload['matched'][0]
    assert hit['line'] == 5 and hit['helper'] == 'parse_number'
    assert hit['return_lines'] == [2] and hit['casts'] == [cast]
    assert f'{cast}() cast in helper parse_number @ L2, called @ L5' in e3.text
    assert 'syntax match' not in e3.text


@pytest.mark.parametrize('kind', ['enum', 'helper'])
def test_multiline_assignment_records_actual_call_line(kind):
    module = ENUM if kind == 'enum' else 'def parse_number(value):\n    return int(value)\n'
    transform = 'Column' if kind == 'enum' else 'parse_number'
    code = program(f'    x = (\n        {transform}(x)\n    )\n', module=module)
    call_line = next(i for i, line in enumerate(code.splitlines(), 1)
                     if f'{transform}(x)' in line)
    hit = evidence(code)[0].payload['matched'][0]
    assert hit['line'] == call_line
    assert f'called @ L{call_line}' in hit['evidence']


@pytest.mark.parametrize("helper", [
    'def choose(value):\n    return {"a": "id", "b": "qty"}[value]\n',
    'COLUMNS = {"a": "id", "b": "qty"}\ndef choose(value):\n    return COLUMNS[value]\n',
    'def choose(value):\n    columns = {"a": "id", "b": "qty"}\n    return columns[value]\n',
    'def choose(value):\n    allowed = {"id", "qty"}\n'
    '    if value not in allowed:\n        raise ValueError()\n    return value\n',
    'ALLOWED = ("id", "qty")\ndef choose(value):\n'
    '    if value in ALLOWED:\n        return value\n    raise ValueError()\n',
    'def choose(value):\n    if value in {"id", "qty"}:\n        return value\n'
    '    else:\n        raise ValueError()\n',
    'from flask import abort\ndef choose(value):\n'
    '    if value not in {"id", "qty"}:\n        abort(400)\n    return value\n',
])
def test_helper_finite_lookup_or_raising_membership(helper):
    e3, _, _ = evidence(program('    x = choose(x)\n', module=helper))
    hit = e3.payload['matched'][0]
    assert hit['members'] == ['id', 'qty'] and hit['helper'] == 'choose'
    assert 'allow-list in helper choose' in e3.text


@pytest.mark.parametrize("helper", [
    '    if value:\n        return int(value)\n    return float(value)\n',
    '    if value:\n        return int(value)\n    raise ValueError()\n',
    '    if value in {"id"}:\n        return value\n    return int(value)\n',
])
def test_every_return_is_sanitized(helper):
    e3, _, _ = evidence(program('    x = choose(x)\n', module='def choose(value):\n' + helper))
    assert len(e3.payload['matched']) == 1


@pytest.mark.parametrize("helper", [
    '    return value\n',
    '    return value.strip()\n',
    '    if value:\n        return int(value)\n    return value\n',
    '    if value:\n        return int(value)\n',
    '    return int(other)\n',
    '    return delegate(value)\n',
    '    try:\n        return int(value)\n    except ValueError:\n        return value\n',
    '    if value not in {"id"}:\n        pass\n    return value\n',
    '    if value not in {"id"}:\n        abort(400)\n    return value\n',  # unbound abort
    '    if value not in {"id"}:\n        return value\n    return value\n',
    '    if value not in {"id"}:\n        raise ValueError()\n'
    '    value = request.args.get("raw")\n    return value\n',
    '    if value not in {"id"}:\n        raise ValueError()\n'
    '    if value in (value := request.args.get("raw")):\n        return value\n'
    '    return value\n',
    '    if value not in {"id"}:\n        raise ValueError()\n'
    '    if value in mutate(value):\n        return value\n    return value\n',
    '    return {"a": value}[value]\n',
    '    return {"a": "id"}.get(value, value)\n',
    '    yield int(value)\n',
])
def test_misleading_partial_and_two_hop_helpers_rejected(helper):
    e3, _, _ = evidence(program('    x = sanitize_id(x)\n',
                               module='def sanitize_id(value):\n' + helper))
    assert not e3.payload['matched']
    assert 'none recognised' in e3.text


@pytest.mark.parametrize("module", [
    '@decorate\ndef choose(value):\n    return int(value)\n',
    'async def choose(value):\n    return int(value)\n',
    'def choose(value):\n    return int(value)\nint = identity\n',
    'def choose(value):\n    return int(value)\nchoose = identity\n',
    'def choose(value, int=identity):\n    return int(value)\n',
    'def choose(value):\n    return int(value)\nalias = choose\n',
    'def choose(value):\n    return int(value)\nfrom elsewhere import *\n',
    'COLUMNS = {"a": "id"}\ndef choose(value):\n    return COLUMNS[value]\n'
    'def poison():\n    COLUMNS.update({"b": "id LIMIT 1"})\n',
])
def test_helpers_must_be_unshadowed_undecorated_and_constants_unchanged(module):
    assert not evidence(program('    x = choose(x)\n', module=module))[0].payload['matched']


def test_existing_hard_safe_and_misleading_cases():
    for file, name, expected in [('safes.py', 'enum_column', 'Enum Column'),
                                  ('flows.py', 'helper_cast', 'int() cast in helper'),
                                  ('flows.py', 'misleading_helper', 'none recognised')]:
        code = (REPO_ROOT / 'demo_target/eval_cases/hard' / file).read_text(encoding='utf-8')
        fn = next(n for n in ast.parse(code).body if isinstance(n, ast.FunctionDef)
                  and n.name == name)
        sink = fn.end_lineno
        facts = allowlist_facts(code, sink)
        assert bool(facts) == (expected != 'none recognised')
        lines = code.splitlines()
        source = fn.lineno + 1
        finding = Finding(case_id='hard-context', fingerprint='ab' * 16, file=file,
                          line=sink, rule_id='flask-sqli-taint')
        trace = DataflowTrace(TraceLine(source, lines[source - 1]), [],
                              TraceLine(sink, lines[sink - 1]))
        items = build_hard_evidence(finding, trace, code=code)
        assert expected in next(item.text for item in items if item.evidence_id == 'E3')

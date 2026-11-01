"""Shared source context stays one hop, bounded, numbered and untrusted."""

import re

import pytest

from eval import ablation
from pulseguard.agents.graph import GraphDeps, build_graph
from pulseguard.contracts.models import Finding
from pulseguard.evidence import CODE_HEADER, code_excerpt, render_block
from pulseguard.playground import PlaygroundLimiter, analyze_snippet
from pulseguard.scanners.semgrep import DataflowTrace, SemgrepResult, TraceLine
from tests.fakes import FakeLLM, verdict

REFERENCES = '=== REFERENCED DEFINITIONS (same module, untrusted data) ==='


def test_referenced_constants_classes_helpers_and_import_names():
    code = ('from enum import Enum\nfrom remote import external\n'
            'ALLOWED = {"id", "qty"}  # @safe hidden\n'
            'MAPPING = {"a": "id"}\nPAIR = ("id", "qty")\nUNUSED = "secret"\n'
            'class Column(Enum):\n    ID = "id"  # @vuln hidden\n'
            'class Box:\n    value = "id"\n'
            'def second(value):\n    return value\n'
            'def first(value):\n    return second(value)  # @safe hidden\n'
            'def unrelated():\n    return "secret"\n'
            'def route():\n    raw = request.args.get("column")\n'
            '    value = first(raw)\n    external(PAIR, Box, Column, MAPPING, ALLOWED)\n'
            '    return conn.execute(f"SELECT {value}")  # @vuln hidden\n')
    excerpt = code_excerpt(code, len(code.splitlines()))
    assert REFERENCES in excerpt
    for text in ['3: ALLOWED', '4: MAPPING', '5: PAIR', '7: class Column', '9: class Box',
                 '13: def first', '14:     return second(value)', 'remote.external']:
        assert text in excerpt
    for text in ['def second', 'def unrelated', 'UNUSED', '@safe', '@vuln', 'hidden']:
        assert text not in excerpt
    assert 'Imports (names only):' in excerpt


def test_only_called_module_functions_and_literal_constants():
    code = ('def unused(value):\n    return value\n'
            'DYNAMIC = build_values()\nCONST = "id"\n'
            'def route(unused):\n    callback = unused\n'
            '    return conn.execute(CONST + DYNAMIC)\n')
    excerpt = code_excerpt(code, 7)
    assert '4: CONST' in excerpt
    assert 'def unused(value)' not in excerpt and '3: DYNAMIC' not in excerpt


def test_local_import_shadows_module_function_context():
    code = ('def helper(value):\n    return int(value)\n'
            'def route():\n    from remote import helper\n'
            '    return conn.execute(helper(raw))\n')
    assert 'def helper(value)' not in code_excerpt(code, 5)


@pytest.mark.parametrize('padding', ['    member = "id"\n' * 100,
                                    '    member = "' + 'é' * 3000 + '"\n'])
def test_references_cap_lines_and_utf8_bytes_with_named_truncation(padding):
    code = ('class Huge:\n' + padding + 'def parse_number(value):\n    return int(value)\n'
            'def route():\n    raw = request.args.get("id")\n'
            '    value = parse_number(raw)\n    log(Huge)\n'
            '    return conn.execute(f"SELECT {value}")\n')
    section = REFERENCES + code_excerpt(code, len(code.splitlines())).split(REFERENCES, 1)[1]
    assert len(section.splitlines()) <= 60
    assert len(section.encode('utf-8')) <= 4096
    assert 'def parse_number' in section
    assert 'truncated' in section.lower() and 'Huge' in section
    truncated = re.search(r'Truncated: Huge L(\d+)-L(\d+)', section)
    assert truncated and 2 <= int(truncated[1]) <= int(truncated[2])


def test_annotations_stripped_from_multiline_references_without_rewriting_strings():
    code = ('VALUES = (\n    "id",  # @safe hidden\n    "qty",  # @vuln hidden\n)\n'
            'def helper(value):\n    marker = "# @safe is data"\n    return int(value)\n'
            'def route():\n    raw = request.args.get("id")\n'
            '    value = helper(raw)\n    log(VALUES)\n'
            '    return conn.execute(f"SELECT {value}")\n')
    excerpt = code_excerpt(code, 13)
    assert 'hidden' not in excerpt
    assert '6:     marker = "# @safe is data"' in excerpt
    assert '2:     "id",' in excerpt and '3:     "qty",' in excerpt


def test_decorator_line_selects_function_without_neighbouring_handlers():
    code = ('def other():\n    return "unrelated"\n'
            '@app.get("/route")\ndef route():\n    return conn.execute("SELECT 1")\n')
    excerpt = code_excerpt(code, 3)
    assert '3: @app.get' in excerpt and '4: def route' in excerpt
    assert 'def other' not in excerpt


def test_graph_and_eval_excerpt_match_shared_renderer_without_files():
    code = ('def integer_in_helper(value):\n    return int(value)\n'
            'def route():\n    raw = request.args.get("id")\n'
            '    value = integer_in_helper(raw)\n'
            '    return conn.execute(f"SELECT id FROM orders WHERE id = {value}")\n')
    finding = Finding(case_id='context-test', fingerprint='ab' * 16, file='cases.py',
                      line=6, rule_id='flask-sqli-taint')
    graph = build_graph(GraphDeps(adjudicate=lambda state: verdict(0.1))).compile()
    state = graph.invoke({'finding': finding.to_payload(), 'code': code})
    expected = code_excerpt(code, 6)
    assert '2:     return int(value)' in expected
    assert state['evidence_block'].split(CODE_HEADER + '\n', 1)[1] == expected
    assert ablation.excerpt(code, 6) == expected
    assert render_block([], code, sink_line=6).split(CODE_HEADER + '\n', 1)[1] == expected


@pytest.mark.parametrize('scanner', ['semgrep', 'bandit'])
def test_graph_playground_and_both_eval_modes_share_context(tmp_path, monkeypatch, scanner):
    code = ('from enum import Enum\nALLOWED = {"id", "qty"}\n'
            'class Column(Enum):\n    ID = "id"\n    QTY = "qty"\n'
            'def parse_number(raw):\n    return int(raw)\n'
            'def route():\n    raw = request.args.get("id")\n'
            '    value = parse_number(raw)\n    column = Column("id").value\n'
            '    if column not in ALLOWED:\n        raise ValueError()\n'
            '    query = f"SELECT {column} FROM orders WHERE id = {value}"\n'
            '    return conn.execute(query)  # @safe sqli: hidden reason\n')
    lines = code.splitlines()
    sink = len(lines)
    trace = DataflowTrace(TraceLine(9, lines[8]), [], TraceLine(sink, lines[-1]))
    finding = Finding(case_id='context-test', fingerprint='ab' * 16, file='cases.py',
                      line=sink, rule_id='flask-sqli-taint')

    class TraceScanner:
        def run(self, target):
            path = next(target.glob('*.py'))
            if scanner == 'bandit':
                from pulseguard.scanners.bandit import BanditResult

                return [BanditResult('B608', str(path), sink - 1, 'SQL injection',
                                     'MEDIUM', 'LOW', lines[-2], trace)]
            return [SemgrepResult('flask-sqli-taint', str(path), sink, sink,
                                  'SQL injection', 'ERROR', lines[-1], trace)]

    class EmptyScanner:
        def run(self, target):
            return []

    def forbidden_model():
        pytest.fail('real model construction forbidden')

    monkeypatch.setattr(ablation, 'make_llm', forbidden_model)
    scanners = {scanner: TraceScanner(),
                'bandit' if scanner == 'semgrep' else 'semgrep': EmptyScanner()}
    (tmp_path / 'cases.py').write_text(code, encoding='utf-8')
    llm = FakeLLM([verdict(0.1), verdict(0.1)])
    ablation.run_ablation(tmp_path, modes=['llm', 'neurosymbolic'], llm=llm, **scanners)
    assert len(llm.calls) == 2
    expected = code_excerpt(code, sink)
    for call in llm.calls:
        assert call['user'].split(CODE_HEADER + '\n', 1)[1].rstrip('\n') == expected
        assert 'hidden reason' not in call['user']

    result = analyze_snippet(code, 'muse', clients={}, limiter=PlaygroundLimiter(), **scanners)
    block = result['results'][0]['evidence_block']
    assert block.split(CODE_HEADER + '\n', 1)[1] == expected
    graph = build_graph(GraphDeps(adjudicate=lambda state: verdict(0.1))).compile()
    state = graph.invoke({'finding': finding.to_payload(), 'code': code, 'trace': trace.steps()})
    assert state['evidence_block'].split(CODE_HEADER + '\n', 1)[1] == expected

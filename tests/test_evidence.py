"""Prompt hygiene for SymbAI-Taint evidence and evaluation annotations."""

from pulseguard.evidence import build_hard_evidence, code_excerpt, render_block
from pulseguard.paths import REPO_ROOT
from pulseguard.scanners.normalize import normalize
from tests.fakes import FakeScanner


def test_sink_function_excerpt_has_real_lines_without_ground_truth():
    code = (REPO_ROOT / "demo_target" / "order_api" / "routes.py").read_text(encoding="utf-8")
    lines = code.splitlines()
    sink = next(i for i, line in enumerate(lines, 1) if "rows = conn.execute(q)" in line)
    excerpt = code_excerpt(code, sink)
    assert 'def order():' in excerpt
    assert f'{sink}:     rows = conn.execute(q).fetchall()' in excerpt
    assert 'request.args.get("id")' in excerpt
    assert "@vuln" not in excerpt
    assert "DELIBERATELY VULNERABLE" not in excerpt
    assert "def get_db" not in excerpt and 'app.run' not in excerpt
    assert "# @vuln sqli" in code


def test_safe_annotation_is_stripped_from_excerpt():
    code = ("def order_by_number():\n"
            "    number = int(request.args.get('n'))  # @safe int-cast\n"
            "    sink(number)\n")
    excerpt = code_excerpt(code, 3)
    assert "# @safe" not in excerpt
    assert "int(request.args.get('n'))" in excerpt


def test_comment_annotations_only_and_innermost_async_function():
    code = ('"""Module ground truth"""\n'
            'def outer():\n'
            '    async def inner():\n'
            '        marker = "# @vuln is literal data"\n'
            '        sink(marker)  # @vuln label\n'
            '    return inner\n')
    excerpt = code_excerpt(code, 5)
    assert '3:     async def inner():' in excerpt
    assert '4:         marker = "# @vuln is literal data"' in excerpt
    assert '5:         sink(marker)' in excerpt
    assert "label" not in excerpt and "Module ground truth" not in excerpt
    assert "def outer" not in excerpt


def test_window_fallback_preserves_line_numbers_and_hides_module_docstring():
    code = '"""DELIBERATELY VULNERABLE\nground truth\n"""\n' + '\n'.join(
        f"value_{number} = {number}" for number in range(4, 65))
    excerpt = code_excerpt(code, 40)
    assert excerpt.splitlines()[0] == "15: value_15 = 15"
    assert excerpt.splitlines()[-1] == "64: value_64 = 64"
    assert "DELIBERATELY VULNERABLE" not in code_excerpt(code, 5)
    broken = code + '\ndef broken(\n'
    assert "40: value_40 = 40" in code_excerpt(broken, 40)
    assert "DELIBERATELY VULNERABLE" not in code_excerpt(broken, 5)


def test_parenthesized_module_docstring_excluded_from_window():
    excerpt = code_excerpt('(\n"""DELIBERATELY VULNERABLE"""\n)\nsink()\n', 4)
    assert excerpt == "4: sink()"


def test_render_block_infers_sink_from_evidence():
    target = REPO_ROOT / "demo_target" / "order_api"
    result = FakeScanner().run(target)[0]
    items = build_hard_evidence(normalize(result, root=target), result.trace)
    block = render_block(items, (target / "routes.py").read_text(encoding="utf-8"))
    assert f"{result.line}:     rows = conn.execute(q).fetchall()" in block
    assert "@vuln" not in block and "DELIBERATELY VULNERABLE" not in block

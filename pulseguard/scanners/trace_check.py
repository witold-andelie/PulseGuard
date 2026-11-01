"""Bind trace claims to Python tokens at their exact physical source lines."""

from __future__ import annotations

import ast
import io
import tokenize

_REQUEST_CONTAINERS = {"args", "form", "values", "json", "headers", "cookies", "view_args"}
_SIMPLE_STATEMENTS = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Expr, ast.Return, ast.Raise)


def _request(node: ast.AST) -> bool:
    return (isinstance(node, ast.Name) and node.id == "request") or (
        isinstance(node, ast.Attribute) and node.attr == "request"
        and isinstance(node.value, ast.Name) and node.value.id == "flask")


def source_access(node: ast.AST) -> bool:
    """Recognise request container reads and get_json(), never a mere mention."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "get_json" and _request(node.func.value):
            return True
        if node.func.attr != "get":
            return False
        base = node.func.value
    elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
        base = node.value
    else:
        return False
    return (isinstance(base, ast.Attribute) and base.attr in _REQUEST_CONTAINERS
            and _request(base.value)) or (
        isinstance(base, ast.Call) and source_access(base))


def _tokens(text: str) -> list[tuple[int, str]]:
    try:
        return [(t.type, t.string) for t in tokenize.generate_tokens(io.StringIO(text).readline)
                if t.type not in {tokenize.ENCODING, tokenize.ENDMARKER, tokenize.INDENT,
                                  tokenize.DEDENT, tokenize.NEWLINE, tokenize.NL, tokenize.COMMENT}]
    except (tokenize.TokenError, IndentationError):
        return []


def _contains(actual: list, expected: list) -> bool:
    return bool(expected) and any(actual[i:i + len(expected)] == expected
                                  for i in range(len(actual) - len(expected) + 1))


def source_text(code: str, line: int, content: str) -> str | None:
    """Return the source call present in both the trace and that exact line."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if (source_access(node) and node.lineno == line and node.end_lineno == line):
            text = ast.get_source_segment(code, node)
            if text and _contains(_tokens(content.strip()), _tokens(text)):
                return text
    return None


def trace_line_issue(code: str | None, line: int, content: str, kind: str) -> str | None:
    """Silence on doubt: neither comments, strings nor headers confirm a trace hop."""
    if code is None:
        return "source code unavailable"
    lines = code.splitlines()
    if not 1 <= line <= len(lines):
        return f"L{line} is out of range"
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "source is not valid Python"
    actual = lines[line - 1].strip()
    if not _contains(_tokens(actual), _tokens(content.strip())):
        return f"L{line} does not contain the claimed trace text"
    statements = [n for n in ast.walk(tree) if isinstance(n, ast.stmt) and n.lineno == line]
    if statements and not all(isinstance(n, _SIMPLE_STATEMENTS) for n in statements):
        return f"L{line} is a compound-statement header"
    if kind == "source":
        if source_text(code, line, content) is None:
            return f"L{line} does not contain the claimed request source call"
    else:
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and n.lineno == line}
        if not any(t == tokenize.NAME and word in names for t, word in _tokens(content.strip())):
            return f"L{line} does not contain the claimed variable"
    return None

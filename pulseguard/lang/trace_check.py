"""Bind grammar-tier trace claims to syntax at exact physical lines.

Token comparison adapted from revio (Apache-2.0),
src/revio/layers/parser/function_index.py, by the same author.
Copyright 2026 witold-andelie; licensed under the Apache License, Version 2.0.
Unlike its dedup normalizer, preserve identifier and literal spelling for claims.
Source tables and trace validation are new PulseGuard code.
"""

from __future__ import annotations

import re

from .treesitter_generic import Snippet, text, walk

_TOKEN_PATTERN = re.compile(
    r'//[^\n]*|/\*[\s\S]*?\*/|`(?:\\.|[^`\\])*`|"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'|[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|===|!==|=>|"
    r"\.\.\.|\+\+|--|\|\||&&|==|!=|<=|>=|\+=|-=|:=|\S"
)


def tokens(content: str) -> list[str]:
    return [m.group() for m in _TOKEN_PATTERN.finditer(content)
            if not m.group().startswith(("//", "/*"))]


def _contains(actual: list[str], claimed: list[str]) -> bool:
    return bool(claimed) and any(actual[i:i + len(claimed)] == claimed
                                 for i in range(len(actual) - len(claimed) + 1))


def _compact(node) -> str:
    return "".join(tokens(text(node)))


def _read(node) -> bool:
    """Do not turn an assignment target or a TS type query into a source read."""
    access = node
    while access.parent is not None and access.parent.type in {
        "member_expression", "subscript_expression", "member_access_expression",
        "element_access_expression",
    }:
        access = access.parent
    parent = access.parent
    if parent is not None and parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left is not None and left.start_byte <= node.start_byte < left.end_byte:
            return False
    while parent is not None:
        if parent.type in {"type_query", "nameof_expression"}:
            return False
        parent = parent.parent
    return True


def _buffer_target(node):
    if (node is not None and node.type in {
            "identifier", "qualified_identifier", "field_expression", "subscript_expression",
            "pointer_expression", "parenthesized_expression", "cast_expression",
    } and any(n.type == "identifier" for n in walk(node))):
        return node
    return None


def _c_source_target(snippet: Snippet, node):
    """Return the input expression/buffer, never an I/O call's return count."""
    if node.type == "identifier" and text(node) == "argv" and _read(node):
        fn = snippet.enclosing(node.start_point.row + 1)
        body = fn.child_by_field_name("body") if fn is not None else None
        if body is None or not body.start_byte <= node.start_byte < body.end_byte:
            return None
        ancestor = node.parent
        while ancestor is not None and ancestor != body:
            declarator = ancestor.child_by_field_name("declarator")
            if declarator is not None and declarator.type == "init_declarator":
                declarator = declarator.child_by_field_name("declarator")
            if (declarator is not None
                    and declarator.start_byte <= node.start_byte < declarator.end_byte):
                return None
            ancestor = ancestor.parent
        return node
    if node.type == "call_expression":
        function = _compact(node.child_by_field_name("function"))
        arguments = node.child_by_field_name("arguments")
        args = [n for n in arguments.named_children if "comment" not in n.type]
        if function in {"getenv", "std::getenv"} and len(args) == 1:
            return node
        if function in {"recv", "recvfrom", "read"} and len(args) >= 3:
            return _buffer_target(args[1])
        if (function in {"fgets", "std::fgets"} and len(args) == 3
                and _compact(args[2]) == "stdin"):
            return _buffer_target(args[0])
        if (function == "std::getline" and len(args) >= 2
                and _compact(args[0]) == "std::cin"):
            return _buffer_target(args[1])
    if snippet.language == "cpp" and node.type == "binary_expression":
        left = node.child_by_field_name("left")
        if text(node.child_by_field_name("operator")) != ">>":
            return None
        while left is not None and left.type == "binary_expression":
            if text(left.child_by_field_name("operator")) != ">>":
                return None
            left = left.child_by_field_name("left")
        if _compact(left) == "std::cin":
            return _buffer_target(node.child_by_field_name("right"))
    return None


def sources(snippet: Snippet) -> list:
    """Recognise source expressions, never comment/string mentions of a source."""
    found = []
    for node in walk(snippet.root):
        language = snippet.language
        if language in {"c", "cpp"}:
            if _c_source_target(snippet, node) is not None:
                found.append(node)
        elif language == "java":
            if node.type == "formal_parameter" and any(
                n.type in {"annotation", "marker_annotation"}
                and re.match(r"@(?:[\w.]*\.)?RequestParam\b", text(n)) for n in walk(node)
            ):
                found.append(node)
            elif node.type == "method_invocation":
                receiver = text(node.child_by_field_name("object"))
                method = text(node.child_by_field_name("name"))
                fn = snippet.enclosing(node.start_point.row + 1)
                if fn is not None and method in {"getParameter", "getHeader", "getCookies"}:
                    if any(n.type == "formal_parameter"
                           and text(n.child_by_field_name("name")) == receiver
                           and text(n.child_by_field_name("type")).split(".")[-1]
                           == "HttpServletRequest" for n in walk(fn)):
                        found.append(node)
        elif language in {"javascript", "typescript"}:
            if (node.type in {"member_expression", "subscript_expression"}
                    and re.fullmatch(r"req\.(?:query|params|body|headers)", _compact(node))
                    and _read(node)):
                found.append(node)
        elif language == "go" and node.type == "call_expression":
            compact = _compact(node)
            if re.fullmatch(r"r\.(?:URL\.Query\(\)\.Get|FormValue)\(.*\)", compact):
                found.append(node)
            elif compact == "mux.Vars(r)":
                found.append(node)
        elif language == "csharp":
            if (node.type == "member_access_expression"
                    and _compact(node) in {"Request.Query", "Request.Form"} and _read(node)):
                found.append(node)
            elif node.type == "parameter" and any(
                n.type == "attribute" and re.match(r"(?:[\w.]*\.)?FromQuery\b", text(n))
                for n in walk(node)
            ):
                found.append(node)
    return found


def source_text(snippet: Snippet, line: int, content: str) -> str | None:
    for node in sources(snippet):
        if snippet.language in {"c", "cpp"}:
            target = _c_source_target(snippet, node)
            if (target is not None and target != node
                    and node.start_point.row + 1 == line == node.end_point.row + 1
                    and _contains(tokens(content), tokens(text(target)))):
                return text(node)
        if node.type in {"formal_parameter", "parameter"}:
            name = node.child_by_field_name("name")
            if (name is not None and name.start_point.row + 1 == line
                    and _contains(tokens(content), tokens(text(name)))):
                return " ".join(text(node).split())
        if (node.start_point.row + 1 == line == node.end_point.row + 1
                and (_contains(tokens(content), tokens(text(node)))
                     or tokens(content) == tokens(snippet.code.splitlines()[line - 1]))):
            return text(node)
    return None


def trace_line_issue(snippet: Snippet, line: int, content: str, kind: str) -> str | None:
    if not 1 <= line <= len(snippet.code.splitlines()):
        return f"L{line} is out of range"
    # Compare only AST tokens outside comments. A string containing a variable's
    # spelling is a single token and cannot confirm that variable.
    leaves = []
    stack = [snippet.root]
    while stack:
        node = stack.pop()
        if "comment" in node.type:
            continue
        if node.type in {"string", "string_literal", "interpreted_string_literal",
                         "raw_string_literal", "template_string", "verbatim_string_literal"}:
            leaves.append(node)
        elif node.children:
            stack.extend(reversed(node.children))
        else:
            leaves.append(node)
    actual = [token for n in leaves if n.start_point.row + 1 == line == n.end_point.row + 1
              for token in tokens(text(n))]
    claimed = tokens(content)
    names = {text(n) for n in walk(snippet.root) if n.type == "identifier"
             and n.start_point.row + 1 == line}
    if not (_contains(actual, claimed) or len(claimed) == 1 and claimed[0] in names):
        return f"L{line} does not contain the claimed trace text"
    if kind == "source":
        if source_text(snippet, line, content) is None:
            return f"L{line} does not contain the claimed request source call"
    else:
        if not names.intersection(claimed):
            return f"L{line} does not contain the claimed variable"
        fn = snippet.enclosing(line)
        if fn is not None and fn.start_point.row + 1 == line:
            return f"L{line} is a function header"
    return None

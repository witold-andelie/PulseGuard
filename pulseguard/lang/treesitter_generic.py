"""Snippet AST context adapted from revio (Apache-2.0).

Source: src/revio/layers/parser/treesitter_generic.py, by the same author.
Copyright 2026 witold-andelie; licensed under the Apache License, Version 2.0.
Retains its node tables and innermost-function selection, replacing filesystem
caches with in-memory parsing and adding bounded, one-hop source context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pulseguard.evidence import REFERENCE_MAX_BYTES, REFERENCE_MAX_LINES, REFERENCES_HEADER

from .language_support import get_parser

FUNCTION_TYPES = {
    "javascript": {"function_declaration", "method_definition", "arrow_function",
                   "generator_function_declaration", "function_expression"},
    "typescript": {"function_declaration", "method_definition", "arrow_function",
                   "generator_function_declaration", "function_expression", "function_signature"},
    "csharp": {"method_declaration", "constructor_declaration", "local_function_statement"},
    "java": {"method_declaration", "constructor_declaration"},
    "go": {"function_declaration", "method_declaration", "func_literal"},
    "sql": {"create_function_statement", "create_function"},
    "c": {"function_definition"},
    "cpp": {"function_definition", "lambda_expression"},
}
_DEFINITIONS = {"variable_declarator", "const_spec", "enum_declaration", "type_declaration"}
_ANNOTATION = re.compile(r"@(?:vuln|safe)\b[^\r\n]*", re.I)
_C_COMMENT_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
)


def _clean_comment(comment: str) -> str:
    clean = _ANNOTATION.sub("", comment)
    if comment.endswith("*/") and not clean.endswith("*/"):
        clean += "*/"
    return clean


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def text(node) -> str:
    return node.text.decode("utf-8") if node is not None else ""


def identifiers(node) -> set[str]:
    return {text(n) for n in walk(node)
            if n.type in {"identifier", "property_identifier", "type_identifier"}}


def _declarator_name(node) -> str:
    """Unwrap C/C++ function/pointer/array declarators, following revio's extractor."""
    while node is not None:
        if node.type in {"identifier", "field_identifier", "type_identifier"}:
            return text(node)
        name = node.child_by_field_name("name")
        if name is not None:
            return text(name)
        node = node.child_by_field_name("declarator")
    return ""


def _c_references(root, fn, language):
    used = identifiers(fn)
    called = set()
    for node in walk(fn):
        if node.type in {"declaration", "parameter_declaration"}:
            for declarator in node.children_by_field_name("declarator"):
                used.discard(_declarator_name(declarator))
        if node.type == "call_expression":
            called.update(text(n) for n in walk(node.child_by_field_name("function"))
                          if n.type in {"identifier", "field_identifier"})
    candidates = []
    for node in walk(root):
        parent = node.parent
        while parent is not None and parent.type not in FUNCTION_TYPES[language]:
            parent = parent.parent
        if parent is not None or node == fn:
            continue
        if node.type == "preproc_def":
            if text(node.child_by_field_name("name")) in used:
                candidates.append(node)
        elif node.type == "function_definition":
            if (_declarator_name(node) in called and any(
                    n.type == "storage_class_specifier" and text(n) == "static"
                    for n in node.named_children)):
                candidates.append(node)
        elif node.type in {"declaration", "field_declaration"} and any(
            n.type == "type_qualifier" and text(n) in {"const", "constexpr"}
            for n in node.named_children
        ):
            if any(_declarator_name(d) in used
                   for d in node.children_by_field_name("declarator")):
                candidates.append(node)
    return candidates


@dataclass
class Snippet:
    code: str
    language: str
    root: object

    def enclosing(self, line: int):
        functions = [n for n in walk(self.root) if n.type in FUNCTION_TYPES[self.language]
                     and n.start_point.row < line <= n.end_point.row + 1]
        return min(functions, key=lambda n: n.end_byte - n.start_byte, default=None)

    def stripped(self) -> str:
        """Blank annotation text inside comment nodes, preserving physical rows."""
        source = self.code.encode("utf-8")
        for node in sorted(walk(self.root), key=lambda n: n.start_byte, reverse=True):
            if "comment" in node.type:
                clean = _clean_comment(text(node))
            elif node.type == "preproc_arg" and self.language in {"c", "cpp"}:
                # The grammar keeps a macro value opaque, including its comments.
                clean = _C_COMMENT_TOKEN.sub(
                    lambda m: _clean_comment(m.group()) if m.group().startswith(("//", "/*"))
                    else m.group(), text(node))
            else:
                continue
            source = source[:node.start_byte] + clean.encode() + source[node.end_byte:]
        return source.decode("utf-8")

    def excerpt(self, line: int) -> str:
        lines = self.stripped().splitlines()
        if not lines:
            return "..."
        fn = self.enclosing(line)
        start = fn.start_point.row + 1 if fn else max(1, line - 25)
        end = fn.end_point.row + 1 if fn else min(len(lines), line + 25)
        rows = [f"{i}: {lines[i - 1]}" for i in range(start, min(end, len(lines)) + 1)]
        if fn is None:
            return "\n".join(rows)

        used = identifiers(fn)
        bound = set()
        for n in walk(fn):
            if n.type in {"variable_declarator", "formal_parameter", "required_parameter",
                          "optional_parameter", "parameter", "parameter_declaration"}:
                name = n.child_by_field_name("name") or n.child_by_field_name("pattern")
                if name:
                    bound.update(identifiers(name))
        used -= bound
        candidates = []
        functions = FUNCTION_TYPES[self.language]
        for node in walk(self.root):
            if node.type not in functions | _DEFINITIONS:
                continue
            # Function-local definitions belong in their function, never in references.
            parent = node.parent
            local = False
            while parent is not None:
                if parent.type in functions:
                    local = True
                    break
                parent = parent.parent
            if local or node == fn:
                continue
            name = node.child_by_field_name("name")
            if name is None or text(name) not in used:
                continue
            # Include the declaration keyword/type as useful untrusted context.
            if node.type == "variable_declarator" and node.parent is not None:
                node = node.parent
            candidates.append(node)

        if self.language in {"c", "cpp"}:
            candidates = _c_references(self.root, fn, self.language)
        if candidates:
            section = [REFERENCES_HEADER]
            seen: set[int] = set()
            omitted = False
            for node in sorted(candidates, key=lambda n: n.start_byte):
                # Preprocessor definitions include their trailing newline.
                end_row, end_column = node.end_point
                last = end_row + (1 if end_column else 0)
                for i in range(node.start_point.row + 1, last + 1):
                    if i in seen or start <= i <= end:
                        continue
                    row = f"{i}: {lines[i - 1]}"
                    proposal = "\n".join([*section, row])
                    # Reserve room for an explicit truncation notice.
                    if (len(section) >= REFERENCE_MAX_LINES - 1
                            or len(proposal.encode()) > REFERENCE_MAX_BYTES - 64):
                        omitted = True
                        break
                    section.append(row)
                    seen.add(i)
            if omitted:
                section.append("... referenced definitions truncated (60 lines / 4 KB cap)")
            rows.extend(["", *section])
        return "\n".join(rows)


def parse(code: str, language: str) -> tuple[Snippet | None, str | None]:
    parser = get_parser(language)
    if parser is None:
        return None, f"Tree-sitter grammar not available for {language}"
    try:
        root = parser.parse(code.encode("utf-8")).root_node
    except (ValueError, UnicodeError) as exc:
        return None, f"Tree-sitter parse failed for {language}: {type(exc).__name__}"
    if root.has_error:
        bad = next((n for n in walk(root) if n.type == "ERROR" or n.is_missing), root)
        return None, f"Tree-sitter parse error for {language} at line {bad.start_point.row + 1}"
    return Snippet(code, language, root), None


def advisory_excerpt(code: str) -> str:
    """Unsupported text has no AST; strip labels without claiming syntax knowledge."""
    return "\n".join(f"{i}: {_ANNOTATION.sub('', line)}"
                     for i, line in enumerate(code.splitlines(), 1)) or "..."

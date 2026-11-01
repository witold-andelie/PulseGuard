"""Snippet fingerprinting adapted from revio (Apache-2.0).

Copyright 2026 witold-andelie; licensed under the Apache License, Version 2.0.
Source: src/revio/detect/fingerprint.py, by the same author. Replaces directory
extension/manifest votes with ordered syntax markers for pasted, unexecuted text.
The supported-id override plays the role of revio's explicit profile selection.
"""

from __future__ import annotations

import re
from pathlib import PurePath
from typing import Literal

LANGUAGES = frozenset({
    "python", "java", "javascript", "typescript", "go", "csharp", "sql",
    "cobol", "sas", "plsql", "unknown", "c", "cpp",
})
GRAMMAR_LANGUAGES = frozenset({"java", "javascript", "typescript", "go", "csharp", "sql",
                               "c", "cpp"})

_CPP_MARKER = (r"\bstd\s*::|\btemplate\s*<|\bnamespace\s+[\w:]+\s*\{"
               r"|(?m:^\s*#\s*include\s*<(?:string|iostream|sstream|vector|array|map|memory)>)")
_CPP_CLASS = r"\bclass\s+\w+\s*(?:final\s*)?(?::[^{}]+)?\{"
_C_TEXT = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_MARKERS = (
    ("cobol", r"\b(?:IDENTIFICATION|PROCEDURE|WORKING-STORAGE)\s+(?:DIVISION|SECTION)\b"),
    ("sas", r"(?m)^\s*(?:proc\s+(?:sql|print|sort)\b|data\s+\w+\s*;|%macro\b|%let\b)"),
    ("plsql", r"\b(?:declare\s+\w+|create\s+(?:or\s+replace\s+)?(?:procedure|package)\b)"
              r"|\bbegin\b[\s\S]*\bend\s*;"),
    ("go", r"(?m)^\s*(?:package\s+\w+|func\s+(?:\([^)]*\)\s*)?\w+\s*\()"),
    ("cpp", _CPP_MARKER),
    ("csharp", r"\b(?:using\s+(?:System|Microsoft)\b|namespace\s+\w+|SqlCommand\b|"
               r"Request\.(?:Query|Form)\b)|\[FromQuery\b"),
    ("java", r"\b(?:import\s+java\w*\.|HttpServletRequest|PreparedStatement|System\.out)\b"
             r"|\b(?:public|private|protected)\s+(?:static\s+)?(?:class|void|String)\b"
             r"|@RequestParam\b"),
    ("typescript", r"\b(?:interface|type)\s+\w+\s*(?:\{|=)|"
                   r"\b\w+\s*:\s*(?:string|number|boolean|Request|Response)\b"),
    ("python", r"(?m)^\s*(?:(?:async\s+)?def\s+\w+\s*\(|from\s+\w+[\w.]*\s+import\b|"
               r"import\s+(?:sqlite3|flask)\b)|\brequest\.args\b"),
    ("cpp", _CPP_CLASS),
    ("c", r"(?m)^\s*#\s*include\b|\btypedef\b|\b(?:struct|union)\s+\w+\s*\{"
          r"|\b(?:void|int|char|size_t|double|float)\s*\**\s*\w+\s*\([^;{}]*\)\s*\{"
          r"|\b(?:static\s+)?const\s+(?:char|int|unsigned)\b"),
    ("javascript", r"\b(?:function\s*\w*\s*\(|(?:const|let|var)\s+\w+|require\s*\(|"
                   r"req\.(?:query|params|body|headers)\b)|=>"),
    ("sql", r"\b(?:select\s+[\s\S]+?\s+from|insert\s+into|update\s+\w+\s+set|"
            r"delete\s+from|create\s+table)\b"),
)


def detect_language(code: str, hint: str | None = None) -> str:
    if hint in LANGUAGES:
        return hint
    c_syntax = _C_TEXT.sub(lambda m: "\n" * m.group().count("\n") + " ", code)
    extension = (hint if hint and hint.startswith(".") else PurePath(hint or "").suffix).lower()
    if extension in {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hxx"}:
        if extension not in {".c", ".h"} or re.search(_CPP_MARKER + "|" + _CPP_CLASS, c_syntax):
            return "cpp"
        return "c"
    for language, pattern in _MARKERS:
        if re.search(pattern, c_syntax if language in {"c", "cpp"} else code, re.I):
            return language
    return "unknown"


def tier_for(language: str, parse_ok: bool) -> Literal["full", "grammar", "llm_only"]:
    if not parse_ok:
        return "llm_only"
    if language == "python":
        return "full"
    return "grammar" if language in GRAMMAR_LANGUAGES else "llm_only"

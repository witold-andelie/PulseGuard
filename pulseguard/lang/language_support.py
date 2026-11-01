"""Lazy Tree-sitter grammar loading, adapted from revio (Apache-2.0).

Source: src/revio/layers/parser/language_support.py, by the same author.
Copyright 2026 witold-andelie; licensed under the Apache License, Version 2.0.
Modified for PulseGuard's language ids, optional wheels and concurrent requests.
Only immutable Language objects are shared; each request gets its own Parser.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import import_module

_GRAMMARS = {
    "python": ("tree_sitter_python", "language"),
    "java": ("tree_sitter_java", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "go": ("tree_sitter_go", "language"),
    "csharp": ("tree_sitter_c_sharp", "language"),
    "sql": ("tree_sitter_sql", "language"),
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
}


@lru_cache(maxsize=len(_GRAMMARS))
def get_language(language: str):
    """Cache successes and failures, as in revio's LanguageSupport registry."""
    if language not in _GRAMMARS:
        return None
    try:
        from tree_sitter import Language

        module, factory = _GRAMMARS[language]
        return Language(getattr(import_module(module), factory)())
    except (ImportError, AttributeError, OSError, TypeError, ValueError, RuntimeError):
        return None


def get_parser(language: str):
    grammar = get_language(language)
    if grammar is None:
        return None
    try:
        from tree_sitter import Parser

        return Parser(grammar)
    except (ImportError, OSError, TypeError, ValueError, RuntimeError):
        return None

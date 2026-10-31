"""Tolerant JSON parsing for (reasoning) model output.

Re-implements, for this repository, the behaviour of SymbAI-Taint
``src/orchestrator/llm_client.py::_parse_json_response``: strip ``<think>`` blocks and code
fences, tolerate truncated output, and fall back to regex extraction of scalar fields.
"""

from __future__ import annotations

import json
import re
from typing import Any

_THINK_RE = re.compile(r"<think>.*?</think>", re.S | re.I)
_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*(.*?)(?:```|$)", re.S)

# Scalar fields recovered by regex when no JSON object can be repaired.
_BOOL_FIELDS = ("is_exploitable",)
_NUM_FIELDS = ("score", "attempt")
_STR_FIELDS = ("step1_dataflow", "step2_constraint", "step3_context", "step4_verdict",
               "rationale", "band")
_LIST_FIELDS = ("cited_evidence",)


def strip_wrappers(text: str) -> str:
    """Remove ``<think>...</think>`` (and an unterminated ``<think>``) plus markdown fences."""
    text = _THINK_RE.sub("", text)
    if "<think>" in text.lower() and "</think>" not in text.lower():
        text = text[: text.lower().index("<think>")]
    m = _FENCE_RE.search(text)
    if m and m.group(1).strip():
        return m.group(1).strip()
    return text.strip()


def _scan_close(fragment: str) -> tuple[list[str], bool, list[int]]:
    """Return (stack of open brackets, inside-string flag, positions of top-level-ish commas)."""
    stack: list[str] = []
    in_str = escape = False
    commas: list[int] = []
    for i, ch in enumerate(fragment):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack:
                stack.pop()
        elif ch == ",":
            commas.append(i)
    return stack, in_str, commas


def _close(fragment: str) -> str:
    stack, in_str, _ = _scan_close(fragment)
    out = fragment
    if in_str:
        out += '"'
    out = re.sub(r"[,:\s]+$", "", out)
    # A dangling key without value (e.g. `, "score"`) cannot be closed; caller trims instead.
    for opener in reversed(stack):
        out += "}" if opener == "{" else "]"
    return out


def repair_truncated(text: str) -> Any | None:
    """Try to close a truncated JSON object/array; progressively drop the last member."""
    start = min((i for i in (text.find("{"), text.find("[")) if i >= 0), default=-1)
    if start < 0:
        return None
    fragment = text[start:]
    for _ in range(50):
        try:
            return json.loads(_close(fragment))
        except json.JSONDecodeError:
            pass
        _, _, commas = _scan_close(fragment)
        if not commas:
            return None
        fragment = fragment[: commas[-1]]
    return None


def regex_fallback(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in _BOOL_FIELDS:
        m = re.search(rf'"?{f}"?\s*[:=]\s*(true|false)', text, re.I)
        if m:
            out[f] = m.group(1).lower() == "true"
    for f in _NUM_FIELDS:
        m = re.search(rf'"?{f}"?\s*[:=]\s*(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)', text)
        if m:
            num = float(m.group(1))
            out[f] = int(num) if f == "attempt" else num
    for f in _STR_FIELDS:
        m = re.search(rf'"{f}"\s*:\s*"((?:[^"\\]|\\.)*)', text, re.S)
        if m:
            out[f] = m.group(1).replace('\\"', '"').replace("\\n", "\n")
    for f in _LIST_FIELDS:
        m = re.search(rf'"{f}"\s*:\s*\[([^\]]*)', text)
        if m:
            out[f] = re.findall(r'"([^"]+)"', m.group(1))
    return out


def parse_json_response(text: str | None) -> dict[str, Any] | None:
    """Best-effort parse of a model reply into a dict.

    Order: direct ``json.loads`` -> outermost ``{...}`` slice -> truncation repair -> regex
    fallback for scalar fields. Returns ``None`` when nothing usable is found.
    """
    if not text or not text.strip():
        return None
    body = strip_wrappers(text)
    for candidate in (body,):
        try:
            value = json.loads(candidate)
            if isinstance(value, dict):
                return value
        except (json.JSONDecodeError, TypeError):
            pass
    first, last = body.find("{"), body.rfind("}")
    if 0 <= first < last:
        try:
            value = json.loads(body[first : last + 1])
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass
    repaired = repair_truncated(body)
    if isinstance(repaired, dict) and repaired:
        # Merge in scalars the repair may have dropped together with a truncated tail.
        for key, val in regex_fallback(body).items():
            repaired.setdefault(key, val)
        return repaired
    fallback = regex_fallback(body)
    return fallback or None

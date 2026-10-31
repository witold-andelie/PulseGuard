"""z3 constraint solving on input validators (framework 6, ST-1).

Question: can a value that passes the validators on the taint path still contain a
single quote (configurable needle)? ``unsat`` is strong counter-evidence against
SQLi through that parameter; ``sat`` yields a witness that can seed a PoC;
``unknown`` makes no claim.

Only a small regex subset is translated (anchors, character classes with ranges and
escapes, literals, alternation, bounded ``{m,n}``, ``?``, and ``+``/``*`` when an
explicit length limit is present). Lookaheads, backreferences and anything else
return ``unknown``. Validator lines are recorded exactly so the Verifier can check
them; a proof about a wrongly extracted validator proves nothing.
"""

from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal

SOLVER_TIMEOUT_MS = 2000
DEFAULT_NEEDLE = "'"
_PREFERRED_SQLI = "' OR 1=1"
_SOURCE_MARK = re.compile(
    r"(?:flask\.)?request\.(?:args|form|values|json|cookies|headers)"
    r"(?:\.get\([^)]*\)|\[[^\]]*\])?"
)


class UnsupportedRegex(ValueError):
    """The pattern uses a construct outside the ST-1 translation subset."""


@dataclass(frozen=True)
class Validator:
    """One extracted check on a tainted name, with the exact source line."""

    kind: str
    line: int
    text: str
    file: str = ""
    pattern: str | None = None
    max_len: int | None = None
    name: str | None = None
    fullmatch: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ConstraintResult:
    """Solver answer for ``validators ∧ contains(needle)``. ``unknown`` makes no claim."""

    result: Literal["sat", "unsat", "unknown"]
    model: str
    needle: str
    witness: str | None
    validators: tuple[Validator, ...]
    detail: str
    claim: bool

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["validators"] = [
            v.to_dict() if isinstance(v, Validator) else v for v in self.validators
        ]
        return payload


def _line_text(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _enclosing_function(
    tree: ast.AST, line: int,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    if not functions:
        return None
    return min(functions, key=lambda fn: (fn.end_lineno or fn.lineno) - fn.lineno)


def _is_source_expr(node: ast.AST) -> bool:
    try:
        return bool(_SOURCE_MARK.search(ast.unparse(node)))
    except Exception:
        return False


def _name_of(node: ast.AST) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _uses_names(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _tainted_in(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, source_line: int, sink_line: int,
) -> set[str]:
    tainted: set[str] = set()
    lo, hi = min(source_line, sink_line), max(source_line, sink_line)

    def consider(target: ast.AST, value: ast.AST, lineno: int) -> None:
        if not (lo <= lineno <= hi):
            return
        if _is_source_expr(value) or _uses_names(value, tainted):
            name = _name_of(target)
            if name:
                tainted.add(name)

    changed = True
    while changed:
        before = set(tainted)
        for node in ast.walk(fn):
            lineno = getattr(node, "lineno", 0)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    consider(target, node.value, lineno)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                consider(node.target, node.value, lineno)
            elif isinstance(node, ast.AugAssign):
                consider(node.target, node.value, lineno)
        changed = tainted != before
    return tainted


def _match_call(node: ast.Call) -> tuple[str, ast.AST, ast.AST] | None:
    """Return ``(fullmatch|match, pattern_node, string_node)`` for ``re.fullmatch``/``re.match``."""
    func = node.func
    if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            and func.value.id == "re" and func.attr in {"fullmatch", "match"}):
        return None
    pattern: ast.AST | None = node.args[0] if node.args else None
    string: ast.AST | None = node.args[1] if len(node.args) > 1 else None
    for keyword in node.keywords:
        if keyword.arg == "pattern":
            pattern = keyword.value
        elif keyword.arg == "string":
            string = keyword.value
        elif keyword.arg == "flags" and not (
            isinstance(keyword.value, ast.Constant) and keyword.value.value in (0, None)
        ):
            return None
    if pattern is None or string is None:
        return None
    return func.attr, pattern, string


def _const_str(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _const_int(node: ast.AST) -> int | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, int) else None


def _len_arg(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len":
        if len(node.args) == 1:
            return _name_of(node.args[0])
    return None


def _max_len_from_compare(node: ast.Compare, tainted: set[str]) -> tuple[str, int] | None:
    """Interpret a 2-operand ``len(x)`` comparison as an upper bound on ``x``."""
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    op, left, right = node.ops[0], node.left, node.comparators[0]
    name: str | None = None
    bound: int | None = None
    swapped = False
    if _len_arg(left) is not None and _const_int(right) is not None:
        name, bound = _len_arg(left), _const_int(right)
    elif _const_int(left) is not None and _len_arg(right) is not None:
        name, bound = _len_arg(right), _const_int(left)
        swapped = True
    if name not in tainted or bound is None:
        return None
    if swapped:
        mapping = {ast.Lt: ast.Gt, ast.LtE: ast.GtE, ast.Gt: ast.Lt, ast.GtE: ast.LtE}
        op_type = mapping.get(type(op))
        if op_type is None:
            return None
        op = op_type()
    if isinstance(op, ast.LtE):
        max_len = bound
    elif isinstance(op, ast.Lt):
        max_len = bound - 1
    elif isinstance(op, ast.Gt):
        max_len = bound
    elif isinstance(op, ast.GtE):
        max_len = bound - 1
    else:
        return None
    if max_len < 0:
        return None
    return name, max_len


def _ctype_call(node: ast.Call, tainted: set[str]) -> tuple[str, str] | None:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in {"isdigit", "isalnum"}:
        name = _name_of(func.value)
        if name in tainted and not node.args:
            return func.attr, name
    return None


def _slice_upper(node: ast.AST) -> int | None:
    if not isinstance(node, ast.Subscript) or not isinstance(node.slice, ast.Slice):
        return None
    sl = node.slice
    if sl.lower is not None or sl.step is not None:
        return None
    return _const_int(sl.upper) if sl.upper is not None else None


def extract_validators(
    code: str, source_line: int, sink_line: int, *, file: str = "",
) -> list[Validator]:
    """Find regex / length / ctype checks on the taint path inside the sink's function."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    fn = _enclosing_function(tree, sink_line)
    if fn is None:
        return []
    lines = code.splitlines()
    lo, hi = min(source_line, sink_line), max(source_line, sink_line)
    tainted = _tainted_in(fn, source_line, sink_line)
    found: list[Validator] = []
    seen: set[tuple[int, str]] = set()

    def record(kind: str, lineno: int, **fields: Any) -> None:
        key = (lineno, kind)
        if key in seen or not (lo <= lineno <= hi):
            return
        seen.add(key)
        found.append(Validator(
            kind=kind, line=lineno, text=_line_text(lines, lineno), file=file, **fields,
        ))

    for node in ast.walk(fn):
        lineno = getattr(node, "lineno", 0)
        if isinstance(node, ast.Call):
            matched = _match_call(node)
            if matched is not None:
                attr, pattern_node, string_node = matched
                pattern = _const_str(pattern_node)
                name = _name_of(string_node)
                if pattern is not None and name in tainted:
                    record("regex", lineno, pattern=pattern, name=name,
                           fullmatch=attr == "fullmatch")
            ctype = _ctype_call(node, tainted)
            if ctype is not None:
                kind, name = ctype
                record(kind, lineno, name=name)
        if isinstance(node, ast.Compare):
            bound = _max_len_from_compare(node, tainted)
            if bound is not None:
                name, max_len = bound
                record("length", lineno, max_len=max_len, name=name)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            upper = _slice_upper(value) if value is not None else None
            if value is None or upper is None:
                continue
            sliced = value.value if isinstance(value, ast.Subscript) else None
            if sliced is not None and (_name_of(sliced) in tainted or _is_source_expr(sliced)):
                target = node.targets[0] if isinstance(node, ast.Assign) else node.target
                name = _name_of(target)
                if name:
                    record("length", lineno, max_len=upper, name=name)
    found.sort(key=lambda item: item.line)
    return found


class _RegexParser:
    """Translate the ST-1 regex subset into a z3 regular expression."""

    def __init__(self, pattern: str, max_len: int | None) -> None:
        self.s = pattern
        self.i = 0
        self.max_len = max_len
        self.need_bound = False

    def peek(self, n: int = 1) -> str:
        return self.s[self.i:self.i + n]

    def get(self) -> str:
        ch = self.s[self.i]
        self.i += 1
        return ch

    def eat(self, token: str) -> bool:
        if self.s.startswith(token, self.i):
            self.i += len(token)
            return True
        return False

    def parse(self) -> Any:
        self.eat("^") or self.eat("\\A")
        body = self.alt()
        self.eat("$") or self.eat("\\Z")
        if self.i != len(self.s):
            raise UnsupportedRegex(f"unparsed suffix {self.s[self.i:]!r}")
        if self.need_bound and self.max_len is None:
            raise UnsupportedRegex("unbounded repetition needs an explicit length limit")
        return body

    def alt(self) -> Any:
        from z3 import Union
        parts = [self.concat()]
        while self.eat("|"):
            parts.append(self.concat())
        return parts[0] if len(parts) == 1 else Union(*parts)

    def concat(self) -> Any:
        from z3 import Concat, Re
        parts = []
        while self.peek() and self.peek() not in "|$)":
            parts.append(self.repeat())
        if not parts:
            return Re("")
        if len(parts) == 1:
            return parts[0]
        return Concat(*parts)

    def repeat(self) -> Any:
        from z3 import Loop, Option, Plus, Star
        atom = self.atom()
        if self.peek(2) in {"??", "*?", "+?"}:
            raise UnsupportedRegex("lazy quantifier")
        if self.eat("?"):
            return Option(atom)
        if self.eat("+"):
            self.need_bound = True
            return Plus(atom) if self.max_len is None else Loop(atom, 1, self.max_len)
        if self.eat("*"):
            self.need_bound = True
            return Star(atom) if self.max_len is None else Loop(atom, 0, self.max_len)
        if self.peek() == "{":
            return self.counted(atom)
        return atom

    def counted(self, atom: Any) -> Any:
        from z3 import Loop
        self.get()
        digits = ""
        while self.peek().isdigit():
            digits += self.get()
        if not digits and self.peek() != ",":
            raise UnsupportedRegex("empty counted repetition")
        lo = int(digits) if digits else 0
        hi = lo
        if self.eat(","):
            digits = ""
            while self.peek().isdigit():
                digits += self.get()
            if digits:
                hi = int(digits)
            else:
                self.need_bound = True
                if self.max_len is None:
                    raise UnsupportedRegex("{m,} needs an explicit length limit")
                hi = self.max_len
        if not self.eat("}"):
            raise UnsupportedRegex("unterminated counted repetition")
        if hi < lo:
            raise UnsupportedRegex("counted repetition upper < lower")
        return Loop(atom, lo, hi)

    def atom(self) -> Any:
        from z3 import Re
        if self.eat("("):
            if self.peek() == "?":
                if self.eat("?:"):
                    inner = self.alt()
                    if not self.eat(")"):
                        raise UnsupportedRegex("unterminated group")
                    return inner
                raise UnsupportedRegex("extension group (lookahead/flags/named)")
            inner = self.alt()
            if not self.eat(")"):
                raise UnsupportedRegex("unterminated group")
            return inner
        if self.peek() == "[":
            return self.char_class()
        if self.eat("\\"):
            char, piece = self.escape()
            return piece if piece is not None else Re(char or "")
        if self.peek() in {".", "^", "*", "+", "?", "|", "{"}:
            if self.peek() == ".":
                raise UnsupportedRegex("dot metacharacter")
            raise UnsupportedRegex(f"bare metacharacter {self.peek()!r}")
        if not self.peek():
            raise UnsupportedRegex("truncated atom")
        return Re(self.get())

    def char_class(self) -> Any:
        from z3 import Range, Union
        self.get()
        if self.peek() == "^":
            raise UnsupportedRegex("negated character class")
        parts: list[Any] = []
        while self.peek() and self.peek() != "]":
            start, piece = self.class_item()
            nxt = self.s[self.i:self.i + 2]
            if start is not None and self.peek() == "-" and len(nxt) == 2 and nxt[1] != "]":
                self.get()
                end, end_piece = self.class_item()
                if end is None:
                    raise UnsupportedRegex("range bound is a class escape")
                if start > end:
                    raise UnsupportedRegex("backwards character range")
                parts.append(Range(start, end))
            else:
                parts.append(piece)
        if not self.eat("]"):
            raise UnsupportedRegex("unterminated character class")
        if not parts:
            raise UnsupportedRegex("empty character class")
        return parts[0] if len(parts) == 1 else Union(*parts)

    def class_item(self) -> tuple[str | None, Any]:
        from z3 import Re
        if self.eat("\\"):
            return self.escape()
        if not self.peek():
            raise UnsupportedRegex("truncated character class")
        ch = self.get()
        return ch, Re(ch)

    def escape(self) -> tuple[str | None, Any]:
        from z3 import Range, Re, Union
        if not self.peek():
            raise UnsupportedRegex("dangling escape")
        ch = self.get()
        if ch == "d":
            return None, Range("0", "9")
        if ch == "w":
            return None, Union(Range("A", "Z"), Range("a", "z"), Range("0", "9"), Re("_"))
        if ch == "s":
            return None, Union(Re(" "), Re("\t"), Re("\n"), Re("\r"))
        if ch in {"n", "t", "r"}:
            mapped = {"n": "\n", "t": "\t", "r": "\r"}[ch]
            return mapped, Re(mapped)
        if ch.isdigit():
            raise UnsupportedRegex("backreference")
        if ch in {"A", "Z", "b", "B"}:
            raise UnsupportedRegex(f"anchor escape \\{ch}")
        return ch, Re(ch)


def _regex_to_z3(pattern: str, *, max_len: int | None, fullmatch: bool) -> Any:
    if not fullmatch:
        start = pattern.startswith("^") or pattern.startswith("\\A")
        end = pattern.endswith("\\Z") or (pattern.endswith("$") and not pattern.endswith("\\$"))
        if not (start and end):
            raise UnsupportedRegex("re.match pattern is not fully anchored")
    return _RegexParser(pattern, max_len).parse()


def _model_text(validators: list[Validator], max_len: int | None) -> str:
    regexes = [v.pattern for v in validators if v.kind == "regex" and v.pattern]
    if regexes:
        return " ∧ ".join(regexes)
    if max_len is not None and any(v.kind == "length" for v in validators):
        return f"length <= {max_len}"
    ctypes = [v.kind for v in validators if v.kind in {"isdigit", "isalnum"}]
    if ctypes:
        return ctypes[0]
    return "validators"


def _max_len_of(validators: list[Validator]) -> int | None:
    bounds = [v.max_len for v in validators if v.max_len is not None]
    return min(bounds) if bounds else None


def _preferred(needle: str, max_len: int | None, has_regex: bool) -> list[str]:
    ordered = [needle, _PREFERRED_SQLI] if has_regex else [_PREFERRED_SQLI, needle]
    out: list[str] = []
    for cand in ordered:
        if needle not in cand:
            continue
        if max_len is not None and len(cand) > max_len:
            continue
        if cand not in out:
            out.append(cand)
    return out


def _no_claim(
    model: str, needle: str, validators: list[Validator], detail: str,
) -> ConstraintResult:
    return ConstraintResult(
        result="unknown", model=model, needle=needle, witness=None,
        validators=tuple(validators), detail=detail, claim=False,
    )


def _solve(
    regexes: list[Any], max_len: int | None, needle: str, timeout_ms: int, preferred: list[str],
) -> tuple[Literal["sat", "unsat", "unknown"], str | None, str]:
    from z3 import Contains, InRe, Length, Solver, String, StringVal, sat, unsat

    payload = String("payload")

    def constrain(solver: Any) -> None:
        solver.set("timeout", timeout_ms)
        for regex in regexes:
            solver.add(InRe(payload, regex))
        if max_len is not None:
            solver.add(Length(payload) <= max_len)
            solver.add(Length(payload) >= 0)
        solver.add(Contains(payload, StringVal(needle)))

    for cand in preferred:
        solver = Solver()
        constrain(solver)
        solver.add(payload == StringVal(cand))
        if solver.check() == sat:
            return "sat", cand, "preferred witness"
    solver = Solver()
    constrain(solver)
    answer = solver.check()
    if answer == sat:
        raw = solver.model()[payload]
        witness = raw.as_string() if hasattr(raw, "as_string") else str(raw).strip('"')
        return "sat", witness, "solver witness"
    if answer == unsat:
        return "unsat", None, "unsat"
    return "unknown", None, "solver timeout or unknown"


def check_validators(
    code: str,
    *,
    source_line: int,
    sink_line: int,
    file: str = "",
    needle: str = DEFAULT_NEEDLE,
    timeout_ms: int = SOLVER_TIMEOUT_MS,
) -> ConstraintResult:
    """Ask whether ``needle`` can pass every validator on the source→sink path."""
    validators = extract_validators(code, source_line, sink_line, file=file)
    if not validators:
        return _no_claim("", needle, [], "no validators on the taint path")
    max_len = _max_len_of(validators)
    model = _model_text(validators, max_len)
    try:
        from z3 import Loop, Range, Union
    except ImportError:
        return _no_claim(model, needle, validators, "z3-solver is not installed")
    regexes: list[Any] = []
    try:
        for validator in validators:
            if validator.kind == "regex" and validator.pattern is not None:
                regexes.append(_regex_to_z3(
                    validator.pattern, max_len=max_len, fullmatch=validator.fullmatch,
                ))
            elif validator.kind == "isdigit":
                regexes.append(Loop(Range("0", "9"), 1, max_len or 64))
            elif validator.kind == "isalnum":
                alnum = Union(Range("A", "Z"), Range("a", "z"), Range("0", "9"))
                regexes.append(Loop(alnum, 1, max_len or 64))
            elif validator.kind == "length":
                continue
            else:
                return _no_claim(
                    model, needle, validators, f"unsupported validator {validator.kind}")
    except UnsupportedRegex as exc:
        return _no_claim(model, needle, validators, f"unsupported regex: {exc}")
    has_regex = any(v.kind == "regex" for v in validators)
    if not regexes and max_len is None:
        return _no_claim(model, needle, validators, "no translatable constraints")
    try:
        result, witness, detail = _solve(
            regexes, max_len, needle, timeout_ms, _preferred(needle, max_len, has_regex),
        )
    except Exception as exc:
        return _no_claim(model, needle, validators, f"solver error: {type(exc).__name__}")
    return ConstraintResult(
        result=result, model=model, needle=needle, witness=witness,
        validators=tuple(validators), detail=detail, claim=result != "unknown",
    )

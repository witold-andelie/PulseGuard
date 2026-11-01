"""Conservative finite-value and one-hop cast E3 facts, not a Python safety proof.

Only literal SQL atoms are recognised. Control flow, captures and mutations use
the same local, unchanged-value discipline as ST-1 validator dominance.
"""

from __future__ import annotations

import ast
import math
import re
from string import Formatter
from typing import Any

from pulseguard.falsify.z3_check import (
    _enclosing_function,
    _guard_exits,
    _local_nodes,
    _value_unchanged,
)


def _literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) in (str, int, float, type(None))


def _sql_atom(value: Any) -> bool:
    if type(value) is str:
        return re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*|[0-9]+", value, re.ASCII) is not None
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _assignment(node: ast.AST, name: str) -> ast.AST | None:
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
    elif isinstance(node, ast.AnnAssign):
        target = node.target
    else:
        return None
    return node.value if isinstance(target, ast.Name) and target.id == name else None


def _constant(node: ast.AST, tree: ast.Module, fn: ast.AST, before: int) -> ast.AST | None:
    if not isinstance(node, ast.Name):
        return node
    name = node.id
    local = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == name
             and isinstance(n.ctx, (ast.Store, ast.Del))]
    scope = fn if local else tree
    definitions = [n for n in scope.body if _assignment(n, name) is not None]
    if len(definitions) != 1 or definitions[0].lineno >= before:
        return None
    definition = definitions[0]
    # Reject aliases, mutation, escape to arbitrary calls, shadowing and rebinding.
    # Module constants are checked throughout the module, including other functions.
    parents = {child: parent for parent in ast.walk(scope)
               for child in ast.iter_child_nodes(parent)}
    stores = [n for n in ast.walk(scope) if isinstance(n, ast.Name) and n.id == name
              and isinstance(n.ctx, (ast.Store, ast.Del))]
    if len(stores) != 1:
        return None
    for use in ast.walk(scope):
        if isinstance(use, (ast.Global, ast.Nonlocal)) and name in use.names:
            return None
        if isinstance(use, ast.arg) and use.arg == name:
            return None
        if not isinstance(use, ast.Name) or use.id != name or not isinstance(use.ctx, ast.Load):
            continue
        parent = parents.get(use)
        if isinstance(parent, ast.Compare) and use in parent.comparators:
            continue
        if isinstance(parent, ast.Subscript) and parent.value is use:
            if isinstance(parent.ctx, ast.Load):
                continue
        if isinstance(parent, ast.Attribute) and parent.value is use and parent.attr == "get":
            call = parents.get(parent)
            if isinstance(call, ast.Call) and call.func is parent:
                continue
        return None
    return _assignment(definition, name)


def _members(node: ast.AST | None, *, mapping: bool = False) -> list[Any] | None:
    if mapping:
        if not isinstance(node, ast.Dict) or not all(k is not None and _literal(k)
                                                   for k in node.keys):
            return None
        elements = node.values
    elif isinstance(node, (ast.Set, ast.Tuple, ast.List)):
        elements = node.elts
    else:
        return None
    if not elements or not all(_literal(n) and _sql_atom(n.value) for n in elements):
        return None
    return sorted({n.value for n in elements}, key=str)


def _format_arguments(node: ast.AST) -> list[ast.AST] | None:
    """Only plain automatic positional fields; no attributes, specs or unused args."""
    if (not isinstance(node, ast.Call) or node.keywords
            or not isinstance(node.func, ast.Attribute) or node.func.attr != "format"
            or not isinstance(node.func.value, ast.Constant)
            or not isinstance(node.func.value.value, str)):
        return None
    try:
        fields = [field for _, field, spec, conversion in Formatter().parse(node.func.value.value)
                  if field is not None or spec or conversion]
        if fields != [""] * len(node.args):
            return None
        if any(spec or conversion for _, _, spec, conversion
               in Formatter().parse(node.func.value.value)):
            return None
    except ValueError:
        return None
    return node.args


def _sink_values(fn: ast.AST, sink_line: int) -> list[tuple[str, int]]:
    """Resolve plain SQL query aliases, retaining each interpolation's capture line."""
    nodes = list(_local_nodes(fn))
    sinks = [n for n in nodes if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "execute" and n.args
             and n.lineno <= sink_line <= (n.end_lineno or n.lineno)]
    if len(sinks) != 1:
        return []

    def holes(node: ast.AST, before: int, seen: set[str]) -> list[tuple[str, int]]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return []
        if isinstance(node, ast.JoinedStr):
            out = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    if part.conversion != -1 or part.format_spec is not None:
                        raise ValueError
                    part = part.value
                out.extend(holes(part, before, seen))
            return out
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return holes(node.left, before, seen) + holes(node.right, before, seen)
        arguments = _format_arguments(node)
        if arguments is not None:
            return [hole for arg in arguments for hole in holes(arg, before, seen)]
        if isinstance(node, ast.Name) and node.id not in seen:
            definitions = [n for n in nodes if _assignment(n, node.id) is not None
                           and n.lineno < before]
            if definitions:
                definition = max(definitions, key=lambda n: n.lineno)
                value = _assignment(definition, node.id)
                is_query = ((isinstance(value, (ast.BinOp, ast.JoinedStr))
                             or _format_arguments(value) is not None) and any(
                    isinstance(n, ast.Constant) and isinstance(n.value, str)
                    and re.search(r"\b(?:SELECT|UPDATE|INSERT|DELETE)\b", n.value, re.I)
                    for n in ast.walk(value)))
                if is_query:
                    if len(definitions) != 1 or not _value_unchanged(
                        fn, node.id, definition.end_lineno or definition.lineno, sink_line,
                        after_node=definition,
                    ):
                        raise ValueError
                    return holes(value, definition.lineno, seen | {node.id})
            return [(node.id, node.lineno)]
        raise ValueError

    try:
        return holes(sinks[0].args[0], sink_line + 1, set())
    except ValueError:
        return []


def _unshadowed(tree: ast.Module, name: str, definition: ast.AST | None = None) -> bool:
    """Fail closed on any competing binding, including in another local scope."""
    for node in ast.walk(tree):
        if node is definition:
            continue
        if isinstance(node, ast.Name) and node.id == name and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            return False
        if isinstance(node, ast.arg) and node.arg == name:
            return False
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ) and any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node.value)):
            return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return False
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
            a.name == '*' or
            (a.asname or (a.name.split('.')[0] if isinstance(node, ast.Import) else a.name)) == name
            for a in node.names
        ):
            return False
        if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name == name:
            return False
    return True


def _module_definition(tree: ast.Module, name: str) -> ast.AST | None:
    definitions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))
                   and n.name == name]
    if len(definitions) != 1 or not _unshadowed(tree, name, definitions[0]):
        return None
    # Reject aliases/escapes and class mutation, including E.MEMBER._value_ writes.
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load):
            parent = parents.get(node)
            if isinstance(parent, ast.Call) and parent.func is node:
                continue
            if isinstance(parent, ast.Subscript) and parent.value is node and isinstance(
                parent.ctx, ast.Load
            ):
                continue
            return None
    return definitions[0]


def _enum_base(tree: ast.Module, base: ast.AST) -> bool:
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def unchanged_import(name: str, definition: ast.AST, namespace: bool = False) -> bool:
        if not _unshadowed(tree, name, definition):
            return False
        for use in ast.walk(tree):
            if not isinstance(use, ast.Name) or use.id != name or not isinstance(use.ctx, ast.Load):
                continue
            reference = use
            if namespace:
                reference = parents.get(use)
                if not isinstance(reference, ast.Attribute) or reference.attr != 'Enum':
                    return False
            parent = parents.get(reference)
            if not isinstance(parent, ast.ClassDef) or reference not in parent.bases:
                return False
        return True

    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == 'enum' and node.level == 0:
            for alias in node.names:
                name = alias.asname or alias.name
                if (alias.name == 'Enum' and isinstance(base, ast.Name) and base.id == name
                        and unchanged_import(name, node)):
                    return True
        if isinstance(node, ast.Import) and isinstance(base, ast.Attribute) and base.attr == 'Enum':
            for alias in node.names:
                name = alias.asname or alias.name
                if (alias.name == 'enum' and isinstance(base.value, ast.Name)
                        and base.value.id == name and unchanged_import(name, node, namespace=True)):
                    return True
    return False


def _enum_fact(value: ast.AST, tree: ast.Module) -> dict[str, Any] | None:
    if isinstance(value, ast.Attribute) and value.attr == 'value':
        value = value.value
    if (isinstance(value, ast.Call) and len(value.args) == 1 and not value.keywords
            and not isinstance(value.args[0], ast.Starred)):
        constructor = value.func
    elif isinstance(value, ast.Subscript):
        constructor = value.value
    else:
        return None
    if not isinstance(constructor, ast.Name):
        return None
    enum = _module_definition(tree, constructor.id)
    if not isinstance(enum, ast.ClassDef) or enum.decorator_list or enum.keywords:
        return None
    if sum(_enum_base(tree, b) for b in enum.bases) != 1:
        return None
    for base in enum.bases:
        if not _enum_base(tree, base) and not (
            isinstance(base, ast.Name) and base.id in {'str', 'int', 'float'}
            and _unshadowed(tree, base.id)
        ):
            return None
    members = []
    for statement in enum.body:
        if isinstance(statement, ast.Pass) or (isinstance(statement, ast.Expr)
                                              and isinstance(statement.value, ast.Constant)
                                              and isinstance(statement.value.value, str)):
            continue
        targets = (statement.targets if isinstance(statement, ast.Assign) else
                   [statement.target] if isinstance(statement, ast.AnnAssign) else [])
        if (len(targets) != 1 or not isinstance(targets[0], ast.Name)
                or targets[0].id.startswith('_') or not _literal(statement.value)
                or not _sql_atom(statement.value.value)):
            return None
        members.append(statement.value.value)
    if not members:
        return None
    members = sorted(set(members), key=str)
    return {'rule': 'allow-list Enum', 'members': members, 'enum': enum.name,
            'definition_line': enum.lineno, 'line': value.lineno,
            'evidence': f"Enum {enum.name} members {{{','.join(map(str, members))}}} "
                        f"@ L{enum.lineno}, called @ L{value.lineno}"}


def _helper_fact(value: ast.AST, tree: ast.Module) -> dict[str, Any] | None:
    if (not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name)
            or len(value.args) != 1 or value.keywords or isinstance(value.args[0], ast.Starred)):
        return None
    helper = _module_definition(tree, value.func.id)
    if not isinstance(helper, ast.FunctionDef) or helper.decorator_list:
        return None
    args = helper.args
    parameters = [*args.posonlyargs, *args.args]
    if (len(parameters) != 1 or args.vararg or args.kwarg or args.kwonlyargs or args.defaults
            or len(list(ast.walk(helper))) > 200):
        return None
    param = parameters[0].arg
    if any(isinstance(n, ast.Name) and n.id == param and isinstance(n.ctx, (ast.Store, ast.Del))
           for n in ast.walk(helper)):
        return None
    work = 0

    def paths(body: list[ast.stmt], allowed: list[Any] | None) -> list[dict[str, Any]]:
        nonlocal work
        work += 1
        if not body or work > 256:
            raise ValueError  # Fall-through (implicit None) is outside the helper contract.
        statement, *rest = body
        if isinstance(statement, ast.Raise):
            return []
        if isinstance(statement, ast.Expr) and _guard_exits(tree, helper, [statement]):
            return []
        if isinstance(statement, ast.Return):
            result = statement.value
            if (isinstance(result, ast.Call) and isinstance(result.func, ast.Name)
                    and result.func.id in {'int', 'float'} and _unshadowed(tree, result.func.id)
                    and len(result.args) == 1 and not result.keywords
                    and isinstance(result.args[0], ast.Name) and result.args[0].id == param):
                return [{'cast': result.func.id, 'line': statement.lineno}]
            if isinstance(result, ast.Name) and result.id == param and allowed is not None:
                return [{'members': allowed, 'line': statement.lineno}]
            if (isinstance(result, ast.Subscript) and isinstance(result.slice, ast.Name)
                    and result.slice.id == param):
                members = _members(_constant(result.value, tree, helper, statement.lineno),
                                   mapping=True)
                if members is not None:
                    return [{'members': members, 'line': statement.lineno}]
            raise ValueError
        if isinstance(statement, ast.If):
            test = statement.test
            if any(isinstance(n, (ast.Call, ast.Attribute, ast.Subscript, ast.NamedExpr,
                                  ast.Lambda, ast.Await, ast.Yield)) for n in ast.walk(test)):
                raise ValueError
            positive = negative = allowed
            if (isinstance(test, ast.Compare) and len(test.ops) == 1
                    and isinstance(test.left, ast.Name) and test.left.id == param
                    and isinstance(test.ops[0], (ast.In, ast.NotIn))):
                members = _members(_constant(test.comparators[0], tree, helper, statement.lineno))
                if members is not None:
                    members = members if allowed is None else [m for m in members if m in allowed]
                    if isinstance(test.ops[0], ast.In):
                        positive = members
                    else:
                        negative = members
            return paths(statement.body + rest, positive) + paths(statement.orelse + rest, negative)
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if (len(targets) != 1 or not isinstance(targets[0], ast.Name)
                    or targets[0].id == param or (_members(statement.value) is None
                        and _members(statement.value, mapping=True) is None)):
                raise ValueError
        elif not (isinstance(statement, ast.Pass) or (isinstance(statement, ast.Expr)
                                                     and isinstance(statement.value, ast.Constant)
                                                     and isinstance(statement.value.value, str))):
            raise ValueError
        return paths(rest, allowed)

    try:
        returns = paths(helper.body, None)
    except ValueError:
        return None
    if not returns:
        return None
    casts = sorted({r['cast'] for r in returns if 'cast' in r})
    members = sorted({m for r in returns for m in r.get('members', [])}, key=str)
    descriptions = [f"{r['cast']}() cast in helper {helper.name} @ L{r['line']}" if 'cast' in r
                    else f"allow-list in helper {helper.name} members "
                         f"{{{','.join(map(str, r['members']))}}} @ L{r['line']}" for r in returns]
    fact = {'rule': 'cast in helper' if casts else 'allow-list in helper',
            'helper': helper.name, 'definition_line': helper.lineno, 'line': value.lineno,
            'return_lines': sorted({r['line'] for r in returns}),
            'evidence': '; '.join(descriptions) + f", called @ L{value.lineno}"}
    if casts:
        fact['casts'] = casts
        if members:
            fact['allowlist_members'] = members
    else:
        fact['members'] = members
    return fact


def allowlist_facts(code: str, sink_line: int) -> list[dict[str, Any]]:
    """Prove finite values/one-hop casts with shared sink dominance; silence on doubt."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    fn = _enclosing_function(tree, sink_line)
    if fn is None:
        return []
    values = _sink_values(fn, sink_line)
    format_calls = {n for n in _local_nodes(fn) if isinstance(n, ast.Call)
                    and _format_arguments(n) is not None}
    facts = []
    for statement in fn.body:
        rule = "allow-list membership guard"
        members = None
        transform = None
        name = None
        after = statement.end_lineno or statement.lineno
        after_node = statement
        positive = False
        if isinstance(statement, ast.If):
            test = statement.test
            if (not isinstance(test, ast.Compare) or len(test.ops) != 1
                    or not isinstance(test.left, ast.Name)):
                continue
            name = test.left.id
            members = _members(_constant(test.comparators[0], tree, fn, statement.lineno))
            if isinstance(test.ops[0], ast.NotIn):
                if statement.orelse or not _guard_exits(tree, fn, statement.body):
                    continue
            elif isinstance(test.ops[0], ast.In):
                positive = True
                after = test.end_lineno or test.lineno
                after_node = test
            else:
                continue
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            name = targets[0].id
            value = statement.value
            transform = _enum_fact(value, tree) or _helper_fact(value, tree)
            if transform is not None:
                rule = transform['rule']
                members = transform.get('members')
            elif isinstance(value, ast.IfExp):
                test = value.test
                if (not isinstance(test, ast.Compare) or len(test.ops) != 1
                        or not isinstance(test.ops[0], ast.In)
                        or not isinstance(test.left, ast.Name) or test.left.id != name
                        or not isinstance(value.body, ast.Name) or value.body.id != name
                        or not _literal(value.orelse) or not _sql_atom(value.orelse.value)):
                    continue
                members = _members(_constant(test.comparators[0], tree, fn, statement.lineno))
                if members is not None:
                    members = sorted(set([*members, value.orelse.value]), key=str)
                rule = "allow-list conditional"
            else:
                mapping = None
                default = None
                implicit_none = False
                if isinstance(value, ast.Subscript) and isinstance(value.slice, ast.Name):
                    mapping = value.value
                elif (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                      and value.func.attr == "get" and len(value.args) in (1, 2)
                      and isinstance(value.args[0], ast.Name) and not value.keywords):
                    mapping = value.func.value
                    if len(value.args) == 2:
                        default = value.args[1]
                    else:
                        implicit_none = True
                if mapping is None:
                    continue
                members = _members(_constant(mapping, tree, fn, statement.lineno), mapping=True)
                if members is not None and implicit_none:
                    members = sorted([*members, None], key=str)
                if default is not None:
                    if not _literal(default) or not _sql_atom(default.value):
                        continue
                    if members is not None:
                        members = sorted(set([*members, default.value]), key=str)
                rule = "allow-list dict lookup"
        if name is None or (members is None and transform is None):
            continue
        captures = [line for var, line in values if var == name]
        if not captures or min(captures) <= after:
            continue
        scope = statement.body if positive else fn.body
        # A direct sink statement excludes conditional/try/loop/finally paths.
        sink_statement = next((s for s in scope if s.lineno <= sink_line
                               <= (s.end_lineno or s.lineno)), None)
        if not isinstance(sink_statement, (ast.Return, ast.Expr, ast.Assign, ast.AnnAssign)):
            continue
        if positive and not all(statement.lineno < line <= (statement.end_lineno or 0)
                                for line in captures):
            continue
        if not _value_unchanged(fn, name, after, sink_line, permitted_calls=format_calls,
                                after_node=after_node):
            continue
        fact = {"rule": rule, "line": statement.lineno, "variable": name}
        if transform is not None:
            fact.update(transform)
        else:
            fact['members'] = members
        facts.append(fact)
    return facts

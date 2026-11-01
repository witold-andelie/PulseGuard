"""Original CWE-89 fixtures: incomplete validators. Never imported by the app.

Assume a populated SQLite connection at current_app.extensions['eval_db'].
Pattern provenance and concrete counterexamples are in eval/README.md.
"""

import re

from flask import Blueprint, current_app, jsonify, request

cases = Blueprint("hard_bypasses", __name__)
ALLOWED = {"id", "item", "qty"}


@cases.get("/hard/regex_search")
def regex_search():
    value = request.args.get("id", "")
    if not re.search(r"[0-9]{1,8}", value):
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: unanchored search


@cases.get("/hard/regex_dollar_multiline")
def regex_dollar_multiline():
    value = request.args.get("id", "")
    if not re.match(r"^[0-9]{1,8}$", value, re.MULTILINE):
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: newline then OR bypasses $


@cases.get("/hard/regex_match_prefix")
def regex_match_prefix():
    value = request.args.get("id", "")
    if not re.match(r"[0-9]{1,8}", value):
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: prefix match permits suffix


@cases.get("/hard/length_only")
def length_only():
    value = request.args.get("id", "")
    if len(value) > 8:
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: 1 OR 1=1 fits


@cases.get("/hard/case_allowlist_fallthrough")
def case_allowlist_fallthrough():
    column = request.args.get("column", "id")
    if column in ALLOWED:
        column = column.lower()
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column.lower()}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: nonmembers fall through


@cases.get("/hard/different_variable")
def different_variable():
    checked = request.args.get("checked", "id")
    column = request.args.get("column", "id")
    if checked not in ALLOWED:
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: guard protects checked only


@cases.get("/hard/one_branch")
def one_branch():
    value = request.args.get("id", "")
    if request.args.get("strict") == "yes":
        if not re.fullmatch(r"[0-9]{1,8}", value):
            return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: optional validation


@cases.get("/hard/try_fallback")
def try_fallback():
    raw = request.args.get("id", "")
    try:
        value = int(raw)
    except ValueError:
        value = raw
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: failed cast restores raw


@cases.get("/hard/validated_reassigned")
def validated_reassigned():
    column = request.args.get("column", "id")
    if column not in ALLOWED:
        return jsonify([])
    column = request.headers.get("X-Column", "id")
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: reassigned after guard


@cases.get("/hard/validated_concatenated")
def validated_concatenated():
    column = request.args.get("column", "id")
    if column not in ALLOWED:
        return jsonify([])
    column += request.args.get("suffix", "")
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: unvalidated suffix


@cases.get("/hard/discarded_int")
def discarded_int():
    value = request.args.get("id", "")
    try:
        int(value)
    except ValueError:
        pass
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: cast discarded and error ignored


@cases.get("/hard/quote_escape_numeric")
def quote_escape_numeric():
    value = request.args.get("id", "").replace("'", "''")
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: numeric OR needs no quote


@cases.get("/hard/escape_format_numeric")
def escape_format_numeric():
    value = request.args.get("id", "").replace("'", "''")
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value:>8}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: format width is not validation

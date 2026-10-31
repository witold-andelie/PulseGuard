"""Author-written constraint cases using SymbAI-Taint annotation conventions.

These handlers are scanner inputs only; the demo app never imports this module.
"""

# Keep the distinct SQL construction forms as benchmark inputs.
# ruff: noqa: UP031, UP032

import sqlite3

from flask import Blueprint, Response, jsonify, request

cases = Blueprint("constraints", __name__)


@cases.get("/integer_text")
def integer_text() -> Response:
    number = int(request.args.get("id", "0"))
    query = "SELECT id FROM orders WHERE id = " + str(number)
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: int-cast


@cases.get("/integer_format")
def integer_format() -> Response:
    number = int(request.args.get("id", "0"))
    query = f"SELECT id FROM orders WHERE id = {number}"
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: int-cast before f-string


@cases.get("/integer_percent")
def integer_percent() -> Response:
    number = int(request.args.get("id", "0"))
    query = "SELECT id FROM orders WHERE id = %d" % number
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: integer format


@cases.get("/column_choice")
def column_choice() -> Response:
    column = request.args.get("column", "id")
    allowed_columns = {"id", "item", "qty"}
    if column not in allowed_columns:
        return jsonify({"error": "unknown column"})
    query = "SELECT id FROM orders ORDER BY " + column
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: finite allow-list


@cases.get("/sort_choice")
def sort_choice() -> Response:
    direction = request.args.get("direction", "ASC")
    if direction not in ("ASC", "DESC"):
        return jsonify({"error": "unknown direction"})
    query = "SELECT id FROM orders ORDER BY id {}".format(direction)
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: finite direction allow-list


@cases.get("/mapped_choice")
def mapped_choice() -> Response:
    selection = request.args.get("sort", "number")
    column = {"number": "id", "product": "item"}.get(selection, "id")
    query = f"SELECT id FROM orders ORDER BY {column}"
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: map to fixed identifiers


@cases.get("/sanitized")
def sanitized_lookup() -> Response:
    sanitized_id = request.args.get("id", "")
    query = f"SELECT id FROM orders WHERE id = '{sanitized_id}'"
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: misleading sanitizer name


@cases.get("/trimmed")
def trimmed_lookup() -> Response:
    value = request.args.get("id", "").strip()
    query = "SELECT id FROM orders WHERE id = '%s'" % value
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: strip is not SQL sanitisation

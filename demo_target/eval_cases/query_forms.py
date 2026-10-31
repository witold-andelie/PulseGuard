"""Author-written SQL cases for SymbAI-Taint-style labels; never registered by the demo.

Judge each handler as if invoked with a request and a populated orders table.
The in-memory database is a self-contained scanner fixture, not a deployed service.
"""

# Keep the distinct SQL construction forms as benchmark inputs.
# ruff: noqa: UP031, UP032

import sqlite3

from flask import Blueprint, Response, jsonify, request

cases = Blueprint("query_forms", __name__)


@cases.get("/by_name")
def by_name() -> Response:
    name = request.args.get("name", "")
    query = f"SELECT id FROM orders WHERE item = '{name}'"
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: f-string


@cases.get("/by_reference")
def by_reference() -> Response:
    reference = request.args.get("reference", "")
    query = "SELECT id FROM orders WHERE reference = '%s'" % reference
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: percent formatting


@cases.get("/by_item")
def by_item() -> Response:
    item = request.args.get("item", "")
    query = "SELECT id FROM orders WHERE item = '{}'".format(item)
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: str.format


@cases.get("/by_quantity")
def by_quantity() -> Response:
    quantity = request.args.get("quantity", "")
    query = "SELECT id FROM orders WHERE qty = " + quantity
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: unquoted numeric input


@cases.get("/sorted")
def sorted_orders() -> Response:
    column = request.args.get("column", "id")
    query = f"SELECT id FROM orders ORDER BY {column}"
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: attacker controls identifier


@cases.get("/search")
def search_orders() -> Response:
    term = request.args.get("term", "")
    query = "SELECT id FROM orders WHERE item LIKE '%{}%'".format(term)
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: LIKE text interpolation


@cases.get("/bound_name")
def bound_name() -> Response:
    name = request.args.get("name", "")
    query = "SELECT id FROM orders WHERE item = ?"
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query, (name,)).fetchall())  # @safe sqli: bound parameter


@cases.get("/bound_item")
def bound_item() -> Response:
    item = request.args.get("item", "")
    query = "SELECT id FROM orders WHERE item = :item"
    conn = sqlite3.connect(":memory:")
    return jsonify(conn.execute(query, {"item": item}).fetchall())  # @safe sqli: named parameter

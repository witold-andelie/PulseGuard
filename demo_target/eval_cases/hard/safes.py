"""Original true-safe controls; source/sanitizer/sink and provenance in eval/README.md."""

import re
from enum import Enum

from flask import Blueprint, current_app, jsonify, request

cases = Blueprint("hard_safes", __name__)
COLUMNS = {"number": "id", "product": "item", "count": "qty"}
ALLOWED = {"id", "item", "qty"}


class Column(Enum):
    NUMBER = "id"
    PRODUCT = "item"
    COUNT = "qty"


@cases.get("/hard/set_guard")
def set_guard():
    column = request.args.get("column", "id")
    if column not in ALLOWED:
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: constant set rejection guard


@cases.get("/hard/tuple_positive")
def tuple_positive():
    column = request.args.get("column", "id")
    conn = current_app.extensions["eval_db"]
    if column in ("id", "item", "qty"):
        query = f"SELECT id FROM orders ORDER BY {column}"
        return jsonify(conn.execute(query).fetchall())  # @safe sqli: sink inside positive guard
    return jsonify([])


@cases.get("/hard/dict_subscript")
def dict_subscript():
    selection = request.args.get("column", "number")
    column = COLUMNS[selection]
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: unknown keys raise before sink


@cases.get("/hard/dict_get")
def dict_get():
    selection = request.args.get("column", "number")
    column = COLUMNS.get(selection, "id")
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: mapping values and default fixed


@cases.get("/hard/enum_column")
def enum_column():
    selection = request.args.get("column", "id")
    column = Column(selection).value
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: Enum rejects nonmember values


@cases.get("/hard/conditional_column")
def conditional_column():
    column = request.args.get("column", "id")
    column = column if column in ALLOWED else "id"
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: finite conditional result


@cases.get("/hard/integer_used")
def integer_used():
    value = int(request.args.get("id", "0"))
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: integer result reaches sink


@cases.get("/hard/float_used")
def float_used():
    value = float(request.args.get("qty", "0"))
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE qty = {value}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: float cannot contain SQL tokens


@cases.post("/hard/positional_binding")
def positional_binding():
    value = request.form.get("item", "")
    conn = current_app.extensions["eval_db"]
    query = "SELECT id FROM orders WHERE item = ?" + " ORDER BY id"
    return jsonify(conn.execute(query, (value,)).fetchall())  # @safe sqli: positional bind


@cases.post("/hard/named_binding")
def named_binding():
    value = request.get_json().get("item", "")
    conn = current_app.extensions["eval_db"]
    query = "SELECT id FROM orders WHERE item = :item"
    return jsonify(conn.execute(query, {"item": value}).fetchall())  # @safe sqli: named bind


@cases.post("/hard/batch_binding")
def batch_binding():
    values = request.get_json().get("items", [])
    conn = current_app.extensions["eval_db"]
    query = "INSERT INTO orders (item, qty) VALUES (?, 1)"
    conn.executemany(query, [(value,) for value in values])  # @safe sqli: every row bound
    return jsonify({"inserted": len(values)})


class BoundOrders:
    """Minimal ORM-style builder whose only value channel is SQLite binding."""

    def __init__(self, connection):
        self.connection = connection
        self.params = {}

    def where_id(self, value):
        self.params = {"id": value}
        return self

    def all(self):
        return self.connection.execute("SELECT id FROM orders WHERE id = :id",
                                       self.params).fetchall()


@cases.get("/hard/bound_builder")
def bound_builder():
    value = request.headers.get("X-Order", "0")
    conn = current_app.extensions["eval_db"]
    rows = BoundOrders(conn).where_id(value).all()  # @safe sqli: bound builder; interprocedural
    return jsonify(rows)


@cases.get("/hard/quoted_mapping")
def quoted_mapping():
    selection = request.args.get("column", "number")
    column = {"number": '"id"', "product": '"item"', "count": '"qty"'}[selection]
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: quoted identifiers from fixed map


@cases.get("/hard/constant_sql")
def constant_sql():
    request.args.get("ignored", "")
    conn = current_app.extensions["eval_db"]
    query = "SELECT id FROM orders " + "WHERE qty > 0 " + "ORDER BY id"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: only SQL literals concatenated


@cases.get("/hard/regex_fullmatch_patch")
def regex_fullmatch_patch():
    value = request.args.get("id", "")
    if not re.fullmatch(r"[0-9]{1,8}", value):
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: patched regex_match_prefix


@cases.get("/hard/try_failclosed_patch")
def try_failclosed_patch():
    raw = request.args.get("id", "")
    try:
        value = int(raw)
    except ValueError:
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: patched try_fallback exits


@cases.get("/hard/normalised_allowlist")
def normalised_allowlist():
    column = request.args.get("column", "id").lower()
    if column not in ALLOWED:
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders ORDER BY {column}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: same normalised value checked


@cases.get("/hard/dollar_final_newline")
def dollar_final_newline():
    value = request.args.get("id", "")
    if not re.match(r"^[0-9]{1,8}$", value):
        return jsonify([])
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: final newline is SQL whitespace

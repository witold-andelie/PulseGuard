"""Original cross-function and second-order cases: beyond intraprocedural taint.

The app never imports this module. The evaluator must supply a populated eval_db
with an orders table and saved_filters(token TEXT, value TEXT).
"""

from flask import Blueprint, current_app, jsonify, request

cases = Blueprint("hard_flows", __name__)


def fetch_rows(connection, value):
    query = f"SELECT id FROM orders WHERE id = {value}"
    return connection.execute(query).fetchall()


def forward_rows(connection, value):
    return fetch_rows(connection, value)


@cases.post("/hard/two_hop")
def two_hop():
    value = request.form.get("id", "")
    conn = current_app.extensions["eval_db"]
    return jsonify(forward_rows(conn, value))  # @vuln sqli: two helper hops; interprocedural


def integer_in_helper(value):
    return int(value)


@cases.get("/hard/helper_cast")
def helper_cast():
    raw = request.cookies.get("order", "0")
    value = integer_in_helper(raw)
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @safe sqli: cast in helper; interprocedural


def sanitize_id(value):
    return value


@cases.post("/hard/misleading_helper")
def misleading_helper():
    value = sanitize_id(request.get_json().get("id", ""))
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: identity helper; interprocedural


@cases.post("/hard/second_order")
def second_order():
    value = request.get_json().get("filter", "")
    conn = current_app.extensions["eval_db"]
    conn.execute("INSERT INTO saved_filters VALUES ('active', ?)", (value,))
    stored = conn.execute("SELECT value FROM saved_filters WHERE token = 'active'").fetchone()[0]
    query = f"SELECT id FROM orders WHERE id = {stored}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: stored then raw SQL; second-order


@cases.post("/hard/second_order_patch")
def second_order_patch():
    value = request.get_json().get("filter", "")
    conn = current_app.extensions["eval_db"]
    conn.execute("INSERT INTO saved_filters VALUES ('active', ?)", (value,))
    stored = conn.execute("SELECT value FROM saved_filters WHERE token = 'active'").fetchone()[0]
    query = "SELECT id FROM orders WHERE id = ?"
    return jsonify(conn.execute(query, (stored,)).fetchall())  # @safe sqli: re-read value bound


@cases.get("/hard/path/<value>")
def path_value(value):
    conn = current_app.extensions["eval_db"]
    query = f"SELECT id FROM orders WHERE id = {value}"
    return jsonify(conn.execute(query).fetchall())  # @vuln sqli: Flask path parameter source


@cases.get("/hard/path_patch/<value>")
def path_value_patch(value):
    conn = current_app.extensions["eval_db"]
    query = "SELECT id FROM orders WHERE id = ?"
    return jsonify(conn.execute(query, (value,)).fetchall())  # @safe sqli: patched path_value

"""Bundled demo order-api for PulseGuard. DELIBERATELY VULNERABLE - never deploy.

``/order`` builds SQL by string concatenation from ``request.args`` (source and sink in one
function, so Semgrep CE's intraprocedural taint analysis sees the whole flow).
"""

import os
import sqlite3

from flask import Flask, Response, g, jsonify, request

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get("ORDER_API_DB", "orders.sqlite")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/order")
def order():
    order_id = request.args.get("id")
    if order_id is None:
        return jsonify({"error": "missing id"}), 400
    q = "SELECT id, item, qty FROM orders WHERE id = '" + order_id + "'"
    conn = get_db()
    rows = conn.execute(q).fetchall()  # @vuln sqli
    return jsonify([dict(r) for r in rows])


@app.route("/order_by_number")
def order_by_number() -> Response | tuple[Response, int]:
    raw_number = request.args.get("number")
    try:
        order_number = int(raw_number)
    except (TypeError, ValueError):
        return jsonify({"error": "number must be an integer"}), 400
    number_query = "SELECT id, item, qty FROM orders WHERE id = " + str(order_number)
    conn = get_db()
    rows = conn.execute(number_query).fetchall()  # @safe sqli: int-cast; Bandit B608 match
    return jsonify([dict(r) for r in rows])


# Imported here, not at the top, so /order keeps the line numbers of the recorded S1 run.
from order_note import register_order_note  # noqa: E402

register_order_note(app, get_db)


if __name__ == "__main__":
    app.run(port=5001)
